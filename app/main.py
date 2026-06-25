"""
PII-прокси для Anthropic API с псевдонимизацией и поддержкой streaming.

Запуск:
    uvicorn app.main:app --host 0.0.0.0 --port 8080

Использование с Claude Code:
    export ANTHROPIC_BASE_URL=http://localhost:8080
    claude
"""
import asyncio
import json
import logging
import re
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from .pseudonymizer import Pseudonymizer

# ─── Настройки ────────────────────────────────────────────────────────────────

ANTHROPIC_API_URL = "https://api.anthropic.com"
LOG_REPLACEMENTS = True   # логировать что было заменено (отключить в prod)

# HTTP/2 включается только если установлен пакет h2 (httpx[http2])
try:
    import h2  # noqa: F401
    HTTP2_AVAILABLE = True
except ImportError:
    HTTP2_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pii-proxy")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Один клиент на всё приложение: keep-alive соединения к Anthropic
    # переиспользуются между запросами вместо TCP+TLS handshake на каждый.
    app.state.client = httpx.AsyncClient(
        base_url=ANTHROPIC_API_URL,
        http2=HTTP2_AVAILABLE,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    yield
    await app.state.client.aclose()


app = FastAPI(title="PII Anonymizing Proxy", lifespan=lifespan)
pseudonymizer = Pseudonymizer()

# ─── Утилиты ──────────────────────────────────────────────────────────────────

def forward_headers(headers: httpx.Headers) -> dict:
    """
    Заголовки upstream-ответа, которые нужно вернуть клиенту:
    retry-after и x-ratelimit-* — для корректного backoff в SDK при 429,
    request-id — для трассировки запросов в поддержке Anthropic.
    """
    return {
        k: v for k, v in headers.items()
        if k.lower() in ("retry-after", "request-id")
        or k.lower().startswith("x-ratelimit-")
    }


def encode_content(session_id: str, content):
    """
    Рекурсивно кодирует PII в content: строке или списке блоков.
    Кроме text-блоков обрабатывает tool_result — содержимое прочитанных
    файлов приходит именно в них, а не как text верхнего уровня.
    """
    if isinstance(content, str):
        return pseudonymizer.encode(session_id, content)
    if isinstance(content, list):
        encoded = []
        for block in content:
            if block.get("type") == "text":
                encoded.append(
                    {**block, "text": pseudonymizer.encode(session_id, block["text"])}
                )
            elif block.get("type") == "tool_result" and "content" in block:
                encoded.append(
                    {**block, "content": encode_content(session_id, block["content"])}
                )
            else:
                encoded.append(block)
        return encoded
    return content


def filter_messages(session_id: str, messages: list[dict]) -> list[dict]:
    """
    Фильтрует PII во всех сообщениях. История assistant тоже кодируется:
    клиент хранит её с уже восстановленными оригиналами.
    """
    return [
        {**msg, "content": encode_content(session_id, msg["content"])}
        if "content" in msg else msg
        for msg in messages
    ]


def filter_system(session_id: str, system) -> str | list | None:
    """Фильтрует PII в системном промпте."""
    return encode_content(session_id, system)


def _decode_tree(session_id: str, value):
    """
    Рекурсивно декодирует токены во всех строках структуры.
    Используется для tool_use.input в не-streaming ответе: содержимое
    записываемого файла приходит как аргумент инструмента (Write/Edit),
    а не как text-блок, поэтому его нужно декодировать отдельно.
    """
    if isinstance(value, str):
        return pseudonymizer.decode(session_id, value)
    if isinstance(value, list):
        return [_decode_tree(session_id, v) for v in value]
    if isinstance(value, dict):
        return {k: _decode_tree(session_id, v) for k, v in value.items()}
    return value


def _sse(event: dict) -> bytes:
    """Сериализует событие в SSE-строку data:."""
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode()


class _StreamDecoder:
    """
    Декодирует токены в SSE-потоке Anthropic с буферизацией незавершённых
    токенов.

    Декодируются дельты двух типов:
        text_delta       — обычный текст ответа (поле delta.text).
        input_json_delta — аргументы инструмента (поле delta.partial_json):
                            именно так приходит содержимое записываемого
                            файла (Write/Edit). Без этой ветки файл писался
                            бы с токенами [BASEPACKAGENAMESRC_n] внутри.

    Буфер и тип текущего блока хранятся как состояние: незавершённый токен
    на конце дельты придерживается до следующей дельты, а на границе блока
    (content_block_stop) остаток сбрасывается дельтой того же типа.

    partial_json — сериализованный JSON-фрагмент; декодирование подменяет
    токен на оригинал внутри строкового значения. Это безопасно для PII
    данного проекта (имена пакетов/орг: без ", \\, переводов строк), но
    оригинал со спецсимволами JSON потребовал бы повторного экранирования.
    """

    # [A-Z_]* (а не +): буфер может оборваться сразу после открывающей '['
    # — например на стыке соседних токенов сегментов ('[...].[...]').
    # С '+' одиночная '[' в конце не распознавалась как начало токена,
    # отдавалась клиенту раньше времени, и следующий токен терял '['
    # и больше не декодировался.
    _INCOMPLETE_RE = re.compile(r"\[[A-Z_]*(?:_\d+)?$")

    def __init__(self, pii: Pseudonymizer, session_id: str):
        self._pii = pii
        self._sid = session_id
        self._buffer = ""
        self._kind: str | None = None   # text_delta | input_json_delta
        self._index = 0

    def _decode_safe(self, text: str) -> str:
        """Декодирует, придерживая незавершённый токен на конце в буфере."""
        self._buffer += text
        m = self._INCOMPLETE_RE.search(self._buffer)
        if m:
            safe, self._buffer = self._buffer[:m.start()], self._buffer[m.start():]
        else:
            safe, self._buffer = self._buffer, ""
        return self._pii.decode(self._sid, safe)

    def _flush(self) -> bytes:
        """
        Сбрасывает остаток буфера на границе блока: здесь это полноценное
        значение поля, незавершённых токенов быть не может — декодируем целиком.
        """
        if not self._buffer or not self._kind:
            self._buffer = ""
            return b""
        decoded = self._pii.decode(self._sid, self._buffer)
        self._buffer = ""
        if not decoded:
            return b""
        field = "text" if self._kind == "text_delta" else "partial_json"
        return _sse({
            "type": "content_block_delta",
            "index": self._index,
            "delta": {"type": self._kind, field: decoded},
        })

    def process_line(self, line: str) -> bytes:
        """Обрабатывает одну SSE-строку, возвращает байты для клиента."""
        if not line.startswith("data: "):
            return f"{line}\n\n".encode()

        raw = line[6:]
        if raw == "[DONE]":
            return b"data: [DONE]\n\n"

        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return f"{line}\n\n".encode()

        etype = event.get("type")
        if etype == "content_block_start":
            # Новый блок — буфер предыдущего уже сброшен на его stop.
            self._index = event.get("index", self._index)
            self._kind = None
            self._buffer = ""
        elif etype == "content_block_delta":
            self._index = event.get("index", self._index)
            delta = event.get("delta", {})
            dtype = delta.get("type")
            if dtype == "text_delta":
                self._kind = "text_delta"
                delta["text"] = self._decode_safe(delta.get("text", ""))
            elif dtype == "input_json_delta":
                self._kind = "input_json_delta"
                delta["partial_json"] = self._decode_safe(delta.get("partial_json", ""))
        elif etype == "content_block_stop":
            self._index = event.get("index", self._index)
            return self._flush() + _sse(event)

        return _sse(event)

    def finish(self) -> bytes:
        """Сбрасывает остаток буфера при завершении потока (обрыв без stop)."""
        return self._flush()


async def _collect_stream(
    client: httpx.AsyncClient,
    session_id: str,
    headers: dict,
    body: dict,
    params: dict,
    queue: asyncio.Queue,
    passthrough: bool,
) -> None:
    """
    Читает SSE-поток от Anthropic целиком внутри httpx-контекста
    и кладёт обработанные чанки в очередь.
    Sentinel None сигнализирует об окончании.
    passthrough=True — в сессии не было замен PII, ответ не может содержать
    токены, поэтому байты пересылаются как есть без разбора SSE/JSON.
    """
    decoder = _StreamDecoder(pseudonymizer, session_id)
    try:
        async with client.stream(
            "POST",
            "/v1/messages",
            headers=headers,
            json=body,
            params=params,
            timeout=120,
        ) as upstream:
            if upstream.status_code != 200:
                error_body = await upstream.aread()
                await queue.put((
                    "error",
                    upstream.status_code,
                    error_body,
                    forward_headers(upstream.headers),
                ))
                return

            await queue.put(("ok", upstream.status_code, None))

            if passthrough:
                async for chunk in upstream.aiter_bytes():
                    await queue.put(chunk)
            else:
                async for line in upstream.aiter_lines():
                    if not line:
                        await queue.put(b"\n")
                        continue
                    await queue.put(decoder.process_line(line))

        # Сбрасываем остаток буфера (на случай обрыва потока без stop-события)
        tail = decoder.finish()
        if tail:
            await queue.put(tail)
    except asyncio.CancelledError:
        pass  # клиент отключился — чистый выход
    except Exception as e:
        log.error(f"[{session_id[:8]}] Ошибка стрима: {e}")
    finally:
        pseudonymizer.clear(session_id)
        # put_nowait чтобы не блокироваться при отмене задачи
        try:
            queue.put_nowait(None)
        except asyncio.QueueFull:
            pass


async def _stream_from_queue(
    queue: asyncio.Queue,
    task: asyncio.Task,
) -> AsyncIterator[bytes]:
    """Читает чанки из очереди и отдаёт клиенту. При выходе отменяет фоновую задачу."""
    try:
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk
    finally:
        if not task.done():
            task.cancel()


# ─── Маршрут: /v1/messages ────────────────────────────────────────────────────

@app.post("/v1/messages")
async def proxy_messages(request: Request):
    session_id = str(uuid.uuid4())
    body = await request.json()

    # Фильтруем входящие данные
    if "messages" in body:
        body["messages"] = filter_messages(session_id, body["messages"])
    if "system" in body:
        body["system"] = filter_system(session_id, body["system"])

    # Если замен не было — ответ не может содержать токены,
    # и его можно пересылать клиенту без разбора SSE/JSON.
    replaced_count = pseudonymizer.stats(session_id).get("replaced", 0)
    passthrough = replaced_count == 0

    if LOG_REPLACEMENTS and replaced_count:
        stats = pseudonymizer.stats(session_id)
        log.info(f"[{session_id[:8]}] Заменено PII: {stats['replaced']} значений")
        log.info(f"[{session_id[:8]}] Маппинг: {stats['mapping']}")

    # Пересылаем заголовки (без host)
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }

    streaming = body.get("stream", False)
    params = dict(request.query_params)
    client: httpx.AsyncClient = request.app.state.client

    if streaming:
        # Очередь связывает фоновую задачу чтения стрима и генератор ответа
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)

        # Запускаем чтение стрима в фоне — httpx-контекст живёт внутри задачи
        task = asyncio.create_task(
            _collect_stream(client, session_id, headers, body, params, queue, passthrough)
        )

        # Ждём первый элемент — статус или ошибку
        first = await queue.get()
        if isinstance(first, tuple) and first[0] == "error":
            _, status_code, error_body, error_headers = first
            pseudonymizer.clear(session_id)
            return Response(
                content=error_body,
                status_code=status_code,
                media_type="application/json",
                headers=error_headers,
            )

        # first == ("ok", 200, None) — стрим начался, отдаём клиенту
        return StreamingResponse(
            _stream_from_queue(queue, task),
            media_type="text/event-stream",
            headers={"X-Session-Id": session_id[:8]},
        )

    else:
        # Обычный (не streaming) запрос
        resp = await client.post(
            "/v1/messages",
            headers=headers,
            json=body,
            params=params,
            timeout=120,
        )

        if passthrough:
            # Замен не было — отдаём ответ без разбора JSON
            pseudonymizer.clear(session_id)
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type="application/json",
                headers=forward_headers(resp.headers),
            )

        resp_body = resp.json()

        if "content" in resp_body:
            for block in resp_body["content"]:
                if block.get("type") == "text":
                    block["text"] = pseudonymizer.decode(session_id, block["text"])
                elif block.get("type") == "tool_use" and "input" in block:
                    # Содержимое записываемого файла приходит здесь, а не в
                    # text-блоке — декодируем аргументы инструмента рекурсивно.
                    block["input"] = _decode_tree(session_id, block["input"])

        pseudonymizer.clear(session_id)
        return Response(
            content=json.dumps(resp_body, ensure_ascii=False),
            status_code=resp.status_code,
            media_type="application/json",
            headers=forward_headers(resp.headers),
        )


# ─── Health check ─────────────────────────────────────────────────────────────

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return Response(status_code=200)


@app.get("/health")
async def health():
    return {"status": "ok", "proxy": "pii-anonymizing"}


# ─── Проксируем остальные эндпоинты Anthropic как есть ───────────────────────

@app.api_route(
    "/{path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"],
)
async def proxy_passthrough(request: Request, path: str):
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    body = await request.body()
    client: httpx.AsyncClient = request.app.state.client
    resp = await client.request(
        method=request.method,
        url=f"/{path}",
        headers=headers,
        content=body,
        params=dict(request.query_params),
        timeout=60,
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
        headers=forward_headers(resp.headers),
    )

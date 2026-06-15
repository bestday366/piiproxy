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


def _decode_safe(session_id: str, buffer: str) -> tuple[str, str]:
    """
    Декодирует завершённые токены в буфере.
    Незавершённый токен в конце буфера (открытая скобка без закрытой)
    остаётся в буфере до следующего чанка.
    """
    incomplete = re.search(r"\[[A-Z_]+(?:_\d+)?$", buffer)
    if incomplete:
        safe_part = buffer[:incomplete.start()]
        remaining = buffer[incomplete.start():]
    else:
        safe_part = buffer
        remaining = ""
    return pseudonymizer.decode(session_id, safe_part), remaining


def _process_sse_line(session_id: str, line: str, buffer: str) -> tuple[bytes, str]:
    """
    Обрабатывает одну SSE-строку: декодирует PII в text_delta событиях.
    Возвращает (bytes_to_send, updated_buffer).
    """
    if not line.startswith("data: "):
        return f"{line}\n\n".encode(), buffer

    raw = line[6:]
    if raw == "[DONE]":
        return b"data: [DONE]\n\n", buffer

    try:
        event = json.loads(raw)
        if (
            event.get("type") == "content_block_delta"
            and event.get("delta", {}).get("type") == "text_delta"
        ):
            buffer += event["delta"]["text"]
            decoded, buffer = _decode_safe(session_id, buffer)
            event["delta"]["text"] = decoded

        return f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode(), buffer
    except json.JSONDecodeError:
        return f"{line}\n\n".encode(), buffer


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
    buffer = ""
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
                    chunk, buffer = _process_sse_line(session_id, line, buffer)
                    await queue.put(chunk)

        # Сбрасываем остаток буфера
        if buffer:
            decoded = pseudonymizer.decode(session_id, buffer)
            if decoded:
                event = {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": decoded},
                }
                await queue.put(
                    f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode()
                )
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

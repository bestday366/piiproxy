"""
Тесты декодирования ответа в main.py.

Проверяют, что деанонимизация происходит не только в text-блоках, но и в
аргументах инструментов (tool_use / input_json_delta) — именно через них
приходит содержимое записываемого файла (Write/Edit).

Запуск (из директории src/piiproxy/, нужны зависимости из requirements.txt):
    python3 -m unittest discover -s tests -v
"""
import json
import unittest

from app.main import _StreamDecoder, _decode_tree, pseudonymizer
from app.pseudonymizer import Pseudonymizer

# Полный пакет org.copita.i.roga -> 4 токена сегментов.
PKG_TOKENS = (
    "[BASEPACKAGENAMESRC_1].[BASEPACKAGENAMESRC_2]"
    ".[BASEPACKAGENAMESRC_3].[BASEPACKAGENAMESRC_4]"
)
PKG_ORIG = "org.copita.i.roga"


def _sse_line(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}"


def _drive(decoder: _StreamDecoder, events: list[dict]) -> str:
    """Прогоняет события через декодер и возвращает склеенные байты как текст."""
    out = b""
    for ev in events:
        out += decoder.process_line(_sse_line(ev))
    out += decoder.finish()
    return out.decode()


def _collect_field(raw: str, field: str) -> str:
    """Склеивает значения delta.<field> из всех content_block_delta в выводе."""
    result = ""
    for line in raw.splitlines():
        if not line.startswith("data: "):
            continue
        payload = line[6:]
        if payload == "[DONE]":
            continue
        ev = json.loads(payload)
        if ev.get("type") == "content_block_delta":
            result += ev.get("delta", {}).get(field, "")
    return result


class DecodeTreeTest(unittest.TestCase):
    """Не-streaming: рекурсивное декодирование tool_use.input."""

    def setUp(self):
        # _decode_tree использует модульный синглтон pseudonymizer.
        self.sid = "tree-1"
        pseudonymizer.encode(self.sid, PKG_ORIG)
        self.addCleanup(pseudonymizer.clear, self.sid)

    def test_decodes_nested_strings(self):
        tool_input = {
            "file_path": "/srv/HelloWorld.java",
            "content": f"package {PKG_TOKENS};\nimport {PKG_TOKENS}.calk.Sum;",
            "meta": {"tags": [f"pkg:{PKG_TOKENS}"]},
        }
        decoded = _decode_tree(self.sid, tool_input)
        self.assertIn(f"package {PKG_ORIG};", decoded["content"])
        self.assertIn(f"import {PKG_ORIG}.calk.Sum;", decoded["content"])
        self.assertEqual(decoded["meta"]["tags"][0], f"pkg:{PKG_ORIG}")
        # Структура и не-строковые значения сохраняются.
        self.assertEqual(decoded["file_path"], "/srv/HelloWorld.java")

    def test_non_string_scalars_untouched(self):
        self.assertEqual(_decode_tree(self.sid, 42), 42)
        self.assertEqual(_decode_tree(self.sid, None), None)
        self.assertEqual(_decode_tree(self.sid, True), True)


class StreamTextDeltaTest(unittest.TestCase):
    """Streaming text_delta продолжает декодироваться (регрессия)."""

    def setUp(self):
        self.p = Pseudonymizer()
        self.sid = "txt-1"
        self.p.encode(self.sid, PKG_ORIG)
        self.dec = _StreamDecoder(self.p, self.sid)

    def test_text_delta_decoded(self):
        events = [
            {"type": "content_block_start", "index": 0,
             "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "text_delta", "text": f"пакет {PKG_TOKENS} готов"}},
            {"type": "content_block_stop", "index": 0},
        ]
        out = _drive(self.dec, events)
        self.assertEqual(_collect_field(out, "text"), f"пакет {PKG_ORIG} готов")

    def test_token_split_across_text_deltas(self):
        # Токен разорван между двумя дельтами — должен собраться и декодироваться.
        events = [
            {"type": "content_block_start", "index": 0,
             "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "text_delta", "text": "[BASEPACKAGENAM"}},
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "text_delta", "text": "ESRC_1] точка"}},
            {"type": "content_block_stop", "index": 0},
        ]
        out = _drive(self.dec, events)
        self.assertEqual(_collect_field(out, "text"), "org точка")


class StreamToolUseTest(unittest.TestCase):
    """Streaming input_json_delta: содержимое файла декодируется (главный фикс)."""

    def setUp(self):
        self.p = Pseudonymizer()
        self.sid = "tool-1"
        self.p.encode(self.sid, PKG_ORIG)
        self.dec = _StreamDecoder(self.p, self.sid)

    def test_input_json_delta_decoded(self):
        full = json.dumps({"content": f"package {PKG_TOKENS};"})
        # Бьём partial_json на куски, в т.ч. посреди токена.
        cut = full.index("_2]") + 1   # разрыв внутри второго токена
        events = [
            {"type": "content_block_start", "index": 1,
             "content_block": {"type": "tool_use", "name": "Write", "input": {}}},
            {"type": "content_block_delta", "index": 1,
             "delta": {"type": "input_json_delta", "partial_json": full[:cut]}},
            {"type": "content_block_delta", "index": 1,
             "delta": {"type": "input_json_delta", "partial_json": full[cut:]}},
            {"type": "content_block_stop", "index": 1},
        ]
        out = _drive(self.dec, events)
        decoded_json = _collect_field(out, "partial_json")
        # Склеенный partial_json — валидный JSON с восстановленным пакетом.
        parsed = json.loads(decoded_json)
        self.assertEqual(parsed["content"], f"package {PKG_ORIG};")

    def test_flush_emits_with_block_index(self):
        # Остаток буфера на content_block_stop сбрасывается с индексом блока.
        events = [
            {"type": "content_block_start", "index": 1,
             "content_block": {"type": "tool_use", "name": "Write", "input": {}}},
            {"type": "content_block_delta", "index": 1,
             "delta": {"type": "input_json_delta",
                       "partial_json": f'{{"c":"{PKG_TOKENS}"'}},
            {"type": "content_block_stop", "index": 1},
        ]
        out = _drive(self.dec, events)
        # Все эмитированные дельты несут index == 1 (не дефолтный 0).
        for line in out.splitlines():
            if line.startswith("data: "):
                ev = json.loads(line[6:])
                if ev.get("type") == "content_block_delta":
                    self.assertEqual(ev["index"], 1)


class StreamMixedBlocksTest(unittest.TestCase):
    """Текстовый блок и tool_use в одном потоке не перемешивают буферы."""

    def setUp(self):
        self.p = Pseudonymizer()
        self.sid = "mix-1"
        self.p.encode(self.sid, PKG_ORIG)
        self.dec = _StreamDecoder(self.p, self.sid)

    def test_text_then_tool_use(self):
        events = [
            {"type": "content_block_start", "index": 0,
             "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "text_delta", "text": f"в {PKG_TOKENS}"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "content_block_start", "index": 1,
             "content_block": {"type": "tool_use", "name": "Write", "input": {}}},
            {"type": "content_block_delta", "index": 1,
             "delta": {"type": "input_json_delta",
                       "partial_json": json.dumps({"content": PKG_TOKENS})}},
            {"type": "content_block_stop", "index": 1},
        ]
        out = _drive(self.dec, events)
        self.assertEqual(_collect_field(out, "text"), f"в {PKG_ORIG}")
        parsed = json.loads(_collect_field(out, "partial_json"))
        self.assertEqual(parsed["content"], PKG_ORIG)


if __name__ == "__main__":
    unittest.main()

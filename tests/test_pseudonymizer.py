"""
Тесты для pseudonymizer.py.

Запуск (из директории src/piiproxy/):
    python3 -m unittest discover -s tests -v

Если установлен pytest:
    pytest tests/ -v
"""
import re
import threading
import unittest

from app.patterns import MODE_UNIQUE, MODE_SINGLE, MODE_SEGMENTS
from app.pseudonymizer import Pseudonymizer, SessionMap


class SessionMapTest(unittest.TestCase):
    """Юнит-тесты низкоуровневого маппинга одной сессии."""

    def test_add_unique_increments_index(self):
        smap = SessionMap()
        self.assertEqual(smap.add("EMAIL", "a@x.ru"), "[EMAIL_1]")
        self.assertEqual(smap.add("EMAIL", "b@x.ru"), "[EMAIL_2]")
        # Разные метки нумеруются независимо.
        self.assertEqual(smap.add("PHONE", "+7..."), "[PHONE_1]")

    def test_add_same_value_returns_same_token(self):
        smap = SessionMap()
        first = smap.add("EMAIL", "a@x.ru")
        second = smap.add("EMAIL", "a@x.ru")
        self.assertEqual(first, second)
        self.assertEqual(smap.counters["EMAIL"], 1)

    def test_add_single_always_uses_index_1(self):
        smap = SessionMap()
        t1 = smap.add("ORG", "Рога", single=True)
        t2 = smap.add("ORG", "Копыта", single=True)
        self.assertEqual(t1, "[ORG_1]")
        self.assertEqual(t2, "[ORG_1]")
        # decode восстанавливает только первое встреченное значение.
        self.assertEqual(smap.decode["[ORG_1]"], "Рога")

    def test_add_populates_both_directions(self):
        smap = SessionMap()
        token = smap.add("EMAIL", "a@x.ru")
        self.assertEqual(smap.encode["a@x.ru"], token)
        self.assertEqual(smap.decode[token], "a@x.ru")


class EncodeDecodeTest(unittest.TestCase):
    """Тесты на реальных паттернах из patterns.py."""

    def setUp(self):
        self.p = Pseudonymizer()
        self.sid = "req-1"

    def test_encode_unique_pattern(self):
        out = self.p.encode(self.sid, "сервер roga.i.copita.org живой")
        self.assertEqual(out, "сервер [BASEORGNAME_URLORG_1] живой")

    def test_encode_ru_pattern_case_insensitive(self):
        out = self.p.encode(self.sid, "компания Рога И Копыта работает")
        self.assertEqual(out, "компания [BASEORGNAME_RU_1] работает")

    def test_roundtrip_restores_original(self):
        original = "сервер roga.i.copita.org принадлежит Рога и Копыта"
        encoded = self.p.encode(self.sid, original)
        self.assertNotIn("roga.i.copita.org", encoded)
        self.assertNotIn("Рога и Копыта", encoded)
        decoded = self.p.decode(self.sid, encoded)
        self.assertEqual(decoded, original)

    def test_encode_is_idempotent_for_repeated_value(self):
        out = self.p.encode(self.sid, "roga.i.copita.org и снова roga.i.copita.org")
        self.assertEqual(out, "[BASEORGNAME_URLORG_1] и снова [BASEORGNAME_URLORG_1]")

    def test_no_pii_returns_text_unchanged(self):
        text = "обычный текст без чувствительных данных"
        self.assertEqual(self.p.encode(self.sid, text), text)


class SegmentsModeTest(unittest.TestCase):
    """MODE_SEGMENTS: сегменты токенизируются, разделители сохраняются."""

    def setUp(self):
        self.p = Pseudonymizer()
        self.sid = "req-seg"

    def test_package_keeps_dots(self):
        out = self.p.encode(self.sid, "import org.copita.i.roga")
        self.assertEqual(
            out,
            "import [BASEPACKAGENAMESRC_1].[BASEPACKAGENAMESRC_2]"
            ".[BASEPACKAGENAMESRC_3].[BASEPACKAGENAMESRC_4]",
        )

    def test_path_keeps_slashes_and_reuses_segment_tokens(self):
        # Сначала пакет (точки), затем директория (слэши): сегменты те же,
        # поэтому переиспользуются те же токены, но разделители разные.
        self.p.encode(self.sid, "org.copita.i.roga")
        out = self.p.encode(self.sid, "путь org/copita/i/roga")
        self.assertEqual(
            out,
            "путь [BASEPACKAGENAMESRC_1]/[BASEPACKAGENAMESRC_2]"
            "/[BASEPACKAGENAMESRC_3]/[BASEPACKAGENAMESRC_4]",
        )

    def test_segments_roundtrip(self):
        original = "org.copita.i.roga"
        encoded = self.p.encode(self.sid, original)
        self.assertEqual(self.p.decode(self.sid, encoded), original)


class SingleModeTest(unittest.TestCase):
    """MODE_SINGLE: все совпадения -> один токен, decode необратим для прочих."""

    def setUp(self):
        # Один паттерн в режиме single для предсказуемости.
        patterns = [("SECRET", re.compile(r"S\d+"), MODE_SINGLE)]
        self.p = Pseudonymizer(patterns=patterns)
        self.sid = "req-single"

    def test_all_matches_collapse_to_one_token(self):
        out = self.p.encode(self.sid, "S1 и S2 и S3")
        self.assertEqual(out, "[SECRET_1] и [SECRET_1] и [SECRET_1]")

    def test_decode_restores_only_first_value(self):
        encoded = self.p.encode(self.sid, "S1 и S2")
        decoded = self.p.decode(self.sid, encoded)
        # Все токены [SECRET_1] декодируются в первое значение "S1".
        self.assertEqual(decoded, "S1 и S1")


class SessionIsolationTest(unittest.TestCase):
    """Маппинги разных сессий независимы."""

    def setUp(self):
        self.p = Pseudonymizer()

    def test_sessions_do_not_share_mapping(self):
        self.p.encode("a", "roga.i.copita.org")
        # Сессия b ничего не знает про токены a.
        self.assertEqual(self.p.decode("b", "[BASEORGNAME_URLORG_1]"),
                         "[BASEORGNAME_URLORG_1]")

    def test_clear_removes_session(self):
        self.p.encode("a", "roga.i.copita.org")
        self.p.clear("a")
        self.assertEqual(self.p.stats("a"), {})
        # decode после clear возвращает текст как есть.
        self.assertEqual(self.p.decode("a", "[BASEORGNAME_URLORG_1]"),
                         "[BASEORGNAME_URLORG_1]")

    def test_clear_unknown_session_is_noop(self):
        # Не должно бросать исключение.
        self.p.clear("never-existed")


class DecodeEdgeCasesTest(unittest.TestCase):
    def setUp(self):
        self.p = Pseudonymizer()

    def test_decode_unknown_session_returns_text(self):
        self.assertEqual(self.p.decode("ghost", "что-то"), "что-то")

    def test_decode_chunk_matches_decode(self):
        self.p.encode("s", "roga.i.copita.org")
        chunk = "ответ про [BASEORGNAME_URLORG_1]"
        self.assertEqual(self.p.decode_chunk("s", chunk),
                         self.p.decode("s", chunk))

    def test_decode_chunk_with_split_token_left_intact(self):
        self.p.encode("s", "roga.i.copita.org")
        # Токен разбит между чанками — частичный фрагмент не подменяется.
        partial = "ответ про [BASEORGNAME_UR"
        self.assertEqual(self.p.decode_chunk("s", partial), partial)


class StatsTest(unittest.TestCase):
    def setUp(self):
        self.p = Pseudonymizer()

    def test_stats_reports_replacements_and_mapping(self):
        self.p.encode("s", "roga.i.copita.org и Рога и Копыта")
        stats = self.p.stats("s")
        self.assertEqual(stats["replaced"], 2)
        self.assertEqual(stats["mapping"]["[BASEORGNAME_URLORG_1]"],
                         "roga.i.copita.org")

    def test_stats_unknown_session_is_empty(self):
        self.assertEqual(self.p.stats("none"), {})


class ThreadSafetyTest(unittest.TestCase):
    """Параллельное использование не должно терять сессии/ломать маппинг."""

    def test_concurrent_encode_distinct_sessions(self):
        p = Pseudonymizer()
        errors = []

        def worker(i):
            try:
                sid = f"req-{i}"
                out = p.encode(sid, "roga.i.copita.org")
                if out != "[BASEORGNAME_URLORG_1]":
                    errors.append((sid, out))
            except Exception as exc:  # pragma: no cover
                errors.append((i, exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        for i in range(50):
            self.assertEqual(p.stats(f"req-{i}")["replaced"], 1)


if __name__ == "__main__":
    unittest.main()

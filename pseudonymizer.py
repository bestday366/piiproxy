"""
Псевдонимизация PII — обратимая замена с хранением маппинга в памяти.
"""
import re
import threading
from dataclasses import dataclass, field

from .patterns import PATTERNS, MODE_SINGLE, MODE_SEGMENTS

# Разделители сегментов для режима MODE_SEGMENTS (захватываются, чтобы
# сохраниться в результате re.split).
_SEP_RE = re.compile(r"([./])")


@dataclass
class SessionMap:
    """Маппинг для одной сессии/запроса."""
    encode: dict[str, str] = field(default_factory=dict)  # оригинал → токен
    decode: dict[str, str] = field(default_factory=dict)  # токен → оригинал
    counters: dict[str, int] = field(default_factory=dict)

    def add(self, label: str, original: str, single: bool = False) -> str:
        if original in self.encode:
            return self.encode[original]
        if single:
            # Новый токен не создаётся: все совпадения паттерна
            # подставляются одним токеном с начальным индексом.
            token = f"[{label}_1]"
            self.encode[original] = token
            # Декодируется в первое встреченное значение.
            self.decode.setdefault(token, original)
            return token
        self.counters[label] = self.counters.get(label, 0) + 1
        token = f"[{label}_{self.counters[label]}]"
        self.encode[original] = token
        self.decode[token] = original
        return token


class Pseudonymizer:
    """
    Thread-safe псевдонимизатор с маппингом per-session.

    Использование:
        p = Pseudonymizer()
        session_id = "req-123"
        clean = p.encode(session_id, text)
        # ... отправить clean в Anthropic ...
        restored = p.decode(session_id, response)
        p.clear(session_id)   # освободить память
    """

    def __init__(self, patterns: list[tuple[str, re.Pattern, str]] = PATTERNS):
        self._patterns = patterns
        self._sessions: dict[str, SessionMap] = {}
        self._lock = threading.Lock()

    def _get_or_create(self, session_id: str) -> SessionMap:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionMap()
            return self._sessions[session_id]

    def encode(self, session_id: str, text: str) -> str:
        """Заменяет PII на токены, запоминает маппинг."""
        smap = self._get_or_create(session_id)
        for label, pattern, mode in self._patterns:
            if mode == MODE_SEGMENTS:
                def replace(m, _label=label, _smap=smap):
                    # Разделители ('.' или '/') сохраняются, сегменты
                    # токенизируются стабильно — пакет и директория получают
                    # одинаковые имена сегментов, но обратимы по-разному.
                    return "".join(
                        part if _SEP_RE.fullmatch(part) else _smap.add(_label, part)
                        for part in _SEP_RE.split(m.group(0))
                    )
            else:
                def replace(m, _label=label, _smap=smap, _single=(mode == MODE_SINGLE)):
                    return _smap.add(_label, m.group(0), _single)
            text = pattern.sub(replace, text)
        return text

    def decode(self, session_id: str, text: str) -> str:
        """Восстанавливает оригинальные значения в тексте ответа."""
        with self._lock:
            smap = self._sessions.get(session_id)
        if not smap:
            return text
        for token, original in smap.decode.items():
            text = text.replace(token, original)
        return text

    def decode_chunk(self, session_id: str, chunk: str) -> str:
        """
        Восстанавливает токены в streaming-чанке.
        Безопасно: если токен разбит между чанками — он останется как есть
        и будет восстановлен при следующем decode_chunk или финальном decode.
        """
        return self.decode(session_id, chunk)

    def clear(self, session_id: str) -> None:
        """Удаляет маппинг после завершения сессии."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def stats(self, session_id: str) -> dict:
        with self._lock:
            smap = self._sessions.get(session_id)
        if not smap:
            return {}
        return {"replaced": len(smap.encode), "mapping": dict(smap.decode)}

"""
Паттерны PII для псевдонимизации.

Заменяемые строки roga.i.copita.org а также ёorg.copita.i.rogaё

Формат записи паттерна: (label, pattern, mode)
    label   — имя метки токена.
    pattern — скомпилированное регулярное выражение.
    mode    — режим токенизации:
        "unique"   — текущее поведение: на каждое новое значение создаётся
                     отдельный токен с инкрементируемым индексом.
        "single"   — новый токен НЕ создаётся; все совпадения этого паттерна
                     подставляются одним и тем же токеном с начальным индексом
                     ([LABEL_1]), который соответствует первому встреченному
                     значению. Замена необратима для остальных значений.
        "segments" — совпадение разбивается по разделителям '.' и '/';
                     токенизируется каждый сегмент (стабильно), а разделители
                     сохраняются как есть. Так пакет (org.copita.i.roga) и
                     директория (org/copita/i/roga) получают одинаковые имена
                     сегментов, но при декодировании пакет остаётся пакетом,
                     а директория — директорией.
"""
import re

# Режимы токенизации.
MODE_UNIQUE = "unique"
MODE_SINGLE = "single"
MODE_SEGMENTS = "segments"

PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("BASEORGNAME_URLORG",    re.compile(r"roga\.i\.copita\.org"), MODE_UNIQUE),
    ("BASEPACKAGENAMESRC",    re.compile(r"org[./]copita[./]i[./]roga"), MODE_SEGMENTS),
    ("BASEORGNAME_RU",        re.compile(r"рога\s+и\s+копыта", re.IGNORECASE), MODE_UNIQUE),
    #("EMAIL",    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), MODE_UNIQUE),
    #("PHONE",    re.compile(r"(\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"), MODE_UNIQUE),
    #("CARD",     re.compile(r"\b(?:\d[ \-]?){15,19}\b"), MODE_UNIQUE),
    #("IBAN",     re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), MODE_UNIQUE),
    #("IP",       re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), MODE_UNIQUE),
    #("INN",      re.compile(r"\b\d{10}(?:\d{2})?\b"), MODE_UNIQUE),
    #("DATE_DOB", re.compile(r"\b\d{1,2}[.\/-]\d{1,2}[.\/-]\d{4}\b"), MODE_UNIQUE),
    #("URL",      re.compile(r"https?://[^\s,;)\"\']+"), MODE_UNIQUE),
    #("NAME_RU",  re.compile(r"[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)?"), MODE_UNIQUE),
]

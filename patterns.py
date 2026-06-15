"""
Паттерны PII для псевдонимизации.

Заменяемые строки roga.i.copita.org а также ёorg.copita.i.rogaё

"""
import re

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("BASEORGNAME_URLORG", re.compile(r"roga\.i\.copita\.org")),
    ("BASEPACKAGENAMESRC",    re.compile(r"org\.copita\.i\.roga")),
    ("BASEORGNAME_RU",        re.compile(r"рога\s+и\s+копыта", re.IGNORECASE)),
    #("EMAIL",    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    #("PHONE",    re.compile(r"(\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")),
    #("CARD",     re.compile(r"\b(?:\d[ \-]?){15,19}\b")),
    #("IBAN",     re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    #("IP",       re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    #("INN",      re.compile(r"\b\d{10}(?:\d{2})?\b")),
    #("DATE_DOB", re.compile(r"\b\d{1,2}[.\/-]\d{1,2}[.\/-]\d{4}\b")),
    #("URL",      re.compile(r"https?://[^\s,;)\"\']+")),
    #("NAME_RU",  re.compile(r"[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)?")),
]

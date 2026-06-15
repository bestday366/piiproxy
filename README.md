# PII Anonymizing Proxy для Anthropic API

Локальный прокси-сервер, который перехватывает все запросы между Claude Code
и Anthropic API, заменяет PII на токены перед отправкой и восстанавливает
оригинальные значения в ответе. Поддерживает streaming.

## Схема работы

```
Claude Code
    ↓  ANTHROPIC_BASE_URL=http://localhost:8080
Прокси (этот сервер)
    ├─ encode: ivan@company.ru → [EMAIL_1]
    ↓
api.anthropic.com
    ↓
Прокси
    ├─ decode: [EMAIL_1] → ivan@company.ru
    ↓
Claude Code
```

## Установка

```bash
cd ~/.local/share/pii-proxy
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

алиас:
```bash
alias pii-proxy="~/.local/share/pii-proxy/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8181 --app-dir ~/.local/share/pii-proxy"
```

## Запуск

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Подключение к Claude Code

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-...
claude
```

Или добавить в ~/.bashrc / ~/.zshrc:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
```

## Настройка паттернов

Паттерны PII находятся в `app/pseudonymizer.py` в переменной `PATTERNS`.
Добавьте свои регулярные выражения в список:

```python
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL",    re.compile(r"...")),
    ("MY_FIELD", re.compile(r"ваш паттерн")),
    ...
]
```

## Отключение логирования маппинга (prod)

В `app/main.py`:

```python
LOG_REPLACEMENTS = False
```

## Health check

```bash
curl http://localhost:8080/health
```

## Структура проекта

```
pii-proxy/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI прокси
│   └── pseudonymizer.py # Логика псевдонимизации
├── requirements.txt
└── README.md
```

# Паттерны и режимы токенизации
Паттерны PII задаются в `src/piiproxy/patterns.py` в списке `PATTERNS`.
Формат записи: `(label, pattern, mode)`, где `mode` определяет способ замены:

- `MODE_UNIQUE` ("unique") — на каждое новое значение создаётся отдельный токен
  с инкрементируемым индексом (`[LABEL_1]`, `[LABEL_2]`, ...). Полностью
  обратимо. Поведение по умолчанию.
- `MODE_SINGLE` ("single") — новый токен не создаётся: все совпадения паттерна
  подставляются одним токеном с начальным индексом (`[LABEL_1]`), который
  соответствует первому встреченному значению. Для остальных значений замена
  необратима (при декодировании восстанавливается первое значение).
- `MODE_SEGMENTS` ("segments") — совпадение разбивается по разделителям `.` и
  `/`; каждый сегмент токенизируется стабильно, а разделители сохраняются как
  есть. Это позволяет анонимизировать Java-пакет (`org.copita.i.roga`) и
  директорию (`org/copita/i/roga`) одинаковыми именами сегментов, но при
  декодировании пакет остаётся пакетом (точки), а директория — директорией
  (слэши).

Пример (`MODE_SEGMENTS`):

| Этап | Значение |
|---|---|
| Оригинал (пакет)    | `org.copita.i.roga` |
| Оригинал (директория) | `org/copita/i/roga` |
| Отдаётся модели (пакет)    | `[BASEPACKAGENAMESRC_1].[BASEPACKAGENAMESRC_2].[BASEPACKAGENAMESRC_3].[BASEPACKAGENAMESRC_4]` |
| Отдаётся модели (директория) | `[BASEPACKAGENAMESRC_1]/[BASEPACKAGENAMESRC_2]/[BASEPACKAGENAMESRC_3]/[BASEPACKAGENAMESRC_4]` |

Режимы реализованы в `src/piiproxy/pseudonymizer.py` (метод `Pseudonymizer.encode`).
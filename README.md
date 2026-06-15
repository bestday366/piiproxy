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

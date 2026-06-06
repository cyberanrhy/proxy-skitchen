# proxy-skitchen

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![PySide6](https://img.shields.io/badge/GUI-PySide6-green.svg)](https://wiki.qt.io/Qt_for_Python)

**proxy-skitchen** — графическое приложение для поиска, парсинга, глубокого тестирования (через sing-box) и сохранения прокси-подписок в форматы Hiddify, Clash, sing-box, V2RayN и другие.

Форк [proxy-fetcher-gui](https://github.com/igareck/proxy-fetcher-gui).

## Возможности

- 🔍 **Поиск источников** — парсинг GitHub-репозиториев по ключевым словам + прямой ввод URL
- ⬇ **Загрузка подписок** — многопоточный парсинг proxy-файлов и Base64-подписок
- ✅ **TCP-тест** — быстрая проверка доступности (host:port, таймаут 12с)
- 🧪 **Deep-тест** — глубокая проверка через sing-box (реальный HTTP-запрос)
- 📦 **Экспорт** — Clash YAML, sing-box JSON, V2RayN TXT, Hiddify, сырые URI
- ⚡ **Три режима производительности** — для слабых и мощных ПК
- 🔄 **Интеграция с Hiddify** — прямой импорт подписок
- 🕵 **Парсинг SNI** — автоматическое извлечение SNI из URI

## Требования

- Python 3.10+
- PySide6 (Qt6)
- sing-box (для deep-теста, опционально)
- curl (для загрузки подписок)

## Установка

```bash
# Клонировать
git clone https://github.com/cyberanrhy/proxy-skitchen.git
cd proxy-skitchen

# Установить зависимости
pip install -r requirements.txt

# Запустить (модуль)
python3 -m proxy_skitchen

# Или (монолит)
python3 proxy-skitchen
```

## Использование

1. **Поиск** — введите ключевые слова, URL репозитория или прямую ссылку на подписку
2. **Загрузка** — выберите источники и нажмите «▶ Скачать и проверить»
3. **Тест** — запустите TCP-тест, затем deep-тест через sing-box
4. **Экспорт** — сохраните рабочие прокси в нужном формате

### Режимы производительности

| Режим | TCP-потоки | Deep-потоки | Репозиториев | Файлов |
|-------|-----------|-------------|--------------|--------|
| 🐢 Low | 2 | 1 | 3 | 20 |
| ⚡ Medium | 4 | 2 | 8 | 50 |
| 🚀 High | 8 | 3 | 15 | 150 |

## Структура проекта

```
proxy-skitchen/
├── proxy-skitchen          # Монолит (самодостаточный скрипт)
├── proxy_skitchen/         # Пакет (модульная структура)
│   ├── __init__.py
│   ├── __main__.py         # Точка входа + CLI
│   ├── ui.py               # GUI (PySide6)
│   ├── workers.py          # Фоновые потоки (поиск, загрузка)
│   ├── models.py           # Модели данных + настройки
│   ├── parsers.py          # Парсинг URI (vmess, vless, trojan, ss, hy2, tuic)
│   ├── tester.py           # TCP + Deep-тестирование
│   ├── exporters.py        # Экспорт в форматы
│   └── compat.py           # Совместимость PySide2/PySide6
├── run_proxy_skitchen.py   # Альтернативный запуск
├── requirements.txt        # Зависимости
├── pyproject.toml          # Метаданные пакета
├── LICENSE                 # MIT лицензия
├── README.md               # Документация
└── .gitignore              # Игнорируемые файлы
```

## CLI

```bash
# Поиск подписок
python3 -m proxy_skitchen search "vless subscription" --output sources.txt

# Полный конвейер: поиск → загрузка → TCP-тест → сохранение
python3 -m proxy_skitchen pipeline "vless subscription" --deep --output working.txt

# Тест одного прокси
python3 -m proxy_skitchen test 1.2.3.4 443
```

## Лицензия

MIT

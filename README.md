# proxy-skitchen

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![PySide2](https://img.shields.io/badge/GUI-PySide2-green.svg)](https://wiki.qt.io/Qt_for_Python)

**proxy-skitchen** — графическое приложение для поиска, парсинга, глубокого тестирования (через sing-box) и сохранения прокси-подписок в форматы Hiddify, Clash, sing-box, V2RayN и другие.

Форк [proxy-fetcher-gui](https://github.com/igareck/proxy-fetcher-gui).

## Возможности

- 🔍 **Поиск источников** — парсинг GitHub-репозиториев по ключевым словам
- ⬇ **Загрузка подписок** — многопоточный парсинг proxy-файлов
- ✅ **TCP-тест** — быстрая проверка доступности (host:port, таймаут 12с)
- 🧪 **Deep-тест** — глубокая проверка через sing-box (реальный HTTP-запрос)
- 📦 **Экспорт** — Clash YAML, sing-box JSON, V2RayN TXT, сырые URI
- ⚡ **Три режима производительности** — для слабых и мощных ПК
- 🔄 **Интеграция с Hiddify** — прямой импорт подписок

## Требования

- Python 3.10+
- PySide2 (Qt5)
- sing-box (для deep-теста)
- socks/PySocks

## Установка

```bash
# Клонировать
git clone https://github.com/your-username/proxy-skitchen.git
cd proxy-skitchen

# Установить зависимости
pip install -r requirements.txt

# Запустить
python3 proxy-skitchen
```

## Использование

1. **Поиск** — введите ключевые слова или ссылку на GitHub-репозиторий
2. **Загрузка** — выберите источники и нажмите «⬇ Загрузить»
3. **Тест** — выделите прокси и запустите TCP или deep-тест
4. **Экспорт** — сохраните рабочие прокси в нужном формате

### Режимы производительности

| Режим | TCP-потоки | Deep-потоки | Репозиториев | Файлов |
|-------|-----------|-------------|--------------|--------|
| 🐢 Low | 2 | 1 | 3 | 10 |
| ⚡ Medium | 4 | 2 | 8 | 30 |
| 🚀 High | 8 | 3 | 15 | 50 |

## Структура проекта

```
proxy-skitchen/
├── proxy-skitchen       # Монолитное приложение (~4000 строк)
├── requirements.txt     # Зависимости
├── LICENSE              # MIT лицензия
├── README.md            # Документация
└── .gitignore           # Игнорируемые файлы
```

## Лицензия

MIT

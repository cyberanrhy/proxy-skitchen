# Auto TTS (conditional)

Озвучивай ответ через speak_clean ТОЛЬКО если пользователь сказал одно из слов: расскажи, озвучь, прочитай, скажи, зачитай, speak, say, прочти.

Если пользователь НЕ сказал этих слов — НЕ вызывай speak_clean. Отвечай текстом без озвучки.


# Auto DCP (Dynamic Context Pruning)

Ты сам управляешь контекстом через DCP-команды. Не жди команды пользователя.

Когда диалог превышает ~20 сообщений или содержит 3+ повторяющихся вызова инструментов — автоматически вызывай /dcp sweep для очистки дубликатов и ошибок.

Когда диалог превышает ~30 сообщений — автоматически вызывай /dcp compress для сжатия старого контекста в саммари.

После сжатия НЕ переспрашивай пользователя — просто продолжай работу с очищенным контекстом.


# VPN Proxy Configs (knowledge)

Когда пользователь просит «дай прокси», «нужен впн», «дай конфиг», «нужен прокси» — используй:

## Отфильтрованные конфиги (ru-sni, для белых списков РКН)
- `/home/skitchen/vpn-configs/githubmirror/ru-sni/BLACK_VLESS_RUS.txt` — VLESS (31 конф.)
- `/home/skitchen/vpn-configs/githubmirror/ru-sni/BLACK_VLESS_RUS_mobile.txt` — VLESS mobile (2)
- `/home/skitchen/vpn-configs/githubmirror/ru-sni/BLACK_SS_All_RUS.txt` — SS/hy2/vmess/trojan (9)

## Сырые конфиги (все)
- `/home/skitchen/vpn-configs/BLACK_VLESS_RUS.txt` — 108 VLESS
- `/home/skitchen/vpn-configs/BLACK_VLESS_RUS_mobile.txt` — 155 VLESS mobile
- `/home/skitchen/vpn-configs/BLACK_SS_All_RUS.txt` — 1280 SS/hy2/vmess/trojan

## Дать прокси
```bash
getproxy [количество]
```
Скрипт: `~/.local/bin/getproxy` — выдаёт случайные конфиги из отфильтрованного пула.

## Импорт в Hiddify
CLI: `/usr/share/hiddify/HiddifyCli` (нужен `LD_LIBRARY_PATH=/usr/share/hiddify/lib`)

## Прокси для curl
`http://127.0.0.1:12334` (уже запущен)

## Парсинг SNI
Скрипт: `/home/skitchen/vpn-configs/filter_ru_sni.py` — извлекает SNI из любого URI.

## Обновление
```bash
curl -sL "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt" -o /home/skitchen/vpn-configs/BLACK_VLESS_RUS.txt
cd /home/skitchen/vpn-configs && python3 filter_ru_sni.py
```

---

# Gemini-web2api + opencode integration

## Результаты сессии (03.06.2026)

### Что сделано
- **Исправлена буферизация SSE**: Заменён `self.wfile.write()` на `self.request.sendall()` во всех стриминговых путях (`send_seevent`/`send_json`). Python `BufferedWriter` не отправляет данные в сокет немедленно, из-за чего `fetch()` в Node.js зависал в ожидании данных. `sendall()` решает проблему.
- **Non-streaming тоже переведён на `sendall()`**: в `send_json()` добавлен `self.wfile.flush()` + `self.request.sendall(body)`.
- **Connection: close** добавлен во все SSE-ответы.
- **TCP_NODELAY** включён в `setup()`.
- **Логгирование запросов** добавлено.

### Текущий статус
- ✅ Прокси-сервер (порт 8081) отвечает на запросы curl и AI SDK
- ✅ `@ai-sdk/openai-compatible` (тестовый скрипт в `/tmp/opencode/test_gemini.mjs`) НЕ зависает — non-streaming и streaming завершаются без таймаутов
- ✅ Upstream Gemini отвечает контентом (куки обновлены)
- ✅ `sendall()` вместо `wfile` — фикс буферизации

### Файлы
- `/home/skitchen/gemini-web2api/gemini_web2api.py` — прокси-сервер (исправлен)
- `/home/skitchen/gemini-web2api/config.json` — конфиг (нужен xsrf_token)
- `/home/skitchen/gemini-web2api/cookie.txt` — куки (нужно обновить)
- `/home/skitchen/.config/opencode/opencode.jsonc` — провайдер gemini
- `/tmp/opencode/test_gemini.mjs` — тест AI SDK
- `/tmp/opencode/test_raw.mjs` — тест raw fetch

---

# proxy-skitchen — параллельная разработка

## Файлы
- **На флешке**: `/media/skitchen/SKI/proxy-skitchen`
- **SMB-шара**: `smb://satellite-l850-cjk.local/publicshare/обмен/proxy-skitchen/proxy-skitchen`
- **Ярлык**: `/home/skitchen/Рабочий стол/proxy-skitchen.desktop`
- **AGENTS.md проекта**: `/media/skitchen/SKI/proxy-skitchen/AGENTS.md`

## Протокол синхронизации
1. Перед работой — скачать последнюю версию из SMB-шары
2. После изменений — выложить обратно в SMB-шару

## Работа с opencode
- `proxy-skitchen` — монолит ~4036 строк, PySide2
- Править напрямую файл, потом выкладывать в SMB
- После каждого изменения СНАЧАЛА проверить: `python3 -m py_compile путь`
- Затем протестировать: `timeout 5 python3 путь` (убить через 3с)
- Затем скопировать в SMB-шару
</</parameter>
</parameter>
<parameter name="filePath" string="true">/home/skitchen/AGENTS.md
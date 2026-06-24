"""
Internationalization — простой словарный подход.

_lang = "ru" | "en"
_(key, **kwargs) -> str
set_lang(lang) — переключает язык в settings
"""

from .models import _settings_data, _save_settings

LANGUAGES = {"ru": "Русский", "en": "English"}

_lang = _settings_data.get("language", "ru")
if _lang not in LANGUAGES:
    _lang = "ru"

STRINGS: dict[str, dict[str, str]] = {
    "ru": {
        # ── SourcesPage ──
        "sources.title": "🔍 <b>Шаг 1: Источники</b>",
        "sources.btn.settings.tooltip": "Настройки",
        "sources.btn.stop": "⏹ Стоп",
        "sources.group.github": "GitHub поиск",
        "sources.label.keywords": "Ключевые слова:",
        "sources.input.keywords.placeholder": "vless subscription, trojan, vmess...",
        "sources.label.period": "Период:",
        "sources.label.gh_url": "GitHub URL:",
        "sources.input.gh_url.placeholder": "github.com/owner или github.com/owner/repo",
        "sources.btn.quick_search": "🔍 Быстрый поиск",
        "sources.btn.deep_search": "🔍 Глубокий поиск",
        "sources.label.repo": "Репозиторий:",
        "sources.input.repo.placeholder": "github.com/owner/repo (опционально)",
        "sources.btn.search": "🔍 Искать на GitHub",
        "sources.group.manual_url": "URL вручную",
        "sources.input.url.placeholder": "https://example.com/subscription",
        "sources.btn.add_url": "+ Добавить",
        "sources.label.subscriptions": "Подписки:",
        "sources.btn.clear": "✕ Очистить",
        "sources.btn.fetch": "▶ Скачать и проверить",
        "sources.context.remove": "🗑 Удалить",
        
        "preset.vless": "vless подписка",
        "preset.vmess": "vmess подписка",
        "preset.trojan": "trojan подписка",
        "preset.ss": "shadowsocks подписка",
        "preset.v2ray_cfg": "v2ray конфиг",
        "preset.v2ray_sub": "v2ray подписка",
        "preset.proxy": "proxy подписка",
        "preset.clash": "clash подписка",
        "preset.singbox": "sing-box подписка",
        "preset.free": "бесплатные прокси",
        "preset.xray": "xray конфиг",
        "preset.hysteria2": "hysteria2 подписка",

        # ── period combo (нейтральные) ──
        "period.1h": "1h",
        "period.2h": "2h",
        "period.4h": "4h",
        "period.6h": "6h",
        "period.8h": "8h",
        "period.12h": "12h",
        "period.24h": "24h",
        "period.3d": "3d",
        "period.7d": "7d",

        # ── GH search status ──
        "gh.searching": "🔍 Поиск: {kw}",
        "gh.stopped": "⏹ Остановлено ({count} файлов)",
        "gh.repo_url": "📁 GitHub репозиторий: {repo} — запускаю поиск...",
        "gh.found_files": "✅ Найдено {count} файлов",
        "gh.keyword": "🔍 Ключевое слово: {kw}",
        "gh.scanning": "📂 Сканирую: {repo} ⭐{stars}",
        "gh.repo_scan": "📁 Репозиторий: {path}",
        "gh.file_scan": "📄 Файл: {path}",
        "gh.embed_prefix": "📦 {name}",

        # ── TestPage ──
        "test.title": "⚡ <b>Шаг 2: Тестирование</b>",
        "test.btn.stop": "⏹ Стоп",
        "test.btn.stop_fetch": "⏹ Стоп загрузку",
        "test.btn.stop_test": "⏹ Стоп тест",
        "test.btn.back": "← Назад",
        "test.group.sources": "Источники",
        "test.table.source": "Источник",
        "test.table.proxies": "Прокси",
        "test.stats.total": "📦 Всего: {count}",
        "test.stats.valid": "✅ Валид: {count}",
        "test.stats.dead": "❌ Мертв: {count}",
        "test.stats.waiting": "⏳ Ожид: {count}",
        "test.btn.tcp": "▶ TCP тест",
        "test.btn.deep": "⚡ Deep тест",
        "test.btn.continue": "▶ Продолжить",
        "test.btn.delete_dead": "🗑 Удалить мёртвые",
        "test.btn.export": "▶ Экспорт →",
        "test.btn.geo": "🌍 Geo",
        "test.phase.fetch": "📥 Загрузка источников...",
        "test.phase.test": "⚡ Тестирование...",
        "test.phase.geo": "🌍 Геолокация...",
        "test.threads": "Потоков:",
        "test.filter.all": "Все",
        "test.filter.tuic": "TUIC",
        "test.filter.vless": "VLESS",
        "test.filter.vmess": "VMESS",
        "test.filter.trojan": "Trojan",
        "test.filter.ss": "SS",
        "test.filter.hy2": "Hy2",
        "test.context.copy_uri": "📋 Копировать URI",
        "test.context.details": "ℹ Детали",
        "test.context.details_text": "{proto} {host}:{port}\nSNI: {sni}\nСтрана: {country}\nTCP: {tcp}\nDeep: {deep}\nПинг: {ping}ms",
        "test.context.country": "Страна: {country}",

        # ── log messages ──
        "log.fetch_start": "Загрузка {count} источников...",
        "log.fetch_done": "✅ Загружено: {count} прокси",
        "log.fetch_stopped": "⏹ Загрузка остановлена: {count} прокси",
        "log.test_done": "✅ Тест завершён: {valid}/{total} валидных",
        "log.test_stopped": "⏹ Тест остановлен",
        "log.test_resumed": "▶ Возобновлён тест: {count} прокси",
        "log.geo_start": "🌍 Геолокация {count} IP...",
        "log.geo_done": "🌍 Гео: {count}",
        "log.geo_stopped": "⏹ Геолокация остановлена",
        "log.deleted_dead": "🗑 Удалено {count} мёртвых прокси",
        "log.no_dead": "Мёртвых прокси нет.",
        "log.no_dead_to_delete": "Нет мёртвых прокси для удаления.",

        # ── ExportPage ──
        "export.title": "📤 <b>Шаг 3: Экспорт</b>",
        "export.btn.back": "← Назад",
        "export.group.format": "Формат",
        "export.radio.raw": "📄 RAW URI (одна строка = один прокси)",
        "export.radio.v2rayn": "🔤 V2RayN / base64",
        "export.radio.singbox": "📦 Sing-box JSON",
        "export.radio.clash": "🌐 Clash YAML",
        "export.radio.hiddify": "🏠 Hiddify (RAW)",
        "export.group.options": "Опции",
        "export.chk.failed": "Включать непроверенные (failed)",
        "export.chk.smart_names": "Умные имена (🇩🇪 1 - DE - VLESS - 443)",
        "export.chk.clean_names": "Очищенные имена (без эмодзи)",
        "export.btn.copy": "📋 В буфер обмена",
        "export.btn.save": "💾 Сохранить в файл",
        "export.btn.save_desktop": "🖥 На рабочий стол",
        "export.label.preview": "Предпросмотр:",
        "export.stats": "📦 Всего: {total}  |  ✅ TCP: {tcp}  |  ⚡ Deep: {deep}",

        # ── MainWindow ──
        "main.title": "Proxy Skitchen",
        "main.proxy_toggle": "🔌 Прокси",
        "main.proxy_toggle_on": "🔌 Прокси ✅",
        "main.proxy_toggle_off": "🔌 Прокси ❌",
        "main.btn.prev": "← Шаг 1",
        "main.btn.next": "Шаг 2 →",
        "main.btn.next_step3": "Шаг 3 →",
        "main.btn.done": "✅ Готово",
        "main.page.title.1": "Шаг 1/3: Источники",
        "main.page.title.2": "Шаг 2/3: Тестирование",
        "main.page.title.3": "Шаг 3/3: Экспорт",

        # ── DownloadPage ──
        "download.title": "📥 <b>Загрузка</b>",
        "download.btn.stop": "⏹ Стоп",
        "download.btn.stop_fetch": "⏹ Стоп загрузку",
        "download.btn.back": "← Назад",
        "download.btn.next": "Тестирование →",
        "download.group.sources": "Источники",
        "download.table.source": "Источник",
        "download.table.proxies": "Прокси",
        "download.hide_sources": "▲ Скрыть",
        "download.show_sources": "▼ Показать ({count})",
        "download.stats.total": "📦 Всего: {count}",
        "download.stats.detail": "📦 {total} | {sources_ok} | {duration} | {protos}",
        "download.stats.protocol": "{proto}: {count}",
        "download.stats.sources_ok": "✅ {ok}/{total}",
        "download.stats.duration": "⏱ {secs}s",
        "download.phase.fetch": "📥 Загрузка источников...",

        # ── SettingsDialog ──
        "settings.title": "⚙ Настройки",
        "settings.tab.general": "Общие",
        "settings.label.performance": "Производительность:",
        "settings.chk.proxy": "Использовать прокси для загрузки",
        "settings.label.type": "Тип:",
        "settings.label.host": "Хост:",
        "settings.label.port": "Порт:",
        "settings.tab.github": "GitHub",
        "settings.label.tokens": "GitHub Personal Access Tokens (по одному на строку):",
        "settings.input.tokens.placeholder": "ghp_xxxxxxxx...\ngho_yyyyyyyy...",
        "settings.btn.check_token": "🔍 Проверить токен",
        "settings.token.checking": "⏳ Проверка...",
        "settings.token.none": "Нет токенов",
        "settings.token.ok": "✅ {login} — лимит: {limit}/ч",
        "settings.token.error": "❌ {error}",
        "settings.label.language": "Язык:",
        "settings.label.gh_url_hint": "GitHub URL (опционально):",
        "settings.label.lang_desc": "Язык интерфейса",
        "settings.perf.low": "low 🐢",
        "settings.perf.medium": "medium ⚡",
        "settings.perf.high": "high 🚀",

        # ── Messages ──
        "msg.warning": "Внимание",
        "msg.info": "Инфо",
        "msg.done": "Готово",
        "msg.no_keywords": "Введи ключевые слова или укажи репозиторий.",
        "msg.copied": "Скопировано в буфер обмена",
        "msg.saved": "Сохранено:\n{path}",
        "msg.all_done": "Все шаги выполнены.\nИспользуй кнопки «Сохранить» на Шаге 3 для экспорта.",
        "msg.no_data": "Нет данных",
        "msg.no_data_text": "Нет прокси для сохранения.",

        # ── Event window ──
        "event.title": "⚡ Событие",
        "event.tcp": "TCP",
        "event.deep": "DEEP",
        "event.ok": "✅",
        "event.fail": "❌",
        "event.test_current": "#{n} {mark} {kind} {proto} {host}:{port}",
        "event.test_progress": "{mode}: {done}/{total} ({pct}%)",
        "event.threads": "{mode}: {done}/{total} ({threads} потоков)",
    },

    "en": {
        # ── SourcesPage ──
        "sources.title": "🔍 <b>Step 1: Sources</b>",
        "sources.btn.settings.tooltip": "Settings",
        "sources.btn.stop": "⏹ Stop",
        "sources.group.github": "GitHub Search",
        "sources.label.keywords": "Keywords:",
        "sources.input.keywords.placeholder": "vless subscription, trojan, vmess...",
        "sources.label.period": "Period:",
        "sources.label.gh_url": "GitHub URL:",
        "sources.input.gh_url.placeholder": "github.com/owner or github.com/owner/repo",
        "sources.btn.quick_search": "🔍 Quick Search",
        "sources.btn.deep_search": "🔍 Deep Search",
        "sources.label.repo": "Repository:",
        "sources.input.repo.placeholder": "github.com/owner/repo (optional)",
        "sources.btn.search": "🔍 Search GitHub",
        "sources.group.manual_url": "Manual URL",
        "sources.input.url.placeholder": "https://example.com/subscription",
        "sources.btn.add_url": "+ Add",
        "sources.label.subscriptions": "Subscriptions:",
        "sources.btn.clear": "✕ Clear",
        "sources.btn.fetch": "▶ Download & Test",
        "sources.context.remove": "🗑 Remove",

        "preset.vless": "vless subscription",
        "preset.vmess": "vmess subscription",
        "preset.trojan": "trojan subscription",
        "preset.ss": "shadowsocks subscription",
        "preset.v2ray_cfg": "v2ray config",
        "preset.v2ray_sub": "v2ray subscription",
        "preset.proxy": "proxy subscription",
        "preset.clash": "clash subscription",
        "preset.singbox": "sing-box subscription",
        "preset.free": "free proxy config",
        "preset.xray": "xray config",
        "preset.hysteria2": "hysteria2 subscription",

        # ── period combo (нейтральные) ──
        "period.1h": "1h",
        "period.2h": "2h",
        "period.4h": "4h",
        "period.6h": "6h",
        "period.8h": "8h",
        "period.12h": "12h",
        "period.24h": "24h",
        "period.3d": "3d",
        "period.7d": "7d",

        # ── GH search status ──
        "gh.searching": "🔍 Searching: {kw}",
        "gh.stopped": "⏹ Stopped ({count} files)",
        "gh.repo_url": "📁 GitHub repo: {repo} — searching...",
        "gh.found_files": "✅ Found {count} files",
        "gh.keyword": "🔍 Keyword: {kw}",
        "gh.scanning": "📂 Scanning: {repo} ⭐{stars}",
        "gh.repo_scan": "📁 Repo: {path}",
        "gh.file_scan": "📄 File: {path}",
        "gh.embed_prefix": "📦 {name}",

        # ── TestPage ──
        "test.title": "⚡ <b>Step 2: Testing</b>",
        "test.btn.stop": "⏹ Stop",
        "test.btn.stop_fetch": "⏹ Stop Fetch",
        "test.btn.stop_test": "⏹ Stop Test",
        "test.btn.back": "← Back",
        "test.group.sources": "Sources",
        "test.table.source": "Source",
        "test.table.proxies": "Proxies",
        "test.stats.total": "📦 Total: {count}",
        "test.stats.valid": "✅ Valid: {count}",
        "test.stats.dead": "❌ Dead: {count}",
        "test.stats.waiting": "⏳ Wait: {count}",
        "test.btn.tcp": "▶ TCP Test",
        "test.btn.deep": "⚡ Deep Test",
        "test.btn.continue": "▶ Continue",
        "test.btn.delete_dead": "🗑 Delete Dead",
        "test.btn.export": "▶ Export →",
        "test.btn.geo": "🌍 Geo",
        "test.phase.fetch": "📥 Fetching sources...",
        "test.phase.test": "⚡ Testing...",
        "test.phase.geo": "🌍 Geolocation...",
        "test.threads": "Threads:",
        "test.filter.all": "All",
        "test.filter.tuic": "TUIC",
        "test.filter.vless": "VLESS",
        "test.filter.vmess": "VMESS",
        "test.filter.trojan": "Trojan",
        "test.filter.ss": "SS",
        "test.filter.hy2": "Hy2",
        "test.context.copy_uri": "📋 Copy URI",
        "test.context.details": "ℹ Details",
        "test.context.details_text": "{proto} {host}:{port}\nSNI: {sni}\nCountry: {country}\nTCP: {tcp}\nDeep: {deep}\nPing: {ping}ms",
        "test.context.country": "Country: {country}",

        # ── log messages ──
        "log.fetch_start": "Fetching {count} sources...",
        "log.fetch_done": "✅ Fetched: {count} proxies",
        "log.fetch_stopped": "⏹ Fetch stopped: {count} proxies",
        "log.test_done": "✅ Test complete: {valid}/{total} valid",
        "log.test_stopped": "⏹ Test stopped",
        "log.test_resumed": "▶ Resumed test: {count} proxies",
        "log.geo_start": "🌍 Geolocating {count} IPs...",
        "log.geo_done": "🌍 Geo: {count}",
        "log.geo_stopped": "⏹ Geo stopped",
        "log.deleted_dead": "🗑 Deleted {count} dead proxies",
        "log.no_dead": "No dead proxies.",
        "log.no_dead_to_delete": "No dead proxies to delete.",

        # ── ExportPage ──
        "export.title": "📤 <b>Step 3: Export</b>",
        "export.btn.back": "← Back",
        "export.group.format": "Format",
        "export.radio.raw": "📄 RAW URI (one per line)",
        "export.radio.v2rayn": "🔤 V2RayN / base64",
        "export.radio.singbox": "📦 Sing-box JSON",
        "export.radio.clash": "🌐 Clash YAML",
        "export.radio.hiddify": "🏠 Hiddify (RAW)",
        "export.group.options": "Options",
        "export.chk.failed": "Include failed",
        "export.chk.smart_names": "Smart names (🇩🇪 1 - DE - VLESS - 443)",
        "export.chk.clean_names": "Clean names (no emoji)",
        "export.btn.copy": "📋 Copy to Clipboard",
        "export.btn.save": "💾 Save to File",
        "export.btn.save_desktop": "🖥 Save to Desktop",
        "export.label.preview": "Preview:",
        "export.stats": "📦 Total: {total}  |  ✅ TCP: {tcp}  |  ⚡ Deep: {deep}",

        # ── MainWindow ──
        "main.title": "Proxy Skitchen",
        "main.proxy_toggle": "🔌 Proxy",
        "main.proxy_toggle_on": "🔌 Proxy ✅",
        "main.proxy_toggle_off": "🔌 Proxy ❌",
        "main.btn.prev": "← Step 1",
        "main.btn.next": "Step 2 →",
        "main.btn.next_step3": "Step 3 →",
        "main.btn.done": "✅ Done",
        "main.page.title.1": "Step 1/3: Sources",
        "main.page.title.2": "Step 2/3: Testing",
        "main.page.title.3": "Step 3/3: Export",

        # ── DownloadPage ──
        "download.title": "📥 <b>Download</b>",
        "download.btn.stop": "⏹ Stop",
        "download.btn.stop_fetch": "⏹ Stop Fetch",
        "download.btn.back": "← Back",
        "download.btn.next": "Testing →",
        "download.group.sources": "Sources",
        "download.table.source": "Source",
        "download.table.proxies": "Proxies",
        "download.hide_sources": "▲ Hide",
        "download.show_sources": "▼ Show ({count})",
        "download.stats.total": "📦 Total: {count}",
        "download.stats.detail": "📦 {total} | {sources_ok} | {duration} | {protos}",
        "download.stats.protocol": "{proto}: {count}",
        "download.stats.sources_ok": "✅ {ok}/{total}",
        "download.stats.duration": "⏱ {secs}s",
        "download.phase.fetch": "📥 Fetching sources...",

        # ── SettingsDialog ──
        "settings.title": "⚙ Settings",
        "settings.tab.general": "General",
        "settings.label.performance": "Performance:",
        "settings.chk.proxy": "Use proxy for downloads",
        "settings.label.type": "Type:",
        "settings.label.host": "Host:",
        "settings.label.port": "Port:",
        "settings.tab.github": "GitHub",
        "settings.label.tokens": "GitHub Personal Access Tokens (one per line):",
        "settings.input.tokens.placeholder": "ghp_xxxxxxxx...\ngho_yyyyyyyy...",
        "settings.btn.check_token": "🔍 Check Token",
        "settings.token.checking": "⏳ Checking...",
        "settings.token.none": "No tokens",
        "settings.token.ok": "✅ {login} — limit: {limit}/h",
        "settings.token.error": "❌ {error}",
        "settings.label.language": "Language:",
        "settings.label.lang_desc": "Interface language",
        "settings.label.gh_url_hint": "GitHub URL (optional):",
        "settings.perf.low": "low 🐢",
        "settings.perf.medium": "medium ⚡",
        "settings.perf.high": "high 🚀",

        # ── Messages ──
        "msg.warning": "Warning",
        "msg.info": "Info",
        "msg.done": "Done",
        "msg.no_keywords": "Enter keywords or specify a repository.",
        "msg.copied": "Copied to clipboard",
        "msg.saved": "Saved:\n{path}",
        "msg.all_done": "All steps complete.\nUse Save buttons on Step 3 to export.",
        "msg.no_data": "No data",
        "msg.no_data_text": "No proxies to save.",

        # ── Event window ──
        "event.title": "⚡ Event",
        "event.tcp": "TCP",
        "event.deep": "DEEP",
        "event.ok": "✅",
        "event.fail": "❌",
        "event.test_current": "#{n} {mark} {kind} {proto} {host}:{port}",
        "event.test_progress": "{mode}: {done}/{total} ({pct}%)",
        "event.threads": "{mode}: {done}/{total} ({threads} threads)",
    },
}


def _(key: str, **kwargs) -> str:
    """Look up a localized string. Falls back to RU, then returns key."""
    lang_dict = STRINGS.get(_lang, {})
    text = lang_dict.get(key)
    if text is None:
        text = STRINGS["ru"].get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError:
            pass
    return text


def current_lang() -> str:
    return _lang


def set_lang(lang: str):
    global _lang
    if lang not in LANGUAGES:
        lang = "ru"
    _lang = lang
    _settings_data["language"] = lang
    _save_settings(_settings_data)

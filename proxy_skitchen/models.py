import json, base64, urllib.parse
from .compat import *

def country_flag(code: str) -> str:
    if len(code) != 2:
        return ""
    code = code.upper()
    return chr(ord(code[0]) - ord("A") + 0x1F1E6) + chr(ord(code[1]) - ord("A") + 0x1F1E6)

_GOOD_SNI_DOMAINS = {
    'bing.com', 'microsoft.com', 'apple.com', 'icloud.com', 'office.com', 'office365.com',
    'azure.com', 'windows.com', 'live.com', 'outlook.com', 'skype.com', 'yammer.com',
    'powerbi.com', 'sharepoint.com', 'dynamics.com', 'samsung.com', 'nvidia.com',
    'amd.com', 'intel.com', 'adobe.com', 'cloudflare.com', 'cloudflare-nginx.com',
    'cloudflare.net', 'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com',
    'ytimg.com', 'ggpht.com', 'blogger.com', 'blogspot.com', 'android.com',
    'googlevideo.com', 'googleusercontent.com', 'google-analytics.com', 'goo.gl',
    'facebook.com', 'fbcdn.net', 'messenger.com', 'instagram.com', 'whatsapp.com',
    'cdninstagram.com', 'telegram.org', 't.me', 'tdesktop.com', 'speedtest.net',
    'ooklaserver.net', 'cdn.jsdelivr.net', 'jsdelivr.net', 'github.com', 'github.io',
    'githubusercontent.com', 'cloudfront.net', 'aws.amazon.com', 'amazonaws.com',
    'amazon.com', 'aws.com', 'twitch.tv', 'twitter.com', 'x.com', 't.co',
    'discord.com', 'discordapp.com', 'spotify.com', 'scdn.co', 'reddit.com',
    'redditmedia.com', 'quic.cloud', 'bootstrapcdn.com', 'cdnjs.cloudflare.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
    'stackpathcdn.com', 'akamaiedge.net', 'akamaihd.net', 'edgesuite.net',
    'azureedge.net', 'azurefd.net', 'trafficmanager.net', 'servicebus.windows.net',
    'v2ex.com', 'v2ex.co', 'ipapi.co', 'ip-api.com', 'ipinfo.io',
    'vl.mccncs.com', 'mccncs.com', 'mmccncs.com', 'aztec.buzz',
    'analytics.google.com', 'stats.g.doubleclick.net', 'adservice.google.com',
    'pagead2.googlesyndication.com', 'googlesyndication.com', 'doubleclick.net',
    'googleadservices.com', 'googleads.g.doubleclick.net', 'pubads.g.doubleclick.net',
    'yandex.ru', 'yastatic.net', 'yandex.net', 'yadi.sk', 'disk.yandex.ru',
}

PROTOCOL_PREFIXES = (
    'vless://', 'vmess://', 'trojan://', 'ss://', 'shadowsocks://',
    'hysteria2://', 'hy2://', 'hysteria://', 'hy://', 'tuic://',
    'socks5://', 'socks4://', 'http://', 'https://', 'naive+',
    'wireguard://', 'wg://',
)

PERF_PRESETS = {
    "low": {"max_repos": 10, "max_files": 20},
    "medium": {"max_repos": 30, "max_files": 50},
    "high": {"max_repos": 100, "max_files": 150},
}

THEMES = {
    "dark": {
        "bg": "#1a1b26",
        "fg": "#a9b1d6",
        "input_bg": "#16161e",
        "button_bg": "#1f2335",
        "border": "#292e42",
        "accent": "#7aa2f7",
    },
    "light": {
        "bg": "#f8f9fa",
        "fg": "#343a40",
        "input_bg": "#ffffff",
        "button_bg": "#e9ecef",
        "border": "#dee2e6",
        "accent": "#0d6efd",
    }
}


DEFAULT_SETTINGS = {
    "proxy_enabled": True, "proxy_type": "http", "proxy_host": "127.0.0.1",
    "proxy_port": 12334, "perf_mode": "medium", "sources": [], "language": "en",
    "theme": "dark",
    "proxy_cache": [],
}

def current_theme() -> str:
    return _settings_data.get("theme", "dark")


def set_theme(theme: str):
    if theme in THEMES:
        _settings_data["theme"] = theme
        _save_settings(_settings_data)

class ProxyEntry:
    __slots__ = ('uri', 'protocol', 'host', 'port', 'sni', 'country', 'source',
                 'tcp_ok', 'deep_ok', 'latency_ms', 'deep_error', 'is_embedded',
                 'tcp_tested', 'deep_tested')

    def __init__(self, uri: str, source: str = ""):
        self.uri = uri
        self.protocol = ""
        self.host = ""
        self.port = 0
        self.sni = ""
        self.country = ""
        self.source = source
        self.tcp_ok = False
        self.deep_ok = False
        self.latency_ms = 0.0
        self.deep_error = ""
        self.is_embedded = False
        self.tcp_tested = False
        self.deep_tested = False
        self._parse()

    def _parse(self):
        try:
            uri_lower = self.uri.lower()
            if uri_lower.startswith('vmess://'):
                self.protocol = 'VMESS'
                try:
                    b64 = self.uri[8:]
                    pad = 4 - len(b64) % 4
                    if pad != 4:
                        b64 += '=' * pad
                    decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                    data = json.loads(decoded)
                    self.host = data.get('add', '') or data.get('host', '')
                    self.port = int(data.get('port', 0))
                    self.sni = data.get('sni', '') or data.get('host', '')
                except Exception:
                    pass
                return
            if uri_lower.startswith('ss://') or uri_lower.startswith('shadowsocks://'):
                self.protocol = 'SS'
                try:
                    clean = self.uri[5:] if uri_lower.startswith('ss://') else self.uri[14:]
                    clean = clean.split('#')[0].split('?')[0]
                    # Try base64 decode first (new format: ss://base64(method:pass@host:port))
                    try:
                        pad = 4 - len(clean) % 4
                        if pad != 4:
                            clean += '=' * pad
                        decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
                        if '@' in decoded:
                            host_part = decoded.split('@', 1)[1]
                            if ':' in host_part:
                                self.host, port_str = host_part.rsplit(':', 1)
                                self.port = int(port_str)
                    except Exception:
                        pass
                    if not self.host:
                        # Old format: ss://method:pass@host:port
                        if '@' in clean:
                            host_part = clean.split('@', 1)[1]
                            if ':' in host_part:
                                self.host, port_str = host_part.rsplit(':', 1)
                                self.port = int(port_str)
                            else:
                                self.host = host_part
                        else:
                            self.host = clean
                except Exception:
                    pass
                return
            u = urllib.parse.urlparse(self.uri)
            self.protocol = u.scheme.rstrip(':').upper()
            self.host = u.hostname or ""
            self.port = u.port or 0
            if u.password:
                self.sni = urllib.parse.unquote(u.password)
            elif u.query:
                qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
                for k in ('sni', 'peer', 'host', 'servername'):
                    if qs.get(k):
                        self.sni = qs[k][0]
                        break
            # extract from fragment
            if not self.sni and u.fragment:
                import html
                frag = html.unescape(u.fragment)
                if '📡' in frag:
                    parts = frag.split('📡')
                    if len(parts) > 1:
                        self.country = parts[1].strip()
        except Exception:
            pass

    def key(self) -> str:
        return f"{self.host}:{self.port}"

    def display_protocol(self) -> str:
        p = self.protocol
        if p in ('VLESS', 'VMESS', 'TROJAN', 'HYSTERIA2', 'HY2', 'TUIC', 'WIREGUARD', 'WG', 'NAIVE+'):
            return p
        return p

    def status_emoji(self) -> str:
        if self.deep_ok: return "⚡"
        if self.tcp_ok: return "✅"
        return "❌"

    def __repr__(self):
        return f"<{self.status_emoji()} {self.display_protocol()} {self.host}:{self.port}>"


def _load_settings() -> dict:
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return dict(DEFAULT_SETTINGS)


def _save_settings(data: dict):
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, SETTINGS_FILE)


def _load_auth() -> dict:
    try:
        if os.path.exists(AUTH_FILE):
            with open(AUTH_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"github_tokens": []}


def _save_auth(data: dict):
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


_auth_data = _load_auth()
_settings_data = _load_settings()

if not _auth_data.get("github_tokens") and _settings_data.get("github_tokens"):
    _auth_data["github_tokens"] = _settings_data.pop("github_tokens")
    _save_auth(_auth_data)
if not _auth_data.get("github_tokens") and _settings_data.get("github_token"):
    _auth_data["github_tokens"] = [_settings_data["github_token"]]
    del _settings_data["github_token"]
    _save_auth(_auth_data)
_settings_data.pop("github_tokens", None)


class ProxyTableModel(QAbstractTableModel):
    HEADERS = ["", "Протокол", "Хост", "Порт", "Страна", "Пинг", "Статус"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proxies: list[ProxyEntry] = []

    def rowCount(self, parent=None):
        return len(self.proxies)

    def columnCount(self, parent=None):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        p = self.proxies[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 1: return p.display_protocol()
            if col == 2: return p.host
            if col == 3: return str(p.port) if p.port else ""
            if col == 4: return p.country
            if col == 5: return f"{p.latency_ms:.0f}ms" if p.latency_ms else ""
        if role == Qt.ItemDataRole.DecorationRole and col == 0:
            return None
        if role == Qt.ItemDataRole.ForegroundRole:
            if p.deep_ok: return QColor("#00e676")
            if p.tcp_ok: return QColor("#69f0ae")
            return QColor("#ff5252")
        if role == Qt.ItemDataRole.ToolTipRole:
            return f"{p.display_protocol()} {p.host}:{p.port}\nSNI: {p.sni or '-'}\nСтрана: {p.country or '-'}\nИсточник: {p.source or '-'}\nTCP: {'✅' if p.tcp_ok else '❌'}  Deep: {'⚡' if p.deep_ok else '-'}  Пинг: {f'{p.latency_ms:.0f}ms' if p.latency_ms else '-'}"
        return None

    def add_proxies(self, entries: list[ProxyEntry]):
        if not entries:
            return
        self.beginInsertRows(QModelIndex(), len(self.proxies), len(self.proxies) + len(entries) - 1)
        self.proxies.extend(entries)
        self.endInsertRows()

    def update_entry(self, row: int, ok: bool, latency: float, error: str, ttype: int):
        if 0 <= row < len(self.proxies):
            p = self.proxies[row]
            if ttype == 0:
                p.tcp_ok = ok
                p.tcp_tested = True
                p.latency_ms = latency
            else:
                p.deep_ok = ok
                p.deep_tested = True
                p.deep_error = error
            self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.HEADERS) - 1))

    def clear(self):
        self.beginResetModel()
        self.proxies.clear()
        self.endResetModel()

    def dedup_by_key(self, prefer_deep: bool = True):
        seen = {}
        for p in self.proxies:
            k = p.key()
            if k not in seen:
                seen[k] = p
            else:
                existing = seen[k]
                if prefer_deep:
                    if p.deep_ok and not existing.deep_ok:
                        seen[k] = p
                    elif p.tcp_ok and not existing.tcp_ok and not existing.deep_ok:
                        seen[k] = p
                else:
                    if p.tcp_ok and not existing.tcp_ok:
                        seen[k] = p
        deduped = list(seen.values())
        self.beginResetModel()
        self.proxies = deduped
        self.endResetModel()
        return len(deduped)

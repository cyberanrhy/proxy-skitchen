import json, base64, urllib.parse
from .compat import *

_FLAG_CACHE: dict[str, str] = {}


def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    cached = _FLAG_CACHE.get(code)
    if cached is not None:
        return cached
    flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    _FLAG_CACHE[code] = flag
    return flag

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
        "bg": "#181c2e",
        "fg": "#d8dee9",
        "input_bg": "#1e2338",
        "button_bg": "#282e45",
        "border": "#363d57",
        "accent": "#5b8def",
        "success": "#74c7a0",
        "success_bg": "#1a2e26",
        "success_border": "#2d4d3e",
        "danger": "#e36262",
        "danger_bg": "#2e1a1e",
        "danger_border": "#523238",
        "warning": "#ebcb8b",
        "warning_bg": "rgba(235,203,139,0.10)",
        "warning_border": "rgba(235,203,139,0.3)",
        "muted": "#4a5168",
        "muted_fg": "#7c89a8",
        "table_ok_bg": "#1a2e26",
        "table_ok_fg": "#74c7a0",
        "table_fail_bg": "#2e1a1e",
        "table_fail_fg": "#e36262",
        "ping_fast": "#00e676",
        "ping_med": "#ffd740",
        "ping_slow": "#ff6d00",
        "ping_dead": "#ff5252",
        "accent2": "#7c5cbf",
        "progress_bg": "#1e293b",
        "code_bg": "#1a1d23",
        "code_fg": "#cdd6f4",
        "tab_muted": "#6b7089",
        "tab_hover_bg": "rgba(255,255,255,0.04)",
    },
    "light": {
        "bg": "#f5f2ed",
        "fg": "#3d424a",
        "input_bg": "#ffffff",
        "button_bg": "#e6e2da",
        "border": "#d0cbc0",
        "accent": "#5f8bc8",
        "success": "#2e7d32",
        "success_bg": "#e8f5e9",
        "success_border": "#a5d6a7",
        "danger": "#c62828",
        "danger_bg": "#ffebee",
        "danger_border": "#ef9a9a",
        "warning": "#f57f17",
        "warning_bg": "rgba(245,127,23,0.08)",
        "warning_border": "rgba(245,127,23,0.25)",
        "muted": "#9e9e9e",
        "muted_fg": "#616161",
        "table_ok_bg": "#e8f5e9",
        "table_ok_fg": "#2e7d32",
        "table_fail_bg": "#ffebee",
        "table_fail_fg": "#c62828",
        "ping_fast": "#2e7d32",
        "ping_med": "#b26a00",
        "ping_slow": "#ef6c00",
        "ping_dead": "#c62828",
        "accent2": "#6a4fb8",
        "progress_bg": "#e0e0e0",
        "code_bg": "#f5f2ed",
        "code_fg": "#3d424a",
        "tab_muted": "#8a8f9e",
        "tab_hover_bg": "rgba(0,0,0,0.04)",
    }
}


DEFAULT_SETTINGS = {
    "proxy_enabled": True, "proxy_type": "http", "proxy_host": "127.0.0.1",
    "proxy_port": 12334, "perf_mode": "medium", "sources": [], "language": "en",
    "theme": "dark",
    "default_repo": "",
    "proxy_cache": [],
    "clean_uris": True,
    "sub_title": "My Subscription",
}

def current_theme() -> str:
    return _settings_data.get("theme", "dark")


def set_theme(theme: str):
    if theme in THEMES:
        _settings_data["theme"] = theme
        _save_settings(_settings_data)

_VALID_NETWORKS = {
    'tcp', 'ws', 'websocket', 'grpc', 'http', 'kcp', 'quic', 'xhttp',
}


def sanitize_network(uri: str) -> str:
    """Repair invalid network types so Xray/Sing-box cores accept the config.

    Both cores reject unknown network types (e.g. 'raw', 'none') with a core
    error on load. We map 'websocket' -> 'ws' and any other invalid value ->
    'tcp' (always valid), so the config at least loads; the connection is then
    re-validated by the app's own tester.
    """
    low = uri.lower()
    if low.startswith('vmess://'):
        try:
            b64 = uri[8:]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += '=' * pad
            data = json.loads(base64.b64decode(b64, validate=False).decode('utf-8', errors='ignore'))
            if not isinstance(data, dict):
                return uri
            net = (data.get('net') or '').strip().lower()
            if net and net not in _VALID_NETWORKS:
                data['net'] = 'ws' if net == 'websocket' else 'tcp'
            new_b64 = base64.b64encode(
                json.dumps(data, ensure_ascii=True).encode('utf-8')
            ).decode('ascii')
            return 'vmess://' + new_b64
        except Exception:
            return uri
        return uri

    if '://' not in uri:
        return uri
    scheme, rest = uri.split('://', 1)
    if scheme.lower() not in ('vless', 'trojan', 'hysteria2', 'hy2',
                              'tuic', 'socks5', 'socks4', 'socks'):
        return uri
    frag = ''
    if '#' in rest:
        rest, frag = rest.split('#', 1)
    if '?' not in rest:
        return uri
    base, q = rest.split('?', 1)
    params = urllib.parse.parse_qsl(q, keep_blank_values=True)
    changed = False
    has_fp = False
    out_params = []
    for k, v in params:
        kl = k.lower()
        if kl == 'type':
            nv = (v or '').strip().lower()
            if nv and nv not in _VALID_NETWORKS:
                v = 'ws' if nv == 'websocket' else 'tcp'
                changed = True
        elif kl == 'fp':
            has_fp = True
            nv = (v or '').strip().lower()
            if nv and nv not in ('chrome', 'firefox', 'edge'):
                v = 'chrome'
                changed = True
        out_params.append((k, v))
    if scheme.lower() == 'vless':
        sec = dict((k.lower(), val) for k, val in params).get('security', '').lower()
        if sec == 'reality' and not has_fp:
            out_params.append(('fp', 'chrome'))
            changed = True
    if not changed:
        return uri
    new_q = urllib.parse.urlencode(out_params)
    result = f"{scheme}://{base}?{new_q}"
    if frag:
        result += '#' + frag
    return result


class ProxyEntry:
    __slots__ = ('uri', 'protocol', 'host', 'port', 'sni', 'country', 'source',
                 'tcp_ok', 'deep_ok', 'rkn_ok', 'latency_ms', 'deep_error', 'is_embedded',
                 'tcp_tested', 'deep_tested', 'rkn_tested', 'geo_tested', 'rkn_results',
                 'security', '_clean_uri')

    def __init__(self, uri: str, source: str = ""):
        from .parsers import normalize_uri
        self.uri = sanitize_network(normalize_uri(uri))
        self.protocol = ""
        self.host = ""
        self.port = 0
        self.sni = ""
        self.country = ""
        self.source = source
        self.tcp_ok = False
        self.deep_ok = False
        self.rkn_ok = False
        self.latency_ms = 0.0
        self.deep_error = ""
        self.is_embedded = False
        self.tcp_tested = False
        self.deep_tested = False
        self.rkn_tested = False
        self.geo_tested = False
        self.rkn_results = []
        self.security = ""
        self._clean_uri = ""
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
                    tls = data.get('tls', '')
                    self.security = 'tls' if tls and tls not in ('none', '') else 'none'
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
                self.security = 'none'
                return
            if uri_lower.startswith('tuic://'):
                self.protocol = 'TUIC'
                try:
                    u = urllib.parse.urlparse(self.uri)
                    self.host = u.hostname or ""
                    self.port = u.port or 0
                    if u.query:
                        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
                        for k in ('sni', 'peer', 'host', 'servername'):
                            if qs.get(k):
                                self.sni = qs[k][0]
                                break
                    if u.fragment:
                        import html
                        frag = html.unescape(u.fragment)
                        if '📡' in frag:
                            parts = frag.split('📡')
                            if len(parts) > 1:
                                self.country = parts[1].strip()
                except Exception:
                    pass
                self.security = 'none'
                return
            u = urllib.parse.urlparse(self.uri)
            self.protocol = u.scheme.rstrip(':').upper()
            self.host = u.hostname or ""
            self.port = u.port or 0
            if u.query:
                qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
                for k in ('sni', 'peer', 'host', 'servername'):
                    if qs.get(k):
                        self.sni = qs[k][0]
                        break
                if qs.get('security'):
                    val = qs['security'][0].lower()
                    if val in ('tls', 'reality', 'xtls', 'none', 'auto'):
                        self.security = val
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
        proto = (self.protocol or "?").lower()
        return f"{proto}:{self.host}:{self.port}"

    def display_protocol(self) -> str:
        p = self.protocol
        if p in ('VLESS', 'VMESS', 'TROJAN', 'HYSTERIA2', 'HY2', 'TUIC', 'WIREGUARD', 'WG', 'NAIVE+'):
            return p
        return p

    def status_emoji(self) -> str:
        if self.rkn_ok: return "🛡"
        if self.deep_ok: return "⚡"
        if self.tcp_ok: return "✅"
        return "❌"

    def clean_uri(self) -> str:
        """Return cached clean URI (without #remark), normalized."""
        if not self._clean_uri:
            self._clean_uri = self.uri
        return self._clean_uri

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
    with open(tmp, "w", encoding="utf-8") as f:
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


def _env_tokens() -> list[str]:
    try:
        return [v for v in [os.getenv("GH_TOKEN"), os.getenv("GITHUB_TOKEN"), os.getenv("GITHUB")] if v]
    except Exception:
        return []


def _save_auth(data: dict):
    from .compat import IS_WINDOWS
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    if not IS_WINDOWS:
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

if not _auth_data.get("github_tokens"):
    _auth_data["github_tokens"] = _env_tokens()


def _get_tokens() -> list[str]:
    tokens = _auth_data.get("github_tokens", [])
    if not tokens:
        tokens = _env_tokens()
    return tokens


class ProxyTableModel(QAbstractTableModel):
    HEADERS = ["Статус", "Протокол", "Хост", "Порт", "Страна", "Пинг"]

    # Pre-allocated QColor objects for data() hot path (per-theme cache)
    _FG_PROTO: dict[str, QColor] = {}
    _PROTO_LIGHT: dict[str, QColor] = {}
    _theme_cache: dict[str, dict] = {}
    _last_theme: str = ""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proxies: list[ProxyEntry] = []
        # Cache translated headers once
        from .i18n import _
        self._headers = [
            _("table.header.status"), _("table.header.proto"),
            _("table.header.host"), _("table.header.port"),
            _("table.header.country"), _("table.header.ping"),
        ]
        # Build QColor cache for protocol foregrounds (once per class)
        if not ProxyTableModel._FG_PROTO:
            ProxyTableModel._build_proto_colors()

    @classmethod
    def _theme_colors(cls) -> dict:
        """QColor objects for the current theme, cached per theme."""
        if not cls._FG_PROTO:
            cls._build_proto_colors()
        theme = current_theme()
        if cls._theme_cache.get("__theme__") == theme:
            return cls._theme_cache
        t = THEMES[theme]
        cls._theme_cache = {
            "__theme__": theme,
            "ok_bg": QColor(t["table_ok_bg"]),
            "ok_fg": QColor(t["table_ok_fg"]),
            "fail_bg": QColor(t["table_fail_bg"]),
            "fail_fg": QColor(t["table_fail_fg"]),
            "ping_fast": QColor(t["ping_fast"]),
            "ping_med": QColor(t["ping_med"]),
            "ping_slow": QColor(t["ping_slow"]),
            "ping_dead": QColor(t["ping_dead"]),
            "proto": cls._PROTO_LIGHT if theme == "light" else cls._FG_PROTO,
        }
        return cls._theme_cache

    @classmethod
    def _build_proto_colors(cls):
        PROTO_COLORS = {
            "VLESS": "#7c4dff", "VMESS": "#448aff", "TROJAN": "#ff5252",
            "HYSTERIA2": "#ff6d00", "HY2": "#ff6d00", "TUIC": "#00bfa5",
            "WIREGUARD": "#76ff03", "WG": "#76ff03", "SS": "#69f0ae",
        }
        cls._FG_PROTO.update(
            {proto: QColor(c) for proto, c in PROTO_COLORS.items()}
        )
        cls._PROTO_LIGHT.update(
            {proto: QColor(c).darker(230) for proto, c in PROTO_COLORS.items()}
        )

    def rowCount(self, parent=None):
        return len(self.proxies)

    def columnCount(self, parent=None):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            if section < len(self._headers):
                return self._headers[section]
        return None

    COUNTRY_FLAGS = {
        "Russia":"🇷🇺","Germany":"🇩🇪","France":"🇫🇷","Netherlands":"🇳🇱","UK":"🇬🇧",
        "USA":"🇺🇸","Canada":"🇨🇦","Japan":"🇯🇵","Singapore":"🇸🇬","Hong Kong":"🇭🇰",
        "South Korea":"🇰🇷","Australia":"🇦🇺","Brazil":"🇧🇷","India":"🇮🇳","China":"🇨🇳",
        "Taiwan":"🇹🇼","Switzerland":"🇨🇭","Sweden":"🇸🇪","Norway":"🇳🇴","Finland":"🇫🇮",
        "Denmark":"🇩🇰","Italy":"🇮🇹","Spain":"🇪🇸","Poland":"🇵🇱","Czech":"🇨🇿",
        "Austria":"🇦🇹","Belgium":"🇧🇪","Ireland":"🇮🇪","UAE":"🇦🇪","Turkey":"🇹🇷",
        "Israel":"🇮🇱","Iran":"🇮🇷","Seychelles":"🇸🇨","Armenia":"🇦🇲","Bulgaria":"🇧🇬",
        "Romania":"🇷🇴","Hungary":"🇭🇺","Ukraine":"🇺🇦","Vietnam":"🇻🇳",
        "Thailand":"🇹🇭","Malaysia":"🇲🇾","Indonesia":"🇮🇩","Philippines":"🇵🇭",
        "Mexico":"🇲🇽","Argentina":"🇦🇷","Chile":"🇨🇱","South Africa":"🇿🇦",
        "Nigeria":"🇳🇬","Egypt":"🇪🇬","Morocco":"🇲🇦","Kazakhstan":"🇰🇿",
        "Saudi Arabia":"🇸🇦","Iceland":"🇮🇸","New Zealand":"🇳🇿","Greece":"🇬🇷",
        "Portugal":"🇵🇹","Croatia":"🇭🇷","Slovakia":"🇸🇰","Lithuania":"🇱🇹",
        "Latvia":"🇱🇻","Estonia":"🇪🇪","Serbia":"🇷🇸","Albania":"🇦🇱",
        "Algeria":"🇩🇿","Colombia":"🇨🇴",
    }

    def _status_text(self, p: ProxyEntry) -> str:
        parts = []
        if p.deep_ok:
            parts.append("⚡")
        if p.rkn_ok:
            parts.append("🛡")
        if not parts and (p.deep_tested or p.rkn_tested):
            parts.append("❌")
        if not parts:
            parts.append("⏳")
        return "".join(parts)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        p = self.proxies[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return self._status_text(p)
            if col == 1: return p.display_protocol()
            if col == 2: return p.host
            if col == 3: return str(p.port) if p.port else ""
            if col == 4:
                flag = self.COUNTRY_FLAGS.get(p.country, "")
                return f"{flag} {p.country}" if flag else (p.country or "")
            if col == 5: return f"{p.latency_ms:.0f}ms" if p.latency_ms else ""
        if role == Qt.ItemDataRole.ForegroundRole:
            tc = self._theme_colors()
            if col == 1:
                qc = tc["proto"].get(p.protocol)
                if qc:
                    return qc
            if col == 5 and p.latency_ms:
                ms = p.latency_ms
                if ms < 100: return tc["ping_fast"]
                if ms < 300: return tc["ping_med"]
                if ms < 500: return tc["ping_slow"]
                return tc["ping_dead"]
            return None
        if role == Qt.ItemDataRole.BackgroundRole:
            tc = self._theme_colors()
            if p.deep_ok or p.rkn_ok:
                return tc["ok_bg"]
            if p.deep_tested or p.rkn_tested:
                return tc["fail_bg"]
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            country_display = p.country or "-"
            rkn_str = f"  RKN: {'🛡' if p.rkn_ok else '-'}" if p.rkn_tested else ""
            return (f"{p.display_protocol()} {p.host}:{p.port}\n"
                    f"SNI: {p.sni or '-'}\n"
                    f"Страна: {country_display}\n"
                    f"Источник: {p.source or '-'}\n"
                    f"Deep: {'⚡' if p.deep_ok else '❌'}{rkn_str}  "
                    f"Пинг: {f'{p.latency_ms:.0f}ms' if p.latency_ms else '-'}")
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
            if ttype == 1:
                p.deep_ok = ok
                p.deep_error = error
                p.deep_tested = True
                p.tcp_ok = ok
                p.tcp_tested = True
                if ok and latency:
                    p.latency_ms = latency
            elif ttype == 2:
                p.rkn_ok = ok
                p.rkn_tested = True
                if latency:
                    p.latency_ms = latency
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

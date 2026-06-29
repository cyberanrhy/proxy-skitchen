import re, json, base64, urllib.parse, html, os, atexit
from typing import Optional

GOOD_SNI_DOMAINS = {
    'bing.com', 'microsoft.com', 'apple.com', 'icloud.com', 'office.com', 'office365.com',
    'azure.com', 'windows.com', 'live.com', 'outlook.com', 'skype.com',
    'samsung.com', 'nvidia.com', 'amd.com', 'intel.com', 'adobe.com',
    'cloudflare.com', 'cloudflare-nginx.com', 'cloudflare.net',
    'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'ytimg.com',
    'ggpht.com', 'blogger.com', 'blogspot.com', 'android.com',
    'googlevideo.com', 'googleusercontent.com', 'google-analytics.com',
    'facebook.com', 'fbcdn.net', 'messenger.com', 'instagram.com', 'whatsapp.com',
    'cdninstagram.com', 'telegram.org', 't.me',
    'speedtest.net', 'ooklaserver.net',
    'github.com', 'github.io', 'githubusercontent.com',
    'cloudfront.net', 'aws.amazon.com', 'amazonaws.com', 'amazon.com', 'aws.com',
    'twitch.tv', 'twitter.com', 'x.com', 't.co',
    'discord.com', 'discordapp.com', 'spotify.com', 'scdn.co',
    'reddit.com', 'redditmedia.com',
    'cdnjs.cloudflare.com', 'jsdelivr.net',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
    'akamaiedge.net', 'akamaihd.net', 'edgesuite.net',
    'azureedge.net', 'azurefd.net', 'trafficmanager.net',
    'v2ex.com', 'ipapi.co', 'ip-api.com', 'ipinfo.io',
    'yandex.ru', 'yastatic.net', 'yandex.net', 'mail.ru',
}

PROTOCOL_PREFIXES = (
    'vless://', 'vmess://', 'trojan://', 'ss://', 'shadowsocks://',
    'hysteria2://', 'hy2://', 'hysteria://', 'hy://', 'tuic://',
    'socks5://', 'socks4://', 'http://', 'https://', 'naive+',
    'wireguard://', 'wg://',
)


def is_ip(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))


def strip_remark(uri: str) -> tuple[str, str]:
    idx = uri.rfind('#')
    if idx == -1:
        return uri, ''
    return uri[:idx], urllib.parse.unquote(uri[idx + 1:])


def extract_sni(uri: str) -> Optional[str]:
    try:
        clean, _ = strip_remark(uri.strip())
        qmark = clean.find('?')
        if qmark != -1:
            params = urllib.parse.parse_qs(clean[qmark + 1:])
            for key in ('sni', 'serverName', 'server_name', 'host'):
                vals = params.get(key, [])
                if vals and vals[0].strip() and not is_ip(vals[0].strip()):
                    return vals[0].strip()
    except Exception:
        pass
    return None


def sni_is_good(sni: str) -> bool:
    if not sni:
        return False
    sni = sni.lower().strip().rstrip('.')
    if is_ip(sni):
        return False
    if sni in GOOD_SNI_DOMAINS:
        return True
    for good in GOOD_SNI_DOMAINS:
        if sni.endswith('.' + good):
            return True
    return False


def get_protocol(uri: str) -> str:
    l = uri.strip().lower()
    if l.startswith('vless://'): return 'vless'
    if l.startswith('vmess://'): return 'vmess'
    if l.startswith('trojan://'): return 'trojan'
    if l.startswith('ss://') or l.startswith('shadowsocks://'): return 'ss'
    if l.startswith('hysteria2://') or l.startswith('hy2://'): return 'hy2'
    if l.startswith('hysteria://') or l.startswith('hy://'): return 'hy'
    if l.startswith('tuic://'): return 'tuic'
    if l.startswith('socks5://') or l.startswith('socks4://'): return 'socks'
    if l.startswith('http://') or l.startswith('https://'): return 'http'
    if l.startswith('naive+'): return 'naive'
    if l.startswith('wireguard://') or l.startswith('wg://'): return 'wireguard'
    return 'unknown'


def get_server_port(uri: str) -> tuple[Optional[str], Optional[int]]:
    line = uri.strip()
    l = line.lower()
    for pfx in ['vless://', 'trojan://', 'ss://', 'hysteria://', 'hy://',
                 'hysteria2://', 'hy2://', 'tuic://', 'socks5://', 'socks4://']:
        if l.startswith(pfx):
            line = line[len(pfx):]
            break

    if l.startswith('vmess://'):
        try:
            b64 = line[len('vmess://'):]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += '=' * pad
            data = json.loads(base64.b64decode(b64))
            return data.get('add', ''), int(data.get('port', 0)) if data.get('port') else None
        except Exception:
            return None, None

    at_idx = line.find('@')
    host_part = line[at_idx + 1:] if at_idx != -1 else line
    qm = host_part.find('?')
    if qm != -1: host_part = host_part[:qm]
    h = host_part.find('#')
    if h != -1: host_part = host_part[:h]
    colon = host_part.rfind(':')
    if colon != -1 and colon > host_part.rfind(']'):
        try:
            return host_part[:colon].strip('[]'), int(host_part[colon + 1:])
        except ValueError:
            return host_part[:colon].strip('[]'), None
    return host_part.strip('[]'), None


def get_remark(uri: str) -> str:
    _, r = strip_remark(uri)
    return r


def guess_country(uri: str) -> str:
    remark = get_remark(uri)
    flags = re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', remark)
    flag_map = {
        '🇦🇱': 'Albania', '🇩🇿': 'Algeria', '🇦🇷': 'Argentina', '🇦🇺': 'Australia', '🇦🇹': 'Austria',
        '🇧🇪': 'Belgium', '🇧🇷': 'Brazil', '🇧🇬': 'Bulgaria', '🇨🇦': 'Canada', '🇨🇱': 'Chile',
        '🇨🇳': 'China', '🇨🇴': 'Colombia', '🇭🇷': 'Croatia', '🇨🇿': 'Czech', '🇩🇰': 'Denmark',
        '🇪🇬': 'Egypt', '🇫🇮': 'Finland', '🇫🇷': 'France', '🇩🇪': 'Germany', '🇬🇷': 'Greece',
        '🇭🇰': 'Hong Kong', '🇭🇺': 'Hungary', '🇮🇸': 'Iceland', '🇮🇳': 'India', '🇮🇩': 'Indonesia',
        '🇮🇷': 'Iran', '🇮🇪': 'Ireland', '🇮🇱': 'Israel', '🇮🇹': 'Italy', '🇯🇵': 'Japan',
        '🇰🇿': 'Kazakhstan', '🇰🇷': 'South Korea', '🇱🇻': 'Latvia', '🇱🇹': 'Lithuania', '🇲🇾': 'Malaysia',
        '🇲🇽': 'Mexico', '🇲🇦': 'Morocco', '🇳🇱': 'Netherlands', '🇳🇿': 'New Zealand', '🇳🇬': 'Nigeria',
        '🇳🇴': 'Norway', '🇵🇭': 'Philippines', '🇵🇱': 'Poland', '🇵🇹': 'Portugal', '🇷🇴': 'Romania',
        '🇷🇺': 'Russia', '🇸🇦': 'Saudi Arabia', '🇷🇸': 'Serbia', '🇸🇬': 'Singapore', '🇸🇰': 'Slovakia',
        '🇿🇦': 'South Africa', '🇪🇸': 'Spain', '🇸🇪': 'Sweden', '🇨🇭': 'Switzerland', '🇹🇼': 'Taiwan',
        '🇹🇭': 'Thailand', '🇹🇷': 'Turkey', '🇺🇦': 'Ukraine', '🇦🇪': 'UAE', '🇬🇧': 'UK',
        '🇺🇸': 'USA', '🇻🇳': 'Vietnam',
    }
    for flag in flags:
        if flag in flag_map:
            return flag_map[flag]
    countries = ['Albania', 'Algeria', 'Argentina', 'Australia', 'Austria', 'Belgium', 'Brazil',
        'Bulgaria', 'Canada', 'Chile', 'China', 'Colombia', 'Croatia', 'Czech', 'Denmark',
        'Egypt', 'Finland', 'France', 'Germany', 'Greece', 'Hong Kong', 'Hungary', 'Iceland',
        'India', 'Indonesia', 'Iran', 'Ireland', 'Israel', 'Italy', 'Japan', 'Kazakhstan',
        'South Korea', 'Latvia', 'Lithuania', 'Malaysia', 'Mexico', 'Morocco', 'Netherlands',
        'New Zealand', 'Nigeria', 'Norway', 'Philippines', 'Poland', 'Portugal', 'Romania',
        'Russia', 'Saudi Arabia', 'Serbia', 'Singapore', 'Slovakia', 'South Africa', 'Spain',
        'Sweden', 'Switzerland', 'Taiwan', 'Thailand', 'Turkey', 'Ukraine', 'UAE', 'UK', 'USA',
        'Vietnam']
    for c in countries:
        if c.lower() in remark.lower():
            return c
    server, _ = get_server_port(uri)
    if server:
        tld_map = {'.ru': 'Russia', '.de': 'Germany', '.fr': 'France', '.nl': 'Netherlands',
            '.uk': 'UK', '.jp': 'Japan', '.sg': 'Singapore', '.hk': 'Hong Kong',
            '.kr': 'South Korea', '.au': 'Australia', '.ca': 'Canada', '.br': 'Brazil',
            '.in': 'India', '.cn': 'China', '.tw': 'Taiwan'}
        for tld, country in tld_map.items():
            if server.endswith(tld):
                return country
    return ''


_GEO_CACHE: dict[str, str] = {}
_GEO_CACHE_DIRTY = False


def _load_geo_cache():
    global _GEO_CACHE
    from .compat import SETTINGS_DIR
    _GEO_CACHE_FILE = os.path.join(SETTINGS_DIR, "geo_cache.json")
    try:
        if os.path.exists(_GEO_CACHE_FILE):
            with open(_GEO_CACHE_FILE) as f:
                _GEO_CACHE = json.load(f)
    except Exception:
        pass


def _save_geo_cache():
    global _GEO_CACHE_DIRTY
    from .compat import SETTINGS_DIR
    _GEO_CACHE_FILE = os.path.join(SETTINGS_DIR, "geo_cache.json")
    try:
        d = os.path.dirname(_GEO_CACHE_FILE)
        os.makedirs(d, exist_ok=True)
        with open(_GEO_CACHE_FILE, "w") as f:
            json.dump(_GEO_CACHE, f, indent=2)
        _GEO_CACHE_DIRTY = False
    except Exception:
        pass


def flush_geo_cache():
    if _GEO_CACHE_DIRTY:
        _save_geo_cache()


_load_geo_cache()
atexit.register(flush_geo_cache)


def geo_lookup(ip: str) -> str:
    global _GEO_CACHE_DIRTY
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        country = data.get("country", "")
        if country:
            _GEO_CACHE[ip] = country
            _GEO_CACHE_DIRTY = True
            if len(_GEO_CACHE) % 10 == 0:
                _save_geo_cache()
            return country
    except Exception:
        pass
    return ""


def is_proxy_uri(s: str) -> bool:
    s = s.strip().lower()
    if s.startswith(PROTOCOL_PREFIXES):
        return True
    # Also accept IP:port or host:port (to be wrapped later)
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', s) or \
       re.match(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}:\d+$', s, re.IGNORECASE):
        return True
    return False


_INLINE_URI_RE = re.compile(
    r'(?:vless|vmess|trojan|ss|shadowsocks|hysteria2|hy2|tuic|socks5|socks4)://[^\s"\'`,;}\])]+',
    re.IGNORECASE
)


def extract_inline_uris(line: str) -> list[str]:
    return _INLINE_URI_RE.findall(line)


def extract_uris(text: str) -> list[str]:
    uris = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            continue
        if re.match(r'^[A-Za-z0-9+/=]{50,}$', line):
            try:
                decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
                for sl in decoded.splitlines():
                    sl = sl.strip()
                    if sl and is_proxy_uri(sl):
                        uris.append(sl)
            except Exception:
                if is_proxy_uri(line):
                    uris.append(line)
        elif is_proxy_uri(line):
            uris.append(line)
    return uris


def parse_json_proxies(data: str) -> list[str]:
    uris = []
    try:
        obj = json.loads(data)
        if isinstance(obj, dict):
            for val in obj.values():
                if isinstance(val, str) and is_proxy_uri(val):
                    uris.append(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and is_proxy_uri(item):
                            uris.append(item)
                        elif isinstance(item, dict):
                            # Try to extract host and port from the dict
                            host = item.get('query') or item.get('ip') or item.get('address') or item.get('server')
                            port = item.get('port')
                            if host and port:
                                protocol = item.get('type') or item.get('protocol') or 'http'
                                # Normalize protocol to lower case and ensure it ends with :// if not already
                                protocol = protocol.lower().strip()
                                if not protocol.endswith('://'):
                                    protocol = protocol + '://'
                                uri = f"{protocol}{host}:{port}"
                                if is_proxy_uri(uri):
                                    uris.append(uri)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str) and is_proxy_uri(item):
                    uris.append(item)
                elif isinstance(item, dict):
                    # Try to extract host and port from the dict
                    host = item.get('query') or item.get('ip') or item.get('address') or item.get('server')
                    port = item.get('port')
                    if host and port:
                        protocol = item.get('type') or item.get('protocol') or 'http'
                        # Normalize protocol to lower case and ensure it ends with :// if not already
                        protocol = protocol.lower().strip()
                        if not protocol.endswith('://'):
                            protocol = protocol + '://'
                        uri = f"{protocol}{host}:{port}"
                        if is_proxy_uri(uri):
                            uris.append(uri)
    except Exception:
        pass
    return uris


def wrap_raw_host(uri: str) -> str:
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', uri) or \
       re.match(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}:\d+$', uri, re.IGNORECASE):
        return f"socks5://{uri}"
    return uri

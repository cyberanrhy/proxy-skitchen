import os, json, base64
from typing import Optional


from .models import ProxyEntry


def _clean_uri(uri: str) -> str:
    """If given a ProxyEntry, use its cached clean_uri(). Otherwise normalize."""
    if isinstance(uri, ProxyEntry):
        return uri.clean_uri()
    from .parsers import normalize_uri
    return normalize_uri(uri)


def _is_valid_entry(e: ProxyEntry) -> bool:
    if not e.host or e.port is None or e.port == 0:
        return False
    from .parsers import uri_has_insecure, uri_sni_messy
    if uri_has_insecure(e.uri):
        return False
    if e.protocol not in ('WIREGUARD', 'WG') and uri_sni_messy(e.uri):
        return False
    if e.protocol in ('VLESS', 'VMESS', 'TROJAN') and not _extract_user(e.uri):
        return False
    if e.protocol == 'SS' and not _extract_ss_pass(e.uri):
        return False
    return True


def _entry_ok(e: ProxyEntry) -> bool:
    if e.deep_tested and not e.deep_ok:
        return False
    if e.rkn_tested and not e.rkn_ok:
        return False
    return True


def _needs_user(proto: str) -> bool:
    return proto in ('VLESS', 'VMESS', 'TROJAN', 'HYSTERIA2', 'HY2', 'SS')


def format_raw(entries: list[ProxyEntry], include_failed: bool = False, clean: bool = True) -> str:
    lines = []
    for e in entries:
        if not _is_valid_entry(e):
            continue
        if include_failed or _entry_ok(e):
            lines.append(_clean_uri(e) if clean else e.uri)
    return "\n".join(lines) + "\n"


def format_v2rayn(entries: list[ProxyEntry], include_failed: bool = False, clean: bool = True) -> str:
    raw = format_raw(entries, include_failed, clean=clean)
    return base64.b64encode(raw.encode()).decode()


def format_singbox(entries: list[ProxyEntry], include_failed: bool = False) -> str:
    outbounds = []
    for e in entries:
        if not _is_valid_entry(e):
            continue
        if not include_failed and not _entry_ok(e):
            continue
        out = _entry_to_outbound(e)
        if out:
            out["tag"] = f"proxy-{len(outbounds)}"
            outbounds.append(out)
    config = {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": 1080,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "proxy-0" if outbounds else "direct"},
    }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def format_clash(entries: list[ProxyEntry], include_failed: bool = False, clean_names: bool = False) -> str:
    proxies = []
    for i, e in enumerate(entries):
        if not _is_valid_entry(e):
            continue
        if not include_failed and not _entry_ok(e):
            continue
        p = _entry_to_clash(e, i + 1, clean_names)
        if p:
            proxies.append(p)
    if not proxies:
        return "proxies: []\n"
    lines = ["proxies:"]
    for p in proxies:
        lines.append(f"  - name: {p['name']}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {p['server']}")
        lines.append(f"    port: {p['port']}")
        if p.get('uuid'):
            lines.append(f"    uuid: {p['uuid']}")
        if p.get('password'):
            lines.append(f"    password: {p['password']}")
        if p.get('cipher'):
            lines.append(f"    cipher: {p['cipher']}")
        if p.get('udp', False):
            lines.append("    udp: true")
        if p.get('tls', False):
            lines.append("    tls: true")
        if p.get('sni'):
            lines.append(f"    sni: {p['sni']}")
        if p.get('skip-cert-verify', False):
            lines.append("    skip-cert-verify: true")
        if p.get('ws-path'):
            lines.append(f"    ws-path: {p['ws-path']}")
    return "\n".join(lines) + "\n"


def format_hiddify(entries: list[ProxyEntry], include_failed: bool = False, title: str = "VPN Config", clean: bool = True) -> str:
    valid = [e for e in entries if _is_valid_entry(e) and (include_failed or _entry_ok(e))]
    lines = [
        f"#profile-title: {title}",
        "#profile-update-interval: 24",
        f"#subscription-userinfo: upload=0; download=0; total={len(valid)}; expire=0",
        "",
    ]
    for e in valid:
        lines.append(_clean_uri(e.uri) if clean else e.uri)
    return "\n".join(lines) + "\n"


def validate_content(content: str, fmt: str) -> tuple[int, int]:
    """Return (valid_count, broken_count) for a rendered export body."""
    if fmt == 'v2rayn':
        try:
            content = base64.b64decode(content).decode('utf-8', errors='ignore')
        except Exception:
            content = ""
    if fmt in ('singbox', 'clash'):
        try:
            obj = json.loads(content)
            items = []
            if isinstance(obj, dict):
                items = obj.get('outbounds', obj.get('proxies', []))
            return len(items), 0
        except Exception:
            return 0, 0
    from .parsers import is_proxy_uri
    valid = 0
    broken = 0
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if is_proxy_uri(line):
            valid += 1
        else:
            broken += 1
    return valid, broken


def smart_name(entry: ProxyEntry, idx: int = 0, clean_names: bool = False) -> str:
    if clean_names:
        country_code = _country_to_code(entry.country) if entry.country else "XX"
        proto = entry.protocol.replace("HYSTERIA2", "HY2").replace("WIREGUARD", "WG")
        return f"server {idx} ({country_code} {proto} {entry.port if entry.port else ''})".strip()
    
    country_code = _country_to_code(entry.country) if entry.country else ""
    flag = _country_to_flag(entry.country) if entry.country else ""
    proto = entry.protocol
    parts = []
    if flag:
        parts.append(flag)
    if idx > 0:
        parts.append(str(idx))
    if country_code:
        parts.append(country_code)
    proto_str = proto.replace("HYSTERIA2", "HY2").replace("WIREGUARD", "WG")
    if entry.sni:
        parts.append(f"{proto_str}/{entry.sni.split('.')[0]}")
    else:
        parts.append(proto_str)
    if entry.port:
        parts.append(str(entry.port))
    return " ".join(parts)


def _country_to_code(country: str) -> str:
    mapping = {"Russia":"RU","Germany":"DE","France":"FR","Netherlands":"NL","UK":"GB",
               "USA":"US","Canada":"CA","Japan":"JP","Singapore":"SG","Hong Kong":"HK",
               "South Korea":"KR","Australia":"AU","Brazil":"BR","India":"IN","China":"CN",
               "Taiwan":"TW","Switzerland":"CH","Sweden":"SE","Norway":"NO","Finland":"FI",
               "Denmark":"DK","Italy":"IT","Spain":"ES","Poland":"PL","Czech":"CZ",
               "Austria":"AT","Belgium":"BE","Ireland":"IE","UAE":"AE","Turkey":"TR",
               "Israel":"IL","Iran":"IR","Seychelles":"SC","Armenia":"AM","Bulgaria":"BG",
               "Romania":"RO","Hungary":"HU","Ukraine":"UA","Vietnam":"VN",
               "Thailand":"TH","Malaysia":"MY","Indonesia":"ID","Philippines":"PH",
               "Mexico":"MX","Argentina":"AR","Chile":"CL","South Africa":"ZA",
               "Nigeria":"NG","Egypt":"EG","Morocco":"MA","Kazakhstan":"KZ",
               "Saudi Arabia":"SA","Iceland":"IS","New Zealand":"NZ","Greece":"GR",
               "Portugal":"PT","Croatia":"HR","Slovakia":"SK","Lithuania":"LT",
               "Latvia":"LV","Estonia":"EE","Serbia":"RS","Albania":"AL",
               "Algeria":"DZ","Colombia":"CO"}
    return mapping.get(country, country[:2].upper())


def _country_to_flag(country: str) -> str:
    mapping = {"Russia":"🇷🇺","Germany":"🇩🇪","France":"🇫🇷","Netherlands":"🇳🇱","UK":"🇬🇧",
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
               "Algeria":"🇩🇿","Colombia":"🇨🇴"}
    return mapping.get(country, "")


def _entry_to_outbound(e: ProxyEntry) -> Optional[dict]:
    proto = e.protocol.lower()
    out = {"type": proto, "server": e.host, "server_port": e.port}
    if proto in ('vless', 'trojan'):
        out["tls"] = {"enabled": True, "server_name": e.sni or e.host}
    elif e.sni:
        out["tls"] = {"enabled": True, "server_name": e.sni}
    if proto in ('vless', 'vmess', 'trojan'):
        out["uuid"] = _extract_user(e.uri)
    elif proto == 'ss':
        out["password"] = _extract_ss_pass(e.uri)
    elif proto in ('hy2', 'hysteria2', 'hysteria', 'hy'):
        out["password"] = _extract_user(e.uri)
    return out


def _entry_to_clash(e: ProxyEntry, idx: int = 0, clean_names: bool = False) -> Optional[dict]:
    proto = e.protocol.lower()
    name = smart_name(e, idx, clean_names)
    p = {"name": name, "server": e.host, "port": e.port}
    if proto in ('vless', 'trojan'):
        p["type"] = proto
        p["uuid"] = _extract_user(e.uri)
        p["tls"] = True
        if e.sni:
            p["sni"] = e.sni
        return p
    if proto == 'vmess':
        p["type"] = "vmess"
        p["uuid"] = _extract_user(e.uri)
        return p
    if proto == 'ss':
        p["type"] = "ss"
        pw = _extract_ss_pass(e.uri)
        if pw:
            p["password"] = pw
            p["cipher"] = _extract_ss_cipher(e.uri) or "aes-256-gcm"
        return p
    if proto in ('hy2', 'hysteria2'):
        p["type"] = "hysteria2"
        p["password"] = _extract_user(e.uri)
        return p
    if proto == 'socks5':
        p["type"] = "socks5"
        return p
    return None


def _extract_user(uri: str) -> str:
    from urllib.parse import urlparse, unquote
    for vmess_pfx in ('vmess://', 'VMESS://'):
        if uri.startswith(vmess_pfx):
            try:
                b64 = uri[len(vmess_pfx):]
                pad = 4 - len(b64) % 4
                if pad != 4:
                    b64 += '=' * pad
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                data = json.loads(decoded)
                return data.get('id', '')
            except Exception:
                pass
            return ""
    u = urlparse(uri)
    if u.username:
        return unquote(u.username)
    return ""


def _extract_ss_pass(uri: str) -> str:
    try:
        clean = uri.replace('ss://', '').replace('SS://', '')
        clean = clean.split('#')[0].split('?')[0]
        at = clean.find('@')
        if at != -1:
            mp_b64 = clean[:at]
        else:
            mp_b64 = clean
        try:
            pad = 4 - len(mp_b64) % 4
            if pad != 4:
                mp_b64 += '=' * pad
            mp = base64.b64decode(mp_b64).decode('utf-8', errors='ignore')
        except Exception:
            mp = mp_b64  # old format: plaintext method:password
        if '@' in mp:
            mp = mp.split('@', 1)[0]
        colon = mp.find(':')
        return mp[colon + 1:] if colon != -1 else mp
    except Exception:
        pass
    return ""


def _parse_wireguard_uri(uri: str) -> Optional[dict]:
    """Parse a wireguard:// URI into fields for a WireGuard .conf."""
    from urllib.parse import parse_qs, unquote
    if not uri.startswith("wireguard://"):
        return None
    rest = uri[len("wireguard://"):]
    if "@" not in rest or "?" not in rest:
        return None
    priv, after_at = rest.split("@", 1)
    host_port, qs_str = after_at.split("?", 1)
    qs_str = qs_str.split("#")[0]
    q = parse_qs(qs_str)
    if ":" not in host_port:
        return None
    host, port_s = host_port.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        return None
    def _v(key, default=""):
        return q[key][0] if q.get(key) else default
    return {
        "private_key": unquote(priv),
        "host": host,
        "port": port,
        "address": unquote(_v("address")),
        "public_key": unquote(_v("publickey", _v("pubkey"))),
        "mtu": _v("mtu", "1280"),
        "keepalive": _v("keepalive", "25"),
    }


def format_amnezia(entries: list[ProxyEntry], include_failed: bool = False) -> str:
    """Concatenated WireGuard .conf blocks for Amnezia import (preview only)."""
    blocks = []
    for i, e in enumerate(entries, 1):
        if e.protocol not in ('WIREGUARD', 'WG'):
            continue
        if not include_failed and not _entry_ok(e):
            continue
        conf = wireguard_conf_from_entry(e)
        if conf:
            blocks.append(f"# {i} — {e.host}:{e.port}\n{conf}")
    return "\n".join(blocks) + "\n"


def wireguard_conf_from_entry(e: ProxyEntry) -> Optional[str]:
    """Build a single WireGuard .conf block from a ProxyEntry's wireguard:// URI."""
    if not (e.uri and e.uri.startswith("wireguard://")):
        return None
    p = _parse_wireguard_uri(e.uri)
    if not p:
        return None
    lines = [
        "[Interface]",
        f"PrivateKey = {p['private_key']}",
        f"Address = {p['address']}",
        "DNS = 1.1.1.1, 1.0.0.1",
        f"MTU = {p['mtu']}",
        "",
        "[Peer]",
        f"PublicKey = {p['public_key']}",
        f"Endpoint = {p['host']}:{p['port']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"PersistentKeepalive = {p['keepalive']}",
    ]
    return "\n".join(lines) + "\n"


def _extract_ss_cipher(uri: str) -> str:
    try:
        clean = uri.replace('ss://', '').replace('SS://', '')
        clean = clean.split('#')[0].split('?')[0]
        at = clean.find('@')
        if at != -1:
            mp_b64 = clean[:at]
        else:
            mp_b64 = clean
        try:
            pad = 4 - len(mp_b64) % 4
            if pad != 4:
                mp_b64 += '=' * pad
            mp = base64.b64decode(mp_b64).decode('utf-8', errors='ignore')
        except Exception:
            mp = mp_b64
        colon = mp.find(':')
        if colon != -1:
            method = mp[:colon]
            if method:
                return method
    except Exception:
        pass
    return ""

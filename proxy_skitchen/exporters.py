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
    # hysteria2 handles `insecure` natively (tls.insecure / skip-cert-verify)
    if e.protocol not in ('HYSTERIA2', 'HY2') and uri_has_insecure(e.uri):
        return False
    if e.protocol not in ('WIREGUARD', 'WG') and uri_sni_messy(e.uri):
        return False
    if e.protocol in ('VLESS', 'VMESS', 'TROJAN') and not _extract_user(e.uri):
        return False
    if e.protocol == 'SS' and not _extract_ss_pass(e.uri):
        return False
    if e.protocol == 'VLESS':
        _sec = (_query_param(e.uri, 'security') or '').lower()
        _pbk = _query_param(e.uri, 'pbk')
        _flow = _query_param(e.uri, 'flow')
        if _flow and (_sec != 'reality' or not _pbk):
            return False
        if _sec == 'reality' and not _pbk:
            return False
        # Only keep transport/security values the Sing-box core actually knows.
        # Unknown ones (e.g. xhttp) make Hiddify's parser panic -> core won't start.
        if _sec and _sec not in ('none', 'tls', 'reality'):
            return False
        _net = (_query_param(e.uri, 'type') or 'tcp').lower()
        if _net not in ('tcp', 'ws', 'websocket', 'grpc', 'h2', 'quic'):
            return False
    if e.protocol == 'SS':
        _m = _extract_ss_cipher(e.uri)
        if not _m or _m.lower() not in _SAFE_SS:
            return False
    if e.protocol in ('WIREGUARD', 'WG'):
        p = _parse_wireguard_uri(e.uri)
        if not p or not p.get('private_key') or not p.get('public_key') or not p.get('address'):
            return False
    if e.protocol in ('VLESS', 'TROJAN', 'HYSTERIA2', 'HY2'):
        # Drop entries carrying corrupted / unexpected query params that crash
        # some client parsers (e.g. "Telegram=...", "spx=/", or absurdly long values).
        from urllib.parse import urlparse, parse_qs
        _q = urlparse(e.uri).query
        if _q:
            for _k, _vl in parse_qs(_q).items():
                if _k.lower() in ('telegram', 'spx'):
                    return False
                for _v in _vl:
                    if len(_v) > 256:
                        return False
    if e.protocol == 'VMESS':
        try:
            b = e.uri[8:]
            b += '=' * ((4 - len(b) % 4) % 4)
            d = json.loads(base64.b64decode(b).decode('utf-8', errors='ignore'))
            if not isinstance(d, dict) or not d.get('id'):
                return False
            _net = (d.get('net') or 'tcp').lower()
            if _net not in ('tcp', 'ws', 'websocket', 'grpc', 'h2', 'quic'):
                return False
            _scy = (d.get('scy') or '').lower()
            if _scy not in ('aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305'):
                return False
        except Exception:
            return False
    return True


# Shadowsocks ciphers supported by Sing-box core (used by Hiddify on iOS/desktop).
# Legacy stream ciphers (CFB/CTR/RC4/CAMELLIA/...) are rejected and break the core.
_SAFE_SS = {
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm',
    'chacha20-ietf-poly1305', 'chacha20', 'xchacha20', 'none',
}


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


def format_singbox(entries: list[ProxyEntry], include_failed: bool = False, dns=None) -> str:
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
    if dns is not None:
        servers = [{"address": u, "tag": f"dns{i}"} for i, u in enumerate(_parse_dns_list(dns))]
        config["dns"] = {
            "servers": servers,
            "final": "dns0",
            "independent_cache": True,
        }
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def format_clash(entries: list[ProxyEntry], include_failed: bool = False, clean_names: bool = False, dns=None) -> str:
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
    lines = []
    if dns is not None:
        servers = _parse_dns_list(dns)
        lines.append("dns:")
        lines.append("  enable: true")
        lines.append("  ipv6: false")
        lines.append("  default-nameserver:")
        for s in servers:
            lines.append(f"    - {s}")
        lines.append("  nameserver:")
        for s in servers:
            lines.append(f"    - {s}")
        lines.append("  fallback:")
        for s in servers:
            lines.append(f"    - {s}")
        lines.append("")
    lines.append("proxies:")
    for p in proxies:
        lines.append(f"  - name: {json.dumps(p['name'], ensure_ascii=False)}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {p['server']}")
        lines.append(f"    port: {p['port']}")
        if p.get('uuid'):
            lines.append(f"    uuid: {p['uuid']}")
        if p.get('password'):
            lines.append(f"    password: {p['password']}")
        if p.get('cipher'):
            lines.append(f"    cipher: {p['cipher']}")
        if p.get('flow'):
            lines.append(f"    flow: {p['flow']}")
        if p.get('network'):
            lines.append(f"    network: {p['network']}")
        if p.get('tls', False):
            lines.append("    tls: true")
        if p.get('servername'):
            lines.append(f"    servername: {p['servername']}")
        if p.get('client-fingerprint'):
            lines.append(f"    client-fingerprint: {p['client-fingerprint']}")
        if p.get('ws-opts'):
            lines.append("    ws-opts:")
            if p['ws-opts'].get('path'):
                lines.append(f"      path: {p['ws-opts']['path']}")
            if p['ws-opts'].get('headers'):
                lines.append("      headers:")
                for k, v in p['ws-opts']['headers'].items():
                    lines.append(f"        {k}: {v}")
        if p.get('grpc-opts'):
            lines.append("    grpc-opts:")
            if p['grpc-opts'].get('grpc-service-name'):
                lines.append(f"      grpc-service-name: {p['grpc-opts']['grpc-service-name']}")
        if p.get('reality-opts'):
            lines.append("    reality-opts:")
            for k, v in p['reality-opts'].items():
                lines.append(f"      {k}: {v}")
        if p.get('skip-cert-verify', False):
            lines.append("    skip-cert-verify: true")
        if p.get('obfs'):
            lines.append(f"    obfs: {p['obfs']}")
        if p.get('obfs-password'):
            lines.append(f"    obfs-password: {p['obfs-password']}")
        if p.get('type') == 'wireguard':
            for key in ('private-key', 'peer-public-key', 'pre-shared-key', 'ip', 'mtu', 'persistent-keepalive', 'udp'):
                if p.get(key) is not None:
                    val = "true" if key == 'udp' else p[key]
                    lines.append(f"    {key}: {val}")
            if p.get('ipv6') is not None:
                lines.append(f'    ipv6: "{p["ipv6"]}"')
            if p.get('reserved') is not None:
                lines.append("    reserved: [" + ", ".join(str(x) for x in p['reserved']) + "]")
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
        if fmt == 'singbox':
            try:
                obj = json.loads(content)
                items = obj.get('outbounds', []) if isinstance(obj, dict) else []
                return len(items), 0
            except Exception:
                return 0, 0
        valid = sum(1 for line in content.splitlines() if line.strip().startswith('- name:'))
        return valid, 0
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


def _query_param(uri: str, key: str) -> str:
    """Extract a single query parameter from a proxy URI (empty if absent)."""
    try:
        from urllib.parse import urlparse, parse_qs
        q = urlparse(uri).query
        if not q:
            return ""
        vals = parse_qs(q)
        return vals.get(key, [''])[0]
    except Exception:
        return ""


def _vless_transport(e: ProxyEntry) -> dict:
    """Build sing-box transport block for a VLESS entry (grpc/ws/xhttp). Empty for tcp."""
    net = (_query_param(e.uri, 'type') or 'tcp').lower()
    uri = e.uri
    if net in ('grpc',):
        svc = _query_param(uri, 'serviceName') or _query_param(uri, 'service-name')
        tr = {"type": "grpc"}
        if svc:
            tr["service_name"] = svc
        return {"transport": tr}
    if net in ('ws', 'websocket'):
        path = _query_param(uri, 'path') or '/'
        host = _query_param(uri, 'host')
        tr = {"type": "ws", "path": path}
        if host:
            tr["headers"] = {"Host": host}
        return {"transport": tr}
    if net == 'xhttp':
        mode = _query_param(uri, 'mode') or 'auto'
        path = _query_param(uri, 'path') or '/'
        host = _query_param(uri, 'host') or e.sni
        tr = {"type": "xhttp", "mode": mode, "path": path}
        if host:
            tr["host"] = host
        return {"transport": tr}
    return {}


def _entry_to_outbound(e: ProxyEntry) -> Optional[dict]:
    """Build a valid sing-box outbound; return None for unsupported/incomplete entries."""
    proto = e.protocol.lower()

    if proto == 'ss':
        method = _extract_ss_cipher(e.uri)
        pw = _extract_ss_pass(e.uri)
        if not method or not pw:
            return None
        return {"type": "shadowsocks", "server": e.host, "server_port": e.port,
                "method": method, "password": pw}

    if proto == 'tuic':
        uuid = _extract_user(e.uri)
        if not uuid:
            return None
        out = {"type": "tuic", "server": e.host, "server_port": e.port, "uuid": uuid}
        return out

    if proto in ('wireguard', 'wg'):
        p = _parse_wireguard_uri(e.uri)
        if not p or not p.get('private_key') or not p.get('public_key') or not p.get('address'):
            return None
        return {
            "type": "wireguard", "server": p['host'], "server_port": p['port'],
            "local_address": [a.strip() for a in p['address'].split(',') if a.strip()],
            "private_key": p['private_key'],
            "peer_public_key": p['public_key'], "mtu": int(p.get('mtu') or 1280),
        }

    if proto not in ('vless', 'vmess', 'trojan', 'hy2', 'hysteria2', 'socks5', 'http', 'https'):
        return None

    out = {"type": proto, "server": e.host, "server_port": e.port}

    if proto == 'vless':
        uuid = _extract_user(e.uri)
        if not uuid:
            return None
        out["uuid"] = uuid
        flow = _query_param(e.uri, 'flow')
        if flow:
            out["flow"] = flow
        fp = _query_param(e.uri, 'fp')
        security = (e.security or "").lower()
        pbk = _query_param(e.uri, 'pbk')
        sid = _query_param(e.uri, 'sid')
        tls = None
        if security == 'reality' and pbk:
            tls = {"enabled": True, "server_name": e.sni or e.host,
                   "reality": {"enabled": True, "public_key": pbk}}
            if sid:
                tls["reality"]["short_id"] = sid
        elif (e.sni and security != 'none') or security == 'tls':
            tls = {"enabled": True, "server_name": e.sni or e.host}
        if tls is not None:
            if fp:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            out["tls"] = tls
        tr = _vless_transport(e)
        if tr:
            out.update(tr)
    elif proto == 'trojan':
        pw = _extract_user(e.uri)
        if not pw:
            return None
        out["password"] = pw
        out["tls"] = {"enabled": True, "server_name": e.sni or e.host}
    elif proto == 'vmess':
        uuid = _extract_user(e.uri)
        if not uuid:
            return None
        out["uuid"] = uuid
        data = _vmess_data(e.uri) or {}
        net = (data.get('net') or 'tcp').lower()
        path = data.get('path') or data.get('ws-path')
        host_h = data.get('host') or data.get('ws-header') or data.get('ws-headers')
        if net in ('ws', 'websocket') and (path or host_h):
            tr = {"type": "ws", "path": path or "/"}
            if host_h:
                tr["headers"] = {"Host": host_h}
            out["transport"] = tr
        elif net == 'grpc':
            svc = data.get('path') or data.get('serviceName')
            if svc:
                out["transport"] = {"type": "grpc", "service_name": svc}
        try:
            out["alter_id"] = int(data.get('aid') or 0)
        except (ValueError, TypeError):
            out["alter_id"] = 0
        if e.sni:
            out["tls"] = {"enabled": True, "server_name": e.sni}
    elif proto in ('hy2', 'hysteria2'):
        pw = _extract_user(e.uri)
        if not pw:
            return None
        out["password"] = pw
        out["tls"] = {"enabled": True, "server_name": e.sni or e.host}
        if _query_param(e.uri, 'insecure') == '1':
            out["tls"]["insecure"] = True
        obfs = _query_param(e.uri, 'obfs')
        obfs_pw = _query_param(e.uri, 'obfs-password')
        if obfs == 'salamander' and obfs_pw:
            out["obfs"] = {"type": "salamander", "password": obfs_pw}

    if proto in ('socks5', 'http', 'https'):
        up = _extract_user(e.uri)
        username = password = None
        if up and ':' in up:
            username, password = up.split(':', 1)
        out = {"type": "socks" if proto == 'socks5' else "http",
               "server": e.host, "server_port": e.port}
        if username:
            out["username"] = username
        if password:
            out["password"] = password
        if proto == 'https':
            out["tls"] = {"enabled": True}
        return out

    return out


def _entry_to_clash(e: ProxyEntry, idx: int = 0, clean_names: bool = False) -> Optional[dict]:
    proto = e.protocol.lower()
    name = smart_name(e, idx, clean_names)
    p = {"name": name, "server": e.host, "port": e.port}
    if proto == 'vless':
        uuid = _extract_user(e.uri)
        if not uuid:
            return None
        p["type"] = "vless"
        p["uuid"] = uuid
        flow = _query_param(e.uri, 'flow')
        if flow:
            p["flow"] = flow
        if e.sni:
            p["servername"] = e.sni
        if (e.security or "").lower() == 'reality':
            pbk = _query_param(e.uri, 'pbk')
            sid = _query_param(e.uri, 'sid')
            if not pbk:
                return None
            p["tls"] = True
            p["client-fingerprint"] = _query_param(e.uri, 'fp') or "chrome"
            p["reality-opts"] = {"public-key": pbk, "short-id": sid or ""}
        elif e.security and e.security.lower() != 'none':
            p["tls"] = True
        net = (_query_param(e.uri, 'type') or 'tcp').lower()
        path = _query_param(e.uri, 'path')
        host = _query_param(e.uri, 'host')
        svc = _query_param(e.uri, 'serviceName')
        if net in ('grpc',) and svc:
            p["network"] = "grpc"
            p["grpc-opts"] = {"grpc-service-name": svc}
        elif net in ('ws', 'websocket') and (path or host):
            p["network"] = "ws"
            opts = {}
            if path:
                opts["path"] = path
            if host:
                opts["headers"] = {"Host": host}
            p["ws-opts"] = opts
        return p
    if proto == 'trojan':
        pw = _extract_user(e.uri)
        if not pw:
            return None
        p["type"] = "trojan"
        p["password"] = pw
        p["tls"] = True
        if e.sni:
            p["servername"] = e.sni
        return p
    if proto == 'vmess':
        uuid = _extract_user(e.uri)
        if not uuid:
            return None
        p["type"] = "vmess"
        p["uuid"] = uuid
        data = _vmess_data(e.uri) or {}
        net = (data.get('net') or 'tcp').lower()
        path = data.get('path') or data.get('ws-path')
        host_h = data.get('host') or data.get('ws-header') or data.get('ws-headers')
        if net in ('ws', 'websocket') and (path or host_h):
            p["network"] = "ws"
            opts = {}
            if path:
                opts["path"] = path
            if host_h:
                opts["headers"] = {"Host": host_h}
            p["ws-opts"] = opts
        elif net == 'grpc':
            svc = data.get('path') or data.get('serviceName')
            if svc:
                p["network"] = "grpc"
                p["grpc-opts"] = {"grpc-service-name": svc}
        if e.security and e.security.lower() != 'none':
            p["tls"] = True
        p["cipher"] = data.get('scy') or 'aes-128-gcm'
        try:
            p["alterId"] = int(data.get('aid', 0))
        except (ValueError, TypeError):
            p["alterId"] = 0
        return p
    if proto == 'ss':
        pw = _extract_ss_pass(e.uri)
        if not pw:
            return None
        p["type"] = "ss"
        p["password"] = pw
        p["cipher"] = _extract_ss_cipher(e.uri) or "aes-256-gcm"
        return p
    if proto in ('hy2', 'hysteria2'):
        pw = _extract_user(e.uri)
        if not pw:
            return None
        p["type"] = "hysteria2"
        p["password"] = pw
        if e.sni:
            p["servername"] = e.sni
        obfs = _query_param(e.uri, 'obfs')
        if obfs == 'salamander':
            p["obfs"] = "salamander"
            obfs_pw = _query_param(e.uri, 'obfs-password')
            if obfs_pw:
                p["obfs-password"] = obfs_pw
        if _query_param(e.uri, 'insecure') == '1':
            p["skip-cert-verify"] = True
        return p
    if proto in ('socks5', 'http', 'https'):
        p["type"] = "socks5" if proto == 'socks5' else "http"
        up = _extract_user(e.uri)
        if up and ':' in up:
            u, pw = up.split(':', 1)
            p["username"] = u
            p["password"] = pw
        if proto == 'https':
            p["tls"] = True
        return p
    if proto in ('wireguard', 'wg'):
        wg = _parse_wireguard_uri(e.uri)
        if not wg or not wg.get("public_key") or not wg.get("private_key") or not wg.get("address"):
            return None
        p["type"] = "wireguard"
        p["private-key"] = wg["private_key"]
        p["peer-public-key"] = wg["public_key"]
        if wg.get("preshared_key"):
            p["pre-shared-key"] = wg["preshared_key"]
        addrs = [a.strip() for a in wg["address"].split(",") if a.strip()]
        v4 = next((a for a in addrs if ":" not in a), None)
        v6 = next((a for a in addrs if ":" in a), None)
        if v4:
            p["ip"] = v4
        if v6:
            p["ipv6"] = v6
        if wg.get("reserved"):
            try:
                p["reserved"] = [int(x) for x in wg["reserved"].split(",") if x.strip()]
            except ValueError:
                pass
        try:
            p["mtu"] = int(wg["mtu"])
        except (ValueError, TypeError):
            p["mtu"] = 1280
        try:
            p["persistent-keepalive"] = int(wg["keepalive"])
        except (ValueError, TypeError):
            p["persistent-keepalive"] = 25
        p["udp"] = True
        return p
    return None


def _vmess_data(uri: str) -> Optional[dict]:
    """Decode a vmess:// base64 JSON body; None for other protocols / bad input."""
    if not (uri.startswith('vmess://') or uri.startswith('VMESS://')):
        return None
    try:
        b64 = uri.split('://', 1)[-1].split('#')[0].split('?')[0]
        pad = 4 - len(b64) % 4
        if pad != 4:
            b64 += '=' * pad
        return json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
    except Exception:
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
    # vless / trojan / hysteria2 / etc.: auth is the userinfo before '@'
    if '@' in uri:
        userinfo = uri.split('://', 1)[-1].split('@', 1)[0]
        return unquote(userinfo)
    return ""


# Default DNS endpoints — encrypted (DoH) foreign resolvers that survive
# Russian DNS poisoning / port-53 blocking. Plain IPs (1.1.1.1) are NOT safe here.
DEFAULT_DOH = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/dns-query",
    "https://dns.adguard-dns.com/dns-query",
]


def _parse_dns_list(value) -> list[str]:
    """Normalize a DNS spec: None -> built-in DoH, str "a,b" -> [a,b], list passthrough."""
    if not value:
        return list(DEFAULT_DOH)
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


def _looks_like_ip(s: str) -> bool:
    """Return True if the DNS spec is a bare IP (wg-quick DNS= needs this)."""
    s = s.strip()
    if "://" in s or s.startswith("https") or s.startswith("tls"):
        return False
    import re as _re
    return bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s)) or (":" in s and not s.startswith("["))


def _doh_server_spec(url: str, idx: int) -> dict:
    """Xray/v2ray DoH server object."""
    return {"address": url, "port": 443, "tag": f"doh-{idx}"}


def rewrite_dns(text: str, dns=None) -> str:
    """Replace the DNS block of an Xray/v2ray or sing-box config with DoH endpoints.

    Returns pretty-printed JSON. Raises ValueError if the config format is unknown.
    """
    cfg = json.loads(text)
    if not isinstance(cfg, dict):
        raise ValueError("config root is not an object")
    dns_list = _parse_dns_list(dns)
    outbounds = cfg.get("outbounds", [])
    if not isinstance(outbounds, list):
        raise ValueError("no outbounds array")
    is_singbox = any(isinstance(o, dict) and o.get("type") for o in outbounds)
    is_xray = any(isinstance(o, dict) and o.get("protocol") for o in outbounds)
    if is_singbox:
        servers = [{"address": u, "tag": f"dns{i}"} for i, u in enumerate(dns_list)]
        cfg["dns"] = {
            "servers": servers,
            "final": "dns0",
            "independent_cache": True,
        }
    elif is_xray:
        servers = [_doh_server_spec(u, i) for i, u in enumerate(dns_list)]
        dns_block = cfg.get("dns", {})
        if not isinstance(dns_block, dict):
            dns_block = {}
        dns_block["servers"] = servers
        cfg["dns"] = dns_block
    else:
        raise ValueError("cannot detect config format (no recognizable outbounds)")
    return json.dumps(cfg, indent=2, ensure_ascii=False)


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
        "preshared_key": unquote(_v("presharedkey")),
        "reserved": _v("reserved"),
        "mtu": _v("mtu", "1280"),
        "keepalive": _v("keepalive", "25"),
    }


def format_amnezia(entries: list[ProxyEntry], include_failed: bool = False, dns=None) -> str:
    """Concatenated WireGuard .conf blocks for Amnezia import (preview only)."""
    blocks = []
    for i, e in enumerate(entries, 1):
        if e.protocol not in ('WIREGUARD', 'WG'):
            continue
        if not include_failed and not _entry_ok(e):
            continue
        conf = wireguard_conf_from_entry(e, dns=dns)
        if conf:
            blocks.append(f"# {i} — {e.host}:{e.port}\n{conf}")
    return "\n".join(blocks) + "\n"


def wireguard_conf_from_entry(e: ProxyEntry, dns=None) -> Optional[str]:
    """Build a single WireGuard .conf block from a ProxyEntry's wireguard:// URI."""
    if not (e.uri and e.uri.startswith("wireguard://")):
        return None
    p = _parse_wireguard_uri(e.uri)
    if not p:
        return None
    if dns is not None:
        # wg-quick only accepts plain IP addresses in the DNS= line.
        ips = [s for s in _parse_dns_list(dns) if _looks_like_ip(s)]
        dns_line = "DNS = " + (", ".join(ips) if ips else "1.1.1.1, 1.0.0.1")
    else:
        dns_line = "DNS = 1.1.1.1, 1.0.0.1"
    lines = [
        "[Interface]",
        f"PrivateKey = {p['private_key']}",
        f"Address = {p['address']}",
        dns_line,
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

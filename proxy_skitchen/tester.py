import os, sys, json, socket, ssl, subprocess, time, random, tempfile, threading, urllib.request, urllib.parse, urllib.error, re, base64
from collections import Counter
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from datetime import datetime

from .compat import TMP_DIR, HIDDIFY_PROXY, _write_log, DEBUG_LOG_PATHS, IS_WINDOWS, IS_MACOS, CREATE_NO_WINDOW
from .parsers import get_protocol, get_server_port, is_ip
from .exporters import DEFAULT_DOH

def _debug(msg: str):
    _LOG = os.path.join(TMP_DIR, "tester.log")
    if _LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(_LOG)
    _write_log(_LOG, msg)


def doh_resolve(host, doh_list=None, cache=None, timeout=5):
    """Resolve host to IPv4 via DNS-over-HTTPS (hardcoded IP endpoints, no local DNS).
    Falls back to system DNS. Returns IPv4 string or None."""
    if is_ip(host):
        return host
    if cache is not None and host in cache:
        return cache[host]
    doh_list = doh_list or DEFAULT_DOH
    result = None
    for url in doh_list:
        try:
            req = urllib.request.Request(
                f"{url}?name={urllib.parse.quote(host)}&type=A",
                headers={"Accept": "application/dns-json"},
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                data = json.loads(r.read().decode())
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:
                    result = ans.get("data")
                    break
            if result:
                break
        except Exception:
            continue
    if result is None:
        try:
            addrs = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
            if addrs:
                result = addrs[0][4][0]
        except Exception:
            result = None
    if cache is not None and result:
        cache[host] = result
    return result


def _system_resolves(host):
    try:
        return bool(socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM))
    except Exception:
        return False


def _harden_dns(outbound, doh_list, cache, kind):
    """Keep the system-resolved server when the local DNS already works (safe).
    Only fall back to DoH when the local resolver fails (e.g. NXDOMAIN from
    poisoned/blocked DNS). Blindly overriding a working local resolution with a
    public DoH result breaks many proxies whose backend IP differs from the
    CDN/geo IP that public resolvers return."""
    if kind == 'sb':
        srv = outbound.get('server')
        if srv and not is_ip(srv) and not _system_resolves(srv):
            ip = doh_resolve(srv, doh_list, cache)
            if ip:
                outbound['server'] = ip
    else:
        vnext = outbound.get('settings', {}).get('vnext')
        if vnext:
            srv = vnext[0].get('address')
            if srv and not is_ip(srv) and not _system_resolves(srv):
                ip = doh_resolve(srv, doh_list, cache)
                if ip:
                    vnext[0]['address'] = ip


if IS_WINDOWS:
    SING_BOX = os.path.expandvars("%LOCALAPPDATA%\\sing-box\\sing-box.exe")
    XRAY = os.path.expandvars("%LOCALAPPDATA%\\xray\\xray.exe")
elif IS_MACOS:
    SING_BOX = "/usr/local/bin/sing-box"
    XRAY = "/usr/local/bin/xray"
else:
    SING_BOX = "/usr/local/bin/sing-box"
    XRAY = "/usr/local/bin/xray"
TEST_URL = "https://www.gstatic.com/generate_204"
TEST_HOST = "cp.cloudflare.com"
TCP_TIMEOUT = 8
SB_TIMEOUT = 8
SB_SEMAPHORE = threading.Semaphore(3)

RKN_TEST_TIMEOUT = 10


def find_free_port() -> int:
    for _ in range(10):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            time.sleep(0.05)
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(0.5)
            if c.connect_ex(("127.0.0.1", port)) != 0:
                c.close()
                return port
            c.close()
        except Exception:
            continue
    return 19999 + random.randint(0, 999)


def resolve_host(host: str, cache: dict) -> Optional[str]:
    if host in cache:
        return cache[host]
    try:
        addrs = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
        if addrs:
            ip = addrs[0][4][0]
            cache[host] = ip
            return ip
    except Exception:
        pass
    return None


def test_tcp(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    _debug(f"test_tcp: {host}:{port}")
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if not addrs:
            _debug(f"test_tcp: {host}:{port} no addrs")
            return False
        s = socket.socket(addrs[0][0], addrs[0][1], addrs[0][2])
        s.settimeout(timeout)
        s.connect(addrs[0][4])
        s.close()
        _debug(f"test_tcp: {host}:{port} OK")
        return True
    except socket.timeout:
        _debug(f"test_tcp: {host}:{port} timeout")
        return False
    except Exception as e:
        _debug(f"test_tcp: {host}:{port} error {e}")
        return False


def test_tls(host: str, sni: str = "", timeout: float = TCP_TIMEOUT) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        addrs = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        if not addrs:
            return False
        s = socket.socket(addrs[0][0], addrs[0][1], addrs[0][2])
        s.settimeout(timeout)
        s.connect(addrs[0][4])
        tls_sock = ctx.wrap_socket(s, server_hostname=sni or host)
        tls_sock.do_handshake()
        tls_sock.close()
        return True
    except Exception:
        return False


def test_http_proxy(proxy_url: str, url: str = TEST_URL, timeout: float = SB_TIMEOUT) -> tuple[bool, float]:
    start = time.time()
    try:
        handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(handler)
        resp = opener.open(url, timeout=timeout)
        code = resp.getcode()
        body = resp.read(1024)
        elapsed = (time.time() - start) * 1000
        ok = (code == 204) or (code in (200, 301, 302, 303, 307, 308) and len(body) > 0)
        return ok, elapsed
    except Exception:
        return False, (time.time() - start) * 1000


def test_port(host: str, port: int, timeout: float = 1) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def test_via_socks(host: str, port: int, target_host: str = TEST_HOST, target_port: int = 80,
                   timeout: float = 4) -> tuple[bool, float]:
    try:
        import socks as _socks
    except ImportError:
        return False, 0
    start = time.time()
    try:
        s = _socks.socksocket()
        s.set_proxy(_socks.SOCKS5, host, port)
        s.settimeout(timeout)
        s.connect((target_host, target_port))
        s.close()
        elapsed = (time.time() - start) * 1000
        return True, elapsed
    except Exception:
        return False, (time.time() - start) * 1000


class SingBoxTester:
    def __init__(self, use_doh: bool = False, doh_list=None):
        self.use_doh = use_doh
        self.doh_list = doh_list
        self._doh_cache = {}

    def test(self, uri: str, port: int) -> tuple[bool, float, str]:
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported protocol"
        proc = None
        try:
            with tempfile.TemporaryDirectory(prefix="sb_", dir=TMP_DIR) as tmp_dir:
                config_path = os.path.join(tmp_dir, "config.json")
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                outbound = config.get("outbounds", [{}])[0]
                reality = outbound.get("tls", {}).get("reality", {})
                _debug(f"CONFIG reality: pbk={reality.get('public_key','')!r} sid={reality.get('short_id','')!r}")
                with SB_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = subprocess.Popen(
                        [SING_BOX, "run", "-c", config_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.3)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            _, err_b = proc.communicate(timeout=0.5)
                            err = err_b.decode("utf-8", errors="replace")[:200]
                        except Exception:
                            pass
                        return False, 0, f"sb failed: {err}" if err else "sb failed to start"
                    ok, lat = test_http_proxy(f"http://127.0.0.1:{port}", timeout=5)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    proc = None
                return ok, lat, ""
        except Exception as e:
            return False, 0, str(e)
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass

    def _probe(self, proxy_url: str, domain: str, marker: str | None = None, expect_code: int = 200) -> tuple[bool, int, float]:
        url = "https://" + domain
        try:
            start = time.time()
            handler = urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url})
            opener = urllib.request.build_opener(handler)
            opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
            resp = opener.open(url, timeout=RKN_TEST_TIMEOUT)
            code = resp.getcode()
            body = resp.read(8192).decode("utf-8", errors="ignore") if expect_code == 200 else ""
            elapsed = (time.time() - start) * 1000
            if expect_code == 204:
                ok = code == 204
            else:
                ok = code == 200 and len(body) > 500
                if marker and ok:
                    ok = marker in body.lower()
            _debug(f"_probe {domain}: code={code} ok={ok}")
            return ok, code, elapsed
        except Exception as e:
            _debug(f"_probe {domain}: exc {e}")
            return False, 0, 0.0

    def test_rkn_bypass(self, uri: str, port: int) -> tuple[bool, float, str, list[dict]]:
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported protocol", []
        proc = None
        results = []
        try:
            with tempfile.TemporaryDirectory(prefix="sb_rkn_", dir=TMP_DIR) as tmp_dir:
                config_path = os.path.join(tmp_dir, "config.json")
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                with SB_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = subprocess.Popen(
                        [SING_BOX, "run", "-c", config_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    proxy_url = f"http://127.0.0.1:{port}"
                    # RKN bypass: at least one blocked-in-RU site must really open
                    targets = [("t.me", "Telegram", "telegram"),
                               ("instagram.com", "Instagram", "instagram"),
                               ("youtube.com", "YouTube", "youtube"),
                               ("twitter.com", "Twitter", "twitter")]
                    any_open = False
                    best_lat = 0.0
                    with ThreadPoolExecutor(max_workers=4) as ex:
                        futs = {ex.submit(self._probe, proxy_url, d, mk): (d, n) for d, n, mk in targets}
                        for fut in as_completed(futs):
                            d, n = futs[fut]
                            try:
                                ok, code, lat = fut.result()
                            except Exception:
                                ok, code, lat = False, 0, 0.0
                            results.append({"domain": d, "name": n, "ok": ok, "latency": lat, "status": code})
                            if ok and lat > 0:
                                any_open = True
                                best_lat = lat if best_lat <= 0 else min(best_lat, lat)
                            _debug(f"rkn_bypass: {uri[:60]} {d} ok={ok} code={code}")
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    proc = None
                ok = any_open
                _debug(f"rkn_bypass: {uri[:60]} any_open={any_open} ok={ok}")
                return ok, best_lat, "" if ok else "не открывает заблокированные", results
        except Exception as e:
            return False, 0, str(e), results
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass

    def _make_config(self, uri: str, local_port: int) -> Optional[dict]:
        proto = get_protocol(uri)
        outbound = self._parse(uri)
        if outbound is None:
            return None
        if self.use_doh:
            _harden_dns(outbound, self.doh_list, self._doh_cache, 'sb')
        outbound["tag"] = "proxy"
        return {
            "log": {"level": "error", "output": "nul" if IS_WINDOWS else "/dev/null"},
            "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": local_port}],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": "proxy"},
        }

    def _parse(self, uri: str) -> Optional[dict]:
        try:
            proto = get_protocol(uri)
            line = uri.strip()
            if proto == 'vless':
                return self._parse_vless(line)
            if proto == 'trojan':
                return self._parse_trojan(line)
            if proto == 'vmess':
                return self._parse_vmess(line)
            if proto == 'ss':
                return self._parse_ss(line)
            if proto in ('hy2', 'hysteria2'):
                return self._parse_hysteria2(line)
            if proto == 'tuic':
                return self._parse_tuic(line)
            if proto == 'socks':
                return self._parse_socks(line)
            if proto == 'http':
                return self._parse_http(line)
            return None
        except Exception:
            return None

    def _q(self, uri: str) -> dict:
        qm = uri.find('?')
        if qm == -1:
            return {}
        rest = uri[qm + 1:]
        h = rest.find('#')
        if h != -1:
            rest = rest[:h]
        return urllib.parse.parse_qs(rest)

    def _qv(self, q: dict, key: str, default=""):
        vals = q.get(key, [])
        return vals[0] if vals else default

    def _parse_vless(self, uri: str) -> dict:
        clean = uri.replace('vless://', '')
        q = self._q(clean)
        at = clean.find('@')
        uuid = clean[:at]
        rest = clean[at + 1:]
        qm = rest.find('?')
        hp = rest[:qm] if qm != -1 else rest
        colon = hp.rfind(':')
        host = hp[:colon]
        try:
            port = int(hp[colon + 1:])
        except Exception:
            port = 443
        flow = self._qv(q, 'flow')
        security = self._qv(q, 'security', '')
        sni = self._qv(q, 'sni', host)
        fp = self._qv(q, 'fp', 'chrome')
        alpn = self._qv(q, 'alpn', 'http/1.1')
        out = {"type": "vless", "server": host, "server_port": port, "uuid": uuid,
               "packet_encoding": "xudp"}
        if flow:
            out["flow"] = flow
        if security == 'reality':
            pbk_raw = self._qv(q, 'pbk')
            pbk = pbk_raw.split('#')[0].replace(' ', '+').replace('+', '-').replace('/', '_')
            sid = self._qv(q, 'sid', '').replace(' ', '+')
            _debug(f"pbk_raw={pbk_raw!r} pbk_fixed={pbk!r} sid={sid!r}")
            out["tls"] = {"enabled": True, "server_name": sni or host,
                          "alpn": alpn,
                          "utls": {"enabled": True, "fingerprint": fp},
                          "reality": {"enabled": True, "public_key": pbk, "short_id": sid}}
        elif security in ('tls', 'xtls'):
            out["tls"] = {"enabled": True, "server_name": sni or host,
                          "alpn": alpn,
                          "utls": {"enabled": True, "fingerprint": fp}}
        ttype = self._qv(q, 'type', 'tcp')
        if ttype == 'ws':
            path = self._qv(q, 'path', '/')
            hdr = self._qv(q, 'host', sni or host)
            out["transport"] = {"type": "ws", "path": path,
                                "headers": {"Host": hdr},
                                "early_data_header_name": "Sec-WebSocket-Protocol"}
        elif ttype == 'grpc':
            out["transport"] = {"type": "grpc", "service_name": self._qv(q, 'serviceName', '')}
        elif ttype == 'xhttp':
            xhttp_mode = self._qv(q, 'mode', 'auto')
            xhttp_host = self._qv(q, 'host', '')
            xhttp_path = self._qv(q, 'path', '/')
            out["transport"] = {"type": "xhttp", "mode": xhttp_mode}
            if xhttp_host:
                out["transport"]["host"] = xhttp_host
            if xhttp_path:
                out["transport"]["path"] = xhttp_path
        return out

    def _parse_trojan(self, uri: str) -> dict:
        clean = uri.replace('trojan://', '')
        q = self._q(clean)
        at = clean.find('@')
        password = clean[:at]
        rest = clean[at + 1:]
        qm = rest.find('?')
        hp = rest[:qm] if qm != -1 else rest
        colon = hp.rfind(':')
        host = hp[:colon]
        try:
            port = int(hp[colon + 1:])
        except Exception:
            port = 443
        sni = self._qv(q, 'sni', host)
        fp = self._qv(q, 'fp', 'chrome')
        alpn = self._qv(q, 'alpn', 'http/1.1')
        out = {"type": "trojan", "server": host, "server_port": port, "password": password,
               "packet_encoding": "xudp",
               "tls": {"enabled": True, "server_name": sni or host,
                       "alpn": alpn}}
        if fp:
            out["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        ttype = self._qv(q, 'type', 'tcp')
        if ttype == 'ws':
            path = self._qv(q, 'path', '/')
            hdr = self._qv(q, 'host', sni or host)
            out["transport"] = {"type": "ws", "path": path,
                                "headers": {"Host": hdr},
                                "early_data_header_name": "Sec-WebSocket-Protocol"}
        elif ttype == 'grpc':
            out["transport"] = {"type": "grpc", "service_name": self._qv(q, 'serviceName', '')}
        elif ttype == 'xhttp':
            xhttp_mode = self._qv(q, 'mode', 'auto')
            xhttp_host = self._qv(q, 'host', '')
            xhttp_path = self._qv(q, 'path', '/')
            out["transport"] = {"type": "xhttp", "mode": xhttp_mode}
            if xhttp_host:
                out["transport"]["host"] = xhttp_host
            if xhttp_path:
                out["transport"]["path"] = xhttp_path
        return out

    def _parse_vmess(self, uri: str) -> Optional[dict]:
        b64 = uri.replace('vmess://', '')
        pad = 4 - len(b64) % 4
        if pad != 4:
            b64 += '=' * pad
        data = json.loads(base64.b64decode(b64))
        host = data.get('add', '')
        port = int(data.get('port', 443))
        uuid = data.get('id', '')
        net = data.get('net', 'tcp')
        tls = data.get('tls', '')
        sni = data.get('sni', host)
        path = data.get('path', '/')
        host_hdr = data.get('host', host)
        alpn = data.get('alpn', 'http/1.1')
        out = {"type": "vmess", "server": host, "server_port": port, "uuid": uuid,
               "alter_id": int(data.get('aid', 0)), "packet_encoding": "xudp"}
        if tls:
            out["tls"] = {"enabled": True, "server_name": sni or host,
                          "alpn": alpn,
                          "utls": {"enabled": True, "fingerprint": "chrome"}}
        if net == 'ws':
            out["transport"] = {"type": "ws", "path": path,
                                "headers": {"Host": host_hdr},
                                "early_data_header_name": "Sec-WebSocket-Protocol"}
        elif net == 'grpc':
            out["transport"] = {"type": "grpc", "service_name": path.lstrip('/')}
        return out

    def _parse_ss(self, uri: str) -> Optional[dict]:
        clean = uri.replace('ss://', '')
        q = self._q(clean)
        at = clean.find('@')
        if at == -1:
            b64_part = clean.split('?')[0].split('#')[0]
            try:
                pad = 4 - len(b64_part) % 4
                if pad != 4:
                    b64_part += '=' * pad
                decoded = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
                at2 = decoded.find('@')
                if at2 == -1:
                    return None
                mp = decoded[:at2]
                hp = decoded[at2 + 1:]
            except Exception:
                return None
        else:
            mp_b64 = clean[:at]
            try:
                pad = 4 - len(mp_b64) % 4
                if pad != 4:
                    mp_b64 += '=' * pad
                mp = base64.b64decode(mp_b64).decode('utf-8', errors='ignore')
            except Exception:
                mp = mp_b64
            hp = clean[at + 1:]
        qm = hp.find('?')
        if qm != -1:
            hp = hp[:qm]
        colon = hp.rfind(':')
        host = hp[:colon]
        try:
            port = int(hp[colon + 1:])
        except Exception:
            port = 443
        colon2 = mp.find(':')
        method = mp[:colon2]
        password = mp[colon2 + 1:]
        out = {"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}
        plugin = self._qv(q, 'plugin', '')
        if plugin:
            out["plugin"] = plugin
        return out

    def _parse_hysteria2(self, uri: str) -> Optional[dict]:
        clean = uri.replace('hysteria2://', '').replace('hy2://', '')
        q = self._q(clean)
        auth = self._qv(q, 'auth', '')
        at = clean.find('@')
        if at != -1:
            auth = clean[:at]
            rest = clean[at + 1:]
        else:
            auth = self._qv(q, 'auth', clean.split('?')[0].split('#')[0])
            rest = clean
        qm = rest.find('?')
        hp = rest[:qm] if qm != -1 else rest
        colon = hp.rfind(':')
        host = hp[:colon] if colon != -1 else hp
        try:
            port = int(hp[colon + 1:]) if colon != -1 else 443
        except Exception:
            port = 443
        sni = self._qv(q, 'sni', host)
        insecure = self._qv(q, 'insecure', '0') in ('1', 'true')
        return {"type": "hysteria2", "server": host, "server_port": port, "password": auth,
                "tls": {"enabled": True, "server_name": sni or host, "insecure": insecure}}

    def _parse_tuic(self, uri: str) -> Optional[dict]:
        clean = uri.replace('tuic://', '')
        # strip fragment for query parsing
        q = self._q(clean.split('#')[0])
        at = clean.find('@')
        uuid = password = ""
        if at != -1:
            up = clean[:at]
            colon = up.find(':')
            if colon != -1:
                uuid = up[:colon]
                password = up[colon + 1:]
            else:
                uuid = up
            rest = clean[at + 1:]
        else:
            rest = clean
            uuid = self._qv(q, 'uuid', '')
            password = self._qv(q, 'password', '')
        if not uuid or not password:
            return None
        qm = rest.find('?')
        hp = rest[:qm] if qm != -1 else rest
        hash_pos = hp.find('#')
        if hash_pos != -1:
            hp = hp[:hash_pos]
        colon = hp.rfind(':')
        host = hp[:colon] if colon != -1 else hp
        try:
            port = int(hp[colon + 1:]) if colon != -1 else 443
        except Exception:
            port = 443
        sni = self._qv(q, 'sni', host)
        cc = self._qv(q, 'congestion_control', 'bbr')
        out = {"type": "tuic", "server": host, "server_port": port,
               "uuid": uuid, "password": password,
               "tls": {"enabled": True, "server_name": sni or host}}
        if cc:
            out["congestion_control"] = cc
        return out

    def _parse_socks(self, uri: str) -> Optional[dict]:
        l = uri.strip().lower()
        version = 5 if l.startswith('socks5://') else 4
        clean = uri.replace('socks5://', '').replace('socks4://', '')
        at = clean.find('@')
        user = passwd = ''
        if at != -1:
            up = clean[:at]
            colon = up.find(':')
            if colon != -1:
                user = up[:colon]
                passwd = up[colon + 1:]
            rest = clean[at + 1:]
        else:
            rest = clean
        qm = rest.find('?')
        if qm != -1:
            rest = rest[:qm]
        h = rest.find('#')
        if h != -1:
            rest = rest[:h]
        colon = rest.rfind(':')
        host = rest[:colon]
        try:
            port = int(rest[colon + 1:])
        except Exception:
            port = 1080
        out = {"type": "socks", "server": host, "server_port": port, "version": f"Socks{version}"}
        if user:
            out["username"] = user
        if passwd:
            out["password"] = passwd
        return out

    def _parse_http(self, uri: str) -> Optional[dict]:
        clean = uri.replace('https://', '').replace('http://', '')
        qm = clean.find('?')
        if qm != -1:
            clean = clean[:qm]
        h = clean.find('#')
        if h != -1:
            clean = clean[:h]
        at = clean.find('@')
        user = passwd = ''
        if at != -1:
            up = clean[:at]
            colon = up.find(':')
            if colon != -1:
                user = up[:colon]
                passwd = up[colon + 1:]
            clean = clean[at + 1:]
        colon = clean.rfind(':')
        host = clean[:colon]
        try:
            port = int(clean[colon + 1:])
        except Exception:
            port = 8080
        out = {"type": "http", "server": host, "server_port": port}
        if user:
            out["username"] = user
        if passwd:
            out["password"] = passwd
        return out


class XrayTester:
    XRAY_SEMAPHORE = threading.Semaphore(2)

    def __init__(self, use_doh: bool = False, doh_list=None):
        self.use_doh = use_doh
        self.doh_list = doh_list
        self._doh_cache = {}

    def _probe(self, proxy_url: str, domain: str, marker: str | None = None, expect_code: int = 200) -> tuple[bool, int, float]:
        url = "https://" + domain
        try:
            start = time.time()
            handler = urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url})
            opener = urllib.request.build_opener(handler)
            opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
            resp = opener.open(url, timeout=RKN_TEST_TIMEOUT)
            code = resp.getcode()
            body = resp.read(8192).decode("utf-8", errors="ignore") if expect_code == 200 else ""
            elapsed = (time.time() - start) * 1000
            if expect_code == 204:
                ok = code == 204
            else:
                ok = code == 200 and len(body) > 500
                if marker and ok:
                    ok = marker in body.lower()
            _debug(f"_probe {domain}: code={code} ok={ok}")
            return ok, code, elapsed
        except Exception as e:
            _debug(f"_probe {domain}: exc {e}")
            return False, 0, 0.0

    def test_rkn(self, uri: str, port: int) -> tuple[bool, float, str, list]:
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported protocol", []
        proc = None
        results = []
        try:
            with tempfile.TemporaryDirectory(prefix="xr_rkn_", dir=TMP_DIR) as tmp_dir:
                config_path = os.path.join(tmp_dir, "config.json")
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                with self.XRAY_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = subprocess.Popen(
                        [XRAY, "run", "-c", config_path],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            out_b, err_b = proc.communicate(timeout=0.5)
                            err = (out_b + err_b).decode("utf-8", errors="replace")[:200]
                        except Exception:
                            pass
                        return False, 0, f"xray err: {err}" if err else "xray failed to start", []
                    proxy_url = f"http://127.0.0.1:{port}"
                    # RKN bypass: at least one blocked-in-RU site must really open
                    targets = [("t.me", "Telegram", "telegram"),
                               ("instagram.com", "Instagram", "instagram"),
                               ("youtube.com", "YouTube", "youtube"),
                               ("twitter.com", "Twitter", "twitter")]
                    any_open = False
                    best_lat = 0.0
                    with ThreadPoolExecutor(max_workers=4) as ex:
                        futs = {ex.submit(self._probe, proxy_url, d, mk): (d, n) for d, n, mk in targets}
                        for fut in as_completed(futs):
                            d, n = futs[fut]
                            try:
                                ok, code, lat = fut.result()
                            except Exception:
                                ok, code, lat = False, 0, 0.0
                            results.append({"domain": d, "name": n, "ok": ok, "latency": lat, "status": code})
                            if ok and lat > 0:
                                any_open = True
                                best_lat = lat if best_lat <= 0 else min(best_lat, lat)
                            _debug(f"xr_rkn: {uri[:60]} {d} ok={ok} code={code}")
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    proc = None
                ok = any_open
                _debug(f"xr_rkn: {uri[:60]} any_open={any_open} ok={ok}")
                return ok, best_lat, "" if ok else "не открывает заблокированные", results
        except Exception as e:
            return False, 0, str(e), results
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass

    def test(self, uri: str, port: int) -> tuple[bool, float, str]:
        if not os.path.isfile(XRAY):
            return False, 0, f"xray не найден: {XRAY}"
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported protocol"
        proc = None
        try:
            with tempfile.TemporaryDirectory(prefix="xr_", dir=TMP_DIR) as tmp_dir:
                config_path = os.path.join(tmp_dir, "config.json")
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                with self.XRAY_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = subprocess.Popen(
                        [XRAY, "run", "-c", config_path],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            out_b, err_b = proc.communicate(timeout=0.5)
                            err = (out_b + err_b).decode("utf-8", errors="replace")[:200]
                        except Exception:
                            pass
                        return False, 0, f"xray err: {err}" if err else "xray failed to start"
                    ok, lat = test_http_proxy(f"http://127.0.0.1:{port}", timeout=5)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    proc = None
                return ok, lat, ""
        except Exception as e:
            return False, 0, str(e)
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass

    def _make_config(self, uri: str, local_port: int) -> Optional[dict]:
        proto = get_protocol(uri)
        if proto != 'vless':
            return None
        outbound = self._parse_vless(uri)
        if outbound is None:
            return None
        if self.use_doh:
            _harden_dns(outbound, self.doh_list, self._doh_cache, 'xray')
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "http", "settings": {}}],
            "outbounds": [outbound],
        }

    def _parse_vless(self, uri: str) -> Optional[dict]:
        try:
            clean = uri.replace('vless://', '')
            q = self._q(clean)
            at = clean.find('@')
            uuid = clean[:at]
            rest = clean[at + 1:]
            qm = rest.find('?')
            hp = rest[:qm] if qm != -1 else rest
            colon = hp.rfind(':')
            host = hp[:colon]
            try:
                port = int(hp[colon + 1:])
            except Exception:
                port = 443
            flow = self._qv(q, 'flow')
            security = self._qv(q, 'security', '')
            sni = self._qv(q, 'sni', host)
            fp = self._qv(q, 'fp', 'chrome')
            alpn = self._qv(q, 'alpn', 'http/1.1')
            ttype = self._qv(q, 'type', 'tcp')

            vnext = {
                "address": host,
                "port": port,
                "users": [{"id": uuid, "encryption": "none"}]
            }
            if flow:
                vnext["users"][0]["flow"] = flow

            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [vnext]},
                "streamSettings": {"network": ttype}
            }

            if security == 'reality':
                pbk = self._qv(q, 'pbk').replace(' ', '+').replace('+', '-').replace('/', '_')
                sid = self._qv(q, 'sid', '').replace(' ', '+')
                outbound["streamSettings"]["security"] = "reality"
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": sni or host,
                    "fingerprint": fp,
                    "publicKey": pbk,
                    "shortId": sid,
                }
            elif security in ('tls', 'xtls'):
                outbound["streamSettings"]["security"] = "tls"
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni or host,
                    "fingerprint": fp,
                    "alpn": [alpn],
                }

            if ttype == 'ws':
                path = self._qv(q, 'path', '/')
                hdr = self._qv(q, 'host', sni or host)
                outbound["streamSettings"]["wsSettings"] = {
                    "path": path,
                    "headers": {"Host": hdr},
                }
            elif ttype == 'grpc':
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": self._qv(q, 'serviceName', ''),
                }
            elif ttype == 'xhttp':
                host_hdr = self._qv(q, 'host', '')
                path = self._qv(q, 'path', '/')
                mode = self._qv(q, 'mode', 'auto')
                outbound["streamSettings"]["xhttpSettings"] = {
                    "mode": mode,
                    "host": host_hdr or host,
                    "path": path,
                }
            return outbound
        except Exception:
            return None

    def _q(self, uri: str) -> dict:
        qm = uri.find('?')
        if qm == -1:
            return {}
        rest = uri[qm + 1:]
        h = rest.find('#')
        if h != -1:
            rest = rest[:h]
        return urllib.parse.parse_qs(rest)

    def _qv(self, q: dict, key: str, default=""):
        vals = q.get(key, [])
        return vals[0] if vals else default

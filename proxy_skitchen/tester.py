import os, sys, json, socket, ssl, subprocess, time, random, tempfile, threading, urllib.request, urllib.parse, re, base64
from collections import Counter
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from datetime import datetime

from .compat import TMP_DIR, HIDDIFY_PROXY, _write_log, DEBUG_LOG_PATHS, IS_WINDOWS, IS_MACOS, CREATE_NO_WINDOW
from .parsers import get_protocol, get_server_port, is_ip

def _debug(msg: str):
    _LOG = os.path.join(TMP_DIR, "tester.log")
    if _LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(_LOG)
    _write_log(_LOG, msg)

if IS_WINDOWS:
    SING_BOX = os.path.expandvars("%LOCALAPPDATA%\\sing-box\\sing-box.exe")
    XRAY = os.path.expandvars("%LOCALAPPDATA%\\xray\\xray.exe")
elif IS_MACOS:
    SING_BOX = "/usr/local/bin/sing-box"
    XRAY = "/usr/local/bin/xray"
else:
    SING_BOX = "/usr/local/bin/sing-box"
    XRAY = "/usr/local/bin/xray"
TEST_URL = "http://cp.cloudflare.com/generate_204"
TEST_HOST = "cp.cloudflare.com"
TCP_TIMEOUT = 8
SB_TIMEOUT = 8
SB_SEMAPHORE = threading.Semaphore(3)

RKN_BLOCKED_DOMAINS = [
    ("rutracker.org", "RuTracker"),
    ("meduza.io", "Медуза"),
]

RKN_TEST_TIMEOUT = 6


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
        elapsed = (time.time() - start) * 1000
        return resp.status == 204, elapsed
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
        if target_port == 80:
            s.send(b"GET /generate_204 HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\nConnection: close\r\n\r\n")
            data = s.recv(1024)
        s.close()
        elapsed = (time.time() - start) * 1000
        return True, elapsed
    except Exception:
        return False, (time.time() - start) * 1000


class SingBoxTester:
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
                with SB_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = subprocess.Popen(
                        [SING_BOX, "run", "-c", config_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.3)
                    if proc.poll() is not None:
                        return False, 0, "sing-box failed to start"
                    if not test_port("127.0.0.1", port, timeout=1):
                        return False, 0, "port not opened"
                    ok, lat = test_via_socks("127.0.0.1", port, timeout=3)
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

    def test_rkn_bypass(self, uri: str, port: int, max_domains: int = 2) -> tuple[bool, float, str, list[dict]]:
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported protocol", []
        proc = None
        results = []
        result = (False, 0.0, "", results)
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
                    basic_ok, basic_lat = test_http_proxy(proxy_url)
                    if not basic_ok:
                        result = (False, 0, "proxy not working", results)
                    else:
                        import random as _rnd
                        test_domains = _rnd.sample(RKN_BLOCKED_DOMAINS, min(max_domains, len(RKN_BLOCKED_DOMAINS)))
                        success_count = 0
                        total_lat = 0.0
                        for domain, name in test_domains:
                            try:
                                url = f"https://{domain}/"
                                start = time.time()
                                handler = urllib.request.ProxyHandler({"https": proxy_url, "http": proxy_url})
                                opener = urllib.request.build_opener(handler)
                                opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
                                resp = opener.open(url, timeout=RKN_TEST_TIMEOUT)
                                code = resp.getcode()
                                elapsed = (time.time() - start) * 1000
                                ok = code in (200, 301, 302, 304)
                                if ok:
                                    success_count += 1
                                    total_lat += elapsed
                                results.append({"domain": domain, "name": name, "ok": ok, "latency": elapsed, "status": code})
                            except Exception as ex:
                                err_str = str(ex)[:60]
                                results.append({"domain": domain, "name": name, "ok": False, "latency": 0, "status": 0, "error": err_str})
                        rkn_ok = success_count >= max(1, len(test_domains) // 2)
                        avg_lat = total_lat / max(success_count, 1)
                        result = (rkn_ok, avg_lat, "", results)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    proc = None
                return result
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
        return urllib.parse.parse_qs(uri[qm + 1:])

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
        out = {"type": "vless", "server": host, "server_port": port, "uuid": uuid}
        if flow:
            out["flow"] = flow
        if security == 'reality':
            pbk = self._qv(q, 'pbk')
            sid = self._qv(q, 'sid', '')
            out["tls"] = {"enabled": True, "server_name": sni or host,
                          "utls": {"enabled": True, "fingerprint": fp},
                          "reality": {"enabled": True, "public_key": pbk, "short_id": sid}}
        elif security in ('tls', 'xtls', ''):
            out["tls"] = {"enabled": True, "server_name": sni or host}
        ttype = self._qv(q, 'type', 'tcp')
        if ttype == 'ws':
            path = self._qv(q, 'path', '/')
            hdr = self._qv(q, 'host', sni or host)
            out["transport"] = {"type": "ws", "path": path, "headers": {"Host": hdr}}
        elif ttype == 'grpc':
            out["transport"] = {"type": "grpc", "service_name": self._qv(q, 'serviceName', '')}
        elif ttype == 'xhttp':
            out["transport"] = {"type": "xhttp", "mode": self._qv(q, 'mode', 'auto')}
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
        out = {"type": "trojan", "server": host, "server_port": port, "password": password,
               "tls": {"enabled": True, "server_name": sni or host}}
        if fp:
            out["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        ttype = self._qv(q, 'type', 'tcp')
        if ttype == 'ws':
            path = self._qv(q, 'path', '/')
            hdr = self._qv(q, 'host', sni or host)
            out["transport"] = {"type": "ws", "path": path, "headers": {"Host": hdr}}
        elif ttype == 'grpc':
            out["transport"] = {"type": "grpc", "service_name": self._qv(q, 'serviceName', '')}
        elif ttype == 'xhttp':
            out["transport"] = {"type": "xhttp", "mode": self._qv(q, 'mode', 'auto')}
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
        out = {"type": "vmess", "server": host, "server_port": port, "uuid": uuid, "alter_id": int(data.get('aid', 0))}
        if tls:
            out["tls"] = {"enabled": True, "server_name": sni or host}
        if net == 'ws':
            out["transport"] = {"type": "ws", "path": path, "headers": {"Host": host_hdr}}
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

import os, sys, json, socket, ssl, subprocess, time, random, tempfile, threading, urllib.request, urllib.parse, urllib.error, re, base64, statistics
from collections import Counter
from dataclasses import dataclass, field
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

# RKN targets: (domain, human name, body marker, category)
RKN_TARGETS = (
    ("t.me", "Telegram", "telegram", "messenger"),
    ("instagram.com", "Instagram", "instagram", "social"),
    ("youtube.com", "YouTube", "youtube", "video"),
    ("twitter.com", "Twitter", "twitter", "social"),
)
RKN_TARGETS_EXTENDED = RKN_TARGETS + (
    ("meduza.io", "Meduza", "meduza", "news"),
    ("github.com", "GitHub", "github", "dev"),
)

# Xray TLS-fragmentation profile (commonly used against SNI-based DPI).
XRAY_FRAGMENT_DEFAULT = {
    "packets": "tlshello",
    "length": "100-200",
    "interval": "10-20",
}


# ── Fair probing ──────────────────────────────────────────────────────────
# A single request to one URL is too easy to fool: ISP block pages return 200
# with a body, and one timeout does not prove a proxy is dead.  Deep testing
# uses several independent targets, validates their content and retries.

@dataclass(frozen=True)
class ProbeTarget:
    url: str
    kind: str = "status"        # empty204 | trace | marker | status
    marker: str = ""
    category: str = "control"
    min_bytes: int = 0


CONTROL_TARGETS = (
    ProbeTarget("https://cp.cloudflare.com/cdn-cgi/trace", "trace", category="control"),
    ProbeTarget("https://www.gstatic.com/generate_204", "empty204", category="control"),
)

# Mirror of XTLS/libXray (the library Happ uses): one HEAD request through the
# node, any HTTP response counts as alive, one attempt, fixed timeout.
HAPP_TARGET = "https://www.gstatic.com/generate_204"
HAPP_TIMEOUT = 5.0
_HAPP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
GENERATE_204_TARGET = ProbeTarget(TEST_URL, "empty204")
# DEEP mirrors the Happ app's check: one target, one attempt, fixed 5 s, no
# second core.  Content is still validated (fair logic), so a block page that
# returns 200 does not count as a tunnel.
DEEP_TARGETS = (ProbeTarget(TEST_URL, "head_any"),)
DEEP_TIMEOUT = HAPP_TIMEOUT
INFRA_TARGETS = (
    ProbeTarget("https://github.com", "marker", "github", category="infra", min_bytes=500),
    ProbeTarget("https://1.1.1.1/cdn-cgi/trace", "trace", category="infra"),
)


@dataclass
class ProbeAttempt:
    ok: bool
    code: int = 0
    latency_ms: float = 0.0
    size: int = 0
    error: str = ""


@dataclass
class ProbeResult:
    target: ProbeTarget
    attempts: list = field(default_factory=list)
    ok: bool = False
    success_ratio: float = 0.0
    latency_ms: float = 0.0
    reason: str = ""


def validate_probe_response(target: ProbeTarget, code: int, body: bytes) -> tuple[bool, str]:
    """Validate content, not just the status code.

    A captive portal or ISP block page often returns 200 with HTML; it must not
    count as a working tunnel.
    """
    size = len(body)
    if target.kind == "empty204":
        if code == 204 and size == 0:
            return True, ""
        if code == 204:
            return False, "204_with_body"
        return False, f"http_{code}"
    if target.kind == "head_any":
        # Happ (libXray) accepts any HTTP answer to a HEAD request.  5xx is
        # excluded because our HTTP proxy inbound synthesises it when the
        # outbound fails; a real gstatic 204 target never returns 5xx.
        if 200 <= code < 500:
            return True, ""
        return False, f"http_{code}"
    if target.kind == "trace":
        low = body.lower()
        if code == 200 and b"ip=" in low and (b"colo=" in low or b"warp=" in low):
            return True, ""
        return False, f"trace_invalid_{code}"
    if target.kind == "marker":
        marker = target.marker.lower().encode("utf-8")
        if code == 200 and size >= target.min_bytes and marker in body.lower():
            return True, ""
        return False, f"marker_missing_{code}"
    if code in (200, 301, 302, 303, 307, 308) and size >= target.min_bytes:
        return True, ""
    return False, f"http_{code}"


def _probe_error_reason(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"http_{exc.code}"
    if isinstance(exc, urllib.error.URLError):
        inner = getattr(exc, "reason", None)
        if isinstance(inner, BaseException):
            return _probe_error_reason(inner)
        text = str(inner).lower()
        if "timed out" in text or "timeout" in text:
            return "timeout"
        if "reset" in text:
            return "reset"
        return "urlerror"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ssl.SSLError):
        return "tls_error"
    return type(exc).__name__.lower()


def happ_head(proxy_url: str, url: str = HAPP_TARGET,
              timeout: float = HAPP_TIMEOUT) -> tuple[bool, float, str]:
    """One HEAD request through the node, judged the way Happ judges it.

    XTLS/libXray treats any HTTP answer — including 403/404 and a block page —
    as a live node, so a status code is not validated here either.  The point
    is to reproduce Happ's verdict, not to be right about content; the fair
    check (``CONTROL_TARGETS``) stays the truthful one.
    """
    start = time.time()
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        request = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": _HAPP_UA})
        response = opener.open(request, timeout=timeout)
        response.close()
        return True, (time.time() - start) * 1000, ""
    except urllib.error.HTTPError as exc:
        # A 5xx here is produced by the local proxy inbound when the outbound
        # failed, not by gstatic; counting it as alive was a false positive.
        if 500 <= exc.code < 600:
            return False, (time.time() - start) * 1000, f"http_{exc.code}"
        return True, (time.time() - start) * 1000, ""
    except Exception as exc:
        return False, (time.time() - start) * 1000, _probe_error_reason(exc)


def summarize_attempts(attempts: list[ProbeAttempt]) -> tuple[bool, float, float, str]:
    """Pure verdict for a list of attempts: (ok, ratio, median_latency, reason)."""
    if not attempts:
        return False, 0.0, 0.0, "probe_failed"
    successes = [a for a in attempts if a.ok]
    ratio = len(successes) / len(attempts)
    need = max(1, (len(attempts) + 1) // 2)
    ok = len(successes) >= need
    latency = statistics.median(a.latency_ms for a in successes) if successes else 0.0
    reason = ""
    if not ok:
        reasons = [a.error for a in attempts if a.error]
        reason = Counter(reasons).most_common(1)[0][0] if reasons else "unknown"
    return ok, ratio, latency, reason


def _single_attempt(proxy_url: str, target: ProbeTarget, timeout: float) -> ProbeAttempt:
    start = time.time()
    try:
        handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(handler)
        opener.addheaders = [(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        )]
        if target.kind == "head_any":
            request = urllib.request.Request(
                target.url, method="HEAD",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                                       "Chrome/120.0 Safari/537.36"})
            resp = opener.open(request, timeout=timeout)
        else:
            resp = opener.open(target.url, timeout=timeout)
        code = resp.getcode()
        if target.kind == "head_any":
            # HEAD has no body; reading it would block until the connection
            # closes on some cores.
            resp.close()
            body = b""
        else:
            body = resp.read(262144)
        latency = (time.time() - start) * 1000
        ok, reason = validate_probe_response(target, code, body)
        return ProbeAttempt(ok, code, latency, len(body), reason)
    except Exception as exc:
        return ProbeAttempt(False, 0, (time.time() - start) * 1000, 0, _probe_error_reason(exc))


def _strict_verdict(result: ProbeResult):
    """Require every attempt to pass (used by the two-HEAD DEEP gate)."""
    attempts = result.attempts
    if not attempts:
        result.ok, result.success_ratio, result.latency_ms, result.reason = False, 0.0, 0.0, "probe_failed"
        return
    successes = [a for a in attempts if a.ok]
    failures = [a for a in attempts if not a.ok]
    result.success_ratio = len(successes) / len(attempts)
    result.ok = not failures
    result.latency_ms = statistics.median(a.latency_ms for a in successes) if successes else 0.0
    result.reason = "" if result.ok else (failures[0].error or "probe_failed")


def probe_target(proxy_url: str, target: ProbeTarget, attempts: int = 1,
                 timeout: float = 5.0, pause: tuple = (0.15, 0.45),
                 require_all: bool = False) -> ProbeResult:
    """Probe one target several times and decide by success ratio."""
    attempts = max(1, int(attempts))
    result = ProbeResult(target=target)
    for idx in range(attempts):
        result.attempts.append(_single_attempt(proxy_url, target, timeout))
        if not require_all and result.attempts[-1].ok:
            break
        if idx < attempts - 1:
            time.sleep(random.uniform(*pause))
    if require_all:
        _strict_verdict(result)
    else:
        result.ok, result.success_ratio, result.latency_ms, result.reason = summarize_attempts(result.attempts)
    return result


def probe_targets_rounds(proxy_url: str, targets, attempts: int = 1,
                         timeout: float = 5.0, pause: tuple = (0.15, 0.45),
                         require_all: bool = False) -> list[ProbeResult]:
    """Probe several targets in parallel rounds, stopping at the first success.

    Working proxies finish in the first round; dead ones pay for every round
    but the rounds run in parallel across targets, so the cost stays bounded.
    ``require_all`` runs every round and requires every attempt to pass.
    """
    targets = tuple(targets)
    attempts = max(1, int(attempts))
    results = {target: ProbeResult(target=target) for target in targets}
    for round_idx in range(attempts):
        if require_all:
            pending = list(targets)
        else:
            pending = [t for t in targets if not results[t].ok]
            if not pending:
                break
        with ThreadPoolExecutor(max_workers=min(4, len(pending))) as ex:
            futs = {ex.submit(_single_attempt, proxy_url, target, timeout): target
                    for target in pending}
            for fut in as_completed(futs):
                target = futs[fut]
                try:
                    attempt = fut.result()
                except Exception as exc:
                    attempt = ProbeAttempt(False, 0, 0, 0, type(exc).__name__.lower())
                results[target].attempts.append(attempt)
        if not require_all:
            for target in pending:
                ok, ratio, latency, reason = summarize_attempts(results[target].attempts)
                results[target].ok = ok
                results[target].success_ratio = ratio
                results[target].latency_ms = latency
                results[target].reason = reason
            if any(results[t].ok for t in targets):
                break
        if round_idx < attempts - 1:
            time.sleep(random.uniform(*pause))
    if require_all:
        for target in targets:
            _strict_verdict(results[target])
    return [results[t] for t in targets]


def verdict_from_probes(results: list[ProbeResult]) -> tuple[bool, float, str]:
    """A tunnel is alive if at least one independent target passed."""
    passed = [r for r in results if r.ok]
    if passed:
        latencies = [r.latency_ms for r in passed if r.latency_ms > 0]
        return True, min(latencies) if latencies else 0.0, ""
    reasons = [r.reason for r in results if r.reason]
    reason = Counter(reasons).most_common(1)[0][0] if reasons else "probe_failed"
    return False, 0.0, reason



def summarize_rkn_results(results: list[dict], quorum: int = 1) -> tuple[bool, float, int, int]:
    """Apply a quorum to probe results.

    ``quorum=1`` keeps the historical "at least one site opened" behaviour; a
    higher quorum filters lucky single-domain false positives.
    """
    opened = [r for r in results if r.get("ok")]
    latencies = [r.get("latency", 0.0) for r in opened if r.get("latency", 0.0) > 0]
    best_lat = min(latencies) if latencies else 0.0
    need = max(1, int(quorum))
    return len(opened) >= need, best_lat, len(opened), len(results)


def _as_port(value) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def uri_query_param(uri: str, key: str, default: str = "") -> str:
    """Read one query parameter from a proxy URI (before #fragment)."""
    qm = uri.find('?')
    if qm == -1:
        return default
    qs = uri[qm + 1:]
    hash_pos = qs.find('#')
    if hash_pos != -1:
        qs = qs[:hash_pos]
    values = urllib.parse.parse_qs(qs).get(key)
    return values[0] if values else default


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
_ERROR_HINTS = ("failed", "error", "fatal", "unknown", "invalid", "reject", "panic")


def core_error_text(stdout, stderr, limit: int = 200) -> str:
    """Extract a meaningful error line from a core's output.

    Xray prints its banner first and the real failure later on stdout, while
    sing-box writes FATAL lines to stderr.  Taking the first 200 characters
    used to return the version banner instead of the error.
    """
    def _decode(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return _ANSI_RE.sub("", value)

    text = _decode(stderr).strip() or _decode(stdout).strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        low = line.lower()
        if any(hint in low for hint in _ERROR_HINTS):
            return line[:limit]
    return (lines[-1] if lines else "")[:limit]


def prefer_xray(uri: str) -> bool:
    """Whether Xray should be tried first for this URI.

    Xray 26 supports REALITY only over raw/xhttp/gRPC, while sing-box still
    accepts REALITY over WebSocket.  Trying Xray for ``ws`` reality configs
    guaranteed a core error before, so route those to sing-box instead.
    """
    if get_protocol(uri) != 'vless':
        return False
    if uri_query_param(uri, 'security', '').lower() != 'reality':
        return False
    transport = uri_query_param(uri, 'type', 'tcp').lower()
    return transport not in ('ws', 'websocket')


def xray_can_carry(uri: str) -> bool:
    """Whether our Xray config builder can carry this URI.

    The Xray tester implements only vless, http and socks; trojan, vmess and
    shadowsocks must go to sing-box.  REALITY over WebSocket is also routed to
    sing-box because our Xray config is rejected there.
    """
    proto = get_protocol(uri)
    if proto in ('http', 'https', 'socks', 'socks4', 'socks5'):
        return True
    if proto != 'vless':
        return False
    security = uri_query_param(uri, 'security', '').lower()
    transport = uri_query_param(uri, 'type', 'tcp').lower()
    return not (security == 'reality' and transport in ('ws', 'websocket'))


def singbox_supports_uri(uri: str) -> bool:
    """Whether sing-box can parse this URI's transport.

    sing-box 1.14 does not know ``xhttp``; falling back to it after a failed
    Xray attempt only hides the real reason behind a config error.
    """
    transport = uri_query_param(uri, 'type', 'tcp').lower()
    return transport not in ('xhttp',)


def apply_singbox_overrides(outbound: dict, overrides: dict | None) -> dict:
    """Apply strategy overrides (fragment/utls/sni/port/server) to sing-box."""
    if not overrides:
        return outbound
    needs_tls = any(k in overrides for k in ("sni", "utls", "fragment", "fragment_fallback_delay"))
    tls = None
    if needs_tls:
        tls = outbound.setdefault("tls", {})
        tls.setdefault("enabled", True)
        tls["enabled"] = True
    if tls is not None:
        if overrides.get("sni"):
            tls["server_name"] = str(overrides["sni"])
        if overrides.get("utls"):
            tls["utls"] = {"enabled": True, "fingerprint": str(overrides["utls"])}
        if overrides.get("fragment"):
            tls["fragment"] = True
            if overrides.get("fragment_fallback_delay"):
                tls["fragment_fallback_delay"] = str(overrides["fragment_fallback_delay"])
    port = _as_port(overrides.get("port"))
    if port:
        outbound["server_port"] = port
    if overrides.get("server"):
        outbound["server"] = str(overrides["server"])
    return outbound


def apply_xray_overrides(outbound: dict, overrides: dict | None) -> dict:
    """Apply strategy overrides to an Xray outbound."""
    if not overrides:
        return outbound
    stream = outbound.setdefault("streamSettings", {})
    security = str(stream.get("security", "")).lower()

    def tls_section():
        key = "realitySettings" if security == "reality" else "tlsSettings"
        return stream.setdefault(key, {})

    if overrides.get("sni"):
        tls_section()["serverName"] = str(overrides["sni"])
    if overrides.get("utls"):
        tls_section()["fingerprint"] = str(overrides["utls"])
    if overrides.get("fragment"):
        frag = overrides["fragment"]
        stream["fragment"] = dict(frag) if isinstance(frag, dict) else dict(XRAY_FRAGMENT_DEFAULT)
    port = _as_port(overrides.get("port"))
    if port:
        try:
            outbound["settings"]["vnext"][0]["port"] = port
        except (KeyError, IndexError, TypeError):
            pass
    if overrides.get("server"):
        try:
            outbound["settings"]["vnext"][0]["address"] = str(overrides["server"])
        except (KeyError, IndexError, TypeError):
            pass
    return outbound



_PROCS_LOCK = threading.Lock()
_PROCS: set = set()

_PORT_LOCK = threading.Lock()


class ProcGuard:
    """Worker-scoped core-process registry.

    ``TesterWorker`` and ``StrategyWorker`` each get their own guard so that
    ``stop()`` kills only the cores they started, not those of a sibling worker.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._procs: set = set()
        self._closed = False

    def add(self, proc):
        with self._lock:
            if self._closed:
                stale = proc
            else:
                self._procs.add(proc)
                stale = None
        if stale is not None:
            try:
                stale.kill()
            except Exception:
                pass

    def discard(self, proc):
        if proc is None:
            return
        with self._lock:
            self._procs.discard(proc)

    def kill_all(self):
        with self._lock:
            self._closed = True
            procs = list(self._procs)
            self._procs.clear()
        for proc in procs:
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass


def _spawn(cmd, guard=None, **kwargs):
    """Popen + global + per-guard registry."""
    proc = subprocess.Popen(cmd, **kwargs)
    with _PROCS_LOCK:
        _PROCS.add(proc)
    if guard is not None:
        guard.add(proc)
    return proc


def _reap(proc, guard=None):
    if proc is None:
        return
    with _PROCS_LOCK:
        _PROCS.discard(proc)
    if guard is not None:
        guard.discard(proc)


_PORTS_IN_USE: set[int] = set()
_PORTS_BURNED: set[int] = set()


def kill_all_procs():
    """Kill every core process started by the testers (app shutdown / stop)."""
    with _PROCS_LOCK:
        procs = list(_PROCS)
        _PROCS.clear()
    for proc in procs:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass


def allocate_port() -> int:
    """Reserve a free local port; serialised so two workers never share one."""
    with _PORT_LOCK:
        # Cap the burn list: over a long session thousands of tests would
        # otherwise exhaust the ephemeral port range.
        if len(_PORTS_BURNED) > 4000:
            _PORTS_BURNED.clear()
        for _ in range(50):
            port = find_free_port()
            if port not in _PORTS_IN_USE and port not in _PORTS_BURNED:
                _PORTS_IN_USE.add(port)
                _PORTS_BURNED.add(port)
                return port
        port = find_free_port()
        _PORTS_IN_USE.add(port)
        _PORTS_BURNED.add(port)
        return port


def release_port(port: int):
    with _PORT_LOCK:
        _PORTS_IN_USE.discard(port)


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


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> tuple[bool | None, float]:
    """Fast reachability check with RTT.

    Returns ``(True, rtt_ms)`` when connect succeeds, ``(False, 0)`` when the
    address resolved but the port is unreachable, and ``(None, 0)`` when DNS
    could not resolve at all (do not call that a dead proxy: DoH may still work).
    """
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return None, 0.0
    if not addrs:
        return None, 0.0
    for addr in addrs[:3]:
        try:
            s = socket.socket(addr[0], addr[1], addr[2])
            s.settimeout(timeout)
            try:
                start = time.time()
                s.connect(addr[4])
                return True, (time.time() - start) * 1000
            finally:
                s.close()
        except Exception:
            continue
    return False, 0.0


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


def test_http_proxy(proxy_url: str, url: str = TEST_URL, timeout: float = SB_TIMEOUT,
                    attempts: int = 1) -> tuple[bool, float]:
    """Backwards-compatible wrapper around :func:`probe_target`."""
    if url == TEST_URL:
        target = GENERATE_204_TARGET
    else:
        target = ProbeTarget(url, "status", min_bytes=1)
    result = probe_target(proxy_url, target, attempts=attempts, timeout=timeout)
    return result.ok, result.latency_ms


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
    def __init__(self, use_doh: bool = False, doh_list=None, guard=None):
        self.use_doh = use_doh
        self.doh_list = doh_list
        self._doh_cache = {}
        self._guard = guard

    def test(self, uri: str, port: int, overrides: dict | None = None,
             attempts: int = 1, targets=None, timeout: float | None = None,
             require_all: bool = False) -> tuple[bool, float, str]:
        config = self._make_config(uri, port, overrides)
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
                    proc = _spawn(
                        [SING_BOX, "run", "-c", config_path],
                        guard=self._guard,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.3)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            _, err_b = proc.communicate(timeout=0.5)
                            err = core_error_text(None, err_b)
                        except Exception:
                            pass
                        return False, 0, f"sb failed: {err}" if err else "sb failed to start"
                    probe_targets = tuple(targets) if targets else (GENERATE_204_TARGET,)
                    probe_results = probe_targets_rounds(
                        f"http://127.0.0.1:{port}", probe_targets,
                        attempts=attempts, timeout=timeout or SB_TIMEOUT,
                        require_all=require_all,
                    )
                    ok, lat, reason = verdict_from_probes(probe_results)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    _reap(proc, self._guard)
                    proc = None
                return ok, lat, reason
        except Exception as e:
            return False, 0, str(e)
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass
            _reap(proc, self._guard)

    def test_happ(self, uri: str, port: int, timeout: float = HAPP_TIMEOUT) -> tuple[bool, float, str]:
        """Happ-style single HEAD for protocols Xray does not carry (UDP)."""
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported_protocol"
        proc = None
        try:
            with tempfile.TemporaryDirectory(prefix="sb_happ_", dir=TMP_DIR) as tmp_dir:
                config_path = os.path.join(tmp_dir, "config.json")
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                with SB_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = _spawn(
                        [SING_BOX, "run", "-c", config_path],
                        guard=self._guard,
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        err_b = b""
                        try:
                            _, err_b = proc.communicate(timeout=0.5)
                        except Exception:
                            pass
                        return False, 0, f"sb_start_fail: {core_error_text(None, err_b)}"
                    ok, latency, reason = happ_head(
                        f"http://127.0.0.1:{port}", timeout=timeout)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    _reap(proc, self._guard)
                    proc = None
                return ok, latency, reason
        except Exception as exc:
            return False, 0, _probe_error_reason(exc)
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass
            _reap(proc, self._guard)

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

    def test_rkn_bypass(self, uri: str, port: int, overrides: dict | None = None,
                        targets=None, quorum: int = 1) -> tuple[bool, float, str, list[dict]]:
        config = self._make_config(uri, port, overrides)
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
                    proc = _spawn(
                        [SING_BOX, "run", "-c", config_path],
                        guard=self._guard,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        # Core rejected the config: report it instead of calling
                        # every blocked site "closed".
                        return False, 0, f"sb failed to start (rc={proc.returncode})", []
                    proxy_url = f"http://127.0.0.1:{port}"
                    # RKN bypass: blocked-in-RU sites must really open.
                    use_targets = list(targets) if targets else list(RKN_TARGETS)
                    with ThreadPoolExecutor(max_workers=min(8, len(use_targets))) as ex:
                        futs = {ex.submit(self._probe, proxy_url, d, mk): (d, n, cat)
                                for d, n, mk, cat in use_targets}
                        for fut in as_completed(futs):
                            d, n, cat = futs[fut]
                            try:
                                ok, code, lat = fut.result()
                            except Exception:
                                ok, code, lat = False, 0, 0.0
                            results.append({"domain": d, "name": n, "ok": ok,
                                            "latency": lat, "status": code, "category": cat})
                            _debug(f"rkn_bypass: {uri[:60]} {d} ok={ok} code={code}")
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    _reap(proc, self._guard)
                    proc = None
                ok, best_lat, opened, total = summarize_rkn_results(results, quorum)
                _debug(f"rkn_bypass: {uri[:60]} opened={opened}/{total} quorum={quorum} ok={ok}")
                return ok, best_lat, "" if ok else "проверочные сайты не открываются", results
        except Exception as e:
            return False, 0, str(e), results
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass
            _reap(proc, self._guard)

    def _make_config(self, uri: str, local_port: int, overrides: dict | None = None) -> Optional[dict]:
        proto = get_protocol(uri)
        outbound = self._parse(uri)
        if outbound is None:
            return None
        if self.use_doh:
            _harden_dns(outbound, self.doh_list, self._doh_cache, 'sb')
        apply_singbox_overrides(outbound, overrides)
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
            raw = clean[:at]
            if ':' in raw:
                # SIP002 plaintext userinfo: method:password
                from urllib.parse import unquote
                mp = unquote(raw)
            else:
                try:
                    pad = 4 - len(raw) % 4
                    if pad != 4:
                        raw += '=' * pad
                    raw = raw.replace('-', '+').replace('_', '/')
                    mp = base64.b64decode(raw).decode('utf-8', errors='ignore')
                except Exception:
                    mp = clean[:at]
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
        if colon2 == -1:
            method, password = mp, ""
        else:
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

    def __init__(self, use_doh: bool = False, doh_list=None, guard=None):
        self.use_doh = use_doh
        self.doh_list = doh_list
        self._doh_cache = {}
        self._guard = guard

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

    def test_rkn(self, uri: str, port: int, overrides: dict | None = None,
                 targets=None, quorum: int = 1) -> tuple[bool, float, str, list]:
        if not os.path.isfile(XRAY):
            return False, 0, f"xray не найден: {XRAY}", []
        config = self._make_config(uri, port, overrides)
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
                    proc = _spawn(
                        [XRAY, "run", "-c", config_path],
                        guard=self._guard,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            out_b, err_b = proc.communicate(timeout=0.5)
                            err = core_error_text(out_b, err_b)
                        except Exception:
                            pass
                        return False, 0, f"xray err: {err}" if err else "xray failed to start", []
                    proxy_url = f"http://127.0.0.1:{port}"
                    # RKN bypass: blocked-in-RU sites must really open.
                    use_targets = list(targets) if targets else list(RKN_TARGETS)
                    with ThreadPoolExecutor(max_workers=min(8, len(use_targets))) as ex:
                        futs = {ex.submit(self._probe, proxy_url, d, mk): (d, n, cat)
                                for d, n, mk, cat in use_targets}
                        for fut in as_completed(futs):
                            d, n, cat = futs[fut]
                            try:
                                ok, code, lat = fut.result()
                            except Exception:
                                ok, code, lat = False, 0, 0.0
                            results.append({"domain": d, "name": n, "ok": ok,
                                            "latency": lat, "status": code, "category": cat})
                            _debug(f"xr_rkn: {uri[:60]} {d} ok={ok} code={code}")
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    _reap(proc, self._guard)
                    proc = None
                ok, best_lat, opened, total = summarize_rkn_results(results, quorum)
                _debug(f"xr_rkn: {uri[:60]} opened={opened}/{total} quorum={quorum} ok={ok}")
                return ok, best_lat, "" if ok else "проверочные сайты не открываются", results
        except Exception as e:
            return False, 0, str(e), results
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass
            _reap(proc, self._guard)

    def test(self, uri: str, port: int, overrides: dict | None = None,
             attempts: int = 1, targets=None, timeout: float | None = None,
             require_all: bool = False) -> tuple[bool, float, str]:
        if not os.path.isfile(XRAY):
            return False, 0, f"xray не найден: {XRAY}"
        config = self._make_config(uri, port, overrides)
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
                    proc = _spawn(
                        [XRAY, "run", "-c", config_path],
                        guard=self._guard,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            out_b, err_b = proc.communicate(timeout=0.5)
                            err = core_error_text(out_b, err_b)
                        except Exception:
                            pass
                        return False, 0, f"xray err: {err}" if err else "xray failed to start"
                    probe_targets = tuple(targets) if targets else (GENERATE_204_TARGET,)
                    probe_results = probe_targets_rounds(
                        f"http://127.0.0.1:{port}", probe_targets,
                        attempts=attempts, timeout=timeout or SB_TIMEOUT,
                        require_all=require_all,
                    )
                    ok, lat, reason = verdict_from_probes(probe_results)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    _reap(proc, self._guard)
                    proc = None
                return ok, lat, reason
        except Exception as e:
            return False, 0, str(e)
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass
            _reap(proc, self._guard)

    def _make_config(self, uri: str, local_port: int, overrides: dict | None = None) -> Optional[dict]:
        proto = get_protocol(uri)
        if proto == 'vless':
            outbound = self._parse_vless(uri)
        elif proto == 'http':
            outbound = self._parse_http_outbound(uri)
        elif proto == 'socks':
            outbound = self._parse_socks_outbound(uri)
        else:
            return None
        if outbound is None:
            return None
        if self.use_doh:
            _harden_dns(outbound, self.doh_list, self._doh_cache, 'xray')
        apply_xray_overrides(outbound, overrides)
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "http", "settings": {}}],
            "outbounds": [outbound],
        }

    def _http_server(self, uri: str) -> Optional[dict]:
        """Split ``scheme://[user:pass@]host:port`` into an Xray server entry."""
        clean = uri.strip()
        for pfx in ('http://', 'https://', 'socks5://', 'socks4://'):
            if clean.lower().startswith(pfx):
                clean = clean[len(pfx):]
                break
        for sep in ('?', '#'):
            pos = clean.find(sep)
            if pos != -1:
                clean = clean[:pos]
        server, _, port_text = clean.rpartition(':')
        if not server or not port_text.isdigit():
            return None
        server = server.rpartition('@')[2]
        if not server:
            return None
        entry = {"address": server, "port": int(port_text)}
        userinfo = clean.rpartition('@')[0]
        if userinfo and '@' in clean:
            user, _, password = userinfo.partition(':')
            if user:
                entry["users"] = [{"user": urllib.parse.unquote(user),
                                   "pass": urllib.parse.unquote(password)}]
        return entry

    def _parse_http_outbound(self, uri: str) -> Optional[dict]:
        server = self._http_server(uri)
        if server is None:
            return None
        return {"protocol": "http", "settings": {"servers": [server]}}

    def _parse_socks_outbound(self, uri: str) -> Optional[dict]:
        server = self._http_server(uri)
        if server is None:
            return None
        return {"protocol": "socks", "settings": {"servers": [server]}}

    def test_happ(self, uri: str, port: int, timeout: float = HAPP_TIMEOUT) -> tuple[bool, float, str]:
        """Happ-compatible check: Xray only, one HEAD, no retries, no DoH."""
        if not os.path.isfile(XRAY):
            return False, 0, f"xray не найден: {XRAY}"
        config = self._make_config(uri, port)
        if config is None:
            return False, 0, "unsupported_protocol"
        proc = None
        try:
            with tempfile.TemporaryDirectory(prefix="xr_happ_", dir=TMP_DIR) as tmp_dir:
                config_path = os.path.join(tmp_dir, "config.json")
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                with self.XRAY_SEMAPHORE:
                    time.sleep(random.uniform(0.1, 0.3))
                    proc = _spawn(
                        [XRAY, "run", "-c", config_path],
                        guard=self._guard,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        cwd=tmp_dir, creationflags=CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        err = ""
                        try:
                            out_b, err_b = proc.communicate(timeout=0.5)
                            err = core_error_text(out_b, err_b)
                        except Exception:
                            pass
                        return False, 0, "xray_start_fail" if not err else f"xray_start_fail: {err}"
                    ok, latency, reason = happ_head(
                        f"http://127.0.0.1:{port}", timeout=timeout)
                    proc.kill()
                    try:
                        proc.wait(1)
                    except Exception:
                        pass
                    _reap(proc, self._guard)
                    proc = None
                return ok, latency, reason
        except Exception as exc:
            return False, 0, _probe_error_reason(exc)
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(1)
                except Exception:
                    pass
            _reap(proc, self._guard)

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

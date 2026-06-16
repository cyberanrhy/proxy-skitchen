import os, sys, json, re, base64, time, socket, urllib.request, urllib.error, concurrent.futures, html, subprocess, threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, TimeoutError as FUTURE_TIMEOUT
from typing import Optional
from datetime import datetime

from PySide6.QtCore import QObject, Signal, Slot

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from .compat import *
from .models import ProxyEntry, _auth_data, _settings_data
from .parsers import is_proxy_uri, extract_uris, parse_json_proxies, wrap_raw_host, geo_lookup, guess_country, get_server_port, is_ip as _is_ip, geo_lookup as _geo_lookup
from .tester import test_tcp, test_tls, resolve_host

_WORKERS_LOG = os.path.join(TMP_DIR, "workers.log")

def _debug(msg: str):
    try:
        with open(_WORKERS_LOG, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass

class NetworkWorker(QObject):
    progress_signal = Signal(int, int, str)
    source_started = Signal(str, int)
    proxy_parsed = Signal(list)
    log_signal = Signal(str)
    source_status = Signal(str, bool, int)
    finished = Signal()

    def __init__(self):
        super().__init__()
        self._stop = False
        self._resolved = {}
        self._procs: list[subprocess.Popen] = []
        self._procs_lock = threading.Lock()
        self._pool = None

    def stop(self):
        self._stop = True
        with self._procs_lock:
            for p in self._procs[:]:
                try:
                    p.kill()
                except Exception:
                    pass
            self._procs.clear()
        try:
            if self._pool:
                self._pool.shutdown(wait=False)
        except Exception:
            pass

    @Slot()
    def fetch_all(self, sources: list[tuple[str, str]]):
        self._stop = False
        total = len(sources)
        if not total:
            self.finished.emit()
            return
        self._pool = ThreadPoolExecutor(max_workers=4)
        pool = self._pool
        futs = {}
        names = {}
        start_time = time.time()
        MAX_WAIT = max(30, total * 20)
        try:
            for name, url in sources:
                if self._stop:
                    break
                fut = pool.submit(self._fetch_one, name, url)
                idx = len(futs)
                futs[fut] = idx
                names[fut] = name
                self.source_started.emit(name, idx)
            pending = set(futs)
            done_count = 0
            while pending and not self._stop:
                done, pending = wait(pending, timeout=1.0)
                for fut in done:
                    idx = futs[fut]
                    name = names[fut]
                    self.progress_signal.emit(idx + 1, total, name)
                    try:
                        proxies = fut.result(timeout=5)
                    except Exception:
                        proxies = None
                    if proxies is None:
                        self.log_signal.emit(f"  ✗ {name}: fetch failed")
                        self.source_status.emit(name, False, 0)
                    else:
                        count = 0
                        batch = []
                        geo_ips = {}
                        for uri in proxies:
                            if self._stop:
                                break
                            entry = ProxyEntry(uri)
                            if _is_ip(entry.host) and not entry.country:
                                geo_ips[entry.host] = entry
                            if not entry.country:
                                c = guess_country(uri)
                                if c:
                                    entry.country = c
                            batch.append(entry)
                            count += 1
                            if len(batch) >= 50:
                                self.proxy_parsed.emit(batch)
                                batch = []
                        if geo_ips:
                            with ThreadPoolExecutor(max_workers=8) as geo_pool:
                                geo_futs = {geo_pool.submit(geo_lookup, ip): ip for ip in geo_ips}
                                for gf in as_completed(geo_futs):
                                    ip = geo_futs[gf]
                                    try:
                                        c = gf.result()
                                        if c:
                                            geo_ips[ip].country = c
                                    except Exception:
                                        pass
                        if batch:
                            self.proxy_parsed.emit(batch)
                        self.source_status.emit(name, True, count)
                        self.log_signal.emit(f"  ✓ {name}: {count} proxies")
                    done_count += 1
                if time.time() - start_time > MAX_WAIT:
                    self.log_signal.emit(f"  ⚠ Timeout {MAX_WAIT}s, aborting")
                    break
        finally:
            for fut in futs:
                fut.cancel()
            pool.shutdown(wait=False)
            self.finished.emit()

    def _fetch_one(self, name: str, url: str) -> Optional[list[str]]:
        proxy_enabled = _settings_data.get("proxy_enabled", True)
        data = self._http_get(url, use_proxy=False)
        if data is None and proxy_enabled:
            data = self._http_get(url, use_proxy=True)
        if data is None:
            return None
        proxies = []
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue
            if re.match(r'^[A-Za-z0-9+/=]{50,}$', line):
                try:
                    decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
                    for sl in decoded.splitlines():
                        sl = sl.strip()
                        if sl and is_proxy_uri(sl):
                            proxies.append(sl)
                except Exception:
                    if is_proxy_uri(line):
                        proxies.append(line)
            else:
                if is_proxy_uri(line):
                    proxies.append(line)
        json_proxies = parse_json_proxies(data)
        for p in json_proxies:
            if p and p not in proxies:
                proxies.append(p)
        wrapped = [wrap_raw_host(p) for p in proxies]
        return wrapped

    def _http_get(self, url: str, use_proxy: bool = False) -> Optional[str]:
        proxy_enabled = _settings_data.get("proxy_enabled", True)
        if use_proxy and not proxy_enabled:
            return None
        for attempt in range(2):
            if self._stop:
                return None
            try:
                try:
                    import shutil
                    if shutil.which("curl"):
                        cmd = ["curl", "-sL", "--connect-timeout", "8", "--max-time", "20"]
                        if use_proxy and proxy_enabled:
                            cmd.extend(["--proxy", "socks5://127.0.0.1:12334"])
                        cmd.extend(["-H", "User-Agent: Mozilla/5.0", url])
                        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=creationflags)
                        with self._procs_lock:
                            self._procs.append(proc)
                        try:
                            out, _ = proc.communicate(timeout=25)
                            if proc.returncode == 0:
                                return out.decode("utf-8", errors="ignore")
                        finally:
                            with self._procs_lock:
                                if proc in self._procs:
                                    self._procs.remove(proc)
                            if proc.poll() is None:
                                proc.kill()
                    else:
                        raise FileNotFoundError("curl not found")
                except Exception:
                    if self._stop:
                        return None
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    if use_proxy and proxy_enabled:
                        handler = urllib.request.ProxyHandler({"http": HIDDIFY_PROXY, "https": HIDDIFY_PROXY})
                        opener = urllib.request.build_opener(handler)
                        resp = opener.open(req, timeout=20)
                    else:
                        resp = urllib.request.urlopen(req, timeout=20)
                    data = resp.read().decode("utf-8", errors="ignore")
                    return data
            except Exception:
                pass
            if proxy_enabled:
                use_proxy = True
        return None

class TesterWorker(QObject):
    progress_signal = Signal(int, int, int, str)
    testing_signal = Signal(int, str)
    result_signal = Signal(int, bool, float, str, int)
    log_signal = Signal(str)
    finished = Signal()
    count_signal = Signal(int)

    def __init__(self, deep: bool = False, test_threads: int = 4, deep_threads: int = 2):
        super().__init__()
        self._deep = deep
        self._test_threads = test_threads
        self._deep_threads = deep_threads
        self._stop = False
        self._sb_tester = None

    def stop(self):
        self._stop = True

    @Slot()
    def test_batch(self, entries: list[ProxyEntry]):
        self._stop = False
        total = len(entries)
        if not total:
            self.finished.emit()
            return
        threads = self._deep_threads if self._deep else self._test_threads
        pool = ThreadPoolExecutor(max_workers=threads)
        futs = {}
        resolved = {}
        try:
            for i, entry in enumerate(entries):
                if self._stop:
                    break
                self.testing_signal.emit(i, f"{entry.protocol} {entry.host}:{entry.port}")
                futs[pool.submit(self._test_one, entry, resolved)] = i
            pending = set(futs)
            done_count = 0
            while pending and not self._stop:
                done, pending = wait(pending, timeout=0.5)
                for fut in done:
                    row = futs[fut]
                    try:
                        ok, latency, error, ttype = fut.result()
                        self.result_signal.emit(row, ok, latency, error, ttype)
                    except Exception:
                        self.result_signal.emit(row, False, 0.0, "fail", 0)
                    done_count += 1
                    self.count_signal.emit(done_count)
                if done:
                    self.progress_signal.emit(done_count, total, threads, "deep" if self._deep else "tcp")
        finally:
            for fut in futs:
                fut.cancel()
            pool.shutdown(wait=False)
            self.finished.emit()

    def _test_one(self, entry: ProxyEntry, resolved: dict) -> tuple[bool, float, str, int]:
        host = entry.host
        port = entry.port
        if not host or not port:
            return False, 0, "no host/port", 0
        ok = test_tcp(host, port)
        latency = 0.0
        if ok:
            start = time.time()
            test_tcp(host, port)
            latency = (time.time() - start) * 1000
        if not ok:
            return False, 0, "tcp fail", 0
        if self._deep:
            deep_ok, deep_lat, deep_err = self._deep_test(entry)
            return deep_ok, deep_lat or latency, deep_err, 1
        return ok, latency, "", 0

    def _deep_test(self, entry: ProxyEntry) -> tuple[bool, float, str]:
        if not self._sb_tester:
            from .tester import SingBoxTester
            self._sb_tester = SingBoxTester()
        port = 19999 + (hash(entry.uri) % 10000)
        return self._sb_tester.test(entry.uri, port)

class GitHubSearchWorker(QObject):
    result_signal = Signal(list)
    partial_result_signal = Signal(list)
    error_signal = Signal(str)
    progress_signal = Signal(str)
    count_signal = Signal(int)

    def __init__(self, keywords: list[str], known_sources: set,
                 explicit_repos: Optional[list[str]] = None,
                 time_filter_days: int = 7, github_tokens: Optional[list[str]] = None,
                 max_repos: int = 12, max_files: int = 50,
                 owner: Optional[str] = None, weak_hw: bool = False, deep_search: bool = False):
        super().__init__()
        self.keywords = keywords
        self.known_sources = known_sources
        self.explicit_repos = explicit_repos or []
        self.time_filter_days = time_filter_days
        self.github_tokens = github_tokens or []
        self.max_repos = max_repos
        self.max_files = max_files
        self.owner = owner
        self.weak_hw = weak_hw
        self.deep_search = deep_search
        self._stop = False
        self._token_idx = 0
        self._procs: list[subprocess.Popen] = []
        self._procs_lock = threading.Lock()

    def stop(self):
        self._stop = True
        with self._procs_lock:
            for p in self._procs[:]:
                try:
                    p.kill()
                except Exception:
                    pass
            self._procs.clear()

    def _api(self, url: str, timeout: int = 10) -> Optional[dict]:
        tokens = list(self.github_tokens)
        for attempt in range(max(1, len(tokens) + 1)):
            if self._stop:
                return None
            time.sleep(0.5)
            if tokens:
                token = tokens[self._token_idx % len(tokens)]
                self._token_idx += 1
            else:
                token = None
            for use_proxy in [False, True] if _settings_data.get("proxy_enabled", True) else [False]:
                if self._stop:
                    return None
                try:
                    try:
                        import shutil
                        if shutil.which("curl"):
                            cmd = ["curl", "-s", "--connect-timeout", "8", "--max-time", str(timeout)]
                            if use_proxy:
                                cmd.extend(["--proxy", "socks5://127.0.0.1:12334"])
                            cmd.extend(["-H", "Accept: application/vnd.github.v3+json",
                                        "-H", "User-Agent: proxy-skitchen/2.0"])
                            if token:
                                cmd.extend(["-H", f"Authorization: token {token}"])
                            cmd.append(url)
                            creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=creationflags)
                            with self._procs_lock:
                                self._procs.append(proc)
                            try:
                                out, err = proc.communicate(timeout=timeout + 5)
                                if self._stop:
                                    return None
                                if proc.returncode != 0:
                                    continue
                                data = json.loads(out)
                                if isinstance(data, dict) and data.get("message"):
                                    if "rate" in data["message"].lower():
                                        time.sleep(2)
                                    continue
                                return data
                            finally:
                                with self._procs_lock:
                                    if proc in self._procs:
                                        self._procs.remove(proc)
                        else:
                            raise FileNotFoundError("curl not found")
                    except Exception:
                        continue
                except Exception:
                    continue
        return None

    @Slot()
    def run(self):
        _debug("GitHubSearchWorker.run() started")
        self._stop = False
        results = []
        try:
            seen_repos = set()
            for repo_url in self.explicit_repos:
                if self._stop:
                    break
                found = self._walk_explicit(repo_url)
                results.extend(found)
                self.count_signal.emit(len(results))
            for kw in self.keywords:
                if self._stop:
                    break
                found = self._search_and_walk(kw, seen_repos)
                if found is None:
                    continue
                results.extend(found)
                self.count_signal.emit(len(results))
            results.sort(key=lambda r: r.get("embedded", False))
            self.result_signal.emit(results)
        except Exception as e:
            self.error_signal.emit(f"Search critical error: {e}")
        _debug("GitHubSearchWorker.run() finished")

    def _search_and_walk(self, keyword: str, seen_repos: set) -> list[dict]:
        query = urllib.parse.quote(keyword)
        if self.owner:
            query += f"+user:{self.owner}"
        results = []
        date_filter = ""
        if self.time_filter_days > 0:
            from datetime import datetime, timedelta, timezone
            since = (datetime.now(timezone.utc) - timedelta(days=self.time_filter_days)).strftime("%Y-%m-%d")
            date_filter = f"+pushed:>={since}"
        per_page = 100 if self.deep_search else 30
        limit = self.max_repos * 3 if self.deep_search else self.max_repos
        url = f"https://api.github.com/search/repositories?q={query}{date_filter}&sort=updated&per_page={per_page}"
        data = self._api(url)
        if data is None:
            return results
        for repo in data.get("items", [])[:limit]:
            if self._stop:
                break
            repo_url = repo.get("html_url", "")
            if repo_url in seen_repos:
                continue
            seen_repos.add(repo_url)
            found = self._walk(repo)
            results.extend(found)
            self.partial_result_signal.emit(list(results))
            self.count_signal.emit(len(results))
        return results

    def _walk(self, repo: dict) -> list[dict]:
        full_name = repo.get("full_name", "")
        default_branch = repo.get("default_branch", "main")
        results = []
        stack = [""]
        visited = set()
        while stack and not self._stop:
            path = stack.pop()
            if path in visited:
                continue
            visited.add(path)
            api_url = f"https://api.github.com/repos/{full_name}/contents/{path}"
            data = self._api(api_url)
            if data is None:
                continue
            items = data if isinstance(data, list) else [data]
            if not items:
                continue
            for item in items:
                if self._stop:
                    break
                if not isinstance(item, dict):
                    continue
                name = item.get("name", "")
                item_path = item.get("path", "")
                item_type = item.get("type", "")
                skip_patterns = ()
                if not self.deep_search:
                    skip_patterns = ('.git', '.github', 'node_modules', '__pycache__',
                                     '.vscode', '.idea', 'venv', '.env', 'dist', 'build',
                                     '.img', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                                     '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp3',
                                     '.mp4', '.avi', '.mkv', '.zip', '.rar', '.tar', '.gz',
                                     '.exe', '.dll', '.so', '.dmg', '.iso')
                if any(name.lower().endswith(s) for s in skip_patterns):
                    continue
                skip_dirs = () if self.deep_search else ('.git', '.github', 'node_modules', '__pycache__',
                                                          '.vscode', '.idea', 'venv', '.env', 'dist', 'build', 'assets', 'images')
                if item_type == 'dir':
                    if name not in skip_dirs and (self.deep_search or not name.startswith('.')):
                        stack.append(item_path)
                elif item_type == 'file':
                    ext = os.path.splitext(name)[1].lower()
                    allowed_exts = ('.md', '.rst', '.txt', '.yaml', '.yml', '.json', '.conf', '.cfg', '') if not self.deep_search else ('.md', '.rst', '.txt', '.yaml', '.yml', '.json', '.conf', '.cfg', '', '.py', '.js', '.toml', '.ini', '.xml')
                    if ext in allowed_exts:
                        found = self._check_file(item, full_name, default_branch)
                        results.extend(found)
                        self.count_signal.emit(len(results))
                        maxf = self.max_files * 3 if self.deep_search else self.max_files
                        if len(results) >= maxf:
                            return results
        return results

    def _check_file(self, item: dict, full_name: str, branch: str) -> list[dict]:
        results = []
        download_url = item.get("download_url", "")
        if not download_url:
            return results
        name = item.get("name", "")
        path = item.get("path", "")
        size = item.get("size", 0) or 0
        if size > 5 * 1024 * 1024:
            return results
        url = f"https://raw.githubusercontent.com/{full_name}/{branch}/{path}"
        file_url = item.get("download_url", url)
        try:
            body = None
            try:
                import shutil
                if shutil.which("curl"):
                    cmd = ["curl", "-sL", "--connect-timeout", "5", "--max-time", "10"]
                    if _settings_data.get("proxy_enabled", True):
                        cmd.extend(["--proxy", "socks5://127.0.0.1:12334"])
                    cmd.extend(["-H", "User-Agent: Mozilla/5.0", file_url])
                    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                    result = subprocess.run(cmd, capture_output=True, timeout=15, creationflags=creationflags)
                    if result.returncode == 0:
                        body = result.stdout.decode("utf-8", errors="ignore")
                else:
                    raise FileNotFoundError("curl not found")
            except Exception:
                req = urllib.request.Request(file_url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read().decode("utf-8", errors="ignore")
            if body is None:
                return results
            embedded_links = []
            for line in body.splitlines():
                line = line.strip()
                if is_proxy_uri(line):
                    if line not in self.known_sources:
                        self.known_sources.add(line)
                        embedded_links.append(line)
            entry = {
                "file_url": file_url,
                "name": f"{full_name}/{path}",
                "repo_url": f"https://github.com/{full_name}",
                "size": size,
                "stars": 0,
                "updated": "",
                "embedded": False,
            }
            if embedded_links:
                entry["count"] = len(embedded_links)
            results.append(entry)
        except Exception:
            pass
        return results

    def _walk_explicit(self, repo_url: str) -> list[dict]:
        m = re.match(r'(?:https?://github\.com/)?([^/]+/[^/]+?)(?:\.git)?$', repo_url)
        if not m:
            return []
        full_name = m.group(1).rstrip('/')
        results = []
        stack = [""]
        visited = set()
        while stack and not self._stop:
            path = stack.pop()
            if path in visited:
                continue
            visited.add(path)
            api_url = f"https://api.github.com/repos/{full_name}/contents/{path}"
            data = self._api(api_url)
            if data is None:
                continue
            items = data if isinstance(data, list) else [data]
            if not items:
                continue
            for item in items:
                if self._stop or not isinstance(item, dict):
                    break
                name = item.get("name", "")
                item_path = item.get("path", "")
                item_type = item.get("type", "")
                skip_suffix = ('.git', '.github', 'node_modules', '__pycache__',
                               '.vscode', '.idea', 'venv', '.env', 'dist', 'build',
                               '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                               '.zip', '.rar', '.tar', '.gz', '.exe', '.dll', '.so')
                if any(name.lower().endswith(s) for s in skip_suffix):
                    continue
                if item_type == 'dir':
                    if name not in ('.git', '.github', 'node_modules', '__pycache__',
                                    '.vscode', '.idea', 'venv', '.env', 'dist', 'build'):
                        stack.append(item_path)
                elif item_type == 'file':
                    ext = os.path.splitext(name)[1].lower()
                    if ext in ('.md', '.rst', '.txt', '.yaml', '.yml', '.json', '.conf', '.cfg', ''):
                        found = self._check_file(item, full_name, "main")
                        results.extend(found)
                        self.count_signal.emit(len(results))
                        if len(results) >= self.max_files:
                            return results
        return results

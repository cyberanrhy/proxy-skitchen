import os, sys, json, re, base64, time, socket, urllib.request, urllib.error, concurrent.futures, html, subprocess, threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, TimeoutError as FUTURE_TIMEOUT
from typing import Optional
from datetime import datetime, timedelta, timezone

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from .compat import *
from .compat import _write_log, DEBUG_LOG_PATHS, CREATE_NO_WINDOW
from .models import ProxyEntry, _auth_data, _settings_data, PROTOCOL_PREFIXES
from .parsers import is_proxy_uri, extract_uris, extract_inline_uris, parse_json_proxies, geo_lookup, guess_country, get_server_port, is_ip as _is_ip
from .tester import test_tcp, test_tls, resolve_host

def _debug(msg: str):
    from .compat import TMP_DIR
    _WRK_LOG = os.path.join(TMP_DIR, "workers.log")
    if _WRK_LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(_WRK_LOG)
    _write_log(_WRK_LOG, msg)


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
        self._inner_pool = ThreadPoolExecutor(max_workers=8)
        self._ip_entries: list[ProxyEntry] = []

    def stop(self):
        self._stop = True
        with self._procs_lock:
            for p in self._procs[:]:
                try:
                    p.kill()
                except Exception:
                    pass
            self._procs.clear()
        self._inner_pool.shutdown(wait=False)

    @Slot()
    def fetch_all(self, sources: list[tuple[str, str]]):
        _debug(f"fetch_all: start total={len(sources)}")
        self._stop = False
        total = len(sources)
        if not total:
            _debug("fetch_all: no sources, emitting finished")
            self.finished.emit()
            return
        pool = ThreadPoolExecutor(max_workers=4)
        futs = {}
        names = {}
        start_time = time.time()
        MAX_WAIT = max(30, total * 20)
        try:
            for name, url in sources:
                if self._stop:
                    _debug("fetch_all: stopped before submit")
                    break
                fut = pool.submit(self._fetch_one, name, url)
                idx = len(futs)
                futs[fut] = idx
                names[fut] = name
                self.source_started.emit(name, idx)
            _debug(f"fetch_all: submitted {len(futs)} tasks")
            pending = set(futs)
            done_count = 0
            t_last_debug = time.time()
            while pending and not self._stop:
                done, pending = wait(pending, timeout=1.0)
                for fut in done:
                    idx = futs[fut]
                    name = names[fut]
                    self.progress_signal.emit(idx + 1, total, name)
                    t0_proc = time.time()
                    try:
                        proxies = fut.result(timeout=5)
                    except Exception:
                        proxies = None
                    if proxies is None:
                        self.log_signal.emit(f"  ✗ {name}: fetch failed")
                        self.source_status.emit(name, False, 0)
                    else:
                        t0_parse = time.time()
                        count = 0
                        batch = []
                        for uri in proxies:
                            if self._stop:
                                break
                            entry = ProxyEntry(uri)
                            if _is_ip(entry.host) and not entry.country:
                                self._ip_entries.append(entry)
                            if not entry.country:
                                c = guess_country(uri)
                                if c:
                                    entry.country = c
                            batch.append(entry)
                            count += 1
                            if len(batch) >= 50:
                                self.proxy_parsed.emit(batch)
                                batch = []
                        t1_parse = time.time()
                        if batch:
                            self.proxy_parsed.emit(batch)
                        self.source_status.emit(name, True, count)
                        self.log_signal.emit(f"  ✓ {name}: {count} proxies")
                        # Periodic timing debug
                        if time.time() - t_last_debug > 5.0:
                            elapsed = time.time() - start_time
                            _debug(f"fetch_all: progress {done_count}/{total} elapsed={elapsed:.1f}s parse={t1_parse-t0_parse:.3f}s")
                            t_last_debug = time.time()
                    done_count += 1
                if time.time() - start_time > MAX_WAIT:
                    self.log_signal.emit(f"  ⚠ Timeout {MAX_WAIT}s, aborting")
                    break
            # Batch geo_lookup for all IP hosts after all curls complete
            if not self._stop and self._ip_entries:
                unique_ips = set(e.host for e in self._ip_entries)
                ip_to_country: dict[str, str] = {}
                if unique_ips:
                    geo_futs = {self._inner_pool.submit(geo_lookup, ip): ip for ip in unique_ips}
                    for gf in as_completed(geo_futs):
                        ip = geo_futs[gf]
                        try:
                            c = gf.result()
                            if c:
                                ip_to_country[ip] = c
                        except Exception:
                            pass
                for entry in self._ip_entries:
                    if entry.host in ip_to_country:
                        entry.country = ip_to_country[entry.host]
                self._ip_entries.clear()
        finally:
            elapsed = time.time() - start_time
            _debug(f"fetch_all: done {done_count}/{total} elapsed={elapsed:.1f}s stop={self._stop}")
            for fut in futs:
                fut.cancel()
            pool.shutdown(wait=False)
            _debug("fetch_all: emitting finished")
            try:
                self.finished.emit()
            except RuntimeError:
                pass

    def _fetch_one(self, name: str, url: str) -> Optional[list[str]]:
        _debug(f"_fetch_one: start {name[:60]}")
        proxy_enabled = _settings_data.get("proxy_enabled", True)
        from concurrent.futures import Future
        dir_fut: Optional[Future] = None
        prx_fut: Optional[Future] = None
        dir_fut = self._inner_pool.submit(self._http_get, url, False, 10)
        if proxy_enabled:
            prx_fut = self._inner_pool.submit(self._http_get, url, True, 20)
        for f in as_completed([dir_fut] + ([prx_fut] if prx_fut else [])):
            try:
                data = f.result()
                if data is not None:
                    dir_fut.cancel()
                    if prx_fut:
                        prx_fut.cancel()
                    break
            except Exception:
                data = None
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
                else:
                    inlines = extract_inline_uris(line)
                    for u in inlines:
                        if u not in proxies:
                            proxies.append(u)
        json_proxies = parse_json_proxies(data)
        for p in json_proxies:
            if p and p not in proxies:
                proxies.append(p)
        # Keep only protocol-prefixed URIs, skip bare IP:port/host:port
        proxies = [p for p in proxies if p.lower().startswith(PROTOCOL_PREFIXES)]
        return proxies

    def _http_get(self, url: str, use_proxy: bool = False, timeout: int = 20) -> Optional[str]:
        proxy_enabled = _settings_data.get("proxy_enabled", True)
        if use_proxy and not proxy_enabled:
            return None
        for attempt in range(2):
            if self._stop:
                return None
            try:
                cmd = ["curl", "-sL", "--connect-timeout", "5", "--max-time", str(timeout)]
                if use_proxy and proxy_enabled:
                    cmd.extend(["--proxy", "socks5://127.0.0.1:12334"])
                cmd.extend(["-H", "User-Agent: Mozilla/5.0", url])
                _debug(f"_http_get: curl attempt={attempt} proxy={use_proxy} url={url[:80]}")
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
                with self._procs_lock:
                    self._procs.append(proc)
                try:
                    out, _ = proc.communicate(timeout=25)
                    if self._stop:
                        return None
                    _debug(f"_http_get: curl done rc={proc.returncode} len={len(out)}")
                    if proc.returncode == 0:
                        return out.decode("utf-8", errors="ignore")
                except subprocess.TimeoutExpired:
                    _debug("_http_get: timeout")
                    proc.kill()
                    proc.wait(2)
                finally:
                    with self._procs_lock:
                        if proc in self._procs:
                            self._procs.remove(proc)
            except Exception as e:
                _debug(f"_http_get: error {e}")
            if self._stop:
                return None
        return None


class TesterWorker(QObject):
    progress_signal = Signal(int, int, int, str)
    testing_signal = Signal(int, str)
    result_signal = Signal(int, bool, float, str, int)
    rkn_result_signal = Signal(int, bool, list)
    log_signal = Signal(str)
    finished = Signal()
    count_signal = Signal(int)

    def __init__(self, deep: bool = False, rkn: bool = False, test_threads: int = 4, deep_threads: int = 2):
        super().__init__()
        self._deep = deep
        self._rkn = rkn
        self._test_threads = test_threads
        self._deep_threads = deep_threads
        self._stop = False
        self._sb_tester = None

    def stop(self):
        _debug(f"TesterWorker.stop() called, was_stop={self._stop}")
        self._stop = True

    @Slot()
    def test_batch(self, entries: list[ProxyEntry], indices: list[int] | None = None):
        _debug(f"test_batch: start total={len(entries)} deep={self._deep} rkn={self._rkn}")
        self._stop = False
        total = len(entries)
        if not total:
            _debug("test_batch: no entries, emitting finished")
            self.finished.emit()
            return
        threads = self._deep_threads if self._deep else self._test_threads
        pool = ThreadPoolExecutor(max_workers=threads)
        futs = {}
        resolved = {}
        try:
            for i, entry in enumerate(entries):
                if self._stop:
                    _debug(f"test_batch: stopped at entry {i}")
                    break
                orig_idx = indices[i] if indices else i
                self.testing_signal.emit(orig_idx, f"{entry.protocol} {entry.host}:{entry.port}")
                futs[pool.submit(self._test_one, entry, resolved)] = orig_idx
            _debug(f"test_batch: submitted {len(futs)}/{total}")
            done_count = 0
            pending = set(futs)
            while pending and not self._stop:
                done, pending = wait(pending, timeout=0.5)
                for fut in done:
                    row = futs[fut]
                    try:
                        ok, latency, error, ttype = fut.result()
                        self.result_signal.emit(row, ok, latency, error, ttype)
                    except Exception as ex:
                        _debug(f"test_batch: fut {row} raised {ex}")
                        self.result_signal.emit(row, False, 0.0, str(ex), 0)
                    done_count += 1
                    self.count_signal.emit(done_count)
                if done:
                    mode = "rkn" if self._rkn else ("deep" if self._deep else "tcp")
                    self.progress_signal.emit(done_count, total, threads, mode)
        finally:
            _debug(f"test_batch: done {done_count}/{total} stop={self._stop}")
            for fut in futs:
                fut.cancel()
            pool.shutdown(wait=False)
            _debug("test_batch: emitting finished")
            self.finished.emit()

    def _test_one(self, entry: ProxyEntry, resolved: dict) -> tuple[bool, float, str, int]:
        host = entry.host
        port = entry.port
        if not host or not port:
            return False, 0, "no host/port", 0
        start = time.time()
        ok = test_tcp(host, port)
        latency = (time.time() - start) * 1000
        if not ok:
            return False, 0, "tcp fail", 0
        if self._rkn:
            rkn_ok, rkn_lat, rkn_err, rkn_results = self._rkn_test(entry)
            entry.rkn_ok = rkn_ok
            entry.rkn_results = rkn_results
            return rkn_ok, rkn_lat or latency, rkn_err, 2
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

    def _rkn_test(self, entry: ProxyEntry) -> tuple[bool, float, str, list]:
        if not self._sb_tester:
            from .tester import SingBoxTester
            self._sb_tester = SingBoxTester()
        port = 29999 + (hash(entry.uri) % 10000)
        return self._sb_tester.test_rkn_bypass(entry.uri, port)


class GitHubSearchWorker(QObject):
    result_signal = Signal(list)
    partial_result_signal = Signal(list) # Новый сигнал
    error_signal = Signal(str)
    progress_signal = Signal(str)
    count_signal = Signal(int)

    def __init__(self, keywords: list[str], known_sources: set,
                 explicit_repos: Optional[list[str]] = None,
                 time_filter_days: float = 7, github_tokens: Optional[list[str]] = None,
                 max_repos: int = 12, max_files: int = 50,
                 owner: Optional[str] = None,
                 weak_hw: bool = False, deep_search: bool = False,
                 hidden_search: bool = False):
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
        self.hidden_search = hidden_search
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
        if not tokens:
            self.progress_signal.emit(f"  ⚠ Поиск без токена, лимит 60 запросов/ч")
        for attempt in range(max(1, len(tokens) + 1)):
            if self._stop:
                return None
            time.sleep(2.0 if self.weak_hw else 0.5)
            if tokens:
                token = tokens[self._token_idx % len(tokens)]
                self._token_idx += 1
            else:
                token = None
            for use_proxy in [False, True]:
                if self._stop:
                    return None
                cmd = ["curl", "-s", "--connect-timeout", "8", "--max-time", str(timeout)]
                if use_proxy:
                    cmd.extend(["--proxy", "socks5://127.0.0.1:12334"])
                cmd.extend(["-H", "Accept: application/vnd.github.v3+json",
                            "-H", "User-Agent: proxy-skitchen/2.0"])
                if token:
                    cmd.extend(["-H", f"Authorization: token {token}"])
                cmd.append(url)
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=CREATE_NO_WINDOW)
                    with self._procs_lock:
                        self._procs.append(proc)
                    try:
                        out, err = proc.communicate(timeout=timeout + 5)
                        if self._stop:
                            return None
                        if proc.returncode != 0:
                            self.progress_signal.emit(f"  ⚠ curl err: {err.decode()[:80]}")
                            continue
                        data = json.loads(out)
                        if isinstance(data, dict) and data.get("message"):
                            msg = data['message'][:60]
                            self.progress_signal.emit(f"  ⚠ API: {msg}")
                            if "bad credentials" in msg.lower():
                                self.progress_signal.emit(f"  ⚠ Токен невалиден, ищу без токена...")
                                token = None
                                continue
                            if "rate" in msg.lower():
                                time.sleep(2)
                            continue
                        return data
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(2)
                        self.progress_signal.emit(f"  ⚠ timeout")
                        continue
                    finally:
                        with self._procs_lock:
                            if proc in self._procs:
                                self._procs.remove(proc)
                except json.JSONDecodeError:
                    self.progress_signal.emit(f"  ⚠ bad json")
                    continue
        return None

    @Slot()
    def run(self):
        print("DEBUG: GitHubSearchWorker.run() started", file=sys.stderr)
        self._stop = False
        results = []
        try:
            if self.hidden_search:
                self.progress_signal.emit("  🧪 Hidden config search mode")
                for kw in self.keywords:
                    if self._stop:
                        break
                    self.progress_signal.emit(f"  🔍 scanning repos for: {kw}")
                    found = self._search_hidden(kw)
                    if found:
                        results.extend(found)
                        self.count_signal.emit(len(results))
                if not self._stop:
                    gist_results = self._search_gists(self.keywords)
                    if gist_results:
                        results.extend(gist_results)
                        self.count_signal.emit(len(results))
            else:
                seen_repos = set()
                for repo_url in self.explicit_repos:
                    if self._stop:
                        break
                    self.progress_signal.emit(f"  explicit: {repo_url}")
                    found = self._walk_explicit(repo_url)
                    results.extend(found)
                    self.count_signal.emit(len(results))
                    self.partial_result_signal.emit(list(results))
                if self.owner and not self.keywords:
                    self.progress_signal.emit(f"  📁 fetching repos for {self.owner}")
                    user_repos = self._fetch_user_repos(self.owner)
                    for i, repo_name in enumerate(user_repos):
                        if self._stop:
                            break
                        self.progress_signal.emit(f"  📁 user repo [{i+1}/{len(user_repos)}]: {repo_name}")
                        found = self._walk_explicit(repo_name)
                        results.extend(found)
                        self.count_signal.emit(len(results))
                        self.partial_result_signal.emit(list(results))
                else:
                    for kw in self.keywords:
                        if self._stop:
                            break
                        self.progress_signal.emit(f"  keyword: {kw}")
                        found = self._search_and_walk(kw, seen_repos)
                        if found is None:
                            _debug(f"CRITICAL: _search_and_walk returned None for {kw}")
                            continue
                        results.extend(found)
                        self.count_signal.emit(len(results))
            results.sort(key=lambda r: not r.get("embedded", False))
            self.result_signal.emit(results)
        except Exception as e:
            self.error_signal.emit(f"Search critical error: {e}")
        print("DEBUG: GitHubSearchWorker.run() finished", file=sys.stderr)

    def _fetch_user_repos(self, owner: str) -> list[str]:
        """Fetch all non-derived repos for a user/org via API."""
        repos = []
        page = 1
        while True:
            if self._stop:
                break
            url = f"https://api.github.com/users/{owner}/repos?per_page=100&page={page}&sort=updated&type=all"
            data = self._api(url, timeout=15)
            if data is None:
                break
            if not isinstance(data, list):
                break
            for r in data:
                name = r.get("full_name", "")
                if name and not r.get("fork", False):
                    repos.append(name)
            if len(data) < 100:
                break
            page += 1
        return repos

    def _search_hidden(self, keyword: str) -> list[dict]:
        results = []
        query = urllib.parse.quote(keyword)
        date_filter = ""
        if self.time_filter_days > 0:
            since = (datetime.now(timezone.utc) - timedelta(days=self.time_filter_days)).strftime("%Y-%m-%d")
            date_filter = f"+pushed:>={since}"
        url = f"https://api.github.com/search/repositories?q={query}{date_filter}&sort=updated&per_page={min(self.max_repos, 30)}"
        data = self._api(url)
        if data is None:
            return results
        for repo in data.get("items", [])[:self.max_repos]:
            if self._stop:
                break
            repo_url = repo.get("html_url", "")
            full_name = repo.get("full_name", "")
            default_branch = repo.get("default_branch", "main")
            self.progress_signal.emit(f"  🔍 hidden scan: {full_name} ⭐{repo.get('stargazers_count', 0)}")
            api_url = f"https://api.github.com/repos/{full_name}/git/trees/{default_branch}?recursive=1"
            tree_data = self._api(api_url)
            if tree_data is None or not isinstance(tree_data, dict):
                continue
            tree = tree_data.get("tree", [])
            candidates = self._filter_tree_items(full_name, tree)
            if not candidates:
                continue
            self.progress_signal.emit(f"    🎯 {len(candidates)} files to scan for hidden URIs")
            file_results = self._download_files(full_name, default_branch, candidates)
            for r in file_results:
                r["embedded"] = True
            results.extend(file_results)
            self.count_signal.emit(len(results))
            self.partial_result_signal.emit(list(results))
        return results

    def _search_gists(self, keywords: list[str]) -> list[dict]:
        results = []
        for kw in keywords:
            if self._stop:
                break
            self.progress_signal.emit(f"  🔍 gist search: {kw}")
            query = urllib.parse.quote(kw)
            url = f"https://api.github.com/search/gists?q={query}&per_page=10"
            data = self._api(url)
            if data is None or not isinstance(data, dict):
                continue
            for gist in data.get("items", [])[:10]:
                if self._stop:
                    break
                gist_id = gist.get("id", "")
                desc = gist.get("description", "") or gist_id
                files = gist.get("files", {})
                for fname, fdata in files.items():
                    raw_url = fdata.get("raw_url", "")
                    content = fdata.get("content", "")
                    if not content:
                        continue
                    found_uris = []
                    seen = set()
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('//') or line.startswith('#'):
                            continue
                        if is_proxy_uri(line) and line not in self.known_sources and line not in seen:
                            seen.add(line)
                            found_uris.append(line)
                        inlines = extract_inline_uris(line)
                        for u in inlines:
                            if u not in self.known_sources and u not in seen:
                                seen.add(u)
                                found_uris.append(u)
                    json_uris = parse_json_proxies(content)
                    for u in json_uris:
                        if u not in self.known_sources and u not in seen:
                            seen.add(u)
                            found_uris.append(u)
                    if found_uris:
                        entry = {
                            "file_url": raw_url,
                            "name": f"gist:{gist_id}/{fname}",
                            "repo_url": f"https://gist.github.com/{gist_id}",
                            "size": fdata.get("size", 0),
                            "stars": 0,
                            "updated": gist.get("updated_at", ""),
                            "embedded": True,
                            "count": len(found_uris),
                        }
                        results.append(entry)
                        self.progress_signal.emit(f"      🔗 {len(found_uris)} proxies in gist {fname}")
                        self.count_signal.emit(len(results))
                        break
        return results

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
        url = f"https://api.github.com/search/repositories?q={query}{date_filter}&sort=updated&per_page={min(self.max_repos, 30)}"
        data = self._api(url)
        if data is None:
            return results
        for repo in data.get("items", [])[:self.max_repos]:
            if self._stop:
                break
            repo_url = repo.get("html_url", "")
            if repo_url in seen_repos:
                continue
            seen_repos.add(repo_url)
            self.progress_signal.emit(f"  scan {repo['full_name']} ⭐{repo['stargazers_count']}")
            found = self._walk(repo)
            results.extend(found)
            self.partial_result_signal.emit(list(results))
            self.count_signal.emit(len(results))
        return results

    def _walk(self, repo: dict) -> list[dict]:
        full_name = repo.get("full_name", "")
        default_branch = repo.get("default_branch", "main")
        results = []
        api_url = f"https://api.github.com/repos/{full_name}/git/trees/{default_branch}?recursive=1"
        self.progress_signal.emit(f"  🌲 {full_name} fetching tree...")
        data = self._api(api_url)
        if data is None or not isinstance(data, dict):
            return results
        tree = data.get("tree", [])
        self.progress_signal.emit(f"  🌲 {full_name}: {len(tree)} entries")
        candidates = self._filter_tree_items(full_name, tree)
        if not candidates:
            return results
        self.progress_signal.emit(f"  🎯 {full_name}: {len(candidates)} files to check")
        results = self._download_files(full_name, default_branch, candidates)
        self.count_signal.emit(len(results))
        return results

    def _filter_tree_items(self, full_name: str, tree: list) -> list[dict]:
        skip_dirs = frozenset((
            '.git', '.github', 'node_modules', '__pycache__',
            '.vscode', '.idea', 'venv', 'dist', 'build',
            'assets', 'images', 'tests', 'docs', 'examples',
            'benchmarks', 'spec', '__tests__',
        ))
        skip_dirs_normal = skip_dirs | frozenset(('.env',))
        skip_exts = frozenset((
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4',
            '.avi', '.mkv', '.zip', '.rar', '.tar', '.gz', '.bz2',
            '.7z', '.exe', '.dll', '.so', '.dmg', '.iso',
            '.pyc', '.o', '.obj', '.class', '.img',
        ))
        text_exts = frozenset((
            '.md', '.rst', '.txt', '.yaml', '.yml', '.json',
            '.conf', '.cfg', '',
        ))
        active_skip = skip_dirs if self.hidden_search else skip_dirs_normal
        hidden_skip_exts = frozenset((
            '.txt', '.rst', '.md', '.cfg', '.conf', '',
        ))
        candidates = []
        for item in tree:
            if self._stop:
                break
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            name = os.path.basename(path)
            parts = path.split("/")
            parent_dirs = parts[:-1]
            ext = os.path.splitext(name)[1].lower()
            if ext in skip_exts:
                continue
            if any(d in active_skip for d in parent_dirs):
                continue
            if self.hidden_search:
                if ext in hidden_skip_exts:
                    continue
            elif not self.deep_search:
                if any(d.startswith(".") for d in parent_dirs):
                    continue
                if ext not in text_exts:
                    continue
            candidates.append(item)
            if len(candidates) >= self.max_files:
                break
        return candidates

    def _download_files(self, full_name: str, branch: str, candidates: list) -> list[dict]:
        results = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            fut_map = {}
            for item in candidates:
                path = item.get("path", "")
                raw_url = f"https://raw.githubusercontent.com/{full_name}/{branch}/{path}"
                size = item.get("size", 0) or 0
                fut = pool.submit(self._download_file, raw_url, size, full_name, path)
                fut_map[fut] = path
                self.progress_signal.emit(f"    📄 {full_name}/{path}")
            for fut in as_completed(fut_map):
                if self._stop:
                    break
                try:
                    res = fut.result()
                    if res:
                        results.append(res)
                except Exception:
                    pass
        return results

    def _download_file(self, raw_url: str, size: int, full_name: str, path: str) -> dict | None:
        if size > 5 * 1024 * 1024:
            return None
        try:
            cmd = ["curl", "-sL", "--connect-timeout", "5", "--max-time", "10"]
            if self.weak_hw:
                cmd.extend(["--range", "0-51200"])
            if _settings_data.get("proxy_enabled", True):
                cmd.extend(["--proxy", "socks5://127.0.0.1:12334"])
            cmd.extend(["-H", "User-Agent: Mozilla/5.0", raw_url])
            result = subprocess.run(cmd, capture_output=True, timeout=15, creationflags=CREATE_NO_WINDOW)
            if result.returncode != 0:
                return None
            body = result.stdout.decode("utf-8", errors="ignore")
            ext = os.path.splitext(path)[1].lower()
            embedded_links = []
            seen = set()
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('#'):
                    continue
                if self.hidden_search:
                    if is_proxy_uri(line):
                        continue
                    inlines = extract_inline_uris(line)
                    for u in inlines:
                        if u not in self.known_sources and u not in seen:
                            seen.add(u)
                            embedded_links.append(u)
                else:
                    if is_proxy_uri(line):
                        if line not in self.known_sources and line not in seen:
                            seen.add(line)
                            embedded_links.append(line)
            if self.hidden_search:
                json_uris = parse_json_proxies(body)
                for u in json_uris:
                    if u not in self.known_sources and u not in seen:
                        seen.add(u)
                        embedded_links.append(u)
            if not embedded_links:
                return None
            entry = {
                "file_url": raw_url,
                "name": f"{full_name}/{path}",
                "repo_url": f"https://github.com/{full_name}",
                "size": size,
                "stars": 0,
                "updated": "",
                "embedded": True,
            }
            name = os.path.basename(path)
            entry["count"] = len(embedded_links)
            self.progress_signal.emit(f"      🔗 {len(embedded_links)} hidden proxies in {name}")
            return entry
        except Exception:
            return None

    def _walk_explicit(self, repo_url: str) -> list[dict]:
        m = re.match(r'(?:https?://github\.com/)?([^/]+/[^/]+?)(?:\.git)?$', repo_url)
        if not m:
            return []
        full_name = m.group(1).rstrip('/')
        self.progress_signal.emit(f"  📁 explicit: {full_name}")
        api_url = f"https://api.github.com/repos/{full_name}/git/trees/main?recursive=1"
        self.progress_signal.emit(f"  🌲 {full_name} fetching tree...")
        data = self._api(api_url)
        if data is None or not isinstance(data, dict):
            return []
        tree = data.get("tree", [])
        self.progress_signal.emit(f"  🌲 {full_name}: {len(tree)} entries")
        candidates = self._filter_tree_items(full_name, tree)
        if not candidates:
            return []
        self.progress_signal.emit(f"  🎯 {full_name}: {len(candidates)} files to check")
        results = self._download_files(full_name, "main", candidates)
        self.partial_result_signal.emit(list(results))
        self.count_signal.emit(len(results))
        return results


class GeoWorker(QObject):
    geo_result_signal = Signal(int, str, str)
    log_signal = Signal(str)
    finished = Signal()

    def __init__(self):
        super().__init__()
        self._stop = False

    def stop(self):
        self._stop = True

    @Slot()
    def geo_batch(self, entries: list[ProxyEntry], indices: list[int] | None = None):
        _debug(f"geo_batch: start total={len(entries)}")
        self._stop = False
        total = len(entries)
        if not total:
            self.finished.emit()
            return
        done = 0
        proxy = _settings_data.get("proxy_enabled", False) and _settings_data.get("proxy_type") == "http"
        proxy_url = None
        if proxy:
            ph = _settings_data.get("proxy_host", "127.0.0.1")
            pp = _settings_data.get("proxy_port", 12334)
            proxy_url = f"http://{ph}:{pp}"

        for i, entry in enumerate(entries):
            if self._stop:
                _debug(f"geo_batch: stopped at {i}")
                break
            orig = indices[i] if indices else i
            host = entry.host
            if not host:
                done += 1
                continue
            try:
                url = f"http://ip-api.com/json/{host}?fields=country,countryCode"
                req = urllib.request.Request(url)
                if proxy_url:
                    req.set_proxy(proxy_url, "http")
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read().decode())
                code = data.get("countryCode", "")
                name = data.get("country", "")
                if code and name:
                    self.geo_result_signal.emit(orig, code, name)
                else:
                    self.log_signal.emit(f"⚠ Geo: {host} — no data")
            except Exception as ex:
                self.log_signal.emit(f"⚠ Geo: {host} — {ex}")
            done += 1
            if i < total - 1:
                time.sleep(1.5)
        _debug(f"geo_batch: done {done}/{total}")
        self.finished.emit()

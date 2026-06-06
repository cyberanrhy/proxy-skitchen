#!/usr/bin/env python3
"""
proxy-skitchen v2 — Wizard-based GUI + CLI pipeline for proxy subscription management.
"""

import sys, os, json, argparse, re, time, faulthandler, traceback
from datetime import datetime

os.environ["QT_API"] = "pyside6"

# Crash safety
faulthandler.enable()

FAULT_LOG = "/tmp/proxy-fetcher-fault.log"

def _debug(msg: str):
    try:
        with open(FAULT_LOG, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass

def _crash_log(msg: str):
    with open("/tmp/proxy-fetcher-crash.log", "a") as f:
        f.write(f"\n=== {datetime.now().isoformat()} ===\n{msg}\n")

def excepthook(etype, value, tb):
    msg = "".join(traceback.format_exception(etype, value, tb))
    _crash_log(msg)
    sys.__excepthook__(etype, value, tb)

sys.excepthook = excepthook

from .compat import QCoreApplication, QApplication, QTimer, QEventLoop, _QT6
from .models import ProxyEntry, _auth_data
from .parsers import is_proxy_uri, extract_uris, get_protocol, get_server_port, wrap_raw_host, parse_json_proxies
from .exporters import format_raw
from .tester import test_tcp, test_tls, SingBoxTester
from .workers import GitHubSearchWorker


class CliRunner:
    def __init__(self):
        self._uris: list[str] = []
        self._entries: list[ProxyEntry] = []

    def _json_out(self, data):
        print(json.dumps(data, ensure_ascii=False))

    def cmd_search(self, args):
        tokens = _auth_data.get("github_tokens", [])
        if args.token:
            tokens = [args.token]
        known = set()
        worker = GitHubSearchWorker(
            args.keywords, known, explicit_repos=args.repos or [],
            time_filter_days=7, github_tokens=tokens,
            max_repos=args.max_repos, max_files=args.max_files,
        )
        found = []
        worker.result_signal.connect(lambda res: found.extend(res))
        worker.run()
        if args.output:
            with open(args.output, "w") as f:
                for s in found:
                    f.write(f"{s['file_url']}\n")
            self._json_out({"status": "ok", "count": len(found), "output": args.output})
        else:
            self._json_out({"status": "ok", "count": len(found), "sources": found})

    def cmd_fetch(self, args):
        proxies = []
        for url in args.urls:
            try:
                import subprocess
                cmd = ["curl", "-sL", "--connect-timeout", "8", "--max-time", "15",
                       "-H", "User-Agent: Mozilla/5.0", url]
                from proxy_skitchen.models import _settings_data
                if _settings_data.get("proxy_enabled", True):
                    cmd.insert(1, "--proxy")
                    cmd.insert(2, "socks5://127.0.0.1:12334")
                result = subprocess.run(cmd, capture_output=True, timeout=25)
                if result.returncode != 0:
                    raise Exception(result.stderr.decode()[:80])
                data = result.stdout.decode("utf-8", errors="ignore")
                from proxy_skitchen.parsers import extract_uris, parse_json_proxies
                uris = extract_uris(data)
                json_uris = parse_json_proxies(data)
                # Combine and deduplicate while preserving order
                seen = set()
                for u in uris + json_uris:
                    if u not in seen:
                        seen.add(u)
                        proxies.append(u)
            except Exception as e:
                self._json_out({"status": "error", "url": url, "message": str(e)})
                return
        if args.output:
            with open(args.output, "w") as f:
                for u in proxies:
                    f.write(f"{u}\n")
            self._json_out({"status": "ok", "count": len(proxies), "output": args.output})
        else:
            self._json_out({"status": "ok", "count": len(proxies), "uris": proxies})

    def cmd_test(self, args):
        ok, ms = test_tcp(args.host, args.port), 0.0
        if ok:
            start = time.time()
            test_tcp(args.host, args.port)
            ms = (time.time() - start) * 1000
        self._json_out({"status": "ok" if ok else "fail", "host": args.host, "port": args.port, "latency_ms": round(ms, 1)})

    def cmd_test_file(self, args):
        with open(args.file) as f:
            uris = [l.strip() for l in f if l.strip() and is_proxy_uri(l.strip())]
        total = len(uris)
        tcp_ok = deep_ok = 0
        results = []
        for i, uri in enumerate(uris):
            host, port = get_server_port(uri)
            if not host or not port:
                continue
            ok = test_tcp(host, port)
            if ok:
                tcp_ok += 1
            if args.deep and ok:
                tester = SingBoxTester()
                d_ok, lat, err = tester.test(uri, 19999 + (i % 10000))
                if d_ok:
                    deep_ok += 1
        out = {"status": "ok", "total": total, "tcp_ok": tcp_ok, "deep_ok": deep_ok}
        if args.output:
            def _valid(uri):
                h, p = get_server_port(uri)
                return h and p
            ok_uris = [u for u in uris if _valid(u) and test_tcp(*get_server_port(u))]
            with open(args.output, "w") as f:
                for u in ok_uris:
                    f.write(f"{u}\n")
            out["output"] = args.output
        self._json_out(out)

    def cmd_pipeline(self, args):
        if args.verbose:
            print("Pipeline: поиск...", file=sys.stderr, flush=True)
        tokens = _auth_data.get("github_tokens", [])
        if args.token:
            tokens = [args.token]
        known = set()
        worker = GitHubSearchWorker(
            args.keywords, known, explicit_repos=args.repos or [],
            time_filter_days=7, github_tokens=tokens,
            max_repos=args.max_repos, max_files=args.max_files,
        )
        found = []
        worker.result_signal.connect(lambda res: found.extend(res))
        worker.run()
        if args.verbose:
            print(f"Pipeline: найдено {len(found)} подписок", file=sys.stderr, flush=True)
        if not found:
            self._json_out({"status": "ok", "total": 0, "tcp_ok": 0, "deep_ok": 0, "message": "ничего не найдено"})
            return

        import subprocess
        all_uris = []
        for src in found:
            url = src["file_url"]
            if args.verbose:
                print(f"  fetch {url[:60]}...", file=sys.stderr, flush=True)
            try:
                cmd = ["curl", "-sL", "--connect-timeout", "8", "--max-time", "15",
                       "-H", "User-Agent: Mozilla/5.0", url]
                from proxy_skitchen.models import _settings_data
                if _settings_data.get("proxy_enabled", True):
                    cmd.insert(1, "--proxy")
                    cmd.insert(2, "socks5://127.0.0.1:12334")
                result = subprocess.run(cmd, capture_output=True, timeout=25)
                if result.returncode != 0:
                    if args.verbose:
                        print(f"  ✗ curl err: {result.stderr.decode()[:60]}", file=sys.stderr, flush=True)
                    continue
                data = result.stdout.decode("utf-8", errors="ignore")
                if args.verbose:
                    print(f"  📄 fetched {len(data)} chars: {data[:200]}", file=sys.stderr, flush=True)
                from proxy_skitchen.parsers import extract_uris, parse_json_proxies
                uris = extract_uris(data)
                json_uris = parse_json_proxies(data)
                # Combine and deduplicate while preserving order
                seen_local = set()
                for u in uris + json_uris:
                    if u not in seen_local:
                        seen_local.add(u)
                        all_uris.append(u)
                if args.verbose:
                    print(f"  🔍 Extracted {len(uris)} + {len(json_uris)} = {len(all_uris)} uris from this source", file=sys.stderr, flush=True)
                if args.verbose:
                    print(f"  🔍 extracted {len(uris)} + {len(json_uris)} = {len(all_uris)} uris from this source", file=sys.stderr, flush=True)
            except Exception as e:
                if args.verbose:
                    print(f"  ✗ {str(e)[:60]}", file=sys.stderr, flush=True)

        # dedup
        seen = set()
        unique = []
        for u in all_uris:
            host, port = get_server_port(u)
            if host is not None and port is not None:
                if (host, port) not in seen:
                    seen.add((host, port))
                    unique.append(u)
        if args.verbose:
            print(f"Pipeline: {len(unique)} уникальных URI", file=sys.stderr, flush=True)

        # tcp test
        tcp_ok = 0
        ok_uris = []
        for u in unique:
            host, port = get_server_port(u)
            if host and port and test_tcp(host, port):
                tcp_ok += 1
                ok_uris.append(u)
        if args.verbose:
            print(f"Pipeline: TCP ok {tcp_ok}/{len(unique)}", file=sys.stderr, flush=True)

        deep_ok = 0
        sb_tester = SingBoxTester() if args.deep else None
        if args.deep:
            for i, u in enumerate(ok_uris):
                if args.verbose:
                    print(f"  deep {i+1}/{len(ok_uris)}...", file=sys.stderr, flush=True)
                d_ok, lat, err = sb_tester.test(u, 19999 + (i % 10000))
                if d_ok:
                    deep_ok += 1

        out = {"status": "ok", "total": len(unique), "tcp_ok": tcp_ok, "deep_ok": deep_ok}
        if args.output:
            with open(args.output, "w") as f:
                for u in ok_uris:
                    f.write(f"{u}\n")
            out["output"] = args.output
        self._json_out(out)


def build_parser(runner: CliRunner):
    p = argparse.ArgumentParser(description="Поиск, тестирование и экспорт прокси")
    p.add_argument("--verbose", action="store_true", help="Подробный вывод в stderr")
    sub = p.add_subparsers(dest="command")

    ps = sub.add_parser("search", help="Поиск подписок на GitHub",
        epilog="Пресеты: vless subscription, vmess subscription, trojan subscription, "
               "shadowsocks subscription, v2ray config, v2ray subscription, "
               "proxy subscription, clash subscription, sing-box subscription, "
               "free proxy config, xray config, hysteria2 subscription")
    ps.add_argument("keywords", nargs="+")
    ps.add_argument("--repos", nargs="*", default=[])
    ps.add_argument("--token", default="")
    ps.add_argument("--max-repos", type=int, default=8)
    ps.add_argument("--max-files", type=int, default=30)
    ps.add_argument("--output", "-o", default="")

    pf = sub.add_parser("fetch", help="Скачать и спарсить подписку")
    pf.add_argument("urls", nargs="+")
    pf.add_argument("--output", "-o", default="")

    pt = sub.add_parser("test", help="TCP-тест одного прокси")
    pt.add_argument("host")
    pt.add_argument("port", type=int)

    ptf = sub.add_parser("test-file", help="Проверить все URI из файла")
    ptf.add_argument("file")
    ptf.add_argument("--deep", action="store_true")
    ptf.add_argument("--output", "-o", default="")

    pp = sub.add_parser("pipeline", help="Полный конвейер: поиск → тест → сохранение",
        epilog="Пресеты: vless subscription, vmess subscription, trojan subscription, "
               "shadowsocks subscription, v2ray config, v2ray subscription, "
               "proxy subscription, clash subscription, sing-box subscription, "
               "free proxy config, xray config, hysteria2 subscription")
    pp.add_argument("keywords", nargs="+")
    pp.add_argument("--repos", nargs="*", default=[])
    pp.add_argument("--token", default="")
    pp.add_argument("--max-repos", type=int, default=8)
    pp.add_argument("--max-files", type=int, default=30)
    pp.add_argument("--deep", action="store_true")
    pp.add_argument("--output", "-o", default="")

    return p


def main_gui():
    app = QApplication(sys.argv)
    app.setApplicationName("Proxy Skitchen")
    from .ui import MainWindow
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


def main_cli(args):
    app = QCoreApplication(sys.argv)
    runner = CliRunner()
    cmd = args.command.replace("-", "_")
    getattr(runner, f"cmd_{cmd}")(args)


def main():
    runner = CliRunner()
    p = build_parser(runner)
    if len(sys.argv) <= 1:
        main_gui()
        return
    args = p.parse_args()
    if args.command:
        main_cli(args)
    else:
        main_gui()


if __name__ == "__main__":
    main()

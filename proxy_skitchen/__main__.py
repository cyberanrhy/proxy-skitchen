#!/usr/bin/env python3
"""
proxy-skitchen v2 — Wizard-based GUI + CLI pipeline for proxy subscription management.
"""

import sys, os, json, argparse, re, time, faulthandler, traceback
from datetime import datetime

os.environ["QT_API"] = "pyside6"

# Crash safety
if sys.stderr is not None:
    faulthandler.enable()

from .compat import TMP_DIR
FAULT_LOG = os.path.join(TMP_DIR, "fault.log")
CRASH_LOG = os.path.join(TMP_DIR, "crash.log")

def _debug(msg: str):
    from .compat import _write_log, DEBUG_LOG_PATHS
    if FAULT_LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(FAULT_LOG)
    _write_log(FAULT_LOG, msg)

def _crash_log(msg: str):
    from .compat import _write_log, DEBUG_LOG_PATHS
    if CRASH_LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(CRASH_LOG)
    _write_log(CRASH_LOG, msg)

def excepthook(etype, value, tb):
    msg = "".join(traceback.format_exception(etype, value, tb))
    _crash_log(msg)
    sys.__excepthook__(etype, value, tb)

sys.excepthook = excepthook

from .compat import QCoreApplication, QApplication, QTimer, QEventLoop, _QT6, CREATE_NO_WINDOW, IS_WINDOWS
from .models import ProxyEntry, _auth_data, _get_tokens
from .parsers import is_proxy_uri, extract_uris, get_protocol, get_server_port, wrap_raw_host, parse_json_proxies
from .exporters import (format_raw, format_v2rayn, format_singbox, format_clash,
                        format_hiddify, validate_content, _clean_uri, _is_valid_entry)
from .tester import test_tcp, test_tls, SingBoxTester
from .workers import GitHubSearchWorker


class CliRunner:
    def __init__(self):
        self._uris: list[str] = []
        self._entries: list[ProxyEntry] = []

    def _json_out(self, data):
        print(json.dumps(data, ensure_ascii=False))

    def cmd_search(self, args):
        tokens = _get_tokens()
        if args.token:
            tokens = [args.token]
        known = set()
        worker = GitHubSearchWorker(
            args.keywords, known, explicit_repos=args.repos or [],
            time_filter_days=args.period, github_tokens=tokens,
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
        total_uris = 0
        for url in args.urls:
            try:
                import subprocess
                cmd = ["curl", "-sL", "--connect-timeout", "8", "--max-time", "15",
                       "-H", "User-Agent: Mozilla/5.0", url]
                from proxy_skitchen.models import _settings_data
                if _settings_data.get("proxy_enabled", True):
                    cmd.insert(1, "--proxy")
                    cmd.insert(2, "socks5://127.0.0.1:12334")
                result = subprocess.run(cmd, capture_output=True, timeout=25, creationflags=CREATE_NO_WINDOW)
                if result.returncode != 0:
                    raise Exception(result.stderr.decode()[:80])
                data = result.stdout.decode("utf-8", errors="ignore")
                from proxy_skitchen.parsers import extract_uris, parse_json_proxies
                uris = extract_uris(data)
                json_uris = parse_json_proxies(data)
                # Combine and deduplicate while preserving order, keep only valid entries
                seen = set()
                for u in uris + json_uris:
                    if u in seen:
                        continue
                    seen.add(u)
                    e = ProxyEntry(u)
                    if _is_valid_entry(e):
                        proxies.append(_clean_uri(e) if args.clean else e.uri)
                total_uris += len(seen)
            except Exception as e:
                self._json_out({"status": "error", "url": url, "message": str(e)})
                return
        if args.output:
            with open(args.output, "w") as f:
                for u in proxies:
                    f.write(f"{u}\n")
            self._json_out({"status": "ok", "count": len(proxies), "valid": len(proxies),
                            "dropped": total_uris - len(proxies), "output": args.output})
        else:
            self._json_out({"status": "ok", "count": len(proxies), "valid": len(proxies),
                            "dropped": total_uris - len(proxies), "uris": proxies})

    def cmd_export(self, args):
        formatters = {
            "raw": format_raw,
            "v2rayn": format_v2rayn,
            "singbox": format_singbox,
            "clash": format_clash,
            "hiddify": format_hiddify,
        }
        fmt = args.format
        if fmt not in formatters:
            self._json_out({"status": "error", "message": f"unknown format: {fmt}"})
            return

        raw_uris = []
        for src in args.sources:
            if src.startswith(("http://", "https://")):
                import subprocess
                cmd = ["curl", "-sL", "--connect-timeout", "8", "--max-time", "15",
                       "-H", "User-Agent: Mozilla/5.0", src]
                from proxy_skitchen.models import _settings_data
                if _settings_data.get("proxy_enabled", True):
                    cmd.insert(1, "--proxy")
                    cmd.insert(2, "socks5://127.0.0.1:12334")
                try:
                    result = subprocess.run(cmd, capture_output=True, timeout=25, creationflags=CREATE_NO_WINDOW)
                    if result.returncode != 0:
                        raise Exception(result.stderr.decode()[:80])
                    data = result.stdout.decode("utf-8", errors="ignore")
                except Exception as e:
                    self._json_out({"status": "error", "source": src, "message": str(e)})
                    return
            else:
                try:
                    with open(src, encoding="utf-8") as f:
                        data = f.read().lstrip('\ufeff')
                except Exception as e:
                    self._json_out({"status": "error", "source": src, "message": str(e)})
                    return
            from proxy_skitchen.parsers import extract_uris, parse_json_proxies
            raw_uris.extend(extract_uris(data))
            raw_uris.extend(parse_json_proxies(data))

        # parse -> filter -> dedup by canonical key
        seen = set()
        entries = []
        dropped = 0
        for u in raw_uris:
            e = ProxyEntry(u)
            if not _is_valid_entry(e):
                dropped += 1
                continue
            k = e.key()
            if k in seen:
                continue
            seen.add(k)
            entries.append(e)

        kwargs = {}
        if fmt == "clash":
            kwargs["clean_names"] = args.clean_names
        if fmt == "hiddify":
            kwargs["title"] = args.title
        content = formatters[fmt](entries, include_failed=True, **kwargs)
        valid, broken = validate_content(content, fmt)
        out = {"status": "ok", "format": fmt, "count": len(entries), "dropped": dropped,
               "valid": valid, "broken": broken}
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content)
            out["output"] = args.output
        else:
            print(content, end="")
        self._json_out(out)

    def cmd_test(self, args):
        start = time.time()
        ok = test_tcp(args.host, args.port)
        ms = (time.time() - start) * 1000
        self._json_out({"status": "ok" if ok else "fail", "host": args.host, "port": args.port, "latency_ms": round(ms, 1)})

    def cmd_test_file(self, args):
        with open(args.file, encoding="utf-8") as f:
            data = f.read().lstrip('\ufeff')
        lines = [l.strip() for l in data.splitlines() if l.strip() and is_proxy_uri(l.strip())]
        uris = []
        dropped = 0
        for u in lines:
            e = ProxyEntry(u)
            if _is_valid_entry(e):
                uris.append(_clean_uri(e) if args.clean else u)
            else:
                dropped += 1
        total = len(uris)
        tcp_ok = deep_ok = rkn_ok = 0
        ok_uris = []
        sb_tester = SingBoxTester() if args.deep or args.rkn else None
        for i, uri in enumerate(uris):
            host, port = get_server_port(uri)
            if not host or not port:
                continue
            ok = test_tcp(host, port)
            if ok:
                tcp_ok += 1
                ok_uris.append(uri)
            if args.rkn and ok and sb_tester:
                r_ok, lat, err, results = sb_tester.test_rkn_bypass(uri, 29999 + (i % 10000))
                if r_ok:
                    rkn_ok += 1
            elif args.deep and ok and sb_tester:
                d_ok, lat, err = sb_tester.test(uri, 19999 + (i % 10000))
                if d_ok:
                    deep_ok += 1
        out = {"status": "ok", "total": total, "dropped": dropped, "tcp_ok": tcp_ok, "deep_ok": deep_ok, "rkn_ok": rkn_ok}
        if args.output:
            with open(args.output, "w") as f:
                for u in ok_uris:
                    f.write(f"{u}\n")
            out["output"] = args.output
        self._json_out(out)

    def cmd_pipeline(self, args):
        if args.verbose:
            print("Pipeline: поиск...", file=sys.stderr, flush=True)
        tokens = _get_tokens()
        if args.token:
            tokens = [args.token]
        known = set()
        worker = GitHubSearchWorker(
            args.keywords, known, explicit_repos=args.repos or [],
            time_filter_days=args.period, github_tokens=tokens,
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
                result = subprocess.run(cmd, capture_output=True, timeout=25, creationflags=CREATE_NO_WINDOW)
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
                # Combine and deduplicate while preserving order, keep only valid entries
                seen_local = set()
                for u in uris + json_uris:
                    if u in seen_local:
                        continue
                    seen_local.add(u)
                    e = ProxyEntry(u)
                    if _is_valid_entry(e):
                        all_uris.append(u)
                if args.verbose:
                    print(f"  🔍 Extracted {len(uris)} + {len(json_uris)} = {len(all_uris)} uris from this source", file=sys.stderr, flush=True)
            except Exception as e:
                if args.verbose:
                    print(f"  ✗ {str(e)[:60]}", file=sys.stderr, flush=True)

        # dedup by canonical key: proto:host:port (same host+port but different proto are kept)
        seen = set()
        unique = []
        for u in all_uris:
            e = ProxyEntry(u)
            k = e.key()
            if k not in seen:
                seen.add(k)
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
        rkn_ok = 0
        sb_tester = SingBoxTester() if args.deep or args.rkn else None
        if args.rkn and sb_tester:
            for i, u in enumerate(ok_uris):
                if args.verbose:
                    print(f"  rkn {i+1}/{len(ok_uris)}...", file=sys.stderr, flush=True)
                r_ok, lat, err, results = sb_tester.test_rkn_bypass(u, 29999 + (i % 10000))
                if r_ok:
                    rkn_ok += 1
        elif args.deep and sb_tester:
            for i, u in enumerate(ok_uris):
                if args.verbose:
                    print(f"  deep {i+1}/{len(ok_uris)}...", file=sys.stderr, flush=True)
                d_ok, lat, err = sb_tester.test(u, 19999 + (i % 10000))
                if d_ok:
                    deep_ok += 1

        out = {"status": "ok", "total": len(unique), "tcp_ok": tcp_ok, "deep_ok": deep_ok, "rkn_ok": rkn_ok}
        if args.output:
            lines = [
                "#profile-title: VPN Config",
                "#profile-update-interval: 24",
                f"#subscription-userinfo: upload=0; download=0; total={len(ok_uris)}; expire=0",
                "",
            ]
            for u in ok_uris:
                lines.append(_clean_uri(u) if args.clean else u)
            with open(args.output, "w") as f:
                f.write("\n".join(lines) + "\n")
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
    ps.add_argument("--period", type=int, default=7, help="Фильтр по дням (по умолчанию 7)")
    ps.add_argument("--output", "-o", default="")

    pf = sub.add_parser("fetch", help="Скачать и спарсить подписку")
    pf.add_argument("urls", nargs="+")
    pf.add_argument("--output", "-o", default="")
    pf.add_argument("--clean", action="store_true", default=True, help="Очищать #fragment из URI (по умолчанию включено)")
    pf.add_argument("--no-clean", dest="clean", action="store_false", help="Сохранять оригинальные URI с #fragment")

    pt = sub.add_parser("test", help="TCP-тест одного прокси")
    pt.add_argument("host")
    pt.add_argument("port", type=int)

    ptf = sub.add_parser("test-file", help="Проверить все URI из файла")
    ptf.add_argument("file")
    ptf.add_argument("--deep", action="store_true")
    ptf.add_argument("--rkn", action="store_true", help="RKN bypass тест")
    ptf.add_argument("--output", "-o", default="")
    ptf.add_argument("--clean", action="store_true", default=True, help="Очищать #fragment из URI (по умолчанию включено)")
    ptf.add_argument("--no-clean", dest="clean", action="store_false", help="Сохранять оригинальные URI с #fragment")

    pex = sub.add_parser("export", help="Скачать/прочитать подписку и выгрузить в формате",
        epilog="Примеры: export sub.txt --format singbox -o config.json\n"
               "          export https://example.com/sub --format clash -o config.yaml\n"
               "          export a.txt b.txt --format hiddify --title \"My Sub\"")
    pex.add_argument("sources", nargs="+", help="Локальные файлы или http(s) URL подписок")
    pex.add_argument("--format", "-f", default="raw",
                     choices=["raw", "v2rayn", "singbox", "clash", "hiddify"],
                     help="Формат выгрузки (по умолчанию raw)")
    pex.add_argument("--clean-names", action="store_true", help="Clash: простые имена без эмодзи")
    pex.add_argument("--title", default="VPN Config", help="Hiddify: заголовок подписки")
    pex.add_argument("--output", "-o", default="", help="Файл для сохранения (иначе вывод в stdout)")

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
    pp.add_argument("--period", type=int, default=7, help="Фильтр по дням (по умолчанию 7)")
    pp.add_argument("--deep", action="store_true")
    pp.add_argument("--rkn", action="store_true", help="RKN bypass тест (проверка доступа к заблокированным сайтам)")
    pp.add_argument("--output", "-o", default="")
    pp.add_argument("--clean", action="store_true", default=True, help="Очищать #fragment из URI (по умолчанию включено)")
    pp.add_argument("--no-clean", dest="clean", action="store_false", help="Сохранять оригинальные URI с #fragment")

    return p


def main_gui():
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("proxy-skitchen")
        except Exception:
            pass
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

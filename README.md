# proxy-skitchen

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

<table>
<tr>
<td>

**🇷🇺 Живущим в блокировках — держитесь. Свободный интернет всё ещё существует, просто его теперь ищут.**

**🌍 To those living behind censorship firewalls — stay strong. The open internet still exists; you just have to look a little harder for it.**

</td>
</tr>
</table>

> Find working proxy servers and subscriptions in minutes.  
> Scrape, test, and export — all in one desktop app.

![screenshot](screenshot.png)

---

## Stop hunting for proxies. Let the kitchen do the work.

**proxy-skitchen** automatically finds proxy configs on GitHub, tests them for real, and exports only the working ones.

Whether you need a handful of reliable servers for daily use or a large pool for load testing — you set the keywords, and the app does the rest.

### What you get

- **Live proxy list** — not dead links, not outdated dumps. Only servers that passed real TCP + HTTP testing.
- **Any format** — Clash, sing-box, Hiddify, V2RayN, or plain URI list. Import anywhere.
- **All major protocols** — VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC.
- **Hidden configs** — scrapes base64-encoded subs, inline URIs embedded in text files.
- **Scan GitHub user repos** — paste a user URL (`https://github.com/user`), scans all their repos.
- **Explicit repo URL** — paste any repo URL including paths with `/blob/` or `/tree/`.
- **Country flags** — see at a glance where each server is located.
- **Cross-platform** — works on Linux, Windows, and macOS (PySide2 / PySide6).

---

## How it works

```
🔍 Search GitHub  →  ⬇ Download configs  →  ✅ Test  →  📦 Export
```

1. **Search** — enter keywords like "vless subscription", paste a GitHub repo URL, or a user profile to scan all repos.
2. **Download** — the app fetches all found configs in one click. Configs can be hidden in base64, inline URIs, or plain text.
3. **Test** — quick TCP check, then deep HTTP validation via sing-box (or xray-core for VLESS Reality).
4. **Export** — save the working list in your preferred format.

---

## Why you'll like it

| | |
|---|---|
| **No hunting** | Scans GitHub repos automatically — finds what others hide in config files, READMEs, base64 dumps, even inline URIs in source code. |
| **No dead proxies** | Deep test makes real HTTP requests, not just ping. If it passes — it works. VLESS Reality tested via xray-core. |
| **One-click export** | Clash, sing-box, Hiddify, V2RayN — pick your poison. |
| **Hidden config mode** | Finds proxies embedded in any text file — base64 encoded, inline in code, JSON, markdown — and parses them. |
| **SOCKS5 proxy support** | Built-in toggle to route all downloads through a local SOCKS5 proxy — essential behind censorship firewalls. |
| **Minimize to tray** | Close button hides to system tray. Restore via double-click. Quit only from tray menu. |
| **Dark / Light themes** | Built-in themes + auto-performance presets for low-RAM machines. |
| **i18n** | Interface in Russian and English (auto-detects system language). |
| **Cross-platform** | Works on Linux, Windows (7/10/11), and macOS. |
| **Privacy first** | No accounts, no telemetry, no cloud. Everything runs locally. |

---

## Supported protocols

| Protocol | Parse | Test | Export |
|----------|-------|------|--------|
| VLESS | ✓ | ✓ | ✓ |
| VMess | ✓ | ✓ | ✓ |
| Trojan | ✓ | ✓ | ✓ |
| Shadowsocks | ✓ | ✓ | ✓ |
| Hysteria2 | ✓ | ✓ | ✓ |
| TUIC | ✓ | ✓ | ✓ |
| WireGuard | ✓ | – | – |

---

## Quick start

### Linux / macOS

```bash
git clone https://github.com/cyberanrhy/proxy-skitchen.git
cd proxy-skitchen
pip install -r requirements.txt
python3 -m proxy_skitchen
```

### Windows

```bash
git clone https://github.com/cyberanrhy/proxy-skitchen.git
cd proxy-skitchen
pip install -r requirements.txt
python -m proxy_skitchen
```

### Windows (EXE)

Download the latest release from [Releases](https://github.com/cyberanrhy/proxy-skitchen/releases) and run `proxy-skitchen.exe`.

*Requires Python 3.10+ and curl. sing-box is optional (needed for deep test). xray-core is optional (needed for VLESS Reality deep test).*

---

## CLI mode

```bash
# Search and save
python3 -m proxy_skitchen search "vless subscription" --output sources.txt

# Full pipeline
python3 -m proxy_skitchen pipeline "vless subscription" --deep --output working.txt

# Quick TCP test
python3 -m proxy_skitchen test 1.2.3.4 443

# Test all proxies in a file
python3 -m proxy_skitchen test-file proxies.txt --deep --output working.txt
```

---

## Building from source

```bash
pip install pyinstaller
pyinstaller proxy-skitchen.spec
```

The executable will be in `dist/proxy-skitchen` (Linux/macOS) or `dist/proxy-skitchen.exe` (Windows).

---

## License

MIT

# proxy-skitchen

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![PySide6](https://img.shields.io/badge/GUI-PySide6-green.svg)](https://wiki.qt.io/Qt_for_Python)

**proxy-skitchen** — a desktop application for proxy scraping, searching, deep testing, and exporting.  
Designed for anyone who works with proxy subscriptions, V2Ray configs, and modern proxy protocols.

Built on top of [proxy-fetcher-gui](https://github.com/igareck/proxy-fetcher-gui).  
Supports **VLESS**, **VMess**, **Trojan**, **Shadowsocks**, **Hysteria2**, **TUIC**, and **WireGuard** URIs.

![screenshot](screenshot.png)

---

## Why proxy-skitchen?

- **GitHub proxy search** — finds configs by keywords across repositories, including deep scanning of hidden files.
- **Multi-format export** — Clash YAML, sing-box JSON, Hiddify subscription, V2RayN, raw proxy list.
- **Deep testing** — real HTTP validation via sing-box (not just TCP ping).
- **Lightweight GUI** — runs on modest hardware, optional Weak HW mode.
- **Privacy-first** — no telemetry, no external services (except GitHub API for search).

---

## Features

- **🔍 GitHub Search** — scrape proxy configs from public repositories using keywords and URL filters.
- **⬇ Subscription Download** — multi-threaded fetcher with auto-detection of Base64 and plain text.
- **🌍 Geo Detection** — automatic country flag lookup for tested proxies.
- **✅ TCP Test** — fast connectivity check (host:port, 12s timeout).
- **🧪 Deep Test** — full HTTP validation via sing-box for reliable results.
- **📦 Export Formats** — Clash, sing-box, Hiddify, V2RayN, raw proxy list.
- **🔄 Hiddify Integration** — one-click subscription import into HiddifyNext.
- **🕵 SNI Parsing** — automatic domain extraction from any proxy URI.
- **⚡ Performance Modes** — three presets for low-end to high-end machines.

---

## Protocols

| Protocol | Parsing | Sing-box Test | Hiddify Export |
|----------|---------|---------------|----------------|
| VLESS | ✓ | ✓ | ✓ |
| VMess | ✓ | ✓ | ✓ |
| Trojan | ✓ | ✓ | ✓ |
| Shadowsocks | ✓ | ✓ | ✓ |
| Hysteria2 | ✓ | ✓ | ✓ |
| TUIC | ✓ | ✓ | ✓ |
| WireGuard | ✓ | – | – |

---

## Requirements

- Python 3.10+
- PySide6 (Qt6)
- sing-box *(optional, for deep test)*
- curl

## Installation

```bash
git clone https://github.com/cyberanrhy/proxy-skitchen.git
cd proxy-skitchen
pip install -r requirements.txt
python3 -m proxy_skitchen
```

## Usage

1. **Search** — enter keywords or a GitHub repo URL.
2. **Download** — select sources and fetch.
3. **Test** — TCP (fast) → Deep (sing-box) → optional Geo.
4. **Export** — save working proxies in any supported format.

### Performance Modes

| Mode | TCP Threads | Deep Threads | Repositories | Files |
|------|-------------|--------------|--------------|-------|
| 🐢 Low | 2 | 1 | 3 | 20 |
| ⚡ Medium | 4 | 2 | 8 | 50 |
| 🚀 High | 8 | 3 | 15 | 150 |

### CLI

```bash
# Search subscriptions
python3 -m proxy_skitchen search "vless subscription" --output sources.txt

# Full pipeline: search → download → TCP test → save
python3 -m proxy_skitchen pipeline "vless subscription" --deep --output working.txt

# Test a single proxy
python3 -m proxy_skitchen test 1.2.3.4 443
```

---

## Project Structure

```
proxy-skitchen/
├── proxy_skitchen/
│   ├── ui.py               # GUI (PySide6)
│   ├── workers.py          # Background workers
│   ├── models.py           # Data + settings
│   ├── parsers.py          # Protocol parsing
│   ├── tester.py           # TCP + Deep testing
│   ├── exporters.py        # Export formats
│   └── compat.py           # PySide2/PySide6 compat
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## License

MIT

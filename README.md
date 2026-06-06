# proxy-skitchen

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![PySide6](https://img.shields.io/badge/GUI-PySide6-green.svg)](https://wiki.qt.io/Qt_for_Python)

**proxy-skitchen** — a graphical application for searching, parsing, deep testing (via sing-box), and saving proxy subscriptions in Hiddify, Clash, sing-box, V2RayN, and other formats.

Fork of [proxy-fetcher-gui](https://github.com/igareck/proxy-fetcher-gui).

## Features

- 🔍 **Source Search** — GitHub repository parsing by keywords + direct URL entry.
- ⬇ **Subscription Download** — multi-threaded proxy file and Base64 subscription parsing.
- ✅ **TCP Test** — quick availability check (host:port, 12s timeout).
- 🧪 **Deep Test** — deep check via sing-box (real HTTP request).
- 📦 **Export** — Clash YAML, sing-box JSON, V2RayN TXT, Hiddify, raw URIs.
- ⚡ **Three performance modes** — for low-end and high-end PCs.
- 🔄 **Hiddify Integration** — direct subscription import.
- 🕵 **SNI Parsing** — automatic SNI extraction from URI.

## Requirements

- Python 3.10+
- PySide6 (Qt6)
- sing-box (optional, for deep test)
- curl (for subscription download)

## Installation

```bash
# Clone
git clone https://github.com/cyberanrhy/proxy-skitchen.git
cd proxy-skitchen

# Install dependencies
pip install -r requirements.txt

# Run (module)
python3 -m proxy_skitchen
```

## Usage

1. **Search** — enter keywords, repository URL, or a direct subscription link.
2. **Download** — select sources and click "▶ Download & Test".
3. **Test** — run TCP test, then deep test via sing-box.
4. **Export** — save working proxies in the required format.

### Performance Modes

| Mode | TCP Threads | Deep Threads | Repositories | Files |
|-------|-----------|-------------|--------------|--------|
| 🐢 Low | 2 | 1 | 3 | 20 |
| ⚡ Medium | 4 | 2 | 8 | 50 |
| 🚀 High | 8 | 3 | 15 | 150 |

## Project Structure

```
proxy-skitchen/
├── proxy_skitchen/         # Package (modular structure)
│   ├── __init__.py
│   ├── __main__.py         # Entry point + CLI
│   ├── ui.py               # GUI (PySide6)
│   ├── workers.py          # Background threads (search, download)
│   ├── models.py           # Data models + settings
│   ├── parsers.py          # URI parsing (vmess, vless, trojan, ss, hy2, tuic)
│   ├── tester.py           # TCP + Deep testing
│   ├── exporters.py        # Export formats
│   └── compat.py           # PySide2/PySide6 compatibility
├── requirements.txt        # Dependencies
├── pyproject.toml          # Package metadata
├── LICENSE                 # MIT License
└── README.md               # Documentation
```

## CLI

```bash
# Search subscriptions
python3 -m proxy_skitchen search "vless subscription" --output sources.txt

# Full pipeline: search → download → TCP test → save
python3 -m proxy_skitchen pipeline "vless subscription" --deep --output working.txt

# Test a single proxy
python3 -m proxy_skitchen test 1.2.3.4 443
```

## License

MIT

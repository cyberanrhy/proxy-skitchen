"""Deterministic strategy candidates for bypassing DPI/RKN blocks.

Pure logic: no network, no Qt.  A caller (tester/worker) takes a candidate's
``overrides`` dict and passes it to ``SingBoxTester._make_config`` or
``XrayTester._make_config``.
"""

from dataclasses import dataclass, field

FRAGMENT_OVERRIDES = {"fragment": True, "fragment_fallback_delay": "500ms"}

# Fixed order keeps runs reproducible; the bandit (later) may reorder them.
UTLS_FINGERPRINTS = ("chrome", "firefox", "safari", "randomized")

# Alternative CDN-friendly ports (Cloudflare and friends).
CDN_PORTS = (2053, 2083, 2087, 2096)


@dataclass
class StrategyCandidate:
    name: str
    overrides: dict = field(default_factory=dict)
    cost: int = 1

    def dedupe_key(self) -> tuple:
        return (self.name, tuple(sorted(self.overrides.items())))


def _as_is() -> StrategyCandidate:
    return StrategyCandidate("as_is", {})


def _fragment() -> StrategyCandidate:
    return StrategyCandidate("fragment", dict(FRAGMENT_OVERRIDES))


def _utls(fingerprint: str) -> StrategyCandidate:
    return StrategyCandidate(f"utls_{fingerprint}", {"utls": fingerprint})


def _cdn_port(port: int) -> StrategyCandidate:
    return StrategyCandidate(f"port_{port}", {"port": port})


def candidate_strategies(
    block_type: str,
    protocol: str = "",
    security: str = "",
    transport: str = "",
    server_port: int = 443,
    max_candidates: int = 4,
) -> list[StrategyCandidate]:
    """Return an ordered, deduplicated list of strategies for a block type.

    The first candidate is the cheapest/most likely.  ``max_candidates`` bounds
    the extra test cost per proxy.
    """
    bt = (block_type or "unknown").strip().lower()
    candidates: list[StrategyCandidate] = []

    if bt == "dns_poison":
        # The block is client-side; config overrides cannot fix DNS. The caller
        # should enable DoH instead, so we only re-test as-is.
        candidates = [_as_is()]

    elif bt == "ip_block":
        # Same IP is blocked: try a CDN/alternate port, then as-is as a control.
        candidates = [_as_is()]
        alt = next((p for p in CDN_PORTS if p != int(server_port or 0)), None)
        if alt:
            candidates.insert(0, _cdn_port(alt))

    elif bt == "whitelist":
        # We cannot guess an allowlisted SNI here without a list; fragmentation
        # is the only config-side lever, then a plain re-test.
        candidates = [_as_is(), _fragment()]

    elif bt == "sni_rst":
        candidates = [_fragment()] + [_utls(fp) for fp in UTLS_FINGERPRINTS] + [_as_is()]

    elif bt == "proto_fp":
        candidates = [_utls(fp) for fp in UTLS_FINGERPRINTS] + [_as_is()]

    elif bt == "app_block":
        candidates = [_utls(fp) for fp in UTLS_FINGERPRINTS] + [_as_is()]

    elif bt == "throttle":
        candidates = [_as_is(), _fragment()]

    else:  # none / unknown
        candidates = [
            _as_is(), _fragment(),
            _utls(UTLS_FINGERPRINTS[0]),
            _utls(UTLS_FINGERPRINTS[1]),
        ]

    # De-duplicate while keeping order, then bound the cost.
    seen = set()
    unique: list[StrategyCandidate] = []
    for cand in candidates:
        key = cand.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(cand)
    limit = max(1, int(max_candidates))
    return unique[:limit]


def strategy_names(candidates: list[StrategyCandidate]) -> list[str]:
    return [c.name for c in candidates]


_LABELS = {
    "ru": {
        "as_is": "как есть",
        "fragment": "дробление TLS",
        "utls_chrome": "маскировка Chrome",
        "utls_firefox": "маскировка Firefox",
        "utls_safari": "маскировка Safari",
        "utls_randomized": "случайная маскировка",
    },
    "en": {
        "as_is": "as is",
        "fragment": "TLS split",
        "utls_chrome": "Chrome disguise",
        "utls_firefox": "Firefox disguise",
        "utls_safari": "Safari disguise",
        "utls_randomized": "random disguise",
    },
}

_TOOLTIPS = {
    "ru": {
        "as_is": "Обычное подключение без изменений.",
        "fragment": "Начало защищённого соединения разбивается на части, "
                    "чтобы фильтр не смог узнать сайт по имени.",
        "utls_chrome": "Подключение притворяется обычным браузером Chrome.",
        "utls_firefox": "Подключение притворяется обычным браузером Firefox.",
        "utls_safari": "Подключение притворяется обычным браузером Safari.",
        "utls_randomized": "Каждый раз выбирается случайный браузерный профиль.",
    },
    "en": {
        "as_is": "Plain connection without changes.",
        "fragment": "Splits the start of the TLS handshake so DPI cannot "
                    "recognise the site name.",
        "utls_chrome": "Connects as a regular Chrome browser.",
        "utls_firefox": "Connects as a regular Firefox browser.",
        "utls_safari": "Connects as a regular Safari browser.",
        "utls_randomized": "Picks a random browser profile every time.",
    },
}


def strategy_label(name: str, lang: str = "ru") -> str:
    """Human-readable strategy name for the table and logs."""
    if not name:
        return ""
    table = _LABELS.get(lang, _LABELS["ru"])
    if name in table:
        return table[name]
    if name.startswith("port_"):
        prefix = "порт " if lang == "ru" else "port "
        return prefix + name[5:]
    return name


def strategy_tooltip(name: str, lang: str = "ru") -> str:
    table = _TOOLTIPS.get(lang, _TOOLTIPS["ru"])
    if name in table:
        return table[name]
    if name.startswith("port_"):
        if lang == "ru":
            return f"Подключение через порт {name[5:]} — иногда фильтр проверяет только 443."
        return f"Connect via port {name[5:]} — some filters only inspect 443."
    return strategy_label(name, lang)


def _uri_param(uri: str, key: str, default: str = "") -> str:
    qm = uri.find('?')
    if qm == -1:
        return default
    qs = uri[qm + 1:]
    hash_pos = qs.find('#')
    if hash_pos != -1:
        qs = qs[:hash_pos]
    for part in qs.split('&'):
        k, sep, v = part.partition('=')
        if sep and k == key:
            return v
    return default


def candidates_for_failed_entry(entry, limit: int = 3) -> list[StrategyCandidate]:
    """Pick bypass variants worth trying for a proxy that failed a test.

    ``as_is`` is dropped (it already failed) and so is a port change to the
    port the node already uses.
    """
    block = getattr(entry, "block_type", "") or "unknown"
    current_port = int(getattr(entry, "port", 0) or 0)
    cands = candidate_strategies(
        block,
        protocol=getattr(entry, "protocol", ""),
        security=_uri_param(getattr(entry, "uri", ""), "security"),
        transport=_uri_param(getattr(entry, "uri", ""), "type", "tcp"),
        server_port=current_port,
        max_candidates=max(limit + 1, 4),
    )
    filtered = [
        c for c in cands
        if c.name != "as_is" and c.overrides.get("port") != current_port
    ]
    return filtered[:max(1, int(limit))]

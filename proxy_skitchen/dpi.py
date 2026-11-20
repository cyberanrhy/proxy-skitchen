"""DPI/RKN evidence model and rule-based block classifier.

The module is deliberately free of network I/O so the classification logic can
be unit-tested.  Probes live in ``tester.py`` and fill :class:`DpiEvidence`.
"""

from dataclasses import dataclass, field
from enum import Enum


class BlockType(str, Enum):
    NONE = "none"
    DNS_POISON = "dns_poison"
    SNI_RST = "sni_rst"
    IP_BLOCK = "ip_block"
    THROTTLE = "throttle"
    APP_BLOCK = "app_block"
    PROTO_FP = "proto_fp"
    WHITELIST = "whitelist"
    UNKNOWN = "unknown"


# Human readable labels (RU) used by the UI later.
BLOCK_LABELS = {
    BlockType.NONE: "нет блокировки",
    BlockType.DNS_POISON: "подмена DNS",
    BlockType.SNI_RST: "обрыв по SNI",
    BlockType.IP_BLOCK: "блокировка IP",
    BlockType.THROTTLE: "замедление",
    BlockType.APP_BLOCK: "прикладной блок",
    BlockType.PROTO_FP: "блокировка протокола",
    BlockType.WHITELIST: "режим белых списков",
    BlockType.UNKNOWN: "неизвестно",
}

_PROBE_REASON_RU = {
    "timeout": "таймаут — сервер не ответил",
    "reset": "соединение сброшено (похоже на DPI)",
    "tls_error": "ошибка TLS — соединение подменяют",
    "probe_failed": "нет ответа от проверочного сайта",
    "204_with_body": "ответ подменён (страница-заглушка)",
    "connectionrefusederror": "порт закрыт",
    "connectionreseterror": "соединение сброшено",
    "urlerror": "сеть недоступна",
    "tcp_unreachable": "сервер не отвечает (порт закрыт или IP заблокирован)",
    "unknown": "неизвестная ошибка",
}
_PROBE_REASON_EN = {
    "timeout": "timeout — the server did not answer",
    "reset": "connection reset (looks like DPI)",
    "tls_error": "TLS error — the connection is being tampered with",
    "probe_failed": "no answer from the check site",
    "204_with_body": "response replaced (block page)",
    "connectionrefusederror": "port closed",
    "connectionreseterror": "connection reset",
    "urlerror": "network unreachable",
    "tcp_unreachable": "server did not answer (port closed or IP blocked)",
    "unknown": "unknown error",
}


def probe_reason_label(reason: str, lang: str = "ru") -> str:
    """Turn a technical probe reason into a short human sentence."""
    if not reason:
        return ""
    table = _PROBE_REASON_EN if lang == "en" else _PROBE_REASON_RU
    if reason in table:
        return table[reason]
    if reason.startswith("http_"):
        code = reason[5:]
        return (f"site returned HTTP {code}" if lang == "en"
                else f"сайт ответил HTTP {code}")
    if reason.startswith("trace_invalid_"):
        code = reason.rsplit("_", 1)[-1]
        return (f"response does not look genuine (HTTP {code})" if lang == "en"
                else f"ответ не похож на настоящий (HTTP {code})")
    if reason.startswith("marker_missing_"):
        code = reason.rsplit("_", 1)[-1]
        return (f"wrong page received (HTTP {code})" if lang == "en"
                else f"получена не та страница (HTTP {code})")
    return reason


@dataclass
class DpiEvidence:
    """Facts collected by probes for one (host, sni) pair.

    ``None`` means "not measured" and is skipped by the rules.  Every verdict
    should be backed by a control measurement (``control_*``), otherwise the
    classifier is not allowed to claim a network-level block.
    """

    host: str = ""
    sni: str = ""

    # DNS
    dns_system_ip: str = ""
    dns_doh_ip: str = ""

    # Direct probes to the target
    tcp_ok: bool | None = None
    tcp_error: str = ""
    tls_ok: bool | None = None
    tls_error: str = ""
    http_code: int | None = None
    http_ok: bool | None = None

    # Control probes (known-good endpoints)
    control_tcp_ok: bool | None = None
    control_tls_ok: bool | None = None

    # Throughput, kbps
    throughput_kbps: float | None = None
    throughput_baseline_kbps: float | None = None
    throttle_ratio: float = 0.25

    # Per-protocol outcome, e.g. {"vless": True, "trojan": False}
    protocol_ok: dict[str, bool] = field(default_factory=dict)

    # Whitelist mode: allowlisted SNI works, blocked SNI does not
    allowlisted_ok: bool | None = None
    blocked_ok: bool | None = None


def dns_mismatch(system_ip: str, doh_ip: str) -> bool:
    """True when system and DoH resolvers disagree (both non-empty)."""
    return bool(system_ip) and bool(doh_ip) and system_ip != doh_ip


def throughput_is_throttled(
    kbps: float | None,
    baseline_kbps: float | None,
    ratio: float = 0.25,
) -> bool:
    """True when measured throughput is a small fraction of the baseline."""
    if kbps is None or baseline_kbps is None or baseline_kbps <= 0:
        return False
    return kbps < baseline_kbps * max(0.0, ratio)


def _tls_reset_like(error: str) -> bool:
    text = (error or "").lower()
    return any(token in text for token in (
        "reset", "eof", "alert", "handshake", "unexpected", "connection aborted",
    ))


def classify_block(ev: DpiEvidence) -> BlockType:
    """Apply deterministic rules, ordered from most specific to generic.

    Rules intentionally require control evidence for network-level claims, so
    a dead server is not reported as an ISP block.
    """
    # Whitelist mode has its own signature: allowlisted SNI passes, blocked fails.
    if ev.allowlisted_ok is True and ev.blocked_ok is False:
        return BlockType.WHITELIST

    if dns_mismatch(ev.dns_system_ip, ev.dns_doh_ip):
        return BlockType.DNS_POISON

    # IP block: target TCP fails while control TCP works.
    if ev.tcp_ok is False and ev.control_tcp_ok is True:
        return BlockType.IP_BLOCK

    # SNI-based reset: TCP connects but TLS is killed.
    if ev.tcp_ok is True and ev.tls_ok is False:
        return BlockType.SNI_RST

    # TLS works but the application layer is rejected.
    if ev.tls_ok is True and ev.http_ok is False:
        if ev.http_code in (403, 429, 451):
            return BlockType.APP_BLOCK
        if _tls_reset_like(ev.tls_error):
            return BlockType.SNI_RST

    # Throttling: connection works but is much slower than baseline.
    if ev.tls_ok is True and throughput_is_throttled(
        ev.throughput_kbps, ev.throughput_baseline_kbps, ev.throttle_ratio
    ):
        return BlockType.THROTTLE

    # Protocol fingerprinting: TLS works, one protocol fails while another passes.
    if ev.tls_ok is True and ev.protocol_ok:
        values = list(ev.protocol_ok.values())
        if any(values) and not all(values):
            return BlockType.PROTO_FP

    if ev.tls_ok is True and ev.http_ok is not False:
        return BlockType.NONE

    return BlockType.UNKNOWN


def classify_with_confidence(ev: DpiEvidence) -> tuple[BlockType, float]:
    """Return the verdict plus a coarse confidence for UI/ranking.

    Confidence is rule-based: strong control-backed evidence gets 0.9,
    DNS-only evidence 0.8, and unknown 0.0.  It is not a probability and must
    not be used as one until a calibrated model replaces it.
    """
    block = classify_block(ev)
    if block == BlockType.UNKNOWN:
        return block, 0.0
    if block in (BlockType.IP_BLOCK, BlockType.SNI_RST, BlockType.WHITELIST):
        return block, 0.9
    if block == BlockType.DNS_POISON:
        return block, 0.8
    if block in (BlockType.THROTTLE, BlockType.APP_BLOCK, BlockType.PROTO_FP):
        return block, 0.7
    return block, 0.5

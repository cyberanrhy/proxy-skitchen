import unittest

from proxy_skitchen.dpi import (
    BlockType,
    DpiEvidence,
    classify_block,
    classify_with_confidence,
    dns_mismatch,
    throughput_is_throttled,
)


class TestDnsMismatch(unittest.TestCase):
    def test_equal_is_false(self):
        self.assertFalse(dns_mismatch("1.2.3.4", "1.2.3.4"))

    def test_different_is_true(self):
        self.assertTrue(dns_mismatch("10.0.0.1", "1.2.3.4"))

    def test_missing_data_is_false(self):
        self.assertFalse(dns_mismatch("", "1.2.3.4"))
        self.assertFalse(dns_mismatch("1.2.3.4", ""))


class TestThrottle(unittest.TestCase):
    def test_below_ratio(self):
        self.assertTrue(throughput_is_throttled(10, 1000))

    def test_above_ratio(self):
        self.assertFalse(throughput_is_throttled(500, 1000))

    def test_no_baseline(self):
        self.assertFalse(throughput_is_throttled(10, None))
        self.assertFalse(throughput_is_throttled(None, 1000))
        self.assertFalse(throughput_is_throttled(10, 0))


class TestClassify(unittest.TestCase):
    def test_whitelist_has_priority(self):
        ev = DpiEvidence(
            dns_system_ip="1.1.1.1", dns_doh_ip="2.2.2.2",
            allowlisted_ok=True, blocked_ok=False,
        )
        self.assertEqual(classify_block(ev), BlockType.WHITELIST)

    def test_dns_poison(self):
        ev = DpiEvidence(dns_system_ip="10.0.0.1", dns_doh_ip="1.2.3.4")
        self.assertEqual(classify_block(ev), BlockType.DNS_POISON)

    def test_ip_block_requires_control(self):
        ev = DpiEvidence(tcp_ok=False, control_tcp_ok=True)
        self.assertEqual(classify_block(ev), BlockType.IP_BLOCK)

    def test_dead_server_is_not_ip_block(self):
        ev = DpiEvidence(tcp_ok=False, control_tcp_ok=False)
        self.assertEqual(classify_block(ev), BlockType.UNKNOWN)

    def test_sni_rst(self):
        ev = DpiEvidence(tcp_ok=True, tls_ok=False, tls_error="Connection reset by peer")
        self.assertEqual(classify_block(ev), BlockType.SNI_RST)

    def test_app_block_403(self):
        ev = DpiEvidence(tcp_ok=True, tls_ok=True, http_ok=False, http_code=403)
        self.assertEqual(classify_block(ev), BlockType.APP_BLOCK)

    def test_throttle(self):
        ev = DpiEvidence(
            tcp_ok=True, tls_ok=True, http_ok=True,
            throughput_kbps=20, throughput_baseline_kbps=1000,
        )
        self.assertEqual(classify_block(ev), BlockType.THROTTLE)

    def test_proto_fp(self):
        ev = DpiEvidence(tcp_ok=True, tls_ok=True, protocol_ok={"vless": True, "trojan": False})
        self.assertEqual(classify_block(ev), BlockType.PROTO_FP)

    def test_none(self):
        ev = DpiEvidence(tcp_ok=True, tls_ok=True, http_ok=True)
        self.assertEqual(classify_block(ev), BlockType.NONE)

    def test_unknown(self):
        self.assertEqual(classify_block(DpiEvidence()), BlockType.UNKNOWN)

    def test_confidence_bounds(self):
        for ev in (
            DpiEvidence(tcp_ok=True, tls_ok=True, http_ok=True),
            DpiEvidence(),
            DpiEvidence(tcp_ok=True, tls_ok=False),
            DpiEvidence(dns_system_ip="10.0.0.1", dns_doh_ip="1.2.3.4"),
        ):
            _, conf = classify_with_confidence(ev)
            self.assertGreaterEqual(conf, 0.0)
            self.assertLessEqual(conf, 1.0)


if __name__ == "__main__":
    unittest.main()

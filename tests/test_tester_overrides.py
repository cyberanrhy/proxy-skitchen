import unittest

from proxy_skitchen.tester import (
    RKN_TARGETS,
    SingBoxTester,
    XrayTester,
    summarize_rkn_results,
)

VLESS_TLS = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?type=ws&security=tls&sni=example.com&fp=chrome&path=%2Fws#node"
)
VLESS_REALITY = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome"
    "&pbk=abc123&sid=deadbeef&flow=xtls-rprx-vision#reality"
)


class TestSingBoxOverrides(unittest.TestCase):
    def setUp(self):
        self.tester = SingBoxTester()

    def test_no_overrides_keeps_config(self):
        cfg = self.tester._make_config(VLESS_TLS, 20001)
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["server_port"], 443)
        self.assertNotIn("fragment", outbound.get("tls", {}))

    def test_fragment_utls_sni_port(self):
        cfg = self.tester._make_config(VLESS_TLS, 20001, {
            "fragment": True,
            "utls": "firefox",
            "sni": "front.example",
            "port": 8443,
            "fragment_fallback_delay": "500ms",
        })
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["server_port"], 8443)
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "firefox")
        self.assertEqual(outbound["tls"]["server_name"], "front.example")
        self.assertTrue(outbound["tls"]["fragment"])
        self.assertEqual(outbound["tls"]["fragment_fallback_delay"], "500ms")

    def test_bad_port_is_ignored(self):
        cfg = self.tester._make_config(VLESS_TLS, 20001, {"port": "not-a-port"})
        self.assertEqual(cfg["outbounds"][0]["server_port"], 443)

    def test_server_override(self):
        cfg = self.tester._make_config(VLESS_TLS, 20001, {"server": "10.0.0.9"})
        self.assertEqual(cfg["outbounds"][0]["server"], "10.0.0.9")


class TestXrayOverrides(unittest.TestCase):
    def setUp(self):
        self.tester = XrayTester()

    def test_no_overrides_keeps_config(self):
        cfg = self.tester._make_config(VLESS_REALITY, 20002)
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["settings"]["vnext"][0]["port"], 443)
        self.assertNotIn("fragment", outbound["streamSettings"])

    def test_reality_fragment_utls_port_sni(self):
        cfg = self.tester._make_config(VLESS_REALITY, 20002, {
            "fragment": True,
            "utls": "safari",
            "sni": "cdn.example",
            "port": 2053,
        })
        outbound = cfg["outbounds"][0]
        stream = outbound["streamSettings"]
        self.assertEqual(outbound["settings"]["vnext"][0]["port"], 2053)
        self.assertEqual(stream["fragment"]["packets"], "tlshello")
        self.assertEqual(stream["fragment"]["length"], "100-200")
        self.assertEqual(stream["realitySettings"]["fingerprint"], "safari")
        self.assertEqual(stream["realitySettings"]["serverName"], "cdn.example")

    def test_custom_fragment_dict(self):
        frag = {"packets": "1-3", "length": "10-20", "interval": "1-2"}
        cfg = self.tester._make_config(VLESS_REALITY, 20002, {"fragment": frag})
        self.assertEqual(cfg["outbounds"][0]["streamSettings"]["fragment"], frag)

    def test_bad_port_is_ignored(self):
        cfg = self.tester._make_config(VLESS_REALITY, 20002, {"port": 99999})
        self.assertEqual(cfg["outbounds"][0]["settings"]["vnext"][0]["port"], 443)


class TestRknQuorum(unittest.TestCase):
    @staticmethod
    def _results(*oks):
        return [{"ok": ok, "latency": 100.0 if ok else 0.0} for ok in oks]

    def test_any_open_quorum_1(self):
        ok, lat, opened, total = summarize_rkn_results(self._results(True, False, False, False), 1)
        self.assertTrue(ok)
        self.assertEqual(opened, 1)
        self.assertEqual(total, 4)
        self.assertEqual(lat, 100.0)

    def test_quorum_2_not_met(self):
        ok, _, opened, _ = summarize_rkn_results(self._results(True, False, False, False), 2)
        self.assertFalse(ok)
        self.assertEqual(opened, 1)

    def test_quorum_2_met(self):
        ok, _, opened, _ = summarize_rkn_results(self._results(True, True, False, False), 2)
        self.assertTrue(ok)
        self.assertEqual(opened, 2)

    def test_no_results(self):
        ok, lat, opened, total = summarize_rkn_results([], 1)
        self.assertFalse(ok)
        self.assertEqual((lat, opened, total), (0.0, 0, 0))

    def test_best_latency_among_opened(self):
        results = [
            {"ok": True, "latency": 300.0},
            {"ok": True, "latency": 120.0},
            {"ok": False, "latency": 0.0},
        ]
        _, lat, _, _ = summarize_rkn_results(results, 1)
        self.assertEqual(lat, 120.0)

    def test_default_targets_are_4_tuple(self):
        for item in RKN_TARGETS:
            self.assertEqual(len(item), 4)


if __name__ == "__main__":
    unittest.main()

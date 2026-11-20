import unittest

from proxy_skitchen.strategies import (
    candidates_for_failed_entry,
    strategy_label,
    strategy_tooltip,
)


class FakeEntry:
    def __init__(self, uri, protocol="VLESS", port=443, block_type=""):
        self.uri = uri
        self.protocol = protocol
        self.port = port
        self.block_type = block_type


REALITY_TCP = (
    "vless://uuid@host.example:443?security=reality&type=tcp&sni=example.com"
)
REALITY_WS = (
    "vless://uuid@host.example:443?security=reality&type=ws&path=%2Fws"
)


class TestStrategyLabels(unittest.TestCase):
    def test_known_labels_ru(self):
        self.assertEqual(strategy_label("fragment", "ru"), "дробление TLS")
        self.assertEqual(strategy_label("utls_chrome", "ru"), "профиль Chrome")

    def test_known_labels_en(self):
        self.assertEqual(strategy_label("fragment", "en"), "TLS split")
        self.assertEqual(strategy_label("utls_firefox", "en"), "Firefox profile")

    def test_port_label(self):
        self.assertIn("2053", strategy_label("port_2053", "ru"))
        self.assertIn("2053", strategy_label("port_2053", "en"))

    def test_empty(self):
        self.assertEqual(strategy_label("", "ru"), "")

    def test_tooltips_are_human_readable(self):
        for name in ("fragment", "utls_chrome", "utls_firefox"):
            self.assertTrue(strategy_tooltip(name, "ru"))
            self.assertTrue(strategy_tooltip(name, "en"))


class TestFailedEntryCandidates(unittest.TestCase):
    def test_as_is_is_dropped(self):
        cands = candidates_for_failed_entry(FakeEntry(REALITY_TCP))
        self.assertNotIn("as_is", [c.name for c in cands])

    def test_limit_is_respected(self):
        for limit in (1, 2, 3):
            self.assertLessEqual(
                len(candidates_for_failed_entry(FakeEntry(REALITY_TCP), limit=limit)),
                limit,
            )

    def test_current_port_is_not_retried(self):
        entry = FakeEntry(REALITY_TCP, port=443)
        for cand in candidates_for_failed_entry(entry):
            self.assertNotEqual(cand.overrides.get("port"), 443)

    def test_sni_rst_prefers_fragment(self):
        entry = FakeEntry(REALITY_TCP, block_type="sni_rst")
        cands = candidates_for_failed_entry(entry, limit=3)
        self.assertEqual(cands[0].name, "fragment")

    def test_non_empty_for_unknown(self):
        self.assertTrue(candidates_for_failed_entry(FakeEntry(REALITY_WS)))


if __name__ == "__main__":
    unittest.main()

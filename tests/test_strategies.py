import json
import unittest

from proxy_skitchen.strategies import (
    UTLS_FINGERPRINTS,
    StrategyCandidate,
    candidate_strategies,
    strategy_names,
)


class TestCandidateStrategies(unittest.TestCase):
    def test_unknown_returns_non_empty(self):
        self.assertTrue(candidate_strategies("unknown"))

    def test_none_starts_with_as_is(self):
        self.assertEqual(candidate_strategies("none")[0].name, "as_is")

    def test_sni_rst_starts_with_fragment(self):
        cands = candidate_strategies("sni_rst")
        self.assertEqual(cands[0].name, "fragment")
        self.assertTrue(cands[0].overrides.get("fragment"))

    def test_proto_fp_prefers_utls(self):
        cands = candidate_strategies("proto_fp")
        self.assertTrue(cands[0].name.startswith("utls_"))

    def test_ip_block_prefers_port_change(self):
        cands = candidate_strategies("ip_block", server_port=443)
        self.assertTrue(cands[0].name.startswith("port_"))
        self.assertNotEqual(cands[0].overrides.get("port"), 443)

    def test_ip_block_does_not_reuse_same_port(self):
        cands = candidate_strategies("ip_block", server_port=2053)
        ports = {c.overrides.get("port") for c in cands if "port" in c.overrides}
        self.assertNotIn(2053, ports)

    def test_dns_poison_only_as_is(self):
        self.assertEqual(strategy_names(candidate_strategies("dns_poison")), ["as_is"])

    def test_whitelist_has_as_is(self):
        self.assertIn("as_is", strategy_names(candidate_strategies("whitelist")))

    def test_max_candidates_is_respected(self):
        for limit in (1, 2, 3, 4):
            self.assertLessEqual(len(candidate_strategies("sni_rst", max_candidates=limit)), limit)

    def test_no_duplicate_names(self):
        for block in ("sni_rst", "proto_fp", "unknown", "ip_block"):
            names = strategy_names(candidate_strategies(block))
            self.assertEqual(len(names), len(set(names)))

    def test_overrides_are_json_serializable(self):
        for block in ("sni_rst", "proto_fp", "throttle", "unknown", "ip_block"):
            for cand in candidate_strategies(block):
                json.dumps(cand.overrides)

    def test_protocol_args_do_not_break(self):
        for proto in ("VLESS", "VMess", "Trojan", "SS", ""):
            self.assertTrue(candidate_strategies("unknown", protocol=proto))

    def test_utls_values_are_known(self):
        for cand in candidate_strategies("proto_fp"):
            fp = cand.overrides.get("utls")
            if fp:
                self.assertIn(fp, UTLS_FINGERPRINTS)

    def test_dedupe_key_differs_by_name(self):
        a = StrategyCandidate("a", {"utls": "chrome"})
        b = StrategyCandidate("b", {"utls": "chrome"})
        self.assertNotEqual(a.dedupe_key(), b.dedupe_key())


if __name__ == "__main__":
    unittest.main()

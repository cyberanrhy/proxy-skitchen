import unittest
import unittest.mock

from proxy_skitchen.dpi import probe_reason_label
from proxy_skitchen.tester import (
    CONTROL_TARGETS,
    GENERATE_204_TARGET,
    ProbeAttempt,
    ProbeResult,
    ProbeTarget,
    probe_targets_rounds,
    singbox_supports_uri,
    summarize_attempts,
    tcp_probe,
    validate_probe_response,
    verdict_from_probes,
)


class TestValidateProbeResponse(unittest.TestCase):
    def test_204_empty_is_ok(self):
        ok, reason = validate_probe_response(GENERATE_204_TARGET, 204, b"")
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_204_with_body_is_block_page(self):
        ok, reason = validate_probe_response(GENERATE_204_TARGET, 204, b"<html>blocked</html>")
        self.assertFalse(ok)
        self.assertEqual(reason, "204_with_body")

    def test_200_block_page_is_not_ok(self):
        ok, reason = validate_probe_response(GENERATE_204_TARGET, 200, b"<html>ISP block</html>")
        self.assertFalse(ok)
        self.assertEqual(reason, "http_200")

    def test_trace_requires_fields(self):
        target = ProbeTarget("https://cp.cloudflare.com/cdn-cgi/trace", "trace")
        self.assertTrue(validate_probe_response(target, 200, b"ip=1.2.3.4\ncolo=LED\n")[0])
        self.assertFalse(validate_probe_response(target, 200, b"<html>blocked</html>")[0])

    def test_marker_requires_marker_and_size(self):
        target = ProbeTarget("https://github.com", "marker", "github", min_bytes=10)
        self.assertTrue(validate_probe_response(target, 200, b"github is here")[0])
        self.assertFalse(validate_probe_response(target, 200, b"nope")[0])

    def test_control_targets_are_two(self):
        self.assertGreaterEqual(len(CONTROL_TARGETS), 2)


class TestSummarizeAttempts(unittest.TestCase):
    def test_one_of_two_is_enough(self):
        ok, ratio, lat, _ = summarize_attempts([
            ProbeAttempt(True, 204, 100),
            ProbeAttempt(False, 0, 5000, 0, "timeout"),
        ])
        self.assertTrue(ok)
        self.assertEqual(ratio, 0.5)
        self.assertEqual(lat, 100)

    def test_all_failed(self):
        ok, ratio, lat, reason = summarize_attempts([
            ProbeAttempt(False, 0, 5000, 0, "timeout"),
            ProbeAttempt(False, 0, 5000, 0, "timeout"),
        ])
        self.assertFalse(ok)
        self.assertEqual(ratio, 0.0)
        self.assertEqual(lat, 0)
        self.assertEqual(reason, "timeout")

    def test_three_attempts_need_two(self):
        self.assertFalse(summarize_attempts([
            ProbeAttempt(True, 204, 100),
            ProbeAttempt(False, 0, 100, 0, "reset"),
            ProbeAttempt(False, 0, 100, 0, "reset"),
        ])[0])
        self.assertTrue(summarize_attempts([
            ProbeAttempt(True, 204, 100),
            ProbeAttempt(True, 204, 200),
            ProbeAttempt(False, 0, 100, 0, "reset"),
        ])[0])

    def test_median_latency(self):
        _, _, lat, _ = summarize_attempts([
            ProbeAttempt(True, 204, 100),
            ProbeAttempt(True, 204, 300),
            ProbeAttempt(True, 204, 200),
        ])
        self.assertEqual(lat, 200)

    def test_empty(self):
        self.assertEqual(summarize_attempts([]), (False, 0.0, 0.0, "probe_failed"))


class TestVerdictFromProbes(unittest.TestCase):
    def test_any_target_is_enough(self):
        results = [
            ProbeResult(target=CONTROL_TARGETS[0], ok=False, reason="timeout"),
            ProbeResult(target=CONTROL_TARGETS[1], ok=True, latency_ms=250),
        ]
        ok, lat, reason = verdict_from_probes(results)
        self.assertTrue(ok)
        self.assertEqual(lat, 250)
        self.assertEqual(reason, "")

    def test_all_failed(self):
        results = [
            ProbeResult(target=CONTROL_TARGETS[0], ok=False, reason="timeout"),
            ProbeResult(target=CONTROL_TARGETS[1], ok=False, reason="reset"),
        ]
        ok, lat, reason = verdict_from_probes(results)
        self.assertFalse(ok)
        self.assertEqual(lat, 0)
        self.assertIn(reason, ("timeout", "reset"))


class TestProbeRounds(unittest.TestCase):
    def test_first_round_success_stops_early(self):
        calls = []

        def fake(proxy_url, target, timeout):
            calls.append(target.url)
            return ProbeAttempt(True, 204, 100)

        with unittest.mock.patch("proxy_skitchen.tester._single_attempt", side_effect=fake):
            results = probe_targets_rounds(
                "http://127.0.0.1:1", CONTROL_TARGETS[:2], attempts=2, timeout=0.1)
        self.assertEqual(len(calls), 2)  # both targets, one round only
        self.assertTrue(any(r.ok for r in results))

    def test_second_round_rescues_flaky_target(self):
        calls = []
        state = {"n": 0}

        def fake(proxy_url, target, timeout):
            calls.append(target.url)
            state["n"] += 1
            # First round fails, second round succeeds.
            return ProbeAttempt(state["n"] > 2, 204 if state["n"] > 2 else 0, 100)

        with unittest.mock.patch("proxy_skitchen.tester._single_attempt", side_effect=fake):
            results = probe_targets_rounds(
                "http://127.0.0.1:1", CONTROL_TARGETS[:2], attempts=2,
                timeout=0.1, pause=(0, 0))
        self.assertEqual(len(calls), 4)
        self.assertTrue(any(r.ok for r in results))

    def test_dead_proxy_uses_all_rounds(self):
        calls = []

        def fake(proxy_url, target, timeout):
            calls.append(target.url)
            return ProbeAttempt(False, 0, 4000, 0, "timeout")

        with unittest.mock.patch("proxy_skitchen.tester._single_attempt", side_effect=fake):
            results = probe_targets_rounds(
                "http://127.0.0.1:1", CONTROL_TARGETS[:2], attempts=2,
                timeout=0.1, pause=(0, 0))
        self.assertEqual(len(calls), 4)
        self.assertFalse(any(r.ok for r in results))


class TestTcpProbe(unittest.TestCase):
    def test_closed_port_is_unreachable(self):
        ok, _ = tcp_probe("127.0.0.1", 1, timeout=0.3)
        self.assertIs(ok, False)

    def test_unresolvable_dns_is_unknown(self):
        ok, _ = tcp_probe("does-not-exist.invalid", 443, timeout=0.3)
        self.assertIsNone(ok)


class TestEngineSupport(unittest.TestCase):
    def test_xhttp_is_not_supported_by_singbox(self):
        self.assertFalse(singbox_supports_uri(
            "vless://uuid@host:443?security=reality&type=xhttp"))

    def test_tcp_is_supported(self):
        self.assertTrue(singbox_supports_uri(
            "vless://uuid@host:443?security=reality&type=tcp"))


class TestProbeReasonLabel(unittest.TestCase):
    def test_known_reasons(self):
        self.assertIn("таймаут", probe_reason_label("timeout", "ru"))
        self.assertIn("сброшено", probe_reason_label("reset", "ru"))
        self.assertIn("TLS", probe_reason_label("tls_error", "ru"))

    def test_http_reason(self):
        self.assertIn("403", probe_reason_label("http_403", "ru"))

    def test_block_page_reason(self):
        self.assertIn("заглушка", probe_reason_label("204_with_body", "ru"))

    def test_english(self):
        self.assertIn("timeout", probe_reason_label("timeout", "en"))

    def test_empty(self):
        self.assertEqual(probe_reason_label("", "ru"), "")


if __name__ == "__main__":
    unittest.main()

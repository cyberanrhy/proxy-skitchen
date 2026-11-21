import unittest
import unittest.mock
import urllib.error

from PySide6.QtCore import QCoreApplication

from proxy_skitchen import tester
from proxy_skitchen.models import ProxyEntry, _normalize_settings, is_plain_proxy
from proxy_skitchen.workers import TesterWorker

_APP = QCoreApplication.instance() or QCoreApplication([])

VLESS = ("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
         "?security=reality&type=tcp&pbk=x&sid=y&sni=example.com")


def _opener(side_effect):
    opener = unittest.mock.Mock()
    opener.open.side_effect = side_effect
    return opener


class TestHappHead(unittest.TestCase):
    def test_any_http_status_counts_as_alive(self):
        err = urllib.error.HTTPError("https://x", 403, "Forbidden", {}, None)
        with unittest.mock.patch.object(tester.urllib.request, "build_opener",
                                        return_value=_opener(err)):
            ok, _lat, reason = tester.happ_head("http://127.0.0.1:1", timeout=0.1)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_timeout_is_reported(self):
        err = urllib.error.URLError(TimeoutError("timed out"))
        with unittest.mock.patch.object(tester.urllib.request, "build_opener",
                                        return_value=_opener(err)):
            ok, _lat, reason = tester.happ_head("http://127.0.0.1:1", timeout=0.1)
        self.assertFalse(ok)
        self.assertEqual(reason, "timeout")

    def test_reset_is_reported(self):
        err = urllib.error.URLError(ConnectionResetError("reset by peer"))
        with unittest.mock.patch.object(tester.urllib.request, "build_opener",
                                        return_value=_opener(err)):
            ok, _lat, reason = tester.happ_head("http://127.0.0.1:1", timeout=0.1)
        self.assertFalse(ok)
        self.assertEqual(reason, "reset")

    def test_uses_head_and_single_request(self):
        seen = []
        response = unittest.mock.Mock()

        def fake_open(request, timeout):
            seen.append((request.get_method(), timeout))
            return response

        with unittest.mock.patch.object(tester.urllib.request, "build_opener",
                                        return_value=_opener(fake_open)):
            tester.happ_head("http://127.0.0.1:1", timeout=2.5)
        self.assertEqual(seen, [("HEAD", 2.5)])


class TestXrayOutboundSupport(unittest.TestCase):
    def setUp(self):
        self.tester = tester.XrayTester(use_doh=False)

    def test_http_proxy_builds(self):
        cfg = self.tester._make_config("http://user:p%40ss@10.0.0.1:8080", 1234)
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["protocol"], "http")
        server = outbound["settings"]["servers"][0]
        self.assertEqual(server["address"], "10.0.0.1")
        self.assertEqual(server["port"], 8080)
        self.assertEqual(server["users"][0]["user"], "user")
        self.assertEqual(server["users"][0]["pass"], "p@ss")

    def test_http_proxy_without_auth(self):
        cfg = self.tester._make_config("http://10.0.0.1:3128", 1234)
        server = cfg["outbounds"][0]["settings"]["servers"][0]
        self.assertNotIn("users", server)

    def test_socks_proxy_builds(self):
        cfg = self.tester._make_config("socks5://u:p@10.0.0.2:1080", 1234)
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["protocol"], "socks")
        self.assertEqual(outbound["settings"]["servers"][0]["port"], 1080)

    def test_unknown_protocol_is_none(self):
        self.assertIsNone(self.tester._make_config("hy2://x@1.2.3.4:443", 1))


class TestHappWorker(unittest.TestCase):
    def setUp(self):
        self.worker = TesterWorker(check_mode="happ")
        self.entry = ProxyEntry(VLESS)

    def test_mode_normalisation(self):
        self.assertEqual(TesterWorker()._check_mode, "fair")
        self.assertEqual(TesterWorker(check_mode="HAPP")._check_mode, "happ")
        self.assertEqual(TesterWorker(check_mode="bogus")._check_mode, "fair")

    def test_dns_failure_is_dead(self):
        with unittest.mock.patch.object(tester, "tcp_probe", return_value=(None, 0.0)):
            ok, _lat, reason = self.worker._happ_test(self.entry)
        self.assertFalse(ok)
        self.assertEqual(reason, "dns_fail")
        self.assertEqual(self.entry.probe_stages, {"dns": "fail"})

    def test_closed_port_is_dead(self):
        with unittest.mock.patch.object(tester, "tcp_probe", return_value=(False, 0.0)):
            ok, _lat, reason = self.worker._happ_test(self.entry)
        self.assertFalse(ok)
        self.assertEqual(reason, "tcp_unreachable")
        self.assertEqual(self.entry.probe_stages["tcp"], "refused")

    def test_one_head_with_fixed_timeout_and_no_fallback(self):
        core = unittest.mock.Mock()
        core.test_happ.return_value = (True, 120.0, "")
        with unittest.mock.patch.object(tester, "tcp_probe", return_value=(True, 12.0)), \
                unittest.mock.patch.object(tester, "allocate_port", return_value=12345), \
                unittest.mock.patch.object(tester, "release_port"), \
                unittest.mock.patch.object(self.worker, "_get_happ_xr_tester",
                                           return_value=core):
            ok, latency, reason = self.worker._happ_test(self.entry)
        self.assertTrue(ok)
        self.assertEqual(latency, 120.0)
        self.assertEqual(reason, "")
        core.test_happ.assert_called_once_with(
            self.entry.uri, 12345, timeout=tester.HAPP_TIMEOUT)
        self.assertEqual(self.entry.probe_stages["core"], "ok")
        self.assertEqual(self.entry.probe_stages["probe"], "ok")

    def test_unsupported_protocol_marks_core_failure(self):
        core = unittest.mock.Mock()
        core.test_happ.return_value = (False, 0, "unsupported_protocol")
        with unittest.mock.patch.object(tester, "tcp_probe", return_value=(True, 5.0)), \
                unittest.mock.patch.object(tester, "allocate_port", return_value=1), \
                unittest.mock.patch.object(tester, "release_port"), \
                unittest.mock.patch.object(self.worker, "_get_happ_xr_tester",
                                           return_value=core):
            ok, _lat, reason = self.worker._happ_test(self.entry)
        self.assertFalse(ok)
        self.assertEqual(reason, "unsupported_protocol")
        self.assertEqual(self.entry.probe_stages["core"], "fail")
        self.assertEqual(self.entry.probe_stages["probe"], "n/a")

    def test_udp_protocol_uses_singbox(self):
        entry = ProxyEntry("hy2://pass@1.2.3.4:443?sni=example.com")
        sb = unittest.mock.Mock()
        sb.test_happ.return_value = (True, 90.0, "")
        with unittest.mock.patch.object(tester, "allocate_port", return_value=2), \
                unittest.mock.patch.object(tester, "release_port"), \
                unittest.mock.patch.object(self.worker, "_get_happ_sb_tester",
                                           return_value=sb):
            ok, _lat, _reason = self.worker._happ_test(entry)
        self.assertTrue(ok)
        sb.test_happ.assert_called_once()

    def test_fair_mode_does_not_use_happ_path(self):
        with unittest.mock.patch.object(self.worker, "_happ_test") as happ:
            worker = TesterWorker(check_mode="fair")
            with unittest.mock.patch.object(worker, "_happ_test") as fair_happ, \
                    unittest.mock.patch.object(tester, "tcp_probe",
                                               return_value=(True, 10.0)):
                sb = unittest.mock.Mock()
                sb.test.return_value = (True, 50.0, "")
                with unittest.mock.patch.object(worker, "_get_sb_tester",
                                                return_value=sb), \
                        unittest.mock.patch.object(tester, "allocate_port",
                                                   return_value=3), \
                        unittest.mock.patch.object(tester, "release_port"):
                    ok, _lat, _reason = worker._deep_test(self.entry)
        self.assertTrue(ok)
        fair_happ.assert_not_called()
        happ.assert_not_called()


class TestPlainProxyFilter(unittest.TestCase):
    def test_plain_protocols(self):
        for proto in ("HTTP", "HTTPS", "SOCKS", "SOCKS4", "SOCKS5", "http", "socks5"):
            self.assertTrue(is_plain_proxy(proto), proto)

    def test_plain_uris(self):
        self.assertTrue(is_plain_proxy("http://1.2.3.4:8080"))
        self.assertTrue(is_plain_proxy("socks5://u:p@1.2.3.4:1080"))

    def test_encrypted_protocols_are_kept(self):
        for proto in ("VLESS", "VMESS", "TROJAN", "SS", "HY2", "TUIC"):
            self.assertFalse(is_plain_proxy(proto), proto)


class TestExportFilter(unittest.TestCase):
    def test_plain_proxy_is_not_exported(self):
        from proxy_skitchen.exporters import _is_valid_entry
        self.assertFalse(_is_valid_entry(ProxyEntry("http://45.194.3.119:8080")))
        self.assertFalse(_is_valid_entry(ProxyEntry("socks5://1.2.3.4:1080")))

    def test_encrypted_node_is_still_exported(self):
        from proxy_skitchen.exporters import _is_valid_entry
        self.assertTrue(_is_valid_entry(ProxyEntry(VLESS)))
        self.assertTrue(_is_valid_entry(ProxyEntry(
            "trojan://secret@1.2.3.4:443?sni=example.com")))


class TestCheckModeSetting(unittest.TestCase):
    def test_default_is_fair(self):
        self.assertEqual(_normalize_settings({})["check_mode"], "fair")

    def test_happ_is_kept(self):
        self.assertEqual(_normalize_settings({"check_mode": "happ"})["check_mode"], "happ")

    def test_garbage_falls_back_to_fair(self):
        self.assertEqual(_normalize_settings({"check_mode": "nope"})["check_mode"], "fair")


if __name__ == "__main__":
    unittest.main()

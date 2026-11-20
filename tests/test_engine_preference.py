import unittest

from proxy_skitchen.tester import core_error_text, prefer_xray, uri_query_param

BASE = "vless://uuid@host.example:443"


def uri(query):
    return f"{BASE}?{query}"


class TestUriQueryParam(unittest.TestCase):
    def test_reads_value(self):
        self.assertEqual(uri_query_param(uri("type=grpc&security=reality"), "type"), "grpc")

    def test_ignores_fragment(self):
        self.assertEqual(uri_query_param(uri("type=ws#name?x=1"), "type"), "ws")

    def test_missing_returns_default(self):
        self.assertEqual(uri_query_param(uri("type=ws"), "security", "none"), "none")


class TestPreferXray(unittest.TestCase):
    def test_reality_tcp(self):
        self.assertTrue(prefer_xray(uri("security=reality&type=tcp")))

    def test_reality_default_transport_is_tcp(self):
        self.assertTrue(prefer_xray(uri("security=reality")))

    def test_reality_grpc(self):
        self.assertTrue(prefer_xray(uri("security=reality&type=grpc")))

    def test_reality_xhttp(self):
        self.assertTrue(prefer_xray(uri("security=reality&type=xhttp")))

    def test_reality_raw(self):
        self.assertTrue(prefer_xray(uri("security=reality&type=raw")))

    def test_reality_ws_goes_to_singbox(self):
        self.assertFalse(prefer_xray(uri("security=reality&type=ws")))
        self.assertFalse(prefer_xray(uri("security=reality&type=websocket")))

    def test_tls_ws_does_not_use_xray(self):
        self.assertFalse(prefer_xray(uri("security=tls&type=ws")))

    def test_non_vless_does_not_use_xray(self):
        self.assertFalse(prefer_xray("trojan://pass@host.example:443?security=reality&type=tcp"))


class TestCoreErrorText(unittest.TestCase):
    def test_xray_banner_is_skipped(self):
        stdout = (
            b"Xray 26.3.27 (Xray, Penetrates Everything.)\n"
            b"A unified platform for anti-censorship.\n"
            b"Failed to start: main: failed to load config files\n"
        )
        text = core_error_text(stdout, b"")
        self.assertIn("Failed to start", text)
        self.assertNotIn("Xray 26", text)

    def test_ansi_is_stripped(self):
        stderr = b"\x1b[31mFATAL\x1b[0m[0000] decode config: unknown transport type: xhttp\n"
        text = core_error_text(None, stderr)
        self.assertIn("unknown transport type: xhttp", text)
        self.assertNotIn("\x1b", text)

    def test_stderr_wins(self):
        text = core_error_text(b"stdout noise", b"fatal: bad key")
        self.assertEqual(text, "fatal: bad key")

    def test_empty_output(self):
        self.assertEqual(core_error_text(None, None), "")
        self.assertEqual(core_error_text(b"", b""), "")

    def test_limit(self):
        text = core_error_text(None, b"error " + b"x" * 500, limit=20)
        self.assertEqual(len(text), 20)


if __name__ == "__main__":
    unittest.main()

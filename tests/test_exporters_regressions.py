import base64
import unittest

from proxy_skitchen import tester
from proxy_skitchen.exporters import (
    _extract_ss_cipher,
    _extract_ss_pass,
    _entry_to_outbound,
    _is_valid_entry,
    format_clash,
)
from proxy_skitchen.models import ProxyEntry


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class TestShadowsocksFormats(unittest.TestCase):
    """SIP002 (plain/base64 userinfo) and legacy base64 payloads must all parse."""

    def _assert_entry(self, uri: str, method: str, password: str):
        e = ProxyEntry(uri)
        self.assertEqual(e.protocol, "SS")
        self.assertEqual(e.host, "example.com")
        self.assertEqual(e.port, 8388)
        self.assertEqual(_extract_ss_cipher(e.uri), method)
        self.assertEqual(_extract_ss_pass(e.uri), password)
        self.assertTrue(_is_valid_entry(e))
        return e

    def test_sip002_base64_userinfo(self):
        self._assert_entry(
            "ss://" + _b64("aes-256-gcm:secretpass") + "@example.com:8388#node",
            "aes-256-gcm", "secretpass")

    def test_sip002_plaintext_userinfo(self):
        self._assert_entry(
            "ss://aes-256-gcm:secretpass@example.com:8388#node",
            "aes-256-gcm", "secretpass")

    def test_sip002_percent_encoded_password(self):
        self._assert_entry(
            "ss://aes-256-gcm:p%40ss%3Aword@example.com:8388",
            "aes-256-gcm", "p@ss:word")

    def test_sip002_urlsafe_userinfo(self):
        encoded = base64.urlsafe_b64encode(b"aes-256-gcm:secretpass").decode()
        self._assert_entry(f"ss://{encoded}@example.com:8388", "aes-256-gcm", "secretpass")

    def test_legacy_base64_payload(self):
        self._assert_entry(
            "ss://" + _b64("aes-256-gcm:secretpass@example.com:8388") + "#node",
            "aes-256-gcm", "secretpass")

    def test_singbox_outbound_carries_method_and_password(self):
        e = ProxyEntry("ss://" + _b64("aes-256-gcm:secretpass") + "@example.com:8388")
        out = _entry_to_outbound(e)
        self.assertEqual(out["type"], "shadowsocks")
        self.assertEqual(out["method"], "aes-256-gcm")
        self.assertEqual(out["password"], "secretpass")

    def test_tester_parses_sip002_plaintext(self):
        out = tester.SingBoxTester()._parse_ss(
            "ss://aes-256-gcm:secretpass@example.com:8388")
        self.assertEqual(out["method"], "aes-256-gcm")
        self.assertEqual(out["password"], "secretpass")
        self.assertEqual(out["server"], "example.com")
        self.assertEqual(out["server_port"], 8388)

    def test_tester_parses_sip002_base64(self):
        out = tester.SingBoxTester()._parse_ss(
            "ss://" + _b64("aes-256-gcm:secretpass") + "@example.com:8388")
        self.assertEqual(out["method"], "aes-256-gcm")
        self.assertEqual(out["password"], "secretpass")


class TestHy2Outbound(unittest.TestCase):
    def test_hy2_alias_uses_singbox_hysteria2_type(self):
        out = _entry_to_outbound(ProxyEntry("hy2://pw@example.com:443?sni=example.com"))
        self.assertEqual(out["type"], "hysteria2")


class TestClashQuoting(unittest.TestCase):
    def test_password_with_yaml_breaking_chars(self):
        e = ProxyEntry("hysteria2://pa%3A%20ss@example.com:443?sni=example.com")
        text = format_clash([e], include_failed=True)
        self.assertIn('password: "pa: ss"', text)
        try:
            import yaml
        except ImportError:
            return
        parsed = yaml.safe_load(text)
        self.assertEqual(parsed["proxies"][0]["password"], "pa: ss")

    def test_ws_path_and_host_are_quoted(self):
        e = ProxyEntry(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com")
        text = format_clash([e], include_failed=True)
        self.assertIn('path: "/ws?ed=2048"', text)
        self.assertIn('"Host": "cdn.example.com"', text)


if __name__ == "__main__":
    unittest.main()

import base64
import json
import unittest

from proxy_skitchen import tester
from proxy_skitchen.exporters import format_clash, validate_content
from proxy_skitchen.models import ProxyEntry
from proxy_skitchen.parsers import get_server_port

VLESS = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
         "?security=tls&type=ws#Germany")
VLESS_OTHER = ("vless://99999999-2222-3333-4444-555555555555@example.com:443"
               "?security=tls&type=ws#Germany")


class _FakeProc:
    def __init__(self):
        self.killed = False
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def kill(self):
        self.killed = True
        self._alive = False


class TestProcGuard(unittest.TestCase):
    def test_kill_all_is_worker_scoped(self):
        g1, g2 = tester.ProcGuard(), tester.ProcGuard()
        p1, p2 = _FakeProc(), _FakeProc()
        g1.add(p1)
        g2.add(p2)
        g1.kill_all()
        self.assertTrue(p1.killed)
        self.assertFalse(p2.killed)

    def test_add_after_close_kills_immediately(self):
        guard = tester.ProcGuard()
        guard.kill_all()
        proc = _FakeProc()
        guard.add(proc)
        self.assertTrue(proc.killed)

    def test_discard_removes_from_guard(self):
        guard = tester.ProcGuard()
        proc = _FakeProc()
        guard.add(proc)
        guard.discard(proc)
        guard.kill_all()
        self.assertFalse(proc.killed)


class TestNodeIdentity(unittest.TestCase):
    def test_same_endpoint_different_uuid_kept(self):
        a, b = ProxyEntry(VLESS), ProxyEntry(VLESS_OTHER)
        self.assertNotEqual(a.key(), b.key())

    def test_clean_uri_strips_remark_display_keeps_it(self):
        e = ProxyEntry(VLESS)
        self.assertNotIn("#", e.clean_uri())
        self.assertTrue(e.display_uri(clean=False).endswith("#Germany"))


class TestGetServerPort(unittest.TestCase):
    def test_legacy_shadowsocks_base64_payload(self):
        uri = "ss://" + base64.b64encode(
            b"aes-256-gcm:secretpass@example.com:8388").decode()
        self.assertEqual(get_server_port(uri), ("example.com", 8388))


class TestValidateContent(unittest.TestCase):
    def test_clash_valid_config_counts(self):
        valid, broken = validate_content(
            format_clash([ProxyEntry(VLESS)], include_failed=True), "clash")
        self.assertEqual(valid, 1)
        self.assertEqual(broken, 0)

    def test_clash_broken_yaml_is_reported(self):
        valid, broken = validate_content(
            "proxies:\n  - name: x\n    password: pa: ss\n", "clash")
        self.assertEqual(valid, 0)
        self.assertGreaterEqual(broken, 1)

    def test_singbox_unknown_outbound_type_is_broken(self):
        cfg = {"outbounds": [{"type": "hy2", "server": "e.com", "server_port": 443}]}
        valid, broken = validate_content(json.dumps(cfg), "singbox")
        self.assertEqual(valid, 0)
        self.assertEqual(broken, 1)


if __name__ == "__main__":
    unittest.main()

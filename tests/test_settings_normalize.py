import unittest

from proxy_skitchen.models import _normalize_settings


class TestSettingsNormalize(unittest.TestCase):
    def test_rkn_quorum_from_string(self):
        self.assertEqual(_normalize_settings({"rkn_quorum": "3"})["rkn_quorum"], 3)

    def test_rkn_quorum_clamped(self):
        self.assertEqual(_normalize_settings({"rkn_quorum": 0})["rkn_quorum"], 1)
        self.assertEqual(_normalize_settings({"rkn_quorum": 99})["rkn_quorum"], 4)

    def test_rkn_quorum_default(self):
        self.assertEqual(_normalize_settings({})["rkn_quorum"], 1)

    def test_rkn_quorum_garbage(self):
        self.assertEqual(_normalize_settings({"rkn_quorum": "abc"})["rkn_quorum"], 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from proxy_skitchen.workers import geo_candidates


class FakeEntry:
    def __init__(self, host, deep_ok=False, rkn_ok=False, country=""):
        self.host = host
        self.deep_ok = deep_ok
        self.rkn_ok = rkn_ok
        self.country = country


class TestGeoCandidates(unittest.TestCase):
    def test_deep_ok_ip_is_selected(self):
        e = FakeEntry("1.2.3.4", deep_ok=True)
        self.assertEqual([i for i, _ in geo_candidates([e])], [0])

    def test_rkn_ok_ip_is_selected(self):
        # Regression: standalone RKN runs never set deep_ok.
        e = FakeEntry("1.2.3.4", rkn_ok=True)
        self.assertEqual([i for i, _ in geo_candidates([e])], [0])

    def test_dead_entry_is_skipped(self):
        e = FakeEntry("1.2.3.4")
        self.assertEqual(geo_candidates([e]), [])

    def test_domain_is_skipped(self):
        e = FakeEntry("example.com", rkn_ok=True)
        self.assertEqual(geo_candidates([e]), [])

    def test_known_country_is_skipped(self):
        e = FakeEntry("1.2.3.4", rkn_ok=True, country="Germany")
        self.assertEqual(geo_candidates([e]), [])

    def test_indices_preserved(self):
        entries = [
            FakeEntry("10.0.0.1"),
            FakeEntry("10.0.0.2", rkn_ok=True),
            FakeEntry("10.0.0.3", deep_ok=True),
        ]
        self.assertEqual([i for i, _ in geo_candidates(entries)], [1, 2])

    def test_rkn_mode_flag_does_not_change_selection(self):
        e = FakeEntry("1.2.3.4", rkn_ok=True)
        self.assertEqual(len(geo_candidates([e], rkn_mode=True)), 1)
        self.assertEqual(len(geo_candidates([e], rkn_mode=False)), 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from PySide6.QtCore import QCoreApplication

from proxy_skitchen.workers import StrategyWorker, TesterWorker

_APP = QCoreApplication.instance() or QCoreApplication([])


class TestTesterWorkerOptions(unittest.TestCase):
    def test_quorum_is_stored(self):
        self.assertEqual(TesterWorker(rkn_quorum=3)._rkn_quorum, 3)

    def test_quorum_is_clamped(self):
        self.assertEqual(TesterWorker(rkn_quorum=0)._rkn_quorum, 1)
        self.assertEqual(TesterWorker(rkn_quorum=-5)._rkn_quorum, 1)

    def test_default_quorum(self):
        self.assertEqual(TesterWorker()._rkn_quorum, 1)


class TestStrategyWorker(unittest.TestCase):
    def test_candidate_limit_is_clamped(self):
        w = StrategyWorker([], max_candidates=0)
        self.assertEqual(w._max_candidates, 1)

    def test_stop_sets_flag(self):
        w = StrategyWorker([])
        w.stop()
        self.assertTrue(w._stop)


if __name__ == "__main__":
    unittest.main()

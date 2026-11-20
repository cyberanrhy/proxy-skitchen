import unittest
from pathlib import Path

import proxy_skitchen.ui as ui


class TestThreadingContract(unittest.TestCase):
    """Guards against GUI-updating lambdas connected to worker signals.

    In PySide6 a lambda without a QObject receiver runs in the *emitting*
    (worker) thread, which crashes Qt widgets. Worker signals must be connected
    to bound methods of the page (a QObject) so delivery is queued to the GUI.
    """

    def setUp(self):
        self.src = Path(ui.__file__).read_text(encoding="utf-8", errors="replace")

    def test_no_lambda_for_network_worker(self):
        for signal in ("proxy_parsed", "source_started", "source_status",
                       "progress_signal", "finished"):
            self.assertNotIn(f"_net_worker.{signal}.connect(lambda", self.src)

    def test_no_lambda_for_tester(self):
        for signal in ("result_signal", "testing_signal", "progress_signal",
                       "count_signal", "geo_signal", "finished"):
            self.assertNotIn(f"_tester.{signal}.connect(lambda", self.src)

    def test_no_lambda_for_strategy_worker(self):
        for signal in ("trial_signal", "found_signal", "failed_signal", "finished"):
            self.assertNotIn(f"worker.{signal}.connect(lambda", self.src)

    def test_worker_signals_are_bound_methods(self):
        self.assertIn("self._net_worker.proxy_parsed.connect(self._on_proxy_parsed)",
                      self.src)
        self.assertIn("self._tester.result_signal.connect(self._on_test_result)",
                      self.src)

    def test_network_starter_captures_local_worker(self):
        self.assertIn("net_worker = self._net_worker", self.src)
        self.assertIn("net_worker.fetch_all(sources)", self.src)

    def test_github_push_worker_does_not_touch_gui_or_settings(self):
        start = self.src.index("def _do_github_push")
        end = self.src.index("def _on_filter_change", start)
        body = self.src[start:end]
        self.assertNotIn("_settings_data[", body)
        self.assertNotIn("_save_settings(", body)
        self.assertNotIn("self._log(", body)

    def test_no_single_slot_gh_zombie(self):
        self.assertNotIn("_gh_zombie", self.src)


if __name__ == "__main__":
    unittest.main()

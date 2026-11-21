import unittest

from proxy_skitchen.ui import close_action


class TestCloseAction(unittest.TestCase):
    def test_without_tray_the_app_quits(self):
        # Hiding without a working tray icon leaves an unreachable process.
        self.assertEqual(close_action(False), "quit")

    def test_with_tray_the_app_hides(self):
        self.assertEqual(close_action(True), "tray")


if __name__ == "__main__":
    unittest.main()

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from proxy_skitchen.i18n import current_lang
from proxy_skitchen.models import ProxyEntry, ProxyTableModel
from proxy_skitchen.strategies import strategy_label

_APP = QApplication.instance() or QApplication([])

VLESS = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws#n"


class TestProxyTableModel(unittest.TestCase):
    def setUp(self):
        self.model = ProxyTableModel()
        self.entry = ProxyEntry(VLESS)
        self.model.add_proxies([self.entry])

    def test_column_count_includes_bypass(self):
        self.assertEqual(self.model.columnCount(), 7)

    def test_header_is_present(self):
        header = self.model.headerData(6, Qt.Orientation.Horizontal)
        self.assertTrue(header)

    def test_strategy_is_displayed(self):
        self.entry.strategy_name = "fragment"
        text = self.model.data(self.model.index(0, 6))
        self.assertEqual(text, strategy_label("fragment", current_lang()))

    def test_empty_strategy_cell(self):
        self.assertEqual(self.model.data(self.model.index(0, 6)), "")

    def test_status_marks_bypass(self):
        self.entry.strategy_name = "utls_chrome"
        self.assertIn("🛠", self.model.data(self.model.index(0, 0)))

    def test_tooltip_mentions_bypass(self):
        self.entry.strategy_name = "fragment"
        tip = self.model.data(self.model.index(0, 6), Qt.ItemDataRole.ToolTipRole)
        self.assertIn(strategy_label("fragment", current_lang()), tip)

    def test_headers_retranslate(self):
        import proxy_skitchen.i18n as i18n
        old = i18n._lang
        try:
            i18n._lang = "en"
            self.model.rebuild_headers()
            self.assertEqual(self.model.headerData(6, Qt.Orientation.Horizontal), "Bypass")
            i18n._lang = "ru"
            self.model.rebuild_headers()
            self.assertEqual(self.model.headerData(6, Qt.Orientation.Horizontal), "Обход")
        finally:
            i18n._lang = old


if __name__ == "__main__":
    unittest.main()

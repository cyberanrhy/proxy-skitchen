import sys
from .compat import QSystemTrayIcon, QIcon, QApplication

_tray = None

def _get_tray():
    global _tray
    if _tray is not None:
        return _tray
    app = QApplication.instance()
    if app is None:
        return None
    if not QSystemTrayIcon.isSystemTrayAvailable():
        return None
    _tray = QSystemTrayIcon(QIcon(), app)
    _tray.setVisible(True)
    return _tray

def notify(title: str, message: str, duration_ms: int = 5000):
    tray = _get_tray()
    if tray is None:
        return
    tray.showMessage(title, message, QSystemTrayIcon.Information, duration_ms)

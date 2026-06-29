import os, sys, json, re, time, socket, base64, struct, concurrent.futures, subprocess, traceback, faulthandler, functools, urllib.request, urllib.parse, http.server, email.utils, itertools, html, platform
from datetime import datetime
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

try:
    from PySide6.QtCore import (
        Qt, Signal, QObject, QThread, QTimer, Slot, QUrl, QCoreApplication,
        QSortFilterProxyModel, QEventLoop, QPropertyAnimation, QEasingCurve,
        QAbstractTableModel, QModelIndex,
    )
    from PySide6.QtGui import QFont, QColor, QBrush, QDesktopServices, QAction, QIcon, QPalette
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
        QSplitter, QTabWidget, QTableView, QTableWidget, QTableWidgetItem,
        QTreeWidget, QTreeWidgetItem, QListWidget, QListWidgetItem,
        QLabel, QLineEdit, QTextEdit, QPlainTextEdit, QPushButton, QCheckBox, QComboBox, QSpinBox,
        QGroupBox, QRadioButton, QButtonGroup, QDialog, QDialogButtonBox, QMessageBox, QProgressBar,
        QHeaderView, QAbstractItemView, QMenu, QFileDialog, QInputDialog, QStatusBar, QToolBar,
        QToolButton, QFrame, QScrollArea, QSizePolicy, QSystemTrayIcon, QStackedWidget,
    )
    from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
    _QT6 = True
    _QT5 = False
except ImportError:
    from PySide2.QtCore import (
        Qt, Signal, QObject, QThread, QTimer, Slot, QUrl, QCoreApplication,
        QSortFilterProxyModel, QEventLoop, QPropertyAnimation, QEasingCurve,
        QAbstractTableModel, QModelIndex,
    )
    from PySide2.QtGui import QFont, QColor, QBrush, QDesktopServices, QAction, QIcon, QPalette
    from PySide2.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
        QSplitter, QTabWidget, QTableView, QTableWidget, QTableWidgetItem,
        QTreeWidget, QTreeWidgetItem, QListWidget, QListWidgetItem,
        QLabel, QLineEdit, QTextEdit, QPlainTextEdit, QPushButton, QCheckBox, QComboBox, QSpinBox,
        QGroupBox, QRadioButton, QButtonGroup, QDialog, QDialogButtonBox, QMessageBox, QProgressBar,
        QHeaderView, QAbstractItemView, QMenu, QFileDialog, QInputDialog, QStatusBar, QToolBar,
        QToolButton, QFrame, QScrollArea, QSizePolicy, QSystemTrayIcon, QStackedWidget,
    )
    from PySide2.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
    _QT6 = False
    _QT5 = True

if IS_WINDOWS:
    SETTINGS_DIR = os.path.join(os.path.expandvars("%APPDATA%"), "proxy-skitchen")
else:
    SETTINGS_DIR = os.path.expanduser("~/.config/proxy-skitchen")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")
AUTH_FILE = os.path.join(SETTINGS_DIR, "auth.json")

if IS_WINDOWS:
    VPN_DIR = os.path.join(os.path.expandvars("%LOCALAPPDATA%"), "proxy-skitchen", "vpn")
elif IS_MACOS:
    VPN_DIR = os.path.expanduser("~/Library/Application Support/proxy-skitchen/vpn")
else:
    VPN_DIR = os.path.expanduser("~/.local/share/proxy-skitchen/vpn")

OUT_DIR = os.path.join(VPN_DIR, "tested")

if IS_WINDOWS:
    TMP_DIR = os.path.join(os.path.expandvars("%TEMP%"), "proxy-skitchen")
else:
    TMP_DIR = "/tmp/proxy-skitchen"

HIDDIFY_PROXY = "http://127.0.0.1:12334"

if IS_WINDOWS:
    DESKTOP_DIR = os.path.join(os.path.expandvars("%USERPROFILE%"), "Desktop")
elif IS_MACOS:
    DESKTOP_DIR = os.path.expanduser("~/Desktop")
else:
    DESKTOP_DIR = next((p for p in [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Рабочий стол"),
    ] if os.path.isdir(p)), os.path.expanduser("~"))

APP_NAME = "proxy-skitchen"
APP_VERSION = "2.2.0"

_LOG_LIMIT = 1024 * 1024       # 1 MB max
_LOG_KEEP = 768 * 1024         # keep ~768 KB after truncation

def _write_log(path: str, msg: str):
    """Write to a debug log with built-in size limit."""
    try:
        if os.path.exists(path) and os.path.getsize(path) > _LOG_LIMIT:
            with open(path, "r") as f:
                data = f.read()
            tail = data[-_LOG_KEEP:]
            with open(path, "w") as f:
                f.write(tail)
        with open(path, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass

DEBUG_LOG_PATHS: list[str] = []

os.makedirs(SETTINGS_DIR, exist_ok=True)
os.makedirs(VPN_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

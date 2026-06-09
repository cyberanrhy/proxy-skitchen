import os, sys, json, re, time, socket, base64, struct, concurrent.futures, subprocess, traceback, faulthandler, functools, urllib.request, urllib.parse, http.server, email.utils, itertools, html, tempfile, shutil
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    _CONFIG_ROOT = os.environ.get("APPDATA", os.path.expanduser("~"))
    _DATA_ROOT = os.environ.get("APPDATA", os.path.expanduser("~"))
    SEP = ";"
else:
    _CONFIG_ROOT = os.path.expanduser("~/.config")
    _DATA_ROOT = os.path.expanduser("~/.local/share")
    SEP = ":"

SETTINGS_DIR = os.path.join(_CONFIG_ROOT, "proxy-fetcher")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")
AUTH_FILE = os.path.join(SETTINGS_DIR, "auth.json")
VPN_DIR = os.path.join(_DATA_ROOT, "proxy-fetcher", "vpn")
OUT_DIR = os.path.join(VPN_DIR, "tested")
TMP_DIR = os.path.join(tempfile.gettempdir(), "proxy-fetcher")
HIDDIFY_PROXY = "http://127.0.0.1:12334"
DESKTOP_DIR = next((p for p in [
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.expanduser("~/Рабочий стол"),
    os.path.expanduser("~/Escritorio"),
    os.path.expanduser("~/桌面"),
] if os.path.isdir(p)), os.path.expanduser("~"))
FORK_NAME = "proxy-skitchen"
FORK_VERSION = "2.1.0"
DEVNULL = os.devnull

os.makedirs(SETTINGS_DIR, exist_ok=True)
os.makedirs(VPN_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

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

import os, sys, json, re, time, socket, base64, struct, concurrent.futures, subprocess, traceback, faulthandler, functools, urllib.request, urllib.parse, http.server, email.utils, itertools, html
from pathlib import Path

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

SETTINGS_DIR = os.path.expanduser("~/.config/proxy-fetcher")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")
AUTH_FILE = os.path.join(SETTINGS_DIR, "auth.json")
VPN_DIR = os.path.expanduser("~/.local/share/proxy-fetcher/vpn")
OUT_DIR = os.path.join(VPN_DIR, "tested")
TMP_DIR = "/tmp/proxy-fetcher"
HIDDIFY_PROXY = "http://127.0.0.1:12334"
DESKTOP_DIR = os.path.expanduser("~/Рабочий стол")
FORK_NAME = "proxy-skitchen"
FORK_VERSION = "2.1.0"

os.makedirs(SETTINGS_DIR, exist_ok=True)
os.makedirs(VPN_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)

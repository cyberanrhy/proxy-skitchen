"""Single-instance guard.

A second launch must not spawn another invisible copy of the app: it should
bring the existing window to the front and exit.  A local socket is used as
both the lock and the activation channel, so a crashed process never leaves a
dead lock behind (Windows named pipes are kernel objects).
"""

import getpass
import hashlib
import os
import time

from .compat import IS_WINDOWS, QObject, Signal, QLocalServer, QLocalSocket
from .compat import _write_log, TMP_DIR

_LOG = os.path.join(TMP_DIR, "single-instance.log")


def _log(msg: str):
    _write_log(_LOG, msg)


def instance_name(prefix: str = "proxy-skitchen") -> str:
    """Per-user server name; avoids collisions on shared machines."""
    user = ""
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    digest = hashlib.sha1(user.encode("utf-8", "replace")).hexdigest()[:8]
    return f"{prefix}-{digest}"


class SingleInstance(QObject):
    """Owns the local server that marks this process as the primary one."""

    activated = Signal()

    def __init__(self, name: str | None = None, parent=None):
        super().__init__(parent)
        self._name = name or instance_name()
        self._server = None
        self._mutex = None

    @property
    def name(self) -> str:
        return self._name

    def _acquire_mutex(self) -> bool:
        """Windows: a named mutex is the real lock.

        QLocalServer alone is not enough there -- Windows named pipes accept
        several listeners with the same name, so ``listen()`` succeeds twice.
        """
        if not IS_WINDOWS:
            return True
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.CreateMutexW(None, False, f"Local\\{self._name}")
            last_error = ctypes.get_last_error()
            if not handle:
                return False
            if last_error == 183:  # ERROR_ALREADY_EXISTS
                kernel32.CloseHandle(handle)
                return False
            self._mutex = (kernel32, handle)
            return True
        except Exception as exc:
            _log(f"mutex error: {exc}")
            return True  # fall back to the socket check

    def _release_mutex(self):
        if self._mutex is None:
            return
        kernel32, handle = self._mutex
        self._mutex = None
        try:
            kernel32.CloseHandle(handle)
        except Exception:
            pass

    def acquire(self) -> bool:
        """Try to become the primary instance.  Idempotent."""
        if self._server is not None:
            return True
        if not self._acquire_mutex():
            _log(f"acquire failed (mutex): {self._name}")
            return False
        server = QLocalServer(self)
        if not server.listen(self._name):
            # A stale Unix socket from a killed process blocks listen().
            QLocalServer.removeServer(self._name)
            if not server.listen(self._name):
                _log(f"acquire failed: {self._name} {server.errorString()}")
                server.deleteLater()
                self._release_mutex()
                return False
        server.newConnection.connect(self._on_new_connection)
        self._server = server
        _log(f"acquired: {self._name}")
        return True

    def release(self):
        if self._server is not None:
            self._server.close()
            QLocalServer.removeServer(self._name)
            self._server.deleteLater()
            self._server = None
        self._release_mutex()

    def _on_new_connection(self):
        while self._server is not None and self._server.hasPendingConnections():
            conn = self._server.nextPendingConnection()
            try:
                conn.disconnectFromServer()
            except Exception:
                pass
            conn.deleteLater()
        self.activated.emit()


def activate_existing(name: str | None = None, timeout_ms: int = 2000) -> bool:
    """Ask a running instance to show its window.  True if it answered."""
    name = name or instance_name()
    deadline = time.monotonic() + max(0.1, timeout_ms / 1000.0)
    while True:
        sock = QLocalSocket()
        sock.connectToServer(name)
        if sock.waitForConnected(250):
            try:
                sock.write(b"activate")
                sock.flush()
                sock.waitForBytesWritten(250)
            except Exception:
                pass
            sock.disconnectFromServer()
            sock.deleteLater()
            _log(f"activated existing: {name}")
            return True
        sock.deleteLater()
        if time.monotonic() >= deadline:
            _log(f"no running instance answered: {name}")
            return False
        time.sleep(0.1)

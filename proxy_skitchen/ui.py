import os, sys, json, re, threading, time, base64, urllib.request
from datetime import datetime
from .compat import TMP_DIR

_DEBUG_LOG = os.path.join(TMP_DIR, "debug-ui.log")

def _debug(msg: str):
    if _DEBUG_LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(_DEBUG_LOG)
    _write_log(_DEBUG_LOG, msg)

from .compat import *
from .compat import _write_log, DEBUG_LOG_PATHS
from .models import ProxyEntry, ProxyTableModel, _auth_data, _settings_data, _save_auth, _load_auth, _save_settings, _load_settings, PERF_PRESETS, THEMES, current_theme, set_theme, country_flag, _get_tokens, is_plain_proxy
from .parsers import is_proxy_uri, extract_uris, get_server_port, get_protocol
from .exporters import format_raw, format_v2rayn, format_singbox, format_clash, format_hiddify, format_amnezia, smart_name, _country_to_code, _is_valid_entry, _entry_ok, _clean_uri, wireguard_conf_from_entry, validate_content, DEFAULT_DOH
from .workers import NetworkWorker, TesterWorker, GitHubSearchWorker, StrategyWorker
from .i18n import _, LANGUAGES, current_lang, set_lang
from .strategies import strategy_label, strategy_tooltip

try:
    import subprocess
    DESKTOP_DIR = subprocess.check_output(["xdg-user-dir", "DESKTOP"], text=True).strip()
    if not os.path.isdir(DESKTOP_DIR):
        raise OSError
except Exception:
    DESKTOP_DIR = next((p for p in [
        os.path.expanduser("~/Рабочий стол"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Escritorio"),
        os.path.expanduser("~/桌面"),
    ] if os.path.isdir(p)), os.path.expanduser("~"))


ROS_TUNNEL_STD = [
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/22.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/23.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/24.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/25.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://shadowmere.xyz/api/b64sub/",
    "https://shadowmere.xyz/api/sub/",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR#MEGA.STR.BYPASS??",
    "https://raw.githubusercontent.com/Egkaz/Proxy-list-20k-server/refs/heads/main/stable.txt",
    "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/other",
]
ROS_TUNNEL_WL = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://fsub.flux.2bd.net/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/bywarm/whitelists-vpns-etc/refs/heads/main/whitelists1-4pda.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
    "https://bp.wl.free.nf/confs/selected.txt",
    "https://bp.wl.free.nf/confs/wl.txt",
    "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt",
    "https://raw.githubusercontent.com/gbwltg/gbwl/refs/heads/main/m3EsPqwmlc",
    "https://gitverse.ru/api/repos/Vsevj/OBS/raw/branch/master/wwh",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://storage.yandexcloud.net/cid-vpn/whitelist.txt",
    "https://raw.githubusercontent.com/officialdakari/psychic-octo-tribble/refs/heads/main/subwl.txt",
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/LimeVPN.txt",
    "https://gitverse.ru/api/repos/lolfomka/tg-WLTGFF/raw/branch/master/TG-@WLTGFF",
]
ROS_TUNNEL_ALL = ROS_TUNNEL_STD + ROS_TUNNEL_WL


try:
    from PySide6.QtGui import QPainter, QLinearGradient, QRadialGradient
    from PySide6.QtCore import QRectF
except ImportError:
    from PySide2.QtGui import QPainter, QLinearGradient, QRadialGradient
    from PySide2.QtCore import QRectF


class ScanProgressBar(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._scan_pos = 0.0
        self._scan_dir = 1
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._scanning = False

    def start_scan(self):
        if not self._scanning:
            self._scanning = True
            self._scan_pos = 0.0
            self._timer.start(30)

    def stop_scan(self):
        self._scanning = False
        self._timer.stop()
        self.update()

    def _tick(self):
        self._scan_pos += 0.02 * self._scan_dir
        if self._scan_pos > 1.0:
            self._scan_pos = 1.0
            self._scan_dir = -1
        elif self._scan_pos < 0.0:
            self._scan_pos = 0.0
            self._scan_dir = 1
        self.update()

    def paintEvent(self, event):
        if not self._scanning:
            super().paintEvent(event)
            return

        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        r = h // 2

        bar_rect = QRectF(1, 1, w - 2, h - 2)

        p.setPen(Qt.PenStyle.NoPen)

        # light bg
        _t = THEMES[current_theme()]
        p.setBrush(QColor(_t['progress_bg']))
        p.drawRoundedRect(bar_rect, r, r)

        val = max(0, min(1, self.value() / max(self.maximum(), 1)))
        if val > 0:
            fill_w = max(4, (w - 2) * val)
            fill_rect = QRectF(1, 1, fill_w, h - 2)
            grad = QLinearGradient(0, 0, w, 0)
            if current_theme() == "dark":
                grad.setColorAt(0.0, QColor("#2563eb"))
                grad.setColorAt(0.5, QColor("#3b82f6"))
                grad.setColorAt(1.0, QColor("#60a5fa"))
            else:
                grad.setColorAt(0.0, QColor("#1d4ed8"))
                grad.setColorAt(0.5, QColor("#2f6fed"))
                grad.setColorAt(1.0, QColor("#3b82f6"))
            p.setBrush(grad)
            p.drawRoundedRect(fill_rect, r, r)

            scan_x = 1 + (w - 2) * self._scan_pos
            if scan_x < fill_w:
                glow = QRadialGradient(scan_x, h / 2, h * 0.8)
                glow.setColorAt(0.0, QColor(255, 255, 255, 180))
                glow.setColorAt(0.4, QColor(255, 255, 255, 60))
                glow.setColorAt(1.0, QColor(255, 255, 255, 0))
                p.setBrush(glow)
                p.drawRoundedRect(fill_rect, r, r)

        p.end()


def _as_bool(value, default: bool = True) -> bool:
    """Coerce a settings value to bool without treating "false" as True."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off", ""):
            return False
    return default


def _as_int(value, default: int, lo: int | None = None, hi: int | None = None) -> int:
    """Coerce a settings value to int.

    settings.json is user-editable (and older builds wrote strings), so a
    ``QSpinBox.setValue("1234")`` TypeError used to abort dialog creation.
    """
    try:
        result = int(str(value).strip()) if not isinstance(value, (int, float)) else int(value)
    except (TypeError, ValueError):
        result = default
    if lo is not None:
        result = max(lo, result)
    if hi is not None:
        result = min(hi, result)
    return result


def _safe_filename_part(value: str, fallback: str = "host") -> str:
    """Make a string safe for use inside a file name on Windows and POSIX."""
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value or "").strip(" .")
    return cleaned[:60] or fallback


def _view_text_dialog(title: str, content: str, parent=None):
    """Show a read-only text dialog with the given content (cross-platform)."""
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(700, 500)
    layout = QVBoxLayout(dlg)
    te = QPlainTextEdit(content)
    te.setReadOnly(True)
    te.setFont(QFont("Consolas", 10))
    _t = THEMES[current_theme()]
    te.setStyleSheet(f"background: {_t['code_bg']}; color: {_t['code_fg']}; border: 1px solid {_t['border']};")
    layout.addWidget(te)
    btn = QPushButton("Close")
    btn.clicked.connect(dlg.accept)
    layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignRight)
    run = getattr(dlg, "exec", None) or dlg.exec_
    run()

_ZOMBIE: list = []


def _prune_zombies():
    """Drop finished zombie threads; deleted C++ wrappers raise RuntimeError."""
    keep = []
    for thread, worker in _ZOMBIE:
        try:
            if thread.isRunning():
                keep.append((thread, worker))
        except RuntimeError:
            continue
    _ZOMBIE[:] = keep


def wait_zombies(timeout_ms: int = 2000):
    """Wait briefly for stopped-but-not-yet-finished threads before exit."""
    deadline = time.time() + max(0, timeout_ms) / 1000.0
    for thread, _worker in list(_ZOMBIE):
        try:
            if thread.isRunning():
                remaining = max(0, int((deadline - time.time()) * 1000))
                thread.wait(remaining)
        except RuntimeError:
            continue
    _prune_zombies()


def _cleanup_thread(thread, worker, wait_sec=0.05):
    """Stop a worker/thread pair without blocking the GUI.

    A blocking ``thread.wait(15000)`` freezes the window for up to 15 s while a
    stuck curl finishes. We stop the worker, ask the thread to quit, give it a
    few milliseconds and then keep a reference until Qt reports it finished —
    destroying a running QThread aborts the process.
    """
    if thread is None and worker is None:
        return
    if worker is not None:
        try:
            worker.stop()
        except Exception:
            pass
    still_running = False
    if thread is not None:
        try:
            thread.quit()
        except Exception:
            pass
        try:
            thread.wait(int(wait_sec * 1000))
        except Exception:
            pass
        try:
            still_running = thread.isRunning()
        except RuntimeError:
            still_running = False
        if still_running:
            try:
                thread.finished.connect(thread.deleteLater)
            except Exception:
                pass
            _ZOMBIE.append((thread, worker))
            if len(_ZOMBIE) > 32:
                _prune_zombies()
    if worker is not None and not still_running:
        try:
            worker.deleteLater()
        except Exception:
            pass


class _BgCallWorker(QObject):
    """Runs one blocking callable in a worker thread."""

    finished = Signal(object, object)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    @Slot()
    def run(self):
        try:
            self.finished.emit(self._fn(), None)
        except Exception as exc:
            self.finished.emit(None, exc)


_BG_CALLS: set = set()


def wait_background_calls(timeout_ms: int = 1500):
    """Give in-flight BackgroundCall threads a moment to stop before exit."""
    deadline = time.time() + max(0, timeout_ms) / 1000.0
    for call in list(_BG_CALLS):
        remaining = max(0, int((deadline - time.time()) * 1000))
        try:
            call._thread.wait(remaining)
        except (RuntimeError, AttributeError):
            pass


class BackgroundCall(QObject):
    """Run a blocking callable off the GUI thread, deliver the result to it.

    ``callback(result, error)`` runs in the GUI thread and may touch widgets.
    This replaces ad-hoc ``ThreadPoolExecutor.add_done_callback`` usage: that
    callback runs in the worker thread and mutating Qt widgets there crashes.

    The object has no QObject parent on purpose: it must outlive the widget
    that started it, otherwise closing a dialog while the request is in flight
    destroys a running QThread and aborts the process.
    """

    def __init__(self, fn, callback, parent=None):
        super().__init__(None)
        self._callback = callback
        self._thread = QThread()
        self._worker = _BgCallWorker(fn)
        self._worker.moveToThread(self._thread)
        self._worker.finished.connect(self._on_finished)
        self._thread.started.connect(self._worker.run, Qt.ConnectionType.DirectConnection)
        self._thread.finished.connect(self._worker.deleteLater)
        _BG_CALLS.add(self)
        self._thread.start()

    def _on_finished(self, result, error):
        try:
            # The owning widget may have been closed meanwhile: touching its
            # deleted C++ object raises RuntimeError, which we swallow.
            self._callback(result, error)
        except RuntimeError:
            pass
        finally:
            try:
                self._thread.quit()
                stopped = self._thread.wait(2000)
            except RuntimeError:
                stopped = True
            if stopped:
                _BG_CALLS.discard(self)
                try:
                    self.deleteLater()
                except RuntimeError:
                    pass
            else:
                # The callable is still blocking (e.g. a slow request). Keep
                # this object alive until the thread really stops; deleting a
                # running QThread aborts the process.
                try:
                    self._thread.finished.connect(self._finalize)
                except RuntimeError:
                    pass

    def _finalize(self):
        _BG_CALLS.discard(self)
        try:
            self.deleteLater()
        except RuntimeError:
            pass


class WizardPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._completed = False
        self._stopped = False

    def is_completed(self):
        return self._completed

    def is_stopped(self):
        return self._stopped

    def reset_state(self):
        self._completed = False
        self._stopped = False

    def on_enter(self):
        pass

    def on_leave(self):
        pass

    def _purge_jsdelivr_cdn(self, repo: str, file_path: str, branch: str = "") -> bool:
        """Best-effort purge of jsDelivr CDN cache so subscribers get the fresh file.

        GitHub is blocked in RU, so distribution goes through the jsDelivr CDN,
        which caches GitHub content for ~12h. Call this after a successful push.
        """
        if not repo or not file_path:
            return False
        import urllib.request
        branch = (branch or _settings_data.get("gh_branch") or "main").strip()
        url = f"https://purge.jsdelivr.net/gh/{repo}@{branch}/{file_path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "proxy-skitchen"})
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception:
            return False


class SourcesPage(WizardPage):
    def __init__(self, main):
        super().__init__(main)
        self._main = main
        self._sources = []
        self._gh_results = []
        self._gh_thread = None
        self._gh_worker = None

        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(8, 4, 8, 4)

        # ── Top bar ──
        top = QHBoxLayout()
        self.lbl_title = QLabel(_("sources.title"))
        top.addWidget(self.lbl_title)
        top.addStretch()
        self.btn_lang_ru = QPushButton("RU")
        self.btn_lang_ru.setFixedSize(28, 22)
        self.btn_lang_ru.setStyleSheet("QPushButton { font-size: 10px; font-weight: bold; padding: 0px; }")
        self.btn_lang_ru.setToolTip("Русский")
        self.btn_lang_ru.clicked.connect(lambda: self._switch_lang("ru"))
        top.addWidget(self.btn_lang_ru)
        self.btn_lang_en = QPushButton("EN")
        self.btn_lang_en.setFixedSize(28, 22)
        self.btn_lang_en.setStyleSheet("QPushButton { font-size: 10px; font-weight: bold; padding: 0px; }")
        self.btn_lang_en.setToolTip("English")
        self.btn_lang_en.clicked.connect(lambda: self._switch_lang("en"))
        top.addWidget(self.btn_lang_en)

        self.btn_theme_dark = QPushButton("🌙")
        self.btn_theme_dark.setFixedSize(28, 22)
        self.btn_theme_dark.setStyleSheet("QPushButton { font-size: 10px; padding: 0px; }")
        self.btn_theme_dark.setToolTip("Dark Theme")
        self.btn_theme_dark.clicked.connect(lambda: self._main._switch_theme("dark"))
        top.addWidget(self.btn_theme_dark)

        self.btn_theme_light = QPushButton("☀️")
        self.btn_theme_light.setFixedSize(28, 22)
        self.btn_theme_light.setStyleSheet("QPushButton { font-size: 10px; padding: 0px; }")
        self.btn_theme_light.setToolTip("Light Theme")
        self.btn_theme_light.clicked.connect(lambda: self._main._switch_theme("light"))
        top.addWidget(self.btn_theme_light)

        self.btn_settings = QPushButton(_("sources.btn.settings"))
        self.btn_settings.setFixedHeight(22)
        self.btn_settings.setToolTip(_("sources.btn.settings.tooltip"))
        self.btn_settings.clicked.connect(self._on_settings)
        top.addWidget(self.btn_settings)
        self.btn_stop = QPushButton(_("sources.btn.stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        top.addWidget(self.btn_stop)
        layout.addLayout(top)

        # ── Preset buttons (standalone, always visible) ──
        self._presets = [
            _("preset.vless"), _("preset.vmess"), _("preset.trojan"),
            _("preset.ss"), _("preset.v2ray_cfg"), _("preset.v2ray_sub"),
            _("preset.proxy"), _("preset.clash"), _("preset.singbox"),
            _("preset.free"), _("preset.xray"), _("preset.hysteria2"),
            _("preset.tuic"),
        ]
        half = (len(self._presets) + 1) // 2
        for row_idx in range(2):
            row_layout = QHBoxLayout()
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(2)
            start = row_idx * half
            end = min(start + half, len(self._presets))
            for kw in self._presets[start:end]:
                btn = QPushButton(kw)
                btn.setFixedHeight(22)
                btn.setStyleSheet("QPushButton { font-size: 9px; padding: 0px 4px; }")
                btn.clicked.connect(lambda checked, kw=kw: self._on_preset(kw))
                row_layout.addWidget(btn)
            layout.addLayout(row_layout)

        # ── RosTunnel preset row ──
        row_ros = QHBoxLayout()
        row_ros.setContentsMargins(0, 0, 0, 0)
        row_ros.setSpacing(2)
        self._btn_ros_all = QPushButton(_("preset.rostunnel_all"))
        self._btn_ros_all.setFixedHeight(22)
        self._btn_ros_all.setToolTip(_("preset.rostunnel_all"))
        self._btn_ros_all.setStyleSheet("QPushButton { font-size: 9px; padding: 0px 4px; font-weight: bold; }")
        self._btn_ros_all.clicked.connect(lambda: self._on_rostunnel_preset("all"))
        row_ros.addWidget(self._btn_ros_all)
        self._btn_ros_std = QPushButton(_("preset.rostunnel_std"))
        self._btn_ros_std.setFixedHeight(22)
        self._btn_ros_std.setToolTip(_("preset.rostunnel_std"))
        self._btn_ros_std.setStyleSheet("QPushButton { font-size: 9px; padding: 0px 4px; }")
        self._btn_ros_std.clicked.connect(lambda: self._on_rostunnel_preset("std"))
        row_ros.addWidget(self._btn_ros_std)
        self._btn_ros_wl = QPushButton(_("preset.rostunnel_wl"))
        self._btn_ros_wl.setFixedHeight(22)
        self._btn_ros_wl.setToolTip(_("preset.rostunnel_wl"))
        self._btn_ros_wl.setStyleSheet("QPushButton { font-size: 9px; padding: 0px 4px; }")
        self._btn_ros_wl.clicked.connect(lambda: self._on_rostunnel_preset("wl"))
        row_ros.addWidget(self._btn_ros_wl)
        layout.addLayout(row_ros)

        # ── GitHub search ──
        self.gh_group = QGroupBox(_("sources.group.github"))
        gh_body = QVBoxLayout(self.gh_group)
        gh_body.setSpacing(3)

        # Row: keywords (full width)
        kw_row = QHBoxLayout()
        self.lbl_keywords = QLabel(_("sources.label.keywords"))
        kw_row.addWidget(self.lbl_keywords)
        self.kw_input = QLineEdit()
        self.kw_input.setPlaceholderText(_("sources.input.keywords.placeholder"))
        kw_row.addWidget(self.kw_input, 1)
        gh_body.addLayout(kw_row)

        # Row: period + search buttons + options
        action_row = QHBoxLayout()
        action_row.addSpacing(70)
        self.lbl_period = QLabel(_("sources.label.period"))
        action_row.addWidget(self.lbl_period)
        self.period_combo = QComboBox()
        for p in [_("period.1h"), _("period.2h"), _("period.4h"), _("period.6h"), _("period.8h"), _("period.12h"), _("period.24h"), _("period.3d"), _("period.7d"), _("period.30d")]:
            self.period_combo.addItem(p)
        self.period_combo.setCurrentText(_("period.6h"))
        action_row.addWidget(self.period_combo)
        action_row.addSpacing(8)
        self.btn_quick_search = QPushButton(_("sources.btn.quick_search"))
        self.btn_quick_search.setObjectName("BtnQuickSearch")
        self.btn_quick_search.clicked.connect(lambda: self._on_github_search(False, False))
        action_row.addWidget(self.btn_quick_search)
        self.btn_deep_search = QPushButton(_("sources.btn.deep_search"))
        self.btn_deep_search.setObjectName("BtnDeepSearch")
        self.btn_deep_search.clicked.connect(lambda: self._on_github_search(True, True))
        action_row.addWidget(self.btn_deep_search)
        self.btn_wg_search = QPushButton("🔒 WG")
        self.btn_wg_search.setObjectName("BtnWgSearch")
        self.btn_wg_search.clicked.connect(self._on_wg_search)
        action_row.addWidget(self.btn_wg_search)
        self.chk_hidden_configs = QCheckBox(_("sources.chk.hidden_configs"))
        self.chk_hidden_configs.setToolTip(_("sources.chk.hidden_configs.tooltip"))
        self.chk_hidden_configs.setObjectName("ChkHiddenConfigs")
        action_row.addWidget(self.chk_hidden_configs)
        self.chk_wireguard = QCheckBox("🔒 WireGuard")
        self.chk_wireguard.setObjectName("ChkWireguard")
        action_row.addWidget(self.chk_wireguard)
        action_row.addStretch()
        gh_body.addLayout(action_row)

        # Row: GitHub URL filter
        url_row = QHBoxLayout()
        self.lbl_gh_url = QLabel(_("sources.label.gh_url"))
        url_row.addWidget(self.lbl_gh_url)
        self.gh_url_input = QLineEdit()
        self.gh_url_input.setPlaceholderText(_("sources.input.gh_url.placeholder"))
        url_row.addWidget(self.gh_url_input, 1)
        gh_body.addLayout(url_row)

        # Progress + status
        self.gh_progress = QWidget()
        gp = QVBoxLayout(self.gh_progress)
        gp.setContentsMargins(0, 0, 0, 0)
        gp.setSpacing(1)
        pr = QHBoxLayout()
        self.gh_progress_bar = QProgressBar()
        self.gh_progress_bar.setVisible(False)
        self.gh_progress_bar.setMaximum(0)
        self.gh_progress_bar.setFixedHeight(6)
        pr.addWidget(self.gh_progress_bar)
        self.gh_found_label = QLabel("")
        self.gh_found_label.setObjectName("GhFoundLabel")
        pr.addWidget(self.gh_found_label)
        gp.addLayout(pr)
        self.gh_status = QLabel("")
        self.gh_status.setWordWrap(True)
        self.gh_status.setObjectName("GhStatus")
        gp.addWidget(self.gh_status)
        self.gh_log = QPlainTextEdit()
        self.gh_log.setReadOnly(True)
        self.gh_log.setMaximumBlockCount(300)
        self.gh_log.setVisible(False)
        self.gh_log.setFixedHeight(120)
        self.gh_log.setObjectName("GhLog")
        self.gh_log.setFont(QFont("Consolas", 9))
        gp.addWidget(self.gh_log)
        self.wg_results = QPlainTextEdit()
        self.wg_results.setReadOnly(True)
        self.wg_results.setVisible(False)
        self.wg_results.setFixedHeight(80)
        self.wg_results.setPlaceholderText("WireGuard URIs from search appear here")
        self.wg_results.setObjectName("WgResults")
        self.wg_results.setFont(QFont("Consolas", 9))
        gp.addWidget(self.wg_results)
        self.btn_copy_wg = QPushButton("📋 Copy all")
        self.btn_copy_wg.setVisible(False)
        self.btn_copy_wg.setFixedHeight(20)
        self.btn_copy_wg.setStyleSheet(
            "QPushButton { font-size: 10px; padding: 0px 8px; }"
        )
        self.btn_copy_wg.clicked.connect(self._on_copy_wg)
        gp.addWidget(self.btn_copy_wg)
        gh_body.addWidget(self.gh_progress)

        layout.addWidget(self.gh_group)

        # ── Manual URL ──
        self.url_group = QGroupBox(_("sources.group.manual_url"))
        url_row = QHBoxLayout(self.url_group)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(_("sources.input.url.placeholder"))
        url_row.addWidget(self.url_input)
        self.btn_add_url = QPushButton(_("sources.btn.add_url"))
        self.btn_add_url.setFixedHeight(24)
        self.btn_add_url.clicked.connect(self._on_add_url)
        url_row.addWidget(self.btn_add_url)
        layout.addWidget(self.url_group)

        # ── Sources list ──
        src_header = QHBoxLayout()
        self.lbl_subscriptions = QLabel(_("sources.label.subscriptions"))
        src_header.addWidget(self.lbl_subscriptions)
        self.import_status = QLabel("")
        self.import_status.setObjectName("ImportStatus")
        src_header.addWidget(self.import_status)
        src_header.addStretch()
        self.btn_import_file = QPushButton("📂")
        self.btn_import_file.setFixedSize(24, 24)
        self.btn_import_file.setToolTip(_("sources.btn.import_file"))
        self.btn_import_file.clicked.connect(self._on_import_file)
        src_header.addWidget(self.btn_import_file)
        self.btn_import_paste = QPushButton("📋")
        self.btn_import_paste.setFixedSize(24, 24)
        self.btn_import_paste.setToolTip(_("sources.btn.import_paste"))
        self.btn_import_paste.clicked.connect(self._on_import_paste)
        src_header.addWidget(self.btn_import_paste)
        self.chk_auto_pipeline = QCheckBox(_("sources.chk.auto_pipeline"))
        self.chk_auto_pipeline.setChecked(False)
        src_header.addWidget(self.chk_auto_pipeline)
        self.btn_clear = QPushButton("✕")
        self.btn_clear.setEnabled(False)
        self.btn_clear.setFixedHeight(24)
        self.btn_clear.setStyleSheet("QPushButton { font-size: 12px; padding: 0px; }")
        self.btn_clear.clicked.connect(self._on_clear)
        src_header.addWidget(self.btn_clear)
        layout.addLayout(src_header)

        self.src_list = QListWidget()
        self.src_list.setAlternatingRowColors(True)
        self.src_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.src_list.customContextMenuRequested.connect(self._on_src_context)
        self.src_list.itemDoubleClicked.connect(self._on_src_double_click)
        layout.addWidget(self.src_list, 1)

        nav = QHBoxLayout()
        self.btn_fetch = QPushButton(_("sources.btn.fetch"))
        self.btn_fetch.setEnabled(False)
        self.btn_fetch.clicked.connect(self._on_fetch)
        nav.addStretch()
        self.btn_pipeline = QPushButton(_("sources.btn.pipeline"))
        self.btn_pipeline.setStyleSheet("QPushButton { background: rgba(124,92,191,0.15); border: 2px solid #7c5cbf; border-radius: 4px; padding: 4px 12px; font-weight: bold; } QPushButton:hover { background: rgba(124,92,191,0.3); }")
        self.btn_pipeline.clicked.connect(self._on_pipeline)
        nav.addWidget(self.btn_pipeline)
        self.chk_github_push = QCheckBox(_("sources.chk.github_push"))
        self.chk_github_push.setChecked(False)
        nav.addWidget(self.chk_github_push)
        nav.addWidget(self.btn_fetch)
        layout.addLayout(nav)

        self._refresh_toolbar_buttons()

    def _cleanup_gh(self):
        worker = getattr(self, '_gh_worker', None)
        thread = getattr(self, '_gh_thread', None)
        if worker is None and thread is None:
            return
        # Clear references FIRST — stale queued signals see None
        self._gh_worker = None
        self._gh_thread = None
        if worker is not None:
            # Disconnect all signals — stale queued events are silently dropped by Qt
            for sig_name in ('wg_signal', 'result_signal', 'partial_result_signal',
                             'error_signal', 'progress_signal', 'count_signal', 'log_signal'):
                try:
                    getattr(worker, sig_name).disconnect()
                except (TypeError, RuntimeError):
                    pass
            worker.stop()  # sets _stop=True, kills API procs
            # NOTE: no deleteLater() — pool threads may still hold self ref via
            # bound methods. Python GC cleans up when pool threads finish.
        if thread is not None:
            # Shared cleanup keeps a zombie reference until the thread really
            # stops; the old single-slot reference could be overwritten by a
            # new search and destroy a running QThread.
            _cleanup_thread(thread, worker)

    def _switch_lang(self, code: str):
        if code != current_lang():
            set_lang(code)
            self._main.apply_language()
            self._refresh_toolbar_buttons()

    def _refresh_toolbar_buttons(self):
        t = THEMES[current_theme()]
        acc = t['accent']
        lang = current_lang()
        self.btn_lang_ru.setStyleSheet(
            f"QPushButton {{ font-size: 10px; font-weight: bold; padding: 0px; background: {acc}; color: white; border: none; border-radius: 3px; }}"
            if lang == "ru" else
            "QPushButton { font-size: 10px; font-weight: bold; padding: 0px; background: transparent; border: none; }"
        )
        self.btn_lang_en.setStyleSheet(
            f"QPushButton {{ font-size: 10px; font-weight: bold; padding: 0px; background: {acc}; color: white; border: none; border-radius: 3px; }}"
            if lang == "en" else
            "QPushButton { font-size: 10px; font-weight: bold; padding: 0px; background: transparent; border: none; }"
        )
        theme = current_theme()
        self.btn_theme_dark.setStyleSheet(
            f"QPushButton {{ font-size: 10px; padding: 0px; background: {acc}; color: white; border: none; border-radius: 3px; }}"
            if theme == "dark" else
            "QPushButton { font-size: 10px; padding: 0px; background: transparent; border: none; }"
        )
        self.btn_theme_light.setStyleSheet(
            f"QPushButton {{ font-size: 10px; padding: 0px; background: {acc}; color: white; border: none; border-radius: 3px; }}"
            if theme == "light" else
            "QPushButton { font-size: 10px; padding: 0px; background: transparent; border: none; }"
        )
        self.lbl_title.setStyleSheet(f"font-size: 14px; font-weight: bold; padding: 2px 0; color: {t['fg']};")
        self.gh_found_label.setStyleSheet(f"color: {acc}; font-weight: 700;")
        self.gh_status.setStyleSheet(f"color: {t['muted_fg']}; font-size: 11px;")
        self.url_group.setStyleSheet(f"QGroupBox {{ border: 1px solid {t['border']}; border-radius: 6px; margin-top: 10px; padding: 12px 8px 8px 8px; font-weight: 600; color: {t['accent']}; }} QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; }}")
        self.import_status.setStyleSheet(f"font-size:11px;color:{t['muted']};")
        self.btn_import_file.setStyleSheet(f"QPushButton{{font-size:12px;padding:2px;border:1px solid {t['success_border']};border-radius:3px;color:{t['success']};}}QPushButton:hover{{background:rgba({int(t['success'][1:3],16)},{int(t['success'][3:5],16)},{int(t['success'][5:7],16)},0.15);}}")
        self.btn_import_paste.setStyleSheet(f"QPushButton{{font-size:12px;padding:2px;border:1px solid {acc};border-radius:3px;color:{acc};}}QPushButton:hover{{background:rgba({int(acc[1:3],16)},{int(acc[3:5],16)},{int(acc[5:7],16)},0.15);}}")
        self.btn_quick_search.setStyleSheet(
            f"QPushButton {{ background: transparent; border: 1px solid {t['border']}; border-radius: 3px; padding: 2px 8px; font-size: 10px; color: {t['fg']}; }}"
            f"QPushButton:hover {{ background: rgba({int(acc[1:3],16)},{int(acc[3:5],16)},{int(acc[5:7],16)},0.08); border-color: {acc}; }}"
        )
        self.btn_deep_search.setStyleSheet(
            f"QPushButton {{ background: transparent; border: 2px solid {t['accent2']}; border-radius: 3px; padding: 2px 8px; font-size: 10px; color: {t['accent2']}; }}"
            f"QPushButton:hover {{ background: rgba({int(t['accent2'][1:3],16)},{int(t['accent2'][3:5],16)},{int(t['accent2'][5:7],16)},0.12); }}"
        )
        self.btn_wg_search.setStyleSheet(
            f"QPushButton {{ background: transparent; border: 2px solid {t['success']}; border-radius: 3px; padding: 2px 8px; font-size: 10px; color: {t['success']}; }}"
            f"QPushButton:hover {{ background: rgba({int(t['success'][1:3],16)},{int(t['success'][3:5],16)},{int(t['success'][5:7],16)},0.12); }}"
        )
        self.chk_hidden_configs.setStyleSheet(f"QCheckBox {{ font-size: 10px; color: {t['muted_fg']}; }}")
        self.chk_wireguard.setStyleSheet(f"QCheckBox {{ font-size: 10px; color: {t['muted_fg']}; }}")
        self.gh_log.setStyleSheet(
            f"QPlainTextEdit {{ background: {t['code_bg']}; color: {t['code_fg']}; "
            f"border: 1px solid {t['border']}; border-radius: 3px; padding: 2px; }}"
        )
        self.wg_results.setStyleSheet(
            f"QPlainTextEdit {{ background: {t['code_bg']}; color: {t['code_fg']}; "
            f"border: 1px solid {t['border']}; border-radius: 3px; padding: 2px; }}"
        )

    def _on_settings(self):
        try:
            dlg = SettingsDialog(self._main)
            run = getattr(dlg, "exec", None) or dlg.exec_
            run()
        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(
                self, _("sources.btn.settings.tooltip"),
                f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}",
            )

    def _on_preset(self, kw: str):
        current = self.kw_input.text().strip()
        if current:
            kws = set(current.replace(",", " ").split())
            kws.add(kw)
            self.kw_input.setText(", ".join(sorted(kws)))
        else:
            self.kw_input.setText(kw)

    def _on_rostunnel_preset(self, variant: str):
        urls = {"all": ROS_TUNNEL_ALL, "std": ROS_TUNNEL_STD, "wl": ROS_TUNNEL_WL}
        for url in urls.get(variant, []):
            self._add_source(url, url)

    def _on_stop(self):
        self._cleanup_gh()
        self._stopped = True
        self.btn_stop.setEnabled(False)
        self.btn_quick_search.setEnabled(True)
        self.btn_deep_search.setEnabled(True)
        self.btn_wg_search.setEnabled(True)
        self.gh_progress_bar.setVisible(False)
        count = len(self._gh_results)
        self.gh_status.setText(_("gh.stopped", count=count))
        self.gh_found_label.setText(f"⏹ {count}")
        self._update_fetch_btn()

    def _on_github_search(self, weak_hw: bool = False, deep_search: bool = False):
        self._on_clear()
        kw_text = self.kw_input.text().strip()
        gh_url = self.gh_url_input.text().strip()
        if not kw_text and not gh_url:
            QMessageBox.warning(self, _("msg.warning"), _("msg.no_keywords"))
            return
        keywords = [kw.strip() for kw in kw_text.replace(',', ' ').split() if kw.strip()]
        period_map = {_("period.1h"): 0.04, _("period.2h"): 0.08, _("period.4h"): 0.17, _("period.6h"): 0.25,
                      _("period.8h"): 0.33, _("period.12h"): 0.5, _("period.24h"): 1, _("period.3d"): 3, _("period.7d"): 7, _("period.30d"): 30}
        time_days = period_map.get(self.period_combo.currentText(), 7)
        tokens = _get_tokens()
        repos = []
        owner = None
        if gh_url:
            m_repo = re.match(r'(?:https?://)?github\.com/([^/]+/[^/]+?)(?:/.*)?$', gh_url)
            m_user = re.match(r'(?:https?://)?github\.com/([^/]+)/?$', gh_url)
            m_pages = re.match(r'(?:https?://)?([^.]+)\.github\.io/([^/]+?)/?$', gh_url)
            m_pages_user = re.match(r'(?:https?://)?([^.]+)\.github\.io/?$', gh_url)
            if m_repo:
                repos.append(m_repo.group(1))
            elif m_user:
                owner = m_user.group(1)
            elif m_pages:
                repos.append(f"{m_pages.group(1)}/{m_pages.group(2)}")
            elif m_pages_user:
                repos.append(f"{m_pages_user.group(1)}/{m_pages_user.group(1)}.github.io")
        self._cleanup_gh()
        cfg = PERF_PRESETS.get(_settings_data.get("perf_mode", "medium"))
        hidden = self.chk_hidden_configs.isChecked()
        self._gh_worker = GitHubSearchWorker(
            keywords, set(), explicit_repos=repos,
            time_filter_days=time_days, github_tokens=tokens,
            max_repos=cfg["max_repos"], max_files=cfg["max_files"],
            owner=owner, weak_hw=weak_hw, deep_search=deep_search,
            hidden_search=hidden
        )
        self._gh_thread = QThread()
        self._gh_worker.moveToThread(self._gh_thread)
        self._gh_worker.result_signal.connect(self._on_gh_result)
        self._gh_worker.partial_result_signal.connect(self._on_gh_partial)
        self._gh_worker.error_signal.connect(self._on_gh_error)
        self._gh_worker.progress_signal.connect(self._on_gh_progress)
        self._gh_worker.count_signal.connect(self._on_gh_count)
        self._gh_worker.log_signal.connect(self._on_gh_log)
        self._gh_worker.wg_signal.connect(self._on_wg_uri)
        self._gh_thread.started.connect(self._gh_worker.run, Qt.ConnectionType.DirectConnection)
        self.gh_log.clear()
        self.gh_log.setVisible(False)
        self.wg_results.clear()
        self.wg_results.setVisible(False)
        self.btn_copy_wg.setVisible(False)
        self.btn_quick_search.setEnabled(False)
        self.btn_deep_search.setEnabled(False)
        self.btn_wg_search.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.gh_progress_bar.setVisible(True)
        self.gh_status.setText(_("gh.searching", kw=", ".join(keywords[:3]) + ("..." if len(keywords) > 3 else "")))
        self.gh_found_label.setText("⏳")
        self._stopped = False
        self._gh_results = []
        self._gh_count = 0
        self._gh_thread.start()

    def _on_wg_search(self):
        self.chk_wireguard.setChecked(True)
        kw_text = self.kw_input.text().strip()
        gh_url = self.gh_url_input.text().strip()
        # Fallback: если нет ни ключевых слов, ни URL — ищем "wireguard" везде
        if not kw_text and not gh_url:
            self.kw_input.setText("wireguard")
        self._on_github_search(True, True)

    def _on_wg_uri(self, uri: str):
        if self.sender() is not self._gh_worker:
            return
        if not self.chk_wireguard.isChecked():
            return
        self.wg_results.appendPlainText(uri)
        if not self.wg_results.isVisible():
            self.wg_results.setVisible(True)
            self.btn_copy_wg.setVisible(True)

    def _on_copy_wg(self):
        text = self.wg_results.toPlainText()
        if text.strip():
            QApplication.clipboard().setText(text)

    def _on_gh_log(self, msg: str):
        if self.sender() is not self._gh_worker:
            return
        self.gh_log.appendPlainText(msg)
        if not self.gh_log.isVisible():
            self.gh_log.setVisible(True)
        sb = self.gh_log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_gh_progress(self, msg: str):
        if self.sender() is not self._gh_worker:
            return
        c = getattr(self, '_gh_count', 0)
        self.gh_found_label.setText(f"📄 {c}")
        stripped = msg.strip()
        if stripped.startswith('📁 explicit:'):
            self.gh_status.setText(_("gh.repo_scan", path=stripped[12:]))
        elif stripped.startswith('📄'):
            s = stripped[4:].strip() if len(stripped) > 4 else ""
            self.gh_status.setText(_("gh.file_scan", path=s))
        elif stripped.startswith('🔗'):
            self.gh_status.setText(stripped)
        elif stripped.startswith('keyword:'):
            kw = stripped[8:].strip()
            self.gh_status.setText(_("gh.keyword", kw=kw))
        elif stripped.startswith('scan') and '⭐' in stripped:
            parts = stripped.split('⭐')
            repo = parts[0].replace('scan', '').strip()
            stars = parts[1].strip() if len(parts) > 1 else ""
            self.gh_status.setText(_("gh.scanning", repo=repo, stars=stars))
        elif stripped.startswith('⚠'):
            self.gh_status.setText(f"⚠ {stripped[4:].strip()}")
        elif stripped.startswith('📁'):
            self.gh_status.setText(_("gh.repo_scan", path=stripped[4:].strip()))
        else:
            self.gh_status.setText(stripped)

    def _on_gh_count(self, count: int):
        if self.sender() is not self._gh_worker:
            return
        self._gh_count = count
        self.gh_found_label.setText(f"📄 {count}")

    def _on_gh_partial(self, results: list):
        if self.sender() is not self._gh_worker:
            return
        self._gh_results = results
        for r in results:
            url = r.get("file_url", "")
            name = r.get("name", url)
            uris = r.get("uris", [])
            if r.get("embedded", False):
                self._add_source(_("gh.embed_prefix", name=name), url, uris)
            else:
                self._add_source(name, url, uris)
        self._update_fetch_btn()

    def _on_gh_result(self, results: list):
        if self.sender() is not self._gh_worker:
            return
        self.gh_progress_bar.setVisible(False)
        self.btn_quick_search.setEnabled(True)
        self.btn_deep_search.setEnabled(True)
        self.btn_wg_search.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._gh_results = results
        added = 0
        for r in results:
            url = r.get("file_url", "")
            name = r.get("name", url)
            uris = r.get("uris", [])
            if r.get("embedded", False):
                self._add_source(_("gh.embed_prefix", name=name), url, uris)
            else:
                self._add_source(name, url, uris)
            added += 1
        self.gh_status.setText(_("gh.found_files", count=added))
        self.gh_found_label.setText(f"✅ {added}")
        self._cleanup_gh()
        self._completed = True
        
        # Bright success indicator
        self._main._tab_btns[0].setStyleSheet("color: #74c7a0; font-weight: bold;")
        self._main._tab_btns[0].setText(f"{_('main.tab.sources')} ✅")
        QTimer.singleShot(3000, self._reset_gh_tab_indicator)
        if self._main._pipeline_mode and self._sources:
            QTimer.singleShot(500, self._on_fetch)

    def _on_gh_error(self, err: str):
        if self.sender() is not self._gh_worker:
            return
        self.gh_progress_bar.setVisible(False)
        self.btn_quick_search.setEnabled(True)
        self.btn_deep_search.setEnabled(True)
        self.btn_wg_search.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.gh_status.setText(f"⚠ {err[:60]}")
        self.gh_found_label.setText("⚠")
        self._cleanup_gh()
        
        # Bright error indicator
        self._main._tab_btns[0].setStyleSheet("color: #e36262; font-weight: bold;")
        self._main._tab_btns[0].setText(f"{_('main.tab.sources')} ❌")
        QTimer.singleShot(3000, self._reset_gh_tab_indicator)

    def _reset_gh_tab_indicator(self):
        # A new search may have started while the 3 s indicator was pending —
        # never overwrite its running state.
        if self._gh_thread is not None:
            return
        self._main._tab_btns[0].setStyleSheet("")
        self._main.update_status_bar()

    def _on_add_url(self):
        url = self.url_input.text().strip()
        if not url:
            return
        # GitHub repo URL → добавить в поле "Репозиторий" и запустить поиск
        m = None
        if url.startswith(('http://', 'https://')):
            m = re.match(r'^https?://github\.com/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+?)(?:\.git)?$', url)
        else:
            m = re.match(r'^(?:github\.com/)?([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+?)(?:\.git)?$', url)
        if m:
            repo = m.group(1).rstrip('/')
            self.gh_url_input.setText(repo)
            self.url_input.clear()
            self.gh_status.setText(_("gh.repo_url", repo=repo))
            QTimer.singleShot(100, self._on_github_search)
            return
        self._add_source(url, url)
        self.url_input.clear()

    def _add_source(self, name: str, url: str, uris: list[str] | None = None):
        for i in range(self.src_list.count()):
            item = self.src_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == url:
                return
        # Build display text with protocol breakdown
        label = name
        if uris:
            proto_counts: dict[str, int] = {}
            for u in uris:
                p = get_protocol(u)
                proto_counts[p] = proto_counts.get(p, 0) + 1
            parts = sorted(proto_counts.items(), key=lambda x: -x[1])
            summary = " | ".join(f"{c} {p}" for p, c in parts[:5])
            label = f"{name}  —  {summary}"
        item = QListWidgetItem(label)
        item.setData(Qt.ItemDataRole.UserRole, url)
        item.setData(Qt.ItemDataRole.UserRole + 1, uris or [])
        if uris:
            item.setToolTip("\n".join(uris))
        self.src_list.addItem(item)
        self._sources.append((name, url, uris or []))
        self._update_fetch_btn()

    def _remove_source(self, url: str):
        for i in range(self.src_list.count()):
            item = self.src_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == url:
                self.src_list.takeItem(i)
                self._sources = [t for t in self._sources if t[1] != url]
                self._update_fetch_btn()
                return

    def _on_src_context(self, pos):
        item = self.src_list.itemAt(pos)
        if not item:
            return
        menu = QMenu()
        url = item.data(Qt.ItemDataRole.UserRole)
        menu.addAction(_("sources.context.view"), lambda: self._fetch_and_view(url, item))
        menu.addAction(_("sources.context.open_browser"), lambda: QDesktopServices.openUrl(QUrl(url)))
        menu.addAction(_("sources.context.remove"), lambda: self._remove_source(url))
        menu.exec_(self.src_list.mapToGlobal(pos))

    def _on_src_double_click(self, item):
        if item:
            url = item.data(Qt.ItemDataRole.UserRole)
            if url:
                self._fetch_and_view(url, item)

    def _fetch_and_view(self, url: str, item=None):
        """Download URL content and show in text dialog."""
        if not url:
            return
        # If item has stored URIs, show those as a quick list instead of full download
        uris = item.data(Qt.ItemDataRole.UserRole + 1) if item and item.data(Qt.ItemDataRole.UserRole + 1) else None
        if uris:
            title = item.text().split("  —  ")[0] if "  —  " in item.text() else url.rsplit("/", 1)[-1]
            content = "\n".join(uris)
            _view_text_dialog(title, content, self)
            return
        use_proxy = _settings_data.get("proxy_enabled", True)

        def _download():
            req = urllib.request.Request(url, headers={"User-Agent": "proxy-skitchen/2.0"})
            if use_proxy:
                req.set_proxy("socks5://127.0.0.1:12334", "http")
            resp = urllib.request.urlopen(req, timeout=15)
            return resp.read().decode("utf-8", errors="replace")

        def _show(content, error):
            if error is not None:
                QMessageBox.warning(self, _("msg.error"), f"Failed to load:\n{url}\n\n{error}")
                return
            name = url.rsplit("/", 1)[-1] if "/" in url else url
            _view_text_dialog(name, content, self)

        BackgroundCall(_download, _show, parent=self)

    def _on_clear(self):
        self.src_list.clear()
        self._sources.clear()
        self._update_fetch_btn()

    def _update_fetch_btn(self):
        has = len(self._sources) > 0
        self.btn_fetch.setEnabled(has)
        self.btn_clear.setEnabled(has)

    def _on_fetch(self):
        if not self._sources:
            return
        _debug(f"_on_fetch: {len(self._sources)} sources")
        self._main.download_page.fetch_sources([(t[0], t[1]) for t in self._sources])
        self._main.set_page(1)
        _debug("_on_fetch: set_page done")

    def _on_pipeline(self):
        kw_text = self.kw_input.text().strip()
        gh_url = self.gh_url_input.text().strip()
        if not kw_text and not gh_url and not self._sources:
            QMessageBox.warning(self, _("msg.warning"), _("msg.no_keywords"))
            return
        self._main._pipeline_mode = True
        if self._sources:
            self._on_fetch()
        else:
            self._on_github_search(True, True)

    def _on_import_file(self):
        from .parsers import is_proxy_uri
        paths, _filt = QFileDialog.getOpenFileNames(
            self, _("sources.import.file_title"), DESKTOP_DIR,
            "Text files (*.txt *.text);;All files (*.*)")
        if not paths:
            return
        all_uris = []
        for path in paths:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lstrip('\ufeff')
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('//'):
                        continue
                    if re.match(r'^[A-Za-z0-9+/=]{50,}$', line):
                        try:
                            decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
                            for sl in decoded.splitlines():
                                sl = sl.strip()
                                if sl and is_proxy_uri(sl):
                                    all_uris.append(sl)
                        except Exception:
                            if is_proxy_uri(line):
                                all_uris.append(line)
                    elif is_proxy_uri(line):
                        all_uris.append(line)
            except Exception as ex:
                QMessageBox.warning(self, _("msg.warning"), f"{path}: {ex}")
        if all_uris:
            entries = [ProxyEntry(uri) for uri in all_uris]
            self._main.test_page.load_entries(entries)
            if self.chk_auto_pipeline.isChecked():
                self._main._pipeline_mode = True
                self._main._pipeline_stage = 1
                self._main.set_page(2)
                QTimer.singleShot(100, self._main.test_page._on_deep_test)
            else:
                self._main.set_page(2)
            self.import_status.setText(_("sources.import.file_done", count=len(all_uris)))
        else:
            self.import_status.setText(_("sources.import.no_uris"))

    def _on_import_paste(self):
        from .parsers import is_proxy_uri
        text, ok = QInputDialog.getMultiLineText(self, _("sources.btn.import_paste"),
            _("sources.import.paste_prompt"), "")
        if not ok or not text.strip():
            return
        uris = []
        seen = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            if re.match(r'^[A-Za-z0-9+/=]{50,}$', line):
                try:
                    decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
                    for sl in decoded.splitlines():
                        sl = sl.strip()
                        if sl and is_proxy_uri(sl) and sl not in seen:
                            seen.add(sl)
                            uris.append(sl)
                except Exception:
                    if is_proxy_uri(line) and line not in seen:
                        seen.add(line)
                        uris.append(line)
            elif is_proxy_uri(line) and line not in seen:
                seen.add(line)
                uris.append(line)
        if uris:
            entries = [ProxyEntry(uri) for uri in uris]
            self._main.test_page.load_entries(entries)
            if self.chk_auto_pipeline.isChecked():
                self._main._pipeline_mode = True
                self._main._pipeline_stage = 1
                self._main.set_page(2)
                QTimer.singleShot(100, self._main.test_page._on_deep_test)
            else:
                self._main.set_page(2)
            self.import_status.setText(_("sources.import.paste_done", count=len(uris)))
        else:
            self.import_status.setText(_("sources.import.no_uris"))

    def retranslate(self):
        self.lbl_title.setText(_("sources.title"))
        self.btn_settings.setText(_("sources.btn.settings"))
        self.btn_settings.setToolTip(_("sources.btn.settings.tooltip"))
        self.btn_stop.setText(_("sources.btn.stop"))
        self._refresh_toolbar_buttons()
        self.gh_group.setTitle(_("sources.group.github"))
        self.lbl_keywords.setText(_("sources.label.keywords"))
        self.kw_input.setPlaceholderText(_("sources.input.keywords.placeholder"))
        self.lbl_period.setText(_("sources.label.period"))
        self.btn_quick_search.setText(_("sources.btn.quick_search"))
        self.btn_deep_search.setText(_("sources.btn.deep_search"))
        self.url_group.setTitle(_("sources.group.manual_url"))
        self.url_input.setPlaceholderText(_("sources.input.url.placeholder"))
        self.btn_add_url.setText(_("sources.btn.add_url"))
        self.lbl_subscriptions.setText(_("sources.label.subscriptions"))
        self.btn_clear.setText(_("sources.btn.clear"))
        self.btn_fetch.setText(_("sources.btn.fetch"))
        self.btn_pipeline.setText(_("sources.btn.pipeline"))
        self.chk_github_push.setText(_("sources.chk.github_push"))
        self.chk_auto_pipeline.setText(_("sources.chk.auto_pipeline"))
        self.btn_import_file.setToolTip(_("sources.btn.import_file"))
        self.btn_import_paste.setToolTip(_("sources.btn.import_paste"))
        # period combo — rebuild items
        current = self.period_combo.currentText()
        self.period_combo.blockSignals(True)
        self.period_combo.clear()
        for p in [_("period.1h"), _("period.2h"), _("period.4h"), _("period.6h"), _("period.8h"), _("period.12h"), _("period.24h"), _("period.3d"), _("period.7d"), _("period.30d")]:
            self.period_combo.addItem(p)
        if self.period_combo.findText(current) >= 0:
            self.period_combo.setCurrentText(current)
        else:
            self.period_combo.setCurrentText(_("period.6h"))
        self.period_combo.blockSignals(False)

    def get_sources(self) -> list[tuple[str, str]]:
        return [(t[0], t[1]) for t in self._sources]

    def on_enter(self):
        self._update_fetch_btn()
        self._main.update_status_bar()

    def on_leave(self):
        self._cleanup_gh()


class DownloadPage(WizardPage):
    PHASE_IDLE = 0
    PHASE_FETCH = 1

    def __init__(self, main):
        super().__init__(main)
        self._main = main
        self._entries = []
        self._phase = self.PHASE_IDLE
        self._net_thread = None
        self._net_worker = None
        self._net_run = 0
        self._stopped = False
        self._completed = False
        self._fetch_start_time = 0.0
        self._cell_started_bg = QColor("#1e2338")
        self._cell_done_bg = QColor("#181c2e")
        self._sources_ok = 0
        self._sources_total = 0
        self._source_rows: dict[str, int] = {}
        self._proto_counts: dict[str, int] = {}
        self._progress_tick = 0
        self._progress_last_done = 0
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(600)
        self._progress_timer.timeout.connect(self._on_progress_tick)

        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        self.lbl_title = QLabel(_("download.title"))
        top.addWidget(self.lbl_title)
        top.addStretch()

        self.btn_stop = QPushButton(_("download.btn.stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        top.addWidget(self.btn_stop)

        self.btn_back = QPushButton(_("download.btn.back"))
        self.btn_back.clicked.connect(lambda: self._main.set_page(0))
        top.addWidget(self.btn_back)
        layout.addLayout(top)

        # Source status table
        self.src_group = QGroupBox(_("download.group.sources"))
        src_layout = QVBoxLayout(self.src_group)
        src_layout.setContentsMargins(4, 4, 4, 4)
        self.src_table = QTableWidget(0, 3)
        self.src_table.setHorizontalHeaderLabels(["", _("download.table.source"), _("download.table.proxies")])
        self.src_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.src_table.setColumnWidth(0, 24)
        self.src_table.setColumnWidth(2, 80)
        self.src_table.verticalHeader().setVisible(False)
        self.src_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.src_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.src_table.setAlternatingRowColors(True)
        self.src_table.cellDoubleClicked.connect(self._on_src_table_double_click)
        src_layout.addWidget(self.src_table)
        layout.addWidget(self.src_group)

        # Toggle button
        self.btn_toggle_sources = QPushButton(_("download.hide_sources"))
        self.btn_toggle_sources.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_sources.setStyleSheet("""
            QPushButton {
                background: transparent; border: 1px dashed #5b8def;
                color: #5b8def; font-size: 11px; padding: 2px 10px;
                border-radius: 10px; font-weight: 400; text-transform: none;
                letter-spacing: 0;
            }
            QPushButton:hover {
                background: rgba(122, 162, 247, 0.12);
                border: 1px solid #5b8def;
            }
        """)
        self.btn_toggle_sources.clicked.connect(self._toggle_sources)
        layout.addWidget(self.btn_toggle_sources)

        # Stats
        stats_row = QHBoxLayout()
        self.lbl_total = QLabel(_("download.stats.total", count=0))
        self.lbl_total.setStyleSheet("padding: 4px 8px; background: #1e2338; border: 1px solid #4a5168; border-radius: 4px;")
        stats_row.addWidget(self.lbl_total)
        self.lbl_detail = QLabel("")
        self.lbl_detail.setStyleSheet("padding: 4px 8px; background: #1e2338; border: 1px solid #4a5168; border-radius: 4px;")
        self.lbl_detail.hide()
        stats_row.addWidget(self.lbl_detail)
        stats_row.addStretch()
        self.lbl_progress = QLabel("")
        stats_row.addWidget(self.lbl_progress)
        layout.addLayout(stats_row)

        # Progress bar
        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_row.addWidget(self.progress_bar)
        self.lbl_phase = QLabel("")
        self.lbl_phase.setStyleSheet("font-size: 11px; color: #4a5168;")
        progress_row.addWidget(self.lbl_phase)
        layout.addLayout(progress_row)

        # Log
        self.log_out = QTextEdit()
        self.log_out.setReadOnly(True)
        self.log_out.setMaximumHeight(100)
        self.log_out.setStyleSheet("background: #181c2e; color: #f0f4ff; font-size: 12px;")
        layout.addWidget(self.log_out)

        # Bottom nav
        nav = QHBoxLayout()
        self.btn_next = QPushButton(_("download.btn.next"))
        self.btn_next.setEnabled(False)
        self.btn_next.clicked.connect(self._on_next)
        nav.addStretch()
        nav.addWidget(self.btn_next)
        layout.addLayout(nav)

        self._apply_download_theme()

    def _apply_download_theme(self):
        t = THEMES[current_theme()]
        bg = t['bg']
        m = t['muted']
        bd = t['border']
        fg = t['fg']
        ibg = t['input_bg']

        self.lbl_title.setStyleSheet(f"font-size: 14px; font-weight: bold; padding: 2px 0; color: {fg};")
        self.lbl_total.setStyleSheet(f"padding: 4px 8px; background: {ibg}; border: 1px solid {bd}; border-radius: 4px; color: {fg};")
        self.lbl_detail.setStyleSheet(f"padding: 4px 8px; background: {ibg}; border: 1px solid {bd}; border-radius: 4px; color: {fg};")
        self.lbl_phase.setStyleSheet(f"font-size: 11px; color: {m};")
        self.log_out.setStyleSheet(f"background: {ibg}; color: {fg}; font-family: monospace; font-size: 11px; border: 1px solid {bd}; border-radius: 4px; padding: 2px 4px;")
        self.progress_bar.setStyleSheet(f"QProgressBar {{ border: 1px solid {bd}; border-radius: 4px; background: {ibg}; text-align: center; color: {fg}; font-size: 10px; }} QProgressBar::chunk {{ background: {t['accent']}; border-radius: 3px; }}")

        btn_s = f"QPushButton {{ background: {t['button_bg']}; border: 1px solid {bd}; border-radius: 4px; padding: 4px 12px; font-weight: bold; color: {fg}; }} QPushButton:hover {{ background: {t['accent']}; color: white; border-color: {t['accent']}; }}"
        self.btn_back.setStyleSheet(btn_s)
        self.btn_next.setStyleSheet(btn_s)

        stop_s = f"QPushButton {{ background: {t['danger_bg']}; border: 1px solid {t['danger_border']}; color: {t['danger']}; padding: 3px 10px; border-radius: 4px; }} QPushButton:hover {{ background: rgba(227,98,98,0.2); }}"
        self.btn_stop.setStyleSheet(stop_s)

        self.btn_toggle_sources.setStyleSheet(f"""
            QPushButton {{
                background: transparent; border: 1px dashed {t['accent']};
                color: {t['accent']}; font-size: 11px; padding: 2px 10px;
                border-radius: 10px;
            }}
            QPushButton:hover {{ background: rgba(91,141,239,0.12); border: 1px solid {t['accent']}; }}
        """)

        self.src_table.setStyleSheet(f"""
            QTableWidget {{ background: {ibg}; color: {fg}; border: 1px solid {bd}; gridline-color: {bd}; }}
            QTableWidget::item {{ color: {fg}; padding: 2px 4px; }}
            QHeaderView::section {{ background: {bg}; color: {fg}; border: none; border-bottom: 1px solid {bd}; padding: 4px 6px; font-weight: bold; }}
        """)
        self._cell_started_bg = QColor(t['input_bg'])
        self._cell_done_bg = QColor(t['bg'])

    def _set_phase(self, phase: int):
        self._phase = phase
        if phase == self.PHASE_FETCH:
            self.btn_stop.setText(_("download.btn.stop_fetch"))
            t = THEMES[current_theme()]
            self.btn_stop.setStyleSheet(f"background: {t['danger_bg']}; color: {t['danger']}; border: 1px solid {t['danger_border']}; border-radius: 4px; padding: 3px 10px;")
            self.btn_stop.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.lbl_phase.setText(_("download.phase.fetch"))
        else:
            self.btn_stop.setText(_("download.btn.stop"))
            self.btn_stop.setStyleSheet("")
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.lbl_phase.setText("")
            self._progress_timer.stop()

    def _log(self, msg: str):
        self.log_out.append(msg)
        sb = self.log_out.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _cleanup_net(self):
        # Short wait only: NetworkWorker.stop() cancels the pool and the thread
        # quits on its own; a 15 s wait used to freeze the whole window.
        _cleanup_thread(getattr(self, '_net_thread', None), getattr(self, '_net_worker', None))
        self._net_thread = None
        self._net_worker = None

    def _on_stop(self):
        _debug("DownloadPage._on_stop")
        self._stopped = True
        self._net_run += 1  # ignore everything still queued from this run
        self._cleanup_net()
        self._set_phase(self.PHASE_IDLE)
        self._log(_("log.fetch_stopped", count=len(self._entries)))
        self._main.update_status_bar()
        if self._entries:
            self.btn_next.setEnabled(True)

    def _on_next(self):
        self._main.test_page.load_entries(self._entries)
        self._main.set_page(2)

    def fetch_sources(self, sources: list[tuple[str, str]]):
        _debug(f"fetch_sources: start n={len(sources)}")
        self._cleanup_net()
        self._set_phase(self.PHASE_FETCH)
        self._log(_("log.fetch_start", count=len(sources)))
        self._entries = []
        self._completed = False
        self._stopped = False
        self._fetch_start_time = time.time()
        self._sources_ok = 0
        self._sources_total = 0
        self._sources_done = set()
        self._source_rows.clear()
        self._proto_counts.clear()
        self._dedup_keys: set[str] = set()

        n = len(sources)
        self.src_table.setRowCount(n)
        for i, (name, url) in enumerate(sources):
            self._add_source_row_at(i, name, url)

        self.src_group.show()
        self.btn_toggle_sources.show()
        self.btn_toggle_sources.setText(_("download.hide_sources"))
        self.lbl_detail.hide()
        self.lbl_total.show()
        self.btn_next.setEnabled(False)
        self.progress_bar.setMaximum(len(sources))
        self.progress_bar.setValue(0)
        self._progress_last_done = 0
        self._progress_tick = 0
        self._progress_timer.start()
        self.lbl_total.setText(_("download.stats.total", count=0))

        # Run token: queued signals from a stopped worker must not touch the
        # freshly reset table/entries of the next run.
        self._net_run += 1
        run_id = self._net_run
        self._net_worker = NetworkWorker()
        self._net_worker.proxy_parsed.connect(self._on_proxy_parsed)
        self._net_worker.log_signal.connect(self._log)
        self._net_worker.source_started.connect(self._on_source_started)
        self._net_worker.source_status.connect(self._update_source_row)
        self._net_worker.progress_signal.connect(self._on_fetch_progress)
        self._net_worker.finished.connect(self._on_fetch_finished)

        net_worker = self._net_worker
        self._net_thread = QThread()
        net_worker.moveToThread(self._net_thread)
        self._net_thread.started.connect(lambda: net_worker.fetch_all(sources), Qt.ConnectionType.DirectConnection)
        self._net_thread.start()

    def _on_fetch_progress(self, done: int, total: int, name: str, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._net_worker:
                return
        elif run_id != self._net_run:
            return
        self.progress_bar.setValue(done)
        self._progress_last_done = done
        elapsed = time.time() - self._fetch_start_time
        self.lbl_progress.setText(f"{done}/{total} ({elapsed:.0f}s)")
        self._progress_tick = 0
        self._progress_timer.start()

    def _on_progress_tick(self):
        if self._phase != self.PHASE_FETCH:
            self._progress_timer.stop()
            return
        elapsed = time.time() - self._fetch_start_time
        self._progress_tick += 1
        dots = "." * ((self._progress_tick % 3) + 1)
        self.lbl_progress.setText(f"загрузка{dots} ({self._progress_last_done}/{self.progress_bar.maximum()}, {elapsed:.0f}s)")

    def _on_proxy_parsed(self, entries: list[ProxyEntry], run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._net_worker:
                return
        elif run_id != self._net_run:
            return
        added = 0
        for e in entries:
            k = e.key()
            if k in self._dedup_keys:
                continue
            self._dedup_keys.add(k)
            self._entries.append(e)
            added += 1
            p = e.protocol or "?"
            self._proto_counts[p] = self._proto_counts.get(p, 0) + 1
        if added:
            self.lbl_total.setText(_("download.stats.total", count=len(self._entries)))

    def _on_source_started(self, name: str, idx: int, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._net_worker:
                return
        elif run_id != self._net_run:
            return
        row = self._source_rows.get(name)
        if row is None:
            return
        icon_item = self.src_table.item(row, 0)
        if icon_item:
            icon_item.setText("⟳")
        for c in range(3):
            cell = self.src_table.item(row, c)
            if cell:
                cell.setBackground(self._cell_started_bg)

    def _add_source_row_at(self, row: int, name: str, url: str = ""):
        icon_item = QTableWidgetItem("⏳")
        icon_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_table.setItem(row, 0, icon_item)
        name_item = QTableWidgetItem(name[:60])
        name_item.setToolTip(name)
        name_item.setData(Qt.ItemDataRole.UserRole, url)
        self.src_table.setItem(row, 1, name_item)
        count_item = QTableWidgetItem("...")
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_table.setItem(row, 2, count_item)
        self._source_rows[name] = row
        self._sources_total += 1

    def _update_source_row(self, name: str, ok: bool, count: int, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._net_worker:
                return
        elif run_id != self._net_run:
            return
        row = self._source_rows.get(name)
        if row is None:
            return
        icon_item = self.src_table.item(row, 0)
        if icon_item:
            icon_item.setText("✅" if ok else "❌")
        count_item = self.src_table.item(row, 2)
        if count_item:
            count_item.setText(str(count))
        for c in range(3):
            cell = self.src_table.item(row, c)
            if cell:
                cell.setBackground(self._cell_done_bg)
        if ok and name not in self._sources_done:
            self._sources_done.add(name)
            self._sources_ok += 1

    def _toggle_sources(self):
        hidden = self.src_group.isHidden()
        self.src_group.setVisible(hidden)
        self.btn_toggle_sources.setText(
            _("download.hide_sources") if not hidden else _("download.show_sources", count=self.src_table.rowCount())
        )

    def _on_src_table_double_click(self, row: int, col: int):
        if col == 0:
            return
        item = self.src_table.item(row, 1)
        if item is None:
            return
        url = item.data(Qt.ItemDataRole.UserRole)
        if url:
            self._main.source_page._fetch_and_view(url)

    def _on_fetch_finished(self, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._net_worker:
                return
        elif run_id != self._net_run:
            return
        self._cleanup_net()
        if self._stopped:
            # Stop was pressed: never auto-start the next pipeline stage.
            self._stopped = False
            self._set_phase(self.PHASE_IDLE)
            self.src_group.hide()
            self.btn_toggle_sources.show()
            self.btn_toggle_sources.setText(_("download.show_sources", count=self.src_table.rowCount()))
            self.btn_next.setEnabled(len(self._entries) > 0)
            self._main.update_status_bar()
            return
        self._log(_("log.fetch_done", count=len(self._entries)))
        self._set_phase(self.PHASE_IDLE)
        self.src_group.hide()
        self.btn_toggle_sources.setText(_("download.show_sources", count=self.src_table.rowCount()))
        self.btn_toggle_sources.show()

        # Build detail stats
        dur = time.time() - self._fetch_start_time
        protos = self._proto_counts
        proto_parts = []
        order = ["VLESS", "VMess", "VMESS", "Trojan", "SS", "Hy2", "hysteria2", "Shadowsocks"]
        seen = set()
        for p in order:
            if p in protos:
                proto_parts.append(_("download.stats.protocol", proto=p, count=protos[p]))
                seen.add(p)
        for p, c in sorted(protos.items()):
            if p not in seen:
                proto_parts.append(_("download.stats.protocol", proto=p, count=c))
        proto_str = " | ".join(proto_parts) if proto_parts else "—"

        self.lbl_detail.setText(_("download.stats.detail",
            total=len(self._entries),
            sources_ok=_("download.stats.sources_ok", ok=self._sources_ok, total=self._sources_total),
            duration=_("download.stats.duration", secs=f"{dur:.1f}"),
            protos=proto_str))
        self.lbl_detail.show()
        self.lbl_total.hide()

        self.btn_next.setEnabled(len(self._entries) > 0)
        self._main.update_status_bar()
        if self._main._pipeline_mode and self._entries:
            self._main._pipeline_stage = 1
            self._main.test_page.load_entries(self._entries)
            self._main.test_page._on_deep_test()
            self._main.set_page(2)

    def on_enter(self):
        self._main.update_status_bar()

    def on_leave(self):
        self._cleanup_net()

    def retranslate(self):
        self.lbl_title.setText(_("download.title"))
        self.btn_stop.setText(_("download.btn.stop"))
        self.btn_back.setText(_("download.btn.back"))
        self.btn_next.setText(_("download.btn.next"))
        self.src_group.setTitle(_("download.group.sources"))
        self.src_table.setHorizontalHeaderLabels(["", _("download.table.source"), _("download.table.proxies")])
        self.lbl_total.setText(_("download.stats.total", count=len(self._entries)))
        if self._phase == self.PHASE_FETCH:
            self.btn_stop.setText(_("download.btn.stop_fetch"))
            self.lbl_phase.setText(_("download.phase.fetch"))
        else:
            self.lbl_phase.setText("")

    def get_entries(self) -> list[ProxyEntry]:
        return self._entries


class ProxyFilterModel(QSortFilterProxyModel):
    """Filters by protocol and/or security. Set filter props then invalidateFilter()."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_proto: str | None = None
        self._filter_security: str | None = None

    def setFilterProto(self, proto: str | None):
        self._filter_proto = proto
        self.invalidateFilter()

    def setFilterSecurity(self, sec: str | None):
        self._filter_security = sec
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent=QModelIndex()) -> bool:
        if self._filter_proto is None and self._filter_security is None:
            return True
        model = self.sourceModel()
        if not hasattr(model, 'proxies') or source_row >= len(model.proxies):
            return True
        entry = model.proxies[source_row]
        if self._filter_proto and entry.protocol.upper() != self._filter_proto.upper():
            return False
        if self._filter_security and entry.security.upper() != self._filter_security.upper():
            return False
        return True

    def getFilteredEntries(self) -> tuple[list[int], list[ProxyEntry]]:
        """Return (indices_in_source, entries) passing current filter."""
        model = self.sourceModel()
        if not hasattr(model, 'proxies'):
            return [], []
        indices = [i for i in range(len(model.proxies)) if self.filterAcceptsRow(i)]
        return indices, [model.proxies[i] for i in indices]


class TestPage(WizardPage):
    PHASE_IDLE = 0
    PHASE_TEST = 1

    def __init__(self, main):
        super().__init__(main)
        self._main = main
        self._entries = []
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._last_log_time = 0.0
        self._test_start_time = 0.0
        self._phase = self.PHASE_IDLE
        self._test_thread = None
        self._tester = None
        self._test_run = 0
        self._strategy_thread = None
        self._strategy_worker = None
        self._strategy_run = 0
        self._strategy_total = 0
        self._strategy_found = 0
        self._stopped = False
        self._completed = False
        self._test_type: str | None = None
        self._stop_requested = False
        self._last_scroll_time = 0.0
        self._stats_dirty = False
        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(400)
        self._stats_timer.setSingleShot(True)
        self._stats_timer.timeout.connect(self._flush_stats)
        self._lbl_style_set = False

        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        # ── Header ──
        top = QHBoxLayout()
        self.lbl_title = QLabel(_("test.title"))
        top.addWidget(self.lbl_title)
        top.addStretch()
        self.btn_stop = QPushButton(_("test.btn.stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        top.addWidget(self.btn_stop)
        self.btn_back = QPushButton(_("test.btn.back"))
        self.btn_back.clicked.connect(lambda: self._main.set_page(1))
        top.addWidget(self.btn_back)
        layout.addLayout(top)

        # ── Stats cards ──
        cards = QHBoxLayout()
        cards.setSpacing(6)
        self.lbl_total = QLabel(_("test.stats.total", count=0))
        self.lbl_valid = QLabel(_("test.stats.valid", count=0))
        self.lbl_dead = QLabel(_("test.stats.dead", count=0))
        self.lbl_wg = QLabel("")
        self.lbl_wg.setVisible(False)
        self.lbl_rkn = QLabel("")
        cards.addWidget(self.lbl_total)
        cards.addWidget(self.lbl_valid)
        cards.addWidget(self.lbl_dead)
        cards.addWidget(self.lbl_wg)
        cards.addWidget(self.lbl_rkn)
        cards.addStretch()
        self.lbl_current = QLabel("")
        cards.addWidget(self.lbl_current)
        layout.addLayout(cards)

        # ── Action bar ──
        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.btn_deep = QPushButton(_("test.btn.deep"))
        self.btn_deep.clicked.connect(self._on_deep_test)
        actions.addWidget(self.btn_deep)

        self.btn_rkn = QPushButton(_("test.btn.rkn"))
        self.btn_rkn.clicked.connect(self._on_rkn_test)
        actions.addWidget(self.btn_rkn)

        self.btn_continue = QPushButton(_("test.btn.continue"))
        self.btn_continue.clicked.connect(self._on_continue)
        self.btn_continue.setVisible(False)
        actions.addWidget(self.btn_continue)

        actions.addSpacing(10)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            _("test.filter.all"), _("test.filter.tuic"),
            _("test.filter.vless"), _("test.filter.vmess"),
            _("test.filter.trojan"), _("test.filter.ss"),
            _("test.filter.hy2"), _("test.filter.wireguard"),
        ])
        self.filter_combo.currentIndexChanged.connect(self._on_filter_change)
        actions.addWidget(self.filter_combo)

        self.security_combo = QComboBox()
        self.security_combo.addItems([
            _("test.security.all"), _("test.security.tls"),
            _("test.security.reality"), _("test.security.none"),
        ])
        self.security_combo.currentIndexChanged.connect(self._on_security_filter_change)
        actions.addWidget(self.security_combo)

        self.chk_max_latency = QCheckBox(_("test.max_latency"))
        self.chk_max_latency.setChecked(_as_bool(_settings_data.get("max_latency_enabled", False), False))
        self.chk_max_latency.toggled.connect(self._on_max_latency_toggled)
        actions.addWidget(self.chk_max_latency)
        self.spin_max_latency = QSpinBox()
        self.spin_max_latency.setRange(100, 30000)
        self.spin_max_latency.setSuffix(" ms")
        self.spin_max_latency.setValue(_as_int(_settings_data.get("max_latency_ms", 3100), 3100, 100, 30000))
        self.spin_max_latency.setFixedWidth(80)
        self.spin_max_latency.valueChanged.connect(self._on_max_latency_changed)
        actions.addWidget(self.spin_max_latency)

        self.chk_test_doh = QCheckBox("DoH для дозвона (защита от отравленного DNS)")
        self.chk_test_doh.setToolTip("Резолвить адрес сервера прокси через DoH (1.1.1.1 / 8.8.8.8) только если локальный DNS не может резолвить домен (NXDOMAIN). Не переопределяет рабочий локальный резолв, чтобы не ломать прокси.")
        self.chk_test_doh.setChecked(False)
        actions.addWidget(self.chk_test_doh)

        actions.addStretch()

        self.lbl_threads = QLabel(_("test.threads"))
        actions.addWidget(self.lbl_threads)
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 32)
        self.spin_threads.setValue(4)
        self.spin_threads.setFixedWidth(50)
        self.spin_threads.valueChanged.connect(self._on_threads_changed)
        actions.addWidget(self.spin_threads)

        self.btn_delete_dead = QPushButton(_("test.btn.delete_dead"))
        self.btn_delete_dead.clicked.connect(self._on_delete_dead)
        self.btn_delete_dead.setEnabled(False)
        actions.addWidget(self.btn_delete_dead)

        self.btn_delete_untested = QPushButton(_("test.btn.delete_untested"))
        self.btn_delete_untested.clicked.connect(self._on_delete_untested)
        self.btn_delete_untested.setEnabled(False)
        actions.addWidget(self.btn_delete_untested)
        layout.addLayout(actions)

        # ── Bypass row: explained in plain language ──
        aux = QHBoxLayout()
        aux.setSpacing(6)
        self.btn_auto_strategy = QPushButton(_("test.btn.auto_strategy"))
        self.btn_auto_strategy.setToolTip(_("test.auto_strategy.tooltip"))
        self.btn_auto_strategy.clicked.connect(self._on_auto_strategy)
        aux.addWidget(self.btn_auto_strategy)

        self.lbl_check_mode = QLabel(_("test.mode"))
        aux.addWidget(self.lbl_check_mode)
        self.combo_check_mode = QComboBox()
        self.combo_check_mode.addItems([_("test.mode.fair"), _("test.mode.happ")])
        self.combo_check_mode.setCurrentIndex(
            1 if str(_settings_data.get("check_mode", "fair")).lower() == "happ" else 0)
        self.combo_check_mode.setToolTip(_("test.mode.tooltip"))
        self.combo_check_mode.currentIndexChanged.connect(self._on_check_mode_changed)
        aux.addWidget(self.combo_check_mode)

        self.lbl_rkn_quorum = QLabel(_("test.rkn.quorum"))
        aux.addWidget(self.lbl_rkn_quorum)
        self.combo_rkn_quorum = QComboBox()
        self.combo_rkn_quorum.addItems([
            _("test.rkn.quorum.soft"),
            _("test.rkn.quorum.medium"),
            _("test.rkn.quorum.strict"),
        ])
        qidx = _as_int(_settings_data.get("rkn_quorum", 1), 1, 1, 4) - 1
        self.combo_rkn_quorum.setCurrentIndex(min(qidx, 2))
        self.combo_rkn_quorum.setToolTip(_("test.rkn.quorum.tooltip"))
        self.combo_rkn_quorum.currentIndexChanged.connect(self._on_rkn_quorum_changed)
        aux.addWidget(self.combo_rkn_quorum)

        self.lbl_strategy_hint = QLabel(_("test.hint.bypass"))
        self.lbl_strategy_hint.setWordWrap(True)
        aux.addWidget(self.lbl_strategy_hint, 1)
        layout.addLayout(aux)

        # ── Progress ──
        progress_row = QHBoxLayout()
        progress_row.setSpacing(6)
        self.progress_bar = ScanProgressBar()
        self.progress_bar.setFixedHeight(18)
        self.progress_bar.setVisible(False)
        progress_row.addWidget(self.progress_bar, 1)
        self.lbl_phase = QLabel("")
        progress_row.addWidget(self.lbl_phase)
        layout.addLayout(progress_row)

        # ── Table ──
        self.model = ProxyTableModel()
        self.sort_proxy = ProxyFilterModel()
        self.sort_proxy.setSourceModel(self.model)
        self.sort_proxy.setDynamicSortFilter(True)
        self.proxy_table = QTableView()
        self.proxy_table.setModel(self.sort_proxy)
        self.proxy_table.setSortingEnabled(True)
        self.proxy_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.proxy_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.proxy_table.setAlternatingRowColors(True)
        self.proxy_table.horizontalHeader().setStretchLastSection(True)
        self.proxy_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.proxy_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.proxy_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.proxy_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.proxy_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.proxy_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.proxy_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.proxy_table.setColumnWidth(0, 120)
        self.proxy_table.setColumnWidth(3, 60)
        self.proxy_table.setColumnWidth(5, 75)
        self.proxy_table.verticalHeader().setDefaultSectionSize(22)
        self.proxy_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.proxy_table.customContextMenuRequested.connect(self._on_table_context)
        layout.addWidget(self.proxy_table, 1)

        # ── Log (compact) ──
        self.log_out = QTextEdit()
        self.log_out.setReadOnly(True)
        self.log_out.setFixedHeight(100)
        self.log_out.setStyleSheet("font-size: 12px;")
        layout.addWidget(self.log_out)

        # ── Bottom nav ──
        nav = QHBoxLayout()
        nav.addStretch()
        self.btn_export = QPushButton(_("test.btn.export"))
        self.btn_export.setEnabled(True)
        self.btn_export.clicked.connect(lambda: self._main.set_page(3))
        nav.addWidget(self.btn_export)
        layout.addLayout(nav)

        self._apply_test_theme()

    def _apply_test_theme(self):
        t = THEMES[current_theme()]
        m = t['muted']
        mf = t['muted_fg']
        acc = t['accent']
        bg = t['bg']
        ibg = t['input_bg']
        bd = t['border']
        fg = t['fg']
        ok = t['success']
        ok_bg = t['success_bg']
        ok_bd = t['success_border']
        bad = t['danger']
        bad_bg = t['danger_bg']
        bad_bd = t['danger_border']
        warn = t['warning']
        warn_bg = t['warning_bg']
        warn_bd = t['warning_border']

        self.lbl_title.setStyleSheet(f"font-size: 14px; font-weight: bold; padding: 2px 0; color: {fg};")

        stop_d = f"QPushButton {{ background: {bad_bg}; border: 1px solid {bad_bd}; color: {bad}; padding: 3px 10px; border-radius: 4px; }} QPushButton:hover {{ background: rgba(227,98,98,0.2); }} QPushButton:disabled {{ color: {m}; border-color: {bd}; background: transparent; }}"
        self.btn_stop.setStyleSheet(stop_d)

        self._card_total = f"padding: 6px 12px; background: {bg}; border: 1px solid {bd}; border-radius: 6px; font-size: 13px; font-weight: bold; color: {fg}; min-width: 80px;"
        self._card_valid = f"padding: 6px 12px; background: {ok_bg}; border: 1px solid {ok_bd}; border-radius: 6px; font-size: 13px; font-weight: bold; color: {ok}; min-width: 80px;"
        self._card_dead = f"padding: 6px 12px; background: {bad_bg}; border: 1px solid {bad_bd}; border-radius: 6px; font-size: 13px; font-weight: bold; color: {bad}; min-width: 80px;"
        self._card_wg = f"padding: 6px 12px; background: {ibg}; border: 1px solid #76ff03; border-radius: 6px; font-size: 13px; font-weight: bold; color: #76ff03; min-width: 80px;"
        self.lbl_total.setStyleSheet(self._card_total)
        self.lbl_valid.setStyleSheet(self._card_valid)
        self.lbl_dead.setStyleSheet(self._card_dead)
        self.lbl_wg.setStyleSheet(self._card_wg)
        self._card_rkn = f"padding: 4px 10px; background: {ibg}; border: 1px solid {warn}; border-radius: 6px; color: {warn}; font-size: 11px;"
        self.lbl_rkn.setStyleSheet(self._card_rkn)

        self.lbl_current.setStyleSheet(f"padding: 4px 10px; background: {ibg}; border: 1px solid {bd}; border-radius: 6px; color: {acc}; font-size: 11px;")

        btn_d = f"QPushButton {{ background: {t['button_bg']}; border: 1px solid {bd}; border-radius: 4px; padding: 4px 14px; font-weight: bold; color: {fg}; }} QPushButton:hover {{ background: {acc}; color: white; border-color: {acc}; }} QPushButton:disabled {{ color: {m}; border-color: {bd}; background: transparent; }}"
        self.btn_deep.setStyleSheet(btn_d)
        self.btn_back.setStyleSheet(btn_d)
        self.btn_continue.setStyleSheet(f"QPushButton {{ background: {ok_bg}; border: 1px solid {ok_bd}; color: {ok}; padding: 4px 12px; border-radius: 4px; }} QPushButton:hover {{ background: rgba(116,199,160,0.2); }}")

        rkn_d = f"QPushButton {{ background: {warn_bg}; border: 2px solid {warn}; border-radius: 4px; padding: 4px 14px; font-weight: bold; color: {warn}; }} QPushButton:hover {{ background: rgba(235,203,139,0.25); }} QPushButton:disabled {{ color: {m}; border-color: {bd}; background: transparent; }}"
        self.btn_rkn.setStyleSheet(rkn_d)

        del_d = f"QPushButton {{ background: {bad_bg}; border: 1px solid {bad_bd}; color: {bad}; padding: 3px 10px; border-radius: 4px; }} QPushButton:hover {{ background: rgba(227,98,98,0.2); }} QPushButton:disabled {{ color: {m}; border-color: {bd}; background: transparent; }}"
        self.btn_delete_dead.setStyleSheet(del_d)
        self.btn_delete_untested.setStyleSheet(del_d)

        self.lbl_strategy_hint.setStyleSheet(f"font-size: 11px; color: {mf};")
        self.btn_auto_strategy.setStyleSheet(
            f"QPushButton {{ background: {ibg}; border: 1px solid {acc}; color: {acc}; "
            f"padding: 3px 10px; border-radius: 4px; font-weight: bold; }} "
            f"QPushButton:hover {{ background: rgba(91,141,239,0.15); }}"
        )
        self.lbl_threads.setStyleSheet(f"font-size: 11px; color: {mf};")
        self.spin_threads.setStyleSheet(f"QSpinBox {{ font-size: 11px; padding: 2px 4px; background: {ibg}; color: {fg}; border: 1px solid {bd}; border-radius: 3px; }}")
        self.spin_max_latency.setStyleSheet(f"QSpinBox {{ font-size: 11px; padding: 2px 4px; background: {ibg}; color: {fg}; border: 1px solid {bd}; border-radius: 3px; }}")
        self.filter_combo.setStyleSheet(f"QComboBox {{ font-size: 11px; padding: 3px 8px; min-width: 80px; background: {ibg}; color: {fg}; border: 1px solid {bd}; border-radius: 3px; }}")
        self.security_combo.setStyleSheet(f"QComboBox {{ font-size: 11px; padding: 3px 8px; min-width: 80px; background: {ibg}; color: {fg}; border: 1px solid {bd}; border-radius: 3px; }}")

        self.progress_bar.setStyleSheet(f"QProgressBar {{ border: 1px solid {bd}; border-radius: 4px; background: {ibg}; text-align: center; color: {fg}; font-size: 10px; }} QProgressBar::chunk {{ background: {acc}; border-radius: 3px; }}")
        self.lbl_phase.setStyleSheet(f"font-size: 11px; color: {m}; min-width: 60px;")

        sel_alpha = "0.15" if current_theme() == "dark" else "0.1"
        alt_bg = "#1a1f33" if current_theme() == "dark" else "#eae7e0"
        self.proxy_table.setStyleSheet(f"""
            QTableView {{ background: {ibg}; color: {fg}; gridline-color: {bd}; font-size: 12px; }}
            QTableView::item {{ color: {fg}; padding: 2px 4px; }}
            QTableView::item:selected {{ background: rgba({int(acc[1:3],16)},{int(acc[3:5],16)},{int(acc[5:7],16)},{sel_alpha}); }}
            QTableView::item:alternate {{ background: {alt_bg}; }}
            QHeaderView::section {{ background: {bg}; color: {mf}; border: none; border-bottom: 1px solid {bd}; padding: 4px 6px; font-size: 11px; font-weight: bold; }}
        """)

        self.log_out.setStyleSheet(f"background: {ibg}; color: {fg}; font-family: monospace; font-size: 11px; border: 1px solid {bd}; border-radius: 4px; padding: 2px 4px;")

        exp_d = f"QPushButton {{ background: {ok_bg}; border: 2px solid {ok}; border-radius: 4px; padding: 6px 20px; font-weight: bold; font-size: 12px; color: {ok}; }} QPushButton:hover {{ background: rgba(116,199,160,0.2); }} QPushButton:disabled {{ color: {m}; border-color: {bd}; background: transparent; }}"
        self.btn_export.setStyleSheet(exp_d)

    def load_entries(self, entries: list[ProxyEntry]):
        if self._strategy_worker is not None:
            self._cleanup_strategy()
            self.btn_auto_strategy.setText(_("test.btn.auto_strategy"))
        # Plain HTTP/SOCKS proxies are dropped on load: unencrypted, never
        # tested, never exported.
        plain = [e for e in entries if is_plain_proxy(e.protocol)]
        if plain:
            entries = [e for e in entries if not is_plain_proxy(e.protocol)]
            self._log(f"⚠ Пропущено открытых прокси без шифрования: {len(plain)}")
        seen_uris = set()
        seen_keys = {}
        deduped = []
        for e in entries:
            if e.uri in seen_uris:
                continue
            seen_uris.add(e.uri)
            k = e.key()
            if k in seen_keys:
                continue
            seen_keys[k] = e
            deduped.append(e)
        self._entries = deduped
        self._test_run += 1  # any in-flight test now refers to old rows
        self._valid_cnt = 0
        self._dead_cnt = 0
        self.filter_combo.setCurrentIndex(0)
        self.security_combo.setCurrentIndex(0)
        self.model.clear()
        self.model.add_proxies(deduped)
        self._update_stats()
        has = len(deduped) > 0
        self.btn_deep.setEnabled(has)
        self.btn_rkn.setEnabled(has)

    def _set_phase(self, phase: int):
        self._phase = phase
        if phase == self.PHASE_TEST:
            self.btn_stop.setText(_("test.btn.stop_test"))
            t = THEMES[current_theme()]
            self.btn_stop.setStyleSheet(f"background: {t['danger_bg']}; color: {t['danger']}; border: 1px solid {t['danger_border']}; border-radius: 4px; padding: 3px 10px;")
            self.btn_stop.setEnabled(True)
            self.btn_deep.setEnabled(False)
            self.btn_rkn.setEnabled(False)
            self.btn_delete_dead.setEnabled(False)
            self.btn_continue.setVisible(False)
            self.progress_bar.setVisible(True)
            self.lbl_phase.setText(_("test.phase.test"))
            self.progress_bar.start_scan()
        else:
            self.btn_stop.setText(_("test.btn.stop"))
            self._apply_test_theme()
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.lbl_phase.setText("")
            self.progress_bar.stop_scan()
            has_entries = len(self._entries) > 0
            self.btn_deep.setEnabled(has_entries)
            self.btn_rkn.setEnabled(has_entries)
            self.btn_delete_dead.setEnabled(self._dead_cnt > 0)

    def _log(self, msg: str):
        self.log_out.append(msg)
        sb = self.log_out.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _cleanup_test(self):
        _cleanup_thread(getattr(self, '_test_thread', None), getattr(self, '_tester', None))
        self._test_thread = None
        self._tester = None

    def _on_stop(self):
        _debug("TestPage._on_stop")
        self.sort_proxy.setDynamicSortFilter(True)
        self._flush_stats()
        self._stats_timer.stop()
        self._stop_requested = True
        self._test_run += 1  # drop results still queued from the stopped tester
        self._cleanup_test()
        self._cleanup_strategy()
        self._log(_("log.test_stopped"))
        self.model.dedup_by_key()
        self._entries = self.model.proxies
        self._stopped = True
        self._set_phase(self.PHASE_IDLE)
        if self._valid_cnt > 0:
            self.btn_export.setEnabled(True)
        if self._test_type and self._count_untested() > 0:
            self.btn_continue.setVisible(True)
        self._main.update_status_bar()

    def _count_untested(self) -> int:
        if self._test_type == "rkn":
            return sum(1 for e in self._entries if not e.rkn_tested)
        return sum(1 for e in self._entries if not e.deep_tested)

    def _count_untested_all(self) -> int:
        return sum(1 for e in self._entries
                   if e.protocol not in ('WIREGUARD', 'WG')
                   and not (e.tcp_tested or e.deep_tested or e.rkn_tested))

    def _on_continue(self):
        if not self._test_type or not self._entries:
            return
        if self._test_type == "rkn":
            remaining = [(i, e) for i, e in enumerate(self._entries) if not e.rkn_tested]
        else:
            remaining = [(i, e) for i, e in enumerate(self._entries) if not e.deep_tested]
        if not remaining:
            self.btn_continue.setVisible(False)
            return
        indices, entries = zip(*remaining) if remaining else ([], [])
        self._log(_("log.test_resumed", count=len(entries)))
        self._run_test(rkn=(self._test_type == "rkn"), subset=list(entries), subset_indices=list(indices))

    def _on_deep_test(self):
        if self._phase == self.PHASE_TEST:
            return
        indices, filtered = self.sort_proxy.getFilteredEntries()
        if not filtered:
            return
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._test_type = "deep"
        self._run_test(subset=filtered, subset_indices=indices)

    def _on_rkn_test(self):
        if self._phase == self.PHASE_TEST:
            return
        indices, filtered = self.sort_proxy.getFilteredEntries()
        if not filtered:
            return
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._test_type = "rkn"
        self._run_test(rkn=True, subset=filtered, subset_indices=indices)

    def _on_rkn_quorum_changed(self, idx: int):
        _settings_data["rkn_quorum"] = max(1, min(4, idx + 1))
        _save_settings(_settings_data)

    def _on_check_mode_changed(self, idx: int):
        _settings_data["check_mode"] = "happ" if idx == 1 else "fair"
        _save_settings(_settings_data)

    def _cleanup_strategy(self):
        self._strategy_run += 1  # ignore queued signals from the stopped worker
        _cleanup_thread(self._strategy_thread, self._strategy_worker)
        self._strategy_thread = None
        self._strategy_worker = None

    def _start_strategy(self, items):
        self._strategy_run += 1
        run_id = self._strategy_run
        worker = StrategyWorker(
            items,
            max_candidates=3,
            max_workers=max(1, min(3, self.spin_threads.value())),
            use_doh=self.chk_test_doh.isChecked(),
            dns_list=DEFAULT_DOH,
        )
        worker.trial_signal.connect(self._on_strategy_trial)
        worker.found_signal.connect(self._on_strategy_found)
        worker.failed_signal.connect(self._on_strategy_failed)
        worker.finished.connect(self._on_strategy_finished)
        self._strategy_worker = worker
        self._strategy_thread = QThread()
        worker.moveToThread(self._strategy_thread)
        self._strategy_thread.started.connect(worker.run, Qt.ConnectionType.DirectConnection)
        self._strategy_thread.start()
        self._strategy_total = len(items)
        self._strategy_found = 0
        self.btn_auto_strategy.setText(_("test.btn.auto_strategy.stop"))
        self._log(_("test.auto_strategy.started", count=len(items)))

    def _on_auto_strategy(self):
        if self._strategy_worker is not None:
            self._log(_("test.auto_strategy.stopping"))
            self._cleanup_strategy()
            self.btn_auto_strategy.setText(_("test.btn.auto_strategy"))
            return
        if self._phase == self.PHASE_TEST:
            QMessageBox.information(self, _("msg.info"), _("test.auto_strategy.wait"))
            return
        indices, entries = self.sort_proxy.getFilteredEntries()
        items = [
            (i, e) for i, e in zip(indices, entries)
            if e.protocol not in ('WIREGUARD', 'WG')
            and not (e.deep_ok or e.rkn_ok)
            and not e.strategy_name
            and (e.tcp_tested or e.deep_tested or e.rkn_tested or e.tcp_ok)
        ]
        if not items:
            QMessageBox.information(self, _("msg.info"), _("test.auto_strategy.none"))
            return
        self._start_strategy(items[:300])

    def _find_bypass_for_row(self, row: int):
        if not (0 <= row < len(self._entries)):
            return
        entry = self._entries[row]
        if entry.protocol in ('WIREGUARD', 'WG') or entry.deep_ok or entry.rkn_ok:
            QMessageBox.information(self, _("msg.info"), _("test.auto_strategy.none"))
            return
        if self._strategy_worker is not None:
            self._log(_("test.auto_strategy.stopping"))
            self._cleanup_strategy()
        self._start_strategy([(row, entry)])

    def _on_strategy_trial(self, row, host, name, run_id=None):
        if run_id is None:
            if self.sender() is not self._strategy_worker:
                return
        elif run_id != self._strategy_run:
            return
        self._log(_("test.auto_strategy.trying",
                    host=host or "?",
                    strategy=strategy_label(name, current_lang())))

    def _on_strategy_found(self, row, name, overrides, latency, run_id=None):
        if run_id is None:
            if self.sender() is not self._strategy_worker:
                return
        elif run_id != self._strategy_run:
            return
        host = "?"
        if 0 <= row < len(self._entries):
            entry = self._entries[row]
            host = entry.host or host
            entry.strategy_name = name
            entry.strategy_overrides = overrides
            if latency:
                entry.latency_ms = latency
            self.model.dataChanged.emit(self.model.index(row, 0), self.model.index(row, 6))
        self._strategy_found += 1
        self._log(_("test.auto_strategy.found",
                    host=host,
                    strategy=strategy_label(name, current_lang()),
                    lat=int(latency or 0)))

    def _on_strategy_failed(self, row, host, run_id=None):
        if run_id is None:
            if self.sender() is not self._strategy_worker:
                return
        elif run_id != self._strategy_run:
            return
        self._log(_("test.auto_strategy.not_found", host=host or "?"))

    def _on_strategy_finished(self, run_id=None):
        if run_id is None:
            if self.sender() is not self._strategy_worker:
                return
        elif run_id != self._strategy_run:
            return
        self._log(_("test.auto_strategy.done",
                    found=self._strategy_found, total=self._strategy_total))
        self._cleanup_strategy()
        self.btn_auto_strategy.setText(_("test.btn.auto_strategy"))
        self._main.update_status_bar()

    def _on_delete_dead(self):
        if self._phase == self.PHASE_TEST:
            QMessageBox.information(self, _("msg.info"), _("test.delete_need_stop"))
            return
        if self._dead_cnt == 0:
            QMessageBox.information(self, _("msg.info"), _("log.no_dead"))
            return
        alive = [
            e for e in self._entries
            if not (e.tcp_tested or e.deep_tested or e.rkn_tested)
               or (e.rkn_tested and e.rkn_ok)
               or (not e.rkn_tested and (e.tcp_ok or e.deep_ok))
        ]
        removed = len(self._entries) - len(alive)
        if removed == 0:
            QMessageBox.information(self, _("msg.info"), _("log.no_dead_to_delete"))
            return
        self._entries = alive
        self._valid_cnt = sum(1 for e in alive if e.tcp_ok or e.deep_ok or e.rkn_ok)
        self._dead_cnt = 0
        self.model.clear()
        self.model.add_proxies(self._entries)
        self._update_stats()
        self.btn_delete_dead.setEnabled(False)
        self.btn_rkn.setEnabled(len(self._entries) > 0)
        self._log(_("log.deleted_dead", count=removed))

    def _on_delete_untested(self):
        if self._phase == self.PHASE_TEST:
            QMessageBox.information(self, _("msg.info"), _("test.delete_need_stop"))
            return
        kept = [
            e for e in self._entries
            if e.protocol in ('WIREGUARD', 'WG')
            or (e.tcp_tested or e.deep_tested or e.rkn_tested)
        ]
        removed = len(self._entries) - len(kept)
        if removed == 0:
            QMessageBox.information(self, _("msg.info"), _("log.no_untested_to_delete"))
            return
        self._entries = kept
        self._valid_cnt = sum(1 for e in kept if e.tcp_ok or e.deep_ok or e.rkn_ok)
        self._dead_cnt = sum(1 for e in kept
                             if (e.tcp_tested or e.deep_tested or e.rkn_tested)
                             and not (e.tcp_ok or e.deep_ok or e.rkn_ok))
        self.model.clear()
        self.model.add_proxies(self._entries)
        self._update_stats()
        self.btn_delete_dead.setEnabled(self._dead_cnt > 0)
        self.btn_delete_untested.setEnabled(self._count_untested_all() > 0)
        self.btn_rkn.setEnabled(len(self._entries) > 0)
        self.btn_export.setEnabled(self._valid_cnt > 0)
        self._log(_("log.deleted_untested", count=removed))

    def _on_threads_changed(self, value):
        if self._phase != self.PHASE_TEST or not self._tester or not self._test_type:
            return
        if self._test_type == "rkn":
            remaining = [(i, e) for i, e in enumerate(self._entries) if not e.rkn_tested]
        else:
            remaining = [(i, e) for i, e in enumerate(self._entries) if not e.deep_tested]
        if not remaining:
            return
        indices, entries = zip(*remaining)
        self._tester.stop()
        _cleanup_thread(self._test_thread, self._tester)
        self._test_thread = None
        self._tester = None
        self._log(f"🔄 потоков: {value}, продолжаю {len(entries)}...")
        self._run_test(rkn=(self._test_type == "rkn"),
                       subset=list(entries), subset_indices=list(indices))

    def _run_test(self, rkn: bool = False, subset: list[ProxyEntry] | None = None, subset_indices: list[int] | None = None):
        if self._strategy_worker is not None:
            self._cleanup_strategy()
            self.btn_auto_strategy.setText(_("test.btn.auto_strategy"))
        base = subset if subset is not None else self._entries
        base_indices = subset_indices if subset_indices is not None else list(range(len(base)))
        # Always keep model-row indices paired with entries: the tester reports
        # rows back, so dropping WireGuard entries without dropping their
        # indices would mark the wrong proxies.
        pairs = [(i, e) for i, e in zip(base_indices, base)
                 if e.protocol not in ('WIREGUARD', 'WG')]
        # Plain proxies are never tested: no encryption, nothing to measure.
        before_plain = len(pairs)
        pairs = [(i, e) for i, e in pairs if not is_plain_proxy(e.protocol)]
        plain_skipped = before_plain - len(pairs)
        if plain_skipped:
            self._log(f"⚠ Пропущено открытых прокси без шифрования: {plain_skipped}")
        if not pairs:
            self._log("⚠ Нет подходящих узлов для проверки")
            return
        target_indices = [i for i, _ in pairs]
        target = [e for _, e in pairs]
        skipped_wg = sum(1 for e in base if e.protocol in ('WIREGUARD', 'WG'))
        if skipped_wg:
            self._log(f"⚠ Пропущено WireGuard: {skipped_wg}")
        self._stop_requested = False
        self._test_start_time = time.time()
        self._set_phase(self.PHASE_TEST)
        self.progress_bar.setMaximum(len(target))
        self.progress_bar.setValue(0)
        self.sort_proxy.setDynamicSortFilter(False)
        self._last_scroll_time = 0.0
        self._stats_dirty = False
        self._lbl_style_set = False

        self._test_run += 1
        run_id = self._test_run
        threads = max(1, self.spin_threads.value())
        self._tester = TesterWorker(rkn=rkn, test_threads=threads, deep_threads=threads,
                                    use_doh=self.chk_test_doh.isChecked(), dns_list=DEFAULT_DOH,
                                    rkn_quorum=self.combo_rkn_quorum.currentIndex() + 1,
                                    check_mode=str(_settings_data.get("check_mode", "fair")))
        # Run token: results from a stopped/superseded tester are dropped instead
        # of being written into rows of the next run.
        self._tester.result_signal.connect(self._on_test_result)
        self._tester.testing_signal.connect(self._on_testing_start)
        self._tester.progress_signal.connect(self._on_test_progress)
        self._tester.count_signal.connect(self._on_test_count)
        self._tester.log_signal.connect(self._log)
        self._tester.geo_signal.connect(self._on_geo_result)
        self._tester.finished.connect(self._on_test_finished)

        tester = self._tester
        self._test_thread = QThread()
        tester.moveToThread(self._test_thread)
        self._test_thread.started.connect(
            lambda: tester.test_batch(target, target_indices),
            Qt.ConnectionType.DirectConnection,
        )
        self._test_thread.start()

    def _on_testing_start(self, row: int, info: str, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._tester:
                return
        elif run_id != self._test_run:
            return
        now = time.time()
        if now - self._last_scroll_time >= 0.2:
            proxy_idx = self.sort_proxy.mapFromSource(self.model.index(row, 0))
            if proxy_idx.isValid():
                if self.proxy_table.visualRect(proxy_idx).isValid():
                    self.proxy_table.scrollTo(proxy_idx)
                # Select the *proxy* row: with an active filter source row != view row.
                self.proxy_table.selectRow(proxy_idx.row())
            self._last_scroll_time = now

    def _on_test_result(self, row: int, ok: bool, latency: float, error: str, ttype: int, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._tester:
                return
        elif run_id != self._test_run:
            return
        if ok and _as_bool(_settings_data.get("max_latency_enabled"), False) \
                and latency > _as_int(_settings_data.get("max_latency_ms", 3100), 3100, 100, 30000):
            ok = False
        self.model.update_entry(row, ok, latency, error, ttype)
        if ok:
            self._valid_cnt += 1
        else:
            self._dead_cnt += 1
        self._stats_dirty = True
        self._stats_timer.start()
        now = time.time()
        if now - self._last_scroll_time >= 0.2:
            proxy_idx = self.sort_proxy.mapFromSource(self.model.index(row, 0))
            if proxy_idx.isValid():
                if self.proxy_table.visualRect(proxy_idx).isValid():
                    self.proxy_table.scrollTo(proxy_idx)
                self.proxy_table.selectRow(proxy_idx.row())
            self._last_scroll_time = now
        if 0 <= row < len(self._entries):
            e = self._entries[row]
            if ttype == 2:
                kind = "SITE"
                mark = "🛡" if ok else "✗"
                detail = ""
            else:
                kind = "TCP" if ttype == 0 else "DEEP"
                mark = "✓" if ok else "✗"
                detail = ""
            ping = f" {latency:.0f}ms" if latency else ""
            self.lbl_current.setText(f"{mark} [{kind}] {e.protocol} {e.host}:{e.port}{ping}{detail}")
            if not self._lbl_style_set:
                t = THEMES[current_theme()]
                color = t['success'] if ok else t['danger']
                if ttype == 2:
                    color = t['warning'] if ok else t['danger']
                self.lbl_current.setStyleSheet(f"padding: 4px 10px; background: {t['input_bg']}; border: 1px solid {t['border']}; border-radius: 6px; color: {color}; font-size: 11px;")
                self._lbl_style_set = True

    def _on_test_count(self, c: int, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._tester:
                return
        elif run_id != self._test_run:
            return
        self.progress_bar.setValue(c)

    def _on_test_progress(self, done: int, total: int, threads: int, mode: str, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._tester:
                return
        elif run_id != self._test_run:
            return
        now = time.time()
        if now - self._last_log_time > 0.5:
            self._log(_("event.threads", mode=mode, done=done, total=total, threads=threads))
            self._last_log_time = now
        if not self.lbl_current.text():
            self.lbl_current.setText(_("event.test_progress", mode=mode, done=done, total=total, pct=done*100//max(total,1)))
        elapsed = now - self._test_start_time
        if done > 0 and elapsed > 1:
            pct = done * 100 // max(total, 1)
            eta_secs = (total - done) / (done / elapsed)
            self.lbl_phase.setText(f"{_('test.phase.test')} · {pct}% · {_('event.eta', eta=self._format_eta(eta_secs))}")

    def _format_eta(self, secs: float) -> str:
        secs = int(max(0, secs))
        ru = current_lang() == 'ru'
        sec_u = "с" if ru else "s"
        min_u = "м" if ru else "m"
        h_u = "ч" if ru else "h"
        if secs < 60:
            return f"{secs} {sec_u}"
        m, s = divmod(secs, 60)
        if m < 60:
            return f"{m} {min_u} {s:02d} {sec_u}"
        h, m = divmod(m, 60)
        return f"{h} {h_u} {m} {min_u}"

    def _on_max_latency_toggled(self, checked: bool):
        _settings_data["max_latency_enabled"] = checked
        _save_settings(_settings_data)

    def _on_max_latency_changed(self, value: int):
        _settings_data["max_latency_ms"] = value
        _save_settings(_settings_data)

    def _on_geo_result(self, row: int, country: str, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._tester:
                return
        elif run_id != self._test_run:
            return
        idx = self.model.index(row, 4)
        self.model.dataChanged.emit(idx, idx)

    def _on_test_finished(self, run_id: int | None = None):
        if run_id is None:
            if self.sender() is not self._tester:
                return
        elif run_id != self._test_run:
            return
        self.sort_proxy.setDynamicSortFilter(True)
        self._flush_stats()
        self._stats_timer.stop()
        self._cleanup_test()
        if self._stop_requested:
            self._stop_requested = False
            return
        self._stopped = False
        self._completed = True
        self._update_stats()
        self._set_phase(self.PHASE_IDLE)
        self.btn_delete_dead.setEnabled(self._dead_cnt > 0)
        self._log(_("log.test_done", valid=self._valid_cnt, total=len(self._entries)))
        tray = getattr(self._main, "_tray", None)
        if tray is not None and QSystemTrayIcon.isSystemTrayAvailable():
            try:
                tray.showMessage(
                    "Proxy Skitchen",
                    _("notify.test_done", valid=self._valid_cnt, total=len(self._entries)),
                    QSystemTrayIcon.Information, 3000,
                )
            except Exception:
                pass
        self._main.update_status_bar()
        if self._main._pipeline_mode:
            if self._main._pipeline_stage == 1:
                self._main._pipeline_stage = 2
                alive = [
                    e for e in self._entries
                    if not (e.tcp_tested or e.deep_tested or e.rkn_tested)
                       or (e.rkn_tested and e.rkn_ok)
                       or (not e.rkn_tested and (e.tcp_ok or e.deep_ok))
                ]
                removed = len(self._entries) - len(alive)
                if removed:
                    self._entries = alive
                    self._valid_cnt = len(alive)
                    self._dead_cnt = 0
                    self.model.clear()
                    self.model.add_proxies(self._entries)
                    self._update_stats()
                    self._log(f"🗑 удалено мёртвых: {removed}")
                if any(e.tcp_ok or e.deep_ok for e in self._entries):
                    self._log(_("log.rkn_started"))
                    self._on_rkn_test()
                else:
                    self._main._pipeline_mode = False
                    self._save_pipeline_result()
            else:
                self._main._pipeline_mode = False
                self._save_pipeline_result()

    def _save_pipeline_result(self):
        from .exporters import format_hiddify
        title = self._main.export_page.sub_title_input.text().strip() or "My Subscription"
        clean = _as_bool(_settings_data.get("clean_uris", True))
        content = format_hiddify(self._entries, include_failed=False, title=title, clean=clean)
        if not content.strip():
            QMessageBox.information(self, _("msg.info"), _("msg.no_data_text"))
            return
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        path = os.path.join(DESKTOP_DIR, f"hiddify_sub_{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self._log(f"✅ Hiddify подпись сохранена: {path}")
        do_gh = self._main.source_page.chk_github_push.isChecked()
        repo = _settings_data.get("gh_repo", "")
        file_path = _settings_data.get("gh_file", "")
        tokens = _get_tokens()

        def _show_done():
            QMessageBox.information(self, _("msg.done"),
                f"✅ Готово!\n\n"
                f"Файл: {path}\n\n"
                f"Импортируй в Hiddify: Меню → Подписки → (+) → Выбери файл")

        if not do_gh:
            _show_done()
            return
        self._log("📤 GitHub push...")
        if not repo or not file_path:
            self._log("❌ GitHub: не указан репозиторий или файл")
            _show_done()
            return
        if not tokens:
            self._log("❌ GitHub: нет токена")
            _show_done()
            return

        def _push():
            return self._do_github_push(content, repo, file_path, tokens[0])

        def _pushed(result, error):
            if error is not None:
                self._log(f"❌ GitHub: {str(error)[:60]}")
                _show_done()
                return
            ok, err, branch = result
            if ok:
                # Persist on the GUI thread only: the worker must not write
                # settings.json concurrently with the UI.
                _settings_data["gh_branch"] = branch
                _save_settings(_settings_data)
                self._log(f"✅ GitHub: файл обновлён — {repo}@{branch}/{file_path}")
                if err:
                    self._log(f"⚠ {err}")
            else:
                self._log(f"❌ GitHub: {err}")
            _show_done()

        BackgroundCall(_push, _pushed, parent=self)

    def _do_github_push(self, content: str, repo: str, file_path: str, token: str) -> tuple[bool, str, str]:
        import urllib.request, urllib.error, base64, json
        api_base = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "proxy-skitchen",
        }
        # Write and advertise the repo's real default branch: hardcoding "main"
        # produced dead jsDelivr links for master-based repos.
        branch = (_settings_data.get("gh_branch") or "").strip()
        try:
            req = urllib.request.Request(f"https://api.github.com/repos/{repo}", headers=headers)
            repo_info = json.loads(urllib.request.urlopen(req, timeout=10).read())
            branch = repo_info.get("default_branch") or branch or "main"
        except Exception:
            branch = branch or "main"
        try:
            req = urllib.request.Request(api_base, headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            sha = data.get("sha", "")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                sha = ""
            else:
                return False, f"API error: {e.code}", branch
        except Exception as e:
            return False, str(e)[:60], branch
        body = {
            "message": f"Update subscription {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        }
        if sha:
            body["sha"] = sha
        if branch:
            body["branch"] = branch
        try:
            data_bytes = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(api_base, data=data_bytes, headers=headers, method="PUT")
            resp = urllib.request.urlopen(req, timeout=15)
            purged = self._purge_jsdelivr_cdn(repo, file_path, branch)
            return True, "" if purged else "CDN purge failed", branch
        except Exception as e:
            return False, str(e)[:60], branch

    def _on_filter_change(self, idx: int):
        proto_map = [None, "TUIC", "VLESS", "VMESS", "Trojan", "SS", "Hy2", "WIREGUARD"]
        proto = proto_map[idx] if 0 < idx < len(proto_map) else None
        self.sort_proxy.setFilterProto(proto)
        self._update_stats()

    def _on_security_filter_change(self, idx: int):
        sec_map = [None, "tls", "reality", "none"]
        sec = sec_map[idx] if 0 < idx < len(sec_map) else None
        self.sort_proxy.setFilterSecurity(sec)
        self._update_stats()

    def _flush_stats(self):
        if self._stats_dirty:
            self._stats_dirty = False
            self._update_stats()

    def _update_stats(self):
        _, entries = self.sort_proxy.getFilteredEntries()
        total = len(entries)
        rkn_ok = sum(1 for e in entries if e.rkn_tested and e.rkn_ok)
        rkn_total = sum(1 for e in entries if e.rkn_tested)
        wg_cnt = sum(1 for e in self._entries if e.protocol in ('WIREGUARD', 'WG'))
        self.lbl_total.setText(f"Всего: {total}")
        if self._test_type is None:
            self.lbl_valid.setText(f"Живых: ?")
            self.lbl_dead.setText(f"Мёртвых: ?")
            self.lbl_valid.setStyleSheet(self._card_total)
            self.lbl_dead.setStyleSheet(self._card_total)
        else:
            self.lbl_valid.setText(f"Живых: {self._valid_cnt}")
            self.lbl_dead.setText(f"Мёртвых: {self._dead_cnt}")
            self.lbl_valid.setStyleSheet(self._card_valid if self._valid_cnt > 0 else self._card_total)
            self.lbl_dead.setStyleSheet(self._card_dead if self._dead_cnt > 0 else self._card_total)
        if wg_cnt:
            self.lbl_wg.setText(f"🔒 WG: {wg_cnt}")
            self.lbl_wg.setVisible(True)
        else:
            self.lbl_wg.setVisible(False)
        if rkn_total:
            self.lbl_rkn.setText(f"🛡 Сайты: {rkn_ok}/{rkn_total}")
            self.lbl_rkn.setVisible(True)
        else:
            self.lbl_rkn.setVisible(False)
        self.btn_delete_untested.setEnabled(
            self._phase != self.PHASE_TEST and self._count_untested_all() > 0)

    def _on_table_context(self, pos):
        idx = self.proxy_table.indexAt(pos)
        if not idx.isValid():
            return
        src_row = self.sort_proxy.mapToSource(idx).row()
        entry = self._entries[src_row]
        menu = QMenu()
        menu.addAction(_("test.context.copy_uri"), lambda: QApplication.clipboard().setText(entry.uri))
        if entry.protocol not in ('WIREGUARD', 'WG') and not (entry.deep_ok or entry.rkn_ok):
            menu.addAction(_("test.context.find_bypass"), lambda: self._find_bypass_for_row(src_row))
        tcp_mark = "✅" if entry.tcp_ok else "❌"
        deep_mark = "⚡" if entry.deep_ok else "—"
        rkn_mark = "🛡" if entry.rkn_ok else ("—" if not entry.rkn_tested else "❌")
        ping_str = f"{entry.latency_ms:.0f}ms" if entry.latency_ms else "—"
        lines = [
            f"{entry.display_protocol()} {entry.host}:{entry.port}",
            f"SNI: {entry.sni or '—'}",
            f"Страна: {entry.country or '—'}",
            f"TCP: {tcp_mark}  Deep: {deep_mark}  Сайты: {rkn_mark}  Пинг: {ping_str}",
            f"Источник: {entry.source or '—'}",
            f"{_('test.context.strategy')}: "
            f"{strategy_label(entry.strategy_name, current_lang()) if entry.strategy_name else '—'}",
        ]
        if entry.rkn_results:
            lines.append("")
            lines.append("Проверка сайтов:")
            for r in entry.rkn_results:
                status = "✅" if r.get("ok") else "❌"
                lat = f" {r['latency']:.0f}ms" if r.get("latency") else ""
                lines.append(f"  {status} {r['name']} ({r['domain']}){lat}")
        details = "\n".join(lines)
        menu.addAction(_("test.context.details"), lambda: QMessageBox.information(self, _("test.context.details"), details))
        menu.exec_(self.proxy_table.mapToGlobal(pos))

    def on_enter(self):
        self._update_stats()
        self._main.update_status_bar()

    def on_leave(self):
        self._cleanup_test()
        self._cleanup_strategy()

    def retranslate(self):
        self.lbl_title.setText(_("test.title"))
        self.btn_stop.setText(_("test.btn.stop"))
        self.btn_back.setText(_("test.btn.back"))
        self.lbl_total.setText(_("test.stats.total", count=len(self._entries)))
        self.lbl_valid.setText(_("test.stats.valid", count=self._valid_cnt))
        self.lbl_dead.setText(_("test.stats.dead", count=self._dead_cnt))
        self.btn_deep.setText(_("test.btn.deep"))
        self.btn_rkn.setText(_("test.btn.rkn"))
        self.btn_auto_strategy.setText(
            _("test.btn.auto_strategy.stop") if self._strategy_worker is not None
            else _("test.btn.auto_strategy"))
        self.btn_auto_strategy.setToolTip(_("test.auto_strategy.tooltip"))
        self.lbl_rkn_quorum.setText(_("test.rkn.quorum"))
        self.combo_rkn_quorum.blockSignals(True)
        current_q = self.combo_rkn_quorum.currentIndex()
        self.combo_rkn_quorum.clear()
        self.combo_rkn_quorum.addItems([
            _("test.rkn.quorum.soft"),
            _("test.rkn.quorum.medium"),
            _("test.rkn.quorum.strict"),
        ])
        self.combo_rkn_quorum.setCurrentIndex(min(current_q, 2))
        self.combo_rkn_quorum.blockSignals(False)
        self.combo_rkn_quorum.setToolTip(_("test.rkn.quorum.tooltip"))
        self.lbl_check_mode.setText(_("test.mode"))
        self.combo_check_mode.blockSignals(True)
        current_mode = self.combo_check_mode.currentIndex()
        self.combo_check_mode.clear()
        self.combo_check_mode.addItems([_("test.mode.fair"), _("test.mode.happ")])
        self.combo_check_mode.setCurrentIndex(min(current_mode, 1))
        self.combo_check_mode.blockSignals(False)
        self.combo_check_mode.setToolTip(_("test.mode.tooltip"))
        self.lbl_strategy_hint.setText(_("test.hint.bypass"))
        self.btn_continue.setText(_("test.btn.continue"))
        self.btn_delete_dead.setText(_("test.btn.delete_dead"))
        self.btn_delete_untested.setText(_("test.btn.delete_untested"))
        self.btn_export.setText(_("test.btn.export"))
        self.chk_max_latency.setText(_("test.max_latency"))
        self.model.rebuild_headers()
        # Rebuild filter combos
        current = self.filter_combo.currentIndex()
        self.filter_combo.blockSignals(True)
        self.filter_combo.clear()
        self.filter_combo.addItems([
            _("test.filter.all"), _("test.filter.tuic"),
            _("test.filter.vless"), _("test.filter.vmess"),
            _("test.filter.trojan"), _("test.filter.ss"),
            _("test.filter.hy2"), _("test.filter.wireguard"),
        ])
        self.filter_combo.setCurrentIndex(min(current, self.filter_combo.count() - 1))
        self.filter_combo.blockSignals(False)
        sec_current = self.security_combo.currentIndex()
        self.security_combo.blockSignals(True)
        self.security_combo.clear()
        self.security_combo.addItems([
            _("test.security.all"), _("test.security.tls"),
            _("test.security.reality"), _("test.security.none"),
        ])
        self.security_combo.setCurrentIndex(min(sec_current, self.security_combo.count() - 1))
        self.security_combo.blockSignals(False)
        self.lbl_threads.setText(_("test.threads"))
        if self._phase == self.PHASE_TEST:
            self.btn_stop.setText(_("test.btn.stop_test"))
            self.lbl_phase.setText(_("test.phase.test"))
        else:
            self.lbl_phase.setText("")
        self._update_stats()
        self.proxy_table.viewport().update()

    def get_entries(self) -> list[ProxyEntry]:
        _, entries = self.sort_proxy.getFilteredEntries()
        return entries


class ExportPage(WizardPage):
    def __init__(self, main):
        super().__init__(main)
        self._main = main
        # Typing in a QLineEdit must not rebuild the whole export and rewrite
        # settings.json on every keystroke.
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(400)
        self._save_timer.timeout.connect(self._flush_settings)
        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        self._preview_timer.setInterval(150)
        self._preview_timer.timeout.connect(self._render_preview)

        root = QVBoxLayout(self)
        root.setSpacing(4)
        root.setContentsMargins(6, 4, 6, 4)

        # ── Header ──
        hdr = QHBoxLayout()
        self.lbl_title = QLabel(_("export.title"))
        hdr.addWidget(self.lbl_title)
        hdr.addStretch()
        self.btn_back = QPushButton(_("export.btn.back"))
        self.btn_back.clicked.connect(lambda: self._main.set_page(2))
        hdr.addWidget(self.btn_back)
        root.addLayout(hdr)

        # ── Stats ──
        self.stats_lbl = QLabel("")
        root.addWidget(self.stats_lbl)

        # ── Format (top row) + Options (bottom row) ──
        fmt_opts = QVBoxLayout()
        fmt_opts.setSpacing(8)

        fmt_l = QHBoxLayout()
        fmt_l.setSpacing(8)
        fmt_l.addWidget(QLabel("<b>" + _("export.group.format") + "</b>"))
        self.fmt_raw = QRadioButton(_("export.radio.raw"))
        self.fmt_v2rayn = QRadioButton(_("export.radio.v2rayn"))
        self.fmt_singbox = QRadioButton(_("export.radio.singbox"))
        self.fmt_clash = QRadioButton(_("export.radio.clash"))
        self.fmt_hiddify = QRadioButton(_("export.radio.hiddify"))
        self.fmt_amnezia = QRadioButton(_("export.radio.amnezia"))
        self.fmt_raw.setChecked(True)
        for rb in (self.fmt_raw, self.fmt_v2rayn, self.fmt_singbox, self.fmt_clash, self.fmt_hiddify, self.fmt_amnezia):
            fmt_l.addWidget(rb)
            rb.toggled.connect(self._update_preview)
        fmt_opts.addLayout(fmt_l)

        opt_l = QHBoxLayout()
        opt_l.setSpacing(8)
        opt_l.addWidget(QLabel("<b>" + _("export.group.options") + "</b>"))
        self.chk_smart_names = QCheckBox(_("export.chk.smart_names"))
        self.chk_clean_names = QCheckBox(_("export.chk.clean_names"))
        self.chk_failed = QCheckBox(_("export.chk.failed"))
        self.chk_failed.setChecked(_as_bool(_settings_data.get("include_failed", True)))
        self.chk_failed.toggled.connect(self._on_include_failed_changed)
        self.chk_failed.toggled.connect(self._update_preview)
        self.chk_clean_uris = QCheckBox(_("export.chk.clean_uris"))
        self.chk_clean_uris.setChecked(_as_bool(_settings_data.get("clean_uris", True)))
        self.chk_clean_uris.toggled.connect(self._on_clean_uris_changed)
        self.chk_clean_uris.toggled.connect(self._update_preview)
        self.chk_no_wg = QCheckBox("Happ-совместимо: без WG/TUIC, socks5→socks")
        self.chk_no_wg.setToolTip("Для Happ: убрать WireGuard/TUIC (не поддерживаются) и привести socks5:// к socks://. socks4 исключается (менять на v5 нельзя, Happ его не понимает)")
        self.chk_no_wg.toggled.connect(self._update_preview)
        self.chk_smart_names.setChecked(True)
        self.chk_smart_names.toggled.connect(self._update_preview)
        self.chk_clean_names.toggled.connect(self._update_preview)
        self.chk_failed.toggled.connect(self._update_preview)
        for chk in (self.chk_smart_names, self.chk_clean_names, self.chk_failed, self.chk_clean_uris, self.chk_no_wg):
            opt_l.addWidget(chk)
        fmt_opts.addLayout(opt_l)

        dns_l = QHBoxLayout()
        dns_l.setSpacing(8)
        self.chk_dns_hook = QCheckBox(_("export.chk.dns_hook"))
        self.chk_dns_hook.setToolTip("Вшить шифрованный DNS (DoH) в конфиг для защиты от подмены DNS")
        self.chk_dns_hook.toggled.connect(self._update_preview)
        dns_l.addWidget(self.chk_dns_hook)
        self.dns_input = QLineEdit(", ".join(DEFAULT_DOH))
        self.dns_input.setPlaceholderText("https://1.1.1.1/dns-query, https://8.8.8.8/dns-query")
        self.dns_input.setEnabled(False)
        self.chk_dns_hook.toggled.connect(lambda on: self.dns_input.setEnabled(on))
        dns_l.addWidget(self.dns_input, 1)
        fmt_opts.addLayout(dns_l)

        fmt_opts.addStretch()
        root.addLayout(fmt_opts)

        # ── Preview + Action buttons ──
        body = QHBoxLayout()
        body.setSpacing(8)

        preview_col = QVBoxLayout()
        preview_col.setSpacing(4)
        self.lbl_preview = QLabel(_("export.label.preview"))
        preview_col.addWidget(self.lbl_preview)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        preview_col.addWidget(self.preview, 1)

        body.addLayout(preview_col, 3)

        btn_col = QVBoxLayout()
        btn_col.setSpacing(6)

        self.btn_copy = QPushButton(_("export.btn.copy"))
        self.btn_copy.clicked.connect(self._on_copy)
        btn_col.addWidget(self.btn_copy)
        self.btn_save = QPushButton(_("export.btn.save"))
        self.btn_save.clicked.connect(self._on_save)
        btn_col.addWidget(self.btn_save)
        self.btn_save_desk = QPushButton(_("export.btn.save_desktop"))
        self.btn_save_desk.clicked.connect(self._on_save_desktop)
        btn_col.addWidget(self.btn_save_desk)

        btn_col.addStretch()
        body.addLayout(btn_col, 1)
        root.addLayout(body, 1)

        # ── GitHub Push ──
        self.gh_group = QGroupBox(_("export.group.github"))
        gh_l = QVBoxLayout(self.gh_group)
        gh_l.setSpacing(3)

        g1 = QHBoxLayout()
        g1.setSpacing(6)
        g1.addWidget(QLabel(_("export.label.gh_repo")))
        self.gh_repo_input = QLineEdit(_settings_data.get("gh_repo", "owner/repo"))
        self.gh_repo_input.setPlaceholderText("ivanov/my-vpn-subscriptions")
        self.gh_repo_input.setToolTip("Репозиторий на GitHub, куда сохранять файл.\nФормат: ваш_логин/название_репозитория\nМожно вставить полный URL: raw.githubusercontent.com/...")
        self.gh_repo_input.textChanged.connect(self._on_gh_repo_changed)
        g1.addWidget(self.gh_repo_input, 1)
        g1.addWidget(QLabel(_("export.label.gh_file")))
        self.gh_file_input = QLineEdit(_settings_data.get("gh_file", "subscription.txt"))
        self.gh_file_input.setPlaceholderText("vpn/подписка.txt")
        self.gh_file_input.setToolTip("Путь к файлу внутри репозитория.\nМожно указать папку: vpn/sub.txt\nНапример: proxy/config.txt или просто list.txt")
        self.gh_file_input.textChanged.connect(self._on_gh_file_changed)
        g1.addWidget(self.gh_file_input, 1)
        gh_l.addLayout(g1)

        g2 = QHBoxLayout()
        self.lbl_sub_title = QLabel(_("export.label.sub_title") + ":")
        g2.addWidget(self.lbl_sub_title)
        self.sub_title_input = QLineEdit(_settings_data.get("sub_title", "My Subscription"))
        self.sub_title_input.setPlaceholderText(_("export.label.sub_title_ph"))
        self.sub_title_input.setToolTip(_("export.label.sub_title_tt"))
        self.sub_title_input.textChanged.connect(self._on_sub_title_changed)
        g2.addWidget(self.sub_title_input, 1)
        gh_l.addLayout(g2)

        g3 = QHBoxLayout()
        self.gh_status_label = QLabel("")
        g3.addWidget(self.gh_status_label, 1)
        self.btn_gh_push = QPushButton(_("export.btn.github_push"))
        self.btn_gh_push.clicked.connect(self._on_github_push)
        g3.addWidget(self.btn_gh_push)
        gh_l.addLayout(g3)

        g4 = QHBoxLayout()
        self.lbl_gh_cdn = QLabel(_("export.label.cdn_url"))
        g4.addWidget(self.lbl_gh_cdn)
        self.cdn_url_input = QLineEdit()
        self.cdn_url_input.setReadOnly(True)
        g4.addWidget(self.cdn_url_input, 1)
        self.btn_gh_cdn_copy = QPushButton(_("export.btn.cdn_copy"))
        self.btn_gh_cdn_copy.clicked.connect(self._on_cdn_copy)
        g4.addWidget(self.btn_gh_cdn_copy)
        gh_l.addLayout(g4)
        self.gh_repo_input.textChanged.connect(lambda t: self._update_cdn_url())
        self.gh_file_input.textChanged.connect(lambda t: self._update_cdn_url())
        self._update_cdn_url()

        root.addWidget(self.gh_group)

        self._apply_export_theme()

    def _apply_export_theme(self):
        t = THEMES[current_theme()]
        c = t['border']
        fg = t['fg']
        ibg = t['input_bg']
        muted = t['muted']

        self.lbl_title.setStyleSheet(f"font-size:14px;font-weight:bold;padding:2px 0;color:{fg};")
        self.stats_lbl.setStyleSheet(f"padding:5px 10px;background:{ibg};border:1px solid {c};border-radius:5px;color:{fg};font-size:12px;")
        self.sub_title_input.setStyleSheet(f"QLineEdit{{background:{ibg};color:{fg};border:1px solid {c};border-radius:4px;padding:4px 8px;font-size:12px;}}")
        self.lbl_preview.setStyleSheet(f"font-size:12px;font-weight:bold;color:{fg};")
        self.preview.setStyleSheet(f"background:{ibg};color:{fg};font-family:monospace;font-size:11px;border:1px solid {c};border-radius:4px;padding:3px;")

        gen_btn = f"QPushButton{{background:{t['button_bg']};border:1px solid {c};border-radius:4px;padding:5px 14px;font-weight:bold;color:{fg};}}QPushButton:hover{{background:{t['accent']};color:white;border-color:{t['accent']};}}"
        for b in (self.btn_back, self.btn_copy, self.btn_save, self.btn_save_desk):
            b.setStyleSheet(gen_btn)

        acc_c = t['accent']
        acc_rgb = f"{int(acc_c[1:3],16)},{int(acc_c[3:5],16)},{int(acc_c[5:7],16)}"
        self.btn_gh_push.setStyleSheet(f"QPushButton{{background:rgba({acc_rgb},0.10);border:2px solid {acc_c};border-radius:4px;padding:6px 18px;font-weight:bold;font-size:12px;color:{acc_c};}}QPushButton:hover{{background:rgba({acc_rgb},0.25);}}QPushButton:disabled{{color:{muted};border-color:{c};background:transparent;}}")

        self.gh_status_label.setStyleSheet(f"font-size:11px;color:{muted};")

        gbox = f"QGroupBox{{border:1px solid {c};border-radius:6px;margin-top:8px;padding:10px 8px 8px 8px;font-weight:600;color:{fg};}}QGroupBox::title{{subcontrol-origin:margin;left:12px;padding:0 6px;color:{fg};}}"
        for g in (self.gh_group,):
            g.setStyleSheet(gbox)

        for rb in (self.fmt_raw, self.fmt_v2rayn, self.fmt_singbox, self.fmt_clash, self.fmt_hiddify):
            rb.setStyleSheet(f"QRadioButton{{color:{fg};spacing:4px;font-size:12px;}}QRadioButton::indicator{{width:14px;height:14px;}}")
        for chk in (self.chk_smart_names, self.chk_clean_names, self.chk_failed, self.chk_clean_uris):
            chk.setStyleSheet(f"QCheckBox{{color:{fg};spacing:4px;font-size:12px;}}QCheckBox::indicator{{width:14px;height:14px;}}")

    def on_enter(self):
        entries = self._main.test_page.get_entries()
        total = len(entries)
        tcp_cnt = sum(1 for e in entries if e.tcp_ok)
        deep_cnt = sum(1 for e in entries if e.deep_ok)
        self.stats_lbl.setText(_("export.stats", total=total, tcp=tcp_cnt, deep=deep_cnt))
        self.sub_title_input.setText(_settings_data.get("sub_title", "My Subscription"))
        QTimer.singleShot(0, self._update_preview)
        self._main.update_status_bar()
        tokens = _get_tokens()
        self.btn_gh_push.setEnabled(len(tokens) > 0)
        self.gh_status_label.setText("" if tokens else _("export.github.no_token"))

    def _flush_settings(self):
        _settings_data["gh_repo"] = self.gh_repo_input.text().strip()
        _settings_data["gh_file"] = self.gh_file_input.text().strip()
        _settings_data["sub_title"] = self.sub_title_input.text()
        _save_settings(_settings_data)

    def _on_sub_title_changed(self, text):
        _settings_data["sub_title"] = text
        self._save_timer.start()
        self._update_preview()

    def _on_gh_file_changed(self, text):
        _settings_data["gh_file"] = text
        self._save_timer.start()
        self._update_preview()

    def _on_include_failed_changed(self, checked: bool):
        _settings_data["include_failed"] = checked
        self._save_timer.start()
        self._update_preview()

    def _on_clean_uris_changed(self, checked: bool):
        _settings_data["clean_uris"] = checked
        self._save_timer.start()
        self._update_preview()

    def _on_gh_repo_changed(self, text):
        text = text.strip()
        _settings_data["gh_repo"] = text
        self._save_timer.start()
        raw_m = re.match(r'https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)', text)
        if raw_m:
            repo = f"{raw_m.group(1)}/{raw_m.group(2)}"
            file_path = raw_m.group(4)
            _settings_data["gh_repo"] = repo
            _settings_data["gh_file"] = file_path
            self.gh_repo_input.blockSignals(True)
            self.gh_file_input.blockSignals(True)
            self.gh_repo_input.setText(repo)
            self.gh_file_input.setText(file_path)
            self.gh_repo_input.blockSignals(False)
            self.gh_file_input.blockSignals(False)
            _save_settings(_settings_data)
            return
        gh_m = re.match(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)', text)
        if gh_m:
            repo = f"{gh_m.group(1)}/{gh_m.group(2)}"
            file_path = gh_m.group(4)
            _settings_data["gh_repo"] = repo
            _settings_data["gh_file"] = file_path
            self.gh_repo_input.blockSignals(True)
            self.gh_file_input.blockSignals(True)
            self.gh_repo_input.setText(repo)
            self.gh_file_input.setText(file_path)
            self.gh_repo_input.blockSignals(False)
            self.gh_file_input.blockSignals(False)
            _save_settings(_settings_data)

    def _get_format_func(self):
        if self.fmt_v2rayn.isChecked():
            return format_v2rayn
        if self.fmt_singbox.isChecked():
            return format_singbox
        if self.fmt_clash.isChecked():
            return format_clash
        if self.fmt_hiddify.isChecked():
            return format_hiddify
        if self.fmt_amnezia.isChecked():
            return format_amnezia
        return format_raw

    def _get_content(self) -> str:
        tp = self._main.test_page
        entries = tp.get_entries()
        if not entries:
            entries = tp._entries
        if self.chk_no_wg.isChecked():
            kept = []
            for e in entries:
                if e.protocol in ('WIREGUARD', 'WG', 'TUIC'):
                    continue
                uri = e.uri
                low = uri[:9].lower()
                if low == 'socks4://':
                    continue
                if low == 'socks5://':
                    uri = 'socks://' + uri[9:]
                    e = ProxyEntry(uri)
                kept.append(e)
            entries = kept
        fmt = self._get_format_func()
        clean_names = self.chk_clean_names.isChecked()
        clean = self.chk_clean_uris.isChecked()
        dns = None
        if self.chk_dns_hook.isChecked():
            from .exporters import _parse_dns_list
            dns = _parse_dns_list(self.dns_input.text())
        if (self.chk_smart_names.isChecked() or clean_names) and self.fmt_raw.isChecked():
            lines = []
            idx = 0
            include_failed = self.chk_failed.isChecked()
            for e in entries:
                if not _is_valid_entry(e):
                    continue
                if not include_failed and not _entry_ok(e):
                    continue
                idx += 1
                name = smart_name(e, idx, clean_names)
                uri = _clean_uri(e.uri)
                lines.append(f"{uri}#{name}")
            return "\n".join(lines) + "\n"
        if self.fmt_clash.isChecked():
            return fmt(entries, include_failed=self.chk_failed.isChecked(), clean_names=clean_names, dns=dns)
        if self.fmt_hiddify.isChecked():
            title = self.sub_title_input.text().strip() or "My Subscription"
            return fmt(entries, include_failed=self.chk_failed.isChecked(), title=title, clean=clean)
        if self.fmt_amnezia.isChecked():
            return fmt(entries, include_failed=self.chk_failed.isChecked(), dns=dns)
        kwargs = {}
        if fmt is format_singbox and dns is not None:
            kwargs["dns"] = dns
        if fmt in (format_raw, format_v2rayn):
            kwargs["clean"] = clean
        body = fmt(entries, include_failed=self.chk_failed.isChecked(), **kwargs)
        return body

    def _update_preview(self, *args):
        # Debounced: several toggles/keystrokes within 150 ms rebuild once.
        self._preview_timer.start()

    def _render_preview(self):
        content = self._get_content()
        lines = content.splitlines()
        if len(lines) > 20:
            self.preview.setPlainText("\n".join(lines[:10]) + "\n...\n" + "\n".join(lines[-10:]))
        else:
            self.preview.setPlainText(content)

    def retranslate(self):
        self.lbl_title.setText(_("export.title"))
        self.btn_back.setText(_("export.btn.back"))
        self.fmt_raw.setText(_("export.radio.raw"))
        self.fmt_v2rayn.setText(_("export.radio.v2rayn"))
        self.fmt_singbox.setText(_("export.radio.singbox"))
        self.fmt_clash.setText(_("export.radio.clash"))
        self.fmt_hiddify.setText(_("export.radio.hiddify"))
        self.fmt_amnezia.setText(_("export.radio.amnezia"))
        self.chk_failed.setText(_("export.chk.failed"))
        self.chk_smart_names.setText(_("export.chk.smart_names"))
        self.chk_clean_names.setText(_("export.chk.clean_names"))
        self.chk_dns_hook.setText(_("export.chk.dns_hook"))
        self.chk_no_wg.setText("Happ-совместимо: без WG/TUIC, socks5→socks")
        self.btn_copy.setText(_("export.btn.copy"))
        self.btn_save.setText(_("export.btn.save"))
        self.btn_save_desk.setText(_("export.btn.save_desktop"))
        self.lbl_preview.setText(_("export.label.preview"))
        self.lbl_sub_title.setText(_("export.label.sub_title") + ":")
        self.sub_title_input.setPlaceholderText(_("export.label.sub_title_ph"))
        self.sub_title_input.setToolTip(_("export.label.sub_title_tt"))
        self.gh_group.setTitle(_("export.group.github"))
        self.btn_gh_push.setText(_("export.btn.github_push"))
        self.lbl_gh_cdn.setText(_("export.label.cdn_url"))
        self.btn_gh_cdn_copy.setText(_("export.btn.cdn_copy"))

    def _update_cdn_url(self):
        repo = self.gh_repo_input.text().strip()
        fp = self.gh_file_input.text().strip()
        branch = (_settings_data.get("gh_branch") or "main").strip() or "main"
        if repo and fp:
            self.cdn_url_input.setText(f"https://cdn.jsdelivr.net/gh/{repo}@{branch}/{fp}")
        else:
            self.cdn_url_input.setText("")

    def _on_cdn_copy(self):
        url = self.cdn_url_input.text().strip()
        if url:
            QApplication.clipboard().setText(url)
            self.gh_status_label.setText(_("export.github.cdn_copied"))

    def _on_copy(self):
        content = self._get_content_with_header()
        QApplication.clipboard().setText(content)
        QMessageBox.information(self, _("msg.done"), _("msg.copied"))

    def _save_amnezia_confs(self, base_dir: str) -> int:
        """Write one .conf per WG entry into base_dir/amnezia_<ts>/ ."""
        entries = self._main.test_page.get_entries() or self._main.test_page._entries
        include_failed = self.chk_failed.isChecked()
        confs = []
        for e in entries:
            if e.protocol not in ('WIREGUARD', 'WG'):
                continue
            if not include_failed and not _entry_ok(e):
                continue
            conf = wireguard_conf_from_entry(e)
            if conf:
                confs.append((e, conf))
        if not confs:
            return 0
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        out_dir = os.path.join(base_dir, f"amnezia_{ts}")
        os.makedirs(out_dir, exist_ok=True)
        for i, (e, conf) in enumerate(confs, 1):
            # A host may contain '/', ':' or other characters invalid on Windows.
            name = f"wg-{i:02d}_{_safe_filename_part(e.host)}_{e.port}.conf"
            with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
                f.write(conf)
        return len(confs)

    def _current_fmt(self) -> str:
        if self.fmt_v2rayn.isChecked():
            return 'v2rayn'
        if self.fmt_singbox.isChecked():
            return 'singbox'
        if self.fmt_clash.isChecked():
            return 'clash'
        if self.fmt_hiddify.isChecked():
            return 'hiddify'
        if self.fmt_amnezia.isChecked():
            return 'amnezia'
        return 'raw'

    def _on_save(self):
        if self.fmt_amnezia.isChecked():
            count = self._save_amnezia_confs(DESKTOP_DIR)
            if count == 0:
                QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_wg"))
                return
            ts = datetime.now().strftime("%Y.%m.%d_%H%M")
            path = os.path.join(DESKTOP_DIR, f"amnezia_{ts}")
            QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))
            return
        content = self._get_content_with_header()
        if not content.strip():
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_data"))
            return
        valid, broken = validate_content(content, self._current_fmt())
        if valid == 0:
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.empty_after_filter"))
            return
        if broken > 0:
            ret = QMessageBox.question(self, _("msg.warning"), _("export.msg.broken_lines", count=broken))
            if ret != QMessageBox.StandardButton.Yes:
                return
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        default_name = f"sub_ski_{ts}.txt"
        path, _ = QFileDialog.getSaveFileName(self, _("export.btn.save"),
                                              os.path.join(DESKTOP_DIR, default_name),
                                              "All files (*.*)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))

    def _on_save_desktop(self):
        if self.fmt_amnezia.isChecked():
            count = self._save_amnezia_confs(DESKTOP_DIR)
            if count == 0:
                QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_wg"))
                return
            ts = datetime.now().strftime("%Y.%m.%d_%H%M")
            path = os.path.join(DESKTOP_DIR, f"amnezia_{ts}")
            QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))
            return
        content = self._get_content_with_header()
        if not content.strip():
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_data"))
            return
        valid, broken = validate_content(content, self._current_fmt())
        if valid == 0:
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.empty_after_filter"))
            return
        if broken > 0:
            ret = QMessageBox.question(self, _("msg.warning"), _("export.msg.broken_lines", count=broken))
            if ret != QMessageBox.StandardButton.Yes:
                return
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        path = os.path.join(DESKTOP_DIR, f"sub_ski_{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))

    def _get_content_with_header(self) -> str:
        if self.fmt_hiddify.isChecked():
            return self._get_content()
        content = self._get_content()
        if self.fmt_v2rayn.isChecked() or self.fmt_singbox.isChecked():
            return content
        title = self.sub_title_input.text().strip() or "My Subscription"
        repo = self.gh_repo_input.text().strip()
        fpath = self.gh_file_input.text().strip()
        branch = (_settings_data.get("gh_branch") or "main").strip() or "main"
        link = f"github.com/{repo}/blob/{branch}/{fpath}" if repo and fpath else ""
        if link:
            return f"# {title} | {link}\n\n{content}"
        return content

    def _on_github_push(self):
        repo = self.gh_repo_input.text().strip()
        file_path = self.gh_file_input.text().strip()
        if not repo or not file_path:
            QMessageBox.warning(self, _("msg.warning"), _("export.github.no_settings"))
            return
        tokens = _get_tokens()
        if not tokens:
            QMessageBox.warning(self, _("msg.warning"), _("export.github.no_token"))
            return
        token = tokens[0]
        content = self._get_content_with_header()
        if not content.strip():
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_data"))
            return
        self.gh_status_label.setText(_("export.github.pushing"))
        self.btn_gh_push.setEnabled(False)
        sub_title = self.sub_title_input.text().strip()

        def _push():
            import urllib.request, urllib.error, base64, json
            api_base = f"https://api.github.com/repos/{repo}/contents/{file_path}"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "proxy-skitchen",
            }
            # The contents API writes to the default branch; ask GitHub which one
            # it is so the CDN link and purge target the real branch (main/master).
            branch = (_settings_data.get("gh_branch") or "").strip()
            try:
                req = urllib.request.Request(f"https://api.github.com/repos/{repo}", headers=headers)
                info = json.loads(urllib.request.urlopen(req, timeout=10).read())
                branch = info.get("default_branch") or branch or "main"
            except Exception:
                branch = branch or "main"
            try:
                req = urllib.request.Request(api_base, headers=headers)
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read())
                sha = data.get("sha", "")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    sha = ""
                else:
                    return False, f"API error: {e.code}", branch
            except Exception as e:
                return False, str(e)[:60], branch
            body = {
                "message": f"Update subscription {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "branch": branch,
            }
            if sha:
                body["sha"] = sha
            try:
                data_bytes = json.dumps(body).encode("utf-8")
                req = urllib.request.Request(api_base, data=data_bytes, headers=headers, method="PUT")
                urllib.request.urlopen(req, timeout=15)
            except Exception as e:
                return False, str(e)[:60], branch
            purged = self._purge_jsdelivr_cdn(repo, file_path, branch)
            return True, "" if purged else "CDN purge failed", branch

        def _on_done(result, error):
            # Runs in the GUI thread (unlike ThreadPoolExecutor callbacks).
            self.btn_gh_push.setEnabled(True)
            if error is not None:
                self.gh_status_label.setText(f"❌ {str(error)[:60]}")
                return
            ok, err, branch = result
            if not ok:
                self.gh_status_label.setText(f"❌ {err}")
                return
            _settings_data["gh_repo"] = repo
            _settings_data["gh_file"] = file_path
            _settings_data["gh_branch"] = branch
            _settings_data["sub_title"] = sub_title
            _save_settings(_settings_data)
            note = "" if not err else f" (⚠ {err})"
            self.gh_status_label.setText(f"✅ {_('export.github.done')} — {repo}@{branch}/{file_path}{note}")
            self._update_cdn_url()

        BackgroundCall(_push, _on_done, parent=self)


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._main = parent
        self.setWindowTitle(_("settings.title"))
        self.setMinimumWidth(380)

        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # General tab
        gen = QWidget()
        gen_layout = QFormLayout(gen)

        self.perf_combo = QComboBox()
        self.perf_combo.addItems([_("settings.perf.low"), _("settings.perf.medium"), _("settings.perf.high")])
        mode = _settings_data.get("perf_mode", "medium")
        idx = {"low": 0, "medium": 1, "high": 2}.get(mode, 1)
        self.perf_combo.setCurrentIndex(idx)
        gen_layout.addRow(_("settings.label.performance"), self.perf_combo)

        self.lang_combo = QComboBox()
        for code, label in LANGUAGES.items():
            self.lang_combo.addItem(label, code)
        # Never blow up if settings.json holds an unknown language code.
        lang_idx = self.lang_combo.findData(current_lang())
        self.lang_combo.setCurrentIndex(lang_idx if lang_idx >= 0 else 0)
        self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        gen_layout.addRow(_("settings.label.language"), self.lang_combo)

        self.cb_proxy = QCheckBox(_("settings.chk.proxy"))
        self.cb_proxy.setChecked(_as_bool(_settings_data.get("proxy_enabled", True)))
        gen_layout.addRow(self.cb_proxy)
        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["HTTP", "SOCKS5"])
        ptype = str(_settings_data.get("proxy_type", "HTTP")).upper()
        self.proxy_type.setCurrentIndex(1 if ptype == "SOCKS5" else 0)
        gen_layout.addRow(_("settings.label.type"), self.proxy_type)
        self.proxy_host = QLineEdit(str(_settings_data.get("proxy_host", "127.0.0.1")))
        gen_layout.addRow(_("settings.label.host"), self.proxy_host)
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(_as_int(_settings_data.get("proxy_port", 12334), 12334, 1, 65535))
        gen_layout.addRow(_("settings.label.port"), self.proxy_port)
        gen_layout.addRow(QLabel(""))
        btn_open_settings = QPushButton(_("settings.btn.open_json"))
        btn_open_settings.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(SETTINGS_FILE)))
        gen_layout.addRow(btn_open_settings)
        tabs.addTab(gen, _("settings.tab.general"))

        # GitHub tab
        gh = QWidget()
        gh_layout = QVBoxLayout(gh)
        gh_layout.addWidget(QLabel(_("settings.label.tokens")))
        self.tokens_edit = QPlainTextEdit()
        self.tokens_edit.setPlaceholderText(_("settings.input.tokens.placeholder"))
        self.tokens_edit.setFixedHeight(80)
        tokens = _get_tokens()
        self.tokens_edit.setPlainText("\n".join(tokens))
        gh_layout.addWidget(self.tokens_edit)

        gh_layout.addWidget(QLabel(_("settings.label.gh_url_hint")))
        btn_check = QPushButton(_("settings.btn.check_token"))
        btn_check.clicked.connect(self._on_check_token)
        gh_layout.addWidget(btn_check)

        self.check_result = QLabel("")
        gh_layout.addWidget(self.check_result)

        gh_layout.addWidget(QLabel(""))
        gh_layout.addWidget(QLabel(_("settings.label.gh_repo")))
        self.gh_repo = QLineEdit(_settings_data.get("gh_repo", "owner/repo"))
        self.gh_repo.setPlaceholderText("owner/repo")
        gh_layout.addWidget(self.gh_repo)
        gh_layout.addWidget(QLabel(_("settings.label.gh_file")))
        self.gh_file = QLineEdit(_settings_data.get("gh_file", "subscription.txt"))
        self.gh_file.setPlaceholderText("path/to/file.txt")
        gh_layout.addWidget(self.gh_file)
        gh_layout.addWidget(QLabel(_("settings.label.gh_branch")))
        self.gh_branch = QLineEdit(_settings_data.get("gh_branch", "main"))
        self.gh_branch.setPlaceholderText("main")
        gh_layout.addWidget(self.gh_branch)

        gh_layout.addStretch()
        tabs.addTab(gh, "GitHub")

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(self._on_save)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _on_lang_changed(self, idx: int):
        code = self.lang_combo.itemData(idx)
        if code and code != current_lang():
            set_lang(code)
            if self._main is not None and hasattr(self._main, "apply_language"):
                self._main.apply_language()

    def _on_check_token(self):
        import urllib.request, urllib.error
        tokens = [t.strip() for t in self.tokens_edit.toPlainText().strip().splitlines() if t.strip()]
        if not tokens:
            self.check_result.setText(_("settings.token.none"))
            return
        token = tokens[0]
        self.check_result.setText(_("settings.token.checking"))
        proxy_enabled = _as_bool(_settings_data.get("proxy_enabled", True))
        proxy_type = str(_settings_data.get("proxy_type", "http")).lower()
        proxy_host = str(_settings_data.get("proxy_host", "127.0.0.1"))
        proxy_port = _as_int(_settings_data.get("proxy_port", 12334), 12334, 1, 65535)

        def _check():
            req = urllib.request.Request(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}", "User-Agent": "proxy-skitchen"},
            )
            try:
                resp = urllib.request.urlopen(req, timeout=4)
                data = json.loads(resp.read())
                limit = resp.headers.get('X-RateLimit-Remaining', '?')
                return _("settings.token.ok", login=data.get('login', '?'), limit=limit)
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    return _("settings.token.error", error="Invalid token")
                return _("settings.token.error", error=f"HTTP {e.code}")
            except Exception as ex:
                if not proxy_enabled or proxy_type == "socks5":
                    return _("settings.token.error", error=f"Connection failed: {str(ex)[:40]}")
            try:
                proxy_url = f"http://{proxy_host}:{proxy_port}"
                handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
                opener = urllib.request.build_opener(handler)
                resp = opener.open(req, timeout=4)
                data = json.loads(resp.read())
                limit = resp.headers.get('X-RateLimit-Remaining', '?')
                return _("settings.token.ok", login=data.get('login', '?'), limit=limit)
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    return _("settings.token.error", error="Invalid token")
                return _("settings.token.error", error=f"HTTP {e.code}")
            except Exception as ex:
                return _("settings.token.error", error=f"Connection failed: {str(ex)[:40]}")

        def _done(result, error):
            # GUI thread: safe to touch the label.
            if error is not None:
                self.check_result.setText(str(error)[:80])
            else:
                self.check_result.setText(result)

        BackgroundCall(_check, _done, parent=self)

    def _on_save(self):
        tokens = [t.strip() for t in self.tokens_edit.toPlainText().strip().splitlines() if t.strip()]
        _auth_data["github_tokens"] = tokens
        _save_auth(_auth_data)

        _settings_data["perf_mode"] = ["low", "medium", "high"][self.perf_combo.currentIndex()]
        _settings_data["proxy_enabled"] = self.cb_proxy.isChecked()
        _settings_data["proxy_type"] = self.proxy_type.currentText().lower()
        _settings_data["proxy_host"] = self.proxy_host.text().strip()
        _settings_data["proxy_port"] = self.proxy_port.value()
        _settings_data["gh_repo"] = self.gh_repo.text().strip()
        _settings_data["gh_file"] = self.gh_file.text().strip()
        _settings_data["gh_branch"] = self.gh_branch.text().strip()
        _save_settings(_settings_data)
        self.accept()


class RepoLinkLabel(QLabel):
    """Clickable repo link with theme-aware inline color (QSS can't style <a> in QLabel)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._base = "#5b8def"
        self._hover = "#8cb0f5"
        self.setOpenExternalLinks(True)
        self.setTextFormat(Qt.TextFormat.RichText)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._render(False)

    def set_colors(self, base: str, hover: str):
        self._base = base
        self._hover = hover
        self._render(False)

    def _render(self, hovered: bool):
        color = self._hover if hovered else self._base
        deco = "underline" if hovered else "none"
        self.setText(
            f'<a href="https://github.com/cyberanrhy/proxy-skitchen" '
            f'style="color:{color};text-decoration:{deco};">{_("main.repo_link")}</a>'
        )

    def enterEvent(self, e):
        self._render(True)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._render(False)
        super().leaveEvent(e)


class MainWindow(QMainWindow):
    @staticmethod
    def _make_app_icon() -> QIcon:
        """Window/tray icon, with a drawn fallback.

        An empty ``QIcon()`` is invisible: Windows then shows no tray entry at
        all, so the app looks like it vanished after closing the window.
        """
        path = resource_path("icon.png")
        if os.path.exists(path):
            icon = QIcon(path)
            if not icon.isNull():
                return icon
        pix = QPixmap(64, 64)
        pix.fill(QColor("#000000"))
        painter = QPainter(pix)
        try:
            painter.setPen(QColor("#ffffff"))
            font = QFont()
            font.setBold(True)
            font.setPixelSize(32)
            painter.setFont(font)
            painter.drawText(pix.rect(), Qt.AlignCenter, "PS")
        finally:
            painter.end()
        return QIcon(pix)

    def __init__(self):
        super().__init__()
        from proxy_skitchen.compat import APP_VERSION
        self.setWindowTitle(f"{_('main.title')} v{APP_VERSION}")
        # Window icon for taskbar and tray
        self._app_icon = self._make_app_icon()
        self.setWindowIcon(self._app_icon)
        self.setMinimumSize(640, 480)
        self.resize(880, 600)
        self._pipeline_mode = False
        self._pipeline_stage = 0

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 0)
        layout.setSpacing(0)

        # App header: title + clickable repo link
        self._header_bar = QFrame()
        self._header_bar.setObjectName("AppHeader")
        header_l = QHBoxLayout(self._header_bar)
        header_l.setContentsMargins(10, 6, 10, 6)
        header_l.setSpacing(10)

        self.header_title = QLabel(_("main.header_title"))
        self.header_title.setObjectName("HeaderTitle")
        self.header_title.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        header_l.addWidget(self.header_title)
        header_l.addStretch()

        self.repo_link = RepoLinkLabel()
        header_l.addWidget(self.repo_link)
        layout.addWidget(self._header_bar)

        self.source_page = SourcesPage(self)
        self.download_page = DownloadPage(self)
        self.test_page = TestPage(self)
        self.export_page = ExportPage(self)

        # Proxy toggle
        proxy_row = QHBoxLayout()
        proxy_row.setContentsMargins(0, 1, 0, 1)
        self.proxy_toggle = QCheckBox(_("main.proxy_toggle"))
        self.proxy_toggle.setChecked(_as_bool(_settings_data.get("proxy_enabled", True)))
        self.proxy_toggle.toggled.connect(self._on_toggle_proxy)
        self.proxy_toggle.setObjectName("ProxyToggle")
        proxy_row.addWidget(self.proxy_toggle)
        proxy_row.addStretch()
        layout.addLayout(proxy_row)

        self.stack = QStackedWidget()
        self.stack.addWidget(self.source_page)    # 0
        self.stack.addWidget(self.download_page)  # 1
        self.stack.addWidget(self.test_page)      # 2
        self.stack.addWidget(self.export_page)    # 3
        layout.addWidget(self.stack)

        # Bottom tab bar (browser-style tabs)
        self._tab_bar = QWidget()
        self._tab_bar.setObjectName("TabBar")
        tab_layout = QHBoxLayout(self._tab_bar)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(0)

        tab_labels = ["🔍 Sources", "📥 Download", "⚡ Test", "📤 Export"]

        self._tab_btns = []
        for i, label in enumerate(tab_labels):
            btn = QPushButton(label)
            btn.setObjectName("TabButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            btn.clicked.connect(lambda checked, i=i: self.set_page(i))
            tab_layout.addWidget(btn)
            self._tab_btns.append(btn)

        layout.addWidget(self._tab_bar)

        self._current_page = 0
        self._tab_btns[0].setProperty("active", True)

        self._tray = QSystemTrayIcon(self._app_icon, self)
        self._tray.setToolTip(f"Proxy Skitchen v{APP_VERSION}")
        tray_menu = QMenu()
        self._tray_show_act = tray_menu.addAction(_("tray.show"))
        self._tray_show_act.triggered.connect(self._show_from_tray)
        tray_menu.addSeparator()
        self._tray_quit_act = tray_menu.addAction(_("tray.quit"))
        self._tray_quit_act.triggered.connect(self._quit_app)
        self._tray.setContextMenu(tray_menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.setVisible(True)
        _debug(
            "tray: available=%s icon_null=%s icon_path=%s"
            % (QSystemTrayIcon.isSystemTrayAvailable(),
               self._app_icon.isNull(), resource_path("icon.png"))
        )

        # Hiding the main window must not terminate the app: the tray icon is
        # the only way back unless the user picks "Quit" explicitly.
        app = QApplication.instance()
        if app is not None:
            app.setQuitOnLastWindowClosed(False)

        self.apply_theme()
        self.update_status_bar()

    def _on_toggle_proxy(self, enabled: bool):
        _settings_data["proxy_enabled"] = enabled
        _save_settings(_settings_data)
        self.proxy_toggle.setText(_("main.proxy_toggle_on") if enabled else _("main.proxy_toggle_off"))

    def update_status_bar(self):
        sp = self.source_page
        dp = self.download_page
        tp = self.test_page
        ep = self.export_page

        src_has_sources = len(sp.get_sources()) > 0
        self._tab_btns[0].setText(f"{_('main.tab.sources')} {'✅' if src_has_sources else '⏹'}")

        dl_entries = dp.get_entries() if hasattr(dp, 'get_entries') else []
        if dp._phase == dp.PHASE_FETCH:
            self._tab_btns[1].setText(f"{_('main.tab.download')} ⏳")
        elif len(dl_entries) > 0:
            self._tab_btns[1].setText(f"{_('main.tab.download')} ✅")
        else:
            self._tab_btns[1].setText(f"{_('main.tab.download')} ⏹")

        test_entries = tp.get_entries()
        total = len(test_entries)
        valid = sum(1 for e in test_entries if e.tcp_ok is True or e.deep_ok is True)
        if tp._phase == tp.PHASE_TEST:
            self._tab_btns[2].setText(f"{_('main.tab.test')} ⏳")
        elif valid > 0:
            self._tab_btns[2].setText(f"{_('main.tab.test')} ✅")
        elif total > 0:
            self._tab_btns[2].setText(f"{_('main.tab.test')} ❌")
        else:
            self._tab_btns[2].setText(f"{_('main.tab.test')} ⏹")

        ep_visited = ep._main._current_page >= 2
        self._tab_btns[3].setText(f"{_('main.tab.export')} {'✅' if ep_visited else '⏹'}")

    def set_page(self, idx: int):
        if idx < 0 or idx > 3:
            return
        current_w = self.stack.currentWidget()
        if hasattr(current_w, 'on_leave'):
            current_w.on_leave()

        self._current_page = idx
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._tab_btns):
            btn.setProperty("active", i == idx)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        w = self.stack.currentWidget()
        if hasattr(w, 'on_enter'):
            w.on_enter()
        self.update_status_bar()

    def apply_theme(self):
        theme = current_theme()
        colors = THEMES[theme]
        QApplication.instance().setStyleSheet(get_style_string(colors))

        for btn in self._tab_btns:
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        # Theme-aware proxy toggle
        indicator_bg = colors.get('button_bg', '#282e45')
        indicator_accent = colors['accent']
        fg = colors['fg']
        self.proxy_toggle.setStyleSheet(f"""
            QCheckBox {{
                spacing: 6px; font-size: 12px; color: {fg};
            }}
            QCheckBox::indicator {{
                width: 40px; height: 20px; border-radius: 10px;
                border: 2px solid {indicator_accent};
            }}
            QCheckBox::indicator:checked {{
                background: {indicator_accent}; border-color: {indicator_accent};
            }}
            QCheckBox::indicator:unchecked {{
                background: {indicator_bg}; border-color: {indicator_accent};
            }}
        """)
        # App header: title + clickable repo link with hover
        accent = colors['accent']
        if current_theme() == 'dark':
            link_color = QColor(accent).lighter(120).name()
            link_hover = QColor(accent).lighter(150).name()
        else:
            link_color = accent
            link_hover = QColor(accent).darker(115).name()
        self._header_bar.setStyleSheet(f"""
            #AppHeader {{
                background: {colors['input_bg']};
                border-bottom: 1px solid {colors['border']};
                border-radius: 6px;
            }}
            #HeaderTitle {{
                color: {fg};
                font-size: 14px;
                font-weight: bold;
            }}
            #RepoLink {{
                font-size: 12px;
                font-weight: bold;
            }}
        """)
        self.header_title.setText(_('main.header_title'))
        self.repo_link.set_colors(link_color, link_hover)
        self.apply_language()
        self.test_page._apply_test_theme()
        self.export_page._apply_export_theme()
        self.download_page._apply_download_theme()

    def apply_language(self):
        self.source_page.retranslate()
        self.download_page.retranslate()
        self.test_page.retranslate()
        self.export_page.retranslate()
        if getattr(self, "_tray_show_act", None) is not None:
            self._tray_show_act.setText(_("tray.show"))
        if getattr(self, "_tray_quit_act", None) is not None:
            self._tray_quit_act.setText(_("tray.quit"))
        self.update_status_bar()

    def _switch_theme(self, theme: str):
        if theme != current_theme():
            set_theme(theme)
            self.apply_theme()
            self.source_page._refresh_toolbar_buttons()
        self.update_status_bar()

    def changeEvent(self, event):
        super().changeEvent(event)

    def closeEvent(self, event):
        if self.test_page._phase == self.test_page.PHASE_TEST:
            ret = QMessageBox.question(
                self, "Proxy Skitchen",
                _("main.close.test_running"),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if ret == QMessageBox.Yes:
                event.accept()
                self._quit_app()
                return
            event.ignore()
            self.hide()
            self._notify_minimized()
            return
        if self._tray is None or not QSystemTrayIcon.isSystemTrayAvailable():
            # No tray to restore from: quitting is the only sane option.
            event.accept()
            self._quit_app()
            return
        event.ignore()
        self.hide()
        self._notify_minimized()

    def _notify_minimized(self):
        if self._tray is None:
            return
        try:
            self._tray.showMessage(
                "Proxy Skitchen",
                _("tray.minimized"),
                self._app_icon, 2000,
            )
        except Exception:
            pass

    def show_window(self):
        """Bring the window back from tray/minimized and focus it."""
        if self.isMinimized() or not self.isVisible():
            self.showNormal()
        self.activateWindow()
        self.raise_()

    def _show_from_tray(self):
        self.show_window()

    def _on_tray_activated(self, reason: int):
        # Windows/Linux send Trigger on a single click; macOS uses DoubleClick.
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._show_from_tray()

    def _quit_app(self):
        if self._tray is not None:
            self._tray.hide()
        self._tray = None
        self.source_page._cleanup_gh()
        self.download_page._cleanup_net()
        self.test_page._cleanup_test()
        self.test_page._cleanup_strategy()
        wait_background_calls(1500)
        wait_zombies(2000)
        # The testers spawn sing-box/xray; kill any survivor before exiting.
        try:
            from .tester import kill_all_procs
            kill_all_procs()
        except Exception:
            pass
        QApplication.instance().quit()

def get_style_string(colors: dict) -> str:
    return f"""
        QMainWindow {{ background-color: {colors['bg']}; }}
        QWidget {{ background-color: {colors['bg']}; color: {colors['fg']}; }}
        QLabel {{ color: {colors['fg']}; }}
        QPushButton {{
            background-color: {colors['button_bg']}; color: {colors['fg']};
            border: 1px solid {colors['border']};
            padding: 4px 12px; border-radius: 4px; min-height: 20px;
            font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;
        }}
        QPushButton:hover {{ background-color: {colors['accent']}; color: white; border-color: {colors['accent']}; }}
        QPushButton:disabled {{ background-color: transparent; color: {colors['muted']}; border-color: {colors['border']}; }}
        QLineEdit, QComboBox {{
            background-color: {colors['input_bg']}; color: {colors['fg']};
            border: 1px solid {colors['border']}; border-radius: 3px; padding: 4px 8px;
        }}
        QGroupBox {{
            border: 1px solid {colors['border']}; border-radius: 6px; margin-top: 10px;
            padding: 12px 8px 8px 8px; font-weight: 600;
        }}
        QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {colors['accent']}; }}
        QProgressBar {{
            background-color: {colors['input_bg']}; border: 1px solid {colors['border']};
            text-align: center; color: {colors['fg']}; height: 6px; border-radius: 3px;
        }}
        QProgressBar::chunk {{ background-color: {colors['accent']}; border-radius: 2px; }}
        QListWidget, QTableWidget {{
            background-color: {colors['input_bg']}; color: {colors['fg']}; border: 1px solid {colors['border']};
        }}
        QListWidget::item, QTableWidget::item {{
            color: {colors['fg']}; padding: 2px 4px;
        }}
        QListWidget::item:alternate {{
            background: {colors['button_bg']};
        }}
        QHeaderView::section {{
            background: {colors['bg']}; color: {colors['fg']};
            border: none; border-bottom: 1px solid {colors['border']};
            padding: 4px 6px; font-weight: bold;
        }}
        #TabBar {{
            background: {colors['input_bg']};
            border: none;
            border-top: 1px solid {colors['border']};
            max-height: 28px;
        }}
        QPushButton#TabButton {{
            background: transparent;
            border: none;
            border-right: 1px solid {colors['border']};
            padding: 4px 12px 3px 12px;
            color: {colors['tab_muted']};
            font-family: monospace;
            font-size: 10px;
            font-weight: 500;
            min-height: 20px;
            border-radius: 0;
            margin: 0;
            text-transform: none;
            letter-spacing: 0;
        }}
        QPushButton#TabButton:hover {{
            background: {colors['tab_hover_bg']};
            color: {colors['muted_fg']};
        }}
        QPushButton#TabButton[active="true"] {{
            background: {colors['bg']};
            color: {colors['accent']};
            font-weight: 700;
            font-family: monospace;
            font-size: 10px;
            padding: 4px 12px 3px 12px;
            border: none;
            border-top: 2px solid {colors['accent']};
            border-right: 1px solid {colors['border']};
            min-height: 20px;
            border-radius: 0;
            margin: 0;
            text-transform: none;
            letter-spacing: 0;
        }}
        QPushButton#TabButton[active="true"]:hover {{
            background: {colors['bg']};
            color: {colors['accent']};
            font-weight: 700;
        }}
    """

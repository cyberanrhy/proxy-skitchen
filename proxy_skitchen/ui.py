import os, sys, json, re, threading, time, base64
from datetime import datetime
from .compat import TMP_DIR

_DEBUG_LOG = os.path.join(TMP_DIR, "debug-ui.log")

def _debug(msg: str):
    if _DEBUG_LOG not in DEBUG_LOG_PATHS:
        DEBUG_LOG_PATHS.append(_DEBUG_LOG)
    _write_log(_DEBUG_LOG, msg)

from .compat import *
from .compat import _write_log, DEBUG_LOG_PATHS
from .models import ProxyEntry, ProxyTableModel, _auth_data, _settings_data, _save_auth, _load_auth, _save_settings, _load_settings, PERF_PRESETS, THEMES, current_theme, set_theme, country_flag, _get_tokens
from .parsers import is_proxy_uri, extract_uris, get_server_port
from .exporters import format_raw, format_v2rayn, format_singbox, format_clash, format_hiddify, smart_name, _country_to_code, _is_valid_entry, _entry_ok, _clean_uri
from .workers import NetworkWorker, TesterWorker, GitHubSearchWorker
from .i18n import _, LANGUAGES, current_lang, set_lang

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
        p.setBrush(QColor("#1e293b"))
        p.drawRoundedRect(bar_rect, r, r)

        val = max(0, min(1, self.value() / max(self.maximum(), 1)))
        if val > 0:
            fill_w = max(4, (w - 2) * val)
            fill_rect = QRectF(1, 1, fill_w, h - 2)
            grad = QLinearGradient(0, 0, w, 0)
            grad.setColorAt(0.0, QColor("#2563eb"))
            grad.setColorAt(0.5, QColor("#3b82f6"))
            grad.setColorAt(1.0, QColor("#60a5fa"))
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


def _cleanup_thread(thread, worker, wait_sec=3.0):
    if thread is None and worker is None:
        return
    if worker is not None:
        try:
            worker.stop()
        except Exception:
            pass
    if thread is not None:
        try:
            thread.quit()
            thread.wait(int(wait_sec * 1000))
        except Exception:
            pass
    if worker is not None:
        try:
            worker.deleteLater()
        except Exception:
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

        self.btn_settings = QPushButton("⚙")
        self.btn_settings.setFixedSize(32, 22)
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

        # Row: keywords + period + search buttons
        kw_row = QHBoxLayout()
        self.lbl_keywords = QLabel(_("sources.label.keywords"))
        kw_row.addWidget(self.lbl_keywords)
        self.kw_input = QLineEdit()
        self.kw_input.setPlaceholderText(_("sources.input.keywords.placeholder"))
        kw_row.addWidget(self.kw_input, 1)
        kw_row.addSpacing(4)
        self.lbl_period = QLabel(_("sources.label.period"))
        kw_row.addWidget(self.lbl_period)
        self.period_combo = QComboBox()
        for p in [_("period.1h"), _("period.2h"), _("period.4h"), _("period.6h"), _("period.8h"), _("period.12h"), _("period.24h"), _("period.3d"), _("period.7d")]:
            self.period_combo.addItem(p)
        self.period_combo.setCurrentText(_("period.6h"))
        kw_row.addWidget(self.period_combo)
        kw_row.addSpacing(8)
        self.btn_quick_search = QPushButton(_("sources.btn.quick_search"))
        self.btn_quick_search.setStyleSheet("QPushButton { background: transparent; border: 1px solid #4a5168; border-radius: 3px; padding: 2px 8px; font-size: 10px; } QPushButton:hover { background: rgba(91,141,239,0.08); }")
        self.btn_quick_search.clicked.connect(lambda: self._on_github_search(False, False))
        kw_row.addWidget(self.btn_quick_search)
        self.btn_deep_search = QPushButton(_("sources.btn.deep_search"))
        self.btn_deep_search.setStyleSheet("QPushButton { background: transparent; border: 2px solid #7c5cbf; border-radius: 3px; padding: 2px 8px; font-size: 10px; } QPushButton:hover { background: rgba(124,92,191,0.12); }")
        self.btn_deep_search.clicked.connect(lambda: self._on_github_search(True, True))
        kw_row.addWidget(self.btn_deep_search)
        self.chk_hidden_configs = QCheckBox(_("sources.chk.hidden_configs"))
        self.chk_hidden_configs.setToolTip(_("sources.chk.hidden_configs.tooltip"))
        self.chk_hidden_configs.setStyleSheet("QCheckBox { font-size: 10px; color: #7c89a8; }")
        kw_row.addWidget(self.chk_hidden_configs)
        gh_body.addLayout(kw_row)

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
        self.gh_found_label.setStyleSheet("color: #5b8def; font-weight: 700;")
        pr.addWidget(self.gh_found_label)
        gp.addLayout(pr)
        self.gh_status = QLabel("")
        self.gh_status.setWordWrap(True)
        self.gh_status.setStyleSheet("color: #7c89a8; font-size: 11px;")
        gp.addWidget(self.gh_status)
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
        self.import_status.setStyleSheet("color: #7c89a8; font-size: 10px;")
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
        self.btn_clear.setFixedSize(24, 24)
        self.btn_clear.setStyleSheet("QPushButton { font-size: 12px; padding: 0px; }")
        self.btn_clear.clicked.connect(self._on_clear)
        src_header.addWidget(self.btn_clear)
        layout.addLayout(src_header)

        self.src_list = QListWidget()
        self.src_list.setAlternatingRowColors(True)
        self.src_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.src_list.customContextMenuRequested.connect(self._on_src_context)
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
        _cleanup_thread(getattr(self, '_gh_thread', None), getattr(self, '_gh_worker', None))
        self._gh_thread = None
        self._gh_worker = None

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
        self.btn_import_file.setStyleSheet("QPushButton{font-size:12px;padding:2px;border:1px solid rgba(116,199,160,0.3);border-radius:3px;}QPushButton:hover{background:rgba(116,199,160,0.15);}")
        self.btn_import_paste.setStyleSheet("QPushButton{font-size:12px;padding:2px;border:1px solid rgba(91,141,239,0.3);border-radius:3px;}QPushButton:hover{background:rgba(91,141,239,0.15);}")

    def _on_settings(self):
        try:
            dlg = SettingsDialog(self._main)
            dlg.exec_()
        except Exception as e:
            import traceback
            QMessageBox.critical(self, _("sources.title"), f"Settings error: {e}\n\n{traceback.format_exc()}")

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
                      _("period.8h"): 0.33, _("period.12h"): 0.5, _("period.24h"): 1, _("period.3d"): 3, _("period.7d"): 7}
        time_days = period_map.get(self.period_combo.currentText(), 7)
        tokens = _get_tokens()
        repos = []
        owner = None
        if gh_url:
            m_repo = re.match(r'(?:https?://)?github\.com/([^/]+/[^/]+?)/?$', gh_url)
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
        self._gh_thread.started.connect(self._gh_worker.run, Qt.ConnectionType.DirectConnection)
        self.btn_quick_search.setEnabled(False)
        self.btn_deep_search.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.gh_progress_bar.setVisible(True)
        self.gh_status.setText(_("gh.searching", kw=", ".join(keywords[:3]) + ("..." if len(keywords) > 3 else "")))
        self.gh_found_label.setText("⏳")
        self._stopped = False
        self._gh_results = []
        self._gh_count = 0
        self._gh_thread.start()

    def _on_gh_progress(self, msg: str):
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
        self._gh_count = count
        self.gh_found_label.setText(f"📄 {count}")

    def _on_gh_partial(self, results: list):
        self._gh_results = results
        for r in results:
            url = r.get("file_url", "")
            name = r.get("name", url)
            if r.get("embedded", False):
                self._add_source(_("gh.embed_prefix", name=name), url)
            else:
                self._add_source(name, url)
        self._update_fetch_btn()

    def _on_gh_result(self, results: list):
        self.gh_progress_bar.setVisible(False)
        self.btn_quick_search.setEnabled(True)
        self.btn_deep_search.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self._gh_results = results
        added = 0
        for r in results:
            url = r.get("file_url", "")
            name = r.get("name", url)
            if r.get("embedded", False):
                self._add_source(_("gh.embed_prefix", name=name), url)
            else:
                self._add_source(name, url)
            added += 1
        self.gh_status.setText(_("gh.found_files", count=added))
        self.gh_found_label.setText(f"✅ {added}")
        self._cleanup_gh()
        self._completed = True
        
        # Bright success indicator
        self._main._tab_btns[0].setStyleSheet("color: #74c7a0; font-weight: bold;")
        self._main._tab_btns[0].setText("🔍 ✅ DONE")
        QTimer.singleShot(3000, lambda: (self._main._tab_btns[0].setStyleSheet(""), self._main.update_status_bar()))
        if self._main._pipeline_mode and self._sources:
            QTimer.singleShot(500, self._on_fetch)

    def _on_gh_error(self, err: str):
        self.gh_progress_bar.setVisible(False)
        self.btn_quick_search.setEnabled(True)
        self.btn_deep_search.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.gh_status.setText(f"⚠ {err[:60]}")
        self.gh_found_label.setText("⚠")
        self._cleanup_gh()
        
        # Bright error indicator
        self._main._tab_btns[0].setStyleSheet("color: #e36262; font-weight: bold;")
        self._main._tab_btns[0].setText("🔍 ❌ ERROR")
        QTimer.singleShot(3000, lambda: (self._main._tab_btns[0].setStyleSheet(""), self._main.update_status_bar()))

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

    def _add_source(self, name: str, url: str):
        for i in range(self.src_list.count()):
            item = self.src_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == url:
                return
        item = QListWidgetItem(name)
        item.setData(Qt.ItemDataRole.UserRole, url)
        self.src_list.addItem(item)
        self._sources.append((name, url))
        self._update_fetch_btn()

    def _remove_source(self, url: str):
        for i in range(self.src_list.count()):
            item = self.src_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == url:
                self.src_list.takeItem(i)
                self._sources = [(n, u) for n, u in self._sources if u != url]
                self._update_fetch_btn()
                return

    def _on_src_context(self, pos):
        item = self.src_list.itemAt(pos)
        if not item:
            return
        menu = QMenu()
        menu.addAction(_("sources.context.remove"), lambda: self._remove_source(item.data(Qt.ItemDataRole.UserRole)))
        menu.exec_(self.src_list.mapToGlobal(pos))

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
        self._main.download_page.fetch_sources(list(self._sources))
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
                    content = f.read()
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
        for p in [_("period.1h"), _("period.2h"), _("period.4h"), _("period.6h"), _("period.8h"), _("period.12h"), _("period.24h"), _("period.3d"), _("period.7d")]:
            self.period_combo.addItem(p)
        if self.period_combo.findText(current) >= 0:
            self.period_combo.setCurrentText(current)
        else:
            self.period_combo.setCurrentText(_("period.6h"))
        self.period_combo.blockSignals(False)

    def get_sources(self) -> list[tuple[str, str]]:
        return list(self._sources)

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
        self._stopped = False
        self._completed = False
        self._fetch_start_time = 0.0
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
        self.log_out.setStyleSheet("background: #181c2e; color: #4a5168; font-size: 12px;")
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
        self.log_out.setStyleSheet(f"background: {ibg}; color: {m}; font-family: monospace; font-size: 11px; border: 1px solid {bd}; border-radius: 4px; padding: 2px 4px;")
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
        _cleanup_thread(getattr(self, '_net_thread', None), getattr(self, '_net_worker', None), wait_sec=15)
        self._net_thread = None
        self._net_worker = None

    def _on_stop(self):
        _debug("DownloadPage._on_stop")
        self._cleanup_net()
        self._log(_("log.fetch_stopped", count=len(self._entries)))
        self._set_phase(self.PHASE_IDLE)
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

        n = len(sources)
        self.src_table.setRowCount(n)
        for i, (name, _url) in enumerate(sources):
            self._add_source_row_at(i, name)

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

        self._net_worker = NetworkWorker()
        self._net_worker.proxy_parsed.connect(self._on_proxy_parsed)
        self._net_worker.log_signal.connect(self._log)
        self._net_worker.source_started.connect(self._on_source_started)
        self._net_worker.source_status.connect(self._update_source_row)
        self._net_worker.progress_signal.connect(self._on_fetch_progress)
        self._net_worker.finished.connect(self._on_fetch_finished)

        self._net_thread = QThread()
        self._net_worker.moveToThread(self._net_thread)
        self._net_thread.started.connect(lambda: self._net_worker.fetch_all(sources), Qt.ConnectionType.DirectConnection)
        self._net_thread.start()

    def _on_fetch_progress(self, done: int, total: int, name: str):
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

    def _on_proxy_parsed(self, entries: list[ProxyEntry]):
        self._entries.extend(entries)
        for e in entries:
            p = e.protocol or "?"
            self._proto_counts[p] = self._proto_counts.get(p, 0) + 1
        self.lbl_total.setText(_("download.stats.total", count=len(self._entries)))

    def _on_source_started(self, name: str, idx: int):
        row = self._source_rows.get(name[:60])
        if row is None:
            return
        icon_item = self.src_table.item(row, 0)
        if icon_item:
            icon_item.setText("⟳")
        for c in range(3):
            cell = self.src_table.item(row, c)
            if cell:
                cell.setBackground(QColor("#1e2338"))

    def _add_source_row_at(self, row: int, name: str):
        icon_item = QTableWidgetItem("⏳")
        icon_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_table.setItem(row, 0, icon_item)
        name_item = QTableWidgetItem(name[:60])
        name_item.setToolTip(name)
        self.src_table.setItem(row, 1, name_item)
        count_item = QTableWidgetItem("...")
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_table.setItem(row, 2, count_item)
        self._source_rows[name[:60]] = row
        self._sources_total += 1

    def _update_source_row(self, name: str, ok: bool, count: int):
        row = self._source_rows.get(name[:60])
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
                cell.setBackground(QColor("#181c2e"))
        if ok and name not in self._sources_done:
            self._sources_done.add(name)
            self._sources_ok += 1

    def _toggle_sources(self):
        hidden = self.src_group.isHidden()
        self.src_group.setVisible(hidden)
        self.btn_toggle_sources.setText(
            _("download.hide_sources") if not hidden else _("download.show_sources", count=self.src_table.rowCount())
        )

    def _on_fetch_finished(self):
        self._cleanup_net()
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


class TestPage(WizardPage):
    PHASE_IDLE = 0
    PHASE_TEST = 1

    def __init__(self, main):
        super().__init__(main)
        self._main = main
        self._entries = []
        self._filtered_entries = []
        self._filter_proto: str | None = None
        self._filter_security: str | None = None
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._last_log_time = 0.0
        self._phase = self.PHASE_IDLE
        self._test_thread = None
        self._tester = None
        self._stopped = False
        self._completed = False
        self._test_type: str | None = None
        self._stop_requested = False

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
        self.lbl_rkn = QLabel("")
        cards.addWidget(self.lbl_total)
        cards.addWidget(self.lbl_valid)
        cards.addWidget(self.lbl_dead)
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
            _("test.filter.hy2"),
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
        self.chk_max_latency.setChecked(_settings_data.get("max_latency_enabled", False))
        self.chk_max_latency.toggled.connect(self._on_max_latency_toggled)
        actions.addWidget(self.chk_max_latency)
        self.spin_max_latency = QSpinBox()
        self.spin_max_latency.setRange(100, 30000)
        self.spin_max_latency.setSuffix(" ms")
        self.spin_max_latency.setValue(_settings_data.get("max_latency_ms", 3100))
        self.spin_max_latency.setFixedWidth(80)
        self.spin_max_latency.valueChanged.connect(self._on_max_latency_changed)
        actions.addWidget(self.spin_max_latency)

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
        layout.addLayout(actions)

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
        self.sort_proxy = QSortFilterProxyModel()
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
        self.log_out.setFixedHeight(70)
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
        self.lbl_total.setStyleSheet(self._card_total)
        self.lbl_valid.setStyleSheet(self._card_valid)
        self.lbl_dead.setStyleSheet(self._card_dead)
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

        self.log_out.setStyleSheet(f"background: {ibg}; color: {m}; font-family: monospace; font-size: 11px; border: 1px solid {bd}; border-radius: 4px; padding: 2px 4px;")

        exp_d = f"QPushButton {{ background: {ok_bg}; border: 2px solid {ok}; border-radius: 4px; padding: 6px 20px; font-weight: bold; font-size: 12px; color: {ok}; }} QPushButton:hover {{ background: rgba(116,199,160,0.2); }} QPushButton:disabled {{ color: {m}; border-color: {bd}; background: transparent; }}"
        self.btn_export.setStyleSheet(exp_d)

    def load_entries(self, entries: list[ProxyEntry]):
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
        self._filtered_entries = list(deduped)
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
        self._stop_requested = True
        self._cleanup_test()
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
        if not self._filtered_entries:
            return
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._test_type = "deep"
        self._run_test(subset=self._filtered_entries)

    def _on_rkn_test(self):
        if self._phase == self.PHASE_TEST:
            return
        if not self._filtered_entries:
            return
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._test_type = "rkn"
        alive = list(self._filtered_entries)
        indices = list(range(len(alive)))
        self._run_test(rkn=True, subset=alive, subset_indices=indices)

    def _on_delete_dead(self):
        if self._dead_cnt == 0:
            QMessageBox.information(self, _("msg.info"), _("log.no_dead"))
            return
        alive = [e for e in self._entries if e.tcp_ok is True or e.deep_ok is True]
        removed = len(self._entries) - len(alive)
        if removed == 0:
            QMessageBox.information(self, _("msg.info"), _("log.no_dead_to_delete"))
            return
        self._entries = alive
        self._valid_cnt = len(alive)
        self._dead_cnt = 0
        self._apply_filter()
        self.btn_delete_dead.setEnabled(False)
        self.btn_rkn.setEnabled(len(self._entries) > 0)
        self._log(_("log.deleted_dead", count=removed))

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
        target = subset if subset is not None else self._entries
        self._stop_requested = False
        self._set_phase(self.PHASE_TEST)
        self.progress_bar.setMaximum(len(target))
        self.progress_bar.setValue(0)

        self._tester = TesterWorker(rkn=rkn, test_threads=self.spin_threads.value(), deep_threads=max(1, self.spin_threads.value() // 2))
        self._tester.result_signal.connect(self._on_test_result)
        self._tester.testing_signal.connect(self._on_testing_start)
        self._tester.progress_signal.connect(self._on_test_progress)
        self._tester.count_signal.connect(self._on_test_count)
        self._tester.log_signal.connect(self._log)
        self._tester.geo_signal.connect(self._on_geo_result)
        self._tester.finished.connect(self._on_test_finished)

        self._test_thread = QThread()
        self._tester.moveToThread(self._test_thread)
        if subset_indices is not None:
            self._test_thread.started.connect(lambda: self._tester.test_batch(target, subset_indices), Qt.ConnectionType.DirectConnection)
        else:
            self._test_thread.started.connect(lambda: self._tester.test_batch(target), Qt.ConnectionType.DirectConnection)
        self._test_thread.start()

    def _on_testing_start(self, row: int, info: str):
        idx = self.model.index(row, 0)
        self.proxy_table.scrollTo(idx)
        self.proxy_table.selectRow(row)

    def _on_test_result(self, row: int, ok: bool, latency: float, error: str, ttype: int):
        filtered = False
        if ok and _settings_data.get("max_latency_enabled") and latency > _settings_data.get("max_latency_ms", 3100):
            ok = False
            filtered = True
        self.model.update_entry(row, ok, latency, error, ttype)
        if filtered and ttype in (1, 2) and 0 <= row < len(self._entries):
            self._entries[row].tcp_ok = False
            self._entries[row].deep_ok = False
        if ok:
            self._valid_cnt += 1
        else:
            self._dead_cnt += 1
        self._update_stats()
        idx = self.model.index(row, 0)
        self.proxy_table.scrollTo(idx)
        self.proxy_table.selectRow(row)
        if 0 <= row < len(self._entries):
            e = self._entries[row]
            if ttype == 2:
                kind = "RKN"
                passed = sum(1 for r in e.rkn_results if r.get("ok")) if e.rkn_results else 0
                total = len(e.rkn_results) if e.rkn_results else 0
                mark = "🛡" if ok else "✗"
                detail = f" ({passed}/{total} sites)"
            else:
                kind = "TCP" if ttype == 0 else "DEEP"
                mark = "✓" if ok else "✗"
                detail = ""
            t = THEMES[current_theme()]
            color = t['success'] if ok else t['danger']
            if ttype == 2:
                color = t['warning'] if ok else t['danger']
            ping = f" {latency:.0f}ms" if latency else ""
            self.lbl_current.setText(f"{mark} [{kind}] {e.protocol} {e.host}:{e.port}{ping}{detail}")
            self.lbl_current.setStyleSheet(f"padding: 4px 10px; background: {t['input_bg']}; border: 1px solid {t['border']}; border-radius: 6px; color: {color}; font-size: 11px;")

    def _on_test_count(self, c: int):
        self.progress_bar.setValue(c)

    def _on_test_progress(self, done: int, total: int, threads: int, mode: str):
        now = time.time()
        if now - self._last_log_time > 0.5:
            self._log(_("event.threads", mode=mode, done=done, total=total, threads=threads))
            self._last_log_time = now
        if not self.lbl_current.text():
            self.lbl_current.setText(_("event.test_progress", mode=mode, done=done, total=total, pct=done*100//max(total,1)))

    def _on_max_latency_toggled(self, checked: bool):
        _settings_data["max_latency_enabled"] = checked
        _save_settings(_settings_data)

    def _on_max_latency_changed(self, value: int):
        _settings_data["max_latency_ms"] = value
        _save_settings(_settings_data)

    def _on_geo_result(self, row: int, country: str):
        idx = self.model.index(row, 4)
        self.model.dataChanged.emit(idx, idx)

    def _on_test_finished(self):
        self._cleanup_test()
        if self._stop_requested:
            self._stop_requested = False
            return
        self._stopped = False
        self._completed = True
        self._apply_filter()
        self._set_phase(self.PHASE_IDLE)
        self.btn_delete_dead.setEnabled(self._dead_cnt > 0)
        self._log(_("log.test_done", valid=self._valid_cnt, total=len(self._entries)))
        self._main.update_status_bar()
        if self._main._pipeline_mode:
            if self._main._pipeline_stage == 1:
                self._main._pipeline_stage = 2
                alive = [e for e in self._entries if e.tcp_ok is True or e.deep_ok is True]
                removed = len(self._entries) - len(alive)
                if removed:
                    self._entries = alive
                    self._valid_cnt = len(alive)
                    self._dead_cnt = 0
                    self._apply_filter()
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
        clean = _settings_data.get("clean_uris", True)
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
        if do_gh:
            self._log("📤 GitHub push...")
            repo = _settings_data.get("gh_repo", "")
            file_path = _settings_data.get("gh_file", "")
            tokens = _get_tokens()
            if not repo or not file_path:
                self._log("❌ GitHub: не указан репозиторий или файл")
            elif not tokens:
                self._log("❌ GitHub: нет токена")
            else:
                ok, err = self._do_github_push(content, repo, file_path, tokens[0])
                if ok:
                    self._log(f"✅ GitHub: файл обновлён — {repo}/{file_path}")
                else:
                    self._log(f"❌ GitHub: {err}")
        QMessageBox.information(self, _("msg.done"),
            f"✅ Готово!\n\n"
            f"Файл: {path}\n\n"
            f"Импортируй в Hiddify: Меню → Подписки → (+) → Выбери файл")

    def _do_github_push(self, content: str, repo: str, file_path: str, token: str) -> tuple[bool, str]:
        import urllib.request, urllib.error, base64, json
        api_base = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "proxy-skitchen",
        }
        try:
            req = urllib.request.Request(api_base, headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            sha = data.get("sha", "")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                sha = ""
            else:
                return False, f"API error: {e.code}"
        except Exception as e:
            return False, str(e)[:60]
        body = {
            "message": f"Update subscription {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        }
        if sha:
            body["sha"] = sha
        try:
            data_bytes = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(api_base, data=data_bytes, headers=headers, method="PUT")
            resp = urllib.request.urlopen(req, timeout=15)
            return True, ""
        except Exception as e:
            return False, str(e)[:60]

    def _on_filter_change(self, idx: int):
        proto_map = [None, "TUIC", "VLESS", "VMESS", "Trojan", "SS", "Hy2"]
        self._filter_proto = proto_map[idx] if 0 < idx < len(proto_map) else None
        self._apply_filter()

    def _on_security_filter_change(self, idx: int):
        sec_map = [None, "tls", "reality", "none"]
        self._filter_security = sec_map[idx] if 0 < idx < len(sec_map) else None
        self._apply_filter()

    def _apply_filter(self):
        entries = self._entries
        if self._filter_proto is not None:
            entries = [e for e in entries if e.protocol == self._filter_proto]
        if self._filter_security is not None:
            entries = [e for e in entries if e.security == self._filter_security]
        self._filtered_entries = list(entries)
        self.model.clear()
        self.model.add_proxies(self._filtered_entries)
        self._update_stats()

    def _update_stats(self):
        entries = self._filtered_entries
        total = len(entries)
        valid = sum(1 for e in entries if e.deep_ok)
        dead = sum(1 for e in entries if not e.deep_ok and (e.deep_tested or e.rkn_tested))
        rkn_ok = sum(1 for e in entries if e.rkn_tested and e.rkn_ok)
        rkn_total = sum(1 for e in entries if e.rkn_tested)
        self.lbl_total.setText(f"Всего: {total}")
        self.lbl_valid.setText(f"Живых: {valid}")
        self.lbl_dead.setText(f"Мёртвых: {dead}")
        if rkn_total:
            self.lbl_rkn.setText(f"🛡 RKN: {rkn_ok}/{rkn_total}")
            self.lbl_rkn.setVisible(True)
        else:
            self.lbl_rkn.setVisible(False)
        self.lbl_valid.setStyleSheet(self._card_valid if valid > 0 else self._card_total)
        self.lbl_dead.setStyleSheet(self._card_dead if dead > 0 else self._card_total)

    def _on_table_context(self, pos):
        idx = self.proxy_table.indexAt(pos)
        if not idx.isValid():
            return
        src_row = self.sort_proxy.mapToSource(idx).row()
        entry = self._entries[src_row]
        menu = QMenu()
        menu.addAction(_("test.context.copy_uri"), lambda: QApplication.clipboard().setText(entry.uri))
        tcp_mark = "✅" if entry.tcp_ok else "❌"
        deep_mark = "⚡" if entry.deep_ok else "—"
        rkn_mark = "🛡" if entry.rkn_ok else ("—" if not entry.rkn_tested else "❌")
        ping_str = f"{entry.latency_ms:.0f}ms" if entry.latency_ms else "—"
        lines = [
            f"{entry.display_protocol()} {entry.host}:{entry.port}",
            f"SNI: {entry.sni or '—'}",
            f"Страна: {entry.country or '—'}",
            f"TCP: {tcp_mark}  Deep: {deep_mark}  RKN: {rkn_mark}  Пинг: {ping_str}",
            f"Источник: {entry.source or '—'}",
        ]
        if entry.rkn_results:
            lines.append("")
            lines.append("RKN результаты:")
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

    def retranslate(self):
        self.lbl_title.setText(_("test.title"))
        self.btn_stop.setText(_("test.btn.stop"))
        self.btn_back.setText(_("test.btn.back"))
        self.lbl_total.setText(_("test.stats.total", count=len(self._entries)))
        self.lbl_valid.setText(_("test.stats.valid", count=self._valid_cnt))
        self.lbl_dead.setText(_("test.stats.dead", count=self._dead_cnt))
        self.btn_deep.setText(_("test.btn.deep"))
        self.btn_rkn.setText(_("test.btn.rkn"))
        self.btn_continue.setText(_("test.btn.continue"))
        self.btn_delete_dead.setText(_("test.btn.delete_dead"))
        self.btn_export.setText(_("test.btn.export"))
        self.chk_max_latency.setText(_("test.max_latency"))
        self.model.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, self.model.columnCount() - 1)
        # Rebuild filter combos
        current = self.filter_combo.currentIndex()
        self.filter_combo.blockSignals(True)
        self.filter_combo.clear()
        self.filter_combo.addItems([
            _("test.filter.all"), _("test.filter.tuic"),
            _("test.filter.vless"), _("test.filter.vmess"),
            _("test.filter.trojan"), _("test.filter.ss"),
            _("test.filter.hy2"),
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

    def get_entries(self) -> list[ProxyEntry]:
        return self._filtered_entries


class ExportPage(WizardPage):
    def __init__(self, main):
        super().__init__(main)
        self._main = main

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

        # ── Format + Options row ──
        fmt_opts = QHBoxLayout()
        fmt_opts.setSpacing(12)

        fmt_l = QHBoxLayout()
        fmt_l.setSpacing(8)
        fmt_l.addWidget(QLabel("<b>" + _("export.group.format") + "</b>"))
        self.fmt_raw = QRadioButton(_("export.radio.raw"))
        self.fmt_v2rayn = QRadioButton(_("export.radio.v2rayn"))
        self.fmt_singbox = QRadioButton(_("export.radio.singbox"))
        self.fmt_clash = QRadioButton(_("export.radio.clash"))
        self.fmt_hiddify = QRadioButton(_("export.radio.hiddify"))
        self.fmt_raw.setChecked(True)
        for rb in (self.fmt_raw, self.fmt_v2rayn, self.fmt_singbox, self.fmt_clash, self.fmt_hiddify):
            fmt_l.addWidget(rb)
            rb.toggled.connect(self._update_preview)
        fmt_opts.addLayout(fmt_l)

        fmt_opts.addSpacing(20)

        opt_l = QHBoxLayout()
        opt_l.setSpacing(8)
        opt_l.addWidget(QLabel("<b>" + _("export.group.options") + "</b>"))
        self.chk_smart_names = QCheckBox(_("export.chk.smart_names"))
        self.chk_clean_names = QCheckBox(_("export.chk.clean_names"))
        self.chk_failed = QCheckBox(_("export.chk.failed"))
        self.chk_clean_uris = QCheckBox(_("export.chk.clean_uris"))
        self.chk_clean_uris.setChecked(_settings_data.get("clean_uris", True))
        self.chk_clean_uris.toggled.connect(self._on_clean_uris_changed)
        self.chk_clean_uris.toggled.connect(self._update_preview)
        self.chk_smart_names.setChecked(True)
        self.chk_smart_names.toggled.connect(self._update_preview)
        self.chk_clean_names.toggled.connect(self._update_preview)
        self.chk_failed.toggled.connect(self._update_preview)
        for chk in (self.chk_smart_names, self.chk_clean_names, self.chk_failed, self.chk_clean_uris):
            opt_l.addWidget(chk)
        fmt_opts.addLayout(opt_l)

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
        self.gh_file_input.textChanged.connect(lambda t: _settings_data.update({"gh_file": t}) or _save_settings(_settings_data))
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

        self.btn_gh_push.setStyleSheet(f"QPushButton{{background:rgba(91,141,239,0.10);border:2px solid #5b8def;border-radius:4px;padding:6px 18px;font-weight:bold;font-size:12px;color:#5b8def;}}QPushButton:hover{{background:rgba(91,141,239,0.25);}}QPushButton:disabled{{color:{muted};border-color:{c};background:transparent;}}")

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

    def _on_sub_title_changed(self, text):
        _settings_data["sub_title"] = text
        _save_settings(_settings_data)
        self._update_preview()

    def _on_clean_uris_changed(self, checked: bool):
        _settings_data["clean_uris"] = checked
        _save_settings(_settings_data)
        self._update_preview()

    def _on_gh_repo_changed(self, text):
        text = text.strip()
        _settings_data["gh_repo"] = text
        _save_settings(_settings_data)
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
        return format_raw

    def _get_content(self) -> str:
        tp = self._main.test_page
        entries = tp.get_entries()
        if not entries:
            entries = tp._entries
        fmt = self._get_format_func()
        clean_names = self.chk_clean_names.isChecked()
        clean = self.chk_clean_uris.isChecked()
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
                uri = _clean_uri(e.uri) if clean else e.uri
                lines.append(f"{uri}#{name}")
            return "\n".join(lines) + "\n"
        if self.fmt_clash.isChecked():
            return fmt(entries, include_failed=self.chk_failed.isChecked(), clean_names=clean_names)
        if self.fmt_hiddify.isChecked():
            title = self.sub_title_input.text().strip() or "My Subscription"
            return fmt(entries, include_failed=self.chk_failed.isChecked(), title=title, clean=clean)
        body = fmt(entries, include_failed=self.chk_failed.isChecked(), clean=clean)
        return body

    def _update_preview(self):
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
        self.chk_failed.setText(_("export.chk.failed"))
        self.chk_smart_names.setText(_("export.chk.smart_names"))
        self.chk_clean_names.setText(_("export.chk.clean_names"))
        self.btn_copy.setText(_("export.btn.copy"))
        self.btn_save.setText(_("export.btn.save"))
        self.btn_save_desk.setText(_("export.btn.save_desktop"))
        self.lbl_preview.setText(_("export.label.preview"))
        self.lbl_sub_title.setText(_("export.label.sub_title") + ":")
        self.sub_title_input.setPlaceholderText(_("export.label.sub_title_ph"))
        self.sub_title_input.setToolTip(_("export.label.sub_title_tt"))
        self.gh_group.setTitle(_("export.group.github"))
        self.btn_gh_push.setText(_("export.btn.github_push"))

    def _on_copy(self):
        content = self._get_content_with_header()
        QApplication.clipboard().setText(content)
        QMessageBox.information(self, _("msg.done"), _("msg.copied"))

    def _on_save(self):
        content = self._get_content_with_header()
        if not content.strip():
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_data"))
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
        content = self._get_content_with_header()
        if not content.strip():
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_data"))
            return
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        path = os.path.join(DESKTOP_DIR, f"sub_ski_{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))

    def _get_content_with_header(self) -> str:
        if self.fmt_hiddify.isChecked():
            return self._get_content()
        title = self.sub_title_input.text().strip() or "My Subscription"
        repo = self.gh_repo_input.text().strip()
        fpath = self.gh_file_input.text().strip()
        link = f"github.com/{repo}/blob/main/{fpath}" if repo and fpath else ""
        header_lines = [
            f"#profile-title: {title}",
            "#profile-update-interval: 1",
            "#hide-settings: 1",
        ]
        if link:
            header_lines.insert(0, f"# {title} | {link}")
        content = self._get_content()
        return "\n".join(header_lines) + "\n" + content

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
        content = self._get_content()
        if not content.strip():
            QMessageBox.warning(self, _("msg.warning"), _("export.msg.no_data"))
            return
        if not self.fmt_hiddify.isChecked():
            title = self.sub_title_input.text().strip() or "My Subscription"
            content = f"#profile-title: {title}\n#profile-update-interval: 24\n#hide-settings: 1\n\n{content}"
        self.gh_status_label.setText(_("export.github.pushing"))
        self.btn_gh_push.setEnabled(False)
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(1)

        def _push():
            import urllib.request, urllib.error, base64, json
            api_base = f"https://api.github.com/repos/{repo}/contents/{file_path}"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "proxy-skitchen",
            }
            try:
                req = urllib.request.Request(api_base, headers=headers)
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read())
                sha = data.get("sha", "")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    sha = ""
                else:
                    return False, f"API error: {e.code}"
            except Exception as e:
                return False, str(e)[:60]
            body = {
                "message": f"Update subscription {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            }
            if sha:
                body["sha"] = sha
            try:
                data_bytes = json.dumps(body).encode("utf-8")
                req = urllib.request.Request(api_base, data=data_bytes, headers=headers, method="PUT")
                resp = urllib.request.urlopen(req, timeout=15)
                return True, ""
            except Exception as e:
                return False, str(e)[:60]

        def _on_done(fut):
            ok, err = fut.result()
            self.btn_gh_push.setEnabled(True)
            if ok:
                self.gh_status_label.setText(f"✅ {_('export.github.done')} — {repo}/{file_path}")
                _settings_data["gh_repo"] = repo
                _settings_data["gh_file"] = file_path
                _settings_data["sub_title"] = self.sub_title_input.text().strip()
                _save_settings(_settings_data)
            else:
                self.gh_status_label.setText(f"❌ {err}")

        fut = pool.submit(_push)
        fut.add_done_callback(_on_done)


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
        self.lang_combo.setCurrentIndex(list(LANGUAGES.keys()).index(current_lang()))
        self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        gen_layout.addRow(_("settings.label.language"), self.lang_combo)

        self.cb_proxy = QCheckBox(_("settings.chk.proxy"))
        self.cb_proxy.setChecked(_settings_data.get("proxy_enabled", True))
        gen_layout.addRow(self.cb_proxy)
        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["HTTP", "SOCKS5"])
        self.proxy_type.setCurrentText(_settings_data.get("proxy_type", "HTTP").upper())
        gen_layout.addRow(_("settings.label.type"), self.proxy_type)
        self.proxy_host = QLineEdit(_settings_data.get("proxy_host", "127.0.0.1"))
        gen_layout.addRow(_("settings.label.host"), self.proxy_host)
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(_settings_data.get("proxy_port", 12334))
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
        if not tokens:
            tokens = _env_tokens()
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
            if self._main:
                self._main.apply_language()

    def _on_check_token(self):
        import urllib.request, urllib.error
        tokens = [t.strip() for t in self.tokens_edit.toPlainText().strip().splitlines() if t.strip()]
        if not tokens:
            self.check_result.setText(_("settings.token.none"))
            return
        token = tokens[0]
        self.check_result.setText(_("settings.token.checking"))
        from concurrent.futures import ThreadPoolExecutor
        proxy_enabled = _settings_data.get("proxy_enabled", True)
        proxy_type = _settings_data.get("proxy_type", "http").lower()
        proxy_host = _settings_data.get("proxy_host", "127.0.0.1")
        proxy_port = _settings_data.get("proxy_port", 12334)
        pool = ThreadPoolExecutor(1)
        def _check():
            req = urllib.request.Request("https://api.github.com/user",
                                         headers={"Authorization": f"token {token}", "User-Agent": "proxy-skitchen"})
            import socket
            socket.setdefaulttimeout(4)
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
        def _on_done(fut):
            try:
                result = fut.result()
                QTimer.singleShot(0, lambda: self.check_result.setText(result))
            except Exception as ex:
                QTimer.singleShot(0, lambda: self.check_result.setText(str(ex)[:60]))
        fut = pool.submit(_check)
        fut.add_done_callback(_on_done)

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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(_("main.title"))
        # Window icon for taskbar
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(640, 480)
        self.resize(880, 600)
        self._pipeline_mode = False
        self._pipeline_stage = 0

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 0)
        layout.setSpacing(0)

        self.source_page = SourcesPage(self)
        self.download_page = DownloadPage(self)
        self.test_page = TestPage(self)
        self.export_page = ExportPage(self)

        # Proxy toggle
        proxy_row = QHBoxLayout()
        proxy_row.setContentsMargins(0, 1, 0, 1)
        self.proxy_toggle = QCheckBox(_("main.proxy_toggle"))
        self.proxy_toggle.setChecked(_settings_data.get("proxy_enabled", True))
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
        self._tab_btns[0].setText(f"🔍 Sources {'✅' if src_has_sources else '⏹'}")

        dl_entries = dp.get_entries() if hasattr(dp, 'get_entries') else []
        if dp._phase == dp.PHASE_FETCH:
            self._tab_btns[1].setText(f"📥 Download ⏳")
        elif len(dl_entries) > 0:
            self._tab_btns[1].setText(f"📥 Download ✅")
        else:
            self._tab_btns[1].setText(f"📥 Download ⏹")

        test_entries = tp.get_entries()
        total = len(test_entries)
        valid = sum(1 for e in test_entries if e.tcp_ok is True or e.deep_ok is True)
        if tp._phase == tp.PHASE_TEST:
            self._tab_btns[2].setText(f"⚡ Test ⏳")
        elif valid > 0:
            self._tab_btns[2].setText(f"⚡ Test ✅")
        elif total > 0:
            self._tab_btns[2].setText(f"⚡ Test ❌")
        else:
            self._tab_btns[2].setText(f"⚡ Test ⏹")

        ep_visited = ep._main._current_page >= 2
        self._tab_btns[3].setText(f"📤 Export {'✅' if ep_visited else '⏹'}")

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
        self.apply_language()
        self.test_page._apply_test_theme()
        self.export_page._apply_export_theme()
        self.download_page._apply_download_theme()

    def apply_language(self):
        self.source_page.retranslate()
        self.download_page.retranslate()
        self.test_page.retranslate()
        self.export_page.retranslate()

    def _switch_theme(self, theme: str):
        if theme != current_theme():
            set_theme(theme)
            self.apply_theme()
            self.source_page._refresh_toolbar_buttons()
        self.update_status_bar()

    def closeEvent(self, event):
        self.source_page._cleanup_gh()
        self.download_page._cleanup_net()
        self.test_page._cleanup_test()
        event.accept()

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
        QPushButton:disabled {{ background-color: transparent; color: #4a5168; border-color: {colors['border']}; }}
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
            border-right: 1px solid rgba(54,61,87,0.4);
            padding: 4px 12px 3px 12px;
            color: #6b7089;
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
            background: rgba(255,255,255,0.04);
            color: #9aa0b8;
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

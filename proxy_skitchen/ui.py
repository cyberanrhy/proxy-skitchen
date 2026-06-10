import os, sys, json, re, threading, time
from datetime import datetime

from .compat import *

_DEBUG_LOG = os.path.join(TMP_DIR, "debug-ui.log")
def _debug(msg: str):
    try:
        with open(_DEBUG_LOG, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass
from .models import ProxyEntry, ProxyTableModel, _auth_data, _settings_data, _save_auth, _load_auth, _save_settings, _load_settings, PERF_PRESETS, THEMES, current_theme, set_theme, country_flag
from .parsers import is_proxy_uri, extract_uris, get_server_port
from .exporters import format_raw, format_v2rayn, format_singbox, format_clash, format_hiddify, smart_name, _country_to_code, _is_valid_entry, _entry_ok
from .workers import NetworkWorker, TesterWorker, GitHubSearchWorker
from .geo import GeoWorker
from .i18n import _, LANGUAGES, current_lang, set_lang


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
            if not thread.wait(int(wait_sec * 1000)):
                thread.terminate()
                thread.wait(1000)
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
        self.btn_settings.setFixedWidth(32)
        self.btn_settings.setToolTip(_("sources.btn.settings.tooltip"))
        self.btn_settings.clicked.connect(self._on_settings)
        top.addWidget(self.btn_settings)
        self.btn_stop = QPushButton(_("sources.btn.stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        top.addWidget(self.btn_stop)
        layout.addLayout(top)

        # ── GitHub search ──
        self.gh_group = QGroupBox(_("sources.group.github"))
        gh_body = QVBoxLayout(self.gh_group)
        gh_body.setSpacing(4)

        # Row: keywords + period
        kw_row = QHBoxLayout()
        self.lbl_keywords = QLabel(_("sources.label.keywords"))
        kw_row.addWidget(self.lbl_keywords)
        self.kw_input = QLineEdit()
        self.kw_input.setPlaceholderText(_("sources.input.keywords.placeholder"))
        kw_row.addWidget(self.kw_input, 1)
        kw_row.addSpacing(6)
        self.lbl_period = QLabel(_("sources.label.period"))
        kw_row.addWidget(self.lbl_period)
        self.period_combo = QComboBox()
        for p in [_("period.1h"), _("period.2h"), _("period.4h"), _("period.6h"), _("period.8h"), _("period.12h"), _("period.24h"), _("period.3d"), _("period.7d")]:
            self.period_combo.addItem(p)
        self.period_combo.setCurrentText(_("period.6h"))
        self.period_combo.setStyleSheet("QComboBox { border: 1px solid #7aa2f7; background-color: #1f2335; }")
        kw_row.addWidget(self.period_combo)
        gh_body.addLayout(kw_row)

        # Row: preset buttons (2 rows)
        self._presets = [
            _("preset.vless"), _("preset.vmess"), _("preset.trojan"),
            _("preset.ss"), _("preset.v2ray_cfg"), _("preset.v2ray_sub"),
            _("preset.proxy"), _("preset.clash"), _("preset.singbox"),
            _("preset.free"), _("preset.xray"), _("preset.hysteria2"),
            _("preset.tuic"),
        ]
        pw = QWidget()
        pw.setStyleSheet("QWidget { background: transparent; }")
        pw_vbox = QVBoxLayout(pw)
        pw_vbox.setContentsMargins(0, 0, 0, 0)
        pw_vbox.setSpacing(2)
        
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
                btn.setStyleSheet("QPushButton { font-size: 8px; padding: 0px 4px; }")
                btn.clicked.connect(lambda checked, kw=kw: self._on_preset(kw))
                row_layout.addWidget(btn)
            pw_vbox.addLayout(row_layout)
        gh_body.addWidget(pw)

        # Row: GitHub URL filter (user/org or specific repo)
        url_row = QHBoxLayout()
        self.lbl_gh_url = QLabel(_("sources.label.gh_url"))
        url_row.addWidget(self.lbl_gh_url)
        self.gh_url_input = QLineEdit()
        self.gh_url_input.setPlaceholderText(_("sources.input.gh_url.placeholder"))
        url_row.addWidget(self.gh_url_input, 1)
        gh_body.addLayout(url_row)

        # Row: Search buttons
        search_layout = QHBoxLayout()
        self.btn_quick_search = QPushButton(_("sources.btn.quick_search"))
        self.btn_quick_search.setStyleSheet("QPushButton { background: transparent; border: 1px solid #555; border-radius: 3px; padding: 2px 8px; } QPushButton:hover { background: rgba(255,255,255,0.08); }")
        self.btn_quick_search.clicked.connect(lambda: self._on_github_search(False, False))
        
        self.btn_deep_search = QPushButton(_("sources.btn.deep_search"))
        self.btn_deep_search.setStyleSheet("QPushButton { background: transparent; border: 2px solid #9b59b6; border-radius: 3px; padding: 2px 8px; } QPushButton:hover { background: rgba(155,89,182,0.12); }")
        self.btn_deep_search.clicked.connect(lambda: self._on_github_search(True, True))
        
        search_layout.addWidget(self.btn_quick_search)
        search_layout.addWidget(self.btn_deep_search)
        gh_body.addLayout(search_layout)

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
        self.gh_found_label.setStyleSheet("color: #7aa2f7; font-weight: 700;")
        pr.addWidget(self.gh_found_label)
        gp.addLayout(pr)
        self.gh_status = QLabel("")
        self.gh_status.setWordWrap(True)
        self.gh_status.setStyleSheet("color: #9aa5ce; font-size: 11px;")
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
        self.btn_add_url.clicked.connect(self._on_add_url)
        url_row.addWidget(self.btn_add_url)
        layout.addWidget(self.url_group)

        # ── Sources list ──
        src_header = QHBoxLayout()
        self.lbl_subscriptions = QLabel(_("sources.label.subscriptions"))
        src_header.addWidget(self.lbl_subscriptions)
        src_header.addStretch()
        self.btn_clear = QPushButton(_("sources.btn.clear"))
        self.btn_clear.setEnabled(False)
        self.btn_clear.setFixedHeight(24)
        self.btn_clear.setStyleSheet("QPushButton { font-size: 10px; padding: 1px 8px; }")
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
        lang = current_lang()
        self.btn_lang_ru.setStyleSheet(
            "QPushButton { font-size: 10px; font-weight: bold; padding: 0px; background: %s; }"
            % ("#3b82f6; color: white" if lang == "ru" else "transparent")
        )
        self.btn_lang_en.setStyleSheet(
            "QPushButton { font-size: 10px; font-weight: bold; padding: 0px; background: %s; }"
            % ("#3b82f6; color: white" if lang == "en" else "transparent")
        )
        theme = current_theme()
        self.btn_theme_dark.setStyleSheet(
            "QPushButton { font-size: 10px; padding: 0px; background: %s; }"
            % ("#3b82f6; color: white" if theme == "dark" else "transparent")
        )
        self.btn_theme_light.setStyleSheet(
            "QPushButton { font-size: 10px; padding: 0px; background: %s; }"
            % ("#3b82f6; color: white" if theme == "light" else "transparent")
        )

    def _on_settings(self):
        dlg = SettingsDialog(self._main)
        dlg.exec_()

    def _on_preset(self, kw: str):
        current = self.kw_input.text().strip()
        if current:
            kws = set(current.replace(",", " ").split())
            kws.add(kw)
            self.kw_input.setText(", ".join(sorted(kws)))
        else:
            self.kw_input.setText(kw)

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
        period_map = {_("period.1h"): 1/24, _("period.2h"): 2/24, _("period.4h"): 4/24, _("period.6h"): 6/24,
                      _("period.8h"): 8/24, _("period.12h"): 12/24, _("period.24h"): 1, _("period.3d"): 3, _("period.7d"): 7}
        time_days = period_map.get(self.period_combo.currentText(), 1)
        tokens = _auth_data.get("github_tokens", [])
        repos = []
        owner = None
        if gh_url:
            m_repo = re.match(r'(?:https?://)?github\.com/([^/]+/[^/]+?)/?$', gh_url)
            m_user = re.match(r'(?:https?://)?github\.com/([^/]+)/?$', gh_url)
            if m_repo:
                repos.append(m_repo.group(1))
            elif m_user:
                owner = m_user.group(1)
        self._cleanup_gh()
        cfg = PERF_PRESETS.get(_settings_data.get("perf_mode", "medium"))
        self._gh_worker = GitHubSearchWorker(
            keywords, set(), explicit_repos=repos,
            time_filter_days=int(time_days), github_tokens=tokens,
            max_repos=cfg["max_repos"], max_files=cfg["max_files"],
            owner=owner, weak_hw=weak_hw, deep_search=deep_search
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
        self._main._status_search.setStyleSheet("color: #00ff00; font-weight: bold; padding: 1px 4px;")
        self._main._status_search.setText("🔍 ✅ DONE")
        QTimer.singleShot(3000, lambda: self._main._status_search.setStyleSheet(""))

    def _on_gh_error(self, err: str):
        self.gh_progress_bar.setVisible(False)
        self.btn_quick_search.setEnabled(True)
        self.btn_deep_search.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.gh_status.setText(f"⚠ {err[:60]}")
        self.gh_found_label.setText("⚠")
        self._cleanup_gh()
        
        # Bright error indicator
        self._main._status_search.setStyleSheet("color: #ff0000; font-weight: bold; padding: 1px 4px;")
        self._main._status_search.setText("🔍 ❌ ERROR")
        QTimer.singleShot(3000, lambda: self._main._status_search.setStyleSheet(""))

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
            self.repo_input.setText(repo)
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
        self.src_table.horizontalHeader().setStretchLastSection(True)
        self.src_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.src_table.setColumnWidth(0, 24)
        self.src_table.setColumnWidth(2, 60)
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
                background: transparent; border: 1px dashed #7aa2f7;
                color: #7aa2f7; font-size: 11px; padding: 2px 10px;
                border-radius: 10px; font-weight: 400; text-transform: none;
                letter-spacing: 0;
            }
            QPushButton:hover {
                background: rgba(122, 162, 247, 0.12);
                border: 1px solid #7aa2f7;
            }
        """)
        self.btn_toggle_sources.clicked.connect(self._toggle_sources)
        layout.addWidget(self.btn_toggle_sources)

        # Stats
        stats_row = QHBoxLayout()
        self.lbl_total = QLabel(_("download.stats.total", count=0))
        self.lbl_total.setStyleSheet("padding: 4px 8px; background: #0a0a0a; border: 1px solid #404040; border-radius: 4px;")
        stats_row.addWidget(self.lbl_total)
        self.lbl_detail = QLabel("")
        self.lbl_detail.setStyleSheet("padding: 4px 8px; background: #0a0a0a; border: 1px solid #404040; border-radius: 4px;")
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
        self.lbl_phase.setStyleSheet("font-size: 11px; color: #545457;")
        progress_row.addWidget(self.lbl_phase)
        layout.addLayout(progress_row)

        # Log
        self.log_out = QTextEdit()
        self.log_out.setReadOnly(True)
        self.log_out.setMaximumHeight(100)
        self.log_out.setStyleSheet("background: #000000; color: #545457; font-size: 12px;")
        layout.addWidget(self.log_out)

        # Bottom nav
        nav = QHBoxLayout()
        self.btn_next = QPushButton(_("download.btn.next"))
        self.btn_next.setEnabled(False)
        self.btn_next.clicked.connect(self._on_next)
        nav.addStretch()
        nav.addWidget(self.btn_next)
        layout.addLayout(nav)

    def _set_phase(self, phase: int):
        self._phase = phase
        if phase == self.PHASE_FETCH:
            self.btn_stop.setText(_("download.btn.stop_fetch"))
            self.btn_stop.setStyleSheet("background: rgba(224, 108, 117, 0.12); color: #e06c75; border: 1px solid rgba(224, 108, 117, 0.4);")
            self.btn_stop.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.lbl_phase.setText(_("download.phase.fetch"))
        else:
            self.btn_stop.setText(_("download.btn.stop"))
            self.btn_stop.setStyleSheet("")
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.lbl_phase.setText("")

    def _log(self, msg: str):
        self.log_out.append(msg)
        sb = self.log_out.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _cleanup_net(self):
        _cleanup_thread(getattr(self, '_net_thread', None), getattr(self, '_net_worker', None))
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

        self.src_table.setRowCount(0)
        for name, _url in sources:
            self._add_source_row(name)

        self.src_group.show()
        self.btn_toggle_sources.show()
        self.btn_toggle_sources.setText(_("download.hide_sources"))
        self.lbl_detail.hide()
        self.lbl_total.show()
        self.btn_next.setEnabled(False)
        self.progress_bar.setMaximum(len(sources))
        self.progress_bar.setValue(0)
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
        self.lbl_progress.setText(f"{done}/{total}")

    def _on_proxy_parsed(self, entries: list[ProxyEntry]):
        self._entries.extend(entries)
        self.lbl_total.setText(_("download.stats.total", count=len(self._entries)))

    def _on_source_started(self, name: str, idx: int):
        for row in range(self.src_table.rowCount()):
            item = self.src_table.item(row, 1)
            if item and item.text() == name[:60]:
                icon_item = self.src_table.item(row, 0)
                if icon_item:
                    icon_item.setText("⟳")
                for c in range(3):
                    cell = self.src_table.item(row, c)
                    if cell:
                        cell.setBackground(QColor("#1a1a2e"))
                break

    def _add_source_row(self, name: str):
        row = self.src_table.rowCount()
        self.src_table.insertRow(row)
        icon_item = QTableWidgetItem("⏳")
        icon_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_table.setItem(row, 0, icon_item)
        name_item = QTableWidgetItem(name[:60])
        name_item.setToolTip(name)
        self.src_table.setItem(row, 1, name_item)
        count_item = QTableWidgetItem("...")
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.src_table.setItem(row, 2, count_item)
        self._sources_total += 1

    def _update_source_row(self, name: str, ok: bool, count: int):
        for row in range(self.src_table.rowCount()):
            item = self.src_table.item(row, 1)
            if item and item.text() == name[:60]:
                icon_item = self.src_table.item(row, 0)
                if icon_item:
                    icon_item.setText("✅" if ok else "❌")
                count_item = self.src_table.item(row, 2)
                if count_item:
                    count_item.setText(str(count))
                for c in range(3):
                    cell = self.src_table.item(row, c)
                    if cell:
                        cell.setBackground(QColor("#000000"))
                if ok:
                    self._sources_ok += 1
                break

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
        protos: dict[str, int] = {}
        for e in self._entries:
            p = e.protocol or "?"
            protos[p] = protos.get(p, 0) + 1
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
    PHASE_GEO = 2

    def __init__(self, main):
        super().__init__(main)
        self._main = main
        self._entries = []
        self._filtered_entries = []
        self._filter_proto: str | None = None
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
        self._geo_thread = None
        self._geo_worker = None

        layout = QVBoxLayout(self)

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

        # Stats bar
        stats_row = QHBoxLayout()
        self.lbl_total = QLabel(_("test.stats.total", count=0))
        self.lbl_valid = QLabel(_("test.stats.valid", count=0))
        self.lbl_dead = QLabel(_("test.stats.dead", count=0))
        self.lbl_current = QLabel("")
        self.lbl_current.setStyleSheet("padding: 4px 8px; background: #0a0a0a; border: 1px solid #404040; border-radius: 4px; color: #7aa2f7;")
        for lbl in (self.lbl_total, self.lbl_valid, self.lbl_dead):
            lbl.setStyleSheet("padding: 4px 8px; background: #0a0a0a; border: 1px solid #404040; border-radius: 4px;")
            stats_row.addWidget(lbl)
        stats_row.addStretch()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            _("test.filter.all"), _("test.filter.tuic"),
            _("test.filter.vless"), _("test.filter.vmess"),
            _("test.filter.trojan"), _("test.filter.ss"),
            _("test.filter.hy2"),
        ])
        self.filter_combo.setStyleSheet("QComboBox { font-size: 10px; padding: 2px 4px; min-width: 60px; }")
        self.filter_combo.currentIndexChanged.connect(self._on_filter_change)
        stats_row.addWidget(self.filter_combo)
        stats_row.addWidget(self.lbl_current)

        self.btn_tcp = QPushButton(_("test.btn.tcp"))
        self.btn_tcp.clicked.connect(self._on_tcp_test)
        stats_row.addWidget(self.btn_tcp)

        self.btn_deep = QPushButton(_("test.btn.deep"))
        self.btn_deep.clicked.connect(self._on_deep_test)
        stats_row.addWidget(self.btn_deep)

        self.btn_continue = QPushButton(_("test.btn.continue"))
        self.btn_continue.clicked.connect(self._on_continue)
        self.btn_continue.setVisible(False)
        stats_row.addWidget(self.btn_continue)

        self.btn_geo = QPushButton(_("test.btn.geo"))
        self.btn_geo.setEnabled(False)
        self.btn_geo.clicked.connect(self._on_geo)
        
        self.lbl_threads = QLabel(_("test.threads"))
        stats_row.addWidget(self.lbl_threads)
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 32)
        self.spin_threads.setValue(4)
        self.spin_threads.setFixedWidth(50)
        self.spin_threads.setStyleSheet("QSpinBox { font-size: 10px; padding: 2px; }")
        stats_row.addWidget(self.spin_threads)
        
        stats_row.addWidget(self.btn_geo)

        self.btn_delete_dead = QPushButton(_("test.btn.delete_dead"))
        self.btn_delete_dead.clicked.connect(self._on_delete_dead)
        self.btn_delete_dead.setEnabled(False)
        stats_row.addWidget(self.btn_delete_dead)
        layout.addLayout(stats_row)

        # Proxy table
        self.model = ProxyTableModel()
        self.proxy_table = QTableView()
        self.proxy_table.setModel(self.model)
        self.proxy_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.proxy_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.proxy_table.setAlternatingRowColors(True)
        self.proxy_table.horizontalHeader().setStretchLastSection(True)
        self.proxy_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.proxy_table.setColumnWidth(0, 30)
        self.proxy_table.setColumnWidth(1, 80)
        self.proxy_table.setColumnWidth(2, 150)
        self.proxy_table.setColumnWidth(3, 70)
        self.proxy_table.setColumnWidth(4, 100)
        self.proxy_table.setColumnWidth(5, 60)
        self.proxy_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.proxy_table.customContextMenuRequested.connect(self._on_table_context)
        layout.addWidget(self.proxy_table)

        # Progress bar
        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_row.addWidget(self.progress_bar)
        self.lbl_phase = QLabel("")
        self.lbl_phase.setStyleSheet("font-size: 11px; color: #545457;")
        progress_row.addWidget(self.lbl_phase)
        layout.addLayout(progress_row)

        # Log
        self.log_out = QTextEdit()
        self.log_out.setReadOnly(True)
        self.log_out.setMaximumHeight(100)
        self.log_out.setStyleSheet("background: #000000; color: #545457; font-size: 12px;")
        layout.addWidget(self.log_out)

        # Bottom nav
        nav = QHBoxLayout()
        self.btn_export = QPushButton(_("test.btn.export"))
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(lambda: self._main.set_page(3))
        nav.addStretch()
        nav.addWidget(self.btn_export)
        layout.addLayout(nav)

    def load_entries(self, entries: list[ProxyEntry]):
        self._entries = entries
        self._filtered_entries = list(entries)
        self._valid_cnt = 0
        self._dead_cnt = 0
        self.filter_combo.setCurrentIndex(0)
        self.model.clear()
        self.model.add_proxies(entries)
        self._update_stats()
        has = len(entries) > 0
        self.btn_tcp.setEnabled(has)
        self.btn_deep.setEnabled(has)

    def _set_phase(self, phase: int):
        self._phase = phase
        if phase == self.PHASE_TEST:
            self.btn_stop.setText(_("test.btn.stop_test"))
            self.btn_stop.setStyleSheet("background: rgba(224, 108, 117, 0.12); color: #e06c75; border: 1px solid rgba(224, 108, 117, 0.4);")
            self.btn_stop.setEnabled(True)
            self.btn_tcp.setEnabled(False)
            self.btn_deep.setEnabled(False)
            self.btn_continue.setVisible(False)
            self.btn_geo.setEnabled(False)
            self.btn_export.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.lbl_phase.setText(_("test.phase.test"))
        elif phase == self.PHASE_GEO:
            self.btn_stop.setText(_("test.btn.stop_test"))
            self.btn_stop.setStyleSheet("background: rgba(224, 108, 117, 0.12); color: #e06c75; border: 1px solid rgba(224, 108, 117, 0.4);")
            self.btn_stop.setEnabled(True)
            self.btn_tcp.setEnabled(False)
            self.btn_deep.setEnabled(False)
            self.btn_continue.setVisible(False)
            self.btn_geo.setEnabled(False)
            self.btn_export.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.lbl_phase.setText(_("test.phase.geo"))
        else:
            self.btn_stop.setText(_("test.btn.stop"))
            self.btn_stop.setStyleSheet("")
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.lbl_phase.setText("")
            has_entries = len(self._entries) > 0
            has_valid = self._valid_cnt > 0
            self.btn_tcp.setEnabled(has_entries)
            self.btn_deep.setEnabled(has_entries)
            self.btn_geo.setEnabled(has_valid)
            self.btn_delete_dead.setEnabled(self._dead_cnt > 0)
            self.btn_export.setEnabled(has_valid)

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
        if self._phase == self.PHASE_GEO:
            self._cleanup_geo()
            self._log(_("log.geo_stopped"))
            self._set_phase(self.PHASE_IDLE)
            self._main.update_status_bar()
            return
        self._cleanup_test()
        self._log(_("log.test_stopped"))
        self.model.dedup_by_key()
        self._entries = self.model.proxies
        if self._valid_cnt > 0:
            self.btn_export.setEnabled(True)
        self._stopped = True
        self._set_phase(self.PHASE_IDLE)
        # Show continue if there are untested entries
        if self._test_type and self._count_untested() > 0:
            self.btn_continue.setVisible(True)
        self._main.update_status_bar()

    def _count_untested(self) -> int:
        f = "tcp_tested" if self._test_type == "tcp" else "deep_tested"
        return sum(1 for e in self._entries if not getattr(e, f))

    def _on_continue(self):
        if not self._test_type or not self._entries:
            return
        f = "tcp_tested" if self._test_type == "tcp" else "deep_tested"
        remaining = [(i, e) for i, e in enumerate(self._entries) if not getattr(e, f)]
        if not remaining:
            self.btn_continue.setVisible(False)
            return
        indices, entries = zip(*remaining) if remaining else ([], [])
        self._log(_("log.test_resumed", count=len(entries)))
        self._run_test(deep=(self._test_type == "deep"), subset=list(entries), subset_indices=list(indices))

    def _count_geo_remaining(self) -> int:
        return sum(1 for e in self._entries if (e.tcp_ok or e.deep_ok) and not e.geo_tested)

    def _cleanup_geo(self):
        _cleanup_thread(getattr(self, '_geo_thread', None), getattr(self, '_geo_worker', None))
        self._geo_thread = None
        self._geo_worker = None

    def _on_geo(self):
        _debug(f"_on_geo: phase={self._phase}")
        if self._phase != self.PHASE_IDLE:
            return
        entry_set = set(id(e) for e in self._filtered_entries)
        valid = [(i, e) for i, e in enumerate(self._entries) if id(e) in entry_set and (e.tcp_ok or e.deep_ok) and not e.geo_tested]
        if not valid:
            self._log(_("log.geo_done", count=0))
            return
        indices, entries = zip(*valid)
        self._log(_("log.geo_start", count=len(entries)))
        self._set_phase(self.PHASE_GEO)
        self.progress_bar.setMaximum(len(entries))
        self.progress_bar.setValue(0)

        self._geo_worker = GeoWorker()
        self._geo_worker.geo_result_signal.connect(self._on_geo_result)
        self._geo_worker.log_signal.connect(self._log)
        self._geo_worker.finished.connect(self._on_geo_finished)

        self._geo_thread = QThread()
        self._geo_worker.moveToThread(self._geo_thread)
        self._geo_thread.started.connect(
            lambda: self._geo_worker.geo_batch(list(entries), list(indices)),
            Qt.ConnectionType.DirectConnection)
        self._geo_thread.start()

    def _on_geo_result(self, row: int, code: str, name: str):
        if 0 <= row < len(self._entries):
            e = self._entries[row]
            e.country = f"{country_flag(code)} {name}"
            e.geo_tested = True
            idx = self.model.index(row, 4)
            self.model.dataChanged.emit(idx, idx)

    def _on_geo_finished(self):
        self._cleanup_geo()
        total = sum(1 for e in self._entries if e.geo_tested)
        self._log(_("log.geo_done", count=total))
        self._set_phase(self.PHASE_IDLE)
        self._main.update_status_bar()

    def _on_tcp_test(self):
        if self._phase == self.PHASE_TEST:
            return
        if not self._filtered_entries:
            return
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._test_type = "tcp"
        self._run_test(deep=False, subset=self._filtered_entries)

    def _on_deep_test(self):
        if self._phase == self.PHASE_TEST:
            return
        if not self._filtered_entries:
            return
        self._valid_cnt = 0
        self._dead_cnt = 0
        self._test_type = "deep"
        self._run_test(deep=True, subset=self._filtered_entries)

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
        self.btn_export.setEnabled(self._valid_cnt > 0)
        self._log(_("log.deleted_dead", count=removed))

    def _run_test(self, deep: bool = False, subset: list[ProxyEntry] | None = None, subset_indices: list[int] | None = None):
        target = subset if subset is not None else self._entries
        self._stop_requested = False
        self._set_phase(self.PHASE_TEST)
        self.progress_bar.setMaximum(len(self._entries))
        self.progress_bar.setValue(len(self._entries) - len(target))

        self._tester = TesterWorker(deep=deep, test_threads=self.spin_threads.value(), deep_threads=max(1, self.spin_threads.value() // 2))
        self._tester.result_signal.connect(self._on_test_result)
        self._tester.testing_signal.connect(self._on_testing_start)
        self._tester.progress_signal.connect(self._on_test_progress)
        self._tester.count_signal.connect(self._on_test_count)
        self._tester.log_signal.connect(self._log)
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
        self.model.update_entry(row, ok, latency, error, ttype)
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
            kind = "TCP" if ttype == 0 else "DEEP"
            mark = _("event.ok") if ok else _("event.fail")
            self.lbl_current.setText(_("event.test_current", n=row+1, mark=mark, kind=kind, proto=e.protocol, host=e.host, port=e.port))

    def _on_test_count(self, c: int):
        self.progress_bar.setValue(c)

    def _on_test_progress(self, done: int, total: int, threads: int, mode: str):
        now = time.time()
        if now - self._last_log_time > 0.5:
            self._log(_("event.threads", mode=mode, done=done, total=total, threads=threads))
            self._last_log_time = now
        if not self.lbl_current.text():
            self.lbl_current.setText(_("event.test_progress", mode=mode, done=done, total=total, pct=done*100//max(total,1)))

    def _on_test_finished(self):
        self._cleanup_test()
        if self._stop_requested:
            self._stop_requested = False
            return
        self._stopped = False
        self._completed = True
        self._set_phase(self.PHASE_IDLE)
        self.btn_delete_dead.setEnabled(self._dead_cnt > 0)
        self.btn_geo.setEnabled(self._valid_cnt > 0)
        self._log(_("log.test_done", valid=self._valid_cnt, total=len(self._entries)))
        self._main.update_status_bar()

    def _on_filter_change(self, idx: int):
        proto_map = [None, "TUIC", "VLESS", "VMESS", "Trojan", "SS", "Hy2"]
        self._filter_proto = proto_map[idx] if 0 < idx < len(proto_map) else None
        self._apply_filter()

    def _apply_filter(self):
        if self._filter_proto is None:
            self._filtered_entries = list(self._entries)
        else:
            self._filtered_entries = [e for e in self._entries if e.protocol == self._filter_proto]
        self.model.clear()
        self.model.add_proxies(self._filtered_entries)
        self._update_stats()

    def _update_stats(self):
        entries = self._filtered_entries
        total = len(entries)
        valid = sum(1 for e in entries if e.tcp_ok is True or e.deep_ok is True)
        dead = sum(1 for e in entries if e.tcp_ok is False and e.deep_ok is False and (e.tcp_tested or e.deep_tested))
        self.lbl_total.setText(_("test.stats.total", count=total))
        self.lbl_valid.setText(_("test.stats.valid", count=valid))
        self.lbl_dead.setText(_("test.stats.dead", count=dead))

    def _on_table_context(self, pos):
        idx = self.proxy_table.indexAt(pos)
        if not idx.isValid():
            return
        entry = self._entries[idx.row()]
        menu = QMenu()
        menu.addAction(_("test.context.copy_uri"), lambda: QApplication.clipboard().setText(entry.uri))
        tcp_mark = _("event.ok") if entry.tcp_ok else _("event.fail")
        deep_mark = "⚡" if entry.deep_ok else "—"
        ping_str = f"{entry.latency_ms:.0f}ms" if entry.latency_ms else "—"
        details = _("test.context.details_text",
            proto=entry.protocol, host=entry.host, port=entry.port,
            sni=entry.sni or "—", country=entry.country or "—",
            tcp=tcp_mark, deep=deep_mark, ping=ping_str)
        menu.addAction(_("test.context.details"), lambda: QMessageBox.information(self, _("test.context.details"), details))
        menu.exec_(self.proxy_table.mapToGlobal(pos))

    def on_enter(self):
        self._update_stats()
        self.btn_export.setEnabled(self._valid_cnt > 0)
        self.btn_geo.setEnabled(self._valid_cnt > 0 and self._count_geo_remaining() > 0)
        self._main.update_status_bar()

    def on_leave(self):
        self._cleanup_test()
        self._cleanup_geo()

    def retranslate(self):
        self.lbl_title.setText(_("test.title"))
        self.btn_stop.setText(_("test.btn.stop"))
        self.btn_back.setText(_("test.btn.back"))
        self.lbl_total.setText(_("test.stats.total", count=len(self._entries)))
        self.lbl_valid.setText(_("test.stats.valid", count=self._valid_cnt))
        self.lbl_dead.setText(_("test.stats.dead", count=self._dead_cnt))
        self.btn_tcp.setText(_("test.btn.tcp"))
        self.btn_deep.setText(_("test.btn.deep"))
        self.btn_continue.setText(_("test.btn.continue"))
        self.btn_geo.setText(_("test.btn.geo"))
        self.btn_delete_dead.setText(_("test.btn.delete_dead"))
        self.btn_export.setText(_("test.btn.export"))
        # Rebuild filter combo
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
        self.lbl_threads.setText(_("test.threads"))
        if self._phase == self.PHASE_TEST:
            self.btn_stop.setText(_("test.btn.stop_test"))
            self.lbl_phase.setText(_("test.phase.test"))
        elif self._phase == self.PHASE_GEO:
            self.lbl_phase.setText(_("test.phase.geo"))
        else:
            self.lbl_phase.setText("")
        self._update_stats()

    def get_entries(self) -> list[ProxyEntry]:
        return self._filtered_entries


class ExportPage(WizardPage):
    def __init__(self, main):
        super().__init__(main)
        self._main = main

        layout = QVBoxLayout(self)
        layout.setSpacing(5)

        top = QHBoxLayout()
        self.lbl_title = QLabel(_("export.title"))
        top.addWidget(self.lbl_title)
        top.addStretch()

        self.btn_back = QPushButton(_("export.btn.back"))
        self.btn_back.clicked.connect(lambda: self._main.set_page(2))
        top.addWidget(self.btn_back)
        layout.addLayout(top)

        # Stats
        self.stats_lbl = QLabel("")
        self.stats_lbl.setStyleSheet("padding: 8px; background: #0a0a0a; border: 1px solid #404040; border-radius: 4px;")
        layout.addWidget(self.stats_lbl)

        # Format selection
        self.fmt_group = QGroupBox(_("export.group.format"))
        fmt_layout = QVBoxLayout(self.fmt_group)
        self.fmt_raw = QRadioButton(_("export.radio.raw"))
        self.fmt_v2rayn = QRadioButton(_("export.radio.v2rayn"))
        self.fmt_singbox = QRadioButton(_("export.radio.singbox"))
        self.fmt_clash = QRadioButton(_("export.radio.clash"))
        self.fmt_hiddify = QRadioButton(_("export.radio.hiddify"))
        self.fmt_raw.setChecked(True)
        for rb in (self.fmt_raw, self.fmt_v2rayn, self.fmt_singbox, self.fmt_clash, self.fmt_hiddify):
            fmt_layout.addWidget(rb)
        layout.addWidget(self.fmt_group)

        # Options
        self.opt_group = QGroupBox(_("export.group.options"))
        opt_layout = QVBoxLayout(self.opt_group)
        self.chk_failed = QCheckBox(_("export.chk.failed"))
        self.chk_smart_names = QCheckBox(_("export.chk.smart_names"))
        self.chk_clean_names = QCheckBox(_("export.chk.clean_names"))
        self.chk_smart_names.setChecked(True)
        opt_layout.addWidget(self.chk_failed)
        opt_layout.addWidget(self.chk_smart_names)
        opt_layout.addWidget(self.chk_clean_names)
        layout.addWidget(self.opt_group)

        layout.addStretch()

        # Buttons
        btn_row = QHBoxLayout()
        self.btn_copy = QPushButton(_("export.btn.copy"))
        self.btn_copy.clicked.connect(self._on_copy)
        btn_row.addWidget(self.btn_copy)

        self.btn_save = QPushButton(_("export.btn.save"))
        self.btn_save.clicked.connect(self._on_save)
        btn_row.addWidget(self.btn_save)

        self.btn_save_desk = QPushButton(_("export.btn.save_desktop"))
        self.btn_save_desk.clicked.connect(self._on_save_desktop)
        btn_row.addWidget(self.btn_save_desk)
        layout.addLayout(btn_row)

        # Preview
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(120)
        self.preview.setStyleSheet("background: #000000; color: #f0f0fa; font-family: monospace; font-size: 11px;")
        self.lbl_preview = QLabel(_("export.label.preview"))
        layout.addWidget(self.lbl_preview)
        layout.addWidget(self.preview)

    def on_enter(self):
        entries = self._main.test_page.get_entries()
        total = len(entries)
        tcp_ok = self._main.test_page._valid_cnt
        self.stats_lbl.setText(_("export.stats", total=total, tcp=tcp_ok, deep="—"))
        QTimer.singleShot(0, self._update_preview)
        self._main.update_status_bar()

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
        entries = self._main.test_page.get_entries()
        fmt = self._get_format_func()
        clean_names = self.chk_clean_names.isChecked()
        
        # Check if we are doing Raw + Smart/Clean names
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
                lines.append(f"{e.uri}#{name}")
            return "\n".join(lines) + "\n"
        
        # Handle other formats
        if self.fmt_clash.isChecked():
            return fmt(entries, include_failed=self.chk_failed.isChecked(), clean_names=clean_names)
        return fmt(entries, include_failed=self.chk_failed.isChecked())

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
        self.fmt_group.setTitle(_("export.group.format"))
        self.fmt_raw.setText(_("export.radio.raw"))
        self.fmt_v2rayn.setText(_("export.radio.v2rayn"))
        self.fmt_singbox.setText(_("export.radio.singbox"))
        self.fmt_clash.setText(_("export.radio.clash"))
        self.fmt_hiddify.setText(_("export.radio.hiddify"))
        self.opt_group.setTitle(_("export.group.options"))
        self.chk_failed.setText(_("export.chk.failed"))
        self.chk_smart_names.setText(_("export.chk.smart_names"))
        self.btn_copy.setText(_("export.btn.copy"))
        self.btn_save.setText(_("export.btn.save"))
        self.btn_save_desk.setText(_("export.btn.save_desktop"))
        self.lbl_preview.setText(_("export.label.preview"))

    def _on_copy(self):
        content = self._get_content()
        QApplication.clipboard().setText(content)
        QMessageBox.information(self, _("msg.done"), _("msg.copied"))

    def _on_save(self):
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        default_name = f"sub_ski_{ts}.txt"
        path, _ = QFileDialog.getSaveFileName(self, _("export.btn.save"),
                                              os.path.join(DESKTOP_DIR, default_name),
                                              "All files (*.*)")
        if not path:
            return
        content = self._get_content()
        with open(path, "w") as f:
            f.write(content)
        QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))

    def _on_save_desktop(self):
        ts = datetime.now().strftime("%Y.%m.%d_%H%M")
        path = os.path.join(DESKTOP_DIR, f"sub_ski_{ts}.txt")
        content = self._get_content()
        with open(path, "w") as f:
            f.write(content)
        QMessageBox.information(self, _("msg.done"), _("msg.saved", path=path))


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
        tabs.addTab(gen, _("settings.tab.general"))

        # GitHub tab
        gh = QWidget()
        gh_layout = QVBoxLayout(gh)
        gh_layout.addWidget(QLabel(_("settings.label.tokens")))
        self.tokens_edit = QPlainTextEdit()
        self.tokens_edit.setPlaceholderText(_("settings.input.tokens.placeholder"))
        self.tokens_edit.setFixedHeight(80)
        tokens = _auth_data.get("github_tokens", [])
        self.tokens_edit.setPlainText("\n".join(tokens))
        gh_layout.addWidget(self.tokens_edit)

        gh_layout.addWidget(QLabel(_("settings.label.gh_url_hint")))
        btn_check = QPushButton(_("settings.btn.check_token"))
        btn_check.clicked.connect(self._on_check_token)
        gh_layout.addWidget(btn_check)

        self.check_result = QLabel("")
        gh_layout.addWidget(self.check_result)
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
        tokens = [t.strip() for t in self.tokens_edit.toPlainText().strip().splitlines() if t.strip()]
        if not tokens:
            self.check_result.setText(_("settings.token.none"))
            return
        token = tokens[0]
        self.check_result.setText(_("settings.token.checking"))
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(1)
        def _check():
            try:
                req = urllib.request.Request("https://api.github.com/user",
                                             headers={"Authorization": f"token {token}", "User-Agent": "proxy-skitchen"})
                resp = urllib.request.urlopen(req, timeout=5)
                data = json.loads(resp.read())
                limit = resp.headers.get('X-RateLimit-Remaining', '?')
                return _("settings.token.ok", login=data.get('login', '?'), limit=limit)
            except Exception as e:
                return _("settings.token.error", error=str(e)[:60])
        def _on_done(fut):
            result = fut.result()
            QTimer.singleShot(0, lambda: self.check_result.setText(result))
        fut = pool.submit(_check)
        fut.add_done_callback(_on_done)

    def _on_save(self):
        tokens = [t.strip() for t in self.tokens_edit.toPlainText().strip().splitlines() if t.strip()]
        _auth_data["github_tokens"] = tokens

        _settings_data["perf_mode"] = {"low 🐢": "low", "medium ⚡": "medium", "high 🚀": "high"}.get(self.perf_combo.currentText(), "medium")
        _settings_data["proxy_enabled"] = self.cb_proxy.isChecked()
        _settings_data["proxy_type"] = self.proxy_type.currentText().lower()
        _settings_data["proxy_host"] = self.proxy_host.text().strip()
        _settings_data["proxy_port"] = self.proxy_port.value()
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

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 0)

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

        # Clickable step labels (replaces nav bar)
        status_bar = QHBoxLayout()
        status_bar.setContentsMargins(2, 1, 2, 2)
        self._status_search = QLabel("🔍 ⏹")
        self._status_search.setObjectName("StatusBarLabel")
        self._status_search.setCursor(Qt.CursorShape.PointingHandCursor)
        self._status_search.mousePressEvent = lambda e: self.set_page(0)

        self._status_fetch = QLabel("📥 ⏹")
        self._status_fetch.setObjectName("StatusBarLabel")
        self._status_fetch.setCursor(Qt.CursorShape.PointingHandCursor)
        self._status_fetch.mousePressEvent = lambda e: self.set_page(1)

        self._status_test = QLabel("⚡ ⏹")
        self._status_test.setObjectName("StatusBarLabel")
        self._status_test.setCursor(Qt.CursorShape.PointingHandCursor)
        self._status_test.mousePressEvent = lambda e: self.set_page(2)

        self._status_export = QLabel("📤 ⏹")
        self._status_export.setObjectName("StatusBarLabel")
        self._status_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self._status_export.mousePressEvent = lambda e: self.set_page(3)

        status_bar.addWidget(self._status_search)
        status_bar.addWidget(self._status_fetch)
        status_bar.addWidget(self._status_test)
        status_bar.addWidget(self._status_export)
        status_bar.addStretch()
        layout.addLayout(status_bar)

        self._current_page = 0
        self.apply_theme()

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
        self._status_search.setText(f"🔍 {'✅' if src_has_sources else '⏹'}")

        dl_entries = dp.get_entries() if hasattr(dp, 'get_entries') else []
        if dp._phase == dp.PHASE_FETCH:
            self._status_fetch.setText(f"📥 ⏳")
        elif len(dl_entries) > 0:
            self._status_fetch.setText(f"📥 ✅")
        else:
            self._status_fetch.setText(f"📥 ⏹")

        test_entries = tp.get_entries()
        total = len(test_entries)
        valid = sum(1 for e in test_entries if e.tcp_ok is True or e.deep_ok is True)
        if tp._phase == tp.PHASE_TEST:
            self._status_test.setText(f"⚡ ⏳")
        elif valid > 0:
            self._status_test.setText(f"⚡ ✅")
        elif total > 0:
            self._status_test.setText(f"⚡ ❌")
        else:
            self._status_test.setText(f"⚡ ⏹")

        ep_visited = ep._main._current_page >= 2
        self._status_export.setText(f"📤 {'✅' if ep_visited else '⏹'}")

    def set_page(self, idx: int):
        if idx < 0 or idx > 3:
            return
        current_w = self.stack.currentWidget()
        if hasattr(current_w, 'on_leave'):
            current_w.on_leave()

        self._current_page = idx
        self.stack.setCurrentIndex(idx)
        w = self.stack.currentWidget()
        if hasattr(w, 'on_enter'):
            w.on_enter()
        self.update_status_bar()

    def apply_theme(self):
        theme = current_theme()
        colors = THEMES[theme]
        QApplication.instance().setStyleSheet(get_style_string(colors))

        # Theme-aware proxy toggle
        indicator_bg = colors.get('button_bg', '#1f2335')
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
        self.test_page._cleanup_geo()
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
        QPushButton:disabled {{ background-color: transparent; color: #545457; border-color: {colors['border']}; }}
        QLineEdit, QComboBox {{
            background-color: {colors['input_bg']}; color: {colors['fg']};
            border: 1px solid {colors['border']}; border-radius: 3px; padding: 4px 8px;
        }}
        QGroupBox {{
            border: 1px solid {colors['border']}; border-radius: 4px; margin-top: 10px;
            padding: 10px 6px 6px 6px; font-weight: 700;
        }}
        QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; color: {colors['fg']}; }}
        QProgressBar {{
            background-color: {colors['input_bg']}; border: 1px solid {colors['border']};
            text-align: center; color: {colors['fg']}; height: 18px;
        }}
        QProgressBar::chunk {{ background-color: {colors['accent']}; }}
        QListWidget, QTableWidget {{
            background-color: {colors['input_bg']}; border: 1px solid {colors['border']};
        }}
        #StatusBarLabel {{
            padding: 1px 4px;
            background-color: transparent;
            border: none;
            font-family: monospace;
            font-size: 10px;
            color: {colors['accent']};
        }}
    """

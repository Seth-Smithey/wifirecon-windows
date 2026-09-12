"""The application window.

A rail of views on the left, a status bar across the top, and one view showing
at a time. The top left always names the adapter in use and what the engine is
doing right now, so it is never ambiguous whether something is happening.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QPoint, QSize, Qt, Signal
from PySide6.QtGui import QAction, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from .. import scanner
from ..config import config
from ..services import ServiceError, adapters_svc, lifecycle, survey_svc
from ..services import marks as marks_service
from ..services import networks as networks_service
from . import theme
from .bridge import ScanBridge, pool
from .common import (
    PhaseStrip,
    Readout,
    StatusDot,
    ToastArea,
    ago,
    elide,
    human_bytes,
    mono_font,
    ui_font,
)
from .drawer import Drawer
from .icon import app_icon
from .theme import Palette
from .views.base import Context

log = logging.getLogger(__name__)


class _ClickableFrame(QFrame):
    """A panel that behaves like a button."""

    def __init__(self, on_click, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._on_click = on_click

    def mousePressEvent(self, event) -> None:  # noqa: N802
        self._on_click()

# Label, view key, and whether the rail shows a count beside it.
NAV = [
    ("Live", "live", "live"),
    ("Spectrum", "spectrum", None),
    ("Findings", "findings", "findings"),
    ("Networks", "ssids", None),
    ("Marks", "marks", None),
    ("Scan log", "history", None),
    ("Devices", "devices", "devices"),
    ("My network", "network", None),
    ("Survey", "survey", None),
    ("Report", "report", None),
    ("Adapter", "adapters", None),
    ("Diagnostics", "diagnostics", None),
    ("Settings", "settings", None),
]

# Digits are in the order the browser interface used them, which is not the
# rail order. Kept so the shortcuts do not move under anyone.
DIGIT_VIEWS = {
    "1": "live", "2": "spectrum", "3": "findings", "4": "ssids", "5": "devices",
    "6": "network", "7": "survey", "8": "report", "9": "adapters", "0": "settings",
}

MIN_WIDTH = 1100
MIN_HEIGHT = 700

# The engine publishes events, so this only catches anything that changes
# without one.
STATUS_POLL_SECONDS = 4.0


class MainWindow(QMainWindow):
    palette_changed = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._palette = theme.THEMES.get(
            config.get("ui", "theme", default="dark"), theme.DARK
        )
        self._views: dict[str, Any] = {}
        self._nav_buttons: dict[str, QPushButton] = {}
        self._nav_counts: dict[str, QLabel] = {}
        self._current = ""
        self._scanning = False
        self._adapter: dict | None = None
        self._shutting_down = False

        self.setWindowTitle("wifirecon")
        self.setWindowIcon(app_icon(self._palette))
        self.setMinimumSize(QSize(MIN_WIDTH, MIN_HEIGHT))

        self.bridge = ScanBridge(STATUS_POLL_SECONDS, self)
        self.ctx = Context(
            pool=pool,
            bridge=self.bridge,
            palette=self._palette,
            toast=self.toast,
            open_drawer=self.open_drawer,
            show_view=self.show_view,
            refresh_status=self.bridge.refresh_status,
            confirm=self.confirm,
            ask_text=self.ask_text,
            add_mark=self._add_mark,
        )

        self._build()
        self._build_status_bar()
        self._build_tray()
        self._wire()
        self.apply_palette(self._palette)
        self._restore_geometry()

    # -- construction -------------------------------------------------------

    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_rail())

        main = QWidget()
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self._build_topbar())

        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack, 1)
        layout.addWidget(main, 1)

        self._build_views()
        self._build_menus()

        # Overlays sit on the central widget so they cover the whole window.
        self.drawer = Drawer(self._palette, root)
        self.drawer.setGeometry(root.rect())
        self.toasts = ToastArea(self._palette, root)
        self.toasts.setGeometry(root.rect())
        root.installEventFilter(self)

    def _build_rail(self) -> QWidget:
        rail = QFrame()
        rail.setObjectName("rail")
        layout = QVBoxLayout(rail)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        brand = QWidget()
        brand.setObjectName("brandBox")
        brand_layout = QVBoxLayout(brand)
        brand_layout.setContentsMargins(16, 14, 16, 14)
        brand_layout.setSpacing(2)
        title = QLabel("wifirecon")
        title.setObjectName("brandTitle")
        title.setFont(ui_font(15, QFont.Weight.DemiBold))
        subtitle = QLabel("WINDOWS · PASSIVE")
        subtitle.setObjectName("brandSub")
        subtitle.setFont(mono_font(10))
        brand_layout.addWidget(title)
        brand_layout.addWidget(subtitle)
        layout.addWidget(brand)

        site_box = QWidget()
        site_box.setObjectName("sitePickBox")
        site_layout = QVBoxLayout(site_box)
        site_layout.setContentsMargins(12, 10, 12, 10)
        self.site_picker = QComboBox()
        self.site_picker.addItem("No site selected", None)
        site_layout.addWidget(self.site_picker)
        layout.addWidget(site_box)

        nav = QWidget()
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(8, 10, 8, 10)
        nav_layout.setSpacing(2)
        for text, key, count_key in NAV:
            nav_layout.addWidget(self._nav_button(text, key, count_key))
        nav_layout.addStretch(1)
        layout.addWidget(nav, 1)

        foot = QWidget()
        foot.setObjectName("railFoot")
        foot_layout = QVBoxLayout(foot)
        foot_layout.setContentsMargins(16, 10, 16, 14)
        foot_layout.setSpacing(3)
        self.foot_version = self._foot_row(foot_layout, "build", "—")
        self.foot_adapter = self._foot_row(foot_layout, "adapter", "none")
        self.foot_store = self._foot_row(foot_layout, "store", "—")
        layout.addWidget(foot)
        return rail

    def _foot_row(self, layout: QVBoxLayout, name: str, value: str) -> QLabel:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        left = QLabel(name)
        left.setFont(mono_font(10))
        right = QLabel(value)
        right.setFont(mono_font(10))
        right.setAlignment(Qt.AlignmentFlag.AlignRight)
        row.addWidget(left)
        row.addStretch(1)
        row.addWidget(right)
        layout.addWidget(holder)
        return right

    def _nav_button(self, text: str, key: str, count_key: str | None) -> QPushButton:
        btn = QPushButton()
        btn.setProperty("nav", True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setCheckable(False)
        inner = QHBoxLayout(btn)
        inner.setContentsMargins(10, 6, 10, 6)
        inner.setSpacing(10)

        tick = QFrame()
        tick.setFixedSize(3, 15)
        tick.setStyleSheet("background: transparent; border-radius: 1px;")
        inner.addWidget(tick)

        title = QLabel(text)
        title.setFont(ui_font(13))
        title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        inner.addWidget(title)
        inner.addStretch(1)

        if count_key:
            count = QLabel("")
            count.setFont(mono_font(11))
            count.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            inner.addWidget(count)
            self._nav_counts[count_key] = count

        btn.setProperty("tick", tick)
        btn.setProperty("titleLabel", title)
        btn.clicked.connect(lambda _=False, k=key: self.show_view(k))
        self._nav_buttons[key] = btn
        return btn

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("topbar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 8, 18, 8)
        layout.setSpacing(20)

        # A frame rather than a QPushButton: a button sizes itself from its own
        # text, which fights a layout put inside it and collapses the chip.
        self.adapter_chip = _ClickableFrame(lambda: self.show_view("adapters"))
        self.adapter_chip.setObjectName("adapterChip")
        self.adapter_chip.setCursor(Qt.CursorShape.PointingHandCursor)
        self.adapter_chip.setFixedWidth(256)
        chip_layout = QHBoxLayout(self.adapter_chip)
        chip_layout.setContentsMargins(10, 5, 12, 5)
        chip_layout.setSpacing(9)
        self.status_dot = StatusDot(self._palette)
        self.status_dot.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        chip_layout.addWidget(self.status_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        chip_text = QVBoxLayout()
        chip_text.setSpacing(1)
        chip_text.setContentsMargins(0, 0, 0, 0)
        self.adapter_name = QLabel("No adapter")
        self.adapter_name.setObjectName("adapterName")
        self.adapter_name.setFont(ui_font(12, QFont.Weight.DemiBold))
        self.adapter_sub = QLabel("click to choose")
        self.adapter_sub.setObjectName("adapterSub")
        self.adapter_sub.setFont(mono_font(10))
        for part in (self.adapter_name, self.adapter_sub):
            part.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            part.setStyleSheet("border: none; background: transparent;")
        chip_text.addWidget(self.adapter_name)
        chip_text.addWidget(self.adapter_sub)
        chip_layout.addLayout(chip_text, 1)
        layout.addWidget(self.adapter_chip)

        self.btn_startstop = QPushButton("Start scanning")
        self.btn_startstop.setProperty("kind", "primary")
        self.btn_startstop.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.btn_startstop)

        self.btn_single = QPushButton("Single scan")
        self.btn_single.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.btn_single)

        self.phase = PhaseStrip(self._palette)
        layout.addWidget(self.phase)

        layout.addStretch(1)

        self.readout_visible = Readout("in range")
        self.readout_known = Readout("known")
        self.readout_open = Readout("open findings", alarm=True)
        layout.addWidget(self.readout_visible)
        layout.addWidget(self.readout_known)
        layout.addWidget(self.readout_open)
        return bar

    def _build_views(self) -> None:
        from .views import build_views

        self._views = build_views(self.ctx)
        for _, key, _ in NAV:
            view = self._views.get(key)
            if view is not None:
                self.stack.addWidget(view)

    def _build_menus(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        scan_action = QAction("&Single scan", self)
        scan_action.setShortcut(QKeySequence("Ctrl+R"))
        scan_action.triggered.connect(self.single_scan)
        file_menu.addAction(scan_action)
        self.toggle_action = QAction("&Start scanning", self)
        self.toggle_action.setShortcut(QKeySequence("Ctrl+S"))
        self.toggle_action.triggered.connect(self.toggle_scanning)
        file_menu.addAction(self.toggle_action)
        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        view_menu = menu.addMenu("&View")
        for text, key, _ in NAV:
            action = QAction(text, self)
            action.triggered.connect(lambda _=False, k=key: self.show_view(k))
            view_menu.addAction(action)
        view_menu.addSeparator()
        self.theme_action = QAction("Switch to light theme", self)
        self.theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(self.theme_action)

        help_menu = menu.addMenu("&Help")
        about = QAction("About wifirecon", self)
        about.triggered.connect(self._about)
        help_menu.addAction(about)

    def _wire(self) -> None:
        self.btn_startstop.clicked.connect(self.toggle_scanning)
        self.btn_single.clicked.connect(self.single_scan)
        self.site_picker.currentIndexChanged.connect(self._site_changed)

        self.bridge.status_ready.connect(self._on_status)
        self.bridge.scanned.connect(self._on_scanned)
        self.bridge.phase_changed.connect(lambda _: self.bridge.refresh_status())
        self.bridge.state_changed.connect(lambda _: self.bridge.refresh_status())

        self.drawer.mark_requested.connect(self._add_mark)
        self.drawer.note_saved.connect(self._save_note)
        self.drawer.inventory_requested.connect(self._add_inventory)

        for digit, key in DIGIT_VIEWS.items():
            shortcut = QShortcut(QKeySequence(digit), self)
            shortcut.activated.connect(lambda k=key: self.show_view(k))
        QShortcut(QKeySequence("s"), self).activated.connect(self.toggle_scanning)
        QShortcut(QKeySequence("r"), self).activated.connect(self.bridge.refresh_status)
        QShortcut(QKeySequence("/"), self).activated.connect(self._focus_filter)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self).activated.connect(
            self.drawer.close_drawer)

    # -- appearance ---------------------------------------------------------

    def apply_palette(self, palette: Palette) -> None:
        self._palette = palette
        self.ctx.palette = palette
        self.setStyleSheet(theme.stylesheet(palette))
        self.setWindowIcon(app_icon(palette))
        self.status_dot.set_palette_colours(palette)
        self.phase.set_palette_colours(palette)
        self.drawer.set_palette_colours(palette)
        self.toasts.set_palette_colours(palette)
        for view in self._views.values():
            view.apply_palette(palette)
        for key, button in self._nav_buttons.items():
            self._paint_nav(button, key == self._current)
        self.theme_action.setText(
            "Switch to light theme" if palette.is_dark else "Switch to dark theme"
        )
        self.palette_changed.emit(palette)

    def _paint_nav(self, button: QPushButton, active: bool) -> None:
        button.setProperty("on", "true" if active else "false")
        tick = button.property("tick")
        if tick is not None:
            colour = self._palette.b5 if active else "transparent"
            tick.setStyleSheet(f"background: {colour}; border-radius: 1px;")
        title = button.property("titleLabel")
        if title is not None:
            colour = self._palette.text_hi if active else self._palette.dim
            title.setStyleSheet(f"color: {colour}; background: transparent;")
        button.style().unpolish(button)
        button.style().polish(button)

    def toggle_theme(self) -> None:
        name = "light" if self._palette.is_dark else "dark"
        config.set(name, "ui", "theme")
        self.apply_palette(theme.THEMES[name])

    # -- navigation ---------------------------------------------------------

    def show_view(self, key: str) -> None:
        view = self._views.get(key)
        if view is None:
            return
        self._current = key
        self.stack.setCurrentWidget(view)
        for nav_key, button in self._nav_buttons.items():
            self._paint_nav(button, nav_key == key)
        view.on_shown()

    def current_view(self):
        return self._views.get(self._current)

    def _focus_filter(self) -> None:
        self.show_view("live")
        view = self._views.get("live")
        if view is not None and hasattr(view, "focus_search"):
            view.focus_search()

    # -- status -------------------------------------------------------------

    def _on_status(self, payload: dict) -> None:
        engine = payload.get("engine") or {}
        alerts = payload.get("alerts") or {}
        stats = payload.get("stats") or {}

        self._scanning = bool(engine.get("scanning"))
        self._adapter = engine.get("adapter")
        self.phase.set_status(engine)
        self._update_status_bar(engine)
        if getattr(self, "tray", None) is not None:
            adapter_name = (self._adapter or {}).get("label") or "no adapter"
            self.tray.setToolTip(
                f"wifirecon — {'scanning on ' + adapter_name if self._scanning else 'idle'}"
            )
            self.tray_toggle.setText(
                "Stop scanning" if self._scanning else "Start scanning")

        if not engine.get("running") or engine.get("last_error"):
            self.status_dot.set_state("down")
        elif self._scanning:
            self.status_dot.set_state("live")
        else:
            self.status_dot.set_state("idle")

        adapter = self._adapter or {}
        name = adapter.get("label") or adapter.get("description") or "No adapter"
        self.adapter_name.setText(elide(name, 34))
        if not self._adapter:
            sub = "click to choose"
        elif not self._scanning:
            sub = f"ready · {adapter.get('band_label') or 'idle'}"
        elif engine.get("last_error"):
            sub = "scan failing"
        else:
            sub = adapter.get("band_label") or "scanning"
        self.adapter_sub.setText(sub)
        self.adapter_chip.setToolTip(
            f"{adapter.get('description') or 'No adapter selected'}\n"
            f"{adapter.get('mac') or ''} driver {adapter.get('driver') or '—'}\n"
            "Click to change adapter"
        )

        self.btn_startstop.setText("Stop scanning" if self._scanning else "Start scanning")
        self.btn_startstop.setProperty("kind", "danger" if self._scanning else "primary")
        self.btn_startstop.style().unpolish(self.btn_startstop)
        self.btn_startstop.style().polish(self.btn_startstop)
        self.toggle_action.setText(
            "Stop scanning" if self._scanning else "Start scanning")

        # The engine's own count is what it heard last scan. Before it has
        # scanned in this session there is no such number, so what the database
        # saw recently stands in rather than showing a misleading zero.
        visible = engine.get("stats", {}).get("bss_seen") or payload.get("recent") or 0
        open_findings = alerts.get("unacked") or 0
        self.readout_visible.set_value(visible)
        self.readout_known.set_value(stats.get("total_bss") or 0)
        self.readout_open.set_value(open_findings)

        self._set_count("live", visible)
        self._set_count("findings", open_findings, hot=bool(open_findings))
        self._set_count("devices", payload.get("devices") or 0)

        from .. import updater

        self.foot_version.setText(
            f"{updater.version()}{' mock' if engine.get('mock') else ''}"
        )
        self.foot_adapter.setText(elide(name, 18) if self._adapter else "none")
        self.foot_store.setText(human_bytes(payload.get("db_size_bytes")))

    def _set_count(self, key: str, value: Any, hot: bool = False) -> None:
        widget = self._nav_counts.get(key)
        if widget is None:
            return
        widget.setText(str(value) if value else "")
        widget.setStyleSheet(
            f"color: {self._palette.crit if hot else self._palette.dimmer};"
            " background: transparent;"
        )

    def _on_scanned(self, payload: dict) -> None:
        self.bridge.refresh_status()
        for view in self._views.values():
            view.on_scan_finished()

    # -- actions ------------------------------------------------------------

    def toggle_scanning(self) -> None:
        self.btn_startstop.setEnabled(False)
        if self._scanning:
            self.run_service(adapters_svc.stop_scanning, self._after_toggle)
        else:
            selected = config.get("scan", "interface_guid", default="")
            self.run_service(
                lambda: adapters_svc.start_scanning(selected or None),
                self._after_toggle,
            )

    def _after_toggle(self, result: Any) -> None:
        self.btn_startstop.setEnabled(True)
        self.bridge.refresh_status()

    def single_scan(self) -> None:
        self.btn_single.setEnabled(False)
        self.btn_single.setText("Scanning…")

        def done(result: dict) -> None:
            self.btn_single.setEnabled(True)
            self.btn_single.setText("Single scan")
            self.toast(
                f"Found {result['count']} networks in "
                f"{result['duration_ms'] / 1000:.1f}s on {result.get('adapter')}",
                kind="ok",
            )
            self.bridge.refresh_status()
            for view in self._views.values():
                view.on_scan_finished()

        def failed(exc: Exception) -> None:
            self.btn_single.setEnabled(True)
            self.btn_single.setText("Single scan")
            self.toast(str(exc), title="The scan did not finish", kind="err")

        pool.run(scanner.engine.run_once, done, failed)

    def open_drawer(self, bssid: str) -> None:
        self.drawer.setGeometry(self.centralWidget().rect())
        self.drawer.open_for(bssid, pool, self._service_error)

    def _add_mark(self, kind: str, bssid: str, ssid: str) -> None:
        self.run_service(
            lambda: marks_service.add(kind, "bssid", bssid, ssid or None),
            lambda _: self.toast(
                f"{bssid} marked as {marks_service.KIND_LABELS[kind].lower()}", kind="ok"
            ),
        )

    def _save_note(self, bssid: str, note: str) -> None:
        self.run_service(
            lambda: networks_service.set_note(bssid, note),
            lambda _: self.toast("Note saved", kind="ok"),
        )

    def _add_inventory(self, bssid: str, ssid: str) -> None:
        name = self.ask_text("Add to inventory", "Label for this access point",
                             ssid or bssid)
        if name is None:
            return
        location = self.ask_text("Add to inventory", "Location (optional)", "")
        if location is None:
            return
        self.run_service(
            lambda: survey_svc.set_inventory(
                bssid, {"label": name, "location": location, "managed": True}
            ),
            lambda _: self.toast(f"{name} added to the inventory", kind="ok"),
        )

    # -- helpers ------------------------------------------------------------

    def run_service(self, fn, on_done=None) -> None:
        pool.run(fn, on_done, self._service_error)

    def _service_error(self, exc: Exception) -> None:
        if isinstance(exc, ServiceError):
            self.toast(exc.message, kind="err")
        else:
            log.exception("Unexpected failure", exc_info=exc)
            self.toast(str(exc) or exc.__class__.__name__,
                       title="Something went wrong", kind="err")

    def toast(self, message: str, title: str = "", kind: str = "",
              seconds: float = 4.5) -> None:
        self.toasts.setGeometry(self.centralWidget().rect())
        self.toasts.raise_()
        self.toasts.show_toast(message, title, kind, seconds)

    def confirm(self, question: str, title: str = "wifirecon",
                destructive: bool = False) -> bool:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(question)
        box.setIcon(QMessageBox.Icon.Warning if destructive
                    else QMessageBox.Icon.Question)
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No if destructive
                             else QMessageBox.StandardButton.Yes)
        return box.exec() == QMessageBox.StandardButton.Yes

    def ask_text(self, title: str, prompt: str, default: str = "") -> str | None:
        text, ok = QInputDialog.getText(self, title, prompt, text=default)
        return text if ok else None

    def _about(self) -> None:
        from .. import updater

        QMessageBox.about(
            self, "About wifirecon",
            f"<b>wifirecon {updater.version()}</b><br><br>"
            "Passive wireless survey and diagnostics for Windows.<br>"
            "Reads the information elements Windows exposes through the Native "
            "Wifi API. No association or injection is requested; Windows may send probe requests.",
        )

    def _site_changed(self, index: int) -> None:
        site_id = self.site_picker.itemData(index)
        if site_id is None:
            config.set(None, "site", "active_id")
        else:
            self.run_service(lambda: survey_svc.activate_site(site_id))
        view = self.current_view()
        if view is not None:
            view.load()

    def refresh_sites(self) -> None:
        def done(sites: list[dict]) -> None:
            active = config.get("site", "active_id", default=None)
            self.site_picker.blockSignals(True)
            self.site_picker.clear()
            self.site_picker.addItem("No site selected", None)
            for site in sites:
                self.site_picker.addItem(site["name"], site["id"])
                if site["id"] == active:
                    self.site_picker.setCurrentIndex(self.site_picker.count() - 1)
            self.site_picker.blockSignals(False)

        pool.run(survey_svc.sites, done, lambda exc: None)

    # -- window events ------------------------------------------------------

    def eventFilter(self, watched, event) -> bool:  # noqa: N802
        from PySide6.QtCore import QEvent

        if watched is self.centralWidget() and event.type() == QEvent.Type.Resize:
            self.drawer.setGeometry(self.centralWidget().rect())
            self.toasts.setGeometry(self.centralWidget().rect())
        return super().eventFilter(watched, event)

    # -- window geometry ----------------------------------------------------

    def _restore_geometry(self) -> None:
        """Come back the size and place you were left.

        Stored in the settings file rather than the registry, so it travels
        with the data directory and a portable copy keeps its layout.
        """
        saved = config.get("ui", "window", default=None) or {}
        try:
            width = int(saved.get("width") or 0)
            height = int(saved.get("height") or 0)
        except (TypeError, ValueError):
            width = height = 0
        if width >= MIN_WIDTH and height >= MIN_HEIGHT:
            self.resize(width, height)
            x, y = saved.get("x"), saved.get("y")
            if x is not None and y is not None and self._on_a_screen(int(x), int(y)):
                self.move(int(x), int(y))
        else:
            self.resize(1500, 950)
        if saved.get("maximised"):
            self.showMaximized()

    @staticmethod
    def _on_a_screen(x: int, y: int) -> bool:
        """A window restored onto a monitor that is no longer there is lost."""
        from PySide6.QtGui import QGuiApplication

        point = QPoint(x + 40, y + 40)
        return any(screen.availableGeometry().contains(point)
                   for screen in QGuiApplication.screens())

    def _save_geometry(self) -> None:
        if self.isMaximized():
            config.set({"maximised": True,
                        **(config.get("ui", "window", default={}) or {})},
                       "ui", "window")
            return
        geometry = self.normalGeometry()
        config.set({
            "x": geometry.x(), "y": geometry.y(),
            "width": geometry.width(), "height": geometry.height(),
            "maximised": False,
        }, "ui", "window")

    # -- tray ---------------------------------------------------------------

    def _build_tray(self) -> None:
        """A tray icon, so a survey left running is still visible when minimised."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = None
            return
        self.tray = QSystemTrayIcon(app_icon(self._palette), self)
        menu = QMenu()
        menu.addAction("Show wifirecon", self._restore_from_tray)
        self.tray_toggle = menu.addAction("Start scanning", self.toggle_scanning)
        menu.addSeparator()
        menu.addAction("Quit", self.close)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self._restore_from_tray()
            if reason == QSystemTrayIcon.ActivationReason.Trigger else None
        )
        self.tray.setToolTip("wifirecon — idle")
        self.tray.show()

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # -- status bar ---------------------------------------------------------

    def _build_status_bar(self) -> None:
        bar = self.statusBar()
        bar.setSizeGripEnabled(True)
        self.status_left = QLabel("")
        self.status_left.setFont(mono_font(11))
        bar.addWidget(self.status_left, 1)
        self.status_right = QLabel("survey · no network connection needed")
        self.status_right.setFont(mono_font(11))
        bar.addPermanentWidget(self.status_right)

    def _update_status_bar(self, engine: dict) -> None:
        last = engine.get("last_scan_at")
        parts = []
        if engine.get("scanning"):
            next_in = engine.get("next_scan_in")
            parts.append("scanning" + (f", next in {int(next_in)}s"
                                       if next_in is not None else ""))
        else:
            parts.append("idle — nothing is touching the radio")
        if last:
            parts.append(f"last scan {ago(last)}")
        stats = engine.get("stats") or {}
        if stats.get("scans"):
            parts.append(f"{stats['scans']} scan(s) this session")
        self.status_left.setText("   ·   ".join(parts))

        # The one fact people keep asking about, kept permanently on screen.
        adapter = engine.get("adapter") or {}
        bands = adapter.get("band_label") or "unknown bands"
        self.status_right.setText(
            f"survey · no network connection needed · {bands}"
        )

    def start(self) -> None:
        self.bridge.attach()
        self.refresh_sites()
        self.show_view(config.get("ui", "default_tab", default="live") or "live")
        self._check_marks()

    def _check_marks(self) -> None:
        """The impersonation rules are inert with an empty trusted list.

        Said once, on startup, because it is the single most common reason the
        rule that matters most never fires.
        """
        def done(marks: list[dict]) -> None:
            if any(m.get("kind") == "trusted" for m in marks):
                return
            self.toast(
                "Add your own network names as trusted under Marks. The "
                "impersonation rules compare against that list, and with it "
                "empty they can never fire.",
                title="Nothing is marked trusted yet",
                seconds=12,
            )

        pool.run(marks_service.listing, done, lambda exc: None)

    def closeEvent(self, event) -> None:  # noqa: N802
        """Stop cleanly rather than being killed.

        Closing the window ends the session row and folds the write-ahead log
        back into the database. Exiting any other way leaves both untidy.
        """
        if self._shutting_down:
            event.accept()
            return
        self._shutting_down = True
        self._save_geometry()
        if getattr(self, "tray", None) is not None:
            self.tray.hide()
        self.bridge.detach()
        self.setEnabled(False)
        self.statusBar().showMessage("Stopping…")
        try:
            lifecycle.teardown()
        except Exception:
            log.exception("Problem during shutdown")
        pool.wait(2000)
        event.accept()

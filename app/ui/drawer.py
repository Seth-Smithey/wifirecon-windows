"""The detail sheet that slides in from the right.

Opened from anywhere a BSSID appears: a Live row, a group row, a block on the
ribbon, a finding. It always shows the same thing, so there is one place to
look for the full picture of one radio.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    Qt,
    Signal,
)
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..services import networks as networks_service
from .common import Sparkline, button, clock, label, mono_font, ui_font
from .theme import Palette

SLIDE_MS = 180
FADE_MS = 160
WIDTH_FRACTION = 0.94
MAX_WIDTH = 560


class Drawer(QWidget):
    """A right-hand sheet over the current view."""

    mark_requested = Signal(str, str, str)     # kind, bssid, ssid
    inventory_requested = Signal(str, str)     # bssid, ssid
    note_saved = Signal(str, str)              # bssid, note

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._bssid = ""
        self._ssid = ""
        self._open = False
        self.setVisible(False)

        self._backdrop = QWidget(self)
        self._backdrop.setStyleSheet(f"background: {palette.backdrop};")
        self._backdrop.mousePressEvent = lambda event: self.close_drawer()
        self._backdrop_effect = QGraphicsOpacityEffect(self._backdrop)
        self._backdrop.setGraphicsEffect(self._backdrop_effect)
        self._backdrop_effect.setOpacity(0.0)

        self._sheet = QFrame(self)
        self._sheet.setStyleSheet(
            f"background: {palette.panel}; border-left: 1px solid {palette.line};"
        )
        sheet_layout = QVBoxLayout(self._sheet)
        sheet_layout.setContentsMargins(0, 0, 0, 0)
        sheet_layout.setSpacing(0)

        header = QWidget()
        header.setStyleSheet(f"border-bottom: 1px solid {palette.line};")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 14, 12, 14)
        header_layout.setSpacing(10)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        self._title = QLabel("")
        self._title.setFont(ui_font(16, QFont.Weight.DemiBold))
        self._title.setStyleSheet(f"color: {palette.text_hi}; border: none;")
        self._subtitle = QLabel("")
        self._subtitle.setFont(mono_font(11))
        self._subtitle.setStyleSheet(f"color: {palette.dim}; border: none;")
        titles.addWidget(self._title)
        titles.addWidget(self._subtitle)
        header_layout.addLayout(titles, 1)
        close = button("✕", small=True, on_click=self.close_drawer)
        close.setFixedWidth(30)
        header_layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)
        sheet_layout.addWidget(header)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._body = QWidget()
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(20, 18, 20, 20)
        self._body_layout.setSpacing(14)
        self._scroll.setWidget(self._body)
        sheet_layout.addWidget(self._scroll, 1)

        self._slide = QPropertyAnimation(self._sheet, b"pos", self)
        self._slide.setDuration(SLIDE_MS)
        self._slide.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade = QPropertyAnimation(self._backdrop_effect, b"opacity", self)
        self._fade.setDuration(FADE_MS)

    # -- geometry -----------------------------------------------------------

    def _sheet_width(self) -> int:
        return int(min(MAX_WIDTH, self.width() * WIDTH_FRACTION))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._backdrop.setGeometry(0, 0, self.width(), self.height())
        width = self._sheet_width()
        x = self.width() - width if self._open else self.width()
        self._sheet.setGeometry(x, 0, width, self.height())

    # -- open and close -----------------------------------------------------

    def open_for(self, bssid: str, pool, on_error: Callable[[Exception], None]) -> None:
        self._bssid = bssid
        self._ssid = ""
        self._title.setText(bssid)
        self._subtitle.setText("Loading…")
        self._clear_body()
        self._show()
        pool.run(
            lambda: (networks_service.detail(bssid),
                     networks_service.history(bssid, 300)),
            self._render,
            on_error,
        )

    def _show(self) -> None:
        if self._open:
            return
        self._open = True
        self.setVisible(True)
        self.raise_()
        width = self._sheet_width()
        self._sheet.setGeometry(self.width(), 0, width, self.height())
        self._slide.stop()
        self._slide.setStartValue(QPoint(self.width(), 0))
        self._slide.setEndValue(QPoint(self.width() - width, 0))
        self._slide.start()
        self._fade.stop()
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()

    def close_drawer(self) -> None:
        if not self._open:
            return
        self._open = False
        width = self._sheet_width()
        self._slide.stop()
        self._slide.setStartValue(QPoint(self.width() - width, 0))
        self._slide.setEndValue(QPoint(self.width(), 0))
        self._slide.start()
        self._fade.stop()
        self._fade.setStartValue(self._backdrop_effect.opacity())
        self._fade.setEndValue(0.0)
        try:
            self._fade.finished.disconnect()
        except RuntimeError:
            pass
        self._fade.finished.connect(lambda: self.setVisible(self._open))
        self._fade.start()

    @property
    def is_open(self) -> bool:
        return self._open

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        self._backdrop.setStyleSheet(f"background: {palette.backdrop};")
        self._sheet.setStyleSheet(
            f"background: {palette.panel}; border-left: 1px solid {palette.line};"
        )
        self._title.setStyleSheet(f"color: {palette.text_hi}; border: none;")
        self._subtitle.setStyleSheet(f"color: {palette.dim}; border: none;")

    # -- body ---------------------------------------------------------------

    def _clear_body(self) -> None:
        while self._body_layout.count():
            item = self._body_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _render(self, payload: tuple) -> None:
        detail, history = payload
        palette = self._palette
        self._ssid = detail.get("ssid") or ""

        name = "(hidden)" if detail.get("hidden") else (self._ssid or "(no name)")
        self._title.setText(name)
        self._subtitle.setText(
            f"{detail['bssid']} · {detail.get('vendor') or 'unknown vendor'}"
        )

        self._clear_body()
        self._body_layout.addWidget(label("Signal over time", role="eyebrow", mono=True,
                                          size=10))
        spark = Sparkline(palette)
        spark.set_history(history.get("history", []))
        self._body_layout.addWidget(spark)

        self._body_layout.addWidget(label("Details", role="eyebrow", mono=True, size=10))
        self._body_layout.addWidget(self._details_grid(detail))

        self._body_layout.addWidget(label("Notes", role="eyebrow", mono=True, size=10))
        self._note = QPlainTextEdit(detail.get("notes") or "")
        self._note.setFixedHeight(72)
        self._body_layout.addWidget(self._note)

        actions = QWidget()
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(6)
        actions_layout.addWidget(button("Save note", small=True, on_click=self._save_note))
        actions_layout.addWidget(button(
            "Mark trusted", small=True,
            on_click=lambda: self.mark_requested.emit("trusted", self._bssid, self._ssid)))
        actions_layout.addWidget(button(
            "Watch this", small=True,
            on_click=lambda: self.mark_requested.emit("watch", self._bssid, self._ssid)))
        actions_layout.addWidget(button(
            "Ignore", small=True,
            on_click=lambda: self.mark_requested.emit("ignore", self._bssid, self._ssid)))
        actions_layout.addStretch(1)
        self._body_layout.addWidget(actions)

        self._body_layout.addWidget(button(
            "Add to inventory", small=True,
            on_click=lambda: self.inventory_requested.emit(self._bssid, self._ssid)))
        self._body_layout.addStretch(1)

    def _save_note(self) -> None:
        self.note_saved.emit(self._bssid, self._note.toPlainText())

    def _details_grid(self, d: dict) -> QWidget:
        palette = self._palette
        holder = QWidget()
        grid = QGridLayout(holder)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        grid.setColumnMinimumWidth(0, 130)
        grid.setColumnStretch(1, 1)

        for position, (key, value) in enumerate(_detail_rows(d)):
            term = QLabel(key)
            term.setFont(ui_font(12))
            term.setStyleSheet(f"color: {palette.dim};")
            term.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            definition = QLabel(value)
            definition.setFont(mono_font(12))
            definition.setStyleSheet(f"color: {palette.text};")
            definition.setWordWrap(True)
            definition.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            grid.addWidget(term, position, 0)
            grid.addWidget(definition, position, 1)
        return holder


def _detail_rows(d: dict) -> list[tuple[str, str]]:
    """Everything known about one radio, in the order it is worth reading."""
    dash = "—"

    def text(value: Any) -> str:
        if value is None or value == "":
            return dash
        return str(value)

    ie = (d.get("detail") or {}).get("ie") or {}
    wps = ie.get("wps") or {}

    security = d.get("security") or dash
    if d.get("enterprise"):
        security += " (802.1X)"

    if d.get("mfp_required"):
        protection = "required"
    elif d.get("mfp_capable"):
        protection = "optional"
    else:
        protection = "not offered"

    band = d.get("band")
    channel = d.get("channel")
    width = d.get("width_mhz")
    band_text = (f"{band} GHz, channel {channel}, {width} MHz"
                 if band and channel else dash)

    freq = d.get("freq_khz")
    frequency = f"{freq / 1000:.1f} MHz" if freq else dash

    rssi = d.get("rssi")
    signal = (f"{rssi} dBm (best {d.get('rssi_max')}, worst {d.get('rssi_min')})"
              if rssi is not None else dash)

    roaming = [name for name, flag in (
        ("802.11r", ie.get("ft")), ("802.11k", ie.get("rrm")), ("802.11v", ie.get("wnm"))
    ) if flag]

    load = dash
    if d.get("utilization_pct") is not None:
        load = f"{round(float(d['utilization_pct']))}% busy"
        if d.get("station_count") is not None:
            load += f", {d['station_count']} clients"

    hardware = " · ".join(
        part for part in (wps.get("manufacturer"), wps.get("model_name"),
                          wps.get("device_name")) if part
    )

    wps_text = dash
    if d.get("wps"):
        wps_text = text(d.get("wps_state") or "on")
        methods = wps.get("config_methods")
        if methods:
            wps_text += f" ({methods if isinstance(methods, str) else ', '.join(methods)})"
    elif d.get("wps") is False:
        wps_text = "off"

    return [
        ("Security", security),
        ("Key agreement", ", ".join(d.get("akms") or []) or dash),
        ("Ciphers", ", ".join(d.get("ciphers") or []) or dash),
        ("Frame protection", protection),
        ("Band / channel", band_text),
        ("Frequency", frequency),
        ("Generation", text(d.get("phy"))),
        ("Signal", signal),
        ("Beacon interval", f"{d['beacon_period']} TU" if d.get("beacon_period") else dash),
        ("Regulatory", text(d.get("country"))),
        ("Load", load),
        ("Roaming", ", ".join(roaming) if roaming else "none"),
        ("WPS", wps_text),
        ("Hardware", hardware or dash),
        ("MAC type", "locally administered" if d.get("randomized_mac")
         else "vendor assigned"),
        ("Beacon fingerprint", text(d.get("ie_fingerprint"))),
        ("First seen", clock(d.get("first_seen"))),
        ("Times seen", text(d.get("times_seen"))),
    ]

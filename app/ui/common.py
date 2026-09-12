"""Small widgets shared across the views."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QRectF,
    Qt,
    QTimer,
)
from PySide6.QtGui import QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .theme import Palette

# -- text ------------------------------------------------------------------


def mono_font(size: int = 12, weight: int = QFont.Weight.Normal) -> QFont:
    font = QFont()
    font.setFamilies(theme.MONO_FAMILIES)
    font.setPixelSize(size)
    font.setWeight(weight)
    return font


def ui_font(size: int = 14, weight: int = QFont.Weight.Normal) -> QFont:
    font = QFont()
    font.setFamilies(theme.UI_FAMILIES)
    font.setPixelSize(size)
    font.setWeight(weight)
    return font


def dbm(value: Any) -> str:
    return f"{int(value)} dBm" if value is not None else "—"


def human_bytes(count: Any) -> str:
    try:
        size = float(count or 0)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def ago(ts: Any) -> str:
    """How long ago, in the shortest form that is still honest."""
    if not ts:
        return "—"
    seconds = time.time() - float(ts)
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def clock(ts: Any) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))


def short_clock(ts: Any) -> str:
    if not ts:
        return "—"
    return time.strftime("%H:%M:%S", time.localtime(float(ts)))


def elide(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: max(1, limit - 1)] + "…"


# -- building blocks -------------------------------------------------------


def label(text: str = "", *, role: str = "", size: int | None = None,
          bold: bool = False, mono: bool = False, wrap: bool = False,
          colour: str = "") -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setProperty(role, True)
    if mono:
        widget.setProperty("mono", True)
        widget.setFont(mono_font(size or 12))
    elif size or bold:
        widget.setFont(ui_font(size or 14,
                               QFont.Weight.DemiBold if bold else QFont.Weight.Normal))
    if wrap:
        widget.setWordWrap(True)
    if colour:
        widget.setStyleSheet(f"color: {colour};")
    if role == "eyebrow":
        widget.setText(text.upper())
    return widget


def button(text: str, *, kind: str = "", small: bool = False,
           on_click: Callable[[], None] | None = None,
           tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    if kind:
        btn.setProperty("kind", kind)
    if small:
        btn.setProperty("small", True)
    if tooltip:
        btn.setToolTip(tooltip)
    if on_click is not None:
        btn.clicked.connect(lambda: on_click())
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


def row(*widgets: QWidget, spacing: int = 8, stretch_at: int | None = None) -> QWidget:
    holder = QWidget()
    layout = QHBoxLayout(holder)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(spacing)
    for index, widget in enumerate(widgets):
        if widget is None:
            layout.addStretch(1)
            continue
        layout.addWidget(widget)
        if stretch_at is not None and index == stretch_at:
            layout.addStretch(1)
    return holder


def hline(palette: Palette) -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {palette.line_soft}; border: none;")
    return line


class Card(QFrame):
    """A titled panel. Everything in the views sits in one of these."""

    def __init__(self, title: str = "", hint: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", True)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 14, 16, 16)
        self._layout.setSpacing(10)
        self.header = QHBoxLayout()
        self.header.setSpacing(10)
        if title:
            self.title_label = label(title, role="cardTitle", size=14, bold=True)
            self.header.addWidget(self.title_label)
        else:
            self.title_label = None
        self.header.addStretch(1)
        self._layout.addLayout(self.header)
        if hint:
            self._layout.addWidget(label(hint, role="hint", size=12, wrap=True))

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self._layout.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self._layout.addLayout(layout)

    def add_action(self, widget: QWidget) -> QWidget:
        self.header.addWidget(widget)
        return widget

    def body(self) -> QVBoxLayout:
        return self._layout


class Chip(QLabel):
    """A small coloured pill: a band, a security posture, a severity."""

    def __init__(self, text: str, colour: str, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        background, border = theme.tint(palette, colour)
        self.setFont(mono_font(10))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"color: {colour}; background: {background};"
            f" border: 1px solid {border}; border-radius: 3px; padding: 1px 6px;"
        )
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)


class StatusDot(QWidget):
    """The scanning indicator: green and glowing while live, red on a fault."""

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._state = "idle"
        self.setFixedSize(16, 16)

    def set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self.update()

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        colour = {
            "live": self._palette.ok,
            "warn": self._palette.med,
            "down": self._palette.crit,
        }.get(self._state, self._palette.dimmer)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        centre = QRectF(self.rect()).center()
        if self._state in ("live", "warn", "down"):
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(theme.qcolor(colour, 0.16))
            painter.drawEllipse(centre, 7.5, 7.5)
        painter.setBrush(theme.qcolor(colour))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(centre, 3.5, 3.5)
        painter.end()


class PhaseStrip(QWidget):
    """What the engine is doing right now.

    Indeterminate while a scan is in flight, and a real countdown while it
    waits, so it is never ambiguous whether something is happening.
    """

    PHASE_TEXT = {
        "idle": "idle",
        "starting": "starting",
        "selecting": "choosing adapter",
        "requesting": "scanning",
        "settling": "listening",
        "reading": "reading",
        "analysing": "analysing",
        "waiting": "waiting",
        "error": "error",
    }
    BUSY = ("starting", "selecting", "requesting", "settling", "reading", "analysing")

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._phase = "idle"
        self._fraction = 0.0
        self._sweep = 0.0
        self._busy = False
        self.setMinimumWidth(190)
        self.setFixedHeight(30)

        self._text = label("idle", role="phaseText")
        self._text.setObjectName("phaseText")
        self._text.setFont(mono_font(10))
        self._text.setMinimumWidth(96)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(9)
        layout.addWidget(self._text)
        self._bar = _PhaseBar(palette, self)
        layout.addWidget(self._bar, 1)

        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._tick)

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        self._bar.set_palette_colours(palette)

    def set_status(self, engine: dict) -> None:
        phase = engine.get("phase") or "idle"
        detail = self.PHASE_TEXT.get(phase, phase)
        if engine.get("last_error") and phase == "error":
            detail = "scan failed"
        busy = phase in self.BUSY
        next_in = engine.get("next_scan_in")
        interval = float(engine.get("interval_seconds") or 20) or 20

        if phase == "waiting" and next_in is not None:
            detail = f"next in {int(next_in)}s"
            self._bar.set_determinate(max(0.0, min(1.0, 1 - float(next_in) / interval)))
            self._stop_sweep()
        elif busy:
            self._start_sweep()
        else:
            self._bar.set_determinate(0.0)
            self._stop_sweep()

        self._phase = phase
        self._text.setText(detail)

    def set_message(self, text: str) -> None:
        self._text.setText(text)

    def _start_sweep(self) -> None:
        if not self._busy:
            self._busy = True
            self._timer.start()

    def _stop_sweep(self) -> None:
        if self._busy:
            self._busy = False
            self._timer.stop()

    def _tick(self) -> None:
        self._sweep = (self._sweep + 0.022) % 1.0
        self._bar.set_sweep(self._sweep)


class _PhaseBar(QWidget):
    SWEEP_WIDTH = 0.34

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._fraction = 0.0
        self._sweep: float | None = None
        self.setFixedHeight(3)
        self.setMinimumWidth(80)

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        self.update()

    def set_determinate(self, fraction: float) -> None:
        self._sweep = None
        self._fraction = fraction
        self.update()

    def set_sweep(self, position: float) -> None:
        self._sweep = position
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = self.width()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(theme.qcolor(self._palette.line))
        painter.drawRoundedRect(QRectF(0, 0, width, 3), 1.5, 1.5)
        painter.setBrush(theme.qcolor(self._palette.b5))
        if self._sweep is not None:
            span = width * self.SWEEP_WIDTH
            # Travels from fully off the left to fully off the right.
            x = -span + self._sweep * (width + span * 2)
            painter.drawRoundedRect(QRectF(x, 0, span, 3), 1.5, 1.5)
        elif self._fraction > 0:
            painter.drawRoundedRect(QRectF(0, 0, width * self._fraction, 3), 1.5, 1.5)
        painter.end()


class Readout(QWidget):
    """A number with a caption under it, for the topbar."""

    def __init__(self, caption: str, alarm: bool = False,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.value = QLabel("0")
        self.value.setProperty("readoutValue", True)
        if alarm:
            self.value.setProperty("alarm", True)
        self.value.setFont(mono_font(17, QFont.Weight.DemiBold))
        self.value.setAlignment(Qt.AlignmentFlag.AlignRight)
        caption_label = QLabel(caption.upper())
        caption_label.setProperty("readoutCaption", True)
        caption_label.setFont(ui_font(9))
        caption_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self.value)
        layout.addWidget(caption_label)

    def set_value(self, value: Any) -> None:
        self.value.setText(str(value))


class Sparkline(QWidget):
    """Signal over time for one radio.

    The scale is pinned to -95 and -30 rather than fitted to the data, so two
    sparklines can be compared and a flat strong line does not look identical
    to a flat weak one.
    """

    FLOOR = -95
    CEILING = -30

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._values: list[float] = []
        self.setFixedHeight(74)

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        self.update()

    def set_history(self, history: list[dict]) -> None:
        # History arrives newest first; a chart reads left to right in time.
        values = [h["rssi"] for h in reversed(history) if h.get("rssi") is not None]
        self._values = [float(v) for v in values]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        painter.setPen(QPen(theme.qcolor(self._palette.line), 1))
        painter.setBrush(theme.qcolor(self._palette.panel2))
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)

        if len(self._values) < 2:
            painter.setPen(theme.qcolor(self._palette.dimmer))
            painter.setFont(mono_font(11))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter,
                             "Not enough history yet.")
            painter.end()
            return

        pad = 8.0
        low = min(self.FLOOR, min(self._values))
        high = max(self.CEILING, max(self._values))
        span = max(1.0, high - low)
        width = rect.width() - pad * 2
        height = rect.height() - pad * 2

        path = QPainterPath()
        count = len(self._values)
        for index, value in enumerate(self._values):
            x = pad + (index / (count - 1)) * width
            y = pad + (1 - (value - low) / span) * height
            if index == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        painter.setPen(QPen(theme.qcolor(self._palette.b5), 1.4))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        painter.setFont(mono_font(9))
        painter.setPen(theme.qcolor(self._palette.dimmer))
        painter.drawText(QPoint(5, 12), f"{int(high)} dBm")
        painter.drawText(QPoint(5, int(rect.height()) - 5), f"{int(low)} dBm")
        painter.end()


def _alive(widget: QWidget) -> bool:
    """Whether Qt has already destroyed the object behind this wrapper."""
    try:
        import shiboken6

        return bool(shiboken6.isValid(widget))
    except ImportError:
        try:
            widget.objectName()
            return True
        except RuntimeError:
            return False


class Toast(QFrame):
    """A short message that fades in at the bottom right and leaves on its own."""

    def __init__(self, message: str, title: str = "", kind: str = "",
                 palette: Palette = theme.DARK, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        accent = {
            "err": palette.crit,
            "ok": palette.ok,
        }.get(kind, palette.b5)
        self.setStyleSheet(
            f"background: {palette.raised}; border: 1px solid {palette.line};"
            f" border-left: 3px solid {accent}; border-radius: 6px;"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)
        if title:
            heading = QLabel(title)
            heading.setFont(ui_font(13, QFont.Weight.DemiBold))
            heading.setStyleSheet(f"color: {palette.text_hi}; border: none;")
            layout.addWidget(heading)
        body = QLabel(message)
        body.setWordWrap(True)
        body.setFont(ui_font(13))
        body.setStyleSheet(f"color: {palette.text}; border: none;")
        layout.addWidget(body)
        self.setMaximumWidth(380)


class ToastArea(QWidget):
    """Stacks toasts bottom right over whatever view is showing."""

    MAX_VISIBLE = 4

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 18, 18)
        self._layout.setSpacing(8)
        self._layout.addStretch(1)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
        self._animations: list[Any] = []
        self._live: list[QWidget] = []

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette

    def show_toast(self, message: str, title: str = "", kind: str = "",
                   seconds: float = 4.5) -> None:
        toast = Toast(message, title, kind, self._palette, self)
        effect = QGraphicsOpacityEffect(toast)
        toast.setGraphicsEffect(effect)
        effect.setOpacity(0.0)
        self._layout.addWidget(toast, 0,
                               Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
        toast.show()

        fade_in = QPropertyAnimation(effect, b"opacity", self)
        fade_in.setDuration(180)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        fade_in.start()
        self._animations.append(fade_in)

        # Retiring only fades; it does not remove the widget from the layout.
        # Counting layout items to decide what to drop therefore never
        # converges, so the live list is tracked directly instead.
        self._live.append(toast)
        while len(self._live) > self.MAX_VISIBLE:
            self._retire(self._live.pop(0))

        QTimer.singleShot(int(seconds * 1000), lambda: self._retire(toast))

    def _retire(self, toast: QWidget) -> None:
        # The dismissal timer still fires for a toast already retired by a
        # burst, and by then Qt has deleted the C++ object underneath it. Every
        # attribute access on that wrapper raises, so the check comes first.
        if toast is None or not _alive(toast):
            return
        if toast in self._live:
            self._live.remove(toast)
        if toast.parent() is None:
            return
        effect = toast.graphicsEffect()
        if effect is None:
            toast.deleteLater()
            return
        fade_out = QPropertyAnimation(effect, b"opacity", self)
        fade_out.setDuration(220)
        fade_out.setStartValue(effect.opacity())
        fade_out.setEndValue(0.0)
        fade_out.finished.connect(toast.deleteLater)
        fade_out.start()
        self._animations.append(fade_out)

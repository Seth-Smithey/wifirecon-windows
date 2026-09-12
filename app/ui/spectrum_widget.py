"""The frequency occupancy ribbon, drawn natively.

Every access point is a block at its real centre frequency spanning its real
channel width, so two blocks that overlap on screen are two radios that
overlap in the air. Nothing here rounds to a channel number, because doing so
would hide exactly the overlap the view exists to show.

The geometry is kept in a fixed 1000-unit virtual space and scaled to the
widget, which is what the browser version did with a viewBox. Keeping that
means the label packing, the tick spacing and the block proportions stay the
ones that were tuned against real scans.
"""

from __future__ import annotations

import math
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget

from ..services import spectrum as spectrum_service
from . import theme
from .common import label, mono_font
from .theme import Palette

# Virtual drawing space. Everything below is in these units.
W = 1000.0
PAD_L = 44.0
PAD_R = 14.0
PAD_T = 16.0
PAD_B = 26.0
PLOT_W = W - PAD_L - PAD_R          # 942

ROW_H = 19.0
BLOCK_H = ROW_H - 5                  # 14

# The advance width of the monospace face at 10 units. Measured rather than
# queried so packing stays identical whichever font actually resolves.
CHAR_W = 6.1
LABEL_PAD = 8.0

# One very long name must not be able to push every later block onto its own
# row, so the space a label reserves is capped even though the label itself
# may be drawn longer.
MAX_LABEL_RESERVE = 190.0

# Below this a label will not fit inside its own block and goes to the right.
INSIDE_MIN_WIDTH = 30.0

MIN_BLOCK_W = 3.0

# Signal maps to opacity and to a filled meter rather than to height, so every
# row is the same height and a weak network is still readable.
RSSI_FLOOR = -95.0
RSSI_SPAN = 65.0
STRENGTH_MIN = 0.08

TICK_STEPS = {"2.4": 20, "5": 100, "6": 200}

BAND_LABELS = {"2.4": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}

HOVER_BRIGHTNESS = 1.45


def strength_of(rssi: Any) -> float:
    """Where this signal sits between unusable and excellent, 0.08 to 1."""
    if rssi is None:
        return STRENGTH_MIN
    value = (float(rssi) - RSSI_FLOOR) / RSSI_SPAN
    return max(STRENGTH_MIN, min(1.0, value))


def pack_rows(items: list[dict], to_x) -> list[int]:
    """First-fit row assignment so no two blocks or their labels collide.

    Items must already be sorted by low frequency. The extent a block claims
    is the greater of its own right edge and the room its label needs.
    """
    row_ends: list[float] = []
    rows: list[int] = []
    for item in items:
        left = to_x(item["low_mhz"])
        right = to_x(item["high_mhz"])
        text = "(hidden)" if item.get("hidden") else (item.get("ssid") or item["bssid"])
        reserve = min(len(str(text)) * CHAR_W, MAX_LABEL_RESERVE)
        needed = max(right, left + reserve + LABEL_PAD)
        placed = False
        for index, end in enumerate(row_ends):
            if left > end:
                row_ends[index] = needed
                rows.append(index)
                placed = True
                break
        if not placed:
            row_ends.append(needed)
            rows.append(len(row_ends) - 1)
    return rows


class RibbonWidget(QWidget):
    """One band's ribbon."""

    bssid_clicked = Signal(str)

    def __init__(self, band: str, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._band = band
        self._palette = palette
        self._items: list[dict] = []
        self._rows: list[int] = []
        self._row_count = 1
        self._flagged: set[str] = set()
        self._hover_index = -1
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    # -- data ---------------------------------------------------------------

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        self.update()

    def set_items(self, items: list[dict], flagged: set[str] | None = None) -> None:
        self._items = sorted(items, key=lambda i: i["low_mhz"])
        self._flagged = flagged or set()
        self._rows = pack_rows(self._items, self._to_x)
        self._row_count = max(max(self._rows) + 1 if self._rows else 0, 1)
        self._hover_index = -1
        # The ribbon grows a row at a time as blocks stop fitting beside each
        # other, so its height is data-dependent and has to be resolved here
        # rather than once at construction.
        self._sync_height()
        self.updateGeometry()
        self.update()

    # -- geometry -----------------------------------------------------------

    @property
    def _range(self) -> tuple[float, float]:
        low, high = spectrum_service.BAND_RANGES[self._band]
        return float(low), float(high)

    def _to_x(self, mhz: float) -> float:
        low, high = self._range
        return PAD_L + ((float(mhz) - low) / (high - low)) * PLOT_W

    @property
    def _virtual_height(self) -> float:
        return self._row_count * ROW_H + PAD_T + PAD_B

    @property
    def _scale(self) -> float:
        return max(0.1, self.width() / W)

    def sizeHint(self):  # noqa: N802
        from PySide6.QtCore import QSize

        return QSize(int(W), int(self._virtual_height * self._scale))

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        return int(self._virtual_height * (width / W))

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def _sync_height(self) -> None:
        wanted = int(round(self._virtual_height * self._scale))
        if wanted != self.height():
            self.setFixedHeight(wanted)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._sync_height()

    # -- interaction --------------------------------------------------------

    def _block_rect(self, index: int) -> QRectF:
        item = self._items[index]
        left = self._to_x(item["low_mhz"])
        width = max(MIN_BLOCK_W, self._to_x(item["high_mhz"]) - left)
        top = PAD_T + self._rows[index] * ROW_H
        return QRectF(left, top, width, BLOCK_H)

    def _index_at(self, pos) -> int:
        scale = self._scale
        x = pos.x() / scale
        y = pos.y() / scale
        for index in range(len(self._items)):
            if self._block_rect(index).contains(QPointF(x, y)):
                return index
        return -1

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        index = self._index_at(event.position())
        if index != self._hover_index:
            self._hover_index = index
            self.setCursor(
                Qt.CursorShape.PointingHandCursor if index >= 0
                else Qt.CursorShape.ArrowCursor
            )
            self.setToolTip(self._tooltip(index) if index >= 0 else "")
            self.update()

    def leaveEvent(self, event) -> None:  # noqa: N802
        if self._hover_index != -1:
            self._hover_index = -1
            self.update()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        index = self._index_at(event.position())
        if index >= 0:
            self.bssid_clicked.emit(self._items[index]["bssid"])

    def _tooltip(self, index: int) -> str:
        item = self._items[index]
        name = "(hidden)" if item.get("hidden") else (item.get("ssid") or item["bssid"])
        facts = (
            f"ch {item.get('channel')} · {item.get('width_mhz')} MHz · "
            f"{item.get('rssi')} dBm · {item.get('security')}"
        )
        if item.get("vendor"):
            facts += f" · {item['vendor']}"
        return f"{name}\n{item['bssid']}\n{facts}"

    # -- painting -----------------------------------------------------------

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        scale = self._scale
        painter.scale(scale, scale)

        palette = self._palette
        plot_h = self._row_count * ROW_H
        height = self._virtual_height

        painter.setPen(QPen(theme.qcolor(palette.line), 1 / scale))
        painter.setBrush(theme.qcolor(palette.panel2))
        painter.drawRoundedRect(QRectF(0.5, 0.5, W - 1, height - 1), 6, 6)

        self._paint_ticks(painter, plot_h, height, scale)
        self._paint_blocks(painter, scale)
        painter.end()

    def _paint_ticks(self, painter: QPainter, plot_h: float, height: float,
                     scale: float) -> None:
        low, high = self._range
        step = TICK_STEPS.get(self._band, 100)
        palette = self._palette

        painter.setFont(self._scaled_font(9))
        start = math.ceil(low / step) * step
        tick = start
        while tick <= high:
            x = self._to_x(tick)
            painter.setPen(QPen(theme.qcolor(palette.line_soft), 1 / scale))
            painter.drawLine(QPointF(x, PAD_T), QPointF(x, PAD_T + plot_h))
            painter.setPen(theme.qcolor(palette.dimmer))
            text = str(int(tick))
            width = painter.fontMetrics().horizontalAdvance(text)
            painter.drawText(QPointF(x - width / 2, height - 8), text)
            tick += step

        painter.setPen(QPen(theme.qcolor(palette.line), 1 / scale))
        painter.drawLine(QPointF(PAD_L, PAD_T + plot_h),
                         QPointF(W - PAD_R, PAD_T + plot_h))

    def _paint_blocks(self, painter: QPainter, scale: float) -> None:
        palette = self._palette
        colour = theme.band_colour(palette, self._band)
        painter.setFont(self._scaled_font(10))
        metrics = painter.fontMetrics()

        for index, item in enumerate(self._items):
            rect = self._block_rect(index)
            strength = strength_of(item.get("rssi"))
            flagged = item["bssid"] in self._flagged
            hovered = index == self._hover_index

            fill = QColor(colour)
            fill.setAlphaF(0.10 + strength * 0.30)
            stroke_colour = palette.crit if flagged else colour
            stroke = QColor(stroke_colour)
            stroke.setAlphaF(1.0 if flagged else 0.35 + strength * 0.5)
            if hovered:
                fill = _brighten(fill, HOVER_BRIGHTNESS)
                stroke = _brighten(stroke, HOVER_BRIGHTNESS)

            painter.setBrush(fill)
            painter.setPen(QPen(stroke, (1.5 if flagged else 1.0) / scale))
            painter.drawRoundedRect(rect, 2, 2)

            # The meter along the bottom edge is how strong reads at a glance.
            meter = QColor(colour)
            meter.setAlphaF(0.9)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(meter)
            painter.drawRoundedRect(
                QRectF(rect.left(), rect.bottom() - 3, rect.width() * strength, 2), 1, 1
            )

            self._paint_label(painter, metrics, item, rect)

    def _paint_label(self, painter: QPainter, metrics, item: dict,
                     rect: QRectF) -> None:
        palette = self._palette
        text = "(hidden)" if item.get("hidden") else (item.get("ssid") or item["bssid"])
        text = str(text)
        inside = rect.width() > INSIDE_MIN_WIDTH
        room = rect.width() - 8 if inside else (W - PAD_R) - (rect.right() + 6)
        max_chars = max(3, int(room / CHAR_W))
        shown = text if len(text) <= max_chars else text[: max(1, max_chars - 1)] + "…"

        width = metrics.horizontalAdvance(shown)
        x = rect.left() + 4 if inside else rect.right() + 5
        # A label must never hang off either edge of the plot.
        x = max(PAD_L + 2, min(x, W - PAD_R - width - 2))

        painter.setPen(theme.qcolor(palette.text_hi if inside else palette.dim))
        painter.drawText(QPointF(x, rect.bottom() - 4), shown)

    def _scaled_font(self, pixels: int) -> QFont:
        font = mono_font(pixels)
        # Painter scaling handles the size, so the font is set in virtual units.
        font.setPixelSize(pixels)
        return font


def _brighten(colour: QColor, factor: float) -> QColor:
    out = QColor(colour)
    out.setRed(min(255, int(colour.red() * factor)))
    out.setGreen(min(255, int(colour.green() * factor)))
    out.setBlue(min(255, int(colour.blue() * factor)))
    out.setAlphaF(colour.alphaF())
    return out


class SpectrumWidget(QWidget):
    """All three bands, stacked, with a header on each."""

    bssid_clicked = Signal(str)

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._ribbons: dict[str, RibbonWidget] = {}
        self._headings: dict[str, Any] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(22)

        for band in spectrum_service.BAND_ORDER:
            block = QWidget()
            block_layout = QVBoxLayout(block)
            block_layout.setContentsMargins(0, 0, 0, 0)
            block_layout.setSpacing(8)

            heading = QWidget()
            heading_layout = QVBoxLayout(heading)
            heading_layout.setContentsMargins(0, 0, 0, 0)
            heading_layout.setSpacing(2)
            title = label(BAND_LABELS[band], mono=True, size=11)
            title.setStyleSheet(
                f"color: {theme.band_colour(palette, band)}; letter-spacing: 1px;"
            )
            title.setText(BAND_LABELS[band].upper())
            meta = label("", role="dimmer", size=12)
            meta.setStyleSheet(f"color: {palette.dimmer};")
            heading_layout.addWidget(title)
            heading_layout.addWidget(meta)
            block_layout.addWidget(heading)

            ribbon = RibbonWidget(band, palette)
            ribbon.bssid_clicked.connect(self.bssid_clicked)
            block_layout.addWidget(ribbon)

            layout.addWidget(block)
            self._ribbons[band] = ribbon
            self._headings[band] = {"title": title, "meta": meta, "ribbon": ribbon}

        layout.addStretch(1)

    def set_palette_colours(self, palette: Palette) -> None:
        self._palette = palette
        for band, parts in self._headings.items():
            parts["title"].setStyleSheet(
                f"color: {theme.band_colour(palette, band)}; letter-spacing: 1px;"
            )
            parts["meta"].setStyleSheet(f"color: {palette.dimmer};")
            parts["ribbon"].set_palette_colours(palette)

    def set_data(self, payload: dict, flagged: set[str] | None = None) -> None:
        bands = payload.get("bands", {})
        for band in spectrum_service.BAND_ORDER:
            items = bands.get(band, [])
            parts = self._headings[band]
            low, high = spectrum_service.BAND_RANGES[band]
            if items:
                noun = "access point" if len(items) == 1 else "access points"
                text = f"{len(items)} {noun} · {low}–{high} MHz"
                if band == "6":
                    psc = spectrum_service.psc_count(items)
                    if psc:
                        text += f" · {psc} on a scanning channel"
                parts["ribbon"].show()
            else:
                parts["ribbon"].hide()
                text = (
                    "nothing detected — 6 GHz access points are still uncommon, and "
                    "they are only discoverable on the preferred scanning channels"
                    if band == "6" else "nothing detected"
                )
            parts["meta"].setText(text)
            parts["meta"].setWordWrap(True)
            parts["ribbon"].set_items(items, flagged)

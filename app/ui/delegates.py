"""Custom-painted table cells.

A signal is easier to read as a bar than as a number, and a security posture
is easier to scan as coloured badges than as a sentence. Both are painted
rather than composed from widgets, because a table with several hundred rows
cannot afford a widget per cell.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QStyle, QStyledItemDelegate

from . import theme
from .common import mono_font, ui_font
from .models import FLAG_ROLE, ROW_ROLE, STALE_ROLE
from .theme import Palette

# A signal bar is drawn between these, so the widest bar is a very strong
# network and an empty one is at or below the noise floor.
BAR_FLOOR = -95.0
BAR_CEILING = -30.0
BAR_MAX_W = 46
BAR_H = 6

CHIP_H = 15
CHIP_PAD = 5
CHIP_GAP = 4

STALE_OPACITY = 0.45

# Rows older than this are dimmed: still listed, visibly not current.
STALE_SECONDS = 300


class BaseDelegate(QStyledItemDelegate):
    def __init__(self, palette: Palette, parent=None) -> None:
        super().__init__(parent)
        self.palette_colours = palette

    def set_palette_colours(self, palette: Palette) -> None:
        self.palette_colours = palette

    def _prepare(self, painter: QPainter, option, index) -> float:
        """Common row chrome: selection, hover, flag stripe, stale dimming."""
        painter.save()
        palette = self.palette_colours
        rect = option.rect

        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(rect, theme.qcolor(palette.raised))
        elif option.state & QStyle.StateFlag.State_MouseOver:
            painter.fillRect(rect, theme.qcolor(palette.raised, 0.6))

        if index.column() == 0:
            flag = index.data(FLAG_ROLE)
            if flag:
                colour = palette.crit if flag == "flagged" else palette.b5
                painter.fillRect(rect.x(), rect.y(), 2, rect.height(),
                                 theme.qcolor(colour))

        painter.setPen(QPen(theme.qcolor(palette.line_soft), 1))
        painter.drawLine(rect.bottomLeft(), rect.bottomRight())

        return STALE_OPACITY if index.data(STALE_ROLE) else 1.0


class TextDelegate(BaseDelegate):
    """Plain text with the theme's colours, tabular numerals when mono."""

    def __init__(self, palette: Palette, mono: bool = False, dim: bool = False,
                 parent=None) -> None:
        super().__init__(palette, parent)
        self._mono = mono
        self._dim = dim

    def paint(self, painter, option, index) -> None:
        opacity = self._prepare(painter, option, index)
        painter.setOpacity(opacity)
        palette = self.palette_colours
        painter.setFont(mono_font(12) if self._mono else ui_font(13))
        painter.setPen(theme.qcolor(palette.dim if self._dim else palette.text))
        align = index.data(Qt.ItemDataRole.TextAlignmentRole) or int(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        rect = option.rect.adjusted(8, 0, -8, 0)
        text = index.data(Qt.ItemDataRole.DisplayRole) or ""
        metrics = QFontMetrics(painter.font())
        elided = metrics.elidedText(str(text), Qt.TextElideMode.ElideRight, rect.width())
        painter.drawText(rect, int(align), elided)
        painter.restore()

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        size = super().sizeHint(option, index)
        return QSize(size.width(), max(size.height(), 28))


class SignalDelegate(BaseDelegate):
    """A bar in the band's colour, then the level in dBm."""

    def paint(self, painter, option, index) -> None:
        opacity = self._prepare(painter, option, index)
        painter.setOpacity(opacity)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette_colours
        row = index.data(ROW_ROLE) or {}
        rssi = row.get("rssi")
        colour = theme.band_colour(palette, row.get("band"))

        rect = option.rect.adjusted(8, 0, -8, 0)
        centre_y = rect.center().y()

        fraction = 0.0
        if rssi is not None:
            fraction = max(0.0, min(1.0, (float(rssi) - BAR_FLOOR) / (BAR_CEILING - BAR_FLOOR)))

        track = QRectF(rect.x(), centre_y - BAR_H / 2, BAR_MAX_W, BAR_H)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(theme.qcolor(palette.line))
        painter.drawRoundedRect(track, 3, 3)
        if fraction > 0:
            painter.setBrush(theme.qcolor(colour))
            painter.drawRoundedRect(
                QRectF(rect.x(), centre_y - BAR_H / 2, BAR_MAX_W * fraction, BAR_H), 3, 3
            )

        painter.setFont(mono_font(12))
        painter.setPen(theme.qcolor(palette.text if rssi is not None else palette.dimmer))
        text = f"{int(rssi)}" if rssi is not None else "?"
        painter.drawText(
            option.rect.adjusted(8 + BAR_MAX_W + 8, 0, -8, 0),
            int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
            text,
        )
        painter.restore()


class NameDelegate(BaseDelegate):
    """The network name, plus a chip when the same name is on another band."""

    def __init__(self, palette: Palette, parent=None) -> None:
        super().__init__(palette, parent)
        self._siblings: dict[str, set[str]] = {}

    def set_siblings(self, siblings: dict[str, set[str]]) -> None:
        self._siblings = siblings or {}

    def paint(self, painter, option, index) -> None:
        opacity = self._prepare(painter, option, index)
        painter.setOpacity(opacity)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette_colours
        row = index.data(ROW_ROLE) or {}

        if row.get("hidden"):
            text, colour = "(hidden)", palette.dim
        elif row.get("ssid"):
            text, colour = str(row["ssid"]), palette.text
        else:
            text, colour = "(no name)", palette.dim

        rect = option.rect.adjusted(8, 0, -8, 0)
        painter.setFont(ui_font(13))
        metrics = QFontMetrics(painter.font())

        others = sorted(self._siblings.get(row.get("ssid") or "", set())
                        - {str(row.get("band"))})
        chip_text = "+" + "/".join(others) if others else ""
        chip_w = 0
        if chip_text:
            chip_w = QFontMetrics(mono_font(10)).horizontalAdvance(chip_text) + CHIP_PAD * 2 + CHIP_GAP

        elided = metrics.elidedText(text, Qt.TextElideMode.ElideRight,
                                    max(20, rect.width() - chip_w))
        painter.setPen(theme.qcolor(colour))
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                         elided)

        if chip_text:
            x = rect.x() + metrics.horizontalAdvance(elided) + CHIP_GAP
            _draw_chip(painter, palette, x, rect.center().y(), chip_text,
                       palette.dimmer, neutral=True)
        painter.restore()


class BandDelegate(BaseDelegate):
    """A coloured band and channel chip, then the channel width."""

    def paint(self, painter, option, index) -> None:
        opacity = self._prepare(painter, option, index)
        painter.setOpacity(opacity)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette_colours
        row = index.data(ROW_ROLE) or {}
        band = str(row.get("band") or "")
        colour = theme.band_colour(palette, band)

        rect = option.rect.adjusted(8, 0, -8, 0)
        text = f"{band} · {row.get('channel')}" if band else str(row.get("channel") or "—")
        width = _draw_chip(painter, palette, rect.x(), rect.center().y(), text, colour)

        painter.setFont(mono_font(11))
        painter.setPen(theme.qcolor(palette.dimmer))
        painter.drawText(
            rect.adjusted(width + CHIP_GAP + 2, 0, 0, 0),
            int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
            f"{row.get('width_mhz') or 20} MHz",
        )
        painter.restore()


class SecurityDelegate(BaseDelegate):
    """Security posture as badges: what it is, then what is missing."""

    def paint(self, painter, option, index) -> None:
        opacity = self._prepare(painter, option, index)
        painter.setOpacity(opacity)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette_colours
        row = index.data(ROW_ROLE) or {}
        security = str(row.get("security") or "")

        rect = option.rect.adjusted(8, 0, -8, 0)
        x = rect.x()
        centre_y = rect.center().y()

        if security == "Open":
            x += _draw_chip(painter, palette, x, centre_y, "OPEN", palette.high) + CHIP_GAP
        elif security == "WEP":
            x += _draw_chip(painter, palette, x, centre_y, "WEP", palette.crit) + CHIP_GAP
        else:
            painter.setFont(ui_font(13))
            painter.setPen(theme.qcolor(palette.text))
            width = QFontMetrics(painter.font()).horizontalAdvance(security)
            painter.drawText(
                QRectF(x, rect.y(), width, rect.height()),
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                security,
            )
            x += width + CHIP_GAP

        if row.get("wps"):
            x += _draw_chip(painter, palette, x, centre_y, "WPS", palette.med) + CHIP_GAP
        if row.get("enterprise"):
            x += _draw_chip(painter, palette, x, centre_y, "802.1X", palette.low) + CHIP_GAP
        if not row.get("mfp_capable") and security not in ("Open", "WEP", ""):
            _draw_chip(painter, palette, x, centre_y, "no PMF", palette.dim)
        painter.restore()


class SeverityDelegate(BaseDelegate):
    """The severity of a finding, as a coloured badge."""

    def paint(self, painter, option, index) -> None:
        self._prepare(painter, option, index)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette_colours
        row = index.data(ROW_ROLE) or {}
        severity = str(row.get("severity") or "").lower()
        colour = theme.severity_colour(palette, severity)
        rect = option.rect.adjusted(8, 0, -8, 0)
        _draw_chip(painter, palette, rect.x(), rect.center().y(),
                   severity.upper(), colour)
        painter.restore()


class GradeDelegate(BaseDelegate):
    """A coverage grade, coloured against the survey thresholds."""

    def paint(self, painter, option, index) -> None:
        self._prepare(painter, option, index)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette_colours
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        row = index.data(ROW_ROLE) or {}
        colour = theme.grade_colour(palette, row.get("grade") or text.lower())
        rect = option.rect.adjusted(8, 0, -8, 0)
        _draw_chip(painter, palette, rect.x(), rect.center().y(), text, colour)
        painter.restore()


def _draw_chip(painter: QPainter, palette: Palette, x: float, centre_y: float,
               text: str, colour: str, neutral: bool = False) -> int:
    """Draw one pill and return the width it used."""
    font = mono_font(10)
    painter.setFont(font)
    metrics = QFontMetrics(font)
    width = metrics.horizontalAdvance(text) + CHIP_PAD * 2
    rect = QRectF(x, centre_y - CHIP_H / 2, width, CHIP_H)

    if neutral:
        background = theme.qcolor(palette.line, 0.8)
        border = theme.qcolor(palette.line)
    else:
        background = theme.qcolor(colour, palette.tint_alpha_bg)
        border = theme.qcolor(colour, palette.tint_alpha_border)

    painter.setPen(QPen(border, 1))
    painter.setBrush(background)
    painter.drawRoundedRect(rect, 3, 3)
    painter.setPen(theme.qcolor(colour))
    painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), text)
    return int(width)

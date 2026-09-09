"""The application icon, drawn rather than shipped as a file.

Three arcs in the band colours, which is the same wavelength logic the rest of
the interface uses. Drawing it means the icon is crisp at every size the
window manager asks for and there is no asset to lose in a build.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPen, QPixmap

from . import theme
from .theme import Palette

SIZES = (16, 24, 32, 48, 64, 128, 256)

# Outer to inner, so the widest arc is the lowest band.
ARCS = (
    ("b6", 0.92, 0.115),
    ("b5", 0.66, 0.115),
    ("b24", 0.40, 0.115),
)

# Arc angles are in sixteenths of a degree, spanning a fan opening upward.
START_ANGLE = 35 * 16
SPAN_ANGLE = 110 * 16


def render(palette: Palette, size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    centre_x = size / 2
    # The fan radiates from a dot near the bottom, so the arcs sit above it.
    centre_y = size * 0.80
    painter.setBrush(Qt.BrushStyle.NoBrush)

    for name, extent, thickness in ARCS:
        colour = getattr(palette, name)
        radius = size * 0.42 * extent
        pen = QPen(theme.qcolor(colour))
        pen.setWidthF(max(1.0, size * thickness))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(
            QRectF(centre_x - radius, centre_y - radius, radius * 2, radius * 2),
            START_ANGLE, SPAN_ANGLE,
        )

    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(theme.qcolor(palette.b24))
    dot = max(1.0, size * 0.075)
    painter.drawEllipse(QRectF(centre_x - dot, centre_y - dot, dot * 2, dot * 2))
    painter.end()
    return pixmap


def app_icon(palette: Palette) -> QIcon:
    icon = QIcon()
    for size in SIZES:
        icon.addPixmap(render(palette, size))
    return icon

"""Spectrum: what the air actually looks like, by frequency."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QWidget

from ...services import findings as findings_service
from ...services import networks as networks_service
from ...services import spectrum as spectrum_service
from .. import theme
from ..common import Card, label
from ..delegates import BandDelegate
from ..models import Column, DictTableModel, channel_sort
from ..spectrum_widget import SpectrumWidget
from .base import View

WINDOWS = [("Last 5 min", 5), ("Last 15 min", 15), ("Last hour", 60)]

LEGEND = [("2.4 GHz", "b24"), ("5 GHz", "b5"), ("6 GHz", "b6"), ("flagged", "crit")]


class SpectrumView(View):
    title = "Spectrum"
    reload_on_scan = True

    def build(self) -> None:
        card = Card(
            "Occupied spectrum",
            "Width and position are the real occupied spectrum, so overlap on "
            "screen is overlap in the air.",
        )
        self.window = QComboBox()
        for text, value in WINDOWS:
            self.window.addItem(text, value)
        self.window.setCurrentIndex(1)
        self.window.currentIndexChanged.connect(lambda _: self.load())
        card.add_action(self.window)

        self.ribbon = SpectrumWidget(self.palette_colours)
        self.ribbon.bssid_clicked.connect(self.ctx.open_drawer)
        card.add(self.ribbon)

        self.legend = self._build_legend()
        card.add(self.legend)
        self.add(card)

        occupancy = Card("Channel occupancy")
        self.model = DictTableModel([
            Column("band", "Band", width=130, sort=channel_sort),
            Column("channel", "Channel", width=90, mono=True),
            Column("count", "APs", width=80,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("best_rssi", "Best signal", width=120,
                   format=lambda v, r: f"{v} dBm" if v is not None else "\u2014",
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("avg_utilization", "Reported busy", stretch=True,
                   format=lambda v, r: f"{round(float(v))}%" if v is not None else "",
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.table, self.proxy = self.make_table(self.model, sort_column=0,
                                                 sort_order=Qt.SortOrder.AscendingOrder)
        self.set_column_delegate(self.table, 0, BandDelegate(self.palette_colours))
        self.table.setMinimumHeight(260)
        occupancy.add(self.table)
        self.add(occupancy)

    def _build_legend(self) -> QWidget:
        holder = QWidget()
        layout = QHBoxLayout(holder)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(16)
        self._swatches = []
        for text, attribute in LEGEND:
            item = QWidget()
            item_layout = QHBoxLayout(item)
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.setSpacing(6)
            swatch = QWidget()
            swatch.setFixedSize(11, 11)
            item_layout.addWidget(swatch)
            item_layout.addWidget(label(text, role="dimmer", size=12))
            layout.addWidget(item)
            self._swatches.append((swatch, attribute))
        layout.addStretch(1)
        self._paint_legend(self.palette_colours)
        return holder

    def _paint_legend(self, palette) -> None:
        for swatch, attribute in self._swatches:
            colour = getattr(palette, attribute)
            swatch.setStyleSheet(
                f"background: {theme.rgba(colour, 0.35)};"
                f" border: 1px solid {colour}; border-radius: 2px;"
            )

    def repalette(self, palette) -> None:
        self.ribbon.set_palette_colours(palette)
        self._paint_legend(palette)

    def load(self) -> None:
        minutes = self.window.currentData()
        self.run(
            lambda: (
                spectrum_service.layout(minutes=minutes),
                networks_service.channel_usage(minutes),
                findings_service.flagged_bssids(),
            ),
            self._apply,
        )

    def _apply(self, payload: tuple) -> None:
        layout, channels, flagged = payload
        self.ribbon.set_data(layout, flagged)
        self.model.set_rows(channels)

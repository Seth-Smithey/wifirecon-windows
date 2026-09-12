"""Networks: one entry per name, with every radio serving it.

Live lists one row per radio. A tri-band access point puts the same name on
2.4, 5 and 6 GHz with a different BSSID each, so 94 rows in Live can be 40
networks. This is the count that reflects what is actually around you, and
grouping is where inconsistent security shows up.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from ...services import networks as networks_service
from .. import theme
from ..common import Card, label, mono_font, ui_font
from .base import View

WINDOWS = [("Last 15 min", 15), ("Last hour", 60), ("Last day", 1440),
           ("Everything", None)]

BANDS = [("Any band", ""), ("Has 2.4 GHz", "2.4"), ("Has 5 GHz", "5"),
         ("Has 6 GHz", "6")]

BAND_ORDER = {"2.4": 0, "5": 1, "6": 2}

DATA_ROLE = Qt.ItemDataRole.UserRole + 1

SEARCH_DEBOUNCE_MS = 250


class SsidsView(View):
    title = "Networks"

    def build(self) -> None:
        card = Card("Networks by name")
        self.add(card, 1)

        toolbar = QWidget()
        bar = QHBoxLayout(toolbar)
        bar.setContentsMargins(0, 0, 0, 0)
        bar.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, BSSID or vendor")
        self.search.setFixedWidth(280)
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search)

        self.band = QComboBox()
        for text, value in BANDS:
            self.band.addItem(text, value)
        bar.addWidget(self.band)

        self.window = QComboBox()
        for text, value in WINDOWS:
            self.window.addItem(text, value)
        self.window.setCurrentIndex(1)
        bar.addWidget(self.window)

        self.multiband = QCheckBox("Multi-band only")
        bar.addWidget(self.multiband)

        bar.addStretch(1)
        self.count = label("", role="dimmer", mono=True, size=11)
        bar.addWidget(self.count)
        card.add(toolbar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels(
            ["Network", "Ch / width", "Signal", "Security", "PHY", "BSSID", "Vendor"]
        )
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.itemDoubleClicked.connect(self._activated)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 4, 5):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        # Column 3 carries the group's tag string on parent rows, which is long
        # enough to starve the name column if it is allowed to size to content.
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(3, 260)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(6, 250)
        self.tree.setMinimumHeight(440)
        card.add(self.tree, 1)

        self.empty = label("Nothing heard in this window yet.", role="hint")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.empty.hide()
        card.add(self.empty, 1)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(SEARCH_DEBOUNCE_MS)
        self._debounce.timeout.connect(self.load)

        self.search.textChanged.connect(lambda _: self._debounce.start())
        self.band.currentIndexChanged.connect(lambda _: self.load())
        self.window.currentIndexChanged.connect(lambda _: self.load())
        self.multiband.toggled.connect(lambda _: self._render())

    def load(self) -> None:
        minutes = self.window.currentData()
        search = self.search.text().strip() or None
        band = self.band.currentData() or None
        self.run(
            lambda: networks_service.grouped(
                minutes=minutes, search=search, band=band, limit=500),
            self._apply,
        )

    def _apply(self, result: dict) -> None:
        self._result = result
        self._render()

    def _render(self) -> None:
        result = getattr(self, "_result", None)
        if result is None:
            return
        palette = self.palette_colours
        groups = result["groups"]
        if self.multiband.isChecked():
            groups = [g for g in groups if g["band_count"] > 1]

        self.tree.clear()
        for group in groups:
            self.tree.addTopLevelItem(self._group_item(group, palette))

        # Counted over what is on screen, so the sentence cannot disagree with
        # the list under it when a filter is on.
        radios = sum(g["radio_count"] for g in groups)
        multi = sum(1 for g in groups if g["band_count"] > 1)
        tri = sum(1 for g in groups if g.get("tri_band"))
        summary = f"{len(groups)} networks across {radios} radios · {multi} multi-band"
        if tri:
            summary += f", {tri} tri-band"
        self.count.setText(summary)
        self.empty.setVisible(not groups)
        self.tree.setVisible(bool(groups))

    def _group_item(self, group: dict, palette) -> QTreeWidgetItem:
        item = QTreeWidgetItem()
        name = "(hidden network)" if group.get("hidden") else (group.get("ssid") or "")
        bands = " ".join(f"{b} GHz" for b in sorted(
            group.get("bands") or [], key=lambda b: BAND_ORDER.get(b, 9)))
        item.setText(0, f"{name}    {bands}")
        item.setFont(0, ui_font(13, QFont.Weight.DemiBold))
        if group.get("hidden"):
            item.setForeground(0, QBrush(theme.qcolor(palette.dim)))

        tags = []
        if group.get("band_count", 0) > 1:
            tags.append("tri-band" if group.get("tri_band") else "dual-band")
        if len(set(group.get("securities") or [])) > 1:
            tags.append("mixed security")
        if group.get("enterprise"):
            tags.append("802.1X")
        if group.get("wps"):
            tags.append("WPS")
        if not group.get("mfp_required") and "Open" not in (group.get("securities") or []):
            tags.append("PMF optional")
        item.setText(3, " · ".join(tags))
        item.setFont(3, mono_font(10))
        item.setForeground(3, QBrush(theme.qcolor(palette.dimmer)))

        radios = group.get("radio_count", 0)
        noun = "radio" if radios == 1 else "radios"
        item.setText(6, f"{radios} {noun} · best {group.get('best_rssi')} dBm")
        item.setFont(6, mono_font(11))
        item.setForeground(6, QBrush(theme.qcolor(palette.dim)))

        radio_rows = sorted(
            group.get("radios") or [],
            key=lambda r: (BAND_ORDER.get(str(r.get("band")), 9),
                           -(r.get("rssi") if r.get("rssi") is not None else -999)),
        )
        for radio in radio_rows:
            item.addChild(self._radio_item(radio, palette))
        item.setExpanded(len(radio_rows) <= 4)
        return item

    def _radio_item(self, radio: dict, palette) -> QTreeWidgetItem:
        child = QTreeWidgetItem()
        band = str(radio.get("band") or "")
        child.setText(0, f"{band} GHz")
        child.setForeground(0, QBrush(theme.qcolor(theme.band_colour(palette, band))))
        child.setFont(0, mono_font(11))
        child.setText(1, f"{radio.get('channel')} · {radio.get('width_mhz') or 20} MHz")
        child.setFont(1, mono_font(11))
        child.setText(2, f"{radio.get('rssi')} dBm"
                      if radio.get("rssi") is not None else "—")
        child.setFont(2, mono_font(11))
        child.setText(3, str(radio.get("security") or ""))
        child.setText(4, str(radio.get("phy") or ""))
        child.setForeground(4, QBrush(theme.qcolor(palette.dim)))
        child.setText(5, str(radio.get("bssid") or ""))
        child.setFont(5, mono_font(11))
        child.setText(6, str(radio.get("vendor") or ""))
        child.setForeground(6, QBrush(theme.qcolor(palette.dim)))
        child.setData(0, DATA_ROLE, radio)
        return child

    def _activated(self, item: QTreeWidgetItem, column: int) -> None:
        radio = item.data(0, DATA_ROLE)
        if radio and radio.get("bssid"):
            self.ctx.open_drawer(radio["bssid"])

    def repalette(self, palette) -> None:
        self._render()

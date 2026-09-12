"""Live: one row per radio in range."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QWidget,
)

from ...services import findings as findings_service
from ...services import networks as networks_service
from ..common import Card, ago, button, label
from ..delegates import (
    STALE_SECONDS,
    BandDelegate,
    NameDelegate,
    SecurityDelegate,
    SignalDelegate,
    TextDelegate,
)
from ..models import Column, DictTableModel, channel_sort
from .base import View

WINDOWS = [
    ("Seen in last 5 min", 5),
    ("Seen in last 15 min", 15),
    ("Seen in last hour", 60),
    ("Seen in last day", 1440),
    ("Everything ever seen", None),
]

BANDS = [("All bands", ""), ("2.4 GHz", "2.4"), ("5 GHz", "5"), ("6 GHz", "6")]

SEARCH_DEBOUNCE_MS = 250

ROW_LIMIT = 1000

EMPTY_MESSAGE = (
    "Nothing in range yet. Press Start scanning — you do not need to be joined "
    "to a network for this; it listens rather than connects. If it stays empty, "
    "open Diagnostics to check the adapter."
)


def _load_cell(value: Any, row: dict) -> str:
    if value is None:
        return ""
    text = f"{round(float(value))}%"
    stations = row.get("station_count")
    if stations:
        text += f" / {stations}"
    return text


class LiveView(View):
    title = "Live"
    reload_on_scan = True

    def build(self) -> None:
        self._flagged: set[str] = set()
        self._watched: set[str] = set()

        card = Card("In range")
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
        bar.addWidget(self.window)

        self.flagged_only = QCheckBox("Flagged only")
        bar.addWidget(self.flagged_only)

        bar.addStretch(1)
        self.count = label("0 shown", role="dimmer", mono=True, size=11)
        bar.addWidget(self.count)
        bar.addWidget(button("Export…", small=True, on_click=self._export,
                             tooltip="Save exactly the rows shown here as CSV"))
        card.add(toolbar)

        self.model = DictTableModel([
            Column("rssi", "Signal", width=110),
            Column("ssid", "Name", stretch=True),
            Column("channel", "Band / ch", width=140, sort=channel_sort),
            Column("security", "Security", width=210),
            Column("phy", "PHY", width=86),
            Column("bssid", "BSSID", width=150, mono=True),
            Column("vendor", "Vendor", width=150),
            Column("utilization_pct", "Load", width=90, format=_load_cell,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("last_seen", "Seen", width=90,
                   format=lambda v, r: ago(v),
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.model.set_stale_rule("last_seen", STALE_SECONDS)

        self.table, self.proxy = self.make_table(
            self.model, on_activate=lambda r: self.ctx.open_drawer(r["bssid"]),
            sort_column=0,
        )
        palette = self.palette_colours
        self.signal_delegate = SignalDelegate(palette)
        self.name_delegate = NameDelegate(palette)
        self.set_column_delegate(self.table, 0, self.signal_delegate)
        self.set_column_delegate(self.table, 1, self.name_delegate)
        self.set_column_delegate(self.table, 2, BandDelegate(palette))
        self.set_column_delegate(self.table, 3, SecurityDelegate(palette))
        self.set_column_delegate(self.table, 4, TextDelegate(palette, dim=True))
        self.set_column_delegate(self.table, 6, TextDelegate(palette, dim=True))
        self.set_column_delegate(self.table, 7, TextDelegate(palette, mono=True))
        self.set_column_delegate(self.table, 8, TextDelegate(palette, dim=True))
        self.table.setMinimumHeight(360)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        card.add(self.table, 1)

        self.empty = label(EMPTY_MESSAGE, role="hint", wrap=True)
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
        self.flagged_only.toggled.connect(lambda _: self._apply_filter())

    def focus_search(self) -> None:
        self.search.setFocus(Qt.FocusReason.ShortcutFocusReason)
        self.search.selectAll()

    def load(self) -> None:
        minutes = self.window.currentData()
        search = self.search.text().strip() or None
        band = self.band.currentData() or None
        self.run(
            lambda: (
                networks_service.listing(
                    minutes=minutes, search=search, band=band,
                    order="rssi", limit=ROW_LIMIT,
                ),
                findings_service.flagged_bssids(),
                _watched_bssids(),
            ),
            self._apply,
        )

    def _apply(self, payload: tuple) -> None:
        result, flagged, watched = payload
        rows = result["networks"]
        self._flagged = flagged
        self._watched = watched

        # A name on two or more bands is one network with several radios, so
        # the row says which other bands carry it.
        siblings: dict[str, set[str]] = {}
        for row in rows:
            if row.get("hidden") or not row.get("ssid"):
                continue
            siblings.setdefault(row["ssid"], set()).add(str(row.get("band")))
        self.name_delegate.set_siblings(
            {name: bands for name, bands in siblings.items() if len(bands) > 1}
        )

        self.model.set_rows(rows)
        self.model.set_flags(
            {**{b: "watched" for b in watched}, **{b: "flagged" for b in flagged}}
        )
        self._apply_filter()

    def _apply_filter(self) -> None:
        if self.flagged_only.isChecked():
            self.proxy.set_test(lambda r: r.get("bssid") in self._flagged)
        else:
            self.proxy.set_test(None)
        shown = self.proxy.rowCount()
        self.count.setText(f"{shown} shown")

        # A filter that hides everything is not the same as hearing nothing,
        # and saying so saves the person wondering whether the radio died.
        if shown:
            self.empty.hide()
            self.table.show()
            return
        self.table.hide()
        self.empty.show()
        if self.model.rowCount() and self.flagged_only.isChecked():
            self.empty.setText(
                f"None of the {self.model.rowCount()} networks in range have an "
                "open critical or high finding. Untick Flagged only to see them all."
            )
        elif self.model.rowCount():
            self.empty.setText("Nothing matches these filters.")
        else:
            self.empty.setText(EMPTY_MESSAGE)

    # -- actions ------------------------------------------------------------

    def _visible_rows(self) -> list[dict]:
        return [self.proxy.row_at(i) for i in range(self.proxy.rowCount())]

    def _context_menu(self, position) -> None:
        index = self.table.indexAt(position)
        row = self.proxy.row_at(index.row()) if index.isValid() else None
        if row is None:
            return
        name = row.get("ssid") or row["bssid"]
        menu = QMenu(self)
        menu.addAction("Open details", lambda: self.ctx.open_drawer(row["bssid"]))
        menu.addSeparator()
        menu.addAction("Copy BSSID", lambda: self._copy(row["bssid"]))
        menu.addAction("Copy name", lambda: self._copy(row.get("ssid") or ""))
        menu.addAction("Copy row", lambda: self._copy(_row_text(row)))
        menu.addSeparator()
        menu.addAction(
            f"Mark '{name}' trusted",
            lambda: self.ctx.add_mark("trusted", row["bssid"], row.get("ssid") or ""))
        menu.addAction(
            "Watch this radio",
            lambda: self.ctx.add_mark("watch", row["bssid"], row.get("ssid") or ""))
        menu.addAction(
            "Ignore this radio",
            lambda: self.ctx.add_mark("ignore", row["bssid"], row.get("ssid") or ""))
        menu.exec(self.table.viewport().mapToGlobal(position))

    def _copy(self, text: str) -> None:
        QGuiApplication.clipboard().setText(str(text))
        self.ctx.toast("Copied to the clipboard")

    def _export(self) -> None:
        rows = self._visible_rows()
        if not rows:
            self.ctx.toast("Nothing to export with these filters")
            return
        from ...services import naming

        chosen, _ = QFileDialog.getSaveFileName(
            self, "Export what is shown", naming.export_filename("live.csv"),
            "CSV (*.csv)")
        if not chosen:
            return
        self.run(lambda: _write_csv(Path(chosen), rows, self.model.columns()),
                 lambda path: self.ctx.toast(f"{len(rows)} rows saved to {path.name}",
                                             kind="ok"))

    def repalette(self, palette) -> None:
        pass


def _row_text(row: dict) -> str:
    return (f"{row.get('ssid') or '(hidden)'}\t{row['bssid']}\t"
            f"{row.get('band')} GHz ch {row.get('channel')}\t"
            f"{row.get('rssi')} dBm\t{row.get('security')}\t{row.get('vendor') or ''}")


def _write_csv(target: Path, rows: list[dict], columns) -> Path:
    """Exactly the columns on screen, in the order they are on screen."""
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([c.header for c in columns])
        for row in rows:
            writer.writerow([c.text(row) for c in columns])
    return target


def _watched_bssids() -> set[str]:
    from ... import db

    return {
        m["value"] for m in db.list_marks()
        if m.get("kind") == "watch" and m.get("match_type") == "bssid"
    }

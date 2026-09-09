"""Scan log: sessions, individual scans, and the live activity feed."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush
from PySide6.QtWidgets import QListWidget, QListWidgetItem

from ... import db
from .. import theme
from ..common import Card, clock, mono_font, short_clock
from ..delegates import TextDelegate
from ..models import Column, DictTableModel
from .base import View

FEED_LIMIT = 200


def _duration(value: Any, row: dict) -> str:
    started, ended = row.get("started_at"), row.get("ended_at")
    if not started:
        return "\u2014"
    if not ended:
        return "running"
    seconds = float(ended) - float(started)
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    return f"{seconds / 3600:.1f}h"


class HistoryView(View):
    title = "Scan log"
    reload_on_scan = True

    def build(self) -> None:
        feed_card = Card("Activity", "What the engine has been doing, newest last.")
        self.feed = QListWidget()
        self.feed.setFont(mono_font(11))
        self.feed.setMinimumHeight(200)
        self.feed.setWordWrap(True)
        feed_card.add(self.feed)
        self.add(feed_card)

        scans_card = Card("Recent scans")
        self.scan_model = DictTableModel([
            Column("started_at", "When", width=180, format=lambda v, r: clock(v)),
            Column("status", "Status", width=100),
            Column("bss_count", "Networks", width=100,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("new_bss_count", "New", width=80,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("alert_count", "Findings", width=100,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("error", "Error", stretch=True, format=lambda v, r: v or ""),
        ])
        self.scan_table, _ = self.make_table(self.scan_model, sort_column=0)
        self.set_column_delegate(self.scan_table, 0,
                                 TextDelegate(self.palette_colours, mono=True))
        self.scan_table.setMinimumHeight(260)
        scans_card.add(self.scan_table)
        self.add(scans_card)

        sessions_card = Card(
            "Sessions",
            "One row per time scanning was started and stopped.",
        )
        self.session_model = DictTableModel([
            Column("started_at", "Started", width=180, format=lambda v, r: clock(v)),
            Column("ended_at", "Duration", width=110, format=_duration),
            Column("adapter_name", "Adapter", stretch=True),
            Column("scan_count", "Scans", width=90,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.session_table, _ = self.make_table(self.session_model, sort_column=0)
        self.set_column_delegate(self.session_table, 0,
                                 TextDelegate(self.palette_colours, mono=True))
        self.session_table.setMinimumHeight(220)
        sessions_card.add(self.session_table)
        self.add(sessions_card)
        self.add_stretch()

    def load(self) -> None:
        self.run(
            lambda: (db.recent_scans(100), db.list_sessions(50), _activity()),
            self._apply,
        )

    def _apply(self, payload: tuple) -> None:
        scans, sessions, activity = payload
        self.scan_model.set_rows(scans)
        self.session_model.set_rows(sessions)
        self._fill_feed(activity)

    def _fill_feed(self, activity: list[dict]) -> None:
        palette = self.palette_colours
        at_bottom = (self.feed.verticalScrollBar().value()
                     >= self.feed.verticalScrollBar().maximum() - 4)
        self.feed.clear()
        for entry in activity[-FEED_LIMIT:]:
            item = QListWidgetItem(
                f"{short_clock(entry.get('ts'))}   {entry.get('message', '')}"
            )
            colour = {
                "error": palette.crit,
                "warn": palette.med,
            }.get(entry.get("level"), palette.text)
            item.setForeground(QBrush(theme.qcolor(colour)))
            self.feed.addItem(item)
        if at_bottom:
            self.feed.scrollToBottom()

    def repalette(self, palette) -> None:
        pass


def _activity() -> list[dict]:
    from ... import scanner

    return scanner.engine.status().get("activity", [])

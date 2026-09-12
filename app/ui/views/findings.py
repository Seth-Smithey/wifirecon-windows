"""Findings: what the detection rules concluded."""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from ...config import config
from ...services import findings as findings_service
from .. import theme
from ..common import Card, ago, button, clock, label, mono_font, ui_font
from .base import View

SEVERITIES = [("All severities", ""), ("Critical", "critical"), ("High", "high"),
              ("Medium", "medium"), ("Low", "low"), ("Info", "info")]

# A group opens by itself when its worst finding is this severe or worse.
AUTO_OPEN_RANK = 1

ROW_LIMIT = 300

# Below this many findings, grouping hides more than it helps.
GROUP_THRESHOLD = 12

DATA_ROLE = Qt.ItemDataRole.UserRole + 1
IDS_ROLE = Qt.ItemDataRole.UserRole + 2


class FindingsView(View):
    title = "Findings"
    reload_on_scan = True

    def build(self) -> None:
        self._rows: list[dict] = []

        card = Card("Findings")
        self.add(card, 1)

        toolbar = QWidget()
        bar = QHBoxLayout(toolbar)
        bar.setContentsMargins(0, 0, 0, 0)
        bar.setSpacing(8)

        self.severity = QComboBox()
        for text, value in SEVERITIES:
            self.severity.addItem(text, value)
        bar.addWidget(self.severity)

        self.rule = QComboBox()
        self.rule.addItem("All rules", "")
        bar.addWidget(self.rule)

        self.open_only = QCheckBox("Open only")
        self.open_only.setChecked(True)
        bar.addWidget(self.open_only)

        self.grouped = QCheckBox("Group by rule")
        self.grouped.setChecked(True)
        bar.addWidget(self.grouped)

        bar.addStretch(1)
        bar.addWidget(button("Acknowledge all", small=True, on_click=self._ack_all))
        bar.addWidget(button("Reopen", small=True, on_click=self._reopen))
        bar.addWidget(button("Clear…", small=True, kind="danger", on_click=self._clear))
        card.add(toolbar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["Severity", "Finding", "Network", "Rule", "When"])
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        self.tree.itemDoubleClicked.connect(self._activated)
        # The finding's own title gets a generous fixed share and the detail
        # takes the slack, because a truncated title says nothing at all while
        # a truncated detail still reads.
        header = self.tree.header()
        # A QTreeView stretches its last section by default, which hands the
        # timestamp column hundreds of pixels and elides the finding title.
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(0, 118)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.tree.setColumnWidth(2, 300)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(3, 210)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.tree.setColumnWidth(4, 96)
        self.tree.setMinimumHeight(420)
        card.add(self.tree, 1)

        self.empty = label(
            "No findings match these filters. Add your own networks as trusted "
            "under Marks first, or the impersonation rules have nothing to compare "
            "against.",
            role="hint", wrap=True,
        )
        self.empty.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.empty.hide()
        card.add(self.empty, 1)

        self.severity.currentIndexChanged.connect(lambda _: self.load())
        self.rule.currentIndexChanged.connect(lambda _: self.load())
        self.open_only.toggled.connect(lambda _: self.load())
        self.grouped.toggled.connect(lambda _: self._render())

    def load(self) -> None:
        severity = self.severity.currentData() or None
        rule = self.rule.currentData() or None
        unacked = self.open_only.isChecked()
        self.run(
            lambda: (
                findings_service.listing(limit=ROW_LIMIT, severity=severity,
                                         rule=rule, unacked_only=unacked),
                findings_service.rules(),
            ),
            self._apply,
        )

    def _apply(self, payload: tuple) -> None:
        result, rules = payload
        self._rows = result["alerts"]
        self._fill_rules(rules)
        self._render()

    def _fill_rules(self, rules: list[str]) -> None:
        if self.rule.count() - 1 == len(rules):
            return
        current = self.rule.currentData()
        self.rule.blockSignals(True)
        self.rule.clear()
        self.rule.addItem("All rules", "")
        for name in sorted(rules):
            self.rule.addItem(name, name)
        index = self.rule.findData(current)
        self.rule.setCurrentIndex(max(0, index))
        self.rule.blockSignals(False)

    # -- rendering ----------------------------------------------------------

    def _render(self) -> None:
        palette = self.palette_colours
        self.tree.clear()
        rows = self._rows
        self.empty.setVisible(not rows)
        self.tree.setVisible(bool(rows))
        if not rows:
            return

        if self.grouped.isChecked() and len(rows) > GROUP_THRESHOLD:
            self._render_grouped(rows, palette)
        else:
            for row in rows:
                self.tree.addTopLevelItem(self._leaf(row, palette))
        self.tree.setRootIsDecorated(
            self.grouped.isChecked() and len(rows) > GROUP_THRESHOLD)

    def _render_grouped(self, rows: list[dict], palette) -> None:
        groups: dict[str, list[dict]] = {}
        for row in rows:
            groups.setdefault(row.get("rule") or "unknown", []).append(row)

        def worst(items: list[dict]) -> int:
            return min(findings_service.SEVERITY_RANK.get(
                str(i.get("severity") or "").lower(), 9) for i in items)

        ordered = sorted(groups.items(), key=lambda kv: (worst(kv[1]), -len(kv[1])))

        for rule, items in ordered:
            rank = worst(items)
            severity = next(
                (s for s in findings_service.SEVERITIES
                 if findings_service.SEVERITY_RANK[s] == rank), "info"
            )
            parent = QTreeWidgetItem()
            parent.setText(0, severity.upper())
            parent.setForeground(0, QBrush(theme.qcolor(
                theme.severity_colour(palette, severity))))
            parent.setFont(0, mono_font(10, QFont.Weight.DemiBold))
            noun = "network" if len(items) == 1 else "networks"
            parent.setText(1, f"{rule}   ·   {len(items)} {noun}")
            parent.setFont(1, ui_font(13, QFont.Weight.DemiBold))
            summary = str(items[0].get("detail") or "")
            parent.setText(2, summary[:90] + ("…" if len(summary) > 90 else ""))
            parent.setForeground(2, QBrush(theme.qcolor(palette.dim)))
            parent.setText(3, rule)
            parent.setData(0, IDS_ROLE, [i["id"] for i in items])
            for row in items:
                parent.addChild(self._leaf(row, palette))
            self.tree.addTopLevelItem(parent)
            parent.setExpanded(rank <= AUTO_OPEN_RANK)

    def _leaf(self, row: dict, palette) -> QTreeWidgetItem:
        item = QTreeWidgetItem()
        severity = str(row.get("severity") or "").lower()
        item.setText(0, severity.upper())
        item.setForeground(0, QBrush(theme.qcolor(
            theme.severity_colour(palette, severity))))
        item.setFont(0, mono_font(10, QFont.Weight.DemiBold))
        item.setText(1, str(row.get("title") or ""))
        item.setText(2, str(row.get("ssid") or row.get("bssid") or ""))
        item.setFont(2, mono_font(11))
        item.setForeground(2, QBrush(theme.qcolor(palette.dim)))
        item.setText(3, str(row.get("rule") or ""))
        item.setFont(3, mono_font(11))
        item.setForeground(3, QBrush(theme.qcolor(palette.dimmer)))
        item.setText(4, ago(row.get("ts")))
        item.setForeground(4, QBrush(theme.qcolor(palette.dimmer)))
        item.setToolTip(1, self._tooltip(row))
        item.setData(0, DATA_ROLE, row)
        item.setData(0, IDS_ROLE, [row["id"]])
        if row.get("acknowledged"):
            for column in range(5):
                item.setForeground(column, QBrush(theme.qcolor(palette.dimmer)))
        return item

    def _tooltip(self, row: dict) -> str:
        parts = [str(row.get("detail") or "")]
        evidence = row.get("evidence")
        if isinstance(evidence, dict) and evidence:
            parts.append("")
            for key, value in evidence.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                parts.append(f"{key}: {value}")
        parts.append("")
        parts.append(clock(row.get("ts")))
        return "\n".join(parts)

    def repalette(self, palette) -> None:
        self._render()

    # -- actions ------------------------------------------------------------

    def _selected_ids(self) -> list[int]:
        ids: list[int] = []
        for item in self.tree.selectedItems():
            ids.extend(item.data(0, IDS_ROLE) or [])
        return ids

    def _activated(self, item: QTreeWidgetItem, column: int) -> None:
        row = item.data(0, DATA_ROLE)
        if row and row.get("bssid"):
            self.ctx.open_drawer(row["bssid"])

    def _context_menu(self, position) -> None:
        item = self.tree.itemAt(position)
        if item is None:
            return
        row = item.data(0, DATA_ROLE)
        ids = self._selected_ids() or (item.data(0, IDS_ROLE) or [])
        menu = QMenu(self)
        if row and row.get("bssid"):
            menu.addAction("Open details",
                           lambda: self.ctx.open_drawer(row["bssid"]))
            menu.addSeparator()
        menu.addAction(f"Acknowledge {len(ids)}", lambda: self._ack(ids))
        menu.addAction(f"Reopen {len(ids)}", lambda: self._unack(ids))
        rule_name = (row or {}).get("rule") or item.text(3)
        if rule_name:
            menu.addSeparator()
            if rule_name in _muted():
                menu.addAction(f"Unmute '{rule_name}'",
                               lambda: self._set_muted(rule_name, False))
            else:
                menu.addAction(f"Mute '{rule_name}' — stop reporting it",
                               lambda: self._set_muted(rule_name, True))
        menu.exec(self.tree.viewport().mapToGlobal(position))

    def _set_muted(self, rule_name: str, muted: bool) -> None:
        current = set(_muted())
        if muted:
            current.add(rule_name)
        else:
            current.discard(rule_name)
        config.set(sorted(current), "detections", "muted_rules")
        self.ctx.toast(
            f"'{rule_name}' muted. Existing findings stay; no new ones are raised."
            if muted else f"'{rule_name}' will report again from the next scan.",
            kind="ok",
        )
        self._render()

    def _ack(self, ids: list[int]) -> None:
        if not ids:
            return
        self.run(lambda: findings_service.acknowledge(ids), self._after)

    def _unack(self, ids: list[int]) -> None:
        if not ids:
            return
        self.run(lambda: findings_service.unacknowledge(ids), self._after)

    def _ack_all(self) -> None:
        if not self.ctx.confirm("Acknowledge every open finding?"):
            return
        self.run(lambda: findings_service.acknowledge(None), self._after)

    def _reopen(self) -> None:
        rule = self.rule.currentData() or None
        question = (f"Reopen every acknowledged '{rule}' finding?" if rule
                    else "Reopen every acknowledged finding?")
        if not self.ctx.confirm(question):
            return
        self.run(lambda: findings_service.unacknowledge(None, rule), self._after)

    def _clear(self) -> None:
        rule = self.rule.currentData() or None
        choices = ["Acknowledged findings only", "Everything"]
        if rule:
            choices.append(f"Every '{rule}' finding")
        choices.append("Anything older than 30 days")
        scopes = ["acknowledged", "all"] + (["rule"] if rule else []) + ["older"]

        from PySide6.QtWidgets import QInputDialog

        text, ok = QInputDialog.getItem(
            self, "Clear findings", "What should be deleted?", choices, 0, False
        )
        if not ok:
            return
        scope = scopes[choices.index(text)]
        if scope == "all" and not self.ctx.confirm(
            "Delete every finding, acknowledged or not? This cannot be undone.",
            destructive=True,
        ):
            return
        self.run(
            lambda: findings_service.clear(scope=scope, rule=rule, days=30),
            self._after_clear,
        )

    def _after(self, result: Any) -> None:
        self.load()
        self.ctx.refresh_status()

    def _after_clear(self, result: dict) -> None:
        self.ctx.toast(f"Deleted {result['removed']} finding(s)", kind="ok")
        self.load()
        self.ctx.refresh_status()


def _muted() -> set[str]:
    return {str(r) for r in (config.get("detections", "muted_rules", default=[]) or [])}

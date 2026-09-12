"""Marks: the watch, trusted and ignore lists.

Adding your own networks as trusted matters more than anything else here. The
impersonation rules compare against this list, so with it empty `lookalike_ssid`
has nothing to measure against and will never fire.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLineEdit, QWidget

from ...services import marks as marks_service
from ..common import Card, button, clock, label
from ..delegates import TextDelegate
from ..models import Column, DictTableModel
from .base import View

KIND_HELP = {
    "trusted": "Teaches the impersonation rules what the real thing looks like. "
               "Add your own network names here first.",
    "watch": "Raises the severity of changes on this network, and reports when "
             "it stops appearing.",
    "ignore": "Silences this BSSID, vendor prefix or name entirely.",
}


class MarksView(View):
    title = "Marks"

    def build(self) -> None:
        add_card = Card(
            "Add a mark",
            "Add your own networks as trusted first. The impersonation rules "
            "need a reference to compare against.",
        )
        form = QWidget()
        row = QHBoxLayout(form)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self.kind = QComboBox()
        for value in marks_service.VALID_KINDS:
            self.kind.addItem(marks_service.KIND_LABELS[value], value)
        row.addWidget(self.kind)

        self.match_type = QComboBox()
        for value in marks_service.VALID_MATCH_TYPES:
            self.match_type.addItem(marks_service.MATCH_LABELS[value], value)
        row.addWidget(self.match_type)

        self.value = QLineEdit()
        self.value.setPlaceholderText("Network name, MAC address or vendor prefix")
        self.value.returnPressed.connect(self._add)
        row.addWidget(self.value, 1)

        self.mark_label = QLineEdit()
        self.mark_label.setPlaceholderText("Label (optional)")
        self.mark_label.setFixedWidth(180)
        row.addWidget(self.mark_label)

        row.addWidget(button("Add", kind="primary", on_click=self._add))
        add_card.add(form)

        self.help = label("", role="hint", wrap=True)
        add_card.add(self.help)
        self.add(add_card)

        list_card = Card("Marks")
        self.remove_button = button("Remove selected", small=True, kind="danger",
                                    on_click=self._remove)
        list_card.add_action(self.remove_button)

        self.model = DictTableModel([
            Column("kind", "Kind", width=110,
                   format=lambda v, r: marks_service.KIND_LABELS.get(v, str(v))),
            Column("match_type", "Matches on", width=150,
                   format=lambda v, r: marks_service.MATCH_LABELS.get(v, str(v))),
            Column("value", "Value", stretch=True, mono=True),
            Column("label", "Label", width=200,
                   format=lambda v, r: v or ""),
            Column("created_at", "Added", width=170,
                   format=lambda v, r: clock(v),
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.table, self.proxy = self.make_table(self.model, sort_column=4)
        self.set_column_delegate(self.table, 4, TextDelegate(self.palette_colours,
                                                             mono=True, dim=True))
        self.table.setMinimumHeight(340)
        list_card.add(self.table, 1)

        self.empty = label(
            "No marks yet. Add your home network name as trusted to switch the "
            "impersonation rules on.",
            role="hint", wrap=True,
        )
        self.empty.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.empty.hide()
        list_card.add(self.empty, 1)
        self.add(list_card, 1)

        self.kind.currentIndexChanged.connect(lambda _: self._update_help())
        self._update_help()

    def _update_help(self) -> None:
        self.help.setText(KIND_HELP.get(self.kind.currentData(), ""))

    def load(self) -> None:
        self.run(marks_service.listing, self._apply)

    def _apply(self, rows: list[dict]) -> None:
        self.model.set_rows(rows)
        self.empty.setVisible(not rows)
        self.table.setVisible(bool(rows))

    def _add(self) -> None:
        kind = self.kind.currentData()
        match_type = self.match_type.currentData()
        value = self.value.text().strip()
        mark_label = self.mark_label.text().strip() or None
        self.run(
            lambda: marks_service.add(kind, match_type, value, mark_label),
            self._added,
        )

    def _added(self, rows: list[dict]) -> None:
        self.value.clear()
        self.mark_label.clear()
        self.model.set_rows(rows)
        self.empty.hide()
        self.table.show()
        self.ctx.toast("Mark added", kind="ok")

    def _remove(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            self.ctx.toast("Select a mark to remove first")
            return
        row = self.proxy.row_at(indexes[0].row())
        if row is None:
            return
        if not self.ctx.confirm(f"Remove the mark on {row['value']}?"):
            return
        self.run(lambda: marks_service.remove(row["id"]), self._apply)

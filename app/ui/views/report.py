"""Report: the client-ready document, and the raw exports."""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QWidget,
)

from ... import exporters, reporting
from ...config import config, data_dir
from ...services import naming, survey_svc
from ..common import Card, button, label
from ..models import Column, DictTableModel
from .base import View

EXPORTS = [
    ("networks.csv", "Every radio seen, one row each", exporters.bss_csv),
    ("alerts.csv", "Every finding", exporters.alerts_csv),
    ("observations.csv", "The full time series", exporters.observations_csv),
    ("wigle.csv", "WiGLE 1.6 upload format", exporters.wigle_csv),
    ("survey.kml", "Google Earth", exporters.kml),
    ("survey.json", "Everything, as JSON", exporters.full_json),
    ("report.html", "The survey report on its own", exporters.html_report),
]

WINDOWS = [("Last hour", 60), ("Last day", 1440), ("Last week", 10080),
           ("Everything", None)]


class ReportView(View):
    title = "Report"

    def build(self) -> None:
        card = Card(
            "Client report",
            "A self-contained HTML document: executive summary, findings "
            "explained in plain language, channel plan, coverage results and the "
            "full network list. It prints cleanly to PDF from a browser.",
        )
        form = QWidget()
        grid = QGridLayout(form)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)

        self.title_field = QLineEdit(
            config.get("site", "default_report_title", default="Wireless Site Survey"))
        self.prepared_by = QLineEdit(
            config.get("site", "default_prepared_by", default=""))
        self.prepared_by.setPlaceholderText("Your name")
        self.window = QComboBox()
        for text, value in WINDOWS:
            self.window.addItem(text, value)
        self.window.setCurrentIndex(1)

        grid.addWidget(label("Title"), 0, 0)
        grid.addWidget(self.title_field, 0, 1)
        grid.addWidget(label("Prepared by"), 0, 2)
        grid.addWidget(self.prepared_by, 0, 3)
        grid.addWidget(label("Covering"), 0, 4)
        grid.addWidget(self.window, 0, 5)
        grid.setColumnStretch(1, 2)
        grid.setColumnStretch(3, 1)
        card.add(form)

        options = QWidget()
        option_row = QHBoxLayout(options)
        option_row.setContentsMargins(0, 0, 0, 0)
        option_row.setSpacing(16)
        self.include_coverage = QCheckBox("Coverage results")
        self.include_plan = QCheckBox("Channel plan")
        self.include_inventory = QCheckBox("AP inventory")
        for box in (self.include_coverage, self.include_plan, self.include_inventory):
            box.setChecked(True)
            option_row.addWidget(box)
        option_row.addStretch(1)
        card.add(options)

        actions = QWidget()
        action_row = QHBoxLayout(actions)
        action_row.setContentsMargins(0, 0, 0, 0)
        action_row.setSpacing(8)
        action_row.addWidget(button("Open the report", kind="primary",
                                    on_click=lambda: self._build_report(open_after=True)))
        action_row.addWidget(button("Save as…",
                                    on_click=lambda: self._build_report(open_after=False)))
        action_row.addStretch(1)
        card.add(actions)

        card.add(label(
            "The report explains how Windows survey data is collected. "
            "Scanning does not require joining a network, but Windows may send "
            "probe requests. Record any separate discovery or audit activity in your engagement notes.",
            role="hint", wrap=True,
        ))
        self.add(card)

        inventory = Card(
            "Access point inventory",
            "Label the access points you manage. Reports then name them properly, "
            "and anything unlabelled stands out as unmanaged.",
        )
        self.inventory_model = DictTableModel([
            Column("label", "Label", stretch=True, format=lambda v, r: v or "—"),
            Column("bssid", "BSSID", width=150, mono=True),
            Column("location", "Location", width=200, format=lambda v, r: v or ""),
            Column("asset_tag", "Asset tag", width=150, format=lambda v, r: v or ""),
        ])
        self.inventory_table, self.inventory_proxy = self.make_table(
            self.inventory_model, sort_column=0,
            sort_order=Qt.SortOrder.AscendingOrder)
        self.inventory_table.setMinimumHeight(200)
        inventory.add(self.inventory_table)
        inventory_actions = QWidget()
        inventory_row = QHBoxLayout(inventory_actions)
        inventory_row.setContentsMargins(0, 0, 0, 0)
        inventory_row.addWidget(button("Remove from inventory", small=True,
                                       kind="danger", on_click=self._remove_inventory))
        inventory_row.addStretch(1)
        inventory.add(inventory_actions)
        self.add(inventory)

        exports = Card("Exports", "Raw data, for whatever you do with it next.")
        export_host = QWidget()
        export_grid = QGridLayout(export_host)
        export_grid.setContentsMargins(0, 0, 0, 0)
        export_grid.setHorizontalSpacing(10)
        export_grid.setVerticalSpacing(6)
        for position, (name, description, fn) in enumerate(EXPORTS):
            export_grid.addWidget(
                button(name, small=True,
                       on_click=lambda n=name, f=fn: self._export(n, f)),
                position, 0,
            )
            export_grid.addWidget(label(description, role="hint", size=12), position, 1)
        export_grid.setColumnStretch(1, 1)
        exports.add(export_host)
        self.add(exports)
        self.add_stretch()

    def load(self) -> None:
        self.run(lambda: survey_svc.inventory(survey_svc.active_site_id(None)),
                 self.inventory_model.set_rows)

    # -- report -------------------------------------------------------------

    def _build_report(self, open_after: bool) -> None:
        suggested = naming.report_filename(self.title_field.text())
        if open_after:
            target = Path(data_dir()) / "reports" / suggested
            target.parent.mkdir(parents=True, exist_ok=True)
        else:
            chosen, _ = QFileDialog.getSaveFileName(
                self, "Save the report", suggested, "HTML document (*.html)")
            if not chosen:
                return
            target = Path(chosen)

        # Remembered so the next report does not need retyping.
        config.set(self.title_field.text(), "site", "default_report_title")
        config.set(self.prepared_by.text(), "site", "default_prepared_by")

        self.run(
            lambda: _write_report(
                target,
                site_id=survey_svc.active_site_id(None),
                title=self.title_field.text(),
                prepared_by=self.prepared_by.text(),
                minutes=self.window.currentData(),
                include_inventory=self.include_inventory.isChecked(),
                include_coverage=self.include_coverage.isChecked(),
                include_plan=self.include_plan.isChecked(),
            ),
            lambda path: self._report_done(path, open_after),
        )

    def _report_done(self, path: Path, open_after: bool) -> None:
        if open_after:
            webbrowser.open(path.as_uri())
            self.ctx.toast(f"Report opened. Saved to {path.name}", kind="ok")
        else:
            self.ctx.toast(f"Report saved to {path}", kind="ok")

    def _export(self, name: str, fn) -> None:
        suggested = naming.export_filename(name)
        chosen, _ = QFileDialog.getSaveFileName(self, f"Save {name}", suggested)
        if not chosen:
            return
        target = Path(chosen)
        self.run(
            lambda: _write_text(target, fn()),
            lambda path: self.ctx.toast(f"Saved to {path}", kind="ok"),
        )

    def _remove_inventory(self) -> None:
        indexes = self.inventory_table.selectionModel().selectedRows()
        if not indexes:
            self.ctx.toast("Select an entry first")
            return
        entry = self.inventory_proxy.row_at(indexes[0].row())
        if entry is None or not self.ctx.confirm(
            f"Remove {entry.get('label') or entry['bssid']} from the inventory?"
        ):
            return
        self.run(lambda: survey_svc.delete_inventory(entry["bssid"]),
                 lambda _: self.load())


def _write_report(target: Path, **kwargs: Any) -> Path:
    html = reporting.build(**kwargs)
    target.write_text(html, encoding="utf-8")
    return target


def _write_text(target: Path, content: str) -> Path:
    target.write_text(content, encoding="utf-8")
    return target

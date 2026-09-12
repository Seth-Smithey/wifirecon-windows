"""Survey: sites, walk points, coverage, channel plan and snapshots."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from ...services import survey_svc
from .. import theme
from ..common import Card, button, clock, label, mono_font, ui_font
from ..models import Column, DictTableModel
from .base import View

# The thresholds survey reports are normally written to.
VOICE_FLOOR = -67
UNRELIABLE_FLOOR = -72


class SurveyView(View):
    title = "Survey"

    def build(self) -> None:
        sites = Card(
            "Sites",
            "Survey points, inventory and snapshots all belong to the selected "
            "site, so separate engagements stay separate.",
        )
        site_form = QWidget()
        site_row = QHBoxLayout(site_form)
        site_row.setContentsMargins(0, 0, 0, 0)
        site_row.setSpacing(8)
        self.site_name = QLineEdit()
        self.site_name.setPlaceholderText("Site name")
        self.site_client = QLineEdit()
        self.site_client.setPlaceholderText("Client")
        self.site_address = QLineEdit()
        self.site_address.setPlaceholderText("Address")
        site_row.addWidget(self.site_name, 1)
        site_row.addWidget(self.site_client, 1)
        site_row.addWidget(self.site_address, 2)
        site_row.addWidget(button("Add site", kind="primary", on_click=self._add_site))
        sites.add(site_form)

        self.site_model = DictTableModel([
            Column("name", "Name", stretch=True),
            Column("client", "Client", width=200, format=lambda v, r: v or ""),
            Column("address", "Address", width=280, format=lambda v, r: v or ""),
            Column("created_at", "Created", width=170, format=lambda v, r: clock(v),
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.site_table, self.site_proxy = self.make_table(self.site_model,
                                                           sort_column=3)
        self.site_table.setMaximumHeight(180)
        sites.add(self.site_table)
        site_actions = QWidget()
        site_action_row = QHBoxLayout(site_actions)
        site_action_row.setContentsMargins(0, 0, 0, 0)
        site_action_row.setSpacing(8)
        site_action_row.addWidget(button("Make active", small=True,
                                         on_click=self._activate_site))
        site_action_row.addWidget(button("Remove site", small=True, kind="danger",
                                         on_click=self._remove_site))
        site_action_row.addStretch(1)
        sites.add(site_actions)
        self.add(sites)

        capture = Card(
            "Walk survey",
            "Stand somewhere, name it, and capture. It runs a fresh scan and "
            "records every network audible from that spot.",
        )
        capture_form = QWidget()
        capture_row = QHBoxLayout(capture_form)
        capture_row.setContentsMargins(0, 0, 0, 0)
        capture_row.setSpacing(8)
        self.point_name = QLineEdit()
        self.point_name.setPlaceholderText("Location, such as Reception or Suite 204")
        self.point_floor = QLineEdit()
        self.point_floor.setPlaceholderText("Floor")
        self.point_floor.setFixedWidth(120)
        self.point_notes = QLineEdit()
        self.point_notes.setPlaceholderText("Notes")
        capture_row.addWidget(self.point_name, 2)
        capture_row.addWidget(self.point_floor)
        capture_row.addWidget(self.point_notes, 2)
        self.capture_button = button("Capture point", kind="primary",
                                     on_click=self._capture)
        capture_row.addWidget(self.capture_button)
        capture.add(capture_form)

        self.point_model = DictTableModel([
            Column("name", "Location", stretch=True),
            Column("floor", "Floor", width=100, format=lambda v, r: v or ""),
            Column("ap_count", "APs", width=80,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("best_rssi", "Best", width=100,
                   format=lambda v, r: f"{v} dBm" if v is not None else "—",
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("captured_at", "Captured", width=170,
                   format=lambda v, r: clock(v),
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.point_table, self.point_proxy = self.make_table(self.point_model,
                                                             sort_column=4)
        self.point_table.setMinimumHeight(200)
        capture.add(self.point_table)
        point_actions = QWidget()
        point_row = QHBoxLayout(point_actions)
        point_row.setContentsMargins(0, 0, 0, 0)
        point_row.addWidget(button("Delete point", small=True, kind="danger",
                                   on_click=self._delete_point))
        point_row.addStretch(1)
        capture.add(point_actions)
        self.add(capture)

        coverage = Card(
            "Coverage",
            f"Above {VOICE_FLOOR} dBm supports voice. Below {UNRELIABLE_FLOOR} dBm "
            "is unreliable.",
        )
        coverage.add_action(button("Refresh", small=True, on_click=self._load_coverage))
        self.matrix = QTableWidget()
        self.matrix.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.matrix.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.matrix.setMinimumHeight(260)
        self.matrix.verticalHeader().setVisible(False)
        coverage.add(self.matrix)
        self.coverage_note = label("", role="hint", wrap=True)
        coverage.add(self.coverage_note)
        self.add(coverage)

        plan = Card(
            "Channel plan",
            "Scores every channel on how many access points occupy or overlap "
            "it, how strong those are, and reported utilisation.",
        )
        plan.add_action(button("Recalculate", small=True, on_click=self._load_plan))
        self.plan_text = label("", mono=True, size=11, wrap=True)
        plan.add(self.plan_text)
        self.add(plan)

        snapshots = Card(
            "Before and after",
            "Take a snapshot, do the work, compare. It reports what appeared, "
            "what went away, and what changed.",
        )
        snapshot_form = QWidget()
        snapshot_row = QHBoxLayout(snapshot_form)
        snapshot_row.setContentsMargins(0, 0, 0, 0)
        snapshot_row.setSpacing(8)
        self.snapshot_name = QLineEdit()
        self.snapshot_name.setPlaceholderText("Snapshot name, such as Before")
        snapshot_row.addWidget(self.snapshot_name, 1)
        snapshot_row.addWidget(button("Take snapshot", on_click=self._take_snapshot))
        snapshot_row.addWidget(button("Compare selected", kind="primary",
                                      on_click=self._compare))
        snapshots.add(snapshot_form)

        self.snapshot_model = DictTableModel([
            Column("name", "Name", stretch=True),
            Column("ap_count", "Networks", width=110,
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
            Column("taken_at", "Taken", width=170, format=lambda v, r: clock(v),
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.snapshot_table, self.snapshot_proxy = self.make_table(
            self.snapshot_model, sort_column=2)
        self.snapshot_table.setMaximumHeight(180)
        snapshots.add(self.snapshot_table)
        self.compare_text = label("", mono=True, size=11, wrap=True)
        snapshots.add(self.compare_text)
        self.add(snapshots)
        self.add_stretch()

    # -- loading ------------------------------------------------------------

    def load(self) -> None:
        self.run(
            lambda: (survey_svc.sites(), survey_svc.points(
                survey_svc.active_site_id(None)),
                survey_svc.snapshots(survey_svc.active_site_id(None))),
            self._apply,
        )
        self._load_coverage()

    def _apply(self, payload: tuple) -> None:
        sites, points, snapshots = payload
        self.site_model.set_rows(sites)
        self.point_model.set_rows(points)
        self.snapshot_model.set_rows(snapshots)

    def _load_coverage(self) -> None:
        self.run(lambda: survey_svc.coverage(), self._apply_coverage)

    def _apply_coverage(self, report: dict) -> None:
        palette = self.palette_colours
        points = report.get("points") or []
        rows = report.get("rows") or []
        self.matrix.clear()
        if not points or not rows:
            self.matrix.setRowCount(0)
            self.matrix.setColumnCount(0)
            self.coverage_note.setText(
                "No survey points yet. Capture one above and the matrix fills in."
            )
            return

        self.matrix.setColumnCount(len(points) + 1)
        self.matrix.setRowCount(len(rows))
        self.matrix.setHorizontalHeaderLabels(
            ["Network"] + [p["name"] for p in points])
        header = self.matrix.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(points) + 1):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

        for row_index, row in enumerate(rows):
            name = QTableWidgetItem(str(row.get("ssid") or row.get("key") or ""))
            name.setFont(ui_font(13))
            self.matrix.setItem(row_index, 0, name)
            for column_index, cell in enumerate(row.get("cells") or [], start=1):
                rssi = cell.get("rssi")
                item = QTableWidgetItem(f"{rssi}" if rssi is not None else "—")
                item.setFont(mono_font(11))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                colour = theme.grade_colour(palette, cell.get("grade"))
                item.setForeground(QBrush(theme.qcolor(colour)))
                if rssi is not None:
                    item.setBackground(QBrush(theme.qcolor(colour, 0.14)))
                item.setToolTip(f"{cell.get('point')}: {cell.get('grade') or 'no signal'}")
                self.matrix.setItem(row_index, column_index, item)

        notes = report.get("recommendations") or []
        worst = report.get("worst") or []
        text = []
        if worst:
            text.append("Weakest locations: " + ", ".join(
                str(w.get("point") or w) for w in worst[:5]))
        text.extend(str(n) for n in notes)
        self.coverage_note.setText("\n".join(text))

    def _load_plan(self) -> None:
        self.run(survey_svc.channel_plan, self._apply_plan)

    def _apply_plan(self, plan: dict) -> None:
        # channel_plan() keys the result by band directly, and each pick is a
        # dict carrying the channel and why it scored where it did.
        lines = []
        for band in ("2.4", "5", "6"):
            entry = plan.get(band) or {}
            picks = entry.get("recommended") or []
            if not picks:
                continue
            names = ", ".join(str(p["channel"]) for p in picks)
            lines.append(f"{band} GHz   suggest {names}")
            for pick in picks:
                why = ", ".join(pick.get("reasons") or [])
                lines.append(f"          ch {pick['channel']}: {why}")
            lines.append("")
        for note in plan.get("summary") or []:
            lines.append(str(note))
        self.plan_text.setText("\n".join(lines).strip()
                               or "Not enough data for a plan yet.")

    # -- actions ------------------------------------------------------------

    def _add_site(self) -> None:
        self.run(
            lambda: survey_svc.create_site(
                self.site_name.text(), self.site_client.text(),
                self.site_address.text()),
            self._site_added,
        )

    def _site_added(self, result: dict) -> None:
        self.site_name.clear()
        self.site_client.clear()
        self.site_address.clear()
        self.site_model.set_rows(result["sites"])
        self.ctx.toast("Site added", kind="ok")
        self._refresh_site_picker()

    def _selected_site(self) -> dict | None:
        indexes = self.site_table.selectionModel().selectedRows()
        return self.site_proxy.row_at(indexes[0].row()) if indexes else None

    def _activate_site(self) -> None:
        site = self._selected_site()
        if not site:
            self.ctx.toast("Select a site first")
            return
        self.run(lambda: survey_svc.activate_site(site["id"]),
                 lambda _: (self.ctx.toast(f"{site['name']} is now the active site",
                                           kind="ok"),
                            self._refresh_site_picker(), self.load()))

    def _remove_site(self) -> None:
        site = self._selected_site()
        if not site:
            self.ctx.toast("Select a site first")
            return
        if not self.ctx.confirm(
            f"Remove {site['name']}? Its survey points and snapshots go too.",
            destructive=True,
        ):
            return
        self.run(lambda: survey_svc.delete_site(site["id"]),
                 lambda sites: (self.site_model.set_rows(sites),
                                self._refresh_site_picker(), self.load()))

    def _capture(self) -> None:
        name = self.point_name.text().strip()
        self.capture_button.setEnabled(False)
        self.capture_button.setText("Scanning…")

        def done(result: dict) -> None:
            self.capture_button.setEnabled(True)
            self.capture_button.setText("Capture point")
            self.point_name.clear()
            self.point_notes.clear()
            best = result.get("best_rssi")
            self.ctx.toast(
                f"{name}: {result['ap_count']} networks heard"
                + (f", best {best} dBm" if best is not None else ""),
                kind="ok",
            )
            self.point_model.set_rows(result["points"])
            self._load_coverage()

        def failed(exc: Exception) -> None:
            self.capture_button.setEnabled(True)
            self.capture_button.setText("Capture point")
            self._report_error(exc)

        self.ctx.pool.run(
            lambda: survey_svc.capture_point(
                name, True, None, self.point_floor.text(), self.point_notes.text()),
            done, failed,
        )

    def _delete_point(self) -> None:
        indexes = self.point_table.selectionModel().selectedRows()
        if not indexes:
            self.ctx.toast("Select a survey point first")
            return
        point = self.point_proxy.row_at(indexes[0].row())
        if point is None or not self.ctx.confirm(
            f"Delete the survey point {point['name']}?", destructive=True
        ):
            return
        self.run(lambda: survey_svc.delete_point(point["id"]),
                 lambda _: (self.load(), self._load_coverage()))

    def _take_snapshot(self) -> None:
        self.run(
            lambda: survey_svc.take_snapshot(self.snapshot_name.text()),
            lambda result: (self.snapshot_name.clear(),
                            self.snapshot_model.set_rows(result["snapshots"]),
                            self.ctx.toast("Snapshot taken", kind="ok")),
        )

    def _compare(self) -> None:
        indexes = self.snapshot_table.selectionModel().selectedRows()
        if not indexes:
            self.ctx.toast("Select a snapshot to compare against")
            return
        snapshot = self.snapshot_proxy.row_at(indexes[0].row())
        if snapshot is None:
            return
        self.run(lambda: survey_svc.compare_snapshot(snapshot["id"]), self._apply_diff)

    def _apply_diff(self, diff: dict) -> None:
        lines = [str(diff.get("summary") or "")]
        for key, heading in (("added", "appeared"), ("removed", "went away"),
                             ("changed", "changed")):
            entries = diff.get(key) or []
            if entries:
                lines.append(f"\n{heading} ({len(entries)}):")
                for entry in entries[:20]:
                    lines.append(
                        f"  {entry.get('ssid') or entry.get('bssid')}"
                        + (f" — {entry.get('detail')}" if entry.get("detail") else "")
                    )
        self.compare_text.setText("\n".join(lines))

    def _refresh_site_picker(self) -> None:
        window = self.window()
        if hasattr(window, "refresh_sites"):
            window.refresh_sites()

    def repalette(self, palette) -> None:
        self._load_coverage()

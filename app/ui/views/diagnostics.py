"""Diagnostics: what is working, what is not, and the fix for each."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ... import doctor
from ...services import lifecycle, maintenance
from .. import theme
from ..common import Card, button, human_bytes, label, mono_font, ui_font
from .base import View

STATUS_COLOUR = {"ok": "ok", "warn": "med", "fail": "crit"}

LOG_LINES = 400


class DiagnosticsView(View):
    title = "Diagnostics"

    def build(self) -> None:
        card = Card("Health checks")
        card.add_action(button("Run again", small=True, on_click=self.load))
        self.summary = label("", role="hint")
        card.add(self.summary)
        self._checks_host = QWidget()
        self._checks = QVBoxLayout(self._checks_host)
        self._checks.setContentsMargins(0, 0, 0, 0)
        self._checks.setSpacing(0)
        card.add(self._checks_host)
        self.add(card)

        paths = Card("Where things are")
        self.paths = label("", mono=True, size=11, wrap=True)
        self.paths.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        paths.add(self.paths)
        self.add(paths)

        upkeep = Card(
            "Upkeep",
            "Pruning drops observations past their retention window. Compacting "
            "reclaims the space they were using.",
        )
        buttons = QWidget()
        row = QHBoxLayout(buttons)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        row.addWidget(button("Prune old records", small=True, on_click=self._prune))
        row.addWidget(button("Compact the database", small=True, on_click=self._compact))
        row.addWidget(button("Reload vendor database", small=True,
                             on_click=self._reload_vendors))
        row.addStretch(1)
        upkeep.add(buttons)
        self.add(upkeep)

        log_card = Card("Log")
        log_card.add_action(button("Refresh", small=True, on_click=self._load_log))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(mono_font(11))
        self.log.setMinimumHeight(280)
        self.log.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        log_card.add(self.log)
        self.add(log_card)
        self.add_stretch()

    def load(self) -> None:
        self.run(doctor.run_all, self._apply)
        self._load_log()

    def _load_log(self) -> None:
        self.run(lambda: lifecycle.tail_log(LOG_LINES), self._apply_log)

    def _apply_log(self, text: str) -> None:
        self.log.setPlainText(text)
        self.log.verticalScrollBar().setValue(
            self.log.verticalScrollBar().maximum())

    def _apply(self, report: dict) -> None:
        palette = self.palette_colours
        while self._checks.count():
            item = self._checks.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()

        counts = report.get("summary", {})
        self.summary.setText(
            f"{counts.get('ok', 0)} passing · {counts.get('warn', 0)} warning · "
            f"{counts.get('fail', 0)} failing"
        )

        for check in report.get("checks", []):
            self._checks.addWidget(self._check_row(check, palette))

        install = report.get("install") or {}
        self.paths.setText(
            f"version    {report.get('version')}\n"
            f"data       {report.get('data_dir')}\n"
            f"database   {report.get('db_path')}\n"
            f"log        {report.get('log_path')}\n"
            f"installed  {'yes' if install.get('installed') else 'no'}"
            + (f" at {install.get('install_dir')}" if install.get("install_dir") else "")
        )

    def _check_row(self, check: dict, palette) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 7, 0, 7)
        layout.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(10)
        status = str(check.get("status") or "")
        colour = getattr(palette, STATUS_COLOUR.get(status, "dimmer"))
        badge = QLabel(status.upper())
        badge.setFont(mono_font(10))
        badge.setFixedWidth(52)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        background, border = theme.tint(palette, colour)
        badge.setStyleSheet(
            f"color: {colour}; background: {background}; border: 1px solid {border};"
            " border-radius: 3px; padding: 2px 0;"
        )
        top.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(2)
        name = QLabel(str(check.get("name") or "").replace("_", " ").capitalize())
        name.setFont(ui_font(13, QFont.Weight.DemiBold))
        name.setStyleSheet(f"color: {palette.text_hi};")
        text.addWidget(name)
        message = QLabel(str(check.get("message") or ""))
        message.setWordWrap(True)
        message.setFont(ui_font(12))
        message.setStyleSheet(f"color: {palette.text};")
        text.addWidget(message)
        if check.get("fix"):
            fix = QLabel(str(check["fix"]))
            fix.setWordWrap(True)
            fix.setFont(ui_font(12))
            fix.setStyleSheet(f"color: {palette.low};")
            text.addWidget(fix)
        top.addLayout(text, 1)
        layout.addLayout(top)

        line = QFrame()
        line.setFixedHeight(1)
        line.setStyleSheet(f"background: {palette.line_soft}; border: none;")
        layout.addWidget(line)
        return holder

    def _prune(self) -> None:
        self.run(maintenance.prune, lambda r: self.ctx.toast(
            f"Removed {r['total']} old record(s)", kind="ok"))

    def _compact(self) -> None:
        self.run(maintenance.compact, lambda r: self.ctx.toast(
            f"Reclaimed {human_bytes(r['saved'])}, now {human_bytes(r['after'])}",
            kind="ok"))

    def _reload_vendors(self) -> None:
        self.run(maintenance.reload_vendors, lambda r: self.ctx.toast(
            f"Vendor database reloaded: {r['size']} prefixes from {r['source']}",
            kind="ok"))

"""Adapter: which radio is in use, and getting it working when it is not."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from ...config import config
from ...services import adapters_svc
from .. import theme
from ..common import Card, button, label, mono_font, ui_font
from .base import View

# What each repair step's outcome is called, and how it should look.
STEP_LABEL = {
    "fixed": "fixed",
    "no_action": "ok",
    "skipped": "n/a",
    "failed": "failed",
    "needs_admin": "needs admin",
    "manual": "do this",
}

STEP_COLOUR = {
    "fixed": "ok",
    "failed": "crit",
    "needs_admin": "med",
    "manual": "low",
}

REPAIR_TICK_SECONDS = 2


class AdapterCard(QFrame):
    """One radio, with everything needed to tell it from the others."""

    chosen = Signal(str)

    def __init__(self, adapter: dict, palette, selectable: bool = True,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.adapter = adapter
        self._palette = palette
        self.guid = adapter.get("guid", "")
        self.setProperty("card", True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(10)
        self.radio = QRadioButton()
        self.radio.setVisible(selectable)
        self.radio.toggled.connect(
            lambda checked: self.chosen.emit(self.guid) if checked else None)
        head.addWidget(self.radio, 0, Qt.AlignmentFlag.AlignTop)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        name = QLabel(adapter.get("label") or adapter.get("description") or "Adapter")
        name.setFont(ui_font(14, QFont.Weight.DemiBold))
        name.setStyleSheet(f"color: {palette.text_hi}; border: none;")
        titles.addWidget(name)
        description = QLabel(adapter.get("description") or "")
        description.setFont(mono_font(11))
        description.setStyleSheet(f"color: {palette.dimmer}; border: none;")
        titles.addWidget(description)
        head.addLayout(titles, 1)

        if adapter.get("recommended"):
            tag = QLabel("recommended")
            tag.setFont(mono_font(10))
            background, border = theme.tint(palette, palette.ok)
            tag.setStyleSheet(
                f"color: {palette.ok}; background: {background};"
                f" border: 1px solid {border}; border-radius: 3px; padding: 2px 7px;"
            )
            head.addWidget(tag, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(head)

        facts = QGridLayout()
        facts.setHorizontalSpacing(20)
        facts.setVerticalSpacing(4)
        entries = [
            ("Hardware", adapter.get("usb_model") or adapter.get("chipset")),
            ("MAC", adapter.get("mac")),
            ("Bands", adapter.get("band_label")),
            ("Driver", adapter.get("driver")),
            ("State", adapter.get("state_label")),
            ("Radio", _radio_text(adapter)),
        ]
        for position, (key, value) in enumerate(entries):
            column = position % 3
            grid_row = position // 3
            holder = QVBoxLayout()
            holder.setSpacing(1)
            caption = QLabel(key.upper())
            caption.setFont(mono_font(9))
            caption.setStyleSheet(
                f"color: {palette.dimmer}; border: none; letter-spacing: 1px;")
            value_label = QLabel(str(value) if value else "—")
            value_label.setFont(mono_font(11))
            colour = palette.text
            if key == "Radio" and adapter.get("radio_on") is False:
                colour = palette.crit
            value_label.setStyleSheet(f"color: {colour}; border: none;")
            holder.addWidget(caption)
            holder.addWidget(value_label)
            facts.addLayout(holder, grid_row, column)
        layout.addLayout(facts)

        if adapter.get("band_note"):
            note = QLabel(adapter["band_note"])
            note.setWordWrap(True)
            note.setFont(ui_font(12))
            note.setStyleSheet(f"color: {palette.dim}; border: none;")
            layout.addWidget(note)

        self.set_selected(False)

    def set_selected(self, selected: bool) -> None:
        palette = self._palette
        if selected:
            self.setStyleSheet(
                f"QFrame[card='true'] {{ background: {palette.panel};"
                f" border: 1px solid {palette.b5}; border-radius: 6px; }}"
            )
        else:
            self.setStyleSheet("")
        self.radio.blockSignals(True)
        self.radio.setChecked(selected)
        self.radio.blockSignals(False)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        # setChecked emits toggled, which already emits chosen. Emitting again
        # here would select the adapter twice on every click.
        super().mousePressEvent(event)
        self.radio.setChecked(True)


def _radio_text(adapter: dict) -> str:
    state = adapter.get("radio_on")
    if state is False:
        return "off"
    if state is True:
        return "on"
    return "unknown"


class RepairPanel(QFrame):
    """Diagnosis, or the results of a repair, step by step."""

    def __init__(self, palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self.setProperty("card", True)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 12, 14, 14)
        self._layout.setSpacing(8)
        self._busy = None
        self.hide()

    def set_palette_colours(self, palette) -> None:
        self._palette = palette

    def clear(self) -> None:
        # The busy label is about to be destroyed, so drop the reference with
        # it. A stale one turns every later tick into a C++ deleted-object
        # error inside a timer slot, which nothing catches.
        self._busy = None
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def show_busy(self, message: str) -> None:
        self.clear()
        self._layout.addWidget(label("Working", role="cardTitle", size=14, bold=True))
        self._busy = label(message, role="hint", wrap=True)
        self._layout.addWidget(self._busy)
        self.show()

    def set_busy_message(self, message: str) -> None:
        if self._busy is None:
            return
        try:
            self._busy.setText(message)
        except RuntimeError:
            # The panel was re-rendered under us; nothing to update.
            self._busy = None

    def show_report(self, report: dict, diagnosis: bool,
                    on_repair=None, on_close=None) -> None:
        palette = self._palette
        self.clear()
        self._layout.addWidget(label(
            "What is wrong" if diagnosis else "Repair results",
            role="cardTitle", size=14, bold=True,
        ))
        verdict = report.get("verdict") or report.get("summary") or ""
        if verdict:
            self._layout.addWidget(label(verdict, wrap=True))

        problems = report.get("problems") or []
        if problems:
            text = "<br>".join(
                f"{p.get('model') or p.get('name')} — {p.get('problem')} "
                f"(code {p.get('code')})" for p in problems
            )
            broken = QLabel(text)
            broken.setFont(mono_font(11))
            broken.setWordWrap(True)
            broken.setStyleSheet(f"color: {palette.med}; border: none;")
            self._layout.addWidget(broken)

        for step in report.get("steps") or []:
            self._layout.addWidget(self._step_row(step))

        needs_admin = any(
            (s.get("status") == "needs_admin") for s in report.get("steps") or []
        )
        actions = QWidget()
        action_row = QHBoxLayout(actions)
        action_row.setContentsMargins(0, 6, 0, 0)
        action_row.setSpacing(8)
        if on_repair is not None:
            action_row.addWidget(button(
                "Fix it (asks for permission)" if needs_admin else
                ("Try to fix it" if diagnosis else "Run again"),
                kind="primary", small=True, on_click=on_repair,
            ))
        if on_close is not None:
            action_row.addWidget(button("Close", small=True, on_click=on_close))
        action_row.addStretch(1)
        self._layout.addWidget(actions)

        self._layout.addWidget(label(
            "Adapters are only enabled and restarted. Nothing is uninstalled or "
            "deleted, and every step reports what it did.",
            role="hint", wrap=True,
        ))
        self.show()

    def _step_row(self, step: dict) -> QWidget:
        palette = self._palette
        holder = QWidget()
        layout = QHBoxLayout(holder)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(12)

        status = str(step.get("status") or "")
        colour = getattr(palette, STEP_COLOUR.get(status, "dimmer"))
        mark = QLabel(STEP_LABEL.get(status, status))
        mark.setFont(mono_font(10))
        mark.setFixedWidth(78)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        background, border = theme.tint(palette, colour)
        mark.setStyleSheet(
            f"color: {colour}; background: {background}; border: 1px solid {border};"
            " border-radius: 3px; padding: 2px 0;"
        )
        layout.addWidget(mark, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(1)
        name = QLabel(str(step.get("name") or ""))
        name.setFont(ui_font(13, QFont.Weight.DemiBold))
        name.setStyleSheet(f"color: {palette.text_hi}; border: none;")
        text.addWidget(name)
        for extra in (step.get("message"), step.get("detail")):
            if extra:
                line = QLabel(str(extra))
                line.setWordWrap(True)
                line.setFont(ui_font(12))
                line.setStyleSheet(f"color: {palette.dim}; border: none;")
                text.addWidget(line)
        layout.addLayout(text, 1)
        return holder


class AdaptersView(View):
    title = "Adapter"

    def build(self) -> None:
        self._selected = config.get("scan", "interface_guid", default="")
        self._cards: list[AdapterCard] = []
        self._repair_seconds = 0
        # One timer for the life of the view. Creating one per repair left the
        # previous one running for the rest of the process.
        self._ticker = QTimer(self)
        self._ticker.setInterval(REPAIR_TICK_SECONDS * 1000)
        self._ticker.timeout.connect(self._tick_repair)

        card = Card(
            "Wireless adapters",
            "Nothing is scanned until you start. An external adapter with 6 GHz "
            "support and its radio on scores highest.",
        )
        card.add_action(button("Rescan", small=True, on_click=lambda: self.load(True)))
        card.add_action(button("Diagnose & repair", small=True,
                               on_click=self._diagnose))
        self._list_host = QWidget()
        self._list = QVBoxLayout(self._list_host)
        self._list.setContentsMargins(0, 0, 0, 0)
        self._list.setSpacing(10)
        card.add(self._list_host)

        self.hint = label("", role="hint", wrap=True)
        card.add(self.hint)

        actions = QWidget()
        action_row = QHBoxLayout(actions)
        action_row.setContentsMargins(0, 0, 0, 0)
        action_row.setSpacing(8)
        self.use_button = button("Use this adapter", kind="primary", on_click=self._use)
        action_row.addWidget(self.use_button)
        self.start_button = button("Start scanning", on_click=self._start)
        action_row.addWidget(self.start_button)
        action_row.addStretch(1)
        card.add(actions)
        self.add(card)

        self.repair = RepairPanel(self.palette_colours)
        self.add(self.repair)

        usb_card = Card(
            "USB wireless devices",
            "Read underneath the Wi-Fi API, so a device that is plugged in but "
            "not working still shows here.",
        )
        self.usb_text = label("", mono=True, size=11, wrap=True)
        usb_card.add(self.usb_text)
        self.add(usb_card)
        self.add_stretch()

    def load(self, refresh: bool = False) -> None:
        self.run(
            lambda: (adapters_svc.overview(refresh), _usb_summary()),
            self._apply,
        )

    def _apply(self, payload: tuple) -> None:
        overview, usb = payload
        adapters = overview["adapters"]
        self._selected = overview.get("selected") or self._selected

        while self._list.count():
            item = self._list.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        self._cards = []

        for adapter in adapters:
            card = AdapterCard(adapter, self.palette_colours)
            card.chosen.connect(self._select)
            self._list.addWidget(card)
            self._cards.append(card)
            if adapter.get("guid") == self._selected:
                card.set_selected(True)

        if not adapters:
            self.hint.setText(
                "No wireless adapters available. Checking whether one is plugged "
                "in but not working."
            )
            self._diagnose()
        elif not overview.get("has_external"):
            self.hint.setText(
                "No external adapter detected, so this will scan on the built-in "
                "radio."
            )
        else:
            self.hint.setText("")

        self._sync_buttons()
        self.usb_text.setText(_usb_text(usb))

    def _select(self, guid: str) -> None:
        self._selected = guid
        for card in self._cards:
            card.set_selected(card.guid == guid)
        self._sync_buttons()

    def _sync_buttons(self) -> None:
        adapter = next((c.adapter for c in self._cards if c.guid == self._selected), None)
        usable = bool(adapter) and adapter.get("radio_on") is not False
        self.use_button.setEnabled(bool(adapter))
        self.start_button.setEnabled(usable)

    def _use(self) -> None:
        self.run(
            lambda: adapters_svc.select(self._selected),
            lambda _: (self.ctx.toast("Adapter selected", kind="ok"),
                       self.ctx.refresh_status()),
        )

    def _start(self) -> None:
        self.run(
            lambda: adapters_svc.start_scanning(self._selected or None),
            self._started,
        )

    def _started(self, result: dict) -> None:
        adapter = result.get("adapter") or {}
        name = adapter.get("label") or adapter.get("description") or "the adapter"
        self.ctx.toast(f"Scanning started on {name}", kind="ok")
        self.ctx.refresh_status()
        self.ctx.show_view("live")

    # -- repair -------------------------------------------------------------

    def _diagnose(self) -> None:
        self.repair.show_busy("Looking at the USB device tree and the Wi-Fi service.")
        self.run(
            adapters_svc.diagnose,
            lambda report: self.repair.show_report(
                report, diagnosis=True,
                on_repair=self.run_repair, on_close=self.repair.hide,
            ),
        )

    def run_repair(self) -> None:
        if sys.platform != "win32":
            self.ctx.toast("Adapter recovery only applies on Windows.", kind="err")
            return
        self._repair_seconds = 0
        self.repair.show_busy(
            "Working through the repair steps. Device enumeration is the slow "
            "part; it will finish."
        )
        self._ticker.start()

        def done(report: dict) -> None:
            self._ticker.stop()
            self.repair.show_report(
                report, diagnosis=False,
                on_repair=self.run_repair, on_close=self.repair.hide,
            )
            if report.get("resolved"):
                self.ctx.toast("Adapter recovered", kind="ok")
                self.load(refresh=True)

        def failed(exc: Exception) -> None:
            self._ticker.stop()
            self._report_error(exc)

        self.ctx.pool.run(lambda: adapters_svc.repair(False, True), done, failed)

    def _tick_repair(self) -> None:
        self._repair_seconds += REPAIR_TICK_SECONDS
        self.repair.set_busy_message(
            f"Still working ({self._repair_seconds}s). Device enumeration is the "
            "slow part; it will finish."
        )

    def repalette(self, palette) -> None:
        self.repair.set_palette_colours(palette)


def _usb_summary() -> dict:
    try:
        return adapters_svc.usb_summary()
    except Exception as exc:
        return {"error": str(exc)}


def _usb_text(summary: dict) -> str:
    if summary.get("error"):
        return f"Could not read the USB device tree: {summary['error']}"
    lines = []
    for device in summary.get("recognised") or []:
        lines.append(str(device))
    for problem in summary.get("problems") or []:
        lines.append(
            f"{problem.get('model') or problem.get('name')} — "
            f"{problem.get('problem')} (code {problem.get('code')})"
        )
    if not lines:
        healthy = summary.get("healthy")
        if healthy:
            return f"{healthy} healthy USB wireless device(s), nothing wrong."
        return "No USB wireless devices found."
    return "\n".join(lines)

"""Settings, and the operations that cannot be undone.

The form is generated from a field list rather than hand-built, so adding a
setting to config.DEFAULTS and naming it here is all it takes to expose it.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QSpinBox,
    QWidget,
)

from ...services import maintenance, settings_svc
from ..common import Card, button, label
from .base import View

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Field:
    path: tuple[str, ...]
    text: str
    kind: str = "text"
    note: str = ""
    choices: list[str] = dc_field(default_factory=list)
    minimum: float = 0
    maximum: float = 1_000_000
    suffix: str = ""


GROUPS: list[tuple[str, str, list[Field]]] = [
    ("Scanning", "Windows rate-limits scan requests to roughly four a minute per "
     "adapter, which is why the interval has a floor.", [
        Field(("scan", "interval_seconds"), "Scan interval", "int",
              minimum=1, maximum=3600, suffix=" s"),
        Field(("scan", "min_interval_seconds"), "Minimum interval", "int",
              note="Below this the driver returns the same cached list.",
              minimum=1, maximum=3600, suffix=" s"),
        Field(("scan", "settle_seconds"), "Settle time", "float",
              note="How long to wait after asking the driver to scan before "
                   "reading the result.",
              minimum=0, maximum=30, suffix=" s"),
        Field(("scan", "autostart_on_launch"), "Start scanning on launch", "bool",
              note="Off by default. Nothing touches the radio until you press "
                   "Start."),
        Field(("scan", "warn_if_no_external_adapter"),
              "Warn when only the built-in radio is available", "bool"),
        Field(("scan", "backoff_max_seconds"), "Maximum backoff after errors", "int",
              minimum=10, maximum=3600, suffix=" s"),
    ]),
    ("Detections", "The severity floor decides what is worth recording at all. "
     "Raise it in a dense area where the inventory rules get noisy.", [
        Field(("detections", "enabled"), "Run detection rules", "bool"),
        Field(("detections", "severity_floor"), "Severity floor", "choice",
              choices=SEVERITIES),
        Field(("detections", "suppress_seconds"), "Cooldown per rule and BSSID",
              "int", minimum=0, maximum=86400, suffix=" s"),
        Field(("detections", "max_findings_per_scan"), "Findings kept per scan",
              "int", minimum=1, maximum=5000),
        Field(("detections", "levenshtein_threshold"),
              "Lookalike name edit distance", "int", minimum=1, maximum=6,
              note="How many character edits still count as an impersonation of "
                   "a trusted name."),
        Field(("detections", "rssi_jump_db"), "Signal jump that counts as an anomaly",
              "int", minimum=5, maximum=60, suffix=" dB"),
        Field(("detections", "min_observations_for_baseline"),
              "Observations before a baseline exists", "int", minimum=1, maximum=100),
        Field(("detections", "missing_scans_before_alert"),
              "Missed scans before a watched AP is reported gone", "int",
              minimum=1, maximum=100),
        Field(("detections", "congestion_utilization_pct"),
              "Channel utilisation that counts as congested", "int",
              minimum=1, maximum=100, suffix=" %"),
        Field(("detections", "max_ssids_per_bssid"),
              "Names one radio may serve before it is suspicious", "int",
              minimum=1, maximum=32),
    ]),
    ("Windows notifications", "", [
        Field(("alerts", "toast", "enabled"), "Show toast notifications", "bool"),
        Field(("alerts", "toast", "min_severity"), "Minimum severity", "choice",
              choices=SEVERITIES),
        Field(("alerts", "eventlog", "enabled"), "Write to the Windows event log",
              "bool"),
        Field(("alerts", "eventlog", "min_severity"), "Minimum severity", "choice",
              choices=SEVERITIES),
    ]),
    ("Webhook", "The payload has a text field that Slack and Teams incoming "
     "webhooks render directly.", [
        Field(("alerts", "webhook", "enabled"), "Post findings to a webhook", "bool"),
        Field(("alerts", "webhook", "url"), "URL", "text"),
        Field(("alerts", "webhook", "min_severity"), "Minimum severity", "choice",
              choices=SEVERITIES),
        Field(("alerts", "webhook", "timeout"), "Timeout", "int",
              minimum=1, maximum=120, suffix=" s"),
    ]),
    ("Syslog", "CEF is the one to use for Splunk or Wazuh.", [
        Field(("alerts", "syslog", "enabled"), "Forward findings to syslog", "bool"),
        Field(("alerts", "syslog", "host"), "Collector host", "text"),
        Field(("alerts", "syslog", "port"), "Port", "int", minimum=1, maximum=65535),
        Field(("alerts", "syslog", "protocol"), "Protocol", "choice",
              choices=["udp", "tcp"]),
        Field(("alerts", "syslog", "format"), "Format", "choice",
              choices=["cef", "json", "rfc5424"]),
        Field(("alerts", "syslog", "min_severity"), "Minimum severity", "choice",
              choices=SEVERITIES),
    ]),
    ("GPS", "With a serial NMEA receiver every observation gets a coordinate, "
     "which is what makes the WiGLE and KML exports useful.", [
        Field(("gps", "enabled"), "Read a GPS receiver", "bool"),
        Field(("gps", "port"), "Serial port", "text", note="For example COM5."),
        Field(("gps", "baud"), "Baud rate", "int", minimum=1200, maximum=921600),
        Field(("gps", "stale_seconds"), "Treat a fix as stale after", "int",
              minimum=1, maximum=600, suffix=" s"),
    ]),
    ("Retention", "", [
        Field(("retention", "observation_days"), "Keep observations for", "int",
              minimum=1, maximum=3650, suffix=" days"),
        Field(("retention", "alert_days"), "Keep findings for", "int",
              minimum=1, maximum=3650, suffix=" days"),
        Field(("retention", "gps_days"), "Keep GPS fixes for", "int",
              minimum=1, maximum=3650, suffix=" days"),
        Field(("retention", "prune_interval_minutes"), "Prune every", "int",
              minimum=1, maximum=10080, suffix=" min"),
        Field(("retention", "max_db_mb"), "Warn when the database passes", "int",
              minimum=16, maximum=1_000_000, suffix=" MB"),
    ]),
    ("Remote access", "Off by default and bound to loopback. Turning this on "
     "binds every interface and requires a token on every request. There is no "
     "TLS and no user accounts, so put it behind something else if it needs to "
     "be exposed.", [
        Field(("server", "allow_lan"), "Reachable from other machines", "bool"),
        Field(("server", "host"), "Bind address", "text",
              note="Takes effect the next time the app starts."),
        Field(("server", "port"), "Port", "int", minimum=1, maximum=65535,
              note="Takes effect the next time the app starts."),
        Field(("server", "api_token"), "API token", "text",
              note="Generated automatically when remote access is switched on."),
    ]),
    ("Interface", "", [
        Field(("ui", "theme"), "Theme", "choice", choices=["dark", "light"]),
        Field(("ui", "default_tab"), "Open on", "choice",
              choices=["live", "spectrum", "findings", "ssids", "adapters",
                       "diagnostics"]),
        Field(("ui", "rssi_floor"), "Signal floor for bars and charts", "int",
              minimum=-120, maximum=-40, suffix=" dBm"),
    ]),
    ("Updates", "", [
        Field(("updates", "check_on_start"), "Check for updates on launch", "bool"),
        Field(("updates", "check_interval_hours"), "Check every", "int",
              minimum=1, maximum=720, suffix=" h"),
    ]),
]


class SettingsView(View):
    title = "Settings"

    def build(self) -> None:
        self._widgets: dict[tuple[str, ...], QWidget] = {}
        self._loading = False

        for title, hint, fields in GROUPS:
            card = Card(title, hint)
            form = QFormLayout()
            form.setContentsMargins(0, 4, 0, 0)
            form.setSpacing(8)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight
                                   | Qt.AlignmentFlag.AlignVCenter)
            form.setFieldGrowthPolicy(
                QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            for spec in fields:
                widget = self._make_widget(spec)
                self._widgets[spec.path] = widget
                form.addRow(spec.text, widget)
                if spec.note:
                    # Its own spanning row. Nested inside the field's cell a
                    # wrapping label does not get the height it asks for, and
                    # the text lands on top of the control above it.
                    note = label(spec.note, role="hint", size=11, wrap=True)
                    note.setContentsMargins(0, 0, 0, 6)
                    form.addRow("", note)
            card.add_layout(form)

            if title == "Windows notifications":
                card.add(self._test_row("toast"))
            elif title == "Webhook":
                card.add(self._test_row("webhook"))
            elif title == "Syslog":
                card.add(self._test_row("syslog"))
            self.add(card)

        actions = Card("Saving")
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(8)
        row_layout.addWidget(button("Save settings", kind="primary", on_click=self._save))
        row_layout.addWidget(button("Reload", on_click=self.load))
        row_layout.addWidget(button("Reset to defaults", kind="danger",
                                    on_click=self._reset))
        row_layout.addStretch(1)
        actions.add(row)
        self.add(actions)

        danger = Card(
            "Data",
            "Neither of these can be undone. Clearing keeps your marks, sites and "
            "inventory unless you say otherwise; wiping does not.",
        )
        danger_row = QWidget()
        danger_layout = QHBoxLayout(danger_row)
        danger_layout.setContentsMargins(0, 0, 0, 0)
        danger_layout.setSpacing(8)
        danger_layout.addWidget(button("Clear observed networks", kind="danger",
                                       on_click=self._clear_networks))
        danger_layout.addWidget(button("Wipe everything", kind="danger",
                                       on_click=self._wipe))
        danger_layout.addStretch(1)
        danger.add(danger_row)
        self.add(danger)
        self.add_stretch()

    def _test_row(self, sink: str) -> QWidget:
        holder = QWidget()
        layout = QHBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(button(
            f"Send a test {sink} finding", small=True,
            on_click=lambda: self._test(sink)))
        layout.addStretch(1)
        return holder

    def _make_widget(self, spec: Field) -> QWidget:
        if spec.kind == "bool":
            widget = QCheckBox()
        elif spec.kind == "choice":
            widget = QComboBox()
            widget.addItems(spec.choices)
        elif spec.kind == "int":
            widget = QSpinBox()
            widget.setRange(int(spec.minimum), int(spec.maximum))
            widget.setSuffix(spec.suffix)
            widget.setFixedWidth(180)
        elif spec.kind == "float":
            widget = QDoubleSpinBox()
            widget.setRange(spec.minimum, spec.maximum)
            widget.setSingleStep(0.5)
            widget.setSuffix(spec.suffix)
            widget.setFixedWidth(180)
        else:
            widget = QLineEdit()
        return widget

    # -- load and save ------------------------------------------------------

    def load(self) -> None:
        self.run(lambda: settings_svc.current(mask_token=False), self._apply)

    def _apply(self, settings: dict) -> None:
        self._loading = True
        for path, widget in self._widgets.items():
            value = settings
            for key in path:
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(key)
            self._set_widget(widget, value)
        self._loading = False

    def _set_widget(self, widget: QWidget, value: Any) -> None:
        if isinstance(widget, QCheckBox):
            widget.setChecked(bool(value))
        elif isinstance(widget, QComboBox):
            index = widget.findText(str(value))
            widget.setCurrentIndex(max(0, index))
        elif isinstance(widget, QSpinBox):
            widget.setValue(int(value or 0))
        elif isinstance(widget, QDoubleSpinBox):
            widget.setValue(float(value or 0))
        elif isinstance(widget, QLineEdit):
            widget.setText("" if value is None else str(value))

    def _read_widget(self, widget: QWidget) -> Any:
        if isinstance(widget, QCheckBox):
            return widget.isChecked()
        if isinstance(widget, QComboBox):
            return widget.currentText()
        if isinstance(widget, QSpinBox):
            return widget.value()
        if isinstance(widget, QDoubleSpinBox):
            return widget.value()
        if isinstance(widget, QLineEdit):
            return widget.text().strip()
        return None

    def _save(self) -> None:
        patch: dict = {}
        for path, widget in self._widgets.items():
            node = patch
            for key in path[:-1]:
                node = node.setdefault(key, {})
            node[path[-1]] = self._read_widget(widget)
        self.run(lambda: settings_svc.update(patch, mask_token=False), self._saved)

    def _saved(self, settings: dict) -> None:
        self.ctx.toast(
            "Settings saved. The bind address and port take effect next launch.",
            kind="ok",
        )
        self._apply(settings)
        self.ctx.refresh_status()

    def _reset(self) -> None:
        if not self.ctx.confirm(
            "Put every setting back to its default? Your data is not touched.",
            destructive=True,
        ):
            return
        self.run(lambda: settings_svc.reset(mask_token=False), self._saved)

    def _test(self, sink: str) -> None:
        from ... import alerts as alert_module

        self.run(
            lambda: alert_module.dispatcher.test(sink),
            lambda result: self.ctx.toast(
                result.get("message") or f"Test {sink} sent",
                kind="ok" if result.get("ok") else "err",
            ),
        )

    # -- destructive --------------------------------------------------------

    def _clear_networks(self) -> None:
        if not self.ctx.confirm(
            "Forget every observed network and its history? Marks, sites and "
            "inventory are kept. This cannot be undone.",
            destructive=True,
        ):
            return
        self.run(
            lambda: maintenance.clear_networks(maintenance.CONFIRM_CLEAR),
            lambda r: (self.ctx.toast(r["message"], kind="ok"),
                       self.ctx.refresh_status()),
        )

    def _wipe(self) -> None:
        typed = self.ctx.ask_text(
            "Wipe everything",
            f'Every network, finding, mark, site, survey and device record is '
            f'deleted.\n\nType {maintenance.CONFIRM_WIPE} to confirm.',
            "",
        )
        if typed != maintenance.CONFIRM_WIPE:
            if typed is not None:
                self.ctx.toast("That did not match, so nothing was deleted.")
            return
        self.run(
            lambda: maintenance.wipe(maintenance.CONFIRM_WIPE),
            lambda r: (self.ctx.toast(r["message"], kind="ok"),
                       self.ctx.refresh_status()),
        )

"""My network: joining one, sharing one, and auditing what is on it.

Everything on this screen is active. Joining a network associates with it,
and the audit connects to hosts and checks ports. Neither happens without an
explicit press, and the audit asks for a typed confirmation first.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QWidget,
)

from ...services import devices_svc
from ..common import Card, button, label
from ..models import Column, DictTableModel
from .base import View

DEFAULT_PORTS = "22, 80, 443, 445, 3389, 8080, 8443"

SECURITIES = ["WPA2PSK", "WPA3SAE", "open"]


class NetworkView(View):
    title = "My network"

    def build(self) -> None:
        state = Card("Connection")
        state.add_action(button("Refresh", small=True, on_click=self.load))
        self.state_text = label("Reading the current connection…", mono=True, size=11,
                                wrap=True)
        state.add(self.state_text)
        self.add(state)

        join = Card(
            "Join a network",
            "Creates a profile and associates with the selected network.",
        )
        form = QWidget()
        grid = QGridLayout(form)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        self.ssid = QLineEdit()
        self.ssid.setPlaceholderText("Network name")
        self.passphrase = QLineEdit()
        self.passphrase.setPlaceholderText("Passphrase (leave blank for open)")
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.security = QComboBox()
        self.security.addItems(SECURITIES)

        grid.addWidget(label("Name"), 0, 0)
        grid.addWidget(self.ssid, 0, 1)
        grid.addWidget(label("Passphrase"), 0, 2)
        grid.addWidget(self.passphrase, 0, 3)
        grid.addWidget(label("Security"), 0, 4)
        grid.addWidget(self.security, 0, 5)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        join.add(form)

        join_actions = QWidget()
        join_row = QHBoxLayout(join_actions)
        join_row.setContentsMargins(0, 0, 0, 0)
        join_row.setSpacing(8)
        join_row.addWidget(button("Join", kind="primary", on_click=self._join))
        join_row.addWidget(button("Disconnect", on_click=self._disconnect))
        join_row.addStretch(1)
        join.add(join_actions)
        self.add(join)

        audit = Card(
            "Audit this network",
            "Discovers hosts on the subnet you are joined to and checks the "
            "listed ports on each. This connects to other people's machines, so "
            "only run it on a network you are responsible for.",
        )
        audit_form = QWidget()
        audit_grid = QGridLayout(audit_form)
        audit_grid.setContentsMargins(0, 0, 0, 0)
        audit_grid.setHorizontalSpacing(8)
        self.ports = QLineEdit(DEFAULT_PORTS)
        audit_grid.addWidget(label("Ports"), 0, 0)
        audit_grid.addWidget(self.ports, 0, 1)
        audit_grid.setColumnStretch(1, 1)
        audit.add(audit_form)

        self.audit_button = button("Run audit", kind="danger", on_click=self._audit)
        audit_actions = QWidget()
        audit_row = QHBoxLayout(audit_actions)
        audit_row.setContentsMargins(0, 0, 0, 0)
        audit_row.addWidget(self.audit_button)
        audit_row.addStretch(1)
        audit.add(audit_actions)

        self.audit_model = DictTableModel([
            Column("ip", "Host", width=150, mono=True),
            Column("hostname", "Name", stretch=True, format=lambda v, r: v or ""),
            # netaudit puts the port numbers here and the service dicts under
            # "services", so this column is a list of ints.
            Column("open_ports", "Open ports", width=240,
                   format=lambda v, r: ", ".join(str(p) for p in (v or []))
                   or "none responded"),
            Column("category", "Kind", width=130, format=lambda v, r: v or ""),
        ])
        self.audit_table, _ = self.make_table(self.audit_model, sort_column=0,
                                              sort_order=Qt.SortOrder.AscendingOrder)
        self.audit_table.setMinimumHeight(260)
        self.audit_table.hide()
        audit.add(self.audit_table)
        self.audit_findings = label("", role="hint", wrap=True)
        audit.add(self.audit_findings)
        self.add(audit)

        hotspot = Card(
            "Mobile hotspot",
            "Shares this machine's connection over Wi-Fi. Untested on real "
            "hardware, so treat a failure here as expected rather than broken.",
        )
        hotspot_form = QWidget()
        hotspot_grid = QGridLayout(hotspot_form)
        hotspot_grid.setContentsMargins(0, 0, 0, 0)
        hotspot_grid.setHorizontalSpacing(8)
        self.hotspot_ssid = QLineEdit()
        self.hotspot_ssid.setPlaceholderText("Hotspot name")
        self.hotspot_pass = QLineEdit()
        self.hotspot_pass.setPlaceholderText("Passphrase, 8 to 63 characters")
        self.hotspot_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.hotspot_band = QComboBox()
        self.hotspot_band.addItems(["auto", "2.4", "5"])
        hotspot_grid.addWidget(label("Name"), 0, 0)
        hotspot_grid.addWidget(self.hotspot_ssid, 0, 1)
        hotspot_grid.addWidget(label("Passphrase"), 0, 2)
        hotspot_grid.addWidget(self.hotspot_pass, 0, 3)
        hotspot_grid.addWidget(label("Band"), 0, 4)
        hotspot_grid.addWidget(self.hotspot_band, 0, 5)
        hotspot_grid.setColumnStretch(1, 1)
        hotspot_grid.setColumnStretch(3, 1)
        hotspot.add(hotspot_form)

        hotspot_actions = QWidget()
        hotspot_row = QHBoxLayout(hotspot_actions)
        hotspot_row.setContentsMargins(0, 0, 0, 0)
        hotspot_row.setSpacing(8)
        hotspot_row.addWidget(button("Apply settings", on_click=self._configure_hotspot))
        hotspot_row.addWidget(button("Start", kind="primary",
                                     on_click=self._start_hotspot))
        hotspot_row.addWidget(button("Stop", on_click=self._stop_hotspot))
        hotspot_row.addStretch(1)
        hotspot.add(hotspot_actions)
        self.hotspot_state = label("", mono=True, size=11, wrap=True)
        hotspot.add(self.hotspot_state)
        self.add(hotspot)
        self.add_stretch()

    def load(self) -> None:
        self.run(
            lambda: (devices_svc.connection_state(), _hotspot_status()),
            self._apply,
        )

    def _apply(self, payload: tuple) -> None:
        state, hotspot = payload
        connection = state.get("connection") or {}
        if connection.get("ssid"):
            lines = [
                f"joined      {connection.get('ssid')}",
                f"signal      {connection.get('signal') or '—'}",
                f"security    {connection.get('security') or '—'}",
                f"channel     {connection.get('channel') or '—'}",
                f"gateway     {state.get('gateway') or '—'}",
            ]
        else:
            # Not associated is not a fault, so it must not read like one.
            lines = ["not joined to a network",
                     f"gateway     {state.get('gateway') or '—'}"]
        for subnet in state.get("subnets") or []:
            lines.append(f"subnet      {subnet.get('network') or subnet.get('ip')}")
        self.state_text.setText("\n".join(lines))

        if hotspot.get("error"):
            self.hotspot_state.setText(hotspot["error"])
        else:
            current = hotspot.get("hotspot") or {}
            self.hotspot_state.setText(
                f"state       {current.get('state') or 'unknown'}\n"
                f"name        {current.get('ssid') or '—'}\n"
                + "\n".join(f"note        {a}" for a in hotspot.get("advice") or [])
            )

    # -- actions ------------------------------------------------------------

    def _join(self) -> None:
        ssid = self.ssid.text().strip()
        if not self.ctx.confirm(
            f"Join {ssid}? This associates with the network and transmits."
        ):
            return
        self.run(
            lambda: devices_svc.connect(ssid, self.passphrase.text() or None,
                                        self.security.currentText()),
            lambda r: (self.ctx.toast(f"Joined {ssid}", kind="ok"), self.load()),
        )

    def _disconnect(self) -> None:
        self.run(devices_svc.disconnect,
                 lambda r: (self.ctx.toast("Left the network", kind="ok"), self.load()))

    def _audit(self) -> None:
        typed = self.ctx.ask_text(
            "Run audit",
            "This connects to hosts on the network you are joined to and checks "
            f"their ports.\n\nType {devices_svc.CONFIRM_AUDIT} to confirm.",
            "",
        )
        if typed != devices_svc.CONFIRM_AUDIT:
            if typed is not None:
                self.ctx.toast("That did not match, so nothing was scanned.")
            return

        ports = [int(p) for p in self.ports.text().replace(",", " ").split() if p.isdigit()]
        self.audit_button.setEnabled(False)
        self.audit_button.setText("Auditing…")

        def done(result: dict) -> None:
            self.audit_button.setEnabled(True)
            self.audit_button.setText("Run audit")
            hosts = result.get("hosts") or []
            self.audit_model.set_rows(hosts)
            self.audit_table.setVisible(bool(hosts))
            findings = result.get("findings") or []
            self.audit_findings.setText(
                "\n".join(f"· {f.get('title') or f}" for f in findings)
                or "Nothing notable found."
            )
            self.ctx.toast(f"Checked {len(hosts)} host(s)", kind="ok")

        def failed(exc: Exception) -> None:
            self.audit_button.setEnabled(True)
            self.audit_button.setText("Run audit")
            self._report_error(exc)

        self.ctx.pool.run(
            lambda: devices_svc.audit(devices_svc.CONFIRM_AUDIT, ports), done, failed
        )

    def _configure_hotspot(self) -> None:
        self.run(
            lambda: devices_svc.configure_hotspot(
                self.hotspot_ssid.text(), self.hotspot_pass.text(),
                self.hotspot_band.currentText()),
            lambda r: (self.ctx.toast("Hotspot settings applied", kind="ok"),
                       self.load()),
        )

    def _start_hotspot(self) -> None:
        self.run(devices_svc.start_hotspot,
                 lambda r: (self.ctx.toast("Hotspot started", kind="ok"), self.load()))

    def _stop_hotspot(self) -> None:
        self.run(devices_svc.stop_hotspot,
                 lambda r: (self.ctx.toast("Hotspot stopped", kind="ok"), self.load()))


def _hotspot_status() -> dict:
    try:
        return devices_svc.hotspot_status()
    except Exception as exc:
        return {"error": f"The hotspot could not be read: {exc}"}

"""Devices: what else is on the network this machine is joined to.

Nothing on this screen uses the survey adapter, and nothing on it is passive.
Discovery sends mDNS, SSDP and NetBIOS queries over whichever network this
machine is joined to, so it needs a connection and it is visible on that
network. The wireless survey is Live and Spectrum, and that one needs no
connection at all.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QWidget

from ...services import devices_svc
from ..common import Card, ago, button, label
from ..delegates import TextDelegate
from ..models import Column, DictTableModel
from .base import View

EMPTY_MESSAGE = (
    "No devices recorded yet. Press Discover while this machine is joined to a "
    "network. This is separate from the wireless survey — Live and Spectrum "
    "listen on the adapter and need no connection."
)

NOT_JOINED_MESSAGE = (
    "Discovery needs this machine to be joined to a network, and it is not. "
    "The wireless survey does not: Live and Spectrum work unconnected."
)


def _sources(value: Any, row: dict) -> str:
    detail = row.get("detail")
    sources = detail.get("sources") if isinstance(detail, dict) else None
    return ", ".join(sources) if sources else ""


def _name(value: Any, row: dict) -> str:
    """A name, or nothing. Repeating the address in the name column is noise."""
    name = value or row.get("label") or ""
    return "" if name == row.get("ip") else str(name)


def _kind(value: Any, row: dict) -> str:
    return row.get("infrastructure") or value or ""


class DevicesView(View):
    title = "Devices"

    def build(self) -> None:
        card = Card(
            "Local network devices",
            "Active discovery over the network this machine is joined to. It "
            "sends queries and is visible to anything listening, so it only "
            "runs when you press the button. The wireless survey is a different "
            "thing entirely — Live and Spectrum listen on the adapter and need "
            "no network connection.",
        )

        toolbar = QWidget()
        bar = QHBoxLayout(toolbar)
        bar.setContentsMargins(0, 0, 0, 0)
        bar.setSpacing(10)
        self.mdns = QCheckBox("mDNS")
        self.ssdp = QCheckBox("SSDP")
        self.netbios = QCheckBox("NetBIOS")
        self.bluetooth = QCheckBox("Bluetooth")
        self.names = QCheckBox("Resolve names")
        for box in (self.mdns, self.ssdp, self.netbios, self.bluetooth, self.names):
            box.setChecked(True)
            bar.addWidget(box)
        self.infrastructure = QCheckBox("Show broadcast and multicast")
        self.infrastructure.setToolTip(
            "Broadcast, multicast and network addresses answer on a network "
            "without being hosts on it. Hidden by default."
        )
        bar.addWidget(self.infrastructure)
        bar.addStretch(1)
        self.count = label("", role="dimmer", mono=True, size=11)
        bar.addWidget(self.count)
        self.discover_button = button("Discover", kind="primary",
                                      on_click=self._discover)
        bar.addWidget(self.discover_button)
        bar.addWidget(button("Forget all", small=True, kind="danger",
                             on_click=self._forget))
        card.add(toolbar)

        self.model = DictTableModel([
            Column("ip", "Address", width=150, mono=True,
                   sort=lambda r: _ip_key(r.get("ip"))),
            Column("hostname", "Name", width=260, format=_name),
            Column("mac", "MAC", width=160, mono=True, format=lambda v, r: v or ""),
            Column("vendor", "Vendor", width=200, format=lambda v, r: v or ""),
            Column("category", "Kind", width=150, format=_kind),
            Column("detail", "Seen by", width=190, format=_sources),
            Column("notes", "Notes", stretch=True, format=lambda v, r: v or ""),
            Column("last_seen", "Seen", width=100, format=lambda v, r: ago(v),
                   align=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
        ])
        self.table, self.proxy = self.make_table(self.model, sort_column=0,
                                                 sort_order=Qt.SortOrder.AscendingOrder)
        self.set_column_delegate(self.table, 3,
                                 TextDelegate(self.palette_colours, dim=True))
        self.set_column_delegate(self.table, 5,
                                 TextDelegate(self.palette_colours, mono=True, dim=True))
        self.table.setMinimumHeight(420)
        card.add(self.table, 1)

        self.empty = label(EMPTY_MESSAGE, role="hint", wrap=True)
        self.empty.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.empty.hide()
        card.add(self.empty, 1)
        self.add(card, 1)

        self.infrastructure.toggled.connect(lambda _: self.load())

    def load(self) -> None:
        show_all = self.infrastructure.isChecked()
        self.run(
            lambda: devices_svc.listing(include_infrastructure=show_all),
            self._apply,
        )

    def _apply(self, rows: list[dict]) -> None:
        self.model.set_rows(rows)
        hosts = sum(1 for r in rows if not r.get("infrastructure"))
        self.count.setText(
            f"{hosts} host(s)" + (f", {len(rows) - hosts} infrastructure"
                                  if len(rows) != hosts else "")
        )
        self.empty.setVisible(not rows)
        self.table.setVisible(bool(rows))
        if not rows:
            self.empty.setText(EMPTY_MESSAGE)

    def _discover(self) -> None:
        if not self.ctx.confirm(
            "Discovery sends mDNS, SSDP and NetBIOS queries across the network "
            "this machine is joined to, so it is visible to anything listening.\n\n"
            "This does not use the survey adapter and is not part of the wireless "
            "scan. Go ahead?",
            title="Discover devices",
        ):
            return

        self.discover_button.setEnabled(False)
        self.discover_button.setText("Discovering…")

        def done(result: dict) -> None:
            self.discover_button.setEnabled(True)
            self.discover_button.setText("Discover")
            found = result.get("devices") or []
            hosts = [d for d in found
                     if not devices_svc.infrastructure_kind(d)]
            errors = result.get("errors") or []
            if not found:
                self.empty.setText(NOT_JOINED_MESSAGE)
            self.ctx.toast(
                f"Found {len(hosts)} host(s)"
                + (f", {len(found) - len(hosts)} infrastructure addresses"
                   if len(found) != len(hosts) else "")
                + (f". {len(errors)} source(s) failed." if errors else ""),
                kind="ok" if hosts else "",
            )
            self.load()

        def failed(exc: Exception) -> None:
            self.discover_button.setEnabled(True)
            self.discover_button.setText("Discover")
            self._report_error(exc)

        self.ctx.pool.run(
            lambda: devices_svc.discover(
                include_mdns=self.mdns.isChecked(),
                include_ssdp=self.ssdp.isChecked(),
                include_netbios=self.netbios.isChecked(),
                include_bluetooth=self.bluetooth.isChecked(),
                resolve_hostnames=self.names.isChecked(),
            ),
            done, failed,
        )

    def _forget(self) -> None:
        if not self.ctx.confirm("Forget every recorded device?", destructive=True):
            return
        self.run(lambda: devices_svc.forget(None),
                 lambda count: (self.ctx.toast(f"Forgot {count} device(s)", kind="ok"),
                                self.load()))


def _ip_key(ip: Any) -> tuple:
    """Sort addresses numerically, so .9 comes before .10."""
    try:
        return tuple(int(part) for part in str(ip).split("."))
    except (TypeError, ValueError):
        return (999, 999, 999, 999)

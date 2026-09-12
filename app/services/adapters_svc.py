"""Choosing, checking and repairing the wireless adapter."""

from __future__ import annotations

import sys
from typing import Any

from .. import adapter_probe, recovery, runtime, scanner
from ..config import config
from .errors import ServiceError


def overview(refresh: bool = False) -> dict[str, Any]:
    """Every wireless adapter with enough detail to tell them apart.

    `refresh` bypasses the short cache, which is what the Rescan button wants.
    Without it repeated presses would return the same cached answer.
    """
    found = scanner.engine.list_interfaces(refresh)
    return {
        "adapters": found,
        "probe": adapter_probe.status(),
        "selected": config.get("scan", "interface_guid", default=""),
        "active": scanner.engine.current_adapter(),
        "has_external": any(a.get("external") for a in found),
        "count": len(found),
    }


def select(guid: str) -> dict[str, Any]:
    """Remember which adapter to scan with.

    Checked before it is stored, so the message names the real problem rather
    than leaving the engine to fail later with something vaguer.
    """
    guid = str(guid or "").strip()
    if guid:
        found = scanner.engine.list_interfaces()
        match = next((a for a in found if a["guid"].lower() == guid.lower()), None)
        if not match:
            raise ServiceError(
                "That adapter is not present. Unplug and replug it, then refresh."
            )
        if match.get("radio_on") is False:
            name = match.get("label") or match["description"]
            raise ServiceError(
                f"The radio on {name} is off. Turn Wi-Fi on, or check for a "
                "hardware switch on the adapter."
            )
    config.set(guid, "scan", "interface_guid")
    if config.get("scan", "enabled", default=False):
        scanner.engine.scan_now()
    return {"guid": guid, "adapters": scanner.engine.list_interfaces()}


def diagnose() -> dict[str, Any]:
    """Read-only check of why an adapter is not available, and what would help."""
    return recovery.diagnose()


def repair(dry_run: bool = False, elevate: bool = True) -> dict[str, Any]:
    """Work through the repair sequence. Changes device state, never automatic.

    The privileged steps run in a short-lived helper rather than restarting
    the whole application, which would lose the session.
    """
    if sys.platform != "win32":
        raise ServiceError("Adapter recovery only applies on Windows.")

    if dry_run:
        return recovery.repair(True)

    if elevate and not runtime.is_admin():
        outcome = recovery.repair_elevated()
        # A repair can change which adapters exist, so drop any cached view.
        scanner.engine.forget_adapters()
        if not outcome.get("ok"):
            raise ServiceError(outcome.get("error") or "The repair helper did not finish.")
        report = dict(outcome["report"])
        report["elevated_helper"] = outcome.get("elevated", False)
        return report

    result = recovery.repair(False)
    scanner.engine.forget_adapters()
    return result


def usb_summary() -> dict[str, Any]:
    from .. import usbwifi

    return usbwifi.summarise()


def start_scanning(guid: str | None = None) -> dict[str, Any]:
    result = scanner.engine.begin(guid)
    if not result.get("ok"):
        raise ServiceError(result.get("error") or "Scanning could not be started.")
    return result


def stop_scanning() -> dict[str, Any]:
    return scanner.engine.halt()

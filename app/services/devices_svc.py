"""Local network discovery and the connect/hotspot/audit operations.

Everything here reaches out to the network the machine is joined to, rather
than listening passively, so each one is explicit and none of them run on
their own.
"""

from __future__ import annotations

import logging
from typing import Any

from .. import db, netaudit
from .. import devices as device_module
from .. import hotspot as hotspot_module
from ..config import config
from . import decode
from .errors import ServiceError

log = logging.getLogger(__name__)

CONFIRM_AUDIT = "audit"

# Bounds, so a typo in a form cannot start a scan that runs for an hour.
DISCOVERY_TIMEOUT = (1.0, 15.0)
PORT_TIMEOUT = (0.2, 3.0)
MAX_HOSTS = (1, 512)
MAX_PORTS = 64


def _clamp(value: Any, bounds: tuple[float, float], fallback: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return max(bounds[0], min(bounds[1], number))


# Addresses that answer on a network without being a device on it. They arrive
# from the ARP table and from every multicast discovery protocol, and listing
# them as devices makes a quiet network look busy and hides the real hosts.
MULTICAST_FIRST_OCTET = range(224, 240)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def infrastructure_kind(row: dict) -> str | None:
    """Why this address is not a device, or None if it is one."""
    ip = str(row.get("ip") or "")
    mac = str(row.get("mac") or "").lower()
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    octets = [int(p) for p in parts]

    if ip == "255.255.255.255":
        return "broadcast"
    if octets[0] in MULTICAST_FIRST_OCTET:
        return "multicast"
    if mac == BROADCAST_MAC:
        # A /24 broadcast address resolves to the broadcast MAC. It is not a
        # host, whatever the ARP table implies.
        return "broadcast"
    if octets[3] == 0:
        return "network address"
    return None


def listing(site_id: int | None = None, minutes: float | None = None,
            include_infrastructure: bool = False) -> list[dict]:
    if site_id is None:
        site_id = config.get("site", "active_id", default=None)
    rows = decode.device_rows(db.list_devices(site_id, minutes))
    for row in rows:
        row["infrastructure"] = infrastructure_kind(row)
    if include_infrastructure:
        return rows
    return [row for row in rows if not row["infrastructure"]]


def discover(timeout: float = 4.0, **sources: bool) -> dict[str, Any]:
    result = device_module.discover(
        timeout=_clamp(timeout, DISCOVERY_TIMEOUT, 4.0), **sources
    )
    site_id = config.get("site", "active_id", default=None)
    try:
        db.record_devices(result.get("devices", []), site_id)
    except Exception:
        # A completed discovery is worth more than a tidy database.
        log.warning("Could not record discovered devices", exc_info=True)
    return result


def set_note(ip: str, mac: str, note: str) -> None:
    db.set_device_note(ip, mac or "", str(note or "")[:2000])


def forget(older_than_days: float | None = None) -> int:
    return db.forget_devices(older_than_days)


# -- the network this machine is joined to ---------------------------------


def connection_state() -> dict[str, Any]:
    return {
        "connection": netaudit.current_connection(),
        "profiles": netaudit.saved_profiles(),
        "subnets": netaudit.local_subnets(),
        "gateway": netaudit.gateway(),
    }


def connect(ssid: str, passphrase: str | None = None,
            security: str = "WPA2PSK") -> dict[str, Any]:
    ssid = str(ssid or "").strip()
    if not ssid:
        raise ServiceError("Give the network name to join")
    if passphrase is not None and passphrase != "" and not 8 <= len(passphrase) <= 63:
        raise ServiceError("The passphrase must be between 8 and 63 characters")
    if passphrase:
        created = netaudit.create_profile(ssid, passphrase, security)
        if not created.get("ok"):
            raise ServiceError(created.get("error") or
                               "The network profile could not be created.")
    result = netaudit.connect(ssid)
    if not result.get("ok"):
        raise ServiceError(result.get("error") or f"Could not join {ssid}.")
    return result


def disconnect() -> dict[str, Any]:
    return netaudit.disconnect()


def audit(confirm: str, ports: list[int] | None = None, timeout: float = 0.8,
          max_hosts: int = 128, discovery_timeout: float = 4.0) -> dict[str, Any]:
    """Discover what is on the joined network, then check each host's services."""
    if confirm != CONFIRM_AUDIT:
        raise ServiceError(
            f'Confirm with "{CONFIRM_AUDIT}". This connects to hosts on the '
            "network you are joined to."
        )
    if ports:
        try:
            ports = [int(p) for p in ports][:MAX_PORTS]
        except (TypeError, ValueError):
            raise ServiceError("Ports must be numbers") from None
        if any(p < 1 or p > 65535 for p in ports):
            raise ServiceError("Ports must be between 1 and 65535")

    result = netaudit.audit(
        ports=ports or None,
        timeout=_clamp(timeout, PORT_TIMEOUT, 0.8),
        max_hosts=int(_clamp(max_hosts, MAX_HOSTS, 128)),
        discovery_timeout=_clamp(discovery_timeout, DISCOVERY_TIMEOUT, 4.0),
    )
    site_id = config.get("site", "active_id", default=None)
    if result.get("hosts"):
        try:
            db.record_devices(result["hosts"], site_id)
        except Exception:
            log.warning("Could not record audited hosts", exc_info=True)
    return result


# -- hotspot ----------------------------------------------------------------


def hotspot_status() -> dict[str, Any]:
    return hotspot_module.status()


def configure_hotspot(ssid: str, passphrase: str, band: str = "auto") -> dict[str, Any]:
    ssid = str(ssid or "").strip()
    # Validated before the platform check, so the message names the real
    # problem rather than the environment.
    if not 1 <= len(ssid) <= 32:
        raise ServiceError("The network name must be between 1 and 32 characters")
    if not 8 <= len(passphrase or "") <= 63:
        raise ServiceError("The passphrase must be between 8 and 63 characters")
    result = hotspot_module.configure(ssid, passphrase, band)
    if not result.get("ok"):
        raise ServiceError(result.get("error") or "The hotspot could not be set up.")
    return result


def start_hotspot() -> dict[str, Any]:
    result = hotspot_module.start()
    if not result.get("ok"):
        raise ServiceError(result.get("error") or "The hotspot would not start.")
    return result


def stop_hotspot() -> dict[str, Any]:
    return hotspot_module.stop()


def set_sharing(source: str, target: str, enable: bool = True) -> dict[str, Any]:
    if not source or not target:
        raise ServiceError("Name both the connection to share and where to share it")
    result = hotspot_module.set_sharing(source, target, enable)
    if not result.get("ok"):
        raise ServiceError(result.get("error") or "Sharing could not be changed.")
    return result

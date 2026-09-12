"""Walk surveys: capturing a location and reporting on coverage."""

from __future__ import annotations

import time
from typing import Any

from .. import db, gps, scanner, survey
from ..config import config
from .errors import NotFound, ServiceError

# How far back a reading can be and still count as "heard at this spot".
READING_WINDOW_SECONDS = 120


def active_site_id(explicit: int | None = None) -> int | None:
    if explicit is not None:
        return explicit
    return config.get("site", "active_id", default=None)


def capture_point(
    name: str,
    scan_first: bool = True,
    site_id: int | None = None,
    floor: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Record what the radio hears right now at a named location."""
    name = str(name or "").strip()
    if not name:
        raise ServiceError("Give the location a name, such as 'Reception'")

    if scan_first:
        try:
            scanner.engine.run_once()
        except Exception as exc:
            raise ServiceError(f"Could not scan at this location: {exc}") from exc

    rows = db.list_bss(since=time.time() - READING_WINDOW_SECONDS, limit=2000)
    if not rows:
        raise ServiceError(
            "No networks were heard here, so there is nothing to record. "
            "Check the adapter is still working."
        )

    readings = [
        {"bssid": r["bssid"], "ssid": r["ssid"], "rssi": r["rssi"],
         "channel": r["channel"], "band": r["band"], "security": r["security"]}
        for r in rows
    ]
    resolved_site = active_site_id(site_id)
    fix = gps.reader.current_fix() or {}
    point_id = db.add_survey_point(
        name, readings, resolved_site, floor, notes,
        lat=fix.get("lat"), lon=fix.get("lon"),
    )

    # Every reading can carry a null RSSI if the driver reported the network
    # without a signal level, so the best signal has to tolerate finding none.
    levels = [r["rssi"] for r in readings if r["rssi"] is not None]
    return {
        "id": point_id,
        "ap_count": len(readings),
        "best_rssi": max(levels) if levels else None,
        "points": db.list_survey_points(resolved_site),
    }


def points(site_id: int | None = None) -> list[dict]:
    return db.list_survey_points(site_id)


def point_detail(point_id: int) -> dict[str, Any]:
    readings = db.survey_point_readings(point_id)
    if not readings:
        # A location where nothing was audible is a finding in its own right,
        # so absence of readings must not be reported as absence of the point.
        known = {p["id"] for p in db.list_survey_points()}
        if point_id not in known:
            raise NotFound("No survey point with that ID")
    return {"id": point_id, "readings": readings}


def delete_point(point_id: int) -> bool:
    if not db.delete_survey_point(point_id):
        raise NotFound("No survey point with that ID")
    return True


def coverage(site_id: int | None = None, ssid: str | None = None) -> dict[str, Any]:
    return survey.coverage_report(active_site_id(site_id), ssid)


def channel_plan(minutes: float = 15, radios_per_band: int = 3) -> dict[str, Any]:
    return survey.channel_plan(minutes, radios_per_band)


def interference(minutes: float = 15) -> dict[str, Any]:
    return survey.interference_report(minutes)


# -- sites -----------------------------------------------------------------


def sites(include_archived: bool = False) -> list[dict]:
    return db.list_sites(include_archived)


def create_site(name: str, client: str = "", address: str = "",
                contact: str = "", notes: str = "") -> dict:
    name = str(name or "").strip()
    if not name:
        raise ServiceError("Give the site a name")
    if len(name) > 120:
        raise ServiceError("That site name is too long; keep it under 120 characters")
    try:
        # Named, because db.create_site takes contact before notes and getting
        # that order wrong silently files the notes as a contact.
        site_id = db.create_site(
            name, client=client, address=address, contact=contact, notes=notes
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise ServiceError("A site with that name already exists") from exc
        raise
    return {"id": site_id, "sites": db.list_sites()}


def update_site(site_id: int, fields: dict) -> list[dict]:
    if not db.get_site(site_id):
        raise NotFound("No site with that ID")
    db.update_site(site_id, fields)
    return db.list_sites()


def delete_site(site_id: int) -> list[dict]:
    if not db.delete_site(site_id):
        raise NotFound("No site with that ID")
    # A deleted site must not stay selected, or every view filters on nothing.
    if config.get("site", "active_id", default=None) == site_id:
        config.set(None, "site", "active_id")
    return db.list_sites()


def activate_site(site_id: int) -> dict[str, Any]:
    if not db.get_site(site_id):
        raise NotFound("No site with that ID")
    config.set(site_id, "site", "active_id")
    return {"active_id": site_id}


# -- snapshots and inventory ------------------------------------------------


def snapshots(site_id: int | None = None) -> list[dict]:
    return db.list_snapshots(site_id)


def take_snapshot(name: str, site_id: int | None = None, notes: str = "") -> dict[str, Any]:
    name = str(name or "").strip()
    if not name:
        raise ServiceError("Give the snapshot a name, such as 'Before'")
    snap_id = db.take_snapshot(name, active_site_id(site_id), notes)
    return {"id": snap_id, "snapshots": db.list_snapshots(active_site_id(site_id))}


def compare_snapshot(snapshot_id: int) -> dict[str, Any]:
    if not db.get_snapshot(snapshot_id):
        raise NotFound("No snapshot with that ID")
    return survey.compare_snapshot(snapshot_id)


def delete_snapshot(snapshot_id: int) -> bool:
    if not db.delete_snapshot(snapshot_id):
        raise NotFound("No snapshot with that ID")
    return True


def inventory(site_id: int | None = None) -> list[dict]:
    return db.get_inventory(site_id)


def set_inventory(bssid: str, fields: dict) -> dict[str, Any]:
    from .. import oui

    normalised = oui.normalise(bssid)
    if len(normalised.replace(":", "")) != 12:
        raise ServiceError("That is not a full MAC address")
    fields = dict(fields)
    fields.setdefault("site_id", active_site_id(None))
    db.set_inventory(normalised, fields)
    return db.inventory_for(normalised) or {}


def delete_inventory(bssid: str) -> bool:
    from .. import oui

    if not db.delete_inventory(oui.normalise(bssid)):
        raise NotFound("That BSSID is not in the inventory")
    return True

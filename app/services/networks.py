"""Reading what is in range, flat and grouped by name."""

from __future__ import annotations

import time
from typing import Any

from .. import db, oui
from . import decode
from .errors import NotFound


def _since(minutes: float | None) -> float | None:
    return time.time() - minutes * 60 if minutes else None


def listing(
    minutes: float | None = None,
    search: str | None = None,
    band: str | None = None,
    security: str | None = None,
    order: str = "rssi",
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    """One row per radio, which is what Live shows."""
    since = _since(minutes)
    rows = db.list_bss(
        since=since, search=search, band=band, security=security,
        limit=limit, offset=offset, order=order,
    )
    return {
        "networks": decode.bss_rows(rows),
        "total": db.count_bss(since),
        "offset": offset,
        "limit": limit,
    }


def grouped(
    minutes: float | None = None,
    search: str | None = None,
    band: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """One entry per network name, with every radio serving it.

    A tri-band access point publishes the same name on 2.4, 5 and 6 GHz with a
    different BSSID each, so a flat list makes one network look like three.
    """
    groups = db.ssid_grouped(_since(minutes), limit)

    if search:
        term = search.lower()
        groups = [
            g for g in groups
            if term in (g["ssid"] or "").lower()
            or any(term in (r["bssid"] or "") for r in g["radios"])
            or any(term in (r["vendor"] or "").lower() for r in g["radios"])
        ]
    if band:
        groups = [g for g in groups if band in g["bands"]]

    return {
        "groups": groups,
        "total": len(groups),
        "radio_total": sum(g["radio_count"] for g in groups),
        "multi_band": sum(1 for g in groups if g["band_count"] > 1),
        "tri_band": sum(1 for g in groups if g["tri_band"]),
    }


def detail(bssid: str) -> dict:
    row = db.get_bss(oui.normalise(bssid))
    if not row:
        raise NotFound("That BSSID has not been seen")
    return decode.bss(row)


def history(bssid: str, limit: int = 500) -> dict[str, Any]:
    normalised = oui.normalise(bssid)
    if not db.get_bss(normalised):
        raise NotFound("That BSSID has not been seen")
    return {"bssid": normalised, "history": db.bss_history(normalised, limit)}


def set_note(bssid: str, note: str) -> dict[str, Any]:
    normalised = oui.normalise(bssid)
    if not db.get_bss(normalised):
        raise NotFound("That BSSID has not been seen")
    trimmed = str(note or "")[:2000]
    db.set_note(normalised, trimmed)
    return {"bssid": normalised, "note": trimmed}


def ssid_summary(minutes: float | None = None) -> list[dict]:
    return db.ssid_groups(_since(minutes))


def channel_usage(minutes: float | None = None) -> list[dict]:
    return db.channel_usage(_since(minutes))

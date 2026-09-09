"""Frequency layout for the occupancy ribbon.

Every access point is placed at its real centre frequency spanning its real
channel width, so two blocks that overlap on screen are two radios that
overlap in the air. That is the whole point of the view, and it only works if
the geometry comes from the frequency rather than from the channel number.
"""

from __future__ import annotations

import time
from typing import Any

from .. import db

# The x-axis domain of each ribbon, in MHz. These are fixed rather than
# derived from the data, so an empty band still draws at the right scale and
# a band does not rescale as access points come and go.
BAND_RANGES: dict[str, tuple[int, int]] = {
    "2.4": (2400, 2500),
    "5": (5150, 5895),
    "6": (5925, 7125),
}

BAND_ORDER = ("2.4", "5", "6")

# 6 GHz Preferred Scanning Channels. A radio that is not on one of these is
# far less likely to be found by a client that is not already looking for it,
# which is worth saying on the ribbon header.
PSC_CHANNELS = frozenset(
    {5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229}
)

# An access point that does not report a width is drawn as the narrowest legal
# channel rather than as a hairline, so it stays visible and does not imply
# more precision than we have.
DEFAULT_WIDTH_MHZ = 20


def layout(minutes: float = 10, limit: int = 2000) -> dict[str, Any]:
    """Everything the ribbon needs, bucketed by band.

    Rows with no frequency are dropped: without one there is nowhere on the
    axis to honestly put them.
    """
    since = time.time() - minutes * 60 if minutes else None
    rows = db.list_bss(since=since, limit=limit, order="rssi")
    return layout_from_rows(rows)


def layout_from_rows(rows: list[dict]) -> dict[str, Any]:
    bands: dict[str, list[dict]] = {band: [] for band in BAND_ORDER}
    for row in rows:
        band = row.get("band")
        if band not in bands or not row.get("freq_khz"):
            continue
        width = row.get("width_mhz") or DEFAULT_WIDTH_MHZ
        centre = row["freq_khz"] / 1000.0
        bands[band].append(
            {
                "bssid": row["bssid"],
                "ssid": row["ssid"] or "",
                "hidden": bool(row["hidden"]),
                "centre_mhz": centre,
                "low_mhz": centre - width / 2,
                "high_mhz": centre + width / 2,
                "width_mhz": width,
                "channel": row["channel"],
                "rssi": row["rssi"],
                "security": row["security"],
                "utilization_pct": row["utilization_pct"],
                "vendor": row["vendor"],
            }
        )
    return {
        "bands": bands,
        "ranges": {band: list(rng) for band, rng in BAND_RANGES.items()},
        "counts": {band: len(items) for band, items in bands.items()},
    }


def psc_count(items: list[dict]) -> int:
    """How many of these are on a 6 GHz preferred scanning channel."""
    return sum(1 for item in items if item.get("channel") in PSC_CHANNELS)

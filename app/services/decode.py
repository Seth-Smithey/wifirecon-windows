"""Turn raw database rows into the shape an interface can display.

Three tables store structured values as JSON text because SQLite has no list
or dict column. Every reader needs them back as real Python objects, and
every reader needs the integer columns back as booleans, so the unpacking
lives here rather than being repeated per view.
"""

from __future__ import annotations

import json
from typing import Any

# Columns stored as 0/1 in the bss table that mean true or false.
BSS_BOOL_KEYS = (
    "hidden", "mfp_required", "mfp_capable", "wps", "enterprise", "randomized_mac",
)

# Columns stored as JSON arrays.
BSS_JSON_LIST_KEYS = ("akms", "ciphers")


def _load(raw: Any, fallback: Any) -> Any:
    if not isinstance(raw, str) or not raw:
        return fallback
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return fallback


def bss(row: dict) -> dict:
    """One row of the bss table, ready to display.

    A value that will not parse is kept rather than dropped: a malformed
    cipher list is still evidence of something, and losing it silently would
    hide it.
    """
    out = dict(row)
    for key in BSS_JSON_LIST_KEYS:
        raw = out.get(key)
        if isinstance(raw, str) and raw:
            out[key] = _load(raw, [raw])
        elif raw is None:
            out[key] = []
    detail = out.pop("detail_json", None)
    if detail:
        out["detail"] = _load(detail, None)
    for key in BSS_BOOL_KEYS:
        out[key] = bool(out.get(key))
    return out


def bss_rows(rows: list[dict]) -> list[dict]:
    return [bss(r) for r in rows]


def alert(row: dict) -> dict:
    """One row of the alerts table. Evidence is a JSON object."""
    out = dict(row)
    if out.get("evidence"):
        out["evidence"] = _load(out["evidence"], out["evidence"])
    out["acknowledged"] = bool(out.get("acknowledged"))
    return out


def alert_rows(rows: list[dict]) -> list[dict]:
    return [alert(r) for r in rows]


def device(row: dict) -> dict:
    """One row of lan_devices, ready to display.

    The payload column is detail_json, matching the bss table. Reading it as
    "detail" silently produced a row with no sources, services or names on it.
    """
    out = dict(row)
    raw = out.pop("detail_json", None)
    if raw:
        out["detail"] = _load(raw, None)
    else:
        out.setdefault("detail", None)
    return out


def device_rows(rows: list[dict]) -> list[dict]:
    return [device(r) for r in rows]

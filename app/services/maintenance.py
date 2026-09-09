"""Pruning, compacting and the destructive operations.

Every operation here that cannot be undone takes a confirmation phrase. The
interface asks for it; this refuses without it, so a mis-wired button cannot
delete a survey.
"""

from __future__ import annotations

import logging
from typing import Any

from .. import db, oui
from ..config import config, data_dir
from .errors import ServiceError

log = logging.getLogger(__name__)

CONFIRM_CLEAR = "clear"
CONFIRM_WIPE = "WIPE EVERYTHING"


def prune() -> dict[str, Any]:
    removed = db.prune(
        int(config.get("retention", "observation_days", default=30)),
        int(config.get("retention", "alert_days", default=90)),
        int(config.get("retention", "gps_days", default=30)),
    )
    return {"removed": removed, "total": sum(removed.values())}


def compact() -> dict[str, Any]:
    before = db.db_size_bytes()
    db.vacuum()
    after = db.db_size_bytes()
    return {"before": before, "after": after, "saved": max(0, before - after)}


def reload_vendors() -> dict[str, Any]:
    oui.autoload(data_dir())
    return {"source": oui.db.source, "size": oui.db.size}


def clear_networks(confirm: str, keep_marks: bool = True,
                   keep_inventory: bool = True) -> dict[str, Any]:
    """Forget every observed network. Marks and inventory survive by default."""
    if confirm != CONFIRM_CLEAR:
        raise ServiceError(
            f'Confirm with "{CONFIRM_CLEAR}" to go ahead. This cannot be undone.'
        )
    removed = db.clear_networks(bool(keep_marks), bool(keep_inventory))
    total = sum(removed.values())
    return {
        "removed": removed,
        "total": total,
        "message": f"Cleared {total} record(s). Scanning starts fresh.",
    }


def wipe(confirm: str, reset_settings: bool = False,
         compact_after: bool = True) -> dict[str, Any]:
    """Delete everything: networks, findings, marks, sites, surveys, devices."""
    if confirm != CONFIRM_WIPE:
        raise ServiceError(
            f'Confirm with "{CONFIRM_WIPE}" to go ahead. Every network, finding, '
            "mark, site, survey and device record is deleted."
        )
    removed = db.wipe_everything()
    if reset_settings:
        config.reset()
    if compact_after:
        try:
            db.vacuum()
        except Exception as exc:
            log.warning("Could not compact after wipe: %s", exc)
    total = sum(removed.values())
    return {
        "removed": removed,
        "total": total,
        "message": f"Deleted {total} record(s) across {len(removed)} tables.",
    }

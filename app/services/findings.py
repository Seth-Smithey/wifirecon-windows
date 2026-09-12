"""Detection findings: reading, acknowledging, clearing."""

from __future__ import annotations

import time
from typing import Any

from .. import db, detections, scanner
from . import decode
from .errors import ServiceError

CLEAR_SCOPES = ("all", "acknowledged", "rule", "ids", "older")

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Highest first, which is the order findings are worth reading in.
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def listing(
    limit: int = 200,
    offset: int = 0,
    severity: str | None = None,
    rule: str | None = None,
    unacked_only: bool = False,
    minutes: float | None = None,
) -> dict[str, Any]:
    since = time.time() - minutes * 60 if minutes else None
    rows = db.list_alerts(
        limit=limit, offset=offset, severity=severity, rule=rule,
        unacked_only=unacked_only, since=since,
    )
    return {"alerts": decode.alert_rows(rows), "counts": db.alert_counts()}


def _ids(raw: Any, cap: int) -> list[int] | None:
    if raw is None:
        return None
    if not isinstance(raw, (list, tuple, set)):
        raise ServiceError("'ids' must be a list of finding IDs")
    if not raw:
        return None
    try:
        return [int(i) for i in raw][:cap]
    except (TypeError, ValueError):
        raise ServiceError("Finding IDs must be numbers") from None


def acknowledge(ids: Any = None, before: float | None = None) -> int:
    return db.acknowledge_alerts(ids=_ids(ids, 2000), all_before=before)


def unacknowledge(ids: Any = None, rule: str | None = None) -> dict[str, Any]:
    count = db.unacknowledge_alerts(ids=_ids(ids, 5000), rule=rule)
    return {"reopened": count, "counts": db.alert_counts()}


def clear(
    scope: str = "acknowledged",
    ids: Any = None,
    rule: str | None = None,
    days: float = 30,
) -> dict[str, Any]:
    """Delete findings. Their cooldowns go too, so anything still true is
    reported again on the next scan rather than staying quiet."""
    if scope not in CLEAR_SCOPES:
        raise ServiceError("scope must be one of: " + ", ".join(CLEAR_SCOPES))
    # A scope that names what to delete but names nothing falls through to an
    # unfiltered DELETE. Only "all" is allowed to mean everything.
    if scope == "ids" and not _ids(ids, 5000):
        raise ServiceError("Give the finding IDs to delete")
    if scope == "rule" and not rule:
        raise ServiceError("Give the rule whose findings should be deleted")
    removed = db.delete_alerts(
        _ids(ids, 5000) if scope == "ids" else None,
        rule if scope == "rule" else None,
        scope == "acknowledged",
        float(days) if scope == "older" else None,
    )
    return {"removed": removed, "counts": db.alert_counts()}


def reset_cooldowns() -> dict[str, Any]:
    """Forget every suppression so all current conditions re-report at once."""
    cleared = db.clear_suppressions()
    scanner.engine.scan_now()
    return {
        "cleared": cleared,
        "message": f"Cleared {cleared} cooldown(s). The next scan will report "
                   "everything it still finds.",
    }


def rules() -> list[str]:
    return detections.rule_names()


def flagged_bssids(minutes: float | None = None) -> set[str]:
    """BSSIDs with an open critical or high finding.

    The spectrum ribbon and the live table both outline these, so both ask
    the same question here rather than each deciding for itself what counts
    as worth flagging.
    """
    since = time.time() - minutes * 60 if minutes else None
    flagged: set[str] = set()
    for severity in ("critical", "high"):
        for row in db.list_alerts(limit=2000, severity=severity,
                                  unacked_only=True, since=since):
            if row.get("bssid"):
                flagged.add(row["bssid"])
    return flagged

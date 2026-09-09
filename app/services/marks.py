"""Watch, trusted and ignore lists.

The database will store whatever it is handed, and the detection rules match
against it literally, so a mark with a half-typed MAC in it silently never
fires. Validation therefore belongs in front of every caller, not in one of
them.
"""

from __future__ import annotations

from .. import db, oui
from .errors import NotFound, ServiceError

VALID_KINDS = ("watch", "trusted", "ignore")
VALID_MATCH_TYPES = ("bssid", "oui", "ssid", "ssid_prefix")

KIND_LABELS = {
    "watch": "Watch",
    "trusted": "Trusted",
    "ignore": "Ignore",
}

MATCH_LABELS = {
    "bssid": "MAC address",
    "oui": "Vendor prefix",
    "ssid": "Network name",
    "ssid_prefix": "Name starts with",
}

HEX = "0123456789abcdef"


def listing() -> list[dict]:
    return db.list_marks()


def normalise(kind: str, match_type: str, value: str) -> tuple[str, str, str]:
    """Validate and clean one mark. Raises ServiceError naming what is wrong."""
    kind = str(kind or "").lower().strip()
    match_type = str(match_type or "").lower().strip()
    value = str(value or "").strip()

    if kind not in VALID_KINDS:
        raise ServiceError(f"kind must be one of {sorted(VALID_KINDS)}")
    if match_type not in VALID_MATCH_TYPES:
        raise ServiceError(f"match_type must be one of {sorted(VALID_MATCH_TYPES)}")
    if not value:
        raise ServiceError("A value is required")

    if match_type == "bssid":
        value = oui.normalise(value)
        if len(value.replace(":", "")) != 12:
            raise ServiceError("That is not a full MAC address")
    elif match_type == "oui":
        cleaned = "".join(c for c in value.lower() if c in HEX)
        if len(cleaned) < 6:
            raise ServiceError("An OUI needs at least 6 hex digits")
        value = cleaned

    return kind, match_type, value


def add(kind: str, match_type: str, value: str, label: str | None = None) -> list[dict]:
    kind, match_type, value = normalise(kind, match_type, value)
    db.add_mark(kind, match_type, value, label)
    return db.list_marks()


def remove(mark_id: int) -> list[dict]:
    if not db.delete_mark(mark_id):
        raise NotFound("No mark with that ID")
    return db.list_marks()

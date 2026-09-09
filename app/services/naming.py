"""Default file names for things the person saves.

These end up as the suggested name in a save dialog, so they carry a
timestamp and enough of the title to tell two exports apart later.
"""

from __future__ import annotations

import time

SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

MAX_TITLE_CHARS = 60


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M")


def slug(text: str) -> str:
    cleaned = "".join(c if c in SAFE else "-" for c in (text or "").strip())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-")[:MAX_TITLE_CHARS]


def report_filename(title: str = "") -> str:
    base = slug(title) or "survey"
    return f"{_stamp()}-{base}.html"


def export_filename(export_name: str) -> str:
    """`networks.csv` becomes `wifirecon-networks-20260830-1412.csv`."""
    base, _, ext = export_name.rpartition(".")
    return f"wifirecon-{base or export_name}-{_stamp()}.{ext or 'txt'}"

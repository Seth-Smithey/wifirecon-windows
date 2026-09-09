"""Settings, and pushing them into the workers that already started.

Background workers read their configuration once at start. Without this,
changing the syslog host or turning GPS on would look like it worked and
quietly keep using the old values until the next restart.
"""

from __future__ import annotations

from typing import Any

from .. import alerts as alert_module
from .. import gps, scanner
from ..config import config
from .errors import ServiceError

MASK = "********"


def apply_runtime() -> None:
    """Push settings that background workers read at start into them now."""
    alert_module.dispatcher.configure(config.get("alerts", default={}) or {})
    if config.get("gps", "enabled", default=False):
        gps.reader.start(
            config.get("gps", "port", default=""),
            int(config.get("gps", "baud", default=4800)),
            float(config.get("gps", "stale_seconds", default=30)),
        )
    else:
        gps.reader.stop()
    scanner.engine.scan_now()


def current(mask_token: bool = True) -> dict[str, Any]:
    """The whole settings tree.

    The API token is masked for anything that will display it. The desktop
    interface asks for it unmasked, since it is showing the person their own
    token on their own machine.
    """
    settings = config.as_dict()
    if mask_token and settings.get("server", {}).get("api_token"):
        settings["server"]["api_token"] = MASK
    return settings


def update(patch: dict, mask_token: bool = True) -> dict[str, Any]:
    if not isinstance(patch, dict):
        raise ServiceError("Settings must be an object")

    # Never let a masked token round-trip back into the file and become the
    # real token.
    server = patch.get("server")
    if isinstance(server, dict) and server.get("api_token") == MASK:
        server = dict(server)
        server.pop("api_token")
        patch = dict(patch)
        patch["server"] = server

    updated = config.update(patch)
    apply_runtime()

    if mask_token and updated.get("server", {}).get("api_token"):
        updated = dict(updated)
        updated["server"] = dict(updated["server"])
        updated["server"]["api_token"] = MASK
    return updated


def reset(mask_token: bool = True) -> dict[str, Any]:
    settings = config.reset()
    apply_runtime()
    if mask_token and settings.get("server", {}).get("api_token"):
        settings["server"]["api_token"] = MASK
    return settings

"""Entry point for the desktop application.

This used to open a WebView2 window onto a local web server, which meant the
interface was Edge rendering a page and the application was a browser in a
costume. It is now a native Qt application that calls the service layer in
this process. There is no embedded browser and no port.

The module keeps its name and its two-function shape so callers did not have
to change.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


def available() -> tuple[bool, str]:
    """Whether the desktop interface can run, and the fix if it cannot."""
    from .ui import available as _available

    return _available()


def run(hide_console_when_ready: bool = False) -> int:
    """Open the window and block until it closes. Returns the exit code."""
    from .ui import run as _run

    return _run(hide_console_when_ready)

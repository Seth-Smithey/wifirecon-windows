"""The desktop interface.

Native Qt widgets throughout. There is no embedded browser, no WebView2 and no
web server behind this: the views call the service layer directly, in this
process. The FastAPI server still exists, but only for reaching a running
survey from another machine.
"""

from __future__ import annotations


def available() -> tuple[bool, str]:
    """Whether the interface can run, and why not if it cannot."""
    try:
        import PySide6  # noqa: F401
        from PySide6 import QtWidgets  # noqa: F401
    except ImportError:
        return False, (
            "The desktop interface needs PySide6, which is not installed. "
            "Run: pip install PySide6-Essentials"
        )
    return True, ""


def run(hide_console_when_ready: bool = False) -> int:
    """Start the interface and block until the window closes."""
    from .app import run as _run

    return _run(hide_console_when_ready)

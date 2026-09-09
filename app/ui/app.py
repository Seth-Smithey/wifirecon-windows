"""Starting the desktop application.

This is the whole process. It brings up the database, the vendor list and the
background workers, opens the window, and runs Qt's event loop. There is no
port to wait for and no browser to hand off to.
"""

from __future__ import annotations

import logging
import signal
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

from .. import scanner, updater
from ..config import config
from ..services import lifecycle
from . import theme
from .icon import app_icon

log = logging.getLogger(__name__)

ORGANISATION = "wifirecon"
APPLICATION = "wifirecon"

# Qt swallows Ctrl+C unless the interpreter gets a chance to run, so a short
# idle timer keeps the signal handler reachable when started from a console.
SIGNAL_TICK_MS = 250


def _fatal(application: QApplication, exc: Exception) -> None:
    """Say why nothing opened, in the only place a person will see it."""
    from PySide6.QtWidgets import QMessageBox

    from ..config import data_dir

    try:
        where = str(data_dir())
    except Exception:
        where = "the data directory"
    QMessageBox.critical(
        None, "wifirecon could not start",
        f"{exc.__class__.__name__}: {exc}\n\n"
        f"This usually means {where} is not writable. Set WIFIRECON_DATA_DIR "
        "to somewhere it can write, or check the folder's permissions.",
    )


def build_application(argv: list[str] | None = None) -> QApplication:
    existing = QApplication.instance()
    if existing is not None:
        return existing

    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontShowIconsInMenus, False)
    application = QApplication(argv if argv is not None else sys.argv)
    application.setApplicationName(APPLICATION)
    application.setOrganizationName(ORGANISATION)
    application.setApplicationDisplayName("wifirecon")
    palette = theme.THEMES.get(config.get("ui", "theme", default="dark"), theme.DARK)
    application.setWindowIcon(app_icon(palette))
    return application


def run(hide_console_when_ready: bool = False) -> int:
    from .main_window import MainWindow

    application = build_application()

    try:
        lifecycle.bootstrap()
    except Exception as exc:
        # Nothing can be drawn without a writable data directory, and under a
        # shortcut there is no console for the traceback to land in.
        log.exception("Startup failed")
        _fatal(application, exc)
        return 4

    # Cleared before the engine reads it. A flag left set by a crash or by an
    # update restart would otherwise resume scanning against the setting.
    if not config.get("scan", "autostart_on_launch", default=False):
        config.set(False, "scan", "enabled")
    scanner.engine.start()

    if config.get("updates", "check_on_start", default=True):
        updater.checker.start(
            config.get("updates", "channel", default="main"),
            float(config.get("updates", "check_interval_hours", default=24)),
        )

    window = MainWindow()
    window.show()
    window.start()

    # Only now, with a window on screen, is the console safe to take away.
    if hide_console_when_ready:
        from .. import runtime

        QTimer.singleShot(0, runtime.hide_console)

    signal.signal(signal.SIGINT, lambda *_: application.quit())
    ticker = QTimer()
    ticker.setInterval(SIGNAL_TICK_MS)
    ticker.timeout.connect(lambda: None)
    ticker.start()

    return application.exec()

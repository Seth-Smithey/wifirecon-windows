"""Starting up and stopping cleanly.

There were three copies of the shutdown sequence: the HTTP endpoint, the
server lifespan teardown, and the uninstaller. They drifted. This is the one
that runs now, whichever interface asked.
"""

from __future__ import annotations

import logging
import os
import threading

from .. import alerts as alert_module
from .. import db, gps, oui, runtime, scanner
from ..config import config, data_dir, db_path, log_path

log = logging.getLogger(__name__)

# A worker thread that will not join must never leave the process sitting
# there after the person asked it to quit.
FORCE_EXIT_SECONDS = 6.0


_bootstrapped = False


def bootstrap() -> None:
    """Bring up everything the interface needs before it draws anything.

    Idempotent: the command line calls it during dispatch and the interface
    calls it again on the way up, and re-parsing a 50,000-line vendor file a
    second time is pure cost.
    """
    global _bootstrapped
    if _bootstrapped:
        return
    directory = data_dir()
    runtime.sweep_old_binaries()
    db.init(db_path())
    oui.autoload(directory)
    alert_module.dispatcher.configure(config.get("alerts", default={}) or {})
    alert_module.dispatcher.start()
    if config.get("gps", "enabled", default=False):
        gps.reader.start(
            config.get("gps", "port", default=""),
            int(config.get("gps", "baud", default=4800)),
            float(config.get("gps", "stale_seconds", default=30)),
        )
    _bootstrapped = True


def teardown(timeout: float = 2.0) -> None:
    """Stop the workers and leave the database tidy. Safe to call twice."""
    try:
        if config.get("scan", "enabled", default=False):
            scanner.engine.halt()          # closes the open session row
    except Exception:
        log.debug("Could not halt scanning during shutdown", exc_info=True)
    try:
        scanner.engine.stop()
    except Exception:
        log.debug("Could not stop the scan engine", exc_info=True)
    try:
        gps.reader.stop()
    except Exception:
        log.debug("Could not stop the GPS reader", exc_info=True)
    try:
        alert_module.dispatcher.stop(timeout=timeout)
    except Exception:
        log.debug("Could not stop the alert dispatcher", exc_info=True)
    try:
        from .. import updater

        updater.checker.stop()
    except Exception:
        log.debug("Could not stop the update checker", exc_info=True)
    try:
        # Fold the write-ahead log back in so the file is tidy on disk.
        with db.connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass
    try:
        db.close_thread_connection()
    except Exception:
        pass


def shutdown_now(delay: float = 0.0) -> None:
    """Tear down and exit, with a hard deadline so this always terminates."""
    def stop() -> None:
        watchdog = threading.Timer(FORCE_EXIT_SECONDS, _force_exit)
        watchdog.daemon = True
        watchdog.start()
        if delay:
            threading.Event().wait(delay)
        try:
            teardown()
            log.info("Shut down cleanly on request")
        except Exception:
            log.exception("Problem during shutdown; exiting anyway")
        watchdog.cancel()
        os._exit(0)

    threading.Thread(target=stop, daemon=True, name="shutdown").start()


def _force_exit() -> None:
    log.warning("Shutdown took too long; exiting now")
    os._exit(0)


def tail_log(lines: int = 200) -> str:
    """The end of the log file, which is what the diagnostics view shows."""
    path = log_path()
    if not path.exists():
        return "No log file yet."
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        from .errors import ServiceError

        raise ServiceError(f"Could not read the log: {exc}", status=500) from exc
    return "\n".join(content[-lines:])

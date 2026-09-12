"""Getting work off the interface thread, and scan events onto it.

Two rules hold this together. Every call into db, the scan engine or the
driver blocks, so none of them may run on the thread that paints; and the
scan engine publishes from its own thread, so nothing it hands us may touch a
widget directly. A Qt signal solves the second because emitting one across
threads is safe and Qt queues the delivery.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal, Slot

from .. import db, scanner

log = logging.getLogger(__name__)

# Driver enumeration spawns a child process and can sit there for 20 seconds,
# so a couple of slow calls must not be able to starve the quick ones.
MAX_WORKERS = 4


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(object)


class Task(QRunnable):
    """One blocking call, run on a pool thread.

    Auto-delete is off deliberately. The result crosses threads as a queued
    signal, and letting Qt delete the runnable the moment run() returns takes
    the signal object with it, so the result is silently dropped. The pool
    holds the reference until the callback has been delivered instead.
    """

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = _Signals()
        self.setAutoDelete(False)

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as exc:
            log.debug("Background task failed:\n%s", traceback.format_exc())
            self.signals.failed.emit(exc)
        else:
            self.signals.done.emit(result)


class Pool:
    """The application's worker pool.

    Threads are kept alive rather than expiring, because each one holds its
    own SQLite connection and letting them come and go would open and close a
    database handle for every table refresh.
    """

    def __init__(self) -> None:
        self._pool = QThreadPool()
        self._pool.setMaxThreadCount(MAX_WORKERS)
        self._pool.setExpiryTimeout(-1)
        self._live: set[Task] = set()

    def run(
        self,
        fn: Callable[..., Any],
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Task:
        task = Task(fn, *args, **kwargs)
        if on_done is not None:
            task.signals.done.connect(on_done)
        if on_error is not None:
            task.signals.failed.connect(on_error)

        # Released only once the callback has run, on the next turn of the
        # event loop, so nothing is collected mid-delivery.
        def release(*_: Any) -> None:
            QTimer.singleShot(0, lambda: self._live.discard(task))

        task.signals.done.connect(release)
        task.signals.failed.connect(release)

        self._live.add(task)
        self._pool.start(task)
        return task

    @property
    def pending(self) -> int:
        return len(self._live)

    def wait(self, msecs: int = 3000) -> bool:
        return self._pool.waitForDone(msecs)


pool = Pool()


class ScanBridge(QObject):
    """Scan engine events, delivered on the interface thread.

    The browser interface polled status every four seconds because there was
    no way to be told. These arrive the moment they happen, and the slow poll
    stays only as a safety net for anything that changes without an event.
    """

    scanned = Signal(dict)
    scan_failed = Signal(dict)
    phase_changed = Signal(dict)
    activity = Signal(dict)
    state_changed = Signal(dict)
    status_ready = Signal(dict)

    _EVENTS = {
        "scan": "scanned",
        "scan_failed": "scan_failed",
        "phase": "phase_changed",
        "activity": "activity",
        "state": "state_changed",
    }

    def __init__(self, poll_seconds: float = 4.0, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._attached = False
        self._timer = QTimer(self)
        self._timer.setInterval(int(poll_seconds * 1000))
        self._timer.timeout.connect(self.refresh_status)

    def attach(self) -> None:
        if self._attached:
            return
        scanner.engine.subscribe(self._on_engine_event)
        self._attached = True
        self._timer.start()
        self.refresh_status()

    def detach(self) -> None:
        if not self._attached:
            return
        self._timer.stop()
        scanner.engine.unsubscribe(self._on_engine_event)
        self._attached = False

    # Called on the scan thread. Emitting is the only safe thing to do here.
    def _on_engine_event(self, event: str, payload: dict) -> None:
        name = self._EVENTS.get(event)
        if not name:
            return
        getattr(self, name).emit(dict(payload))

    def refresh_status(self) -> None:
        pool.run(self._read_status, self._deliver_status, self._status_failed)

    @Slot(object)
    def _deliver_status(self, payload: dict) -> None:
        # A QObject slot disconnects when this bridge is destroyed. Connecting
        # directly to Signal.emit leaves a Python callback pointing at a deleted
        # signal when an outstanding refresh finishes after the window closes.
        if self._attached:
            self.status_ready.emit(payload)

    # What counts as "in range" when the engine has not scanned this session.
    RECENT_SECONDS = 300

    @staticmethod
    def _read_status() -> dict:
        import time

        return {
            "engine": scanner.engine.status(),
            "alerts": db.alert_counts(),
            "stats": db.stats(),
            "recent": db.count_bss(time.time() - ScanBridge.RECENT_SECONDS),
            "devices": len(db.list_devices(limit=5000)),
            "db_size_bytes": db.db_size_bytes(),
        }

    def _status_failed(self, exc: Exception) -> None:
        log.debug("Status refresh failed: %s", exc)

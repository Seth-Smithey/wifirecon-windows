"""
Isolated native adapter probe.

Enumerating adapters means calling into wlanapi.dll and, through it, whatever
the vendor driver does. Those calls can block indefinitely — particularly just
after the WLAN service restarts — and a bad driver can fault outright. Either
outcome is fatal in-process: a blocked call ties up a worker thread until the
pool is exhausted and the whole app stops answering, and a fault kills it.

So the native work happens in a short-lived child process with a hard timeout.
If it hangs, we kill it and carry on with less detail. If it faults, only the
child dies. The server always answers.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

DEFAULT_TIMEOUT = 20.0
CACHE_TTL = 6.0

_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "data": None}
_consecutive_failures = 0
_disabled_until = 0.0


def _child_argv(output: str) -> list[str]:
    from . import runtime

    return runtime.relaunch_argv(["--probe-adapters", "--probe-output", output])


def probe(timeout: float = DEFAULT_TIMEOUT, force: bool = False) -> dict:
    """Enumerate adapters in a child process. Never raises, never blocks forever."""
    global _consecutive_failures, _disabled_until

    now = time.time()
    with _lock:
        cached = _cache["data"]
        if not force and cached is not None and now - _cache["at"] < CACHE_TTL:
            return dict(cached, cached=True)

    if not IS_WINDOWS:
        return {"ok": False, "adapters": [], "error": "Not running on Windows",
                "cached": False}

    # After repeated failures, back off rather than spawning a child per request.
    if now < _disabled_until:
        with _lock:
            fallback = _cache["data"]
        return dict(
            fallback or {"ok": False, "adapters": []},
            cached=True,
            degraded=True,
            error="The adapter probe keeps failing, so results are from the last "
                  "successful read. Rescan again in a moment.",
        )

    import tempfile

    handle, path = tempfile.mkstemp(prefix="wifirecon-probe-", suffix=".json")
    os.close(handle)
    try:
        os.unlink(path)
    except OSError:
        pass

    argv = _child_argv(path)
    started = time.time()
    proc = None
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
            cwd=str(_install_dir()),
        )
        try:
            _, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # A driver call is stuck. Kill the child; the server is unaffected.
            log.warning("Adapter probe timed out after %.0fs; killing it", timeout)
            proc.kill()
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
            _note_failure()
            with _lock:
                fallback = _cache["data"]
            return dict(
                fallback or {"ok": False, "adapters": []},
                cached=bool(fallback), degraded=True,
                error="Listing adapters took too long and was stopped. This usually "
                      "means a driver is busy - try again in a few seconds.",
            )
    except Exception as exc:
        log.exception("Could not start the adapter probe")
        _note_failure()
        return {"ok": False, "adapters": [], "cached": False,
                "error": f"Could not start the adapter probe: {exc}"}

    duration = time.time() - started

    if not os.path.exists(path):
        message = (stderr or b"").decode("utf-8", "replace")[:200] if proc else ""
        log.warning("Adapter probe produced no output (rc=%s): %s",
                    getattr(proc, "returncode", "?"), message)
        _note_failure()
        with _lock:
            fallback = _cache["data"]
        return dict(
            fallback or {"ok": False, "adapters": []},
            cached=bool(fallback), degraded=True,
            error="The adapter probe stopped unexpectedly"
                  + (f": {message}" if message else "."),
        )

    try:
        with open(path, encoding="utf-8") as handle_in:
            payload = json.load(handle_in)
    except Exception as exc:
        _note_failure()
        return {"ok": False, "adapters": [], "cached": False,
                "error": f"The adapter probe's result could not be read: {exc}"}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    payload["ok"] = True
    payload["cached"] = False
    payload["duration_ms"] = int(duration * 1000)
    with _lock:
        _cache["at"] = time.time()
        _cache["data"] = payload
    _consecutive_failures = 0
    return payload


def _note_failure() -> None:
    global _consecutive_failures, _disabled_until
    _consecutive_failures += 1
    if _consecutive_failures >= 3:
        _disabled_until = time.time() + 60
        log.error(
            "The adapter probe has failed %d times; pausing it for 60 seconds",
            _consecutive_failures,
        )


def _install_dir():
    from . import runtime

    return runtime.install_dir()


def invalidate() -> None:
    with _lock:
        _cache["at"] = 0.0


def status() -> dict:
    with _lock:
        return {
            "cached_at": _cache["at"],
            "has_cache": _cache["data"] is not None,
            "consecutive_failures": _consecutive_failures,
            "paused_until": _disabled_until if _disabled_until > time.time() else None,
        }


# ---------------------------------------------------------------------------
# Child process entry point
# ---------------------------------------------------------------------------


def run_child(output_path: str) -> int:
    """Runs in the child. Enumerates adapters and writes the result as JSON."""
    from . import adapters, scanner

    payload: dict[str, Any] = {"adapters": [], "error": None}
    try:
        source = scanner.build_source()
        payload["adapters"] = adapters.enumerate_adapters(
            source, _preferred_keywords()
        )
        try:
            source.close()
        except Exception:
            pass
    except Exception as exc:
        payload["error"] = str(exc)

    try:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, default=str)
    except Exception:
        return 1
    return 0


def _preferred_keywords() -> list[str]:
    try:
        from .config import config

        return config.get("scan", "prefer_description_contains", default=[]) or []
    except Exception:
        return []

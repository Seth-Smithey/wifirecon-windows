"""
Optional GPS support. Reads NMEA sentences from a serial port so observations
can be tagged with a position for wardriving and coverage mapping.

pyserial is an optional dependency; without it this module reports unavailable
and everything else keeps working.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

try:  # pragma: no cover - depends on the host
    import serial  # type: ignore
    from serial.tools import list_ports  # type: ignore

    SERIAL_AVAILABLE = True
except ImportError:  # pragma: no cover
    serial = None  # type: ignore
    list_ports = None  # type: ignore
    SERIAL_AVAILABLE = False


def _nmea_checksum_ok(sentence: str) -> bool:
    if "*" not in sentence:
        return False
    body, _, checksum = sentence.partition("*")
    body = body.lstrip("$")
    try:
        expected = int(checksum[:2], 16)
    except ValueError:
        return False
    actual = 0
    for ch in body:
        actual ^= ord(ch)
    return actual == expected


def _dm_to_decimal(value: str, hemisphere: str) -> float | None:
    """Convert NMEA ddmm.mmmm to signed decimal degrees."""
    if not value or not hemisphere:
        return None
    try:
        dot = value.index(".")
    except ValueError:
        if len(value) < 3:
            return None
        dot = len(value)
    degrees_len = dot - 2
    if degrees_len < 1:
        return None
    try:
        degrees = float(value[:degrees_len])
        minutes = float(value[degrees_len:])
    except ValueError:
        return None
    decimal = degrees + minutes / 60.0
    if hemisphere.upper() in ("S", "W"):
        decimal = -decimal
    return round(decimal, 7)


def parse_nmea(line: str) -> dict[str, Any] | None:
    """Parse GGA and RMC sentences. Returns a partial fix dict or None."""
    line = line.strip()
    if not line.startswith("$") or not _nmea_checksum_ok(line):
        return None
    body = line[1:].split("*")[0]
    fields = body.split(",")
    if not fields:
        return None
    sentence = fields[0][-3:]

    if sentence == "GGA" and len(fields) >= 15:
        lat = _dm_to_decimal(fields[2], fields[3])
        lon = _dm_to_decimal(fields[4], fields[5])
        if lat is None or lon is None:
            return None
        try:
            quality = int(fields[6]) if fields[6] else 0
        except ValueError:
            quality = 0
        if quality == 0:
            return None
        return {
            "lat": lat,
            "lon": lon,
            "fix_quality": quality,
            "satellites": int(fields[7]) if fields[7].isdigit() else None,
            "hdop": _to_float(fields[8]),
            "alt": _to_float(fields[9]),
        }

    if sentence == "RMC" and len(fields) >= 9:
        if fields[2] != "A":
            return None
        lat = _dm_to_decimal(fields[3], fields[4])
        lon = _dm_to_decimal(fields[5], fields[6])
        if lat is None or lon is None:
            return None
        speed_knots = _to_float(fields[7])
        return {
            "lat": lat,
            "lon": lon,
            "speed": round(speed_knots * 1.852, 2) if speed_knots is not None else None,
            "course": _to_float(fields[8]),
        }
    return None


def _to_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def list_serial_ports() -> list[dict]:
    if not SERIAL_AVAILABLE:
        return []
    try:
        return [
            {"device": p.device, "description": p.description, "hwid": p.hwid}
            for p in list_ports.comports()
        ]
    except Exception as exc:  # pragma: no cover
        log.warning("Could not enumerate serial ports: %s", exc)
        return []


class GpsReader:
    """Background NMEA reader holding the most recent fix."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._fix: dict[str, Any] | None = None
        self._error: str | None = None
        self._port: str = ""
        self._baud: int = 4800
        self._stale_seconds: float = 30.0
        self._sentences = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, port: str, baud: int = 4800, stale_seconds: float = 30.0) -> None:
        if not SERIAL_AVAILABLE:
            self._error = "pyserial is not installed - run: pip install pyserial"
            log.warning(self._error)
            return
        if not port:
            self._error = "No serial port configured"
            return
        self.stop()
        self._port, self._baud, self._stale_seconds = port, baud, stale_seconds
        self._stop.clear()
        self._error = None
        self._thread = threading.Thread(target=self._run, name="gps-reader", daemon=True)
        self._thread.start()
        log.info("GPS reader started on %s at %d baud", port, baud)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3)
        self._thread = None

    def _run(self) -> None:
        backoff = 2.0
        while not self._stop.is_set():
            try:
                with serial.Serial(self._port, self._baud, timeout=2) as port:
                    log.info("GPS port %s open", self._port)
                    backoff = 2.0
                    self._error = None
                    while not self._stop.is_set():
                        try:
                            raw = port.readline()
                        except Exception as exc:
                            self._error = f"Read failed: {exc}"
                            break
                        if not raw:
                            continue
                        try:
                            line = raw.decode("ascii", "ignore")
                        except Exception:
                            continue
                        parsed = parse_nmea(line)
                        if parsed:
                            self._sentences += 1
                            with self._lock:
                                merged = dict(self._fix or {})
                                merged.update(parsed)
                                merged["ts"] = time.time()
                                self._fix = merged
            except Exception as exc:
                self._error = str(exc)
                log.warning("GPS port %s unavailable: %s", self._port, exc)
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, 60)

    def current_fix(self) -> dict[str, Any] | None:
        """Return the latest fix if it is fresh enough, otherwise None."""
        with self._lock:
            fix = dict(self._fix) if self._fix else None
        if not fix:
            return None
        if time.time() - fix.get("ts", 0) > self._stale_seconds:
            return None
        return fix

    def status(self) -> dict:
        fix = self.current_fix()
        with self._lock:
            last = dict(self._fix) if self._fix else None
        return {
            "available": SERIAL_AVAILABLE,
            "running": self.running,
            "port": self._port,
            "baud": self._baud,
            "error": self._error,
            "sentences": self._sentences,
            "fix": fix,
            "last_fix": last,
            "stale": bool(last and not fix),
        }


reader = GpsReader()

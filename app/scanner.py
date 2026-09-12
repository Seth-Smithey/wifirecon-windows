"""
The scan engine.

Owns interface selection, the scan loop, normalising raw BSS entries into the
records the rest of the app uses, and periodic pruning. Sources are pluggable so
the whole pipeline runs against mock data off Windows.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from typing import Any, Protocol

from . import adapter_probe, adapters, alerts, db, detections, gps, ie_parser, oui, wlanapi
from .config import config

log = logging.getLogger(__name__)


class ScanSource(Protocol):
    """Anything that can list interfaces and return BSS entries."""

    name: str

    def interfaces(self) -> list[dict]: ...
    def trigger_scan(self, guid: Any) -> None: ...
    def read_bss(self, guid: Any) -> list[dict]: ...
    def close(self) -> None: ...


class WindowsSource:
    """Live Native Wifi source."""

    name = "windows"

    def __init__(self) -> None:
        self._handle: wlanapi.WlanHandle | None = None
        self._lock = threading.RLock()
        self._guid_cache: dict[str, Any] = {}

    def _open(self) -> wlanapi.WlanHandle:
        with self._lock:
            if self._handle is None:
                self._handle = wlanapi.WlanHandle()
            return self._handle

    def _reset(self) -> None:
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.close()
                except Exception:
                    pass
                self._handle = None
            self._guid_cache.clear()

    def interfaces(self) -> list[dict]:
        try:
            items = self._open().interfaces()
        except wlanapi.WlanError:
            self._reset()
            items = self._open().interfaces()
        for item in items:
            self._guid_cache[item["guid"]] = item["_guid_struct"]
        return items

    def _guid_struct(self, guid: Any):
        if isinstance(guid, str):
            struct = self._guid_cache.get(guid)
            if struct is None:
                self.interfaces()
                struct = self._guid_cache.get(guid)
            if struct is None:
                raise ValueError(f"Interface {guid} is no longer present")
            return struct
        return guid

    def trigger_scan(self, guid: Any) -> None:
        try:
            self._open().scan(self._guid_struct(guid))
        except wlanapi.WlanError as exc:
            if exc.code in (wlanapi.ERROR_BUSY, wlanapi.ERROR_NDIS_DOT11_MEDIA_IN_USE):
                log.debug("Scan request rejected as busy; reading the cached list instead")
                return
            raise

    def read_bss(self, guid: Any) -> list[dict]:
        try:
            return self._open().bss_list(self._guid_struct(guid))
        except wlanapi.WlanError:
            self._reset()
            return self._open().bss_list(self._guid_struct(guid))

    def close(self) -> None:
        self._reset()


def build_source() -> ScanSource:
    """Pick the live source on Windows, the mock source elsewhere or on request."""
    if os.environ.get("WIFIRECON_MOCK") == "1" or not wlanapi.available():
        from tools.mock_source import MockSource

        if not wlanapi.available() and os.environ.get("WIFIRECON_MOCK") != "1":
            log.warning(
                "Native Wifi is unavailable on this host, so the mock source is in use. "
                "Data you see is synthetic."
            )
        return MockSource()
    return WindowsSource()


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Beacon fingerprint
# ---------------------------------------------------------------------------

# Elements whose presence depends on which frame the driver happened to cache,
# on how many clients the neighbours have, or on a passing regulatory event.
# None of them say anything about the identity of the device, and including
# them made the fingerprint change constantly: a beacon always carries TIM and
# a probe response never does, so a fingerprint over the raw element list
# flips every time Windows swaps which frame it kept.
VOLATILE_ELEMENT_IDS = frozenset({
    "5",    # TIM: beacons only, never a probe response
    "11",   # BSS Load: dropped when no stations are associated
    "32",   # Power Constraint
    "35",   # TPC Report
    "37",   # Channel Switch Announcement
    "40",   # Quiet
    "42",   # ERP: tracks legacy clients on 2.4 GHz
    "60",   # Extended Channel Switch Announcement
    "74",   # Overlapping BSS Scan Parameters
    "201",  # Reduced Neighbour Report: per-beacon
})

# Vendor OUIs where the fourth byte really is a subtype selector. Everywhere
# else it is a version or payload byte that varies between frames.
TYPED_VENDOR_OUIS = frozenset({"00:50:f2", "50:6f:9a"})

# Bumped whenever the recipe changes, so a stored fingerprint from an older
# build is recognisable as incomparable rather than reported as a change.
FINGERPRINT_VERSION = "2"


def stable_elements(info: dict) -> list[str]:
    """The identifying elements an access point advertises, order-independent."""
    ids = sorted({
        eid for eid in (info.get("element_ids") or [])
        if eid not in VOLATILE_ELEMENT_IDS
    })
    vendors = sorted({
        f"{v['oui']}:{v['type']}" if v.get("oui") in TYPED_VENDOR_OUIS
        else str(v.get("oui"))
        for v in (info.get("vendor_ies") or [])
    })
    return ids + [f"vendor:{v}" for v in vendors]


def ie_fingerprint(info: dict) -> str:
    parts = stable_elements(info)
    digest = hashlib.sha1("|".join(parts).encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
    return f"{FINGERPRINT_VERSION}:{digest}"


def build_record(entry: dict, fix: dict | None = None) -> dict:
    """Turn a raw BSS entry into the normalised record used everywhere else."""
    info = ie_parser.parse_ies(entry.get("ie") or b"", entry.get("freq_khz", 0))
    security = ie_parser.security_summary(info, entry.get("capability", 0))

    ssid = info.get("ssid")
    if ssid is None:
        raw = entry.get("ssid_bytes") or b""
        ssid = raw.decode("utf-8", "replace") if raw else ""
    hidden = bool(info.get("ssid_hidden") or not ssid.strip())
    if hidden and entry.get("ssid_bytes"):
        # The driver sometimes fills the SSID in from a probe response even when
        # the beacon suppresses it.
        recovered = entry["ssid_bytes"].decode("utf-8", "replace")
        if recovered.strip():
            ssid = recovered
            hidden = False

    bssid = oui.normalise(entry["bssid"])
    vendor = oui.db.lookup(bssid)
    wps = info.get("wps") or {}

    fingerprint = ie_fingerprint(info)

    load = info.get("bss_load") or {}

    return {
        "bssid": bssid,
        "ssid": ssid,
        "hidden": hidden,
        "vendor": vendor,
        "channel": info.get("channel"),
        "band": info.get("band"),
        "freq_khz": entry.get("freq_khz"),
        "width_mhz": info.get("width_mhz"),
        "rssi": entry.get("rssi"),
        "link_quality": entry.get("link_quality"),
        "phy": ie_parser.phy_label(info, entry.get("phy_type", "")),
        "security": security["generation"],
        "akms": security["akms"],
        "ciphers": security["ciphers"],
        "enterprise": security["enterprise"],
        "mfp_required": security["mfp_required"],
        "mfp_capable": security["mfp_capable"],
        "beacon_period": entry.get("beacon_period"),
        "randomized_mac": oui.is_locally_administered(bssid),
        "ie_fingerprint": fingerprint,
        "ie_elements": db.json_dumps(stable_elements(info)),
        "station_count": load.get("station_count"),
        "utilization_pct": load.get("channel_utilization_pct"),
        "wps_manufacturer": wps.get("manufacturer"),
        "wps_model": wps.get("model_name"),
        "wps_device_name": wps.get("device_name"),
        "country": info.get("country"),
        "detail": info,
        "security_detail": security,
        "lat": (fix or {}).get("lat"),
        "lon": (fix or {}).get("lon"),
        "alt": (fix or {}).get("alt"),
    }


def _db_row(record: dict, ts: float) -> dict:
    return {
        "bssid": record["bssid"],
        "ssid": record["ssid"],
        "hidden": int(record["hidden"]),
        "vendor": record["vendor"],
        "ts": ts,
        "channel": record["channel"],
        "band": record["band"],
        "freq_khz": record["freq_khz"],
        "width_mhz": record["width_mhz"],
        "rssi": record["rssi"],
        "phy": record["phy"],
        "security": record["security"],
        "akms": db.json_dumps(record["akms"]),
        "ciphers": db.json_dumps(record["ciphers"]),
        "mfp_required": int(record["mfp_required"]),
        "mfp_capable": int(record["mfp_capable"]),
        "wps": int(bool(record["detail"].get("wps"))),
        "wps_state": (record["detail"].get("wps") or {}).get("state"),
        "beacon_period": record["beacon_period"],
        "country": record["country"],
        "enterprise": int(record["enterprise"]),
        "randomized_mac": int(record["randomized_mac"]),
        "ie_fingerprint": record["ie_fingerprint"],
        "ie_elements": record.get("ie_elements"),
        "wps_manufacturer": record["wps_manufacturer"],
        "wps_model": record["wps_model"],
        "wps_device_name": record["wps_device_name"],
        "station_count": record["station_count"],
        "utilization_pct": record["utilization_pct"],
        "detail_json": db.json_dumps(
            {
                "ie": record["detail"],
                "security": record["security_detail"],
                "link_quality": record["link_quality"],
            }
        ),
    }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ScanEngine:
    def __init__(self) -> None:
        self.source: ScanSource | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.RLock()
        self._interface: dict | None = None
        self._last_scan_at: float = 0.0
        self._last_error: str | None = None
        self._consecutive_errors = 0
        self._last_prune = 0.0
        self._watchdog: threading.Thread | None = None
        self._phase = "idle"
        self._phase_at = time.time()
        self._phase_detail = ""
        self._session_id: int | None = None
        self._session_started: float | None = None
        self._adapter_info: dict | None = None
        self._adapter_lost_since: float | None = None
        self.activity: list[dict] = []
        self.latest: list[dict] = []
        self.stats = {
            "scans": 0,
            "failures": 0,
            "bss_seen": 0,
            "alerts_raised": 0,
            "last_duration_ms": 0,
        }
        self._subscribers: list[Any] = []

    # -- observers ----------------------------------------------------------
    #
    # The desktop interface used to poll status() on a timer because there was
    # no way to hear about a scan finishing. These let it be told instead.
    # Events are published from the scan thread, so a subscriber must not touch
    # user interface objects directly; the Qt side hands them straight to a
    # signal, which marshals the delivery.

    def subscribe(self, callback) -> None:
        """Register a callback taking (event: str, payload: dict)."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _publish(self, event: str, payload: dict | None = None) -> None:
        """Notify subscribers. A broken subscriber must never stop a scan, so
        every callback is isolated and its failure only logged."""
        with self._lock:
            subscribers = list(self._subscribers)
        if not subscribers:
            return
        data = payload or {}
        for callback in subscribers:
            try:
                callback(event, data)
            except Exception:
                log.debug("A scan subscriber raised; ignoring it", exc_info=True)

    # -- lifecycle ----------------------------------------------------------

    def _set_phase(self, phase: str, detail: str = "") -> None:
        with self._lock:
            self._phase = phase
            self._phase_at = time.time()
            self._phase_detail = detail
        # Published outside the lock so a slow subscriber cannot stall the loop.
        self._publish("phase", {"phase": phase, "detail": detail})

    def note(self, message: str, level: str = "info") -> None:
        """Append to the activity feed the interface shows, newest last."""
        entry = {"ts": time.time(), "level": level, "message": message}
        with self._lock:
            self.activity.append(entry)
            if len(self.activity) > 200:
                del self.activity[:-200]
        if level == "error":
            log.error(message)
        else:
            log.info(message)
        self._publish("activity", dict(entry))

    def start(self, run_loop: bool = True) -> None:
        """Bring the engine thread up. It stays idle until scanning is enabled."""
        if self._thread and self._thread.is_alive():
            return
        self.source = build_source()
        self._stop.clear()
        self._thread = threading.Thread(target=self._supervise, name="scan-engine", daemon=True)
        try:
            orphaned = db.close_orphaned_sessions()
            if orphaned:
                log.info("Closed %d session(s) left open by a previous run", orphaned)
        except Exception:
            log.debug("Could not tidy orphaned sessions", exc_info=True)

        self._thread.start()
        self._start_watchdog()
        log.info("Scan engine ready using the %s source", self.source.name)
        if config.get("scan", "enabled", default=False):
            self.note("Scanning resumed from the last session")
        else:
            self._set_phase("idle", "Waiting for you to start scanning")

    def _supervise(self) -> None:
        """Never let one bad cycle take the loop down for good."""
        while not self._stop.is_set():
            try:
                self._loop()
                return                     # clean exit, stop() was called
            except Exception:
                self._last_error = "The scan loop crashed and was restarted."
                log.exception("Scan loop crashed; restarting it in 10 seconds")
                if self._stop.wait(10):
                    return

    def _start_watchdog(self) -> None:
        """Second line of defence: bring the thread back if it disappears."""
        def watch() -> None:
            while not self._stop.wait(30):
                thread = self._thread
                if thread is None or thread.is_alive():
                    continue
                log.error("Scan engine thread is gone; starting a new one")
                self._thread = threading.Thread(
                    target=self._supervise, name="scan-engine", daemon=True
                )
                self._thread.start()

        if not getattr(self, "_watchdog", None) or not self._watchdog.is_alive():
            self._watchdog = threading.Thread(target=watch, name="scan-watchdog", daemon=True)
            self._watchdog.start()

    def stop(self, timeout: float = 4.0) -> None:
        """Stop the engine. The join is bounded so shutdown cannot hang on a
        scan that is mid-flight inside a driver call."""
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                log.warning("Scan thread did not stop in %.0fs; leaving it", timeout)
        self._thread = None
        if self.source:
            try:
                self.source.close()
            except Exception:
                pass
        db.close_thread_connection()

    def scan_now(self) -> None:
        """Ask the loop to run a scan on the next tick."""
        self._wake.set()

    def begin(self, interface_guid: str | None = None) -> dict:
        """Start scanning. This is what the Start button calls."""
        if interface_guid:
            available = self.list_interfaces()
            match = next(
                (a for a in available if a["guid"].lower() == interface_guid.lower()), None
            )
            if not match:
                names = ", ".join(
                    a.get("label") or a["description"] for a in available
                ) or "none"
                return {
                    "ok": False,
                    "error": f"That adapter is not present. Available now: {names}.",
                }
            config.set(interface_guid, "scan", "interface_guid")
        elif interface_guid == "":
            config.set("", "scan", "interface_guid")

        adapter = self.select_interface()
        if not adapter:
            return {"ok": False, "error": self._last_error or
                    "No wireless adapter is available to scan with."}
        if adapter.get("radio_on") is False:
            return {"ok": False, "error":
                    f"The radio on {adapter.get('label') or adapter['description']} is "
                    "switched off. Turn Wi-Fi on, or check for a hardware switch."}

        config.set(True, "scan", "enabled")
        with self._lock:
            self._session_started = time.time()
            self._adapter_info = adapter
            self._consecutive_errors = 0
            self._last_error = None
        self._session_id = db.start_session(
            adapter.get("guid", ""), adapter.get("description", ""),
        )
        self.note(f"Scanning started on {adapter.get('label') or adapter['description']}")
        self._set_phase("starting", "Preparing the first scan")
        self.scan_now()
        self._publish("state", {"scanning": True, "adapter": _public_adapter(adapter)})
        return {"ok": True, "adapter": _public_adapter(adapter),
                "session_id": self._session_id}

    def halt(self) -> dict:
        """Stop scanning but leave the engine thread alive."""
        config.set(False, "scan", "enabled")
        if self._session_id is not None:
            db.end_session(self._session_id)
        self.note("Scanning stopped")
        self._set_phase("idle", "Stopped")
        with self._lock:
            self._session_id = None
            self._session_started = None
        self._wake.set()
        self._publish("state", {"scanning": False, "adapter": None})
        return {"ok": True}

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # -- interfaces ---------------------------------------------------------

    def forget_adapters(self) -> None:
        """Drop cached adapter data after something changed the device tree."""
        try:
            adapters.invalidate_cache()
            adapter_probe.invalidate()
        except Exception:
            pass
        with self._lock:
            self._last_error = None

    def list_interfaces(self, refresh: bool = False) -> list[dict]:
        """Every wireless adapter with the detail needed to tell them apart.

        The native enumeration runs in a child process. Driver calls can block
        or fault, and neither is survivable in-process: a blocked call ties up a
        worker thread until the pool is exhausted and the whole app stops
        answering.
        """
        if not self.source:
            self.source = build_source()
        if self.source.name == "mock":
            return adapters.mock_adapters()

        if os.environ.get("WIFIRECON_PROBE_INLINE") == "1":
            # Used by the child process itself, and available as an escape hatch.
            try:
                return adapters.enumerate_adapters(
                    self.source,
                    config.get("scan", "prefer_description_contains", default=[]),
                )
            except Exception as exc:
                self._last_error = str(exc)
                log.warning("Could not list adapters: %s", exc)
                return []

        result = adapter_probe.probe(force=refresh)
        if result.get("error") and not result.get("adapters"):
            self._last_error = result["error"]
            log.warning("Adapter probe: %s", result["error"])
        elif result.get("degraded"):
            log.info("Adapter list is from cache: %s", result.get("error"))
        return result.get("adapters") or []

    def select_interface(self, force_guid: str | None = None) -> dict | None:
        """Choose the adapter to scan on and return its full description.

        Order of preference: the GUID you picked, then the highest scoring
        adapter, which favours a recognised external radio with its radio on.
        """
        candidates = self.list_interfaces()
        if not candidates:
            self._last_error = (
                "No wireless adapters found. Plug the Alfa in and confirm Windows "
                "lists it under Network adapters in Device Manager."
            )
            return None

        wanted = force_guid if force_guid is not None else config.get(
            "scan", "interface_guid", default=""
        )
        if wanted:
            for item in candidates:
                if item["guid"].lower() == wanted.lower():
                    return self._attach_handle(item)
            self.note(
                f"The adapter you picked is no longer present, so scanning fell back "
                f"to {candidates[0].get('label') or candidates[0]['description']}.",
                "warn",
            )
        return self._attach_handle(candidates[0])

    def _attach_handle(self, info: dict) -> dict:
        """Pair a described adapter with the GUID struct the API calls need."""
        info = dict(info)
        try:
            assert self.source is not None
            for entry in self.source.interfaces():
                if entry["guid"] == info["guid"]:
                    info["_guid_struct"] = entry.get("_guid_struct", entry["guid"])
                    break
        except Exception as exc:
            log.debug("Could not attach a handle for %s: %s", info.get("description"), exc)
        info.setdefault("_guid_struct", info["guid"])
        return info

    def current_adapter(self) -> dict | None:
        """The adapter in use, or the one that would be used if you started now.

        Before the first scan there is no "in use" adapter, but there is always
        an answer to "which one would this pick", and that is what the interface
        needs to show instead of "No adapter".
        """
        with self._lock:
            if self._adapter_info:
                return _public_adapter(self._adapter_info)
        try:
            candidates = self.list_interfaces()
        except Exception:
            return None
        if not candidates:
            return None
        wanted = config.get("scan", "interface_guid", default="")
        chosen = None
        if wanted:
            chosen = next(
                (a for a in candidates if a["guid"].lower() == wanted.lower()), None
            )
        chosen = chosen or candidates[0]
        pending = dict(chosen)
        pending["pending"] = True          # selected, but not scanning yet
        return _public_adapter(pending)

    # -- the loop -----------------------------------------------------------

    def _loop(self) -> None:
        # Vendor data is loaded once in bootstrap(); nothing to do here but scan.
        while not self._stop.is_set():
            enabled = config.get("scan", "enabled", default=False)
            interval = max(
                float(config.get("scan", "interval_seconds", default=20)),
                float(config.get("scan", "min_interval_seconds", default=16)),
            )
            if not enabled:
                if self._phase not in ("idle",):
                    self._set_phase("idle", "Stopped")
                self._wait(min(interval, 2.0))
                continue

            try:
                self.run_once()
                self._consecutive_errors = 0
                self._last_error = None
                wait_for = interval
            except Exception as exc:
                self._consecutive_errors += 1
                self.stats["failures"] += 1
                self._last_error = str(exc)
                self._set_phase("error", str(exc)[:120])
                if self._consecutive_errors == 1:
                    self.note(f"Scan failed: {exc}", "error")
                log.exception("Scan cycle failed (%d in a row)", self._consecutive_errors)
                backoff_cap = float(config.get("scan", "backoff_max_seconds", default=300))
                wait_for = min(interval * (2 ** min(self._consecutive_errors, 6)), backoff_cap)
                log.info("Backing off for %.0f seconds", wait_for)

            try:
                self._maybe_prune()
            except Exception:
                log.exception("Pruning raised; continuing")
            if config.get("scan", "enabled", default=False):
                self._set_phase("waiting", f"Next scan in about {int(wait_for)}s")
            self._wait(wait_for)

    def _wait(self, seconds: float) -> None:
        """Sleep, but wake early on a manual scan request or shutdown."""
        self._wake.clear()
        deadline = time.time() + seconds
        while not self._stop.is_set():
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            if self._wake.wait(timeout=min(remaining, 1.0)):
                self._wake.clear()
                return

    def run_once(self) -> dict:
        """One full cycle: scan, read, normalise, store, detect, alert."""
        started = time.time()
        self._set_phase("selecting", "Choosing an adapter")
        interface = self.select_interface()
        if not interface:
            raise RuntimeError(self._last_error or "No wireless adapter available")

        handle = interface.get("_guid_struct", interface["guid"])
        scan_id = db.start_scan(interface["guid"], session_id=self._session_id,
                                adapter=interface.get("description"))

        # Notice when the adapter we were told to use disappears, which is what
        # happens if the Alfa is unplugged mid-run.
        previous = self._adapter_info
        if previous and previous.get("guid") != interface.get("guid"):
            was = previous.get("label") or previous.get("description")
            now = interface.get("label") or interface.get("description")
            pinned = config.get("scan", "interface_guid", default="")
            if pinned and pinned.lower() == str(previous.get("guid", "")).lower():
                # The adapter you explicitly chose is gone. Surveying on a
                # different radio without saying so would be worse than stopping.
                self.note(
                    f"{was} is no longer present, so scanning stopped. "
                    f"Reconnect it, or choose {now} on the Adapter tab.",
                    "error",
                )
                self._adapter_lost_since = time.time()
                config.set(False, "scan", "enabled")
                self._set_phase("error", f"{was} was disconnected")
                db.finish_scan(scan_id, 0, 0, 0, status="error",
                               error=f"{was} was disconnected")
                raise RuntimeError(f"{was} was disconnected")
            self.note(f"Adapter changed from {was} to {now}", "warn")
        with self._lock:
            self._interface = interface
            self._adapter_info = interface
            self._adapter_lost_since = None
        try:
            assert self.source is not None
            self._set_phase("requesting", "Asking the driver to scan")
            try:
                self.source.trigger_scan(handle)
            except Exception as exc:
                log.debug("Scan request did not go through (%s); using the cached list", exc)

            settle = float(config.get("scan", "settle_seconds", default=4))
            self._set_phase("settling", f"Listening for {settle:.0f}s")
            if settle > 0 and self._stop.wait(settle):
                db.finish_scan(scan_id, 0, 0, 0, status="cancelled")
                return {"scan_id": scan_id, "count": 0, "new": 0,
                        "findings": 0, "duration_ms": 0}

            self._set_phase("reading", "Reading results from the driver")
            entries = self.source.read_bss(handle)

            fix = gps.reader.current_fix() if config.get("gps", "enabled", default=False) else None
            if fix:
                db.insert_gps_fix(
                    {
                        "ts": fix.get("ts", time.time()),
                        "lat": fix.get("lat"),
                        "lon": fix.get("lon"),
                        "alt": fix.get("alt"),
                        "speed": fix.get("speed"),
                        "course": fix.get("course"),
                        "fix_quality": fix.get("fix_quality"),
                        "satellites": fix.get("satellites"),
                        "hdop": fix.get("hdop"),
                    }
                )

            records: list[dict] = []
            seen: set[str] = set()
            for entry in entries:
                try:
                    record = build_record(entry, fix)
                except Exception:
                    log.exception("Could not decode BSS entry %s", entry.get("bssid"))
                    continue
                if record["bssid"] in seen:
                    continue
                seen.add(record["bssid"])
                records.append(record)

            ts = time.time()
            previous = db.get_bss_many(list(seen))

            _, new_bssids = db.upsert_bss([_db_row(r, ts) for r in records])

            db.insert_observations(
                [
                    {
                        "scan_id": scan_id,
                        "bssid": r["bssid"],
                        "ts": ts,
                        "rssi": r["rssi"],
                        "channel": r["channel"],
                        "ssid": r["ssid"],
                        "security": r["security"],
                        "lat": r["lat"],
                        "lon": r["lon"],
                        "alt": r["alt"],
                        "accuracy": (fix or {}).get("hdop"),
                        "station_count": r["station_count"],
                        "utilization_pct": r["utilization_pct"],
                    }
                    for r in records
                ]
            )

            self._set_phase("analysing", f"Checking {len(records)} networks")
            findings = []
            if config.get("detections", "enabled", default=True):
                findings = detections.run(
                    records=records,
                    previous=previous,
                    marks_rows=db.list_marks(),
                    settings=config.get("detections", default={}) or {},
                    new_bssids=new_bssids,
                    scan_interval=float(config.get("scan", "interval_seconds", default=20)),
                )
                if findings:
                    db.insert_alerts(
                        [
                            {
                                "ts": ts,
                                "rule": f.rule,
                                "severity": f.severity,
                                "bssid": f.bssid,
                                "ssid": f.ssid,
                                "title": f.title,
                                "detail": f.detail,
                                "evidence": db.json_dumps(f.evidence),
                                "scan_id": scan_id,
                            }
                            for f in findings
                        ]
                    )
                    alerts.dispatcher.submit(findings)

            duration_ms = int((time.time() - started) * 1000)
            db.finish_scan(scan_id, len(records), len(new_bssids), len(findings))

            with self._lock:
                self.latest = records
                self._last_scan_at = ts
                self.stats["scans"] += 1
                self.stats["bss_seen"] = len(records)
                self.stats["alerts_raised"] += len(findings)
                self.stats["last_duration_ms"] = duration_ms

            log.info(
                "Scan %d on %s: %d networks, %d new, %d findings, %d ms",
                scan_id, interface.get("description", "?"), len(records),
                len(new_bssids), len(findings), duration_ms,
            )
            if self.stats["scans"] == 1:
                self.note(
                    f"First scan complete: {len(records)} networks found on "
                    f"{interface.get('label') or interface.get('description')}"
                )
            elif new_bssids:
                self.note(f"{len(new_bssids)} new network(s) appeared")
            outcome = {
                "scan_id": scan_id,
                "count": len(records),
                "new": len(new_bssids),
                "findings": len(findings),
                "duration_ms": duration_ms,
                "adapter": interface.get("description"),
            }
            self._publish("scan", dict(outcome))
            return outcome
        except Exception as exc:
            db.finish_scan(scan_id, 0, 0, 0, status="error", error=str(exc))
            self._publish("scan_failed", {"scan_id": scan_id, "error": str(exc)})
            raise

    def _maybe_prune(self) -> None:
        interval = float(config.get("retention", "prune_interval_minutes", default=60)) * 60
        if time.time() - self._last_prune < interval:
            return
        self._last_prune = time.time()
        try:
            removed = db.prune(
                int(config.get("retention", "observation_days", default=30)),
                int(config.get("retention", "alert_days", default=90)),
                int(config.get("retention", "gps_days", default=30)),
            )
            if any(removed.values()):
                log.info("Pruned old rows: %s", removed)
            max_mb = float(config.get("retention", "max_db_mb", default=2048))
            size_mb = db.db_size_bytes() / (1024 * 1024)
            if size_mb > max_mb:
                log.warning(
                    "Database is %.0f MB, over the %.0f MB limit. Shortening retention "
                    "or running Compact from Settings will bring it down.",
                    size_mb, max_mb,
                )
        except Exception:
            log.exception("Pruning failed")

    # -- status -------------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            adapter = _public_adapter(self._adapter_info) if self._adapter_info else None
            phase = self._phase
            phase_at = self._phase_at
            phase_detail = self._phase_detail
            session_id = self._session_id
            session_started = self._session_started
            activity = list(self.activity[-40:])
            stats = dict(self.stats)
            last_scan = self._last_scan_at
            last_error = self._last_error
            errors = self._consecutive_errors

        enabled = config.get("scan", "enabled", default=False)
        if adapter is None:
            # Fall back to the adapter that would be used, so the interface can
            # name it rather than claiming there is none.
            try:
                adapter = self.current_adapter()
            except Exception:
                adapter = None
        return {
            "running": self.running,
            "scanning": bool(enabled),
            "phase": phase if enabled or phase == "idle" else "idle",
            "phase_detail": phase_detail,
            "phase_age": round(time.time() - phase_at, 1),
            "source": self.source.name if self.source else None,
            "mock": bool(self.source and self.source.name == "mock"),
            "adapter": adapter,
            "session": {
                "id": session_id,
                "started_at": session_started,
                "duration": round(time.time() - session_started, 1)
                if session_started else None,
            },
            "last_scan_at": last_scan,
            "seconds_since_scan": round(time.time() - last_scan, 1) if last_scan else None,
            "next_scan_in": self._next_scan_in() if enabled else None,
            "last_error": last_error,
            "consecutive_errors": errors,
            "stats": stats,
            "activity": activity,
            "interval_seconds": config.get("scan", "interval_seconds", default=20),
            "enabled": bool(enabled),
        }

    def _next_scan_in(self) -> float | None:
        if not self._last_scan_at:
            return None
        interval = max(
            float(config.get("scan", "interval_seconds", default=20)),
            float(config.get("scan", "min_interval_seconds", default=16)),
        )
        remaining = (self._last_scan_at + interval) - time.time()
        return round(max(0.0, remaining), 1)


def _public_adapter(info: dict | None) -> dict | None:
    """Strip the ctypes handle before anything gets serialised to JSON."""
    if not info:
        return None
    out = {k: v for k, v in info.items() if not k.startswith("_")}
    return out


engine = ScanEngine()

"""Configuration: defaults, file load/save, and environment overrides."""

from __future__ import annotations

import copy
import json
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

APP_NAME = "wifirecon-win"

DEFAULTS: dict[str, Any] = {
    "server": {
        "host": "127.0.0.1",
        "port": 8722,
        "open_browser": True,
        "api_token": "",           # blank = no token required (loopback only)
        "allow_lan": False,        # bind 0.0.0.0 instead of loopback
    },
    "scan": {
        "interval_seconds": 20,
        "min_interval_seconds": 16,   # Windows rate-limits WlanScan
        "settle_seconds": 4,          # wait after WlanScan before reading the list
        "interface_guid": "",         # blank = auto-pick, prefers an external radio
        "prefer_description_contains": ["alfa", "awus", "mediatek", "mt7921"],
        "use_all_interfaces": False,
        # Scanning starts only when you press Start. The engine remembers the
        # last state across restarts, so this flips to true once you begin.
        "enabled": False,
        "autostart_on_launch": False,
        "backoff_max_seconds": 300,
        "warn_if_no_external_adapter": True,
    },
    "retention": {
        "observation_days": 30,
        "alert_days": 90,
        "gps_days": 30,
        "prune_interval_minutes": 60,
        "max_db_mb": 2048,
    },
    "detections": {
        "enabled": True,
        "levenshtein_threshold": 2,
        "rssi_jump_db": 25,
        "min_observations_for_baseline": 5,
        "missing_scans_before_alert": 5,
        "lure_ssids": [
            "attwifi", "xfinitywifi", "free wifi", "free_wifi", "guest",
            "linksys", "netgear", "default", "public wifi", "airport wifi",
            "starbucks wifi", "hotel wifi", "wifi", "internet", "optimumwifi",
            "spectrum wifi", "boingo hotspot", "google starbucks",
        ],
        "max_ssids_per_bssid": 3,
        "congestion_utilization_pct": 60,
        "suppress_seconds": 900,      # per (rule, bssid) alert cooldown
        "severity_floor": "low",
        "max_findings_per_scan": 200,
        # Rules that are true but not worth being told about here. Muting is
        # per rule rather than per finding, because a rule that is noise in
        # one environment is noise every scan.
        "muted_rules": [],
    },
    "alerts": {
        "toast": {"enabled": False, "min_severity": "high"},
        "webhook": {"enabled": False, "url": "", "min_severity": "medium", "timeout": 8},
        "syslog": {
            "enabled": False,
            "host": "",
            "port": 514,
            "protocol": "udp",       # udp | tcp
            "format": "cef",         # cef | json | rfc5424
            "min_severity": "low",
        },
        "eventlog": {"enabled": False, "min_severity": "high"},
    },
    "gps": {
        "enabled": False,
        "port": "",                 # e.g. COM5
        "baud": 4800,
        "stale_seconds": 30,
    },
    "ui": {
        "rssi_floor": -95,
        "default_tab": "live",
        "refresh_seconds": 5,
        "theme": "dark",
        "onboarded": False,
        "native_window": True,
    },
    "site": {
        "active_id": None,
        "default_prepared_by": "",
        "default_report_title": "Wireless Site Survey",
    },
    "updates": {
        "channel": "main",
        "check_on_start": True,
        "check_interval_hours": 24,
        "auto_apply": False,
    },
    "logging": {
        "level": "INFO",
        "max_bytes": 5_000_000,
        "backup_count": 5,
    },
}


def data_dir() -> Path:
    """Per-user writable directory. Falls back to the repo dir off Windows."""
    override = os.environ.get("WIFIRECON_DATA_DIR")
    if override:
        p = Path(override)
    else:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
        if base:
            p = Path(base) / APP_NAME
        else:
            p = Path.home() / f".{APP_NAME}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_path() -> Path:
    return data_dir() / "config.json"


def db_path() -> Path:
    override = os.environ.get("WIFIRECON_DB")
    return Path(override) if override else data_dir() / "wifirecon.db"


def log_path() -> Path:
    return data_dir() / "wifirecon.log"


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Thread-safe config holder backed by a JSON file."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data = copy.deepcopy(DEFAULTS)
        self.load()

    def load(self) -> None:
        path = config_path()
        with self._lock:
            if path.exists():
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    self._data = _deep_merge(DEFAULTS, raw)
                except (json.JSONDecodeError, OSError) as exc:
                    log.error("Could not read %s (%s). Using defaults.", path, exc)
                    backup = path.with_suffix(".json.bad")
                    try:
                        path.replace(backup)
                        log.error("Moved the unreadable config to %s", backup)
                    except OSError:
                        pass
                    self._data = copy.deepcopy(DEFAULTS)
            else:
                self._data = copy.deepcopy(DEFAULTS)
                self.save()
        self._apply_env()

    def _apply_env(self) -> None:
        with self._lock:
            if os.environ.get("WIFIRECON_PORT"):
                try:
                    self._data["server"]["port"] = int(os.environ["WIFIRECON_PORT"])
                except ValueError:
                    log.warning("WIFIRECON_PORT is not a number, ignoring it")
            if os.environ.get("WIFIRECON_TOKEN"):
                self._data["server"]["api_token"] = os.environ["WIFIRECON_TOKEN"]
            if os.environ.get("WIFIRECON_LOG_LEVEL"):
                self._data["logging"]["level"] = os.environ["WIFIRECON_LOG_LEVEL"].upper()

    def save(self) -> None:
        path = config_path()
        tmp = path.with_suffix(".json.tmp")
        with self._lock:
            payload = json.dumps(self._data, indent=2, sort_keys=False)
        try:
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            log.error("Could not save config to %s: %s", path, exc)

    def get(self, *keys: str, default: Any = None) -> Any:
        with self._lock:
            node: Any = self._data
            for key in keys:
                if not isinstance(node, dict) or key not in node:
                    return default
                node = node[key]
            return copy.deepcopy(node) if isinstance(node, (dict, list)) else node

    def set(self, value: Any, *keys: str) -> None:
        if not keys:
            raise ValueError("set() needs at least one key")
        with self._lock:
            node = self._data
            for key in keys[:-1]:
                node = node.setdefault(key, {})
                if not isinstance(node, dict):
                    raise ValueError(f"{'.'.join(keys)} is not a settings group")
            node[keys[-1]] = value
        self.save()

    def update(self, patch: dict) -> dict:
        with self._lock:
            self._data = _deep_merge(self._data, patch)
            result = copy.deepcopy(self._data)
        self.save()
        return result

    def as_dict(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    def reset(self) -> dict:
        with self._lock:
            self._data = copy.deepcopy(DEFAULTS)
        self.save()
        return self.as_dict()

    def ensure_token(self) -> str:
        """Generate an API token if LAN binding is on and none is set."""
        with self._lock:
            token = self._data["server"].get("api_token") or ""
            if not token and self._data["server"].get("allow_lan"):
                token = secrets.token_urlsafe(24)
                self._data["server"]["api_token"] = token
                log.warning("LAN access is on, so an API token was generated: %s", token)
        if token:
            self.save()
        return token


config = Config()

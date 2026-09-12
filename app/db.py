"""SQLite storage: schema, migrations, and every query the app runs."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 7

_local = threading.local()
_db_path: Path | None = None
_write_lock = threading.RLock()


def init(path: Path) -> None:
    """Point the layer at a database file and bring the schema up to date."""
    global _db_path
    _db_path = path
    path.parent.mkdir(parents=True, exist_ok=True)
    with connection() as conn:
        _migrate(conn)


def _connect() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("db.init() has not been called")
    conn = sqlite3.connect(str(_db_path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    """Thread-local connection. Each thread gets its own handle."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    try:
        yield conn
    except sqlite3.Error:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """Serialised write transaction. SQLite allows one writer at a time."""
    with _write_lock, connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")


def close_thread_connection() -> None:
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        finally:
            _local.conn = None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   REAL NOT NULL,
    ended_at     REAL,
    adapter_guid TEXT,
    adapter_name TEXT,
    scan_count   INTEGER DEFAULT 0,
    bss_count    INTEGER DEFAULT 0,
    alert_count  INTEGER DEFAULT 0,
    label        TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     REAL NOT NULL,
    finished_at    REAL,
    interface_guid TEXT,
    session_id     INTEGER,
    adapter        TEXT,
    bss_count      INTEGER DEFAULT 0,
    new_bss_count  INTEGER DEFAULT 0,
    alert_count    INTEGER DEFAULT 0,
    duration_ms    INTEGER,
    status         TEXT DEFAULT 'ok',
    error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS bss (
    bssid            TEXT PRIMARY KEY,
    ssid             TEXT,
    hidden           INTEGER DEFAULT 0,
    vendor           TEXT,
    first_seen       REAL NOT NULL,
    last_seen        REAL NOT NULL,
    times_seen       INTEGER DEFAULT 1,
    channel          INTEGER,
    band             TEXT,
    freq_khz         INTEGER,
    width_mhz        INTEGER,
    rssi             INTEGER,
    rssi_max         INTEGER,
    rssi_min         INTEGER,
    phy              TEXT,
    security         TEXT,
    akms             TEXT,
    ciphers          TEXT,
    mfp_required     INTEGER DEFAULT 0,
    mfp_capable      INTEGER DEFAULT 0,
    wps              INTEGER DEFAULT 0,
    wps_state        TEXT,
    beacon_period    INTEGER,
    country          TEXT,
    enterprise       INTEGER DEFAULT 0,
    randomized_mac   INTEGER DEFAULT 0,
    ie_fingerprint   TEXT,
    ie_elements      TEXT,
    wps_manufacturer TEXT,
    wps_model        TEXT,
    wps_device_name  TEXT,
    station_count    INTEGER,
    utilization_pct  REAL,
    detail_json      TEXT,
    notes            TEXT
);
CREATE INDEX IF NOT EXISTS idx_bss_ssid ON bss(ssid);
CREATE INDEX IF NOT EXISTS idx_bss_last_seen ON bss(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_bss_band_channel ON bss(band, channel);

CREATE TABLE IF NOT EXISTS observations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL,
    bssid     TEXT NOT NULL,
    ts        REAL NOT NULL,
    rssi      INTEGER,
    channel   INTEGER,
    ssid      TEXT,
    security  TEXT,
    lat       REAL,
    lon       REAL,
    alt       REAL,
    accuracy  REAL,
    station_count   INTEGER,
    utilization_pct REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_obs_bssid_ts ON observations(bssid, ts DESC);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts DESC);
CREATE INDEX IF NOT EXISTS idx_obs_scan ON observations(scan_id);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    bssid       TEXT,
    ssid        TEXT,
    title       TEXT NOT NULL,
    detail      TEXT,
    evidence    TEXT,
    acknowledged INTEGER DEFAULT 0,
    acked_at    REAL,
    scan_id     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged, ts DESC);

CREATE TABLE IF NOT EXISTS marks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,          -- watch | trusted | ignore
    match_type TEXT NOT NULL,          -- bssid | oui | ssid | ssid_prefix
    value      TEXT NOT NULL,
    label      TEXT,
    created_at REAL NOT NULL,
    UNIQUE(kind, match_type, value)
);
CREATE INDEX IF NOT EXISTS idx_marks_lookup ON marks(match_type, value);

CREATE TABLE IF NOT EXISTS gps_fixes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    lat      REAL, lon REAL, alt REAL,
    speed    REAL, course REAL,
    fix_quality INTEGER, satellites INTEGER, hdop REAL
);
CREATE INDEX IF NOT EXISTS idx_gps_ts ON gps_fixes(ts DESC);

CREATE TABLE IF NOT EXISTS sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    client      TEXT,
    address     TEXT,
    contact     TEXT,
    notes       TEXT,
    created_at  REAL NOT NULL,
    archived    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS survey_points (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER,
    name        TEXT NOT NULL,
    floor       TEXT,
    notes       TEXT,
    captured_at REAL NOT NULL,
    scan_id     INTEGER,
    lat REAL, lon REAL,
    ap_count    INTEGER DEFAULT 0,
    best_rssi   INTEGER,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_points_site ON survey_points(site_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS survey_readings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    point_id  INTEGER NOT NULL,
    bssid     TEXT NOT NULL,
    ssid      TEXT,
    rssi      INTEGER,
    channel   INTEGER,
    band      TEXT,
    security  TEXT,
    FOREIGN KEY (point_id) REFERENCES survey_points(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_readings_point ON survey_readings(point_id);

CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER,
    name       TEXT NOT NULL,
    taken_at   REAL NOT NULL,
    notes      TEXT,
    bss_json   TEXT NOT NULL,
    ap_count   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_snapshots_taken ON snapshots(taken_at DESC);

CREATE TABLE IF NOT EXISTS ap_inventory (
    bssid       TEXT PRIMARY KEY,
    site_id     INTEGER,
    label       TEXT,
    location    TEXT,
    asset_tag   TEXT,
    managed     INTEGER DEFAULT 0,
    notes       TEXT,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inventory_site ON ap_inventory(site_id);

CREATE TABLE IF NOT EXISTS lan_devices (
    ip           TEXT NOT NULL,
    mac          TEXT,
    site_id      INTEGER,
    hostname     TEXT,
    vendor       TEXT,
    category     TEXT,
    label        TEXT,
    detail_json  TEXT,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    times_seen   INTEGER DEFAULT 1,
    notes        TEXT,
    PRIMARY KEY (ip, mac)
);
CREATE INDEX IF NOT EXISTS idx_lan_last_seen ON lan_devices(last_seen DESC);

CREATE TABLE IF NOT EXISTS suppressions (
    key      TEXT PRIMARY KEY,
    until_ts REAL NOT NULL
);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(DDL)
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    current = int(row["value"]) if row else 0
    if current == 0:
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        current = SCHEMA_VERSION
    if current < SCHEMA_VERSION:
        log.info("Upgrading database schema from v%d to v%d", current, SCHEMA_VERSION)
        _add_missing_columns(conn)
        conn.execute(
            "UPDATE meta SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),)
        )
    elif current > SCHEMA_VERSION:
        log.warning(
            "The database was written by a newer build (schema v%d, this build expects v%d). "
            "Update the app before writing to it.",
            current,
            SCHEMA_VERSION,
        )


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    """Additive migration: create any column the current DDL has and the file lacks."""
    wanted = {
        "bss": [
            ("station_count", "INTEGER"),
            ("utilization_pct", "REAL"),
            ("wps_manufacturer", "TEXT"),
            ("wps_model", "TEXT"),
            ("wps_device_name", "TEXT"),
            ("randomized_mac", "INTEGER DEFAULT 0"),
            ("ie_fingerprint", "TEXT"),
            ("ie_elements", "TEXT"),
            ("notes", "TEXT"),
            ("rssi_min", "INTEGER"),
            ("first_session_id", "INTEGER"),
        ],
        "observations": [
            ("station_count", "INTEGER"),
            ("utilization_pct", "REAL"),
            ("accuracy", "REAL"),
        ],
        "alerts": [("scan_id", "INTEGER"), ("acked_at", "REAL"), ("site_id", "INTEGER")],
        "sessions": [("site_id", "INTEGER")],
        "scans": [("duration_ms", "INTEGER"), ("new_bss_count", "INTEGER DEFAULT 0"),
                  ("session_id", "INTEGER"), ("adapter", "TEXT")],
    }
    for table, columns in wanted.items():
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in existing:
                log.info("Adding column %s.%s", table, name)
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def start_session(adapter_guid: str, adapter_name: str) -> int:
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO sessions(started_at, adapter_guid, adapter_name) VALUES(?,?,?)",
            (time.time(), adapter_guid, adapter_name),
        )
        return int(cur.lastrowid)


def end_session(session_id: int) -> None:
    with transaction() as conn:
        conn.execute(
            """UPDATE sessions SET
                 ended_at = ?,
                 scan_count = (SELECT COUNT(*) FROM scans WHERE session_id = sessions.id),
                 alert_count = (SELECT COUNT(*) FROM alerts a JOIN scans s
                                ON a.scan_id = s.id WHERE s.session_id = sessions.id),
                 bss_count = (SELECT COUNT(DISTINCT o.bssid) FROM observations o
                              JOIN scans s ON o.scan_id = s.id
                              WHERE s.session_id = sessions.id)
               WHERE id = ?""",
            (time.time(), session_id),
        )


def close_orphaned_sessions() -> int:
    """Close sessions the process never got to end.

    A session is opened when scanning starts and closed when it stops. If the
    app is killed or crashes in between, the row stays open for ever and shows
    as "running" long after it finished.
    """
    with transaction() as conn:
        rows = conn.execute(
            "SELECT id FROM sessions WHERE ended_at IS NULL"
        ).fetchall()
        for row in rows:
            last = conn.execute(
                "SELECT MAX(finished_at) AS t FROM scans WHERE session_id=?", (row["id"],)
            ).fetchone()
            ended = last["t"] if last and last["t"] else time.time()
            conn.execute(
                """UPDATE sessions SET
                     ended_at = ?,
                     scan_count = (SELECT COUNT(*) FROM scans WHERE session_id = sessions.id),
                     alert_count = (SELECT COUNT(*) FROM alerts a JOIN scans s
                                    ON a.scan_id = s.id WHERE s.session_id = sessions.id),
                     bss_count = (SELECT COUNT(DISTINCT o.bssid) FROM observations o
                                  JOIN scans s ON o.scan_id = s.id
                                  WHERE s.session_id = sessions.id)
                   WHERE id = ?""",
                (ended, row["id"]),
            )
        return len(rows)


def list_sessions(limit: int = 50) -> list[dict]:
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                """SELECT s.*,
                     (SELECT COUNT(*) FROM scans WHERE session_id = s.id) AS live_scans,
                     (SELECT COUNT(DISTINCT o.bssid) FROM observations o
                        JOIN scans sc ON o.scan_id = sc.id
                        WHERE sc.session_id = s.id) AS live_bss,
                     (SELECT COUNT(*) FROM alerts a JOIN scans sc ON a.scan_id = sc.id
                        WHERE sc.session_id = s.id) AS live_alerts
                   FROM sessions s ORDER BY started_at DESC LIMIT ?""",
                (limit,),
            )
        ]


def session_bssids(session_id: int) -> set[str]:
    with connection() as conn:
        return {
            r["bssid"]
            for r in conn.execute(
                """SELECT DISTINCT o.bssid FROM observations o
                   JOIN scans s ON o.scan_id = s.id WHERE s.session_id = ?""",
                (session_id,),
            )
        }


def start_scan(interface_guid: str, session_id: int | None = None,
               adapter: str | None = None) -> int:
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO scans(started_at, interface_guid, session_id, adapter) "
            "VALUES(?,?,?,?)",
            (time.time(), interface_guid, session_id, adapter),
        )
        return int(cur.lastrowid)


def finish_scan(
    scan_id: int,
    bss_count: int,
    new_bss_count: int,
    alert_count: int,
    status: str = "ok",
    error: str | None = None,
) -> None:
    now = time.time()
    with transaction() as conn:
        row = conn.execute("SELECT started_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        duration = int((now - row["started_at"]) * 1000) if row else None
        conn.execute(
            """UPDATE scans SET finished_at=?, bss_count=?, new_bss_count=?,
                   alert_count=?, status=?, error=?, duration_ms=? WHERE id=?""",
            (now, bss_count, new_bss_count, alert_count, status, error, duration, scan_id),
        )


def upsert_bss(records: Iterable[dict]) -> tuple[int, set[str]]:
    """Insert or update BSS rows. Returns (count, set of BSSIDs seen for the first time)."""
    records = list(records)
    if not records:
        return 0, set()
    new_bssids: set[str] = set()
    with transaction() as conn:
        existing: set[str] = set()
        bssids = [r["bssid"] for r in records]
        for start in range(0, len(bssids), 400):   # stay under SQLite's parameter cap
            chunk = bssids[start : start + 400]
            existing.update(
                r["bssid"]
                for r in conn.execute(
                    "SELECT bssid FROM bss WHERE bssid IN (%s)" % ",".join("?" * len(chunk)),
                    chunk,
                )
            )
        for rec in records:
            if rec["bssid"] not in existing:
                new_bssids.add(rec["bssid"])
            conn.execute(
                """
                INSERT INTO bss (
                    bssid, ssid, hidden, vendor, first_seen, last_seen, times_seen,
                    channel, band, freq_khz, width_mhz, rssi, rssi_max, rssi_min, phy,
                    security, akms, ciphers, mfp_required, mfp_capable, wps, wps_state,
                    beacon_period, country, enterprise, randomized_mac, ie_fingerprint,
                    ie_elements,
                    wps_manufacturer, wps_model, wps_device_name, station_count,
                    utilization_pct, detail_json
                ) VALUES (
                    :bssid, :ssid, :hidden, :vendor, :ts, :ts, 1,
                    :channel, :band, :freq_khz, :width_mhz, :rssi, :rssi, :rssi, :phy,
                    :security, :akms, :ciphers, :mfp_required, :mfp_capable, :wps, :wps_state,
                    :beacon_period, :country, :enterprise, :randomized_mac, :ie_fingerprint,
                    :ie_elements,
                    :wps_manufacturer, :wps_model, :wps_device_name, :station_count,
                    :utilization_pct, :detail_json
                )
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid            = excluded.ssid,
                    hidden          = excluded.hidden,
                    vendor          = COALESCE(excluded.vendor, bss.vendor),
                    last_seen       = excluded.last_seen,
                    times_seen      = bss.times_seen + 1,
                    channel         = excluded.channel,
                    band            = excluded.band,
                    freq_khz        = excluded.freq_khz,
                    width_mhz       = excluded.width_mhz,
                    rssi            = excluded.rssi,
                    rssi_max        = MAX(COALESCE(bss.rssi_max, -127), excluded.rssi),
                    rssi_min        = MIN(COALESCE(bss.rssi_min, 0), excluded.rssi),
                    phy             = excluded.phy,
                    security        = excluded.security,
                    akms            = excluded.akms,
                    ciphers         = excluded.ciphers,
                    mfp_required    = excluded.mfp_required,
                    mfp_capable     = excluded.mfp_capable,
                    wps             = excluded.wps,
                    wps_state       = excluded.wps_state,
                    beacon_period   = excluded.beacon_period,
                    country         = excluded.country,
                    enterprise      = excluded.enterprise,
                    randomized_mac  = excluded.randomized_mac,
                    ie_fingerprint  = excluded.ie_fingerprint,
                    ie_elements     = excluded.ie_elements,
                    wps_manufacturer= COALESCE(excluded.wps_manufacturer, bss.wps_manufacturer),
                    wps_model       = COALESCE(excluded.wps_model, bss.wps_model),
                    wps_device_name = COALESCE(excluded.wps_device_name, bss.wps_device_name),
                    station_count   = excluded.station_count,
                    utilization_pct = excluded.utilization_pct,
                    detail_json     = excluded.detail_json
                """,
                rec,
            )
    return len(records), new_bssids


def insert_observations(rows: Iterable[dict]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    with transaction() as conn:
        conn.executemany(
            """INSERT INTO observations
               (scan_id, bssid, ts, rssi, channel, ssid, security,
                lat, lon, alt, accuracy, station_count, utilization_pct)
               VALUES (:scan_id, :bssid, :ts, :rssi, :channel, :ssid, :security,
                       :lat, :lon, :alt, :accuracy, :station_count, :utilization_pct)""",
            rows,
        )
    return len(rows)


def insert_alerts(rows: Iterable[dict]) -> list[int]:
    rows = list(rows)
    if not rows:
        return []
    ids = []
    with transaction() as conn:
        for row in rows:
            cur = conn.execute(
                """INSERT INTO alerts (ts, rule, severity, bssid, ssid, title, detail, evidence, scan_id)
                   VALUES (:ts, :rule, :severity, :bssid, :ssid, :title, :detail, :evidence, :scan_id)""",
                row,
            )
            ids.append(int(cur.lastrowid))
    return ids


def acknowledge_alerts(ids: list[int] | None = None, all_before: float | None = None) -> int:
    now = time.time()
    with transaction() as conn:
        if ids:
            placeholders = ",".join("?" * len(ids))
            cur = conn.execute(
                f"UPDATE alerts SET acknowledged=1, acked_at=? WHERE id IN ({placeholders})",
                [now, *ids],
            )
        elif all_before is not None:
            cur = conn.execute(
                "UPDATE alerts SET acknowledged=1, acked_at=? WHERE ts<=? AND acknowledged=0",
                (now, all_before),
            )
        else:
            cur = conn.execute(
                "UPDATE alerts SET acknowledged=1, acked_at=? WHERE acknowledged=0", (now,)
            )
        return cur.rowcount


def unacknowledge_alerts(ids: list[int] | None = None, rule: str | None = None) -> int:
    """Put findings back into the open list so they can be reviewed again."""
    with transaction() as conn:
        if ids:
            placeholders = ",".join("?" * len(ids))
            cur = conn.execute(
                f"UPDATE alerts SET acknowledged=0, acked_at=NULL "
                f"WHERE id IN ({placeholders})", ids
            )
        elif rule:
            cur = conn.execute(
                "UPDATE alerts SET acknowledged=0, acked_at=NULL WHERE rule=?", (rule,)
            )
        else:
            cur = conn.execute("UPDATE alerts SET acknowledged=0, acked_at=NULL")
        return cur.rowcount


def delete_alerts(ids: list[int] | None = None, rule: str | None = None,
                  acknowledged_only: bool = False,
                  older_than_days: float | None = None) -> int:
    """Remove findings for good. Also clears their suppression so a live
    condition is reported again on the next scan rather than staying silent."""
    clauses, params = [], []
    if ids:
        clauses.append("id IN (%s)" % ",".join("?" * len(ids)))
        params += list(ids)
    if rule:
        clauses.append("rule = ?")
        params.append(rule)
    if acknowledged_only:
        clauses.append("acknowledged = 1")
    if older_than_days is not None:
        clauses.append("ts < ?")
        params.append(time.time() - older_than_days * 86400)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with transaction() as conn:
        keys = [
            f"{r['rule']}|{r['bssid'] or '-'}"
            for r in conn.execute(f"SELECT rule, bssid FROM alerts {where}", params)
        ]
        removed = conn.execute(f"DELETE FROM alerts {where}", params).rowcount
        for start in range(0, len(keys), 400):
            chunk = keys[start:start + 400]
            conn.execute(
                "DELETE FROM suppressions WHERE key IN (%s)" % ",".join("?" * len(chunk)),
                chunk,
            )
    return removed


def clear_networks(keep_marks: bool = True, keep_inventory: bool = True) -> dict:
    """Forget every observed network and its history.

    Marks and inventory are what you configured rather than what was collected,
    so they survive by default.
    """
    removed: dict[str, int] = {}
    with transaction() as conn:
        for table in ("observations", "bss", "scans", "alerts", "suppressions",
                      "sessions"):
            removed[table] = conn.execute(f"DELETE FROM {table}").rowcount
        if not keep_inventory:
            removed["ap_inventory"] = conn.execute("DELETE FROM ap_inventory").rowcount
        if not keep_marks:
            removed["marks"] = conn.execute("DELETE FROM marks").rowcount
    return removed


def wipe_everything() -> dict:
    """Delete all collected and configured data. Only the schema survives."""
    removed: dict[str, int] = {}
    tables = ("observations", "bss", "scans", "alerts", "suppressions", "sessions",
              "marks", "gps_fixes", "lan_devices", "survey_readings", "survey_points",
              "snapshots", "ap_inventory", "sites")
    with transaction() as conn:
        for table in tables:
            try:
                removed[table] = conn.execute(f"DELETE FROM {table}").rowcount
            except Exception as exc:
                log.warning("Could not clear %s: %s", table, exc)
        try:
            conn.execute("DELETE FROM sqlite_sequence")
        except Exception:
            pass
    return removed


def clear_suppressions() -> int:
    """Forget every cooldown, so all current conditions re-report immediately."""
    with transaction() as conn:
        return conn.execute("DELETE FROM suppressions").rowcount


def add_mark(kind: str, match_type: str, value: str, label: str | None = None) -> None:
    with transaction() as conn:
        conn.execute(
            """INSERT INTO marks(kind, match_type, value, label, created_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(kind, match_type, value) DO UPDATE SET label=excluded.label""",
            (kind, match_type, value.strip().lower(), label, time.time()),
        )


def delete_mark(mark_id: int) -> int:
    with transaction() as conn:
        return conn.execute("DELETE FROM marks WHERE id=?", (mark_id,)).rowcount


def list_marks() -> list[dict]:
    with connection() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM marks ORDER BY kind, value")]


def set_note(bssid: str, note: str) -> None:
    with transaction() as conn:
        conn.execute("UPDATE bss SET notes=? WHERE bssid=?", (note, bssid))


def insert_gps_fix(fix: dict) -> None:
    with transaction() as conn:
        conn.execute(
            """INSERT INTO gps_fixes(ts, lat, lon, alt, speed, course, fix_quality, satellites, hdop)
               VALUES(:ts,:lat,:lon,:alt,:speed,:course,:fix_quality,:satellites,:hdop)""",
            fix,
        )


def is_suppressed(key: str, now: float) -> bool:
    with connection() as conn:
        row = conn.execute("SELECT until_ts FROM suppressions WHERE key=?", (key,)).fetchone()
        return bool(row and row["until_ts"] > now)


def suppress(key: str, until_ts: float) -> None:
    with transaction() as conn:
        conn.execute(
            "INSERT INTO suppressions(key, until_ts) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET until_ts=excluded.until_ts",
            (key, until_ts),
        )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def list_bss(
    since: float | None = None,
    search: str | None = None,
    band: str | None = None,
    security: str | None = None,
    limit: int = 1000,
    offset: int = 0,
    order: str = "rssi",
) -> list[dict]:
    clauses, params = [], []
    if since is not None:
        clauses.append("last_seen >= ?")
        params.append(since)
    if search:
        clauses.append(
            "(LOWER(COALESCE(ssid,'')) LIKE ? OR bssid LIKE ? "
            "OR LOWER(COALESCE(vendor,'')) LIKE ?)"
        )
        term = f"%{search.lower()}%"
        params += [term, term, term]
    if band:
        clauses.append("band = ?")
        params.append(band)
    if security:
        clauses.append("security = ?")
        params.append(security)

    order_sql = {
        "rssi": "rssi DESC",
        "ssid": "ssid COLLATE NOCASE ASC",
        "channel": "band ASC, channel ASC",
        "last_seen": "last_seen DESC",
        "first_seen": "first_seen DESC",
        "times_seen": "times_seen DESC",
    }.get(order, "rssi DESC")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM bss {where} ORDER BY {order_sql} LIMIT ? OFFSET ?"
    params += [max(1, min(limit, 5000)), max(0, offset)]
    with connection() as conn:
        return [dict(r) for r in conn.execute(sql, params)]


def get_bss_many(bssids: list[str]) -> dict[str, dict]:
    """Fetch just the rows a scan touched, rather than reading the whole table."""
    out: dict[str, dict] = {}
    if not bssids:
        return out
    with connection() as conn:
        for start in range(0, len(bssids), 400):
            chunk = bssids[start : start + 400]
            for row in conn.execute(
                "SELECT * FROM bss WHERE bssid IN (%s)" % ",".join("?" * len(chunk)), chunk
            ):
                out[row["bssid"]] = dict(row)
    return out


def watched_candidates() -> list[dict]:
    """Lightweight row set for the 'watched AP has gone quiet' rule."""
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT bssid, ssid, last_seen FROM bss ORDER BY last_seen DESC LIMIT 5000"
            )
        ]


def suppress_many(pairs: list[tuple[str, float]]) -> None:
    """Write every suppression in one transaction instead of one each."""
    if not pairs:
        return
    with transaction() as conn:
        conn.executemany(
            "INSERT INTO suppressions(key, until_ts) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET until_ts=excluded.until_ts",
            pairs,
        )


def suppressed_keys(keys: list[str], now: float) -> set[str]:
    """One query for every key rather than a round trip per finding."""
    if not keys:
        return set()
    found: set[str] = set()
    with connection() as conn:
        for start in range(0, len(keys), 400):
            chunk = keys[start : start + 400]
            for row in conn.execute(
                "SELECT key FROM suppressions WHERE until_ts > ? AND key IN (%s)"
                % ",".join("?" * len(chunk)),
                [now, *chunk],
            ):
                found.add(row["key"])
    return found


def count_bss(since: float | None = None) -> int:
    with connection() as conn:
        if since is None:
            row = conn.execute("SELECT COUNT(*) c FROM bss").fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) c FROM bss WHERE last_seen>=?", (since,)).fetchone()
        return int(row["c"])


def get_bss(bssid: str) -> dict | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM bss WHERE bssid=?", (bssid.lower(),)).fetchone()
        return dict(row) if row else None


def bss_history(bssid: str, limit: int = 500) -> list[dict]:
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT ts, rssi, channel, ssid, security, lat, lon, station_count, "
                "utilization_pct FROM observations WHERE bssid=? ORDER BY ts DESC LIMIT ?",
                (bssid.lower(), max(1, min(limit, 5000))),
            )
        ]


def recent_observations(bssid: str, count: int) -> list[dict]:
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT rssi, channel, security, ssid FROM observations "
                "WHERE bssid=? ORDER BY ts DESC LIMIT ?",
                (bssid, count),
            )
        ]


def list_alerts(
    limit: int = 200,
    offset: int = 0,
    severity: str | None = None,
    rule: str | None = None,
    unacked_only: bool = False,
    since: float | None = None,
) -> list[dict]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if rule:
        clauses.append("rule = ?")
        params.append(rule)
    if unacked_only:
        clauses.append("acknowledged = 0")
    if since is not None:
        clauses.append("ts >= ?")
        params.append(since)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params += [max(1, min(limit, 2000)), max(0, offset)]
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ? OFFSET ?", params
            )
        ]


def alert_counts() -> dict:
    with connection() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) c FROM alerts WHERE acknowledged=0 GROUP BY severity"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    out = {r["severity"]: r["c"] for r in rows}
    out["total"] = int(total)
    out["unacked"] = sum(v for k, v in out.items() if k != "total")
    return out


def recent_scans(limit: int = 50) -> list[dict]:
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        ]


def ssid_groups(since: float | None = None) -> list[dict]:
    clause = "WHERE last_seen >= ?" if since is not None else ""
    params = [since] if since is not None else []
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                f"""SELECT COALESCE(NULLIF(ssid,''), '<hidden>') AS ssid,
                           COUNT(*) AS bss_count,
                           MAX(rssi) AS best_rssi,
                           GROUP_CONCAT(DISTINCT security) AS securities,
                           GROUP_CONCAT(DISTINCT band) AS bands,
                           MAX(last_seen) AS last_seen
                    FROM bss {clause}
                    GROUP BY COALESCE(NULLIF(ssid,''), '<hidden>')
                    ORDER BY best_rssi DESC""",
                params,
            )
        ]


def normalise_guid(value: str | None) -> str:
    """An interface GUID with the braces and case taken off.

    Windows hands the same GUID back in more than one spelling depending on
    which API produced it, and comparing the raw strings silently matched
    nothing — which is how a 6 GHz-capable adapter ended up being described as
    2.4/5 GHz despite the database holding its 6 GHz observations.
    """
    return (value or "").strip().strip("{}").lower()


def observed_bands(adapter_guid: str | None = None, days: int = 7) -> list[str]:
    """Bands we have actually received beacons on. If a 6 GHz BSS came back,
    the adapter supports 6 GHz whatever the driver claims."""
    since = time.time() - days * 86400
    sql = """SELECT DISTINCT b.band FROM bss b
             JOIN observations o ON o.bssid = b.bssid
             JOIN scans s ON s.id = o.scan_id
             WHERE b.band IS NOT NULL AND b.band != 'unknown' AND o.ts >= ?"""
    params: list = [since]
    if adapter_guid:
        sql += (" AND REPLACE(REPLACE(LOWER(s.interface_guid), '{', ''), '}', '')"
                " = ?")
        params.append(normalise_guid(adapter_guid))
    with connection() as conn:
        bands = [r["band"] for r in conn.execute(sql, params)]
    return sorted(bands, key=lambda b: float(b) if b.replace(".", "").isdigit() else 99)


def ssid_grouped(since: float | None = None, limit: int = 500) -> list[dict]:
    limit = max(1, min(int(limit), 5000))
    """One row per network name, with each radio serving it.

    A modern AP puts the same SSID on 2.4, 5 and 6 GHz with a different BSSID
    per band, so listing BSSIDs flat makes one network look like three.
    """
    clauses = []
    params: list = []
    if since is not None:
        clauses.append("last_seen >= ?")
        params.append(since)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM bss {where} ORDER BY rssi DESC", params
        )]

    groups: dict[str, dict] = {}
    for row in rows:
        ssid = row.get("ssid") or ""
        hidden = bool(row.get("hidden"))
        # Hidden networks have no name to group on, so each radio stands alone.
        key = f"\x00hidden:{row['bssid']}" if hidden or not ssid else ssid
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "ssid": ssid,
                "hidden": hidden,
                "key": key,
                "radios": [],
                "bands": [],
                "channels": [],
                "securities": [],
                "vendors": [],
                "best_rssi": -127,
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "enterprise": False,
                "wps": False,
                "mfp_required": True,
                "times_seen": 0,
            }
        group["radios"].append({
            "bssid": row["bssid"], "band": row["band"], "channel": row["channel"],
            "rssi": row["rssi"], "width_mhz": row["width_mhz"], "phy": row["phy"],
            "security": row["security"], "vendor": row["vendor"],
            "last_seen": row["last_seen"], "wps": bool(row["wps"]),
            "mfp_required": bool(row["mfp_required"]),
            "utilization_pct": row["utilization_pct"],
        })
        if row["band"] and row["band"] not in group["bands"]:
            group["bands"].append(row["band"])
        if row["channel"] is not None and row["channel"] not in group["channels"]:
            group["channels"].append(row["channel"])
        # "WPA2" alone hides a PSK-vs-802.1X split, which is exactly the
        # difference worth noticing under one name.
        posture = row["security"] or ""
        if row["enterprise"] and posture:
            posture = f"{posture} (802.1X)"
        if posture and posture not in group["securities"]:
            group["securities"].append(posture)
        if row["vendor"] and row["vendor"] not in group["vendors"]:
            group["vendors"].append(row["vendor"])
        group["best_rssi"] = max(group["best_rssi"], row["rssi"] or -127)
        group["first_seen"] = min(group["first_seen"], row["first_seen"])
        group["last_seen"] = max(group["last_seen"], row["last_seen"])
        group["enterprise"] = group["enterprise"] or bool(row["enterprise"])
        group["wps"] = group["wps"] or bool(row["wps"])
        group["mfp_required"] = group["mfp_required"] and bool(row["mfp_required"])
        group["times_seen"] += row["times_seen"] or 0

    out = []
    for group in groups.values():
        group["bands"].sort(key=lambda b: float(b) if b and b[0].isdigit() else 99)
        group["channels"].sort()
        group["radio_count"] = len(group["radios"])
        group["band_count"] = len(group["bands"])
        # More than one security posture under one name is the evil-twin shape.
        group["mixed_security"] = len(group["securities"]) > 1
        group["tri_band"] = len(group["bands"]) >= 3
        out.append(group)
    out.sort(key=lambda g: -g["best_rssi"])
    return out[:limit]


def channel_usage(since: float | None = None) -> list[dict]:
    clauses = ["channel IS NOT NULL"]
    params: list = []
    if since is not None:
        clauses.append("last_seen >= ?")
        params.append(since)
    sql = f"""SELECT band, channel, COUNT(*) AS count, MAX(rssi) AS best_rssi,
                     AVG(utilization_pct) AS avg_utilization
              FROM bss WHERE {' AND '.join(clauses)}
              GROUP BY band, channel ORDER BY band, channel"""
    with connection() as conn:
        return [dict(r) for r in conn.execute(sql, params)]


def stats() -> dict:
    with connection() as conn:
        row = conn.execute(
            """SELECT
                 (SELECT COUNT(*) FROM bss) AS total_bss,
                 (SELECT COUNT(DISTINCT ssid) FROM bss WHERE ssid<>'') AS total_ssids,
                 (SELECT COUNT(*) FROM observations) AS total_observations,
                 (SELECT COUNT(*) FROM alerts) AS total_alerts,
                 (SELECT COUNT(*) FROM alerts WHERE acknowledged=0) AS open_alerts,
                 (SELECT COUNT(*) FROM scans) AS total_scans,
                 (SELECT MIN(first_seen) FROM bss) AS first_seen,
                 (SELECT MAX(last_seen) FROM bss) AS last_seen"""
        ).fetchone()
        return dict(row)


def db_size_bytes() -> int:
    if _db_path is None:
        return 0
    total = 0
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(_db_path) + suffix)
        if p.exists():
            total += p.stat().st_size
    return total


def prune(observation_days: int, alert_days: int, gps_days: int) -> dict:
    now = time.time()
    removed = {}
    with transaction() as conn:
        cur = conn.execute(
            "DELETE FROM observations WHERE ts < ?", (now - observation_days * 86400,)
        )
        removed["observations"] = cur.rowcount
        cur = conn.execute(
            "DELETE FROM alerts WHERE ts < ? AND acknowledged=1", (now - alert_days * 86400,)
        )
        removed["alerts"] = cur.rowcount
        cur = conn.execute("DELETE FROM gps_fixes WHERE ts < ?", (now - gps_days * 86400,))
        removed["gps_fixes"] = cur.rowcount
        cur = conn.execute(
            "DELETE FROM scans WHERE started_at < ?", (now - observation_days * 86400,)
        )
        removed["scans"] = cur.rowcount
        cur = conn.execute("DELETE FROM suppressions WHERE until_ts < ?", (now,))
        removed["suppressions"] = cur.rowcount
        cur = conn.execute(
            "DELETE FROM sessions WHERE started_at < ? AND ended_at IS NOT NULL",
            (now - observation_days * 86400,),
        )
        removed["sessions"] = cur.rowcount
    return removed


def vacuum() -> None:
    with connection() as conn:
        conn.execute("VACUUM")


def export_rows(table: str) -> list[dict]:
    if table not in {"bss", "observations", "alerts", "marks", "scans", "gps_fixes",
                     "sessions", "sites", "survey_points", "survey_readings",
                     "ap_inventory", "snapshots", "lan_devices"}:
        raise ValueError(f"'{table}' is not an exportable table")
    with connection() as conn:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]


# ---------------------------------------------------------------------------
# Discovered LAN devices
# ---------------------------------------------------------------------------


def record_devices(devices: list[dict], site_id: int | None = None) -> int:
    """Store a discovery pass so devices accumulate a first/last seen history."""
    if not devices:
        return 0
    now = time.time()
    with transaction() as conn:
        for device in devices:
            conn.execute(
                """INSERT INTO lan_devices
                     (ip, mac, site_id, hostname, vendor, category, label,
                      detail_json, first_seen, last_seen, times_seen)
                   VALUES(:ip,:mac,:site_id,:hostname,:vendor,:category,:label,
                          :detail,:ts,:ts,1)
                   ON CONFLICT(ip, mac) DO UPDATE SET
                     hostname   = COALESCE(excluded.hostname, lan_devices.hostname),
                     vendor     = COALESCE(excluded.vendor, lan_devices.vendor),
                     category   = excluded.category,
                     label      = excluded.label,
                     detail_json= excluded.detail_json,
                     last_seen  = excluded.last_seen,
                     site_id    = COALESCE(excluded.site_id, lan_devices.site_id),
                     times_seen = lan_devices.times_seen + 1""",
                {
                    "ip": device.get("ip"), "mac": device.get("mac") or "",
                    "site_id": site_id, "hostname": device.get("hostname"),
                    "vendor": device.get("vendor"), "category": device.get("category"),
                    "label": device.get("label"),
                    "detail": json_dumps({
                        k: v for k, v in device.items()
                        if k in ("names", "services", "netbios", "server", "location",
                                 "state", "interface", "randomized_mac", "sources",
                                 "category_label")
                    }),
                    "ts": now,
                },
            )
    return len(devices)


def list_devices(site_id: int | None = None, minutes: float | None = None,
                 limit: int = 1000) -> list[dict]:
    clauses, params = [], []
    if site_id is not None:
        clauses.append("site_id = ?")
        params.append(site_id)
    if minutes:
        clauses.append("last_seen >= ?")
        params.append(time.time() - minutes * 60)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(limit, 5000)))
    with connection() as conn:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM lan_devices {where} ORDER BY last_seen DESC LIMIT ?", params
        )]


def set_device_note(ip: str, mac: str, note: str) -> None:
    with transaction() as conn:
        conn.execute(
            "UPDATE lan_devices SET notes=? WHERE ip=? AND mac=?", (note, ip, mac or "")
        )


def forget_devices(older_than_days: float | None = None) -> int:
    with transaction() as conn:
        if older_than_days is None:
            return conn.execute("DELETE FROM lan_devices").rowcount
        cutoff = time.time() - older_than_days * 86400
        return conn.execute(
            "DELETE FROM lan_devices WHERE last_seen < ?", (cutoff,)
        ).rowcount


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------


def create_site(name: str, client: str = "", address: str = "",
                contact: str = "", notes: str = "") -> int:
    with transaction() as conn:
        cur = conn.execute(
            """INSERT INTO sites(name, client, address, contact, notes, created_at)
               VALUES(?,?,?,?,?,?)""",
            (name.strip(), client, address, contact, notes, time.time()),
        )
        return int(cur.lastrowid)


def list_sites(include_archived: bool = False) -> list[dict]:
    clause = "" if include_archived else "WHERE archived = 0"
    with connection() as conn:
        return [
            dict(r)
            for r in conn.execute(
                f"""SELECT s.*,
                      (SELECT COUNT(*) FROM survey_points WHERE site_id = s.id) AS point_count,
                      (SELECT COUNT(*) FROM ap_inventory WHERE site_id = s.id) AS ap_count
                    FROM sites s {clause} ORDER BY created_at DESC"""
            )
        ]


def get_site(site_id: int) -> dict | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
        return dict(row) if row else None


def update_site(site_id: int, fields: dict) -> bool:
    allowed = {"name", "client", "address", "contact", "notes", "archived"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    assignments = ", ".join(f"{k}=?" for k in updates)
    with transaction() as conn:
        cur = conn.execute(
            f"UPDATE sites SET {assignments} WHERE id=?", [*updates.values(), site_id]
        )
        return cur.rowcount > 0


def delete_site(site_id: int) -> bool:
    with transaction() as conn:
        return conn.execute("DELETE FROM sites WHERE id=?", (site_id,)).rowcount > 0


# ---------------------------------------------------------------------------
# Survey points
# ---------------------------------------------------------------------------


def add_survey_point(name: str, readings: list[dict], site_id: int | None = None,
                     floor: str = "", notes: str = "", scan_id: int | None = None,
                     lat: float | None = None, lon: float | None = None) -> int:
    """Record what the radio hears at one named location."""
    rssis = [r["rssi"] for r in readings if r.get("rssi") is not None]
    with transaction() as conn:
        cur = conn.execute(
            """INSERT INTO survey_points
                 (site_id, name, floor, notes, captured_at, scan_id, lat, lon,
                  ap_count, best_rssi)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (site_id, name.strip(), floor, notes, time.time(), scan_id, lat, lon,
             len(readings), max(rssis) if rssis else None),
        )
        point_id = int(cur.lastrowid)
        if readings:
            conn.executemany(
                """INSERT INTO survey_readings
                     (point_id, bssid, ssid, rssi, channel, band, security)
                   VALUES(?,?,?,?,?,?,?)""",
                [(point_id, r["bssid"], r.get("ssid"), r.get("rssi"), r.get("channel"),
                  r.get("band"), r.get("security")) for r in readings],
            )
    return point_id


def list_survey_points(site_id: int | None = None) -> list[dict]:
    clause = "WHERE site_id = ?" if site_id is not None else ""
    params = [site_id] if site_id is not None else []
    with connection() as conn:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM survey_points {clause} ORDER BY captured_at DESC", params
        )]


def survey_point_readings(point_id: int) -> list[dict]:
    with connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM survey_readings WHERE point_id=? ORDER BY rssi DESC", (point_id,)
        )]


def delete_survey_point(point_id: int) -> bool:
    with transaction() as conn:
        conn.execute("DELETE FROM survey_readings WHERE point_id=?", (point_id,))
        return conn.execute(
            "DELETE FROM survey_points WHERE id=?", (point_id,)
        ).rowcount > 0


def coverage_matrix(site_id: int | None = None, ssid: str | None = None) -> dict:
    """Signal for each tracked network at each surveyed location."""
    points = list_survey_points(site_id)
    if not points:
        return {"points": [], "networks": [], "matrix": {}}

    point_ids = [p["id"] for p in points]
    placeholders = ",".join("?" * len(point_ids))
    params: list = list(point_ids)
    clause = ""
    if ssid:
        clause = " AND ssid = ?"
        params.append(ssid)

    with connection() as conn:
        rows = [dict(r) for r in conn.execute(
            f"""SELECT point_id, ssid, bssid, band, channel, MAX(rssi) AS rssi
                FROM survey_readings
                WHERE point_id IN ({placeholders}){clause}
                GROUP BY point_id, ssid, band""",
            params,
        )]

    networks: dict[str, dict] = {}
    matrix: dict[str, dict[str, int]] = {}
    for row in rows:
        name = row["ssid"] or "(hidden)"
        key = f"{name}|{row['band']}"
        networks.setdefault(key, {
            "ssid": name, "band": row["band"], "key": key, "seen_at": 0,
        })
        matrix.setdefault(key, {})[str(row["point_id"])] = row["rssi"]
        networks[key]["seen_at"] += 1

    ordered = sorted(networks.values(), key=lambda n: -n["seen_at"])
    return {"points": points, "networks": ordered, "matrix": matrix}


# ---------------------------------------------------------------------------
# AP inventory
# ---------------------------------------------------------------------------


def set_inventory(bssid: str, fields: dict) -> None:
    bssid = bssid.lower()
    with transaction() as conn:
        conn.execute(
            """INSERT INTO ap_inventory
                 (bssid, site_id, label, location, asset_tag, managed, notes, updated_at)
               VALUES(:bssid,:site_id,:label,:location,:asset_tag,:managed,:notes,:updated_at)
               ON CONFLICT(bssid) DO UPDATE SET
                 site_id   = COALESCE(excluded.site_id, ap_inventory.site_id),
                 label     = COALESCE(excluded.label, ap_inventory.label),
                 location  = COALESCE(excluded.location, ap_inventory.location),
                 asset_tag = COALESCE(excluded.asset_tag, ap_inventory.asset_tag),
                 managed   = excluded.managed,
                 notes     = COALESCE(excluded.notes, ap_inventory.notes),
                 updated_at= excluded.updated_at""",
            {
                "bssid": bssid,
                "site_id": fields.get("site_id"),
                "label": fields.get("label"),
                "location": fields.get("location"),
                "asset_tag": fields.get("asset_tag"),
                "managed": int(bool(fields.get("managed", False))),
                "notes": fields.get("notes"),
                "updated_at": time.time(),
            },
        )


def get_inventory(site_id: int | None = None) -> list[dict]:
    clause = "WHERE i.site_id = ?" if site_id is not None else ""
    params = [site_id] if site_id is not None else []
    with connection() as conn:
        return [dict(r) for r in conn.execute(
            f"""SELECT i.*, b.ssid, b.band, b.channel, b.rssi, b.vendor, b.security,
                       b.last_seen, b.phy
                FROM ap_inventory i LEFT JOIN bss b ON b.bssid = i.bssid
                {clause} ORDER BY i.label, i.bssid""",
            params,
        )]


def inventory_for(bssid: str) -> dict | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM ap_inventory WHERE bssid=?", (bssid.lower(),)
        ).fetchone()
        return dict(row) if row else None


def delete_inventory(bssid: str) -> bool:
    with transaction() as conn:
        return conn.execute(
            "DELETE FROM ap_inventory WHERE bssid=?", (bssid.lower(),)
        ).rowcount > 0


# ---------------------------------------------------------------------------
# Snapshots (before / after comparison)
# ---------------------------------------------------------------------------


def take_snapshot(name: str, site_id: int | None = None, notes: str = "",
                  minutes: float = 15) -> int:
    """Freeze the current picture so a later scan can be compared against it."""
    since = time.time() - minutes * 60
    rows = list_bss(since=since, limit=5000)
    payload = [
        {k: r.get(k) for k in
         ("bssid", "ssid", "hidden", "vendor", "band", "channel", "width_mhz",
          "rssi", "security", "phy", "wps", "enterprise", "mfp_required")}
        for r in rows
    ]
    with transaction() as conn:
        cur = conn.execute(
            """INSERT INTO snapshots(site_id, name, taken_at, notes, bss_json, ap_count)
               VALUES(?,?,?,?,?,?)""",
            (site_id, name.strip(), time.time(), notes, json_dumps(payload), len(payload)),
        )
        return int(cur.lastrowid)


def list_snapshots(site_id: int | None = None) -> list[dict]:
    clause = "WHERE site_id = ?" if site_id is not None else ""
    params = [site_id] if site_id is not None else []
    with connection() as conn:
        return [
            {k: v for k, v in dict(r).items() if k != "bss_json"}
            for r in conn.execute(
                f"SELECT * FROM snapshots {clause} ORDER BY taken_at DESC", params
            )
        ]


def get_snapshot(snapshot_id: int) -> dict | None:
    import json as _json

    with connection() as conn:
        row = conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not row:
        return None
    out = dict(row)
    try:
        out["bss"] = _json.loads(out.pop("bss_json"))
    except (ValueError, TypeError):
        out["bss"] = []
    return out


def delete_snapshot(snapshot_id: int) -> bool:
    with transaction() as conn:
        return conn.execute(
            "DELETE FROM snapshots WHERE id=?", (snapshot_id,)
        ).rowcount > 0


def json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)

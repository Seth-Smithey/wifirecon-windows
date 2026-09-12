"""
Exports.

CSV and JSON for the raw tables, WiGLE-format CSV and KML for anything captured
with a GPS fix, and a self-contained HTML survey report.
"""

from __future__ import annotations

import csv
import html
import io
import json
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from . import db

WIGLE_HEADER_PRE = (
    "WigleWifi-1.6,appRelease=wifirecon-win,model=NativeWifi,"
    "release=1.0,device=windows,display=,board=,brand=wifirecon"
)
WIGLE_COLUMNS = [
    "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "Frequency",
    "RSSI", "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
    "AccuracyMeters", "RCOIs", "MfgrId", "Type",
]


def _iso(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def rows_to_csv(rows: Iterable[dict], columns: list[str] | None = None) -> str:
    rows = list(rows)
    if not rows:
        return ""
    columns = columns or list(rows[0].keys())
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _flatten(row.get(k)) for k in columns})
    return buffer.getvalue()


def _flatten(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), default=str)
    return value


def bss_csv() -> str:
    columns = [
        "bssid", "ssid", "hidden", "vendor", "security", "akms", "ciphers",
        "band", "channel", "width_mhz", "freq_khz", "phy", "rssi", "rssi_max",
        "rssi_min", "mfp_required", "mfp_capable", "wps", "wps_state",
        "wps_manufacturer", "wps_model", "enterprise", "randomized_mac",
        "beacon_period", "country", "station_count", "utilization_pct",
        "times_seen", "first_seen", "last_seen", "notes",
    ]
    rows = db.export_rows("bss")
    for row in rows:
        row["first_seen"] = _iso(row.get("first_seen"))
        row["last_seen"] = _iso(row.get("last_seen"))
    return rows_to_csv(rows, columns)


def alerts_csv() -> str:
    columns = ["ts", "severity", "rule", "title", "bssid", "ssid", "detail",
               "evidence", "acknowledged"]
    rows = db.export_rows("alerts")
    for row in rows:
        row["ts"] = _iso(row.get("ts"))
    return rows_to_csv(rows, columns)


def observations_csv(limit: int | None = None) -> str:
    rows = db.export_rows("observations")
    if limit:
        rows = rows[-limit:]
    for row in rows:
        row["ts"] = _iso(row.get("ts"))
    return rows_to_csv(rows)


def wigle_csv() -> str:
    """WiGLE 1.6 CSV. Only rows with a position are useful, so those come first."""
    lines = [WIGLE_HEADER_PRE, ",".join(WIGLE_COLUMNS)]
    seen: set[str] = set()

    with db.connection() as conn:
        rows = conn.execute(
            """SELECT o.bssid, o.ssid, o.ts, o.channel, o.rssi, o.lat, o.lon, o.alt,
                      o.accuracy, b.security, b.freq_khz, b.akms, b.wps
               FROM observations o
               LEFT JOIN bss b ON b.bssid = o.bssid
               WHERE o.lat IS NOT NULL AND o.lon IS NOT NULL
               ORDER BY o.ts ASC"""
        ).fetchall()

    for row in rows:
        if row["bssid"] in seen:
            continue
        seen.add(row["bssid"])
        auth = _wigle_auth(row["security"], row["akms"], row["wps"])
        lines.append(
            ",".join(
                _csv_escape(v)
                for v in [
                    row["bssid"].upper(),
                    row["ssid"] or "",
                    auth,
                    datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
                    row["channel"] or "",
                    round((row["freq_khz"] or 0) / 1000) or "",
                    row["rssi"] or "",
                    row["lat"],
                    row["lon"],
                    row["alt"] if row["alt"] is not None else 0,
                    row["accuracy"] if row["accuracy"] is not None else 0,
                    "",
                    "",
                    "WIFI",
                ]
            )
        )
    return "\n".join(lines) + "\n"


def _wigle_auth(security: str | None, akms_json: str | None, wps: int | None) -> str:
    parts = []
    security = security or "Open"
    if security == "Open":
        parts.append("[ESS]")
        return "".join(parts)
    try:
        akms = json.loads(akms_json) if akms_json else []
    except (json.JSONDecodeError, TypeError):
        akms = []
    if "SAE" in akms or "FT-SAE" in akms:
        parts.append("[WPA3-SAE-CCMP]")
    if "PSK" in akms or "FT-PSK" in akms:
        parts.append("[WPA2-PSK-CCMP]")
    if any("802.1X" in a for a in akms):
        parts.append("[WPA2-EAP-CCMP]")
    if security == "WEP":
        parts.append("[WEP]")
    if wps:
        parts.append("[WPS]")
    parts.append("[ESS]")
    return "".join(parts) or "[ESS]"


def _csv_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in (",", '"', "\n")):
        return '"' + text.replace('"', '""') + '"'
    return text


def kml() -> str:
    """Placemarks for every BSS that was seen with a position."""
    with db.connection() as conn:
        rows = conn.execute(
            """SELECT o.bssid, o.ssid, AVG(o.lat) lat, AVG(o.lon) lon,
                      MAX(o.rssi) rssi, b.security, b.channel, b.vendor
               FROM observations o
               LEFT JOIN bss b ON b.bssid = o.bssid
               WHERE o.lat IS NOT NULL AND o.lon IS NOT NULL
               GROUP BY o.bssid"""
        ).fetchall()

    styles = {
        "Open": "ff0000ff",
        "WEP": "ff0080ff",
        "WPA": "ff00ffff",
        "WPA2": "ff00ff00",
        "WPA3": "ffff8000",
    }
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
        "<name>wifirecon survey</name>",
    ]
    for name, colour in styles.items():
        parts.append(
            f'<Style id="s{name}"><IconStyle><color>{colour}</color>'
            f"<scale>0.8</scale></IconStyle></Style>"
        )
    for row in rows:
        style = f"#s{row['security']}" if row["security"] in styles else "#sWPA2"
        label = html.escape(row["ssid"] or row["bssid"])
        description = html.escape(
            f"BSSID {row['bssid']} | {row['security']} | ch {row['channel']} | "
            f"{row['rssi']} dBm | {row['vendor'] or 'unknown vendor'}"
        )
        parts.append(
            f"<Placemark><name>{label}</name><description>{description}</description>"
            f"<styleUrl>{style}</styleUrl>"
            f"<Point><coordinates>{row['lon']},{row['lat']},0</coordinates></Point></Placemark>"
        )
    parts.append("</Document></kml>")
    return "\n".join(parts)


def full_json() -> str:
    return json.dumps(
        {
            "generated_at": _iso(time.time()),
            "generator": "wifirecon-win",
            "stats": db.stats(),
            "bss": db.export_rows("bss"),
            "alerts": db.export_rows("alerts"),
            "marks": db.export_rows("marks"),
            "scans": db.export_rows("scans")[-500:],
        },
        indent=2,
        default=str,
    )


def html_report() -> str:
    """A single-file survey report you can hand to someone else."""
    stats = db.stats()
    bss = db.list_bss(limit=2000, order="rssi")
    alerts = db.list_alerts(limit=200)
    counts = db.alert_counts()

    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    severity_colours = {
        "critical": "#ff4d6d", "high": "#ff9f45", "medium": "#ffd166",
        "low": "#7ad7f0", "info": "#8b95a5",
    }

    rows = "\n".join(
        f"<tr><td class=mono>{esc(b['bssid'])}</td><td>{esc(b['ssid'] or '(hidden)')}</td>"
        f"<td>{esc(b['vendor'])}</td><td>{esc(b['security'])}</td>"
        f"<td>{esc(b['band'])} / {esc(b['channel'])}</td><td>{esc(b['rssi'])} dBm</td>"
        f"<td>{esc(b['phy'])}</td><td>{'yes' if b['wps'] else ''}</td>"
        f"<td>{esc(_iso(b['last_seen']))}</td></tr>"
        for b in bss
    )
    alert_rows = "\n".join(
        f"<tr><td style='color:{severity_colours.get(a['severity'], '#fff')}'>"
        f"{esc(a['severity'])}</td><td>{esc(a['rule'])}</td><td>{esc(a['title'])}</td>"
        f"<td class=mono>{esc(a['bssid'])}</td><td>{esc(_iso(a['ts']))}</td></tr>"
        for a in alerts
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>wifirecon survey report</title>
<style>
 body {{ background:#0d1117; color:#c9d1d9; font:14px/1.5 "Segoe UI",system-ui,sans-serif;
        margin:0; padding:32px; }}
 h1 {{ font-size:24px; letter-spacing:-0.02em; margin:0 0 4px; }}
 h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:0.08em;
       color:#7d8590; margin:32px 0 12px; }}
 .meta {{ color:#7d8590; font-size:13px; margin-bottom:24px; }}
 .cards {{ display:flex; gap:16px; flex-wrap:wrap; }}
 .card {{ background:#161b22; border:1px solid #21262d; border-radius:8px;
          padding:14px 18px; min-width:120px; }}
 .card b {{ display:block; font-size:24px; font-variant-numeric:tabular-nums; }}
 .card span {{ color:#7d8590; font-size:12px; }}
 table {{ width:100%; border-collapse:collapse; font-size:13px; }}
 th {{ text-align:left; color:#7d8590; font-weight:600; padding:8px;
       border-bottom:1px solid #21262d; position:sticky; top:0; background:#0d1117; }}
 td {{ padding:7px 8px; border-bottom:1px solid #161b22; }}
 tr:hover td {{ background:#161b22; }}
 .mono {{ font-family:"Cascadia Code",Consolas,monospace; font-size:12px; }}
</style></head><body>
<h1>Wireless survey report</h1>
<div class="meta">Generated {esc(_iso(time.time()))} &middot; wifirecon-win</div>
<div class="cards">
  <div class="card"><b>{stats['total_bss']}</b><span>access points</span></div>
  <div class="card"><b>{stats['total_ssids']}</b><span>network names</span></div>
  <div class="card"><b>{stats['total_scans']}</b><span>scans</span></div>
  <div class="card"><b>{counts.get('unacked', 0)}</b><span>open findings</span></div>
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>BSSID</th>
<th>Time</th></tr></thead><tbody>{alert_rows or '<tr><td colspan=5>Nothing flagged.</td></tr>'}</tbody></table>
<h2>Access points</h2>
<table><thead><tr><th>BSSID</th><th>Name</th><th>Vendor</th><th>Security</th>
<th>Band / ch</th><th>Signal</th><th>PHY</th><th>WPS</th><th>Last seen</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""

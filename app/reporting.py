"""
Client-facing report generation.

The HTML export in exporters.py is a data dump. This is the thing you hand to a
client: an executive summary they can read, findings ranked by what matters, a
channel plan, coverage results, and recommendations. Styled to print cleanly to
PDF from the browser.
"""

from __future__ import annotations

import html
import time
from datetime import datetime
from typing import Any

from . import db, survey

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_COLOUR = {
    "critical": "#b3123c", "high": "#c2410c", "medium": "#a16207",
    "low": "#1d4ed8", "info": "#525252",
}

# Plain-language explanations so a non-technical reader understands the finding.
RULE_EXPLANATIONS = {
    "weak_crypto": "Encryption in use is outdated and can be broken with commonly "
                   "available tools.",
    "wps_enabled": "Wi-Fi Protected Setup is enabled. Its PIN method is brute-forceable "
                   "and gives an attacker the network password.",
    "pmf_missing": "Management frames are unprotected, so client devices can be forcibly "
                   "disconnected by anyone in range.",
    "open_network": "No encryption. Traffic on this network is readable by anyone nearby.",
    "ssid_conflict": "One network name is being served with inconsistent security, which "
                     "is how an impersonation attack looks.",
    "lookalike_ssid": "A nearby network is using a name almost identical to a legitimate "
                      "one, which is a targeted impersonation attempt.",
    "enterprise_downgrade_bait": "A network name normally requiring certificate "
                                 "authentication is also offered without it. This is a "
                                 "credential-harvesting setup.",
    "rogue_ap": "An access point is present that is not part of the managed estate.",
    "channel_congestion": "This channel is heavily used, which reduces throughput for "
                          "everyone on it.",
    "adjacent_channel_overlap": "Wide channels in the 2.4 GHz band consume spectrum that "
                                "neighbouring networks need.",
    "wps_device_disclosure": "The access point broadcasts its make and model, which tells "
                             "an attacker which vulnerabilities to try.",
}


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _iso(ts: float | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts).strftime("%d %B %Y at %H:%M")


def build(
    site_id: int | None = None,
    title: str = "Wireless Site Survey",
    prepared_by: str = "",
    minutes: float = 1440,
    include_inventory: bool = True,
    include_coverage: bool = True,
    include_plan: bool = True,
) -> str:
    """Assemble the full report as a single self-contained HTML file."""
    site = db.get_site(site_id) if site_id else None
    since = time.time() - minutes * 60 if minutes else None

    networks = db.list_bss(since=since, limit=2000, order="rssi")
    groups = db.ssid_grouped(since, limit=500)
    alerts = [a for a in db.list_alerts(limit=500, since=since) if not a["acknowledged"]]
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))

    plan = survey.channel_plan(minutes=minutes) if include_plan else None
    coverage = survey.coverage_report(site_id) if include_coverage else None
    inventory = db.get_inventory(site_id) if include_inventory else []

    bands = {}
    for network in networks:
        bands[network.get("band") or "unknown"] = bands.get(network.get("band") or "unknown", 0) + 1

    severity_counts: dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert["severity"]] = severity_counts.get(alert["severity"], 0) + 1

    sections = [
        _header(title, site, prepared_by),
        _executive_summary(networks, groups, alerts, severity_counts, coverage, bands),
        _findings(alerts),
    ]
    if include_plan and plan:
        sections.append(_channel_plan(plan))
    if include_coverage and coverage and coverage["points"]:
        sections.append(_coverage(coverage))
    if include_inventory and inventory:
        sections.append(_inventory(inventory))
    sections.append(_network_table(groups))
    sections.append(_footer())

    return _shell(title, "\n".join(sections))


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _header(title: str, site: dict | None, prepared_by: str) -> str:
    meta = []
    if site:
        if site.get("client"):
            meta.append(f"<div><dt>Client</dt><dd>{esc(site['client'])}</dd></div>")
        meta.append(f"<div><dt>Site</dt><dd>{esc(site['name'])}</dd></div>")
        if site.get("address"):
            meta.append(f"<div><dt>Address</dt><dd>{esc(site['address'])}</dd></div>")
    meta.append(f"<div><dt>Survey date</dt><dd>{esc(_iso(time.time()))}</dd></div>")
    if prepared_by:
        meta.append(f"<div><dt>Prepared by</dt><dd>{esc(prepared_by)}</dd></div>")
    return f"""<header class="cover">
  <h1>{esc(title)}</h1>
  <dl class="meta">{''.join(meta)}</dl>
</header>"""


def _executive_summary(networks, groups, alerts, severity_counts, coverage, bands) -> str:
    critical = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    open_networks = len([n for n in networks if n.get("security") == "Open"])
    weak = len([n for n in networks if n.get("security") in ("WEP", "WPA")])
    wps = len([n for n in networks if n.get("wps")])

    points = []
    points.append(
        f"{len(groups)} distinct wireless networks were observed across "
        f"{len(networks)} radios."
    )
    if critical:
        points.append(
            f"<strong>{critical} finding{'s' if critical != 1 else ''} require prompt "
            "attention</strong>, detailed in the Findings section."
        )
    else:
        points.append("No high-severity security findings were identified.")
    if open_networks:
        points.append(f"{open_networks} network(s) operate without encryption.")
    if weak:
        points.append(
            f"{weak} network(s) still use WEP or the original WPA, both of which are "
            "considered broken."
        )
    if wps:
        points.append(f"{wps} network(s) have WPS enabled, which should be disabled.")
    if coverage and coverage["summary"].get("point_count"):
        summary = coverage["summary"]
        weak_points = summary.get("weak", 0)
        points.append(
            f"{summary['point_count']} locations were surveyed; "
            f"{summary['excellent'] + summary['good']} had good or better signal"
            + (f", {weak_points} were weak or unusable" if weak_points else "")
            + "."
        )

    band_cells = "".join(
        f"<div class='stat'><b>{count}</b><span>{esc(band)} GHz</span></div>"
        for band, count in sorted(bands.items())
        if band != "unknown"
    )
    severity_cells = "".join(
        f"<div class='stat'><b style='color:{SEVERITY_COLOUR.get(sev, '#333')}'>{count}</b>"
        f"<span>{esc(sev)}</span></div>"
        for sev, count in sorted(severity_counts.items(),
                                 key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    )

    return f"""<section>
  <h2>Executive summary</h2>
  <div class="stats">
    <div class="stat"><b>{len(groups)}</b><span>networks</span></div>
    <div class="stat"><b>{len(networks)}</b><span>radios</span></div>
    {band_cells}
    {severity_cells}
  </div>
  <ul class="points">{''.join(f'<li>{p}</li>' for p in points)}</ul>
</section>"""


def _findings(alerts: list[dict]) -> str:
    if not alerts:
        return """<section><h2>Findings</h2>
  <p class="none">No outstanding findings. Every issue detected during the survey has
  been reviewed and cleared.</p></section>"""

    by_rule: dict[str, list[dict]] = {}
    for alert in alerts:
        by_rule.setdefault(alert["rule"], []).append(alert)

    blocks = []
    for rule, items in sorted(
        by_rule.items(), key=lambda kv: SEVERITY_ORDER.get(kv[1][0]["severity"], 9)
    ):
        severity = items[0]["severity"]
        explanation = RULE_EXPLANATIONS.get(rule, items[0]["detail"])
        affected = "".join(
            f"<tr><td>{esc(a['ssid'] or '(hidden)')}</td>"
            f"<td class='mono'>{esc(a['bssid'] or '')}</td>"
            f"<td>{esc(a['title'])}</td></tr>"
            for a in items[:25]
        )
        more = (f"<p class='more'>and {len(items) - 25} more</p>"
                if len(items) > 25 else "")
        blocks.append(f"""<div class="finding">
  <h3><span class="pill" style="background:{SEVERITY_COLOUR.get(severity, '#555')}">
    {esc(severity)}</span> {esc(rule.replace('_', ' ').title())}
    <span class="count">{len(items)} affected</span></h3>
  <p class="explain">{esc(explanation)}</p>
  <table><thead><tr><th>Network</th><th>BSSID</th><th>Detail</th></tr></thead>
  <tbody>{affected}</tbody></table>{more}
</div>""")

    return f"<section><h2>Findings</h2>{''.join(blocks)}</section>"


def _channel_plan(plan: dict) -> str:
    blocks = []
    for band in ("2.4", "5", "6"):
        entry = plan.get(band)
        if not entry:
            continue
        recommended = "".join(
            f"<tr><td class='mono big'>{c['channel']}</td>"
            f"<td>{esc(', '.join(c['reasons']))}</td>"
            f"<td class='mono'>{c['score']}</td></tr>"
            for c in entry["recommended"]
        )
        busiest = ", ".join(
            f"ch {b['channel']} ({b['ap_count']} APs)" for b in entry["busiest"]
        ) or "none measured"
        blocks.append(f"""<div class="plan-band">
  <h3>{esc(band)} GHz</h3>
  <p class="explain">{entry['channels_in_use']} channel(s) currently in use.
  Most contended: {esc(busiest)}.</p>
  <table><thead><tr><th>Recommended channel</th><th>Why</th>
  <th>Congestion score</th></tr></thead><tbody>{recommended}</tbody></table>
</div>""")

    notes = "".join(f"<li>{esc(n)}</li>" for n in plan.get("summary", []))
    return f"""<section><h2>Channel plan</h2>
  <p class="explain">Channels are scored on how many access points occupy or overlap
  them, how strong those are, and reported channel utilisation. Lower is better.</p>
  {''.join(blocks)}
  {f'<ul class="points">{notes}</ul>' if notes else ''}
</section>"""


def _coverage(coverage: dict) -> str:
    points = coverage["points"]
    headers = "".join(f"<th>{esc(p['name'])}</th>" for p in points)
    rows = []
    for row in coverage["rows"][:30]:
        cells = "".join(
            f"<td class='grade {esc(c['grade'])}'>{c['rssi'] if c['rssi'] is not None else '&mdash;'}</td>"
            for c in row["cells"]
        )
        rows.append(
            f"<tr><td>{esc(row['ssid'])}</td>"
            f"<td class='mono'>{esc(row['band'])}</td>{cells}"
            f"<td class='mono'>{row['coverage_pct']}%</td></tr>"
        )
    recommendations = "".join(
        f"<li>{esc(r)}</li>" for r in coverage.get("recommendations", [])
    )
    summary = coverage["summary"]
    return f"""<section><h2>Coverage</h2>
  <div class="stats">
    <div class="stat"><b>{summary['point_count']}</b><span>locations</span></div>
    <div class="stat"><b>{summary['excellent']}</b><span>excellent</span></div>
    <div class="stat"><b>{summary['good']}</b><span>good</span></div>
    <div class="stat"><b>{summary['fair']}</b><span>fair</span></div>
    <div class="stat"><b>{summary['weak']}</b><span>weak</span></div>
  </div>
  <p class="explain">Signal strength in dBm at each surveyed location. Above &minus;67
  supports voice; below &minus;72 is unreliable for anything demanding.</p>
  <table class="coverage"><thead><tr><th>Network</th><th>Band</th>{headers}
  <th>Covered</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
  {f'<h3>Recommendations</h3><ul class="points">{recommendations}</ul>' if recommendations else ''}
</section>"""


def _inventory(inventory: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{esc(item.get('label') or item.get('ssid') or '')}</td>"
        f"<td class='mono'>{esc(item['bssid'])}</td>"
        f"<td>{esc(item.get('location') or '')}</td>"
        f"<td class='mono'>{esc(item.get('asset_tag') or '')}</td>"
        f"<td>{esc(item.get('band') or '')} / {esc(item.get('channel') or '')}</td>"
        f"<td>{esc(item.get('security') or '')}</td>"
        f"<td>{'managed' if item.get('managed') else 'unmanaged'}</td></tr>"
        for item in inventory
    )
    return f"""<section><h2>Access point inventory</h2>
  <table><thead><tr><th>Label</th><th>BSSID</th><th>Location</th><th>Asset tag</th>
  <th>Band / channel</th><th>Security</th><th>Status</th></tr></thead>
  <tbody>{rows}</tbody></table></section>"""


def _network_table(groups: list[dict]) -> str:
    rows = "".join(
        f"<tr><td>{esc(g['ssid'] or '(hidden)')}</td>"
        f"<td>{esc(' / '.join(g['bands']))}</td>"
        f"<td class='mono'>{g['radio_count']}</td>"
        f"<td>{esc(', '.join(g['securities']))}</td>"
        f"<td class='mono'>{g['best_rssi']} dBm</td>"
        f"<td>{esc(', '.join(g['vendors'][:2]))}</td></tr>"
        for g in groups[:150]
    )
    return f"""<section class="page-break"><h2>Observed networks</h2>
  <p class="explain">Grouped by name. A single access point commonly serves the same
  name on several bands, each with its own radio.</p>
  <table><thead><tr><th>Network</th><th>Bands</th><th>Radios</th><th>Security</th>
  <th>Strongest</th><th>Vendor</th></tr></thead><tbody>{rows}</tbody></table></section>"""


def _footer() -> str:
    return f"""<footer>
  <p>Generated by wifirecon on {esc(_iso(time.time()))}. Wireless survey data comes
  from the Windows Native Wifi API. Surveying does not require joining a network,
  but Windows and the driver may transmit probe requests. This report does not
  certify radio silence or the absence of separate network discovery or audit activity.</p>
</footer>"""


def _shell(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
  :root {{ --ink:#1a1a1a; --soft:#5c5c5c; --line:#e2e2e2; --accent:#0f4c81; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:48px 56px; max-width:1100px; margin:0 auto;
         font:15px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif;
         color:var(--ink); background:#fff; }}
  h1 {{ font-size:30px; margin:0 0 20px; letter-spacing:-0.02em; }}
  h2 {{ font-size:19px; margin:40px 0 14px; padding-bottom:8px;
        border-bottom:2px solid var(--accent); letter-spacing:-0.01em; }}
  h3 {{ font-size:15px; margin:22px 0 8px; }}
  .cover {{ border-bottom:3px solid var(--accent); padding-bottom:24px; }}
  dl.meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
             gap:12px 24px; margin:0; }}
  dl.meta dt {{ font-size:11px; text-transform:uppercase; letter-spacing:.08em;
                color:var(--soft); }}
  dl.meta dd {{ margin:2px 0 0; font-weight:600; }}
  .stats {{ display:flex; gap:12px; flex-wrap:wrap; margin:18px 0; }}
  .stat {{ border:1px solid var(--line); border-radius:6px; padding:12px 18px;
           min-width:96px; }}
  .stat b {{ display:block; font-size:26px; line-height:1.1;
             font-variant-numeric:tabular-nums; }}
  .stat span {{ font-size:11px; text-transform:uppercase; letter-spacing:.07em;
                color:var(--soft); }}
  ul.points {{ padding-left:20px; }}
  ul.points li {{ margin-bottom:7px; }}
  .explain {{ color:var(--soft); font-size:13.5px; }}
  .none {{ color:var(--soft); font-style:italic; }}
  table {{ width:100%; border-collapse:collapse; margin:12px 0 20px; font-size:13px; }}
  th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em;
        color:var(--soft); border-bottom:2px solid var(--line); padding:8px 10px; }}
  td {{ padding:7px 10px; border-bottom:1px solid var(--line); }}
  tr:nth-child(even) td {{ background:#fafafa; }}
  .mono {{ font-family:"Cascadia Mono",Consolas,monospace; font-size:12px; }}
  .big {{ font-size:16px; font-weight:700; }}
  .finding {{ margin-bottom:30px; page-break-inside:avoid; }}
  .pill {{ display:inline-block; color:#fff; font-size:10px; text-transform:uppercase;
           letter-spacing:.06em; padding:3px 8px; border-radius:3px;
           vertical-align:middle; margin-right:6px; }}
  .count {{ float:right; font-size:12px; color:var(--soft); font-weight:400; }}
  .more {{ font-size:12px; color:var(--soft); font-style:italic; }}
  .plan-band {{ page-break-inside:avoid; margin-bottom:24px; }}
  table.coverage td.grade {{ text-align:center; font-family:"Cascadia Mono",monospace;
                             font-size:12px; }}
  td.excellent {{ background:#d1f0dd !important; }}
  td.good      {{ background:#e4f5d9 !important; }}
  td.fair      {{ background:#fdf3d0 !important; }}
  td.weak      {{ background:#fbe0d4 !important; }}
  td.unusable, td.none {{ background:#f6d6d6 !important; color:var(--soft); }}
  footer {{ margin-top:48px; padding-top:18px; border-top:1px solid var(--line);
            font-size:12px; color:var(--soft); }}
  @media print {{
    body {{ padding:0; font-size:11pt; }}
    h2 {{ page-break-after:avoid; }}
    section {{ page-break-inside:auto; }}
    .page-break {{ page-break-before:always; }}
    tr {{ page-break-inside:avoid; }}
  }}
</style></head><body>{body}</body></html>"""

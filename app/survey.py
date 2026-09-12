"""
Survey analysis for consulting work.

Turns the raw scan data into the things a client actually asks for: which
channels to put their access points on, how bad the interference is, whether
coverage is adequate at each surveyed location, and what changed between two
visits.
"""

from __future__ import annotations

import logging
from typing import Any

from . import db

log = logging.getLogger(__name__)

# 2.4 GHz has only three channels that do not overlap. Everything else is a
# compromise, which is why the recommender only ever suggests these.
NON_OVERLAPPING_24 = [1, 6, 11]

# 5 GHz channels by regulatory group. UNII-2 needs radar detection, so it is
# recommended with a caveat rather than avoided outright.
UNII1 = [36, 40, 44, 48]
UNII2A = [52, 56, 60, 64]
UNII2C = [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
UNII3 = [149, 153, 157, 161, 165]
DFS_CHANNELS = set(UNII2A + UNII2C)

# 6 GHz preferred scanning channels: an AP that wants to be discovered beacons here.
PSC_6GHZ = [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229]

# Signal thresholds in dBm, the numbers most survey reports are written against.
COVERAGE_GRADES = [
    (-60, "excellent", "Supports everything including voice and video calls."),
    (-67, "good", "Reliable for general use and voice."),
    (-72, "fair", "Fine for browsing and email; voice may suffer."),
    (-80, "weak", "Connects, but throughput and reliability will be poor."),
    (-100, "unusable", "Effectively no service."),
]


def grade_signal(rssi: int | None) -> dict:
    if rssi is None:
        return {"grade": "none", "label": "Not detected", "detail": "", "rssi": None}
    for threshold, grade, detail in COVERAGE_GRADES:
        if rssi >= threshold:
            return {"grade": grade, "label": grade.title(), "detail": detail, "rssi": rssi}
    return {"grade": "unusable", "label": "Unusable", "detail": "", "rssi": rssi}


# ---------------------------------------------------------------------------
# Interference and channel planning
# ---------------------------------------------------------------------------


def _channel_span(channel: int, band: str, width: int) -> tuple[float, float]:
    """Approximate occupied range in channel numbers, for overlap maths."""
    if band == "2.4":
        # 20 MHz is about 4 channel numbers either side at 5 MHz spacing.
        half = 2 + (width / 20 - 1) * 4
        return channel - half, channel + half
    half = (width / 20) * 2
    return channel - half, channel + half


def interference_report(minutes: float = 15) -> dict:
    """Score every channel by how contended it is."""
    import time

    since = time.time() - minutes * 60 if minutes else None
    rows = db.list_bss(since=since, limit=5000)

    bands: dict[str, dict[int, dict]] = {"2.4": {}, "5": {}, "6": {}}
    for row in rows:
        band, channel = row.get("band"), row.get("channel")
        if band not in bands or channel is None:
            continue
        entry = bands[band].setdefault(channel, {
            "channel": channel, "band": band, "ap_count": 0, "strong_count": 0,
            "best_rssi": -127, "widths": set(), "utilization": [], "networks": [],
        })
        entry["ap_count"] += 1
        rssi = row.get("rssi") or -127
        if rssi >= -75:
            entry["strong_count"] += 1
        entry["best_rssi"] = max(entry["best_rssi"], rssi)
        entry["widths"].add(row.get("width_mhz") or 20)
        if row.get("utilization_pct") is not None:
            entry["utilization"].append(row["utilization_pct"])
        if len(entry["networks"]) < 12:
            entry["networks"].append(row.get("ssid") or "(hidden)")

    # Overlap: an AP two channels away still lands on top of you in 2.4 GHz.
    out: dict[str, list[dict]] = {}
    for band, channels in bands.items():
        results = []
        for channel, entry in channels.items():
            overlap = 0
            low, high = _channel_span(channel, band, max(entry["widths"]))
            for other, other_entry in channels.items():
                if other == channel:
                    continue
                olow, ohigh = _channel_span(other, band, max(other_entry["widths"]))
                if olow < high and ohigh > low:
                    overlap += other_entry["ap_count"]

            utilisation = (
                round(sum(entry["utilization"]) / len(entry["utilization"]), 1)
                if entry["utilization"] else None
            )
            # Co-channel APs hurt most, overlapping ones somewhat less, and a
            # busy channel is worse than a merely crowded one.
            score = entry["ap_count"] * 3 + overlap * 1.5 + entry["strong_count"] * 2
            if utilisation:
                score += utilisation / 4

            results.append({
                "channel": channel, "band": band,
                "ap_count": entry["ap_count"],
                "strong_count": entry["strong_count"],
                "overlapping_aps": overlap,
                "best_rssi": entry["best_rssi"],
                "widths": sorted(entry["widths"]),
                "utilization_pct": utilisation,
                "congestion_score": round(score, 1),
                "networks": entry["networks"],
            })
        results.sort(key=lambda r: r["channel"])
        out[band] = results
    return out


def channel_plan(minutes: float = 15, radios_per_band: int = 3) -> dict:
    """Recommend channels for new access points, worst-contended avoided."""
    report = interference_report(minutes)
    plan: dict[str, Any] = {}

    for band, candidates in (
        ("2.4", NON_OVERLAPPING_24),
        ("5", UNII1 + UNII3 + UNII2A + UNII2C),
        ("6", PSC_6GHZ),
    ):
        observed = {entry["channel"]: entry for entry in report.get(band, [])}
        scored = []
        for channel in candidates:
            entry = observed.get(channel)
            score = entry["congestion_score"] if entry else 0.0
            # An unobserved channel is genuinely clear, which is the best case.
            reasons = []
            if not entry:
                reasons.append("nothing detected on it")
            else:
                reasons.append(f"{entry['ap_count']} AP(s) present")
                if entry["overlapping_aps"]:
                    reasons.append(f"{entry['overlapping_aps']} overlapping")
                if entry["utilization_pct"]:
                    reasons.append(f"{entry['utilization_pct']:.0f}% busy")
            if band == "5" and channel in DFS_CHANNELS:
                score += 6      # usable, but radar detection can force a move
                reasons.append("DFS: may vacate on radar")
            if band == "6" and channel in PSC_6GHZ:
                reasons.append("preferred scanning channel")
            scored.append({
                "channel": channel, "score": round(score, 1),
                "reasons": reasons,
                "dfs": band == "5" and channel in DFS_CHANNELS,
                "observed_aps": entry["ap_count"] if entry else 0,
            })

        scored.sort(key=lambda c: (c["score"], c["channel"]))
        recommended = scored[:radios_per_band]
        plan[band] = {
            "recommended": recommended,
            "all": scored,
            "busiest": sorted(
                report.get(band, []), key=lambda r: -r["congestion_score"]
            )[:3],
            "channels_in_use": len(report.get(band, [])),
        }

    plan["summary"] = _plan_summary(plan, report)
    return plan


def _plan_summary(plan: dict, report: dict) -> list[str]:
    notes = []
    band24 = report.get("2.4", [])
    if band24:
        off_plan = [c for c in band24 if c["channel"] not in NON_OVERLAPPING_24]
        if off_plan:
            notes.append(
                f"{sum(c['ap_count'] for c in off_plan)} access point(s) in 2.4 GHz sit "
                f"on channels other than 1, 6 or 11, which spreads interference across "
                "the whole band."
            )
        wide = [c for c in band24 if any(w > 20 for w in c["widths"])]
        if wide:
            notes.append(
                f"{len(wide)} channel(s) in 2.4 GHz carry 40 MHz networks. In this band "
                "that consumes most of the usable spectrum and should be avoided."
            )
    if plan.get("2.4", {}).get("recommended"):
        best = plan["2.4"]["recommended"][0]
        notes.append(f"Cleanest 2.4 GHz channel here is {best['channel']}.")
    if plan.get("5", {}).get("recommended"):
        picks = ", ".join(str(c["channel"]) for c in plan["5"]["recommended"])
        notes.append(f"For 5 GHz, {picks} are the least contended.")
    if not report.get("6"):
        notes.append(
            "Nothing is using 6 GHz here, so the whole band is available for a "
            "Wi-Fi 6E deployment."
        )
    return notes


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def coverage_report(site_id: int | None = None, ssid: str | None = None) -> dict:
    """Grade every surveyed location against the networks heard there."""
    data = db.coverage_matrix(site_id, ssid)
    points = data["points"]
    if not points:
        return {"points": [], "networks": [], "rows": [], "summary": {},
                "worst": [], "recommendations": []}

    rows = []
    for network in data["networks"]:
        cells = []
        for point in points:
            rssi = data["matrix"].get(network["key"], {}).get(str(point["id"]))
            cells.append({"point_id": point["id"], "point": point["name"],
                          **grade_signal(rssi)})
        covered = [c for c in cells if c["rssi"] is not None and c["rssi"] >= -72]
        rows.append({
            **network,
            "cells": cells,
            "coverage_pct": round(len(covered) / len(points) * 100),
            "gaps": [c["point"] for c in cells
                     if c["rssi"] is None or c["rssi"] < -72],
        })

    rows.sort(key=lambda r: -r["coverage_pct"])
    worst = [
        {"point": p["name"], "best_rssi": p["best_rssi"],
         **grade_signal(p["best_rssi"])}
        for p in sorted(points, key=lambda p: (p["best_rssi"] or -127))[:5]
    ]

    graded = [grade_signal(p["best_rssi"])["grade"] for p in points]
    summary = {
        "point_count": len(points),
        "network_count": len(rows),
        "excellent": graded.count("excellent"),
        "good": graded.count("good"),
        "fair": graded.count("fair"),
        "weak": graded.count("weak") + graded.count("unusable"),
    }

    recommendations = []
    weak_points = [p for p in points if (p["best_rssi"] or -127) < -72]
    if weak_points:
        names = ", ".join(p["name"] for p in weak_points[:4])
        recommendations.append(
            f"{len(weak_points)} location(s) have no strong signal from any network: "
            f"{names}. These need an additional access point or a repositioned one."
        )
    partial = [r for r in rows if 0 < r["coverage_pct"] < 80 and r["seen_at"] > 1]
    for row in partial[:3]:
        recommendations.append(
            f"'{row['ssid']}' on {row['band']} GHz reaches only "
            f"{row['coverage_pct']}% of surveyed locations. Gaps: "
            f"{', '.join(row['gaps'][:4])}."
        )
    return {"points": points, "networks": data["networks"], "rows": rows,
            "summary": summary, "worst": worst, "recommendations": recommendations}


# ---------------------------------------------------------------------------
# Before / after comparison
# ---------------------------------------------------------------------------


def compare_snapshot(snapshot_id: int, minutes: float = 15) -> dict:
    """What changed between a saved snapshot and what is on air now."""
    import time

    snapshot = db.get_snapshot(snapshot_id)
    if not snapshot:
        return {"error": "That snapshot does not exist"}

    before = {row["bssid"]: row for row in snapshot["bss"]}
    since = time.time() - minutes * 60 if minutes else None
    after = {row["bssid"]: row for row in db.list_bss(since=since, limit=5000)}

    added = [after[b] for b in after.keys() - before.keys()]
    removed = [before[b] for b in before.keys() - after.keys()]

    changed = []
    for bssid in before.keys() & after.keys():
        old, new = before[bssid], after[bssid]
        diffs = {}
        for field in ("ssid", "channel", "band", "security", "width_mhz", "phy"):
            if old.get(field) != new.get(field):
                diffs[field] = {"before": old.get(field), "after": new.get(field)}
        old_rssi, new_rssi = old.get("rssi"), new.get("rssi")
        if old_rssi is not None and new_rssi is not None:
            delta = new_rssi - old_rssi
            if abs(delta) >= 10:
                diffs["rssi"] = {"before": old_rssi, "after": new_rssi, "delta": delta}
        if diffs:
            changed.append({
                "bssid": bssid, "ssid": new.get("ssid") or old.get("ssid"),
                "changes": diffs,
            })

    return {
        "snapshot": {k: v for k, v in snapshot.items() if k != "bss"},
        "added": sorted(added, key=lambda r: -(r.get("rssi") or -127)),
        "removed": sorted(removed, key=lambda r: -(r.get("rssi") or -127)),
        "changed": changed,
        "counts": {
            "before": len(before), "after": len(after),
            "added": len(added), "removed": len(removed), "changed": len(changed),
        },
        "summary": _diff_summary(len(added), len(removed), len(changed)),
    }


def _diff_summary(added: int, removed: int, changed: int) -> str:
    if not (added or removed or changed):
        return "Nothing has changed since the snapshot was taken."
    parts = []
    if added:
        parts.append(f"{added} new access point{'s' if added != 1 else ''}")
    if removed:
        parts.append(f"{removed} no longer present")
    if changed:
        parts.append(f"{changed} changed configuration or signal")
    return ", ".join(parts).capitalize() + "."

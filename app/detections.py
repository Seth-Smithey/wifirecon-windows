"""
Detection rules.

Every rule takes the current scan's records plus a small amount of history and
returns zero or more findings. Rules are pure functions over dicts; the engine
handles marks, suppression and severity floors around them.

Severity ladder: info < low < medium < high < critical
"""

from __future__ import annotations

import json
import logging
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import db, oui

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    bssid: str | None = None
    ssid: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    # What this finding is about, when that is not one radio. A congested
    # channel is one fact however many APs report it, and an SSID conflict is
    # one fact however the signal strengths shuffle between scans.
    scope: str | None = None

    def suppression_key(self) -> str:
        return f"{self.rule}|{self.scope or self.bssid or self.ssid or '-'}"


def json_list(raw: Any) -> list[str]:
    """A JSON array column, as a list. Anything unreadable counts as empty."""
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if not isinstance(raw, str) or not raw:
        return []
    try:
        loaded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(x) for x in loaded] if isinstance(loaded, list) else []


def strongest_first(entries: list[dict], limit: int = 3) -> str:
    """Name the loudest few, because signal is the only clue to what is yours."""
    ranked = sorted(
        entries, key=lambda e: -(e.get("rssi") if e.get("rssi") is not None else -999)
    )
    return ", ".join(
        f"{e.get('ssid') or e.get('bssid')} ({e.get('bssid')}, ch {e.get('channel')}, "
        f"{e.get('rssi')} dBm)"
        for e in ranked[:limit]
    )


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

# Characters that render close enough to an ASCII letter to fool a person.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ᴏ": "o", "ⅰ": "i", "ⅼ": "l",
    "０": "0", "１": "1", "Ⅰ": "I", "ｌ": "l", "І": "I", "Ο": "O", "Α": "A",
    "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ν": "v", "ο": "o",
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
    "\u00a0": " ", "\u2000": " ", "\u200b": "",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def skeleton(text: str) -> str:
    """Fold a string toward its visual skeleton for lookalike comparison."""
    if not text:
        return ""
    normalised = unicodedata.normalize("NFKC", text)
    folded = "".join(CONFUSABLES.get(ch, ch) for ch in normalised)
    folded = folded.casefold().translate(LEET)
    return "".join(ch for ch in folded if ch.isalnum())


def levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Bounded edit distance. Returns cap+1 once it is clear the distance exceeds cap."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        best = current[0]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            best = min(best, value)
        previous = current
        if best > cap:
            return cap + 1
    return previous[-1]


def has_mixed_scripts(text: str) -> bool:
    """True when a name mixes Latin with another alphabet, a classic spoof tell."""
    scripts = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "ARABIC", "HEBREW"):
            if name.startswith(script):
                scripts.add(script)
                break
    return len(scripts) > 1


# ---------------------------------------------------------------------------
# Mark matching
# ---------------------------------------------------------------------------


class MarkSet:
    """Watch / trusted / ignore lists with BSSID, OUI, SSID and prefix matching."""

    def __init__(self, rows: list[dict]):
        self.by_kind: dict[str, dict[str, set[str]]] = {}
        self.labels: dict[tuple[str, str, str], str] = {}
        for row in rows:
            kind = row["kind"]
            match_type = row["match_type"]
            value = (row["value"] or "").strip().lower()
            if not value:
                continue
            self.by_kind.setdefault(kind, {}).setdefault(match_type, set()).add(value)
            if row.get("label"):
                self.labels[(kind, match_type, value)] = row["label"]

    def matches(self, kind: str, bssid: str, ssid: str | None) -> bool:
        rules = self.by_kind.get(kind)
        if not rules:
            return False
        mac = oui.normalise(bssid)
        flat = mac.replace(":", "")
        ssid_l = (ssid or "").lower()

        if mac in rules.get("bssid", set()) or flat in rules.get("bssid", set()):
            return True
        for prefix in rules.get("oui", set()):
            clean = prefix.replace(":", "").replace("-", "")
            if clean and flat.startswith(clean):
                return True
        if ssid_l and ssid_l in rules.get("ssid", set()):
            return True
        for prefix in rules.get("ssid_prefix", set()):
            if ssid_l and ssid_l.startswith(prefix):
                return True
        return False

    def watched_ssids(self) -> set[str]:
        return set(self.by_kind.get("watch", {}).get("ssid", set()))

    def trusted_ssids(self) -> set[str]:
        return set(self.by_kind.get("trusted", {}).get("ssid", set()))


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RuleFn = Callable[["RuleContext"], list[Finding]]
REGISTRY: list[tuple[str, RuleFn]] = []


def rule(name: str):
    def wrap(fn: RuleFn) -> RuleFn:
        REGISTRY.append((name, fn))
        return fn

    return wrap


@dataclass
class RuleContext:
    records: list[dict]              # this scan's parsed BSS records
    previous: dict[str, dict]        # bssid -> stored bss row before this scan
    marks: MarkSet
    settings: dict
    new_bssids: set[str]
    now: float


@rule("open_network")
def _open_network(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        if r["security"] == "Open" and not r["hidden"]:
            out.append(
                Finding(
                    rule="open_network",
                    severity="info",
                    title=f"Open network: {r['ssid'] or '<hidden>'}",
                    detail="No encryption. Anything sent over this network is readable in the air.",
                    bssid=r["bssid"],
                    ssid=r["ssid"],
                    evidence={"channel": r["channel"], "rssi": r["rssi"]},
                )
            )
    return out


@rule("weak_crypto")
def _weak_crypto(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        sec = r["security"]
        ciphers = r.get("ciphers") or []
        if sec == "WEP":
            out.append(
                Finding("weak_crypto", "high", f"WEP in use on {r['ssid'] or r['bssid']}",
                        "WEP is broken and recoverable in minutes. This network should be "
                        "moved to WPA2 or WPA3.",
                        r["bssid"], r["ssid"], {"security": sec})
            )
        elif "TKIP" in ciphers:
            out.append(
                Finding("weak_crypto", "medium", f"TKIP cipher on {r['ssid'] or r['bssid']}",
                        "TKIP is deprecated and caps the network at 802.11g rates. "
                        "Switch to CCMP/AES only.",
                        r["bssid"], r["ssid"], {"ciphers": ciphers})
            )
        elif sec in ("WPA", "WPA/WPA2 mixed"):
            out.append(
                Finding("weak_crypto", "low", f"WPA1 still advertised by {r['ssid'] or r['bssid']}",
                        "The AP still offers the original WPA. Drop it and leave WPA2/WPA3 only.",
                        r["bssid"], r["ssid"], {"security": sec})
            )
    return out


@rule("wps_enabled")
def _wps(ctx: RuleContext) -> list[Finding]:
    """One finding for the whole environment.

    WPS being on is a standing property of somebody's router, not an event. In
    a dense area one finding per access point produced over a hundred rows a
    scan and buried everything worth reading. The per-radio detail moves into
    the evidence, where it is still there when you want it.
    """
    pin_capable, push_only = [], []
    for r in ctx.records:
        wps = (r.get("detail") or {}).get("wps")
        if not wps:
            continue
        methods = wps.get("config_methods") or []
        entry = {
            "bssid": r["bssid"], "ssid": r["ssid"], "channel": r["channel"],
            "rssi": r["rssi"], "vendor": r["vendor"], "config_methods": methods,
            "state": wps.get("state"), "model": wps.get("model_name"),
        }
        if any(m in ("Label", "Display", "Keypad") for m in methods):
            pin_capable.append(entry)
        else:
            push_only.append(entry)

    if not pin_capable and not push_only:
        return []

    total = len(pin_capable) + len(push_only)
    if pin_capable:
        return [Finding(
            "wps_enabled", "medium",
            f"WPS enabled on {total} of {len(ctx.records)} nearby APs "
            f"({len(pin_capable)} PIN-capable)",
            f"{len(pin_capable)} advertise Label, Display or Keypad methods, which "
            f"means the PIN exchange is reachable and brute-forceable. Strongest: "
            f"{strongest_first(pin_capable)}. The full list is in the evidence.",
            evidence={"pin_capable": pin_capable, "push_button_only": push_only,
                      "aps_scanned": len(ctx.records)},
        )]
    return [Finding(
        "wps_enabled", "info",
        f"WPS enabled on {total} of {len(ctx.records)} nearby APs, push-button only",
        f"No PIN methods advertised, so the brute-force route is closed. Worth "
        f"turning off on hardware you own. Strongest: {strongest_first(push_only)}.",
        evidence={"push_button_only": push_only, "aps_scanned": len(ctx.records)},
    )]


@rule("pmf_missing")
def _pmf(ctx: RuleContext) -> list[Finding]:
    """How much of the neighbourhood can have its clients deauthenticated.

    A standing property of other people's equipment, so it is counted rather
    than listed one row at a time.
    """
    exposed, encrypted = [], 0
    for r in ctx.records:
        if r["security"] in ("Open", "WEP", "WPA") or r["hidden"]:
            continue
        encrypted += 1
        if not r["mfp_capable"]:
            exposed.append({
                "bssid": r["bssid"], "ssid": r["ssid"], "channel": r["channel"],
                "rssi": r["rssi"], "vendor": r["vendor"], "security": r["security"],
            })
    if not exposed:
        return []
    return [Finding(
        "pmf_missing", "low",
        f"{len(exposed)} of {encrypted} encrypted APs offer no management frame "
        "protection",
        "Without PMF, deauthentication and disassociation frames can be forged "
        f"against their clients. Strongest: {strongest_first(exposed)}.",
        evidence={"unprotected": exposed, "encrypted_aps": encrypted},
    )]


@rule("wpa3_pmf_optional")
def _wpa3_pmf(ctx: RuleContext) -> list[Finding]:
    """WPA3 advertised without PMF required.

    Not inventory: this is invalid per the specification on a single access
    point, and it is the shape a downgrade attack wants, so it stays per-radio.
    """
    out = []
    for r in ctx.records:
        if r["hidden"] or not r["security"].startswith("WPA3"):
            continue
        if r["mfp_capable"] and not r["mfp_required"]:
            out.append(
                Finding("wpa3_pmf_optional", "medium",
                        f"WPA3 without required PMF on {r['ssid'] or r['bssid']}",
                        "WPA3 requires management frame protection. Advertising it as "
                        "optional points at a misconfiguration, or at a transition "
                        "mode that a downgrade can exploit.",
                        r["bssid"], r["ssid"], {"security": r["security"]})
            )
    return out


@rule("security_downgrade")
def _downgrade(ctx: RuleContext) -> list[Finding]:
    """Same SSID advertised with a weaker posture than it was before."""
    out = []
    for r in ctx.records:
        prev = ctx.previous.get(r["bssid"])
        if not prev or not prev.get("security"):
            continue
        old, new = prev["security"], r["security"]
        if old == new:
            continue
        rank = {"Open": 0, "WEP": 1, "WPA": 2, "WPA/WPA2 mixed": 3, "OWE": 3,
                "WPA2": 4, "WPA2/WPA3 transition": 5, "WPA3": 6, "WPA3-Enterprise": 7}
        if rank.get(new, 4) < rank.get(old, 4):
            out.append(
                Finding("security_downgrade", "high",
                        f"{r['ssid'] or r['bssid']} dropped from {old} to {new}",
                        "The same BSSID is now advertising weaker security than it was. "
                        "That is either a config change or an impersonator reusing the MAC.",
                        r["bssid"], r["ssid"], {"was": old, "now": new})
            )
    return out


@rule("ssid_conflict")
def _ssid_conflict(ctx: RuleContext) -> list[Finding]:
    """One SSID served with inconsistent security across BSSIDs - the evil-twin shape."""
    by_ssid: dict[str, list[dict]] = {}
    for r in ctx.records:
        if not r["ssid"] or r["hidden"]:
            continue
        by_ssid.setdefault(r["ssid"], []).append(r)

    out = []
    for ssid, group in by_ssid.items():
        # The generation label alone collapses PSK and 802.1X into "WPA2", so the
        # posture key carries the enterprise flag as well.
        postures = {
            f"{g['security']}{' (802.1X)' if g['enterprise'] else ''}" for g in group
        }
        securities = postures
        if len(postures) <= 1:
            continue
        # A WPA2/WPA3 transition pair alongside plain WPA2 is normal on many APs.
        if postures <= {"WPA2", "WPA2/WPA3 transition", "WPA3"}:
            continue
        vendors = {g["vendor"] or "unknown" for g in group}
        strongest = max(group, key=lambda g: g["rssi"])
        out.append(
            Finding("ssid_conflict", "high",
                    f"'{ssid}' is being advertised with mismatched security",
                    f"{len(group)} BSSIDs share this name but offer {', '.join(sorted(securities))}. "
                    "A weaker copy of a known network is what an evil twin looks like.",
                    strongest["bssid"], ssid,
                    {"securities": sorted(securities), "vendors": sorted(vendors),
                     "bssids": [g["bssid"] for g in group]},
                    # Keyed on the name. Which radio is loudest shuffles with a
                    # few dB of drift, and keying on that re-reported the same
                    # conflict every time the order changed.
                    scope=f"ssid:{ssid}")
        )
    return out


@rule("lookalike_ssid")
def _lookalike(ctx: RuleContext) -> list[Finding]:
    """A name one or two edits away from something on the watch or trusted list."""
    threshold = int(ctx.settings.get("levenshtein_threshold", 2))
    protected = ctx.marks.watched_ssids() | ctx.marks.trusted_ssids()
    if not protected:
        return []
    protected_skeletons = {s: skeleton(s) for s in protected}

    out = []
    for r in ctx.records:
        ssid = r["ssid"]
        if not ssid or ssid.lower() in protected:
            continue
        if ctx.marks.matches("trusted", r["bssid"], ssid):
            continue
        sk = skeleton(ssid)
        if not sk:
            continue
        for target, target_sk in protected_skeletons.items():
            if sk == target_sk:
                out.append(
                    Finding("lookalike_ssid", "critical",
                            f"'{ssid}' is visually identical to '{target}'",
                            "Different bytes, same appearance once homoglyphs and leetspeak "
                            "are folded out. This is what a targeted impersonation looks like.",
                            r["bssid"], ssid,
                            {"target": target, "distance": 0, "skeleton": sk,
                             "mixed_scripts": has_mixed_scripts(ssid)})
                )
                break
            distance = levenshtein(sk, target_sk, cap=threshold)
            if 0 < distance <= threshold:
                out.append(
                    Finding("lookalike_ssid", "high",
                            f"'{ssid}' closely resembles '{target}'",
                            f"Edit distance {distance} from a network you told the app to "
                            "care about. Worth checking who is running it.",
                            r["bssid"], ssid,
                            {"target": target, "distance": distance,
                             "mixed_scripts": has_mixed_scripts(ssid)})
                )
                break
    return out


@rule("mixed_script_ssid")
def _mixed_script(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        if r["ssid"] and has_mixed_scripts(r["ssid"]):
            out.append(
                Finding("mixed_script_ssid", "medium",
                        f"'{r['ssid']}' mixes alphabets",
                        "The name combines Latin with another script. Legitimate networks "
                        "rarely do this; spoofed ones often do.",
                        r["bssid"], r["ssid"], {"raw": (r.get("detail") or {}).get("ssid_raw")})
            )
    return out


@rule("lure_ssid")
def _lure(ctx: RuleContext) -> list[Finding]:
    lures = {s.lower() for s in ctx.settings.get("lure_ssids", [])}
    out = []
    for r in ctx.records:
        ssid = (r["ssid"] or "").lower().strip()
        if ssid and ssid in lures and r["security"] == "Open":
            out.append(
                Finding("lure_ssid", "medium",
                        f"Open network using a common auto-connect name: {r['ssid']}",
                        "Devices that have ever joined a network with this name will "
                        "reconnect on sight. That is the point of a lure AP.",
                        r["bssid"], r["ssid"],
                        {"rssi": r["rssi"], "vendor": r["vendor"]})
            )
    return out


@rule("hidden_ssid")
def _hidden(ctx: RuleContext) -> list[Finding]:
    return [
        Finding("hidden_ssid", "info",
                f"Hidden network on channel {r['channel']}",
                "The SSID is suppressed in beacons. It still leaks whenever a client "
                "probes for it.",
                r["bssid"], None,
                {"channel": r["channel"], "vendor": r["vendor"], "rssi": r["rssi"]})
        for r in ctx.records
        if r["hidden"]
    ]


@rule("new_bssid")
def _new_bssid(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        if r["bssid"] not in ctx.new_bssids:
            continue
        watched = ctx.marks.matches("watch", r["bssid"], r["ssid"])
        known_ssid = (r["ssid"] or "").lower() in (
            ctx.marks.watched_ssids() | ctx.marks.trusted_ssids()
        )
        if not (watched or known_ssid):
            continue
        out.append(
            Finding("new_bssid", "medium",
                    f"New radio on a tracked network: {r['bssid']} "
                    f"({r['ssid'] or 'hidden'})",
                    f"{r['bssid']} ({r['vendor'] or 'unknown vendor'}) has not been seen "
                    "before but is broadcasting a name you track.",
                    r["bssid"], r["ssid"],
                    {"vendor": r["vendor"], "channel": r["channel"], "rssi": r["rssi"]})
        )
    return out


@rule("vendor_mismatch")
def _vendor_mismatch(ctx: RuleContext) -> list[Finding]:
    """A tracked SSID showing up on hardware from a vendor it never used before."""
    tracked = ctx.marks.watched_ssids() | ctx.marks.trusted_ssids()
    if not tracked:
        return []
    by_ssid: dict[str, set[str]] = {}
    for r in ctx.records:
        ssid = (r["ssid"] or "").lower()
        if ssid in tracked:
            by_ssid.setdefault(ssid, set()).add(r["vendor"] or "unknown")

    out = []
    for r in ctx.records:
        ssid = (r["ssid"] or "").lower()
        if ssid not in tracked:
            continue
        if ctx.marks.matches("trusted", r["bssid"], r["ssid"]):
            continue
        vendors = by_ssid.get(ssid, set())
        if len(vendors) > 1 and (r["vendor"] or "unknown") == "unknown":
            out.append(
                Finding("vendor_mismatch", "medium",
                        f"Unrecognised hardware serving '{r['ssid']}'",
                        f"{r['bssid']} has no known vendor while the rest of this network "
                        f"runs on {', '.join(sorted(v for v in vendors if v != 'unknown'))}.",
                        r["bssid"], r["ssid"], {"vendors_seen": sorted(vendors)})
            )
    return out


@rule("randomized_bssid")
def _randomized(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        if not r["randomized_mac"]:
            continue
        # Phone hotspots do this routinely, so this stays informational unless the
        # name matches something tracked.
        tracked = (r["ssid"] or "").lower() in (
            ctx.marks.watched_ssids() | ctx.marks.trusted_ssids()
        )
        out.append(
            Finding("randomized_bssid", "high" if tracked else "info",
                    f"Locally administered BSSID: {r['bssid']}",
                    "The U/L bit is set, so this MAC was assigned by software rather than "
                    "burned in. Normal for phone hotspots, suspicious on a tracked SSID."
                    if not tracked else
                    "A tracked network is being served from a software-assigned MAC.",
                    r["bssid"], r["ssid"], {"ssid": r["ssid"], "vendor": r["vendor"]})
        )
    return out


@rule("bssid_multi_ssid")
def _multi_ssid(ctx: RuleContext) -> list[Finding]:
    """One radio answering to many names - the karma/multi-SSID responder shape."""
    limit = int(ctx.settings.get("max_ssids_per_bssid", 3))
    seen: dict[str, set[str]] = {}
    for r in ctx.records:
        if r["ssid"]:
            seen.setdefault(r["bssid"], set()).add(r["ssid"])
    out = []
    for bssid, ssids in seen.items():
        if len(ssids) > limit:
            out.append(
                Finding("bssid_multi_ssid", "high",
                        f"{bssid} is advertising {len(ssids)} different names",
                        "A single radio responding to many SSIDs is either a multi-BSSID AP "
                        "reusing one MAC or a responder answering whatever clients ask for.",
                        bssid, None, {"ssids": sorted(ssids)})
            )
    return out


@rule("rssi_anomaly")
def _rssi_anomaly(ctx: RuleContext) -> list[Finding]:
    jump = int(ctx.settings.get("rssi_jump_db", 25))
    minimum = int(ctx.settings.get("min_observations_for_baseline", 5))
    out = []
    for r in ctx.records:
        prev = ctx.previous.get(r["bssid"])
        if not prev or (prev.get("times_seen") or 0) < minimum:
            continue
        history = db.recent_observations(r["bssid"], minimum)
        values = [h["rssi"] for h in history if h["rssi"] is not None]
        if len(values) < minimum:
            continue
        baseline = sum(values) / len(values)
        delta = r["rssi"] - baseline
        if delta >= jump:
            out.append(
                Finding("rssi_anomaly", "medium",
                        f"{r['ssid'] or r['bssid']} got {round(delta)} dB stronger",
                        f"Signal moved from about {round(baseline)} dBm to {r['rssi']} dBm. "
                        "Either the AP moved closer or something nearer is answering to its name.",
                        r["bssid"], r["ssid"],
                        {"baseline": round(baseline, 1), "current": r["rssi"],
                         "delta_db": round(delta, 1)})
            )
    return out


@rule("channel_change")
def _channel_change(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        prev = ctx.previous.get(r["bssid"])
        if not prev or prev.get("channel") is None or r["channel"] is None:
            continue
        if prev["channel"] != r["channel"] and prev.get("band") == r["band"]:
            severity = "medium" if ctx.marks.matches("watch", r["bssid"], r["ssid"]) else "info"
            out.append(
                Finding("channel_change", severity,
                        f"{r['ssid'] or r['bssid']} moved from channel "
                        f"{prev['channel']} to {r['channel']}",
                        "Normal for APs with automatic channel selection, worth noting on "
                        "an AP you manage.",
                        r["bssid"], r["ssid"],
                        {"was": prev["channel"], "now": r["channel"], "band": r["band"]})
            )
    return out


# Elements that carry the security posture. A change here is a different fact
# from a vendor adding a roaming element in a firmware update.
SECURITY_ELEMENTS = {"48", "vendor:00:50:f2:01", "vendor:00:50:f2:04"}


@rule("ie_fingerprint_change")
def _fingerprint(ctx: RuleContext) -> list[Finding]:
    """An access point now advertises a different set of elements.

    Reported with what actually changed, because two opaque hashes tell nobody
    anything. Fingerprints carry a recipe version, and a change of recipe is
    not a change of access point, so those comparisons are skipped.
    """
    out = []
    for r in ctx.records:
        prev = ctx.previous.get(r["bssid"])
        old = (prev or {}).get("ie_fingerprint")
        new = r["ie_fingerprint"]
        if not old or not new or old == new:
            continue
        if old.partition(":")[0] != new.partition(":")[0]:
            continue        # different recipe, not a different device

        before = set(json_list((prev or {}).get("ie_elements")))
        after = set(json_list(r.get("ie_elements")))
        added = sorted(after - before)
        removed = sorted(before - after)
        touched = set(added) | set(removed)

        security_change = bool(touched & SECURITY_ELEMENTS)
        if security_change:
            severity = "high"
            detail = ("The elements that carry this network's security posture "
                      "changed while the MAC stayed the same. That is either a "
                      "reconfiguration or something else answering to this address.")
        else:
            severity = "low"
            detail = ("The set of information elements this AP advertises is "
                      "different from last time. A firmware update does this.")
        if added or removed:
            detail += (f" Added: {', '.join(added) or 'nothing'}."
                       f" Removed: {', '.join(removed) or 'nothing'}.")

        out.append(
            Finding("ie_fingerprint_change", severity,
                    f"Beacon structure changed on {r['ssid'] or r['bssid']}",
                    detail, r["bssid"], r["ssid"],
                    {"added": added, "removed": removed,
                     "security_related": security_change})
        )
    return out


@rule("beacon_interval_anomaly")
def _beacon(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        bp = r["beacon_period"]
        if not bp:
            continue
        if bp < 50 or bp > 200:
            out.append(
                Finding("beacon_interval_anomaly", "low",
                        f"Unusual beacon interval on {r['ssid'] or r['bssid']}: {bp} TU",
                        "Almost every commercial AP beacons at 100 TU. Values well away "
                        "from that are a common software-AP fingerprint.",
                        r["bssid"], r["ssid"], {"beacon_period": bp})
            )
        else:
            prev = ctx.previous.get(r["bssid"])
            if prev and prev.get("beacon_period") and prev["beacon_period"] != bp:
                out.append(
                    Finding("beacon_interval_anomaly", "medium",
                            f"Beacon interval changed on {r['ssid'] or r['bssid']}",
                            f"Was {prev['beacon_period']} TU, now {bp} TU. APs do not normally "
                            "change this at runtime.",
                            r["bssid"], r["ssid"],
                            {"was": prev["beacon_period"], "now": bp})
                )
    return out


@rule("country_mismatch")
def _country(ctx: RuleContext) -> list[Finding]:
    codes: dict[str, int] = {}
    for r in ctx.records:
        code = (r.get("detail") or {}).get("country")
        if code:
            codes[code] = codes.get(code, 0) + 1
    if len(codes) < 2:
        return []
    dominant = max(codes, key=lambda k: codes[k])
    out = []
    for r in ctx.records:
        code = (r.get("detail") or {}).get("country")
        if code and code != dominant:
            out.append(
                Finding("country_mismatch", "low",
                        f"{r['ssid'] or r['bssid']} claims regulatory domain {code}",
                        f"Everything else nearby reports {dominant}. Mismatched country codes "
                        "usually mean imported hardware or a software AP with a default config.",
                        r["bssid"], r["ssid"], {"country": code, "local": dominant})
            )
    return out


@rule("channel_congestion")
def _congestion(ctx: RuleContext) -> list[Finding]:
    """One finding per congested channel.

    Congestion is a property of a channel. Eight access points on channel 6 all
    reporting 70% busy is one fact, not eight.
    """
    limit = float(ctx.settings.get("congestion_utilization_pct", 60))
    by_channel: dict[tuple, list[dict]] = {}
    for r in ctx.records:
        util = r.get("utilization_pct")
        if util is None or util < limit or r["channel"] is None:
            continue
        by_channel.setdefault((r["band"], r["channel"]), []).append({
            "bssid": r["bssid"], "ssid": r["ssid"], "channel": r["channel"],
            "rssi": r["rssi"], "utilization": util, "stations": r.get("station_count"),
        })

    out = []
    for (band, channel), reporters in by_channel.items():
        levels = [e["utilization"] for e in reporters]
        worst = max(levels)
        # The number is already here, so the severity may as well read it.
        severity = "medium" if worst >= max(limit + 25, 85) else "low"
        stations = sum(e["stations"] or 0 for e in reporters)
        out.append(Finding(
            "channel_congestion", severity,
            f"Channel {channel} ({band} GHz) is {worst:.0f}% busy",
            f"Reported by {len(reporters)} AP(s), {stations} associated client(s) "
            f"between them. Throughput here will suffer, so keep your own radios off "
            f"it. Loudest: {strongest_first(reporters, 2)}.",
            scope=f"{band}:{channel}",
            evidence={"band": band, "channel": channel, "worst_utilization": worst,
                      "median_utilization": sorted(levels)[len(levels) // 2],
                      "stations": stations, "reporters": reporters},
        ))
    return out


@rule("watched_ap_missing")
def _missing(ctx: RuleContext) -> list[Finding]:
    """A watched BSSID that has stopped appearing - AP down, moved, or jammed."""
    threshold = int(ctx.settings.get("missing_scans_before_alert", 5))
    interval = float(ctx.settings.get("_scan_interval", 20))
    window = threshold * max(interval, 5)
    present = {r["bssid"] for r in ctx.records}

    out = []
    for row in db.watched_candidates():
        bssid = row["bssid"]
        if bssid in present:
            continue
        if not ctx.marks.matches("watch", bssid, row.get("ssid")):
            continue
        gone_for = ctx.now - (row["last_seen"] or 0)
        if window <= gone_for < window * 4:
            out.append(
                Finding("watched_ap_missing", "medium",
                        f"Watched AP has gone quiet: {row.get('ssid') or bssid}",
                        f"Not seen for {int(gone_for)} seconds across the last several scans.",
                        bssid, row.get("ssid"),
                        {"last_seen": row["last_seen"], "seconds_missing": int(gone_for)})
            )
    return out


@rule("enterprise_downgrade_bait")
def _enterprise_bait(ctx: RuleContext) -> list[Finding]:
    """An open or PSK copy of a name that is normally 802.1X."""
    enterprise_names = {
        (r["ssid"] or "").lower() for r in ctx.records if r["enterprise"] and r["ssid"]
    }
    if not enterprise_names:
        return []
    out = []
    for r in ctx.records:
        name = (r["ssid"] or "").lower()
        if name in enterprise_names and not r["enterprise"]:
            out.append(
                Finding("enterprise_downgrade_bait", "critical",
                        f"'{r['ssid']}' is also being offered without 802.1X",
                        "The same name is served both as an enterprise network and as "
                        "something a client can join without certificate validation. "
                        "That is a credential-capture setup.",
                        r["bssid"], r["ssid"],
                        {"security": r["security"], "vendor": r["vendor"]})
            )
    return out


@rule("wps_device_disclosure")
def _wps_disclosure(ctx: RuleContext) -> list[Finding]:
    """How many neighbours name their hardware in every beacon."""
    disclosing = []
    for r in ctx.records:
        wps = (r.get("detail") or {}).get("wps") or {}
        fields = {k: wps.get(k) for k in ("manufacturer", "model_name", "model_number",
                                          "device_name", "serial_number") if wps.get(k)}
        if len(fields) >= 3:
            disclosing.append({
                "bssid": r["bssid"], "ssid": r["ssid"], "channel": r["channel"],
                "rssi": r["rssi"], **fields,
            })
    if not disclosing:
        return []
    serials = sum(1 for d in disclosing if d.get("serial_number"))
    return [Finding(
        "wps_device_disclosure", "low",
        f"{len(disclosing)} APs publish their make and model in every beacon",
        "The WPS element names the hardware, which hands anyone listening a "
        "firmware version to look up CVEs against"
        + (f", and {serials} also publish a serial number" if serials else "")
        + f". Strongest: {strongest_first(disclosing)}.",
        evidence={"disclosing": disclosing, "with_serial_number": serials},
    )]


@rule("adjacent_channel_overlap")
def _overlap(ctx: RuleContext) -> list[Finding]:
    """2.4 GHz APs sitting on non-standard channels that smear across 1/6/11."""
    out = []
    for r in ctx.records:
        if r["band"] != "2.4" or r["channel"] is None:
            continue
        if r["channel"] in (1, 6, 11, 14):
            continue
        if (r["width_mhz"] or 20) > 20:
            out.append({"bssid": r["bssid"], "ssid": r["ssid"],
                        "channel": r["channel"], "rssi": r["rssi"],
                        "width": r["width_mhz"]})
    if not out:
        return []
    return [Finding(
        "adjacent_channel_overlap", "info",
        f"{len(out)} APs run wide channels on 2.4 GHz off the 1/6/11 grid",
        "There are only three non-overlapping channels at 2.4 GHz. A 40 MHz "
        "channel takes out most of the usable spectrum for everyone nearby. "
        f"Strongest: {strongest_first(out)}.",
        evidence={"offenders": out},
    )]


@rule("malformed_ie")
def _malformed(ctx: RuleContext) -> list[Finding]:
    out = []
    for r in ctx.records:
        detail = r.get("detail") or {}
        errors = list(detail.get("parse_errors") or [])
        rsn = detail.get("rsn") or {}
        wpa = detail.get("wpa") or {}
        if rsn.get("malformed"):
            errors.append("RSN element truncated or inconsistent")
        if wpa.get("malformed"):
            errors.append("WPA element truncated or inconsistent")
        if errors:
            out.append(
                Finding("malformed_ie", "medium",
                        f"Malformed beacon data from {r['ssid'] or r['bssid']}",
                        "Elements did not decode cleanly. Buggy firmware does this, and so "
                        "do hand-rolled software APs.",
                        r["bssid"], r["ssid"], {"errors": errors[:5]})
            )
    return out


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def run(
    records: list[dict],
    previous: dict[str, dict],
    marks_rows: list[dict],
    settings: dict,
    new_bssids: set[str],
    scan_interval: float = 20.0,
) -> list[Finding]:
    """Run every enabled rule and return findings that survive marks and suppression."""
    if not settings.get("enabled", True):
        return []

    marks = MarkSet(marks_rows)
    settings = dict(settings)
    settings["_scan_interval"] = scan_interval
    ctx = RuleContext(
        records=records,
        previous=previous,
        marks=marks,
        settings=settings,
        new_bssids=new_bssids,
        now=time.time(),
    )

    floor = SEVERITY_ORDER.get(settings.get("severity_floor", "low"), 1)
    suppress_for = float(settings.get("suppress_seconds", 900))
    max_per_scan = int(settings.get("max_findings_per_scan", 200))

    candidates: list[Finding] = []
    seen_keys: set[str] = set()

    muted = {str(r) for r in (settings.get("muted_rules") or [])}
    for name, fn in REGISTRY:
        if name in muted:
            continue
        try:
            produced = fn(ctx)
        except Exception:
            log.exception("Detection rule '%s' raised; skipping it for this scan", name)
            continue

        for finding in produced:
            if SEVERITY_ORDER.get(finding.severity, 0) < floor:
                continue
            if finding.bssid and marks.matches("ignore", finding.bssid, finding.ssid):
                continue
            key = finding.suppression_key()
            if key in seen_keys:
                continue
            seen_keys.add(key)
            candidates.append(finding)

    # One query for every key beats a round trip per finding.
    suppressed = db.suppressed_keys([f.suppression_key() for f in candidates], ctx.now)
    findings = [f for f in candidates if f.suppression_key() not in suppressed]

    # A first scan in a dense environment can produce hundreds of findings at once.
    # Keep the most serious and say plainly that the rest were held back.
    if len(findings) > max_per_scan:
        findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
        held = len(findings) - max_per_scan
        findings = findings[:max_per_scan]
        findings.append(
            Finding(
                rule="findings_truncated",
                severity="info",
                title=f"{held} further findings were held back this scan",
                detail="The cap keeps a first scan in a dense area from burying the "
                       "serious findings. Raise max_findings_per_scan in the config "
                       "file, or narrow the rules, to see them all.",
            )
        )

    # The truncation notice is the one finding that must never be silenced:
    # suppressing it means the person stops being told things are hidden.
    db.suppress_many([
        (f.suppression_key(), ctx.now + suppress_for)
        for f in findings if f.rule != "findings_truncated"
    ])
    return findings


def rule_names() -> list[str]:
    return [name for name, _ in REGISTRY]

"""
Adapter identity.

The single most important thing this app has to tell you is which radio it is
actually using. This module assembles everything Windows will say about each
wireless interface — capabilities from the Native Wifi API, driver and band
support from netsh, MAC from the adapter list — and scores how likely each one
is to be the external adapter you meant.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import threading
import time
from typing import Any

from . import oui, wlanapi

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Substrings that mark an adapter as an external USB survey radio. Ordered by
# how specific they are, because the first match decides the label.
KNOWN_ADAPTERS = [
    (("awus036axml",), "Alfa AWUS036AXML", "MT7921AU", True),
    (("awus036ax",), "Alfa AWUS036AX", "MT7921AU", True),
    (("awus036acm",), "Alfa AWUS036ACM", "MT7612U", True),
    (("awus036ach", "awus036acs"), "Alfa AWUS036ACH", "RTL8812AU", True),
    (("awus036nha",), "Alfa AWUS036NHA", "AR9271", True),
    (("awus1900",), "Alfa AWUS1900", "RTL8814AU", True),
    (("alfa",), "Alfa adapter", None, True),
    (("panda wireless", "panda pau"), "Panda Wireless", None, True),
    (("tp-link archer t", "archer t"), "TP-Link Archer", None, True),
    (("mt7921", "mediatek wi-fi 6"), "MediaTek MT7921", "MT7921", True),
    (("rtl8812au", "802.11ac usb"), "Realtek USB adapter", None, True),
    (("usb wireless", "wireless usb", "usb wi-fi", "usb 802.11"), "USB adapter", None, True),
]

# Chipsets worth naming even when the adapter is internal.
CHIPSET_HINTS = [
    ("intel", "Intel"), ("qualcomm", "Qualcomm"), ("atheros", "Atheros"),
    ("broadcom", "Broadcom"), ("realtek", "Realtek"), ("mediatek", "MediaTek"),
    ("marvell", "Marvell"), ("ralink", "Ralink"),
]

_netsh_cache: dict[str, Any] = {"at": 0.0, "interfaces": {}, "drivers": {}}
_netsh_lock = threading.Lock()
NETSH_TTL = 8.0


# ---------------------------------------------------------------------------
# netsh enrichment
# ---------------------------------------------------------------------------


def _run_netsh(args: list[str], timeout: int = 15) -> str:
    if not IS_WINDOWS:
        return ""
    try:
        proc = subprocess.run(
            ["netsh", *args], capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, errors="replace",
        )
        return proc.stdout or ""
    except Exception as exc:
        log.debug("netsh %s failed: %s", " ".join(args), exc)
        return ""


def _parse_blocks(text: str) -> list[dict[str, str]]:
    """netsh prints 'Key : Value' lines grouped into blocks separated by blanks."""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                blocks.append(current)
                current = {}
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key and not key.startswith("there is"):
                # Repeated keys (radio types, auth) accumulate rather than overwrite.
                if key in current and value:
                    current[key] = f"{current[key]}, {value}"
                else:
                    current[key] = value
    if current:
        blocks.append(current)
    return blocks


def invalidate_cache() -> None:
    """Force the next lookup to re-read netsh, after a repair changed things."""
    with _netsh_lock:
        _netsh_cache["at"] = 0.0


def _netsh_data() -> tuple[dict, dict]:
    """Cached netsh interface and driver data, keyed by lowercase adapter name."""
    with _netsh_lock:
        if time.time() - _netsh_cache["at"] < NETSH_TTL:
            return _netsh_cache["interfaces"], _netsh_cache["drivers"]

    interfaces: dict[str, dict] = {}
    for block in _parse_blocks(_run_netsh(["wlan", "show", "interfaces"])):
        name = block.get("name")
        if name:
            interfaces[name.lower()] = block

    driver_text = _run_netsh(["wlan", "show", "drivers"])
    drivers: dict[str, dict] = {}
    for block in _parse_blocks(driver_text):
        name = block.get("interface name")
        if name:
            drivers[name.lower()] = block

    # The supported-bands block has no key, so it needs its own pass.
    bands_by_interface = parse_supported_bands(driver_text)
    for interface_name, bands in bands_by_interface.items():
        if interface_name in drivers:
            drivers[interface_name]["_supported_bands"] = bands

    with _netsh_lock:
        _netsh_cache.update({"at": time.time(), "interfaces": interfaces, "drivers": drivers})
    return interfaces, drivers


def _match_netsh(description: str, guid: str, table: dict) -> dict:
    """netsh keys on the connection name ('Wi-Fi'), not the description, so match
    on the description field inside each block."""
    target = description.lower().strip()
    for block in table.values():
        if block.get("description", "").lower().strip() == target:
            return block
    for block in table.values():
        if target and target in block.get("description", "").lower():
            return block
    # A single wireless adapter is unambiguous.
    if len(table) == 1:
        return next(iter(table.values()))
    return {}


def parse_supported_bands(text: str) -> dict[str, list[str]]:
    """Pull the 'Number of supported bands' block out of `netsh wlan show drivers`.

    The block is indented continuation lines with no key, so the generic
    key:value parser drops them:

        Number of supported bands : 3
                                    2.4 GHz [ 0 MHz - 0 MHz]
                                    5 GHz [ 0 MHz - 0 MHz]
                                    6 GHz [ 0 MHz - 0 MHz]

    This is the only authoritative answer for 6 GHz, because a Wi-Fi 6 and a
    Wi-Fi 6E radio both report 802.11ax as their radio type.
    """
    out: dict[str, list[str]] = {}
    current_interface = None
    collecting = False
    for raw in text.splitlines():
        line = raw.strip()
        lower = line.lower()
        if lower.startswith("interface name"):
            current_interface = line.partition(":")[2].strip().lower()
            collecting = False
            continue
        if lower.startswith("number of supported bands"):
            collecting = True
            if current_interface is not None:
                out.setdefault(current_interface, [])
            continue
        if collecting:
            match = re.match(r"^(\d+(?:\.\d+)?)\s*GHz", line, re.IGNORECASE)
            if match and current_interface is not None:
                band = match.group(1)
                # netsh prints 2.4, 5 and 6; normalise 2.4 GHz variants.
                if band.startswith("2"):
                    band = "2.4"
                if band not in out[current_interface]:
                    out[current_interface].append(band)
            elif line and ":" in line:
                collecting = False
    return out


def _parse_radio_types(text: str) -> list[str]:
    """'802.11a 802.11b 802.11g 802.11n 802.11ac 802.11ax' -> band list."""
    if not text:
        return []
    found = re.findall(r"802\.11(\w+)", text.lower())
    return [f"802.11{f}" for f in dict.fromkeys(found)]


def _bands_from_radio_types(radio_types: list[str], phy_types: list[str]) -> list[str]:
    bands = set()
    joined = " ".join(radio_types).lower() + " " + " ".join(phy_types).lower()
    if any(t in joined for t in ("802.11b", "802.11g", "hrdsss", "erp")):
        bands.add("2.4")
    if any(t in joined for t in ("802.11a", "802.11ac", "ofdm", "vht")):
        bands.add("5")
        bands.add("2.4")
    if "802.11n" in joined or "ht" in phy_types:
        bands.add("2.4")
    if any(t in joined for t in ("802.11ax", "he")):
        bands.update({"2.4", "5"})
    if any(t in joined for t in ("802.11be", "eht")):
        bands.update({"2.4", "5", "6"})
    return sorted(bands, key=lambda b: float(b))


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify(description: str) -> dict:
    """Work out what this adapter is and whether it looks external."""
    text = (description or "").lower()
    for needles, label, chipset, external in KNOWN_ADAPTERS:
        if any(n in text for n in needles):
            return {"label": label, "chipset": chipset, "external": external,
                    "recognised": True}
    for needle, vendor in CHIPSET_HINTS:
        if needle in text:
            return {"label": description, "chipset": vendor, "external": False,
                    "recognised": False}
    return {"label": description or "Unknown adapter", "chipset": None,
            "external": False, "recognised": False}


def preference_score(info: dict, preferred_keywords: list[str]) -> int:
    """Higher wins when picking an adapter automatically."""
    score = 0
    text = (info.get("description") or "").lower()
    for keyword in preferred_keywords:
        if keyword and keyword.lower() in text:
            score += 50
    if info.get("external"):
        score += 40
    if info.get("recognised"):
        score += 20
    if "6" in (info.get("bands") or []):
        score += 15
    if info.get("radio_on") is True:
        score += 10
    elif info.get("radio_on") is False:
        score -= 60          # a radio that is off cannot scan
    if info.get("state") == "connected":
        # A connected adapter still scans, but the survey adapter is usually the
        # idle one, and scanning on the connected radio interrupts traffic.
        score -= 5
    return score


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def describe(entry: dict, handle: Any = None) -> dict:
    """Build the full picture for one interface. `entry` comes from
    WlanEnumInterfaces; `handle` is an open WlanHandle when live queries are
    possible."""
    description = entry.get("description", "")
    guid = entry.get("guid", "")
    info: dict[str, Any] = {
        "guid": guid,
        "description": description,
        "declared_bands": None,
        "observed_bands": [],
        "bands_source": None,
        "state": entry.get("state", "unknown"),
        "mac": None,
        "driver": None,
        "driver_date": None,
        "driver_provider": None,
        "radio_types": [],
        "phy_types": [],
        "bands": [],
        "radio_on": None,
        "radio_detail": None,
        "connected_ssid": None,
        "channel": None,
        "max_bssid_list": None,
        "hosted_network": None,
        "error": None,
    }
    info.update(classify(description))

    # Live capability query
    if handle is not None and entry.get("_guid_struct") is not None:
        try:
            capability = handle.capability(entry["_guid_struct"])
            info["phy_types"] = capability["phy_types"]
            info["max_bssid_list"] = capability["max_bssid_list"]
            info["interface_type"] = capability["interface_type"]
        except Exception as exc:
            log.debug("Capability query failed for %s: %s", description, exc)
        try:
            radio = handle.radio_state(entry["_guid_struct"])
            info["radio_on"] = radio["on"]
            info["radio_detail"] = radio["radios"]
        except Exception as exc:
            log.debug("Radio state query failed for %s: %s", description, exc)
        try:
            info["channel"] = handle.channel(entry["_guid_struct"])
        except Exception:
            pass

    # netsh enrichment: driver version, supported radio types, MAC, current SSID
    interfaces, drivers = _netsh_data()
    block = _match_netsh(description, guid, interfaces)
    if block:
        info["mac"] = block.get("physical address")
        info["connected_ssid"] = block.get("ssid") or None
        if block.get("channel") and not info["channel"]:
            try:
                info["channel"] = int(block["channel"])
            except ValueError:
                pass
        if block.get("radio type"):
            info["radio_types"] = _parse_radio_types(block["radio type"])

    driver_block = _match_netsh(description, guid, drivers)
    if driver_block:
        info["driver"] = driver_block.get("version")
        info["driver_date"] = driver_block.get("date")
        info["driver_provider"] = driver_block.get("provider")
        info["hosted_network"] = driver_block.get("hosted network supported")
        radio_types = driver_block.get("radio types supported")
        if radio_types:
            info["radio_types"] = _parse_radio_types(radio_types)
        # Authoritative band list, when the driver reports one.
        declared = driver_block.get("_supported_bands")
        if declared:
            info["declared_bands"] = declared

    if info["mac"]:
        info["vendor"] = oui.db.lookup(info["mac"])
    # Bands we have actually received beacons on beat every other source: if a
    # 6 GHz BSS came back through this adapter, it does 6 GHz, whatever netsh says.
    observed: list[str] = []
    attribution = "this adapter"
    try:
        from . import db as _db

        observed = _db.observed_bands(guid)
        if not observed:
            # Nothing attributed to this GUID: either it has not scanned yet,
            # or the scans were recorded under a different spelling of the same
            # identifier. Fall back to what this machine has heard at all, and
            # say so rather than quietly under-reporting the radio.
            machine_wide = _db.observed_bands()
            if machine_wide:
                observed = machine_wide
                attribution = "this machine"
    except Exception:
        observed = []
    info["observed_bands"] = observed
    info["bands_attribution"] = attribution if observed else None

    # An external USB radio's brand is not in the Windows description, but the
    # USB device tree knows it. Only used when exactly one is present, because
    # with two plugged in there is nothing to match them against.
    if info.get("external"):
        try:
            from . import usbwifi

            known = [d for d in usbwifi.summarise().get("recognised") or []
                     if d.get("model")]
            if len(known) == 1:
                info["usb_model"] = known[0]["model"]
        except Exception:
            log.debug("Could not read the USB device tree", exc_info=True)

    # Prefer what the driver states over anything inferred from radio types.
    if info.get("declared_bands"):
        info["bands"] = sorted(info["declared_bands"], key=lambda b: float(b))
        info["bands_source"] = "driver"
    else:
        info["bands"] = _bands_from_radio_types(info["radio_types"], info["phy_types"])
        info["bands_source"] = "inferred"

    # Merge in anything seen for real that the other sources missed.
    if observed:
        merged = list(dict.fromkeys(list(info["bands"]) + observed))
        gained = [b for b in observed if b not in info["bands"]]
        info["bands"] = sorted(
            merged, key=lambda b: float(b) if b and b[0].isdigit() else 99
        )
        if gained:
            info["bands_source"] = (
                "observed" if info["bands_source"] != "driver" else "driver + observed"
            )
    info["band_label"] = " / ".join(
        wlanapi.BAND_LABELS.get(b, b) for b in info["bands"]
    ) or "unknown"
    info["state_label"] = _state_label(info)
    info["summary"] = _summary(info)
    info["band_note"] = _band_note(info)
    info["read_at"] = time.time()
    return finalise(info)


def _state_label(info: dict) -> str:
    """Plain-language association state.

    A survey adapter is deliberately not joined to any network, so Windows
    reports "disconnected". That is correct but reads like a fault, which is
    exactly the wrong impression for the radio you are scanning with.
    """
    state = (info.get("state") or "").lower()
    if state == "connected":
        ssid = info.get("connected_ssid")
        return f"joined to {ssid}" if ssid else "joined to a network"
    if state in ("disconnected", "not_ready"):
        return "not joined to a network"
    if state == "associating":
        return "joining a network"
    if state == "discovering":
        return "looking for networks"
    return state or "unknown"


# Adapters whose hardware covers 6 GHz, so we can tell when a driver is the
# thing holding the band back rather than the radio.
SIX_GHZ_CAPABLE = ("awus036axml", "mt7921au", "mt7922", "axe3000", "pau0f")


def _band_note(info: dict) -> str | None:
    text = " ".join(
        str(info.get(k) or "") for k in ("description", "label", "chipset")
    ).lower()
    bands = info.get("bands") or []
    source = info.get("bands_source") or ""
    if "6" in bands and "observed" in source:
        where = info.get("bands_attribution") or "this adapter"
        return (f"6 GHz confirmed from beacons {where} actually received, even "
                "though the driver does not advertise the band.")
    hardware_6e = any(n in text for n in SIX_GHZ_CAPABLE)
    if hardware_6e and "6" not in bands:
        return (
            "This adapter's hardware covers 6 GHz, but the driver currently loaded "
            "only reports 2.4 and 5 GHz. Installing Alfa's or MediaTek's own driver "
            "usually adds the band."
        )
    return None


def _summary(info: dict) -> str:
    """One line a person can read at a glance."""
    parts = [info.get("label") or info.get("description") or "Adapter"]
    if info.get("chipset"):
        parts.append(f"({info['chipset']})")
    bits = []
    if info.get("bands"):
        bits.append(info["band_label"])
    if info.get("radio_on") is False:
        bits.append("radio off")
    elif info.get("state_label"):
        bits.append(info["state_label"])
    if bits:
        parts.append("- " + ", ".join(bits))
    return " ".join(parts)


def enumerate_adapters(source: Any, preferred_keywords: list[str] | None = None) -> list[dict]:
    """Every wireless interface with full detail, best candidate first."""
    preferred_keywords = preferred_keywords or []
    try:
        entries = source.interfaces()
    except Exception as exc:
        log.warning("Could not enumerate interfaces: %s", exc)
        return []

    handle = None
    if IS_WINDOWS and wlanapi.available() and getattr(source, "name", "") == "windows":
        try:
            handle = wlanapi.WlanHandle()
        except Exception as exc:
            log.debug("Could not open a handle for capability queries: %s", exc)

    results = []
    try:
        for entry in entries:
            try:
                info = describe(entry, handle)
            except Exception as exc:
                log.warning("Could not describe %s: %s", entry.get("description"), exc)
                info = {"guid": entry.get("guid"), "description": entry.get("description"),
                        "state": entry.get("state"), "error": str(exc),
                        "label": entry.get("description"), "external": False,
                        "bands": [], "summary": entry.get("description", "Adapter")}
            info["score"] = preference_score(info, preferred_keywords)
            results.append(info)
    finally:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass

    results.sort(key=lambda i: -i.get("score", 0))
    for index, info in enumerate(results):
        info["recommended"] = index == 0 and len(results) > 0
    return results


# Every key describe() produces. The mock source is finalised against this so
# its shape can never drift from the real one.
ADAPTER_KEYS = (
    "guid", "description", "state", "state_label", "read_at", "mac", "vendor",
    "driver", "driver_date",
    "driver_provider", "radio_types", "phy_types", "bands", "declared_bands",
    "observed_bands", "bands_source", "band_label", "band_note", "radio_on",
    "radio_detail", "connected_ssid", "channel", "max_bssid_list",
    "hosted_network", "interface_type", "error", "label", "chipset", "external",
    "recognised", "summary", "score", "recommended", "usb_model",
    "bands_attribution",
)


def finalise(info: dict) -> dict:
    """Guarantee every adapter dict carries the full key set.

    Both the live path and the mock source come through here, so anything
    derived belongs in this function rather than only in describe().
    """
    out = dict(info)
    for key in ADAPTER_KEYS:
        out.setdefault(key, None)
    for key in ("radio_types", "phy_types", "bands", "observed_bands"):
        if out.get(key) is None:
            out[key] = []
    if not out.get("state_label"):
        out["state_label"] = _state_label(out)
    if not out.get("read_at"):
        out["read_at"] = time.time()
    return out


def mock_adapters() -> list[dict]:
    """Adapter list for the synthetic source, so the picker has something to show."""
    observed: list[str] = []
    try:
        from . import db as _db

        observed = _db.observed_bands()
    except Exception:
        observed = []
    bands = sorted(
        set(["2.4", "5", "6"]) | set(observed),
        key=lambda b: float(b) if b and b[0].isdigit() else 99,
    )
    return [finalise({
            "guid": "{00000000-0000-0000-0000-000000000001}",
            "description": "ALFA AWUS036AXML (mock)",
            "label": "Alfa AWUS036AXML",
            "chipset": "MT7921AU",
            "external": True,
            "recognised": True,
            "state": "disconnected",
            "mac": "00:c0:ca:aa:bb:cc",
            "vendor": "Alfa Network",
            "driver": "3.0.0.1 (mock)",
            "driver_provider": "MediaTek",
            "radio_types": ["802.11a", "802.11b", "802.11g", "802.11n", "802.11ac", "802.11ax"],
            "phy_types": ["ht", "vht", "he"],
            "bands": bands,
            "band_label": " / ".join(f"{b} GHz" for b in bands),
            "radio_on": True,
            "channel": None,
            "connected_ssid": None,
            "max_bssid_list": 128,
            "summary": "Alfa AWUS036AXML (MT7921AU) - 2.4 GHz / 5 GHz / 6 GHz, disconnected",
            "score": 125,
            "recommended": True,
            "error": None,
            "declared_bands": ["2.4", "5", "6"],
            "observed_bands": observed,
            "bands_source": "driver",
            "band_note": None,
            "interface_type": "native 802.11",
            "radio_detail": None,
            "driver_date": None,
            "hosted_network": "No",
        })
    ]

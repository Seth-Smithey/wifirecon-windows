"""
Synthetic scan source.

Builds real IE blobs byte-for-byte so the parser, detections and UI can all be
exercised without a radio. Used automatically off Windows, or on Windows by
setting WIFIRECON_MOCK=1.
"""

from __future__ import annotations

import random
import struct
import time
from typing import Any

OUI_RSN = b"\x00\x0f\xac"
OUI_MS = b"\x00\x50\xf2"


def _element(eid: int, payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("Element payload cannot exceed 255 bytes")
    return bytes([eid, len(payload)]) + payload


def _ext_element(ext_id: int, payload: bytes) -> bytes:
    return _element(255, bytes([ext_id]) + payload)


def _rsn(akms: list[int], pairwise: list[int] = None, group: int = 4,
         mfp_capable: bool = True, mfp_required: bool = False) -> bytes:
    pairwise = pairwise or [4]
    body = struct.pack("<H", 1)
    body += OUI_RSN + bytes([group])
    body += struct.pack("<H", len(pairwise))
    for cipher in pairwise:
        body += OUI_RSN + bytes([cipher])
    body += struct.pack("<H", len(akms))
    for akm in akms:
        body += OUI_RSN + bytes([akm])
    caps = 0
    if mfp_required:
        caps |= 0x0040
    if mfp_capable:
        caps |= 0x0080
    body += struct.pack("<H", caps)
    return _element(48, body)


def _wpa1() -> bytes:
    body = OUI_MS + bytes([0x01]) + struct.pack("<H", 1)
    body += OUI_MS + bytes([2])                 # group: TKIP
    body += struct.pack("<H", 1) + OUI_MS + bytes([2])
    body += struct.pack("<H", 1) + OUI_MS + bytes([2])
    return _element(221, body)


def _wps(manufacturer: str, model: str, device: str, state: int = 2,
         config_methods: int = 0x0084) -> bytes:
    def tlv(attr: int, value: bytes) -> bytes:
        return struct.pack(">HH", attr, len(value)) + value

    body = OUI_MS + bytes([0x04])
    body += tlv(0x104A, bytes([0x10]))
    body += tlv(0x1044, bytes([state]))
    body += tlv(0x1021, manufacturer.encode())
    body += tlv(0x1023, model.encode())
    body += tlv(0x1011, device.encode())
    body += tlv(0x1008, struct.pack(">H", config_methods))
    return _element(221, body)


def _wmm() -> bytes:
    return _element(221, OUI_MS + bytes([0x02, 0x01, 0x01]) + b"\x00" * 18)


def _country(code: str = "US", env: str = "I") -> bytes:
    return _element(7, code.encode() + env.encode() + bytes([1, 11, 30]))


def _bss_load(stations: int, utilization_pct: float) -> bytes:
    raw = max(0, min(255, int(utilization_pct / 100 * 255)))
    return _element(11, struct.pack("<H", stations) + bytes([raw]) + struct.pack("<H", 0))


def _ht_operation(channel: int, wide: bool = True) -> bytes:
    secondary = 1 if wide else 0
    info = bytes([channel, (secondary & 0x03) | (0x04 if wide else 0x00)]) + b"\x00" * 20
    return _element(61, info)


def _vht_operation(width: int, seg0: int) -> bytes:
    ch_width = {20: 0, 40: 0, 80: 1, 160: 2}.get(width, 0)
    return _element(192, bytes([ch_width, seg0, 0]) + b"\x00\x00")


def _profile(
    ssid: str,
    channel: int,
    band: str,
    security: str,
    *,
    hidden: bool = False,
    wps: tuple[str, str, str] | None = None,
    stations: int = 0,
    utilization: float = 0.0,
    width: int = 20,
    he: bool = False,
    country: str = "US",
    ft: bool = False,
    beacon: int = 100,
) -> bytes:
    ies = b""
    ies += _element(0, b"" if hidden else ssid.encode("utf-8"))
    ies += _element(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))
    ies += _element(3, bytes([channel & 0xFF]))
    ies += _country(country)

    if security == "wpa3":
        ies += _rsn([8], mfp_capable=True, mfp_required=True)
    elif security == "wpa3-transition":
        ies += _rsn([8, 2], mfp_capable=True, mfp_required=False)
    elif security == "wpa2":
        ies += _rsn([2], mfp_capable=True)
    elif security == "wpa2-nopmf":
        ies += _rsn([2], mfp_capable=False)
    elif security == "enterprise":
        ies += _rsn([1, 3] if ft else [1], mfp_capable=True, mfp_required=True)
    elif security == "wpa2-tkip":
        ies += _rsn([2], pairwise=[2, 4], group=2, mfp_capable=False)
    elif security == "wpa1":
        ies += _wpa1()
    elif security == "owe":
        ies += _rsn([18], mfp_capable=True, mfp_required=True)
    # "open" and "wep" add nothing here; WEP is signalled by the privacy bit.

    ies += _element(45, b"\x2d\x00" + b"\x00" * 24)   # HT capabilities
    ies += _ht_operation(channel, wide=width >= 40)
    if width >= 80:
        ies += _element(191, b"\x00" * 12)
        ies += _vht_operation(width, channel + 6)
    if he:
        ies += _ext_element(35, b"\x00" * 20)
        ies += _ext_element(36, b"\x00" * 8)
    if ft:
        ies += _element(54, b"\xab\xcd\x01")
    ies += _element(70, b"\x02\x00\x00\x00\x00")      # RM enabled caps (802.11k)
    ies += _element(127, b"\x00\x00\x08\x00")         # ext caps with BSS transition
    if stations or utilization:
        ies += _bss_load(stations, utilization)
    if wps:
        ies += _wps(*wps)
    ies += _wmm()
    ies += _element(221, bytes.fromhex("00156d") + b"\x01\x02\x03")
    return ies


def _freq(channel: int, band: str) -> int:
    if band == "2.4":
        return (2407 + channel * 5) * 1000
    if band == "5":
        return (5000 + channel * 5) * 1000
    if band == "6":
        return (5950 + channel * 5) * 1000
    return 0


# BSSID, SSID, channel, band, security, extras
FIXTURES: list[dict[str, Any]] = [
    {"bssid": "02:00:00:00:00:01", "ssid": "Example_Home", "ch": 6, "band": "2.4",
     "sec": "wpa3-transition", "rssi": -42, "width": 20, "beacon": 100},
    {"bssid": "02:00:00:00:00:02", "ssid": "Example_Home", "ch": 44, "band": "5",
     "sec": "wpa3-transition", "rssi": -48, "width": 80, "he": True},
    {"bssid": "02:00:00:00:00:03", "ssid": "Example_Network_03", "ch": 11, "band": "2.4",
     "sec": "wpa2", "rssi": -51, "stations": 14, "util": 38},
    {"bssid": "02:00:00:00:00:04", "ssid": "Example_Network_04", "ch": 149, "band": "5",
     "sec": "wpa2", "rssi": -58, "width": 80},
    {"bssid": "02:00:00:00:00:05", "ssid": "", "ch": 36, "band": "5",
     "sec": "wpa2", "rssi": -63, "hidden": True},
    {"bssid": "02:00:00:00:00:06", "ssid": "Example_Network_06", "ch": 1, "band": "2.4",
     "sec": "wpa2-tkip", "rssi": -71,
     "wps": ("NETGEAR", "R6700", "R6700 AP"), "stations": 3, "util": 22},
    {"bssid": "02:00:00:00:00:07", "ssid": "Example_Network_07", "ch": 3, "band": "2.4",
     "sec": "wpa1", "rssi": -78, "width": 40},
    {"bssid": "02:00:00:00:00:08", "ssid": "attwifi", "ch": 6, "band": "2.4",
     "sec": "open", "rssi": -39, "beacon": 102},
    {"bssid": "02:00:00:00:00:09", "ssid": "Example_Hоme", "ch": 6, "band": "2.4",
     "sec": "open", "rssi": -37},
    {"bssid": "02:00:00:00:00:0a", "ssid": "Example_Network_10", "ch": 40, "band": "5",
     "sec": "wpa2", "rssi": -55},
    {"bssid": "02:00:00:00:00:0b", "ssid": "Example_Network_10", "ch": 40, "band": "5",
     "sec": "enterprise", "rssi": -60, "ft": True, "width": 40},
    {"bssid": "02:00:00:00:00:0c", "ssid": "Example_Network_12", "ch": 6, "band": "2.4",
     "sec": "open", "rssi": -66},
    {"bssid": "02:00:00:00:00:0d", "ssid": "Example_Network_13", "ch": 11, "band": "2.4",
     "sec": "wep", "rssi": -80, "wep": True},
    {"bssid": "02:00:00:00:00:0e", "ssid": "Example_Network_14", "ch": 157, "band": "5",
     "sec": "wpa2", "rssi": -69, "width": 80, "he": True},
    {"bssid": "02:00:00:00:00:0f", "ssid": "Example_Network_15", "ch": 37, "band": "6",
     "sec": "wpa3", "rssi": -59, "width": 160, "he": True},
    {"bssid": "02:00:00:00:00:10", "ssid": "Example_Network_16", "ch": 1, "band": "2.4",
     "sec": "open", "rssi": -74, "beacon": 300},
    {"bssid": "02:00:00:00:00:11", "ssid": "Example_Network_17", "ch": 9, "band": "2.4",
     "sec": "open", "rssi": -73, "width": 40},
    {"bssid": "02:00:00:00:00:12", "ssid": "Example_Network_18", "ch": 60, "band": "5",
     "sec": "wpa2-nopmf", "rssi": -77, "width": 80, "country": "GB"},
    {"bssid": "02:00:00:00:00:13", "ssid": "Example_Network_19", "ch": 6, "band": "2.4",
     "sec": "wpa2", "rssi": -82,
     "wps": ("Hewlett-Packard", "OfficeJet 8710", "HP-Print-8710")},
    {"bssid": "02:00:00:00:00:14", "ssid": "Example_Network_20", "ch": 149, "band": "5",
     "sec": "owe", "rssi": -68, "width": 80},
]


class MockSource:
    """Drop-in replacement for WindowsSource."""

    name = "mock"

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed if seed is not None else 1337)
        self._tick = 0
        self._entries = self._build()

    def _build(self) -> list[dict]:
        entries = []
        for fixture in FIXTURES:
            ies = _profile(
                fixture["ssid"],
                fixture["ch"],
                fixture["band"],
                fixture["sec"],
                hidden=fixture.get("hidden", False),
                wps=fixture.get("wps"),
                stations=fixture.get("stations", 0),
                utilization=fixture.get("util", 0),
                width=fixture.get("width", 20),
                he=fixture.get("he", False),
                country=fixture.get("country", "US"),
                ft=fixture.get("ft", False),
            )
            # ESS | short preamble | short slot time. Privacy is added below.
            capability = 0x0421
            if fixture["sec"] not in ("open",) or fixture.get("wep"):
                capability |= 0x0010
            entries.append(
                {
                    "bssid": fixture["bssid"],
                    "ssid_bytes": b"" if fixture.get("hidden") else fixture["ssid"].encode(),
                    "phy_type": "he" if fixture.get("he") else "ht",
                    "bss_type": "infrastructure",
                    "rssi": fixture["rssi"],
                    "link_quality": max(0, min(100, 2 * (fixture["rssi"] + 100))),
                    "in_reg_domain": True,
                    "beacon_period": fixture.get("beacon", 100),
                    "timestamp": 0,
                    "host_timestamp": 0,
                    "capability": capability,
                    "freq_khz": _freq(fixture["ch"], fixture["band"]),
                    "rates": [{"mbps": 6.0, "basic": True}, {"mbps": 54.0, "basic": False}],
                    "ie": ies,
                    "_base_rssi": fixture["rssi"],
                }
            )
        return entries

    def interfaces(self) -> list[dict]:
        return [
            {
                "guid": "{00000000-0000-0000-0000-000000000001}",
                "_guid_struct": "{00000000-0000-0000-0000-000000000001}",
                "description": "ALFA AWUS036AXML (mock)",
                "state": "disconnected",
            }
        ]

    def trigger_scan(self, guid: Any) -> None:
        self._tick += 1

    def read_bss(self, guid: Any) -> list[dict]:
        out = []
        for entry in self._entries:
            # Skip a couple of far-away APs at random so "missing" logic has something
            # to chew on, and jitter RSSI the way a real survey does.
            if entry["_base_rssi"] < -75 and self._rng.random() < 0.25:
                continue
            copy = dict(entry)
            copy["rssi"] = max(-95, min(-20, entry["_base_rssi"] + self._rng.randint(-4, 4)))
            copy["host_timestamp"] = int(time.time() * 1_000_000)
            copy.pop("_base_rssi", None)
            out.append(copy)
        return out

    def close(self) -> None:
        return None

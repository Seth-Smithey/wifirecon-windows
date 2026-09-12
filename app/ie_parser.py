"""
802.11 information element parsing.

Input is the raw IE blob from a beacon or probe response. Output is a plain
dict of decoded facts. Everything here is pure and side-effect free so it can be
unit tested against captured blobs.
"""

from __future__ import annotations

import struct
from typing import Any

# --- element IDs -----------------------------------------------------------
EID_SSID = 0
EID_SUPPORTED_RATES = 1
EID_DS_PARAMS = 3
EID_TIM = 5
EID_COUNTRY = 7
EID_BSS_LOAD = 11
EID_CHALLENGE = 16
EID_POWER_CONSTRAINT = 32
EID_TPC_REPORT = 35
EID_ERP = 42
EID_HT_CAPABILITIES = 45
EID_RSN = 48
EID_EXTENDED_RATES = 50
EID_MOBILITY_DOMAIN = 54
EID_HT_OPERATION = 61
EID_RM_ENABLED_CAPS = 70
EID_OVERLAPPING_BSS = 74
EID_EXTENDED_CAPS = 127
EID_VHT_CAPABILITIES = 191
EID_VHT_OPERATION = 192
EID_TX_POWER_ENVELOPE = 195
EID_REDUCED_NEIGHBOR = 201
EID_INTERWORKING = 107
EID_ADVERTISEMENT_PROTOCOL = 108
EID_ROAMING_CONSORTIUM = 111
EID_MESH_ID = 114
EID_VENDOR = 221
EID_EXTENSION = 255

# --- element ID extensions (inside EID 255) --------------------------------
# Note: the 802.11be numbers moved around during drafting. Treat EHT detection
# as best effort and fall back on the PHY type reported by the driver.
EXT_HE_CAPABILITIES = 35
EXT_HE_OPERATION = 36
EXT_SPATIAL_REUSE = 39
EXT_MU_EDCA = 38
EXT_HE_6GHZ_BAND_CAP = 59
EXT_EHT_OPERATION = 106
EXT_MULTI_LINK = 107
EXT_EHT_CAPABILITIES = 108

OUI_MS = b"\x00\x50\xf2"
OUI_WFA = b"\x50\x6f\x9a"
OUI_IEEE_RSN = b"\x00\x0f\xac"

CIPHER_SUITES = {
    0: "Use-Group",
    1: "WEP-40",
    2: "TKIP",
    3: "Reserved",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    7: "Group-Not-Allowed",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

AKM_SUITES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    10: "AP-PeerKey",
    11: "802.1X-Suite-B",
    12: "802.1X-Suite-B-192",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
    19: "FT-PSK-SHA384",
    20: "PSK-SHA384",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}

WPS_ATTRS = {
    0x1008: "config_methods",
    0x1011: "device_name",
    0x1012: "device_password_id",
    0x1021: "manufacturer",
    0x1023: "model_name",
    0x1024: "model_number",
    0x1041: "selected_registrar",
    0x1042: "serial_number",
    0x1044: "wps_state",
    0x1047: "uuid_e",
    0x1049: "vendor_extension",
    0x1054: "primary_device_type",
    0x103B: "response_type",
    0x104A: "version",
}

WPS_STATE = {1: "unconfigured", 2: "configured"}

WPS_CONFIG_METHODS = [
    (0x0001, "USBA"),
    (0x0002, "Ethernet"),
    (0x0004, "Label"),
    (0x0008, "Display"),
    (0x0010, "ExtNFCToken"),
    (0x0020, "IntNFCToken"),
    (0x0040, "NFCInterface"),
    (0x0080, "PushButton"),
    (0x0100, "Keypad"),
    (0x0280, "PhysicalPushButton"),
    (0x2008, "VirtualDisplay"),
    (0x0480, "VirtualPushButton"),
]

# Vendor IE OUIs worth naming when we see them.
VENDOR_OUI_NAMES = {
    b"\x00\x50\xf2": "Microsoft/WFA",
    b"\x50\x6f\x9a": "Wi-Fi Alliance",
    b"\x00\x0b\x86": "Aruba/HPE",
    b"\x00\x40\x96": "Cisco Aironet",
    b"\x00\x1b\x2f": "NETGEAR",
    b"\x00\x03\x7f": "Atheros",
    b"\x00\x10\x18": "Broadcom",
    b"\x00\x17\xf2": "Apple",
    b"\x8c\xfd\xf0": "Qualcomm",
    b"\x00\x90\x4c": "Epigram/Broadcom",
    b"\xf8\x32\xe4": "ASUS",
    b"\x00\x1a\x11": "Google",
    b"\x00\x15\x6d": "Ubiquiti",
    b"\xfc\xec\xda": "Ubiquiti",
    b"\x18\xfe\x34": "Espressif",
    b"\x00\x13\x74": "Atheros Comms",
    b"\x00\xe0\x4c": "Realtek",
    b"\x00\x0c\xe7": "MediaTek",
    b"\x00\x1d\x0f": "TP-Link",
    b"\x00\x24\x6c": "Aruba Networks",
    b"\x00\x0c\x43": "Ralink",
    b"\x50\x6f\x9a\x16": "Wi-Fi Alliance P2P",
}


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _suite_name(data: bytes, off: int, table: dict[int, str]) -> str:
    oui = data[off : off + 3]
    stype = data[off + 3]
    if oui == OUI_IEEE_RSN:
        return table.get(stype, f"Unknown-{stype}")
    if oui == OUI_MS:
        return table.get(stype, f"MS-{stype}")
    return f"{oui.hex(':')}:{stype}"


def iter_elements(blob: bytes):
    """Yield (element_id, ext_id_or_None, payload) tuples. Tolerates truncation."""
    i = 0
    n = len(blob)
    while i + 2 <= n:
        eid = blob[i]
        length = blob[i + 1]
        start = i + 2
        end = start + length
        if end > n:
            # Truncated tail; stop rather than raising.
            return
        payload = blob[start:end]
        if eid == EID_EXTENSION and length >= 1:
            yield eid, payload[0], payload[1:]
        else:
            yield eid, None, payload
        i = end


def parse_rsn(payload: bytes) -> dict[str, Any]:
    """Parse an RSN element body (EID 48)."""
    out: dict[str, Any] = {
        "version": None,
        "group_cipher": None,
        "pairwise_ciphers": [],
        "akms": [],
        "mfp_capable": False,
        "mfp_required": False,
        "pmkid_count": 0,
        "group_mgmt_cipher": None,
        "preauth": False,
        "no_pairwise": False,
        "ptksa_replay_counters": None,
        "gtksa_replay_counters": None,
        "malformed": False,
    }
    try:
        if len(payload) < 2:
            out["malformed"] = True
            return out
        off = 0
        out["version"] = _u16(payload, off)
        off += 2

        if off + 4 <= len(payload):
            out["group_cipher"] = _suite_name(payload, off, CIPHER_SUITES)
            off += 4
        if off + 2 <= len(payload):
            count = _u16(payload, off)
            off += 2
            # Sanity clamp: a real AP never advertises hundreds of suites.
            if count > 32:
                out["malformed"] = True
                count = min(count, 32)
            for _ in range(count):
                if off + 4 > len(payload):
                    out["malformed"] = True
                    break
                out["pairwise_ciphers"].append(_suite_name(payload, off, CIPHER_SUITES))
                off += 4
        if off + 2 <= len(payload):
            count = _u16(payload, off)
            off += 2
            if count > 32:
                out["malformed"] = True
                count = min(count, 32)
            for _ in range(count):
                if off + 4 > len(payload):
                    out["malformed"] = True
                    break
                out["akms"].append(_suite_name(payload, off, AKM_SUITES))
                off += 4
        if off + 2 <= len(payload):
            caps = _u16(payload, off)
            off += 2
            out["preauth"] = bool(caps & 0x0001)
            out["no_pairwise"] = bool(caps & 0x0002)
            out["ptksa_replay_counters"] = 1 << ((caps >> 2) & 0x3)
            out["gtksa_replay_counters"] = 1 << ((caps >> 4) & 0x3)
            out["mfp_required"] = bool(caps & 0x0040)
            out["mfp_capable"] = bool(caps & 0x0080)
        if off + 2 <= len(payload):
            out["pmkid_count"] = _u16(payload, off)
            off += 2
            off += 16 * min(out["pmkid_count"], 16)
        if off + 4 <= len(payload):
            out["group_mgmt_cipher"] = _suite_name(payload, off, CIPHER_SUITES)
    except (struct.error, IndexError):
        out["malformed"] = True
    return out


def parse_wpa(payload: bytes) -> dict[str, Any]:
    """Parse a WPA1 vendor element body (after the 00:50:F2:01 header)."""
    out: dict[str, Any] = {
        "version": None,
        "group_cipher": None,
        "pairwise_ciphers": [],
        "akms": [],
        "malformed": False,
    }
    try:
        off = 0
        if len(payload) < 2:
            out["malformed"] = True
            return out
        out["version"] = _u16(payload, off)
        off += 2
        if off + 4 <= len(payload):
            out["group_cipher"] = _suite_name(payload, off, CIPHER_SUITES)
            off += 4
        if off + 2 <= len(payload):
            count = min(_u16(payload, off), 32)
            off += 2
            for _ in range(count):
                if off + 4 > len(payload):
                    out["malformed"] = True
                    break
                out["pairwise_ciphers"].append(_suite_name(payload, off, CIPHER_SUITES))
                off += 4
        if off + 2 <= len(payload):
            count = min(_u16(payload, off), 32)
            off += 2
            for _ in range(count):
                if off + 4 > len(payload):
                    out["malformed"] = True
                    break
                out["akms"].append(_suite_name(payload, off, AKM_SUITES))
                off += 4
    except (struct.error, IndexError):
        out["malformed"] = True
    return out


def parse_wps(payload: bytes) -> dict[str, Any]:
    """Parse WPS TLVs (after the 00:50:F2:04 header). Big-endian type/length."""
    out: dict[str, Any] = {"present": True}
    i = 0
    n = len(payload)
    while i + 4 <= n:
        attr, length = struct.unpack_from(">HH", payload, i)
        i += 4
        if i + length > n:
            break
        value = payload[i : i + length]
        i += length
        name = WPS_ATTRS.get(attr)
        if not name:
            continue
        if name == "wps_state" and length >= 1:
            out["state"] = WPS_STATE.get(value[0], f"unknown({value[0]})")
        elif name in ("manufacturer", "model_name", "model_number", "device_name", "serial_number"):
            try:
                text = value.decode("utf-8", "replace").rstrip("\x00").strip()
            except Exception:
                text = value.hex()
            if text:
                out[name] = text
        elif name == "device_password_id" and length >= 2:
            out["device_password_id"] = struct.unpack(">H", value[:2])[0]
        elif name == "selected_registrar" and length >= 1:
            out["selected_registrar"] = bool(value[0])
        elif name == "config_methods" and length >= 2:
            bits = struct.unpack(">H", value[:2])[0]
            out["config_methods"] = [name for mask, name in WPS_CONFIG_METHODS if bits & mask == mask]
            out["config_methods_raw"] = bits
        elif name == "version" and length >= 1:
            out["version"] = f"{value[0] >> 4}.{value[0] & 0x0F}"
        elif name == "uuid_e":
            out["uuid_e"] = value.hex()
    return out


def _channel_from_freq(freq_khz: int) -> tuple[int | None, str]:
    """Map a centre frequency in kHz to a channel number and band label."""
    if not freq_khz:
        return None, "unknown"
    mhz = freq_khz / 1000.0
    if 2401 <= mhz <= 2495:
        if abs(mhz - 2484) < 1:
            return 14, "2.4"
        ch = int(round((mhz - 2407) / 5))
        return (ch if 1 <= ch <= 13 else None), "2.4"
    if 4900 <= mhz < 5000:
        return int(round((mhz - 4000) / 5)), "5"
    if 5000 <= mhz <= 5925:
        return int(round((mhz - 5000) / 5)), "5"
    if 5925 < mhz <= 7125:
        # 6 GHz channel 1 is centred at 5955 MHz, spaced 5 MHz.
        ch = int(round((mhz - 5950) / 5))
        return (ch if ch >= 1 else None), "6"
    if 57000 <= mhz <= 71000:
        return int(round((mhz - 56160) / 2160)), "60"
    return None, "unknown"


def _vht_width(vht_op: bytes, ht_op: bytes) -> int | None:
    """Best-effort channel width in MHz from VHT/HT operation elements."""
    width = None
    if ht_op and len(ht_op) >= 2:
        secondary = ht_op[1] & 0x03
        sta_width = bool(ht_op[1] & 0x04)
        width = 40 if (sta_width and secondary in (1, 3)) else 20
    if vht_op and len(vht_op) >= 3:
        ch_width = vht_op[0]
        seg0, seg1 = vht_op[1], vht_op[2]
        if ch_width == 0:
            pass  # 20 or 40, keep the HT answer
        elif ch_width == 1:
            if seg1 and abs(seg1 - seg0) == 8:
                width = 160
            elif seg1 and abs(seg1 - seg0) > 8:
                width = 80  # 80+80, report the primary segment
            else:
                width = 80
        elif ch_width == 2:
            width = 160
        elif ch_width == 3:
            width = 80
    return width


def _he_width(he_op: bytes) -> int | None:
    """6 GHz operation info inside the HE Operation element carries the width."""
    if not he_op or len(he_op) < 6:
        return None
    params = he_op[0] | (he_op[1] << 8) | (he_op[2] << 16)
    six_ghz_present = bool(params & 0x020000)
    if not six_ghz_present:
        return None
    off = 6
    if he_op[3] & 0x40:  # VHT operation info present
        off += 3
    if params & 0x008000:  # co-hosted BSS
        off += 1
    if off + 4 < len(he_op):
        control = he_op[off + 1]
        return {0: 20, 1: 40, 2: 80, 3: 160}.get(control & 0x03)
    return None


def parse_ies(blob: bytes, freq_khz: int = 0) -> dict[str, Any]:
    """Decode an IE blob into a flat dict of facts."""
    info: dict[str, Any] = {
        "ssid": None,
        "ssid_hidden": False,
        "ssid_raw": None,
        "channel": None,
        "band": "unknown",
        "width_mhz": None,
        "country": None,
        "country_env": None,
        "max_tx_power": None,
        "power_constraint": None,
        "rsn": None,
        "wpa": None,
        "wps": None,
        "bss_load": None,
        "ht": False,
        "vht": False,
        "he": False,
        "eht": False,
        "wmm": False,
        "ft_80211r": False,
        "rm_80211k": False,
        "bss_transition_80211v": False,
        "interworking": False,
        "hotspot20": False,
        "mesh": False,
        "vendor_ies": [],
        "vendor_names": [],
        "element_ids": [],
        "ie_hash": None,
        "parse_errors": [],
        "colocated_6ghz": False,
    }

    ht_op = b""
    vht_op = b""
    he_op = b""

    for eid, ext, payload in iter_elements(blob):
        try:
            if ext is not None:
                info["element_ids"].append(f"255.{ext}")
            else:
                info["element_ids"].append(str(eid))

            if eid == EID_SSID:
                info["ssid_raw"] = payload.hex()
                if len(payload) == 0 or all(b == 0 for b in payload):
                    info["ssid_hidden"] = True
                    info["ssid"] = ""
                else:
                    info["ssid"] = payload.decode("utf-8", "replace")
            elif eid == EID_DS_PARAMS and payload:
                info["channel"] = payload[0]
            elif eid == EID_COUNTRY and len(payload) >= 3:
                info["country"] = payload[:2].decode("ascii", "replace")
                env = chr(payload[2]) if 32 <= payload[2] < 127 else "?"
                info["country_env"] = {"I": "indoor", "O": "outdoor", " ": "any"}.get(env, env)
                if len(payload) >= 6:
                    info["max_tx_power"] = payload[5]
            elif eid == EID_POWER_CONSTRAINT and payload:
                info["power_constraint"] = payload[0]
            elif eid == EID_BSS_LOAD and len(payload) >= 5:
                info["bss_load"] = {
                    "station_count": _u16(payload, 0),
                    "channel_utilization_pct": round(payload[2] / 255 * 100, 1),
                    "available_admission_capacity": _u16(payload, 3),
                }
            elif eid == EID_RSN:
                info["rsn"] = parse_rsn(payload)
            elif eid == EID_HT_CAPABILITIES:
                info["ht"] = True
            elif eid == EID_HT_OPERATION:
                ht_op = payload
                if payload:
                    info["channel"] = info["channel"] or payload[0]
            elif eid == EID_VHT_CAPABILITIES:
                info["vht"] = True
            elif eid == EID_VHT_OPERATION:
                vht_op = payload
            elif eid == EID_MOBILITY_DOMAIN:
                info["ft_80211r"] = True
            elif eid == EID_RM_ENABLED_CAPS:
                info["rm_80211k"] = True
            elif eid == EID_EXTENDED_CAPS:
                # Bit 19 = BSS Transition Management (802.11v)
                if len(payload) >= 3 and payload[2] & 0x08:
                    info["bss_transition_80211v"] = True
            elif eid == EID_INTERWORKING:
                info["interworking"] = True
            elif eid == EID_MESH_ID:
                info["mesh"] = True
            elif eid == EID_REDUCED_NEIGHBOR:
                info["colocated_6ghz"] = True
            elif eid == EID_EXTENSION:
                if ext in (EXT_HE_CAPABILITIES, EXT_HE_OPERATION):
                    info["he"] = True
                    if ext == EXT_HE_OPERATION:
                        he_op = payload
                elif ext in (EXT_EHT_CAPABILITIES, EXT_EHT_OPERATION, EXT_MULTI_LINK):
                    info["eht"] = True
                elif ext == EXT_HE_6GHZ_BAND_CAP:
                    info["he"] = True
            elif eid == EID_VENDOR and len(payload) >= 3:
                oui = payload[:3]
                oui_type = payload[3] if len(payload) > 3 else None
                name = VENDOR_OUI_NAMES.get(oui)
                entry = {
                    "oui": oui.hex(":"),
                    "type": oui_type,
                    "name": name,
                    "len": len(payload),
                }
                info["vendor_ies"].append(entry)
                if name and name not in info["vendor_names"]:
                    info["vendor_names"].append(name)
                if oui == OUI_MS:
                    if oui_type == 0x01:
                        info["wpa"] = parse_wpa(payload[4:])
                    elif oui_type == 0x02:
                        info["wmm"] = True
                    elif oui_type == 0x04:
                        info["wps"] = parse_wps(payload[4:])
                elif oui == OUI_WFA and oui_type == 0x10:
                    info["hotspot20"] = True
        except (struct.error, IndexError, ValueError) as exc:
            info["parse_errors"].append(f"eid {eid}: {exc}")

    # Width and channel resolution
    width = _he_width(he_op) or _vht_width(vht_op, ht_op)
    if width is None and info["ht"]:
        width = 20
    if width is None:
        width = 20
    info["width_mhz"] = width

    freq_channel, band = _channel_from_freq(freq_khz)
    info["band"] = band
    if info["channel"] is None:
        info["channel"] = freq_channel
    elif freq_channel is not None and band == "6":
        # 6 GHz APs reuse low DS Param numbers; trust the frequency.
        info["channel"] = freq_channel

    return info


def security_summary(info: dict[str, Any], capability: int = 0) -> dict[str, Any]:
    """Collapse RSN/WPA/capability bits into a human-facing security posture."""
    rsn = info.get("rsn")
    wpa = info.get("wpa")
    privacy = bool(capability & 0x0010)

    akms: list[str] = []
    ciphers: list[str] = []
    if rsn:
        akms += rsn.get("akms", [])
        ciphers += rsn.get("pairwise_ciphers", [])
    if wpa:
        akms += [f"WPA1-{a}" for a in wpa.get("akms", [])]
        ciphers += wpa.get("pairwise_ciphers", [])

    akm_set = {a.replace("WPA1-", "") for a in akms}
    generation = "Open"
    if rsn and ("SAE" in akm_set or "FT-SAE" in akm_set or "SAE-EXT-KEY" in akm_set):
        generation = "WPA3"
        if "PSK" in akm_set or "FT-PSK" in akm_set:
            generation = "WPA2/WPA3 transition"
    elif rsn and "OWE" in akm_set:
        generation = "OWE"
    elif rsn and ("802.1X-Suite-B-192" in akm_set or "802.1X-Suite-B" in akm_set):
        generation = "WPA3-Enterprise 192-bit"
    elif rsn and "802.1X-SHA256" in akm_set and rsn.get("mfp_required"):
        # WPA3-Enterprise proper: SHA256 key derivation with PMF mandatory.
        generation = "WPA3-Enterprise"
    elif rsn:
        generation = "WPA2"
        if wpa:
            generation = "WPA/WPA2 mixed"
    elif wpa:
        generation = "WPA"
    elif privacy:
        generation = "WEP"

    enterprise = any("802.1X" in a for a in akm_set)
    weak_cipher = any(c in ("TKIP", "WEP-40", "WEP-104") for c in ciphers)

    mfp_capable = bool(rsn and rsn.get("mfp_capable"))
    mfp_required = bool(rsn and rsn.get("mfp_required"))

    return {
        "generation": generation,
        "akms": sorted(akm_set),
        "ciphers": sorted(set(ciphers)),
        "group_cipher": (rsn or {}).get("group_cipher") or (wpa or {}).get("group_cipher"),
        "enterprise": enterprise,
        "open": generation == "Open",
        "weak_cipher": weak_cipher,
        "wep": generation == "WEP",
        "mfp_capable": mfp_capable,
        "mfp_required": mfp_required,
        "wps": bool(info.get("wps")),
        "wps_state": (info.get("wps") or {}).get("state"),
        "privacy_bit": privacy,
    }


def phy_label(info: dict[str, Any], driver_phy: str = "") -> str:
    if info.get("eht") or driver_phy == "eht":
        return "Wi-Fi 7 (be)"
    if info.get("he") or driver_phy == "he":
        return "Wi-Fi 6E (ax)" if info.get("band") == "6" else "Wi-Fi 6 (ax)"
    if info.get("vht") or driver_phy == "vht":
        return "Wi-Fi 5 (ac)"
    if info.get("ht") or driver_phy == "ht":
        return "Wi-Fi 4 (n)"
    if driver_phy == "erp":
        return "802.11g"
    if driver_phy == "hrdsss":
        return "802.11b"
    if driver_phy == "ofdm":
        return "802.11a"
    return driver_phy or "unknown"

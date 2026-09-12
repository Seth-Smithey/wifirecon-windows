"""
USB wireless device discovery.

The Native Wifi API only lists adapters that reached a working, bound state. An
adapter that is plugged in but disabled, driverless, or failed is invisible to
it — which is the single most confusing failure mode, because "no adapters
found" and "your adapter is sitting right there but disabled" look identical.

This module goes underneath that, enumerating PnP devices directly so we can
tell the difference and say which it is.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from typing import Any

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Windows CM_PROB_* codes, in the words someone would actually use.
PROBLEM_CODES: dict[int, tuple[str, str]] = {
    0:  ("working", "The device is working."),
    1:  ("not configured", "Windows has no driver configured for it."),
    3:  ("driver corrupted", "The driver is corrupted, or the system is low on memory."),
    9:  ("invalid hardware id", "The hardware is reporting an ID Windows cannot use."),
    10: ("cannot start", "The device failed to start. Usually a driver or power problem."),
    12: ("insufficient resources", "Windows could not find free resources for it."),
    14: ("needs restart", "The device needs a restart to finish coming up."),
    16: ("resources unknown", "Windows cannot identify all the resources it uses."),
    18: ("reinstall driver", "The driver needs reinstalling."),
    19: ("registry damaged", "Its registry configuration is damaged."),
    21: ("being removed", "Windows is in the middle of removing it."),
    22: ("disabled", "The device has been disabled."),
    24: ("not present", "The device is not present, or was not installed properly."),
    28: ("no driver", "No driver is installed for it."),
    29: ("firmware disabled", "The firmware has disabled it, usually in the BIOS."),
    31: ("driver failed", "Windows could not load a working driver for it."),
    32: ("service disabled", "Its start-up service is disabled."),
    33: ("resource conflict", "Windows cannot determine which resources it needs."),
    35: ("bios incomplete", "The system firmware lacks information to configure it."),
    38: ("driver in memory", "A previous instance of the driver is still loaded."),
    43: ("stopped by driver", "Windows stopped it after it reported a problem."),
    45: ("not connected", "The device is not currently connected."),
    47: ("prepared for removal", "It is waiting to be safely removed."),
    52: ("unsigned driver", "Windows cannot verify the driver's digital signature."),
}

# USB wireless adapters worth recognising, keyed by vendor id then product id.
# The point is to identify a survey adapter even when Windows has bound no
# driver and has no friendly name for it.
KNOWN_USB_WIFI: dict[str, dict[str, str]] = {
    "0E8D": {                                  # MediaTek
        "_vendor": "MediaTek",
        "7961": "MediaTek MT7921AU (Alfa AWUS036AXML / Panda AXE3000)",
        "7612": "MediaTek MT7612U (Alfa AWUS036ACM)",
        "7662": "MediaTek MT7662U",
        "7610": "MediaTek MT7610U",
        "7922": "MediaTek MT7922AU",
    },
    "0BDA": {                                  # Realtek
        "_vendor": "Realtek",
        "8812": "Realtek RTL8812AU (Alfa AWUS036ACH)",
        "881A": "Realtek RTL8812AU",
        "8813": "Realtek RTL8814AU (Alfa AWUS1900)",
        "A812": "Realtek RTL8812AU",
        "B812": "Realtek RTL88x2BU",
        "C811": "Realtek RTL8811CU",
        "8178": "Realtek RTL8192CU",
        "8187": "Realtek RTL8187 (Alfa AWUS036H)",
    },
    "0CF3": {                                  # Qualcomm Atheros
        "_vendor": "Atheros",
        "9271": "Atheros AR9271 (Alfa AWUS036NHA)",
        "1006": "Atheros AR9271",
    },
    "148F": {                                  # Ralink
        "_vendor": "Ralink",
        "3070": "Ralink RT3070",
        "5372": "Ralink RT5372",
        "7601": "Ralink MT7601U",
    },
    "2357": {"_vendor": "TP-Link", "010C": "TP-Link Archer T4U", "0138": "TP-Link Archer T4U v3"},
    "0846": {"_vendor": "NETGEAR", "9052": "NETGEAR A6210"},
    "7392": {"_vendor": "Edimax", "A822": "Edimax EW-7822"},
    "2001": {"_vendor": "D-Link", "3319": "D-Link DWA-182"},
    "0B05": {"_vendor": "ASUS", "1817": "ASUS USB-AC68"},
}

# Devices that share a chip with a wireless adapter but are not one. Matching
# these stops us reporting the Bluetooth half of a combo chip as a broken radio.
NON_WIFI_FUNCTION_HINTS = ("bluetooth", "bt ", "audio", "serial", "com port")


def _powershell_json(script: str, timeout: int = 60) -> Any:
    """Run PowerShell and parse its JSON output. Returns None on any failure."""
    if not IS_WINDOWS:
        return None
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, errors="replace",
        )
        output = (proc.stdout or "").strip()
        if not output:
            return None
        data = json.loads(output)
        # A single object comes back unwrapped; callers always want a list.
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        log.debug("PowerShell returned output that was not JSON")
        return None
    except Exception as exc:
        log.debug("PowerShell call failed: %s", exc)
        return None


def parse_hardware_id(instance_id: str) -> tuple[str | None, str | None, str | None]:
    """Pull VID, PID and the interface number out of a USB instance id."""
    vid = pid = mi = None
    match = re.search(r"VID_([0-9A-Fa-f]{4})", instance_id)
    if match:
        vid = match.group(1).upper()
    match = re.search(r"PID_([0-9A-Fa-f]{4})", instance_id)
    if match:
        pid = match.group(1).upper()
    match = re.search(r"MI_([0-9A-Fa-f]{2})", instance_id)
    if match:
        mi = match.group(1).upper()
    return vid, pid, mi


def identify(instance_id: str, friendly_name: str = "") -> dict:
    """Work out whether an instance id belongs to a wireless adapter we know."""
    vid, pid, mi = parse_hardware_id(instance_id)
    result = {
        "vid": vid, "pid": pid, "interface": mi,
        "known": False, "model": None, "vendor": None, "is_wifi_function": True,
    }
    if not vid:
        return result

    entry = KNOWN_USB_WIFI.get(vid)
    if entry:
        result["vendor"] = entry.get("_vendor")
        if pid and pid in entry:
            result["known"] = True
            result["model"] = entry[pid]

    name = (friendly_name or "").lower()
    if any(hint in name for hint in NON_WIFI_FUNCTION_HINTS):
        result["is_wifi_function"] = False
    return result


def list_usb_wifi_devices(timeout: int = 60) -> list[dict]:
    """Every PnP device that looks like a USB wireless adapter, working or not.

    Includes devices in an error state, which is the whole point: those are the
    ones the Native Wifi API cannot see.
    """
    if not IS_WINDOWS:
        return []

    # Only devices matching a known wireless vendor id, or already classed as a
    # network device, get the expensive per-device property lookup. Querying
    # every USB device on the machine is slow enough to time out.
    vendor_filter = " -or ".join(
        f"$_.InstanceId -like 'USB\\VID_{vid}*'" for vid in KNOWN_USB_WIFI
    )
    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-PnpDevice -PresentOnly | Where-Object { "
        f"  ($_.InstanceId -like 'USB*') -and ( {vendor_filter} "
        "    -or $_.Class -eq 'Net' -or $_.Status -ne 'OK' ) } | "
        "ForEach-Object { "
        "  $p = 0; "
        "  try { $v = (Get-PnpDeviceProperty -InstanceId $_.InstanceId "
        "        -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop).Data; "
        "        if ($null -ne $v) { $p = $v } } catch {}; "
        "  [pscustomobject]@{ "
        "    InstanceId = $_.InstanceId; Name = $_.FriendlyName; Status = $_.Status; "
        "    Class = $_.Class; Problem = $p } } | "
        "ConvertTo-Json -Compress -Depth 3"
    )
    rows = _powershell_json(script, timeout=timeout) or []

    devices = []
    for row in rows:
        instance_id = row.get("InstanceId") or ""
        name = row.get("Name") or ""
        info = identify(instance_id, name)
        device_class = (row.get("Class") or "").lower()

        # Keep it if we recognise the chip, or Windows already calls it a network
        # device, or it is unnamed and unclassified (the classic driverless case).
        relevant = (
            info["known"]
            or (device_class == "net" and instance_id.upper().startswith("USB"))
            or (not device_class and info["vid"] in KNOWN_USB_WIFI)
        )
        if not relevant:
            continue

        problem = row.get("Problem")
        try:
            problem = int(problem) if problem is not None else 0
        except (TypeError, ValueError):
            problem = 0
        label, explanation = PROBLEM_CODES.get(
            problem, (f"code {problem}", f"Windows reports problem code {problem}.")
        )

        devices.append({
            "instance_id": instance_id,
            "name": name or info.get("model") or "Unnamed device",
            "status": row.get("Status"),
            "class": row.get("Class"),
            "problem_code": problem,
            "problem": label,
            "problem_detail": explanation,
            "healthy": problem == 0 and (row.get("Status") or "").upper() == "OK",
            **info,
        })
    return devices


def wifi_functions(devices: list[dict] | None = None) -> list[dict]:
    """Just the wireless halves, with the Bluetooth side of combo chips dropped."""
    devices = devices if devices is not None else list_usb_wifi_devices()
    return [d for d in devices if d.get("is_wifi_function")]


def unhealthy_adapters(devices: list[dict] | None = None) -> list[dict]:
    """Wireless devices that are present but not working, worst first."""
    candidates = wifi_functions(devices)
    broken = [d for d in candidates if not d["healthy"]]
    # Recognised models first, then by how actionable the problem is.
    priority = {22: 0, 28: 1, 43: 2, 10: 3, 31: 4, 1: 5, 18: 6}
    broken.sort(key=lambda d: (not d["known"], priority.get(d["problem_code"], 9)))
    return broken


def summarise(devices: list[dict] | None = None) -> dict:
    devices = devices if devices is not None else list_usb_wifi_devices()
    wifi = wifi_functions(devices)
    broken = unhealthy_adapters(devices)
    return {
        "total": len(devices),
        "wifi_functions": len(wifi),
        "healthy": len([d for d in wifi if d["healthy"]]),
        "broken": len(broken),
        "devices": devices,
        "problems": broken,
        "recognised": [d for d in wifi if d["known"]],
    }

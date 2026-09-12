"""
Local device discovery.

A passive Wi-Fi survey cannot see client devices — their frames are not
addressed to us and Windows will not hand them over. What it can see is
everything reachable on the networks this machine is actually attached to, and
for IT work that is usually the more useful half.

Sources, cheapest and least intrusive first:
  * ARP / neighbour table    - devices this machine has recently talked to
  * Reverse DNS              - names for those addresses
  * NetBIOS                  - Windows names and workgroups
  * mDNS / Bonjour           - printers, Apple kit, Chromecasts, IoT
  * SSDP / UPnP              - routers, media servers, smart TVs
  * Bluetooth                - paired and nearby radios Windows knows about

Everything here is passive or uses standard local discovery protocols. There is
no port scanning and no probing of hosts that have not announced themselves.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any

from . import oui

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Device categories inferred from what a host announces about itself.
DEVICE_HINTS = [
    (("printer", "officejet", "deskjet", "laserjet", "envy", "pixma", "brother",
      "epson", "_ipp", "_pdl-datastream"), "printer"),
    (("chromecast", "googlecast", "_googlecast", "android tv", "shield"), "media"),
    (("appletv", "apple tv", "_airplay", "_raop", "airport"), "media"),
    (("roku", "firetv", "fire tv", "vizio", "samsung tv", "lg tv", "bravia"), "tv"),
    (("sonos", "_sonos", "bose", "echo", "alexa", "homepod"), "speaker"),
    (("nas", "synology", "qnap", "truenas", "freenas", "_smb", "_afpovertcp"), "storage"),
    (("router", "gateway", "unifi", "ubiquiti", "mikrotik", "openwrt", "pfsense",
      "edgerouter", "_workstation"), "network"),
    (("camera", "hikvision", "dahua", "reolink", "wyze", "nest cam", "ring"), "camera"),
    (("thermostat", "nest", "ecobee", "hue", "lifx", "shelly", "tasmota",
      "esp_", "esp-", "tuya", "sonoff"), "iot"),
    (("iphone", "ipad", "android", "galaxy", "pixel"), "mobile"),
    (("macbook", "imac", "desktop", "laptop", "-pc", "workstation"), "computer"),
    (("xbox", "playstation", "ps5", "ps4", "nintendo", "switch"), "console"),
]

CATEGORY_LABEL = {
    "printer": "Printer", "media": "Media player", "tv": "Television",
    "speaker": "Speaker", "storage": "Storage", "network": "Network equipment",
    "camera": "Camera", "iot": "Smart home", "mobile": "Phone or tablet",
    "computer": "Computer", "console": "Games console", "bluetooth": "Bluetooth",
    "unknown": "Unknown",
}


def _run(args: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, errors="replace",
        )
        return proc.stdout or ""
    except Exception as exc:
        log.debug("%s failed: %s", args[0] if args else "?", exc)
        return ""


def _powershell(script: str, timeout: int = 30) -> Any:
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
        return data if isinstance(data, list) else [data]
    except Exception as exc:
        log.debug("PowerShell discovery call failed: %s", exc)
        return None


def classify(*texts: str) -> str:
    blob = " ".join(t.lower() for t in texts if t)
    for needles, category in DEVICE_HINTS:
        if any(n in blob for n in needles):
            return category
    return "unknown"


# ---------------------------------------------------------------------------
# ARP / neighbour table
# ---------------------------------------------------------------------------


def arp_table() -> list[dict]:
    """Devices this machine has exchanged traffic with recently."""
    devices: dict[str, dict] = {}

    if IS_WINDOWS:
        rows = _powershell(
            "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.State -ne 'Unreachable' -and "
            "  $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | "
            "Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | "
            "ConvertTo-Json -Compress"
        )
        for row in rows or []:
            mac = oui.normalise(str(row.get("LinkLayerAddress", "")).replace("-", ":"))
            ip = row.get("IPAddress")
            if not ip or len(mac.replace(":", "")) != 12:
                continue
            devices[ip] = {
                "ip": ip, "mac": mac, "state": row.get("State"),
                "interface": row.get("InterfaceAlias"), "source": "arp",
            }

    if not devices:
        # `arp -a` works everywhere and is the fallback when the cmdlet is absent.
        for line in _run(["arp", "-a"]).splitlines():
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F:-]{14,})", line
            )
            if not match:
                continue
            ip = match.group(1)
            mac = oui.normalise(match.group(2).replace("-", ":"))
            if len(mac.replace(":", "")) != 12:
                continue
            devices[ip] = {"ip": ip, "mac": mac, "state": "reachable",
                           "interface": None, "source": "arp"}

    for device in devices.values():
        device["vendor"] = oui.db.lookup(device["mac"])
        device["randomized_mac"] = oui.is_locally_administered(device["mac"])
    return list(devices.values())


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    original = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(original)


def resolve_names(devices: list[dict], workers: int = 16) -> None:
    """Fill in hostnames concurrently, because DNS is mostly waiting."""
    lock = threading.Lock()
    queue = list(devices)

    def worker() -> None:
        while True:
            with lock:
                if not queue:
                    return
                device = queue.pop()
            name = reverse_dns(device["ip"])
            if name:
                device["hostname"] = name

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(workers, max(1, len(devices))))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=12)


# ---------------------------------------------------------------------------
# SSDP / UPnP
# ---------------------------------------------------------------------------

SSDP_ADDRESS = ("239.255.255.250", 1900)
SSDP_QUERY = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 2\r\n"
    b"ST: ssdp:all\r\n\r\n"
)


def ssdp_discover(timeout: float = 4.0) -> list[dict]:
    """Ask UPnP devices to announce themselves. Routers, TVs, media servers."""
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(SSDP_QUERY, SSDP_ADDRESS)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, address = sock.recvfrom(65507)
            except TimeoutError:
                break
            except Exception:
                break
            text = data.decode("utf-8", "replace")
            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()
            ip = address[0]
            entry = found.setdefault(ip, {"ip": ip, "source": "ssdp", "services": []})
            server = headers.get("server")
            if server and not entry.get("server"):
                entry["server"] = server
            usn = headers.get("st") or headers.get("nt")
            if usn and usn not in entry["services"]:
                entry["services"].append(usn)
            location = headers.get("location")
            if location and not entry.get("location"):
                entry["location"] = location
        sock.close()
    except Exception as exc:
        log.debug("SSDP discovery failed: %s", exc)
    return list(found.values())


# ---------------------------------------------------------------------------
# mDNS / Bonjour
# ---------------------------------------------------------------------------

MDNS_ADDRESS = ("224.0.0.251", 5353)

MDNS_SERVICES = [
    "_services._dns-sd._udp.local",
    "_http._tcp.local", "_ipp._tcp.local", "_printer._tcp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
    "_smb._tcp.local", "_afpovertcp._tcp.local", "_workstation._tcp.local",
    "_device-info._tcp.local", "_spotify-connect._tcp.local",
    "_homekit._tcp.local", "_hap._tcp.local",
]


def _encode_mdns_query(name: str) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    body = b""
    for label in name.split("."):
        if label:
            body += bytes([len(label)]) + label.encode()
    body += b"\x00" + struct.pack(">HH", 12, 1)   # PTR, IN
    return header + body


def _decode_mdns_names(payload: bytes) -> list[str]:
    """Pull readable labels out of a response without a full DNS parser."""
    names, current, i = [], [], 0
    n = len(payload)
    while i < n:
        length = payload[i]
        if length == 0:
            if current:
                names.append(".".join(current))
                current = []
            i += 1
        elif length & 0xC0:            # compression pointer
            if current:
                names.append(".".join(current))
                current = []
            i += 2
        else:
            i += 1
            chunk = payload[i:i + length]
            try:
                text = chunk.decode("utf-8")
                if text.isprintable():
                    current.append(text)
            except UnicodeDecodeError:
                pass
            i += length
    if current:
        names.append(".".join(current))
    return names


def mdns_discover(timeout: float = 4.0) -> list[dict]:
    """Listen for Bonjour announcements. Printers, Apple kit, Chromecasts, IoT."""
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(1.0)
        for service in MDNS_SERVICES[:6]:
            try:
                sock.sendto(_encode_mdns_query(service), MDNS_ADDRESS)
            except Exception:
                break

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, address = sock.recvfrom(9000)
            except TimeoutError:
                continue
            except Exception:
                break
            ip = address[0]
            entry = found.setdefault(ip, {"ip": ip, "source": "mdns", "names": []})
            for name in _decode_mdns_names(data[12:]):
                if name and name not in entry["names"] and len(name) < 120:
                    entry["names"].append(name)
        sock.close()
    except Exception as exc:
        log.debug("mDNS discovery failed: %s", exc)

    for entry in found.values():
        entry["names"] = entry["names"][:12]
        hostname = next(
            (n for n in entry["names"] if n.endswith(".local") and not n.startswith("_")),
            None,
        )
        if hostname:
            entry["hostname"] = hostname
    return list(found.values())


# ---------------------------------------------------------------------------
# NetBIOS
# ---------------------------------------------------------------------------


def netbios_names() -> dict[str, dict]:
    """Windows names from the NetBIOS cache. Useful on older estates."""
    out: dict[str, dict] = {}
    if not IS_WINDOWS:
        return out
    text = _run(["nbtstat", "-c"], timeout=15)
    for line in text.splitlines():
        match = re.search(r"(\S+)\s+<(\w\w)>\s+\w+\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            name, code, ip = match.groups()
            entry = out.setdefault(ip, {"ip": ip, "netbios": [], "source": "netbios"})
            if name not in entry["netbios"]:
                entry["netbios"].append(name)
            if code == "20" or code == "00":
                entry["hostname"] = name
    return out


# ---------------------------------------------------------------------------
# Bluetooth
# ---------------------------------------------------------------------------


def bluetooth_devices() -> list[dict]:
    """Bluetooth radios Windows knows about, paired or seen."""
    rows = _powershell(
        "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | "
        "Where-Object { $_.FriendlyName -and "
        "  $_.InstanceId -like 'BTHENUM*' -or $_.InstanceId -like 'BTHLE*' } | "
        "Select-Object FriendlyName, InstanceId, Status, Present | "
        "ConvertTo-Json -Compress", timeout=30
    )
    out = []
    for row in rows or []:
        name = row.get("FriendlyName") or ""
        instance = row.get("InstanceId") or ""
        # BTHENUM instance ids carry the remote address in the tail.
        address = None
        match = re.search(r"_?([0-9a-fA-F]{12})(?:_|$|\\)", instance.replace("&", "_"))
        if match:
            raw = match.group(1).lower()
            address = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
        out.append({
            "name": name,
            "address": address,
            "vendor": oui.db.lookup(address) if address else None,
            "status": row.get("Status"),
            "connected": str(row.get("Status", "")).upper() == "OK",
            "category": "bluetooth",
            "source": "bluetooth",
            "instance_id": instance,
        })
    return out


# ---------------------------------------------------------------------------
# Local interfaces
# ---------------------------------------------------------------------------


def local_networks() -> list[dict]:
    """Which networks this machine is on, so discovery results have context."""
    rows = _powershell(
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike '127.*' } | "
        "Select-Object IPAddress, PrefixLength, InterfaceAlias | "
        "ConvertTo-Json -Compress"
    )
    out = []
    for row in rows or []:
        out.append({
            "ip": row.get("IPAddress"),
            "prefix": row.get("PrefixLength"),
            "interface": row.get("InterfaceAlias"),
        })
    if not out:
        try:
            hostname = socket.gethostname()
            out = [{"ip": socket.gethostbyname(hostname), "prefix": None,
                    "interface": hostname}]
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def discover(
    include_mdns: bool = True,
    include_ssdp: bool = True,
    include_netbios: bool = True,
    include_bluetooth: bool = True,
    resolve_hostnames: bool = True,
    timeout: float = 4.0,
) -> dict:
    """Run every enabled source and merge the results by IP address."""
    started = time.time()
    errors: list[str] = []

    devices: dict[str, dict] = {}

    def merge(entries: list[dict]) -> None:
        for entry in entries:
            ip = entry.get("ip")
            if not ip:
                continue
            target = devices.setdefault(ip, {"ip": ip, "sources": []})
            source = entry.pop("source", None)
            if source and source not in target["sources"]:
                target["sources"].append(source)
            for key, value in entry.items():
                if value in (None, "", []):
                    continue
                if key in ("names", "services", "netbios"):
                    existing = target.setdefault(key, [])
                    for item in value:
                        if item not in existing:
                            existing.append(item)
                elif key not in target or not target[key]:
                    target[key] = value

    try:
        merge(arp_table())
    except Exception as exc:
        errors.append(f"ARP: {exc}")

    # Run the network-chatty sources in parallel; they are all just waiting.
    results: dict[str, list[dict]] = {}
    threads = []

    def collect(name: str, fn, *args) -> None:
        def run() -> None:
            try:
                results[name] = fn(*args)
            except Exception as exc:
                errors.append(f"{name}: {exc}")
                results[name] = []
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        threads.append(thread)

    if include_ssdp:
        collect("ssdp", ssdp_discover, timeout)
    if include_mdns:
        collect("mdns", mdns_discover, timeout)
    for thread in threads:
        thread.join(timeout=timeout + 3)

    for entries in results.values():
        merge(entries)

    if include_netbios:
        try:
            merge(list(netbios_names().values()))
        except Exception as exc:
            errors.append(f"NetBIOS: {exc}")

    if resolve_hostnames:
        try:
            unnamed = [d for d in devices.values() if not d.get("hostname")]
            resolve_names(unnamed)
        except Exception as exc:
            errors.append(f"DNS: {exc}")

    # Classify and tidy
    for device in devices.values():
        device.setdefault("mac", None)
        device.setdefault("hostname", None)
        device["vendor"] = device.get("vendor") or (
            oui.db.lookup(device["mac"]) if device.get("mac") else None
        )
        device["category"] = classify(
            device.get("hostname") or "", device.get("vendor") or "",
            device.get("server") or "", " ".join(device.get("names") or []),
            " ".join(device.get("services") or []),
        )
        device["category_label"] = CATEGORY_LABEL.get(device["category"], "Unknown")
        device["label"] = (
            device.get("hostname")
            or (device.get("names") or [None])[0]
            or device.get("vendor")
            or device["ip"]
        )

    bluetooth: list[dict] = []
    if include_bluetooth:
        try:
            bluetooth = bluetooth_devices()
        except Exception as exc:
            errors.append(f"Bluetooth: {exc}")

    ordered = sorted(
        devices.values(),
        key=lambda d: tuple(int(part) for part in d["ip"].split("."))
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", d["ip"]) else (999, 999, 999, 999),
    )

    categories: dict[str, int] = {}
    for device in ordered:
        categories[device["category"]] = categories.get(device["category"], 0) + 1

    return {
        "devices": ordered,
        "bluetooth": bluetooth,
        "networks": local_networks(),
        "count": len(ordered),
        "bluetooth_count": len(bluetooth),
        "categories": categories,
        "errors": errors,
        "duration_ms": int((time.time() - started) * 1000),
        "scanned_at": time.time(),
    }

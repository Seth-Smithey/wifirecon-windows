"""
Connect to a network and audit it.

For looking at a network you run, typically a segregated IoT or guest VLAN:
join it, then find out what is actually on there and how exposed it is.

This does touch the network, unlike the wireless survey. It connects common
service ports on hosts in the local subnet, reads banners where they are
offered, and flags obvious hygiene problems: plaintext management, default
credential pages, unauthenticated services, end-of-life protocols.

Scope is deliberately limited to the subnet this machine is connected to.
There is no scanning of arbitrary ranges, no credential testing, and no
exploitation.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import Any

from . import devices as device_module

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Ports worth checking on a small network, with what finding them means.
PORTS: dict[int, dict[str, Any]] = {
    21:   {"name": "FTP", "risk": "high", "why": "File transfer in plaintext, including credentials."},
    22:   {"name": "SSH", "risk": "info", "why": "Encrypted remote administration."},
    23:   {"name": "Telnet", "risk": "critical", "why": "Remote administration in plaintext. Should not be running."},
    25:   {"name": "SMTP", "risk": "low", "why": "Mail transfer."},
    53:   {"name": "DNS", "risk": "info", "why": "Name resolution."},
    80:   {"name": "HTTP", "risk": "medium", "why": "Unencrypted web interface, often device management."},
    139:  {"name": "NetBIOS", "risk": "medium", "why": "Legacy Windows file sharing."},
    443:  {"name": "HTTPS", "risk": "info", "why": "Encrypted web interface."},
    445:  {"name": "SMB", "risk": "medium", "why": "Windows file sharing. Should not face untrusted segments."},
    515:  {"name": "LPD", "risk": "low", "why": "Legacy print service."},
    554:  {"name": "RTSP", "risk": "medium", "why": "Video streaming, common on cameras and often unauthenticated."},
    631:  {"name": "IPP", "risk": "low", "why": "Printing."},
    1883: {"name": "MQTT", "risk": "high", "why": "IoT message broker, frequently unauthenticated."},
    3306: {"name": "MySQL", "risk": "high", "why": "Database exposed on the network."},
    3389: {"name": "RDP", "risk": "medium", "why": "Windows remote desktop."},
    5000: {"name": "UPnP/HTTP", "risk": "medium", "why": "Device management or UPnP control."},
    5432: {"name": "PostgreSQL", "risk": "high", "why": "Database exposed on the network."},
    5900: {"name": "VNC", "risk": "high", "why": "Remote desktop, often with weak or no authentication."},
    8080: {"name": "HTTP alt", "risk": "medium", "why": "Secondary web interface."},
    8443: {"name": "HTTPS alt", "risk": "info", "why": "Secondary encrypted web interface."},
    8883: {"name": "MQTT/TLS", "risk": "info", "why": "Encrypted IoT message broker."},
    9100: {"name": "JetDirect", "risk": "medium", "why": "Raw printing. Accepts jobs without authentication."},
    23423: {"name": "Unknown", "risk": "info", "why": ""},
}

DEFAULT_PORTS = [21, 22, 23, 80, 139, 443, 445, 554, 631, 1883, 3389, 5900, 8080,
                 8443, 9100]

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, errors="replace",
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except Exception as exc:
        return 1, str(exc)


def _powershell_json(script: str, timeout: int = 30) -> Any:
    if not IS_WINDOWS:
        return None
    code, output = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script], timeout,
    )
    if code != 0 or not output:
        return None
    try:
        data = json.loads(output)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Connecting
# ---------------------------------------------------------------------------


def saved_profiles() -> list[str]:
    """Wireless profiles Windows already has, which can be connected without a key."""
    code, output = _run(["netsh", "wlan", "show", "profiles"])
    if code != 0:
        return []
    return [m.group(1).strip()
            for m in re.finditer(r"All User Profile\s*:\s*(.+)", output)]


def current_connection() -> dict:
    """What this machine is connected to right now."""
    code, output = _run(["netsh", "wlan", "show", "interfaces"])
    info: dict[str, Any] = {"connected": False}
    if code != 0:
        return info
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "state":
            info["state"] = value
            info["connected"] = value.lower() == "connected"
        elif key == "ssid" and "bssid" not in key:
            info.setdefault("ssid", value)
        elif key == "bssid":
            info["bssid"] = value
        elif key == "signal":
            info["signal"] = value
        elif key == "channel":
            info["channel"] = value
        elif key == "authentication":
            info["security"] = value
        elif key == "cipher":
            info["cipher"] = value
        elif key == "name":
            info["interface"] = value
    return info


def create_profile(ssid: str, passphrase: str | None, security: str = "WPA2PSK") -> dict:
    """Add a wireless profile so Windows can connect to this network."""
    if not (ssid or "").strip():
        return {"ok": False, "error": "A network name is required"}
    if passphrase is not None and passphrase and len(passphrase) < 8:
        return {"ok": False,
                "error": "A WPA passphrase must be at least 8 characters"}
    if not IS_WINDOWS:
        return {"ok": False, "error": "Creating profiles is Windows only"}
    import tempfile
    from xml.sax.saxutils import escape

    open_network = not passphrase
    auth = "open" if open_network else ("WPA3SAE" if security == "WPA3SAE" else "WPA2PSK")
    encryption = "none" if open_network else "AES"

    security_xml = (
        f"<authEncryption><authentication>{auth}</authentication>"
        f"<encryption>{encryption}</encryption><useOneX>false</useOneX></authEncryption>"
    )
    if not open_network:
        security_xml += (
            "<sharedKey><keyType>passPhrase</keyType><protected>false</protected>"
            f"<keyMaterial>{escape(passphrase)}</keyMaterial></sharedKey>"
        )

    xml = (
        '<?xml version="1.0"?>'
        '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
        f"<name>{escape(ssid)}</name>"
        f"<SSIDConfig><SSID><name>{escape(ssid)}</name></SSID></SSIDConfig>"
        "<connectionType>ESS</connectionType>"
        "<connectionMode>manual</connectionMode>"
        f"<MSM><security>{security_xml}</security></MSM>"
        "</WLANProfile>"
    )

    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                     encoding="utf-8") as handle:
        handle.write(xml)
        path = handle.name
    try:
        code, output = _run(["netsh", "wlan", "add", "profile", f"filename={path}",
                             "user=current"])
        if code != 0 or "added" not in output.lower():
            return {"ok": False, "error": output[:220] or "Windows rejected the profile"}
        return {"ok": True, "message": f"Profile for '{ssid}' added"}
    finally:
        import os

        try:
            os.unlink(path)
        except OSError:
            pass


def connect(ssid: str, interface: str | None = None, wait: float = 20.0) -> dict:
    """Connect to a network Windows already has a profile for."""
    if not (ssid or "").strip():
        return {"ok": False, "error": "A network name is required"}
    if not IS_WINDOWS:
        return {"ok": False, "error": "Connecting to networks is Windows only"}
    if ssid not in saved_profiles():
        return {
            "ok": False,
            "error": f"There is no saved profile for '{ssid}'.",
            "hint": "Add one first with the passphrase, or connect once through "
                    "Windows so the profile exists.",
        }

    args = ["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"]
    if interface:
        args.append(f"interface={interface}")
    code, output = _run(args, timeout=30)
    if code != 0:
        return {"ok": False, "error": output[:220] or "The connect request failed"}

    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(1.5)
        state = current_connection()
        if state.get("connected") and state.get("ssid") == ssid:
            return {"ok": True, "message": f"Connected to {ssid}", "connection": state}
    return {"ok": False, "error": f"Did not finish connecting to {ssid} within "
                                  f"{wait:.0f} seconds",
            "connection": current_connection()}


def disconnect(interface: str | None = None) -> dict:
    args = ["netsh", "wlan", "disconnect"]
    if interface:
        args.append(f"interface={interface}")
    code, output = _run(args)
    return {"ok": code == 0, "message": output[:200]}


# ---------------------------------------------------------------------------
# Local subnet
# ---------------------------------------------------------------------------


def local_subnets() -> list[dict]:
    """The IPv4 networks this machine is attached to."""
    rows = _powershell_json(
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and "
        "  $_.IPAddress -notlike '169.254.*' } | "
        "Select-Object IPAddress, PrefixLength, InterfaceAlias | ConvertTo-Json -Compress"
    ) or []
    out = []
    for row in rows:
        try:
            network = ipaddress.ip_network(
                f"{row['IPAddress']}/{row['PrefixLength']}", strict=False
            )
        except Exception:
            continue
        out.append({
            "ip": row["IPAddress"],
            "prefix": row["PrefixLength"],
            "interface": row.get("InterfaceAlias"),
            "network": str(network),
            "hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0,
        })
    return out


def gateway() -> str | None:
    rows = _powershell_json(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric | Select-Object -First 1 NextHop | ConvertTo-Json -Compress"
    )
    if rows and rows[0].get("NextHop"):
        return rows[0]["NextHop"]
    return None


# ---------------------------------------------------------------------------
# Service checks
# ---------------------------------------------------------------------------


def check_port(host: str, port: int, timeout: float = 0.8) -> dict | None:
    """Connect one port and read whatever the service volunteers."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = ""
            try:
                if port in (80, 8080, 5000):
                    sock.sendall(
                        b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                    )
                    banner = sock.recv(1024).decode("utf-8", "replace")
                elif port in (443, 8443):
                    banner = _tls_summary(host, port, timeout)
                else:
                    banner = sock.recv(256).decode("utf-8", "replace")
            except Exception:
                banner = ""
        info = PORTS.get(port, {"name": f"port {port}", "risk": "info", "why": ""})
        return {
            "port": port, "service": info["name"], "risk": info["risk"],
            "why": info["why"], "banner": banner.strip()[:300] or None,
        }
    except Exception:
        return None


def _tls_summary(host: str, port: int, timeout: float) -> str:
    """Certificate subject and TLS version, which says a lot about a device."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert()
            version = tls.version()
            subject = ""
            if cert and cert.get("subject"):
                subject = ", ".join(
                    f"{k}={v}" for part in cert["subject"] for k, v in part
                )
            return f"{version} {subject}".strip()
    except ssl.SSLError as exc:
        return f"TLS error: {exc}"
    except Exception:
        return ""


def scan_host(host: str, ports: list[int], timeout: float = 0.8) -> list[dict]:
    found: list[dict] = []
    lock = threading.Lock()
    queue = list(ports)

    def worker() -> None:
        while True:
            with lock:
                if not queue:
                    return
                port = queue.pop()
            result = check_port(host, port, timeout)
            if result:
                with lock:
                    found.append(result)

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(10, len(ports)))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout * len(ports) + 5)
    found.sort(key=lambda f: f["port"])
    return found


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def audit(
    ports: list[int] | None = None,
    timeout: float = 0.8,
    max_hosts: int = 128,
    discovery_timeout: float = 4.0,
) -> dict:
    """Discover what is on the connected network, then check each host's services."""
    started = time.time()
    ports = ports or DEFAULT_PORTS

    connection = current_connection()
    subnets = local_subnets()
    router = gateway()

    discovered = device_module.discover(timeout=discovery_timeout,
                                        include_bluetooth=False)
    hosts = [d for d in discovered["devices"] if d.get("ip")][:max_hosts]

    results = []
    lock = threading.Lock()
    queue = list(hosts)

    def worker() -> None:
        while True:
            with lock:
                if not queue:
                    return
                host = queue.pop()
            services = scan_host(host["ip"], ports, timeout)
            host["services"] = services
            host["open_ports"] = [s["port"] for s in services]
            host["is_gateway"] = host["ip"] == router
            with lock:
                results.append(host)

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(12, max(1, len(hosts))))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=len(ports) * timeout + 30)

    results.sort(key=lambda h: tuple(int(p) for p in h["ip"].split("."))
                 if re.match(r"^\d+\.\d+\.\d+\.\d+$", h["ip"]) else (999,) * 4)

    findings = _findings(results, connection)
    return {
        "connection": connection,
        "subnets": subnets,
        "gateway": router,
        "hosts": results,
        "host_count": len(results),
        "with_services": len([h for h in results if h["services"]]),
        "findings": findings,
        "ports_checked": ports,
        "duration_ms": int((time.time() - started) * 1000),
        "scanned_at": time.time(),
    }


def _findings(hosts: list[dict], connection: dict) -> list[dict]:
    """Turn open services into things worth acting on."""
    out: list[dict] = []

    for host in hosts:
        label = host.get("label") or host["ip"]
        for service in host.get("services", []):
            if service["risk"] in ("critical", "high", "medium"):
                out.append({
                    "risk": service["risk"],
                    "host": host["ip"],
                    "label": label,
                    "title": f"{service['service']} open on {label}",
                    "detail": service["why"],
                    "port": service["port"],
                    "banner": service.get("banner"),
                })

        # A device offering plaintext management where it also offers encrypted.
        ports_open = set(host.get("open_ports") or [])
        if 80 in ports_open and 443 in ports_open:
            out.append({
                "risk": "low", "host": host["ip"], "label": label,
                "title": f"{label} serves its interface over plain HTTP as well as HTTPS",
                "detail": "Anyone on this network can read credentials sent to the "
                          "unencrypted port. Disable HTTP or force a redirect.",
                "port": 80,
            })

        if host.get("randomized_mac"):
            out.append({
                "risk": "info", "host": host["ip"], "label": label,
                "title": f"{label} uses a randomised MAC address",
                "detail": "Normal for phones and laptops. Worth noting if you expected "
                          "a fixed device here.",
                "port": None,
            })

    # Network-level observations
    security = (connection.get("security") or "").lower()
    if connection.get("connected"):
        if "open" in security:
            out.append({
                "risk": "critical", "host": None, "label": connection.get("ssid"),
                "title": f"'{connection.get('ssid')}' has no encryption",
                "detail": "Everything on this network is readable by anyone in range.",
                "port": None,
            })
        elif "wpa2" in security and "wpa3" not in security:
            out.append({
                "risk": "info", "host": None, "label": connection.get("ssid"),
                "title": f"'{connection.get('ssid')}' uses WPA2",
                "detail": "Fine today, but WPA3 resists offline password cracking. "
                          "Worth planning if the hardware supports it.",
                "port": None,
            })

    out.sort(key=lambda f: RISK_ORDER.get(f["risk"], 9))
    return out

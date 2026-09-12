"""
Preflight diagnostics.

Every check returns a status of ok / warn / fail plus a fix that tells the person
exactly what to do. Reachable from the Diagnostics tab and from `python -m app --doctor`.
"""

from __future__ import annotations

import ctypes
import importlib.util
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass

from . import config as config_module
from . import db, gps, installer, oui, runtime, updater, usbwifi, wlanapi

IS_WINDOWS = sys.platform == "win32"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


@dataclass
class Check:
    name: str
    status: str          # ok | warn | fail
    message: str
    fix: str = ""


def _is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_platform() -> Check:
    if IS_WINDOWS:
        return Check("Operating system", "ok", f"{platform.system()} {platform.release()}")
    return Check(
        "Operating system",
        "warn",
        f"Running on {platform.system()}, so live capture is unavailable",
        "The app is running against synthetic data. Native Wifi only exists on Windows.",
    )


def check_python() -> Check:
    if runtime.is_frozen():
        return Check(
            "Runtime", "ok",
            f"Packaged build, Python {platform.python_version()} embedded",
        )
    version = sys.version_info
    if version >= (3, 10):
        return Check("Python", "ok", f"{platform.python_version()} ({sys.executable})")
    return Check(
        "Python", "fail",
        f"{platform.python_version()} is too old",
        "Install Python 3.10 or newer from python.org.",
    )


def check_wlansvc() -> Check:
    if not IS_WINDOWS:
        return Check("WLAN AutoConfig service", "warn", "Not applicable off Windows")
    try:
        proc = subprocess.run(
            ["sc", "query", "wlansvc"], capture_output=True, text=True, timeout=15,
            creationflags=_NO_WINDOW,
        )
        if "RUNNING" in proc.stdout:
            return Check("WLAN AutoConfig service", "ok", "wlansvc is running")
        if "STOPPED" in proc.stdout:
            return Check(
                "WLAN AutoConfig service", "fail", "wlansvc is stopped",
                "Start it from an admin prompt: net start wlansvc",
            )
        return Check(
            "WLAN AutoConfig service", "fail", "wlansvc was not found",
            "On Windows Server, add the Wireless LAN Service feature: "
            "Install-WindowsFeature Wireless-Networking",
        )
    except Exception as exc:
        return Check("WLAN AutoConfig service", "warn", f"Could not query the service: {exc}")


def check_wlanapi() -> Check:
    if not IS_WINDOWS:
        return Check("Native Wifi API", "warn", "Only available on Windows")
    if wlanapi.available():
        return Check("Native Wifi API", "ok", "wlanapi.dll loaded")
    return Check(
        "Native Wifi API", "fail", "wlanapi.dll would not load",
        "Confirm this is a desktop Windows SKU with the WLAN service installed.",
    )


def check_adapters() -> Check:
    if not IS_WINDOWS or not wlanapi.available():
        return Check("Wireless adapters", "warn", "Cannot enumerate adapters on this host")
    from . import scanner

    try:
        found = scanner.engine.list_interfaces()
    except Exception as exc:
        return Check(
            "Wireless adapters", "fail", f"Enumeration failed: {exc}",
            "Run the app as Administrator if this says access denied.",
        )

    if not found:
        # An adapter that is disabled or driverless never reaches the Wi-Fi API,
        # so look underneath before reporting that nothing is plugged in.
        try:
            broken = usbwifi.unhealthy_adapters()
        except Exception:
            broken = []
        if broken:
            first = broken[0]
            model = first.get("model") or first["name"]
            return Check(
                "Wireless adapters", "fail",
                f"{model} is plugged in but not usable: {first['problem_detail']}",
                "Open the Adapter tab and use Diagnose & repair. It can fix this "
                "automatically in most cases.",
            )
        return Check(
            "Wireless adapters", "fail", "No wireless interfaces found",
            "Plug the adapter in and check Device Manager under Network adapters. "
            "A yellow triangle means the driver did not bind.",
        )

    selected = config_module.config.get("scan", "interface_guid", default="")
    chosen = next((a for a in found if a["guid"] == selected), None) or found[0]
    others = [a for a in found if a is not chosen]

    detail = f"Using {chosen.get('label') or chosen['description']}"
    if chosen.get("band_label") and chosen["band_label"] != "unknown":
        detail += f" ({chosen['band_label']})"
    if chosen.get("mac"):
        detail += f", MAC {chosen['mac']}"
    if others:
        detail += ". Also present: " + ", ".join(
            a.get("label") or a["description"] for a in others
        )

    if chosen.get("radio_on") is False:
        return Check(
            "Wireless adapters", "fail", f"{detail}. Its radio is switched off.",
            "Turn Wi-Fi on in Windows, or check for a hardware switch on the adapter.",
        )
    if not any(a.get("external") for a in found):
        return Check(
            "Wireless adapters", "warn", detail,
            "No external adapter recognised, so this will survey on the built-in radio. "
            "Plug the Alfa in for better sensitivity and 6 GHz coverage.",
        )
    if not chosen.get("external"):
        return Check(
            "Wireless adapters", "warn", detail,
            "An external adapter is available but is not the one selected. "
            "Change it on the Adapter tab.",
        )
    return Check("Wireless adapters", "ok", detail)


def check_usb_adapters() -> Check:
    """Adapters that are plugged in but not working, which the Wi-Fi API hides."""
    if not IS_WINDOWS:
        return Check("USB wireless devices", "ok", "Not applicable off Windows")
    try:
        summary = usbwifi.summarise()
    except Exception as exc:
        return Check("USB wireless devices", "warn", f"Could not enumerate USB devices: {exc}")

    if not summary["wifi_functions"]:
        return Check("USB wireless devices", "ok", "No USB wireless adapters detected")
    if not summary["broken"]:
        names = ", ".join(
            d.get("model") or d["name"] for d in summary["recognised"]
        ) or f"{summary['healthy']} working"
        return Check("USB wireless devices", "ok", names)

    first = summary["problems"][0]
    model = first.get("model") or first["name"]
    return Check(
        "USB wireless devices", "warn",
        f"{model} is present but not working: {first['problem']} "
        f"(code {first['problem_code']})",
        "The Adapter tab has a Diagnose & repair button that handles most of these.",
    )


def check_scanning() -> Check:
    """Say plainly whether it is scanning, because idle is a valid state."""
    from . import scanner

    status = scanner.engine.status()
    if not status["running"]:
        return Check(
            "Scan engine", "fail", "The engine thread is not running",
            "Restart the app. If it keeps happening, check the log.",
        )
    if not status["scanning"]:
        return Check(
            "Scan engine", "ok",
            "Ready but idle - press Start scanning when you want it to begin",
        )
    if status["last_error"]:
        return Check(
            "Scan engine", "fail", f"Scanning but failing: {status['last_error']}",
            "Check the adapter is still connected and its radio is on.",
        )
    scans = status["stats"]["scans"]
    return Check(
        "Scan engine", "ok",
        f"Scanning, {scans} scan(s) done, currently {status['phase']}",
    )


def check_admin() -> Check:
    if _is_admin():
        return Check("Privileges", "ok", "Running elevated")
    return Check(
        "Privileges", "warn", "Running as a standard user",
        "Scanning works unelevated on most systems. If WlanScan returns access "
        "denied, restart the app as Administrator.",
    )


def check_scan_rate() -> Check:
    interval = float(config_module.config.get("scan", "interval_seconds", default=20))
    minimum = float(config_module.config.get("scan", "min_interval_seconds", default=16))
    if interval < minimum:
        return Check(
            "Scan interval", "warn",
            f"Interval is {interval:.0f}s but the floor is {minimum:.0f}s",
            "Windows throttles WlanScan to roughly four requests a minute per adapter. "
            "The engine clamps to the floor, so shorter intervals do nothing.",
        )
    return Check("Scan interval", "ok", f"{interval:.0f} seconds between scans")


def check_database() -> Check:
    try:
        stats = db.stats()
        size_mb = db.db_size_bytes() / (1024 * 1024)
        limit = float(config_module.config.get("retention", "max_db_mb", default=2048))
        status = "warn" if size_mb > limit else "ok"
        fix = (
            "Lower the retention window in Settings, then run Compact." if status == "warn" else ""
        )
        return Check(
            "Database", status,
            f"{size_mb:.1f} MB, {stats['total_bss']} access points, "
            f"{stats['total_observations']} observations",
            fix,
        )
    except Exception as exc:
        return Check(
            "Database", "fail", f"Not reachable: {exc}",
            f"Check that {config_module.db_path()} is writable.",
        )


def check_disk() -> Check:
    try:
        path = config_module.data_dir()
        usage = shutil.disk_usage(str(path))
        free_gb = usage.free / (1024 ** 3)
        if free_gb < 1:
            return Check(
                "Disk space", "fail", f"{free_gb:.1f} GB free on the data volume",
                "Free up space or move WIFIRECON_DATA_DIR to another drive.",
            )
        if free_gb < 5:
            return Check("Disk space", "warn", f"{free_gb:.1f} GB free")
        return Check("Disk space", "ok", f"{free_gb:.0f} GB free at {path}")
    except Exception as exc:
        return Check("Disk space", "warn", f"Could not measure free space: {exc}")


def check_port() -> Check:
    """Only meaningful when remote access is on.

    The desktop application binds nothing, so a free port is the normal state
    and reporting on it otherwise would be noise.
    """
    if not config_module.config.get("server", "allow_lan", default=False):
        return Check(
            "Remote access", "ok",
            "Off. The desktop application does not open a port.",
        )
    host = config_module.config.get("server", "host", default="127.0.0.1")
    port = int(config_module.config.get("server", "port", default=8722))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        in_use = sock.connect_ex((host if host != "0.0.0.0" else "127.0.0.1", port)) == 0
    if in_use:
        return Check("Remote access", "ok", f"Serving on {host}:{port}")
    return Check(
        "Remote access", "warn",
        f"Turned on, but nothing is listening on {host}:{port}",
        "Start the server with: wifirecon --server",
    )


def check_oui() -> Check:
    if oui.db.source == "builtin":
        return Check(
            "Vendor database", "warn",
            f"Using the built-in list ({oui.db.size} prefixes)",
            "For full coverage, save Wireshark's `manuf` file or the IEEE OUI CSV into "
            f"{config_module.data_dir()} and restart.",
        )
    return Check("Vendor database", "ok", f"{oui.db.size} prefixes from {oui.db.source}")


def check_gps() -> Check:
    enabled = config_module.config.get("gps", "enabled", default=False)
    if not enabled:
        return Check("GPS", "ok", "Disabled")
    if not gps.SERIAL_AVAILABLE:
        return Check(
            "GPS", "fail", "pyserial is not installed",
            "pip install pyserial, then restart the app.",
        )
    status = gps.reader.status()
    if status["fix"]:
        fix = status["fix"]
        return Check("GPS", "ok", f"Fix at {fix['lat']:.5f}, {fix['lon']:.5f}")
    if status["running"]:
        return Check(
            "GPS", "warn", f"Reading {status['port']} but no fix yet",
            "Give the receiver a clear view of the sky. Cold starts take a minute or two.",
        )
    return Check(
        "GPS", "fail", status.get("error") or "Reader is not running",
        "Pick the right COM port in Settings.",
    )


def check_install() -> Check:
    """Where the executable lives and whether Windows knows about it."""
    if not runtime.is_frozen():
        return Check("Installation", "ok", "Running from source")
    state = installer.status()
    if state["installed"] and state["registered"]:
        bits = ["listed in Apps & features"]
        if state["autostart"]:
            bits.append("starts at logon")
        return Check("Installation", "ok",
                     f"Installed at {state['install_dir']} ({', '.join(bits)})")
    if state["installed"] and not state["registered"]:
        return Check(
            "Installation", "warn",
            "In the right folder but not listed in Apps & features",
            "Run the executable once with --install to register the uninstaller.",
        )
    return Check(
        "Installation", "warn",
        f"Running portably from {state['install_dir']}",
        "That works fine. For a Start Menu entry and a normal uninstall, run it "
        "once with --install.",
    )


# PySide6 draws the application, so without it there is no interface. The
# server packages are needed only for --server, and pyserial only for GPS.
REQUIRED_PACKAGES = {"PySide6": "PySide6-Essentials (the interface)"}
OPTIONAL_PACKAGES = {
    "fastapi": "fastapi (remote access)",
    "uvicorn": "uvicorn (remote access)",
    "serial": "pyserial (GPS)",
}


def check_dependencies() -> Check:
    label = "Bundled packages" if runtime.is_frozen() else "Python packages"
    missing = [
        text for name, text in REQUIRED_PACKAGES.items()
        if importlib.util.find_spec(name) is None
    ]
    if missing:
        fix = ("The executable was built incorrectly. Rebuild with build.ps1."
               if runtime.is_frozen() else "pip install -r requirements.txt")
        return Check(label, "fail", f"Missing: {', '.join(missing)}", fix)

    absent = [
        text for name, text in OPTIONAL_PACKAGES.items()
        if importlib.util.find_spec(name) is None
    ]
    if absent:
        return Check(
            label, "ok",
            f"Everything the interface needs is present. Not installed: "
            f"{', '.join(absent)}",
        )
    return Check(label, "ok", "All packages present")


def check_updates() -> Check:
    if runtime.is_frozen():
        state = updater.state()
        if state.get("error"):
            return Check("Updates", "warn", state["error"])
        if state.get("available"):
            return Check(
                "Updates", "warn", f"Version {state.get('latest')} is available",
                "Install it from the Diagnostics tab, or run with --update.",
            )
        checked = state.get("checked_at") or 0
        if not checked:
            return Check("Updates", "ok",
                         f"Version {updater.version()}, not checked yet this session")
        return Check("Updates", "ok", f"Version {updater.version()}, up to date")

    if not updater.is_git_checkout():
        return Check(
            "Updates", "warn", "Not a git checkout and not a packaged build",
            "Use the released executable, or clone with git, to get updates.",
        )
    state = updater.state()
    if state.get("error"):
        return Check("Updates", "warn", state["error"])
    if state.get("available"):
        return Check(
            "Updates", "warn", f"{state['behind']} update(s) available",
            "Apply them from the Diagnostics tab.",
        )
    return Check("Updates", "ok", f"Version {updater.version()}, up to date")


CHECKS = [
    check_platform, check_python, check_dependencies, check_install, check_wlansvc,
    check_wlanapi, check_adapters, check_admin, check_scan_rate, check_database,
    check_disk, check_port, check_oui, check_gps, check_updates,
]


def run_all() -> dict:
    results = []
    for fn in CHECKS:
        try:
            results.append(asdict(fn()))
        except Exception as exc:  # a broken check must never break diagnostics
            results.append(
                asdict(Check(fn.__name__, "warn", f"Check itself failed: {exc}"))
            )
    summary = {
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "warn": sum(1 for r in results if r["status"] == "warn"),
        "fail": sum(1 for r in results if r["status"] == "fail"),
    }
    return {
        "checks": results,
        "summary": summary,
        "healthy": summary["fail"] == 0,
        "version": updater.version(),
        "data_dir": str(config_module.data_dir()),
        "db_path": str(config_module.db_path()),
        "log_path": str(config_module.log_path()),
        "install": installer.status(),
    }


def print_report() -> int:
    """CLI output. Returns a shell exit code."""
    report = run_all()
    symbols = {"ok": "[ ok ]", "warn": "[warn]", "fail": "[FAIL]"}
    print(f"\nwifirecon-win {report['version']} diagnostics")
    print(f"Data directory: {report['data_dir']}\n")
    for check in report["checks"]:
        print(f"{symbols[check['status']]} {check['name']}: {check['message']}")
        if check["fix"]:
            for line in _wrap(check["fix"], 72):
                print(f"         {line}")
    summary = report["summary"]
    print(f"\n{summary['ok']} ok, {summary['warn']} warnings, {summary['fail']} failures\n")
    return 0 if report["healthy"] else 1


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines

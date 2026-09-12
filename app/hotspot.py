"""
Hotspot and internet sharing.

The travel case: the laptop connects to hotel or conference Wi-Fi, brings up a
VPN, and then shares that VPN'd connection as its own SSID so phones, tablets
and anything else join a network that is already inside the tunnel. One VPN
session covers every device, and the hotel only ever sees one client.

Windows offers two mechanisms:

* **Mobile Hotspot** (Windows 10+) is the modern one. It is a WiFi Direct
  soft AP managed by the Network Operators API, and it handles NAT itself.
* **Hosted network** (`netsh wlan set hostednetwork`) is the legacy one. Most
  current drivers report it as unsupported, MediaTek's included, so it is only
  a fallback.

Sharing is Internet Connection Sharing, which is what puts the hotspot behind
whichever adapter you nominate — the VPN's virtual adapter, for the case above.
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

# Adapter names that usually mean a VPN's virtual interface. Used to suggest a
# sensible sharing source rather than making someone guess.
VPN_HINTS = (
    "wireguard", "wg", "openvpn", "tap-windows", "tap-nordvpn", "nordlynx",
    "proton", "mullvad", "expressvpn", "tunnelbear", "surfshark", "cisco anyconnect",
    "anyconnect", "globalprotect", "fortinet", "pulse", "zscaler", "tailscale",
    "zerotier", "softether", "ipsec", "l2tp", "sstp", "pptp", "vpn",
)


def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    if not IS_WINDOWS:
        return 1, "Not running on Windows"
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, errors="replace",
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} timed out"
    except FileNotFoundError:
        return 127, f"{args[0]} is not available"
    except Exception as exc:
        return 1, str(exc)


def _powershell(script: str, timeout: int = 45) -> tuple[int, str]:
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        timeout,
    )


def _powershell_json(script: str, timeout: int = 45) -> Any:
    code, output = _powershell(script, timeout)
    if code != 0 or not output:
        return None
    try:
        data = json.loads(output)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Capability and state
# ---------------------------------------------------------------------------


def hosted_network_supported() -> bool:
    """Whether the legacy hosted-network mode is available on any adapter."""
    code, output = _run(["netsh", "wlan", "show", "drivers"])
    if code != 0:
        return False
    return bool(re.search(r"Hosted network supported\s*:\s*Yes", output, re.IGNORECASE))


def hotspot_state() -> dict:
    """Current Mobile Hotspot state, read through the Network Operators API."""
    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        "  [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]|Out-Null;"
        "  [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]|Out-Null;"
        "  $profile=[Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile();"
        "  if ($null -eq $profile) { "
        "    [pscustomobject]@{available=$false;reason='No internet connection profile'}"
        "      | ConvertTo-Json -Compress; exit 0 }"
        "  $mgr=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile);"
        "  $cfg=$mgr.GetCurrentAccessPointConfiguration();"
        "  [pscustomobject]@{"
        "    available=$true; state=$mgr.TetheringOperationalState.ToString();"
        "    clients=$mgr.ClientCount; maxClients=$mgr.MaxClientCount;"
        "    ssid=$cfg.Ssid; band=$cfg.Band.ToString();"
        "    source=$profile.ProfileName"
        "  } | ConvertTo-Json -Compress"
        "} catch {"
        "  [pscustomobject]@{available=$false;reason=$_.Exception.Message}"
        "    | ConvertTo-Json -Compress }"
    )
    rows = _powershell_json(script)
    if not rows:
        return {"available": False, "reason": "Could not read the hotspot state",
                "state": "unknown"}
    data = rows[0]
    data.setdefault("state", "Off")
    data["on"] = str(data.get("state", "")).lower() == "on"
    return data


def adapters() -> list[dict]:
    """Every network adapter, tagged with whether it looks like a VPN tunnel."""
    rows = _powershell_json(
        "Get-NetAdapter -ErrorAction SilentlyContinue | "
        "Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, "
        "InterfaceIndex, MediaType | ConvertTo-Json -Compress"
    ) or []
    out = []
    for row in rows:
        name = row.get("Name") or ""
        description = row.get("InterfaceDescription") or ""
        blob = f"{name} {description}".lower()
        is_vpn = any(hint in blob for hint in VPN_HINTS)
        out.append({
            "name": name,
            "description": description,
            "status": row.get("Status"),
            "up": str(row.get("Status", "")).lower() == "up",
            "link_speed": row.get("LinkSpeed"),
            "mac": row.get("MacAddress"),
            "index": row.get("InterfaceIndex"),
            "media": row.get("MediaType"),
            "vpn": is_vpn,
            "wireless": "wi-fi" in blob or "wireless" in blob or "802.11" in blob,
        })
    out.sort(key=lambda a: (not a["vpn"], not a["up"], a["name"]))
    return out


def sharing_state() -> list[dict]:
    """Which adapters currently have Internet Connection Sharing enabled."""
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$m = New-Object -ComObject HNetCfg.HNetShare;"
        "$out = @();"
        "foreach ($c in $m.EnumEveryConnection) {"
        "  $p = $m.NetConnectionProps.Invoke($c);"
        "  $s = $m.INetSharingConfigurationForINetConnection.Invoke($c);"
        "  $out += [pscustomobject]@{"
        "    name=$p.Name; device=$p.DeviceName; enabled=$s.SharingEnabled;"
        "    type=$(if ($s.SharingEnabled) { $s.SharingConnectionType.ToString() } else { '' })"
        "  } };"
        "$out | ConvertTo-Json -Compress"
    )
    rows = _powershell_json(script) or []
    return [
        {
            "name": r.get("name"), "device": r.get("device"),
            "sharing": bool(r.get("enabled")),
            # 0 is the public side (the one with internet), 1 is the private side.
            "role": "internet source" if str(r.get("type")) == "0"
                    else "shared to" if str(r.get("type")) == "1" else "",
        }
        for r in rows
    ]


def status() -> dict:
    """Everything needed to decide what to do, in one call."""
    if not IS_WINDOWS:
        return {"supported": False, "reason": "Hotspot control is Windows only",
                "hotspot": {}, "adapters": [], "sharing": []}
    hotspot = hotspot_state()
    all_adapters = adapters()
    vpn_adapters = [a for a in all_adapters if a["vpn"]]
    return {
        "supported": True,
        "hotspot": hotspot,
        "hosted_network": hosted_network_supported(),
        "adapters": all_adapters,
        "sharing": sharing_state(),
        "vpn_adapters": vpn_adapters,
        "suggested_source": (
            next((a["name"] for a in vpn_adapters if a["up"]), None)
            or next((a["name"] for a in vpn_adapters), None)
        ),
        "advice": _advice(hotspot, vpn_adapters),
    }


def _advice(hotspot: dict, vpn_adapters: list[dict]) -> list[str]:
    notes = []
    if not hotspot.get("available"):
        notes.append(
            "Windows is not offering Mobile Hotspot right now. It needs a working "
            "internet connection before it will start: "
            + str(hotspot.get("reason", "no reason given"))
        )
    if not vpn_adapters:
        notes.append(
            "No VPN adapter was detected. Connect your VPN first, then the hotspot "
            "can be pointed at it so every device joining goes through the tunnel."
        )
    else:
        live = [a for a in vpn_adapters if a["up"]]
        if live:
            notes.append(
                f"'{live[0]['name']}' looks like your VPN tunnel. Share that one and "
                "everything on the hotspot rides inside it."
            )
        else:
            notes.append(
                f"A VPN adapter ('{vpn_adapters[0]['name']}') exists but is down. "
                "Connect the VPN before starting the hotspot."
            )
    notes.append(
        "Order matters: connect upstream Wi-Fi, bring the VPN up, then start the "
        "hotspot. Starting it first usually shares the raw connection instead."
    )
    return notes


# ---------------------------------------------------------------------------
# Control
# ---------------------------------------------------------------------------


def configure(ssid: str, passphrase: str, band: str = "auto") -> dict:
    """Set the hotspot's name and passphrase."""
    # Validate the input before the platform check, so the message names the
    # actual problem rather than the environment.
    ssid = (ssid or "").strip()
    if not 1 <= len(ssid.encode("utf-8")) <= 32:
        return {"ok": False, "error": "The network name must be 1 to 32 bytes"}
    if len(passphrase or "") < 8 or len(passphrase or "") > 63:
        return {"ok": False,
                "error": "The passphrase must be between 8 and 63 characters"}
    if not IS_WINDOWS:
        return {"ok": False, "error": "Hotspot control is Windows only"}

    band_map = {"auto": "Auto", "2.4": "TwoPointFourGigahertz", "5": "FiveGigahertz"}
    band_value = band_map.get(band, "Auto")
    safe_ssid = ssid.replace("'", "''")
    safe_pass = passphrase.replace("'", "''")

    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        "  [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]|Out-Null;"
        "  [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]|Out-Null;"
        "  $p=[Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile();"
        "  $m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p);"
        "  $c=$m.GetCurrentAccessPointConfiguration();"
        f"  $c.Ssid='{safe_ssid}'; $c.Passphrase='{safe_pass}';"
        f"  try {{ $c.Band=[Windows.Networking.NetworkOperators.TetheringWiFiBand]::{band_value} }} catch {{}};"
        "  $op=$m.ConfigureAccessPointAsync($c); "
        "  while ($op.Status -eq 0) { Start-Sleep -Milliseconds 200 };"
        "  'configured'"
        "} catch { 'ERROR: ' + $_.Exception.Message }"
    )
    code, output = _powershell(script, timeout=60)
    if "configured" in output:
        return {"ok": True, "message": f"Hotspot set to '{ssid}'"}
    return {"ok": False, "error": output.replace("ERROR: ", "")[:250]
            or "Windows would not accept the configuration"}


def _tethering_action(action: str) -> dict:
    method = "StartTetheringAsync" if action == "start" else "StopTetheringAsync"
    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        "  [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]|Out-Null;"
        "  [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]|Out-Null;"
        "  $p=[Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile();"
        "  if ($null -eq $p) { throw 'There is no internet connection to share.' };"
        "  $m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p);"
        f"  $op=$m.{method}();"
        "  $t=0; while ($op.Status -eq 0 -and $t -lt 100) { Start-Sleep -Milliseconds 200; $t++ };"
        "  $r=$op.GetResults();"
        "  if ($r) { $r.Status.ToString() + '|' + $r.AdditionalErrorMessage } else { 'Unknown' }"
        "} catch { 'ERROR: ' + $_.Exception.Message }"
    )
    code, output = _powershell(script, timeout=90)
    if output.startswith("ERROR:"):
        return {"ok": False, "error": output.replace("ERROR: ", "")[:250]}
    result = output.split("|")[0].strip()
    if result in ("Success", "0"):
        return {"ok": True, "message": f"Hotspot {action}ed"}
    detail = output.split("|", 1)[1].strip() if "|" in output else ""
    return {"ok": False, "error": f"Windows returned '{result}'"
            + (f": {detail}" if detail else ""),
            "hint": "Mobile Hotspot needs a working internet connection to share, "
                    "and some adapters refuse to run one while connected to Wi-Fi."}


def start() -> dict:
    if not IS_WINDOWS:
        return {"ok": False, "error": "Windows only"}
    return _tethering_action("start")


def stop() -> dict:
    if not IS_WINDOWS:
        return {"ok": False, "error": "Windows only"}
    return _tethering_action("stop")


def set_sharing(source: str, target: str, enable: bool = True) -> dict:
    """Point Internet Connection Sharing at a specific upstream adapter.

    `source` is the connection with internet — the VPN adapter for the travel
    case. `target` is the one being shared to, which is the hotspot adapter.
    """
    if not source or not target:
        return {"ok": False, "error": "Both a source and a target adapter are required"}
    if not IS_WINDOWS:
        return {"ok": False, "error": "Internet sharing control is Windows only"}

    safe_source = source.replace("'", "''")
    safe_target = target.replace("'", "''")
    flag = "$true" if enable else "$false"
    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        "  $m = New-Object -ComObject HNetCfg.HNetShare;"
        "  $src=$null; $dst=$null;"
        "  foreach ($c in $m.EnumEveryConnection) {"
        "    $p=$m.NetConnectionProps.Invoke($c);"
        f"    if ($p.Name -eq '{safe_source}') {{ $src=$c }};"
        f"    if ($p.Name -eq '{safe_target}') {{ $dst=$c }} }};"
        "  if ($null -eq $src) { throw 'Source adapter not found' };"
        "  if ($null -eq $dst) { throw 'Target adapter not found' };"
        "  $sc=$m.INetSharingConfigurationForINetConnection.Invoke($src);"
        "  $dc=$m.INetSharingConfigurationForINetConnection.Invoke($dst);"
        f"  if ({flag}) {{ $sc.EnableSharing(0); $dc.EnableSharing(1) }}"
        "  else { $sc.DisableSharing(); $dc.DisableSharing() };"
        "  'done'"
        "} catch { 'ERROR: ' + $_.Exception.Message }"
    )
    code, output = _powershell(script, timeout=60)
    if "done" in output:
        return {
            "ok": True,
            "message": f"Sharing {'enabled' if enable else 'disabled'}: "
                       f"{source} -> {target}",
        }
    error = output.replace("ERROR: ", "")[:250]
    return {"ok": False, "error": error or "Windows would not change the sharing setting",
            "hint": "Changing Internet Connection Sharing needs administrator rights."}

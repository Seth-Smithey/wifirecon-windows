"""
Adapter recovery.

Getting an external USB radio to present itself as a usable WLAN interface on
Windows involves a predictable set of failures: the device disabled by an
earlier VM passthrough attempt, no driver bound, a driver that loaded and then
failed, the WLAN service stopped, the radio switched off in software, or a
virtualisation stack still holding the USB claim.

Each of those has a known fix. This walks them in order, least invasive first,
re-checking after every step so it stops as soon as the adapter appears.

Design rules:
  * Nothing runs without the person asking for it.
  * Nothing here disables, uninstalls or deletes anything.
  * Every step reports what it did, whether it worked, and why.
  * A step that needs elevation says so rather than failing obscurely.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import runtime, usbwifi, wlanapi

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------


def run(args: list[str], timeout: int = 60) -> tuple[int, str]:
    if not IS_WINDOWS:
        return 1, "Not running on Windows"
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=NO_WINDOW, errors="replace",
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} timed out after {timeout}s"
    except FileNotFoundError:
        return 127, f"{args[0]} is not available"
    except Exception as exc:
        return 1, str(exc)


def powershell(script: str, timeout: int = 60) -> tuple[int, str]:
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        timeout,
    )


def wlan_interface_count() -> int:
    """How many usable WLAN interfaces Windows currently reports."""
    if not IS_WINDOWS or not wlanapi.available():
        return 0
    try:
        with wlanapi.WlanHandle() as handle:
            return len(handle.interfaces())
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Step framework
# ---------------------------------------------------------------------------


@dataclass
class StepResult:
    name: str
    status: str                 # fixed | skipped | failed | no_action | needs_admin | manual
    message: str
    detail: str = ""
    changed: bool = False
    duration_ms: int = 0


@dataclass
class Recovery:
    started_at: float = field(default_factory=time.time)
    steps: list[StepResult] = field(default_factory=list)
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    resolved: bool = False
    admin: bool = False

    def add(self, result: StepResult) -> None:
        self.steps.append(result)
        log.info("Recovery step %s: %s - %s", result.name, result.status, result.message)

    def as_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "duration_ms": int((time.time() - self.started_at) * 1000),
            "admin": self.admin,
            "resolved": self.resolved,
            "before": self.before,
            "after": self.after,
            "steps": [vars(s) for s in self.steps],
            "changed": any(s.changed for s in self.steps),
            "summary": self.summary(),
        }

    def summary(self) -> str:
        if self.resolved:
            gained = self.after.get("interfaces", 0) - self.before.get("interfaces", 0)
            if gained > 0:
                return (f"Recovered {gained} adapter"
                        f"{'s' if gained != 1 else ''}. It should appear in the list now.")
            return "The adapter is available."
        blocked = [s for s in self.steps if s.status == "needs_admin"]
        if blocked:
            return ("Some repairs need administrator rights. Restart wifirecon as "
                    "administrator and run this again.")
        manual = [s for s in self.steps if s.status == "manual"]
        if manual:
            return manual[0].message
        if not self.before.get("usb_wifi_devices"):
            return ("No USB wireless adapter is plugged in, or Windows is not seeing "
                    "it at all. Try a different USB 3.0 port and a different cable.")
        return "Nothing here fixed it. The detail below is what to try by hand."


# ---------------------------------------------------------------------------
# Individual steps
# ---------------------------------------------------------------------------


def step_scan_devices(ctx: dict) -> StepResult:
    """Ask Windows to re-enumerate. Costs nothing and sometimes finds a device
    that was plugged in while the machine was asleep."""
    start = time.time()
    code, output = run(["pnputil", "/scan-devices"], timeout=90)
    return StepResult(
        "rescan", "no_action" if code != 0 else "fixed" if "detected" in output.lower() else "no_action",
        "Asked Windows to re-scan for hardware changes",
        output[:200], changed=False, duration_ms=int((time.time() - start) * 1000),
    )


def step_wlansvc(ctx: dict) -> StepResult:
    """WLAN AutoConfig has to be running or no adapter appears, regardless of
    driver state."""
    start = time.time()
    code, output = run(["sc", "query", "wlansvc"])
    if "RUNNING" in output:
        return StepResult("wlansvc", "no_action", "WLAN AutoConfig is already running",
                          duration_ms=int((time.time() - start) * 1000))
    if "STOPPED" not in output and code != 0:
        return StepResult(
            "wlansvc", "manual",
            "The WLAN AutoConfig service is missing",
            "On Windows Server, add the Wireless LAN Service feature: "
            "Install-WindowsFeature Wireless-Networking",
            duration_ms=int((time.time() - start) * 1000),
        )
    if not ctx["admin"]:
        return StepResult("wlansvc", "needs_admin",
                          "WLAN AutoConfig is stopped and starting it needs administrator rights",
                          duration_ms=int((time.time() - start) * 1000))

    run(["sc", "config", "wlansvc", "start=", "auto"])
    code, output = run(["net", "start", "wlansvc"], timeout=60)
    time.sleep(2)
    ok = "RUNNING" in run(["sc", "query", "wlansvc"])[1]
    return StepResult(
        "wlansvc", "fixed" if ok else "failed",
        "Started the WLAN AutoConfig service" if ok else "Could not start WLAN AutoConfig",
        output[:200], changed=ok, duration_ms=int((time.time() - start) * 1000),
    )


def step_virtualisation_claim(ctx: dict) -> StepResult:
    """A running VM stack can hold the USB device away from the host, which is
    the most common reason an adapter vanishes after Kali work."""
    start = time.time()
    code, output = powershell(
        "$s = Get-Service -ErrorAction SilentlyContinue "
        "-Name 'VMUSBArbService','VBoxUSBMon','VBoxSDS','vmware-usbarbitrator64' | "
        "Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name; "
        "$p = Get-Process -ErrorAction SilentlyContinue "
        "-Name 'vmware','vmware-vmx','VirtualBoxVM','VBoxHeadless' | "
        "Select-Object -ExpandProperty Name; "
        "($s + $p) -join ','"
    )
    holders = [h for h in (output or "").split(",") if h.strip()]
    if not holders:
        return StepResult("virtualisation", "no_action",
                          "No virtual machine software is holding USB devices",
                          duration_ms=int((time.time() - start) * 1000))
    return StepResult(
        "virtualisation", "manual",
        "Virtual machine software is running and may have claimed the adapter",
        f"Found: {', '.join(sorted(set(holders)))}. If a VM has the adapter attached, "
        "the Windows host cannot see it. Shut the VM down, or use "
        "VM > Removable Devices to disconnect the adapter back to the host.",
        duration_ms=int((time.time() - start) * 1000),
    )


def step_enable_disabled(ctx: dict) -> StepResult:
    """Code 22: the device was explicitly disabled. Usually left over from a
    passthrough attempt, and it survives reboots and replugs."""
    start = time.time()
    targets = [d for d in ctx["devices"] if d["problem_code"] == 22]
    if not targets:
        return StepResult("enable", "no_action", "No disabled wireless adapters found",
                          duration_ms=int((time.time() - start) * 1000))
    if not ctx["admin"]:
        names = ", ".join(d["name"] for d in targets)
        return StepResult(
            "enable", "needs_admin",
            f"Found {len(targets)} disabled adapter(s) but enabling needs administrator rights",
            f"Disabled: {names}", duration_ms=int((time.time() - start) * 1000),
        )

    enabled, failures = [], []
    for device in targets:
        # Enable every function of the composite device, not just the Wi-Fi half,
        # so a combo Wi-Fi/Bluetooth chip is not left half-disabled.
        siblings = [
            d for d in ctx["all_devices"]
            if d.get("vid") == device.get("vid") and d.get("pid") == device.get("pid")
            and d["problem_code"] == 22
        ] or [device]
        for sibling in siblings:
            code, output = powershell(
                f"Enable-PnpDevice -InstanceId '{sibling['instance_id']}' "
                "-Confirm:$false -ErrorAction Stop"
            )
            if code == 0:
                enabled.append(sibling["name"])
            else:
                failures.append(f"{sibling['name']}: {output[:80]}")
    if enabled:
        time.sleep(3)
    return StepResult(
        "enable", "fixed" if enabled else "failed",
        f"Enabled {len(enabled)} device function(s)" if enabled
        else "Could not enable the disabled adapter",
        "; ".join(failures)[:300] if failures else ", ".join(enabled)[:300],
        changed=bool(enabled), duration_ms=int((time.time() - start) * 1000),
    )


def step_bind_driver(ctx: dict) -> StepResult:
    """Code 28: no driver bound. Very often a matching driver is already in the
    driver store and simply was not applied."""
    start = time.time()
    targets = [d for d in ctx["devices"] if d["problem_code"] in (28, 1, 31, 18)]
    if not targets:
        return StepResult("driver", "no_action", "Every adapter already has a driver",
                          duration_ms=int((time.time() - start) * 1000))
    if not ctx["admin"]:
        return StepResult(
            "driver", "needs_admin",
            f"{len(targets)} adapter(s) have no driver and installing one needs "
            "administrator rights",
            duration_ms=int((time.time() - start) * 1000),
        )

    bound, notes = [], []
    for device in targets:
        # pnputil can re-run driver selection against the store for one device.
        code, output = run(
            ["pnputil", "/scan-devices"], timeout=90
        )
        time.sleep(2)
        code, output = powershell(
            f"$d = Get-PnpDevice -InstanceId '{device['instance_id']}' "
            "-ErrorAction SilentlyContinue; if ($d) { $d.Status }"
        )
        if "OK" in (output or "").upper():
            bound.append(device["name"])
            continue

        # Nothing in the store matched, so say which driver is needed.
        model = device.get("model") or device["name"]
        notes.append(
            f"{model} (VID_{device.get('vid')}&PID_{device.get('pid')}) still has no "
            "driver. Try Windows Update > Advanced options > Optional updates > "
            "Driver updates first, then the manufacturer's Windows driver."
        )

    if bound:
        return StepResult(
            "driver", "fixed", f"Bound a driver to {len(bound)} adapter(s)",
            ", ".join(bound)[:300], changed=True,
            duration_ms=int((time.time() - start) * 1000),
        )
    return StepResult(
        "driver", "manual", "No matching driver is available on this machine",
        " ".join(notes)[:500], duration_ms=int((time.time() - start) * 1000),
    )


def step_restart_failed(ctx: dict) -> StepResult:
    """Codes 10, 43 and 31: a driver loaded and then failed. A disable/enable
    cycle clears most of these."""
    start = time.time()
    targets = [d for d in ctx["devices"] if d["problem_code"] in (10, 43, 31, 14, 38)]
    if not targets:
        return StepResult("restart_device", "no_action", "No adapters are in a failed state",
                          duration_ms=int((time.time() - start) * 1000))
    if not ctx["admin"]:
        return StepResult("restart_device", "needs_admin",
                          f"{len(targets)} adapter(s) need a restart, which requires "
                          "administrator rights",
                          duration_ms=int((time.time() - start) * 1000))

    restarted, failures = [], []
    for device in targets:
        code, output = powershell(
            f"$id = '{device['instance_id']}'; "
            "Disable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop; "
            "Start-Sleep -Seconds 2; "
            "Enable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop",
            timeout=90,
        )
        if code == 0:
            restarted.append(device["name"])
        else:
            failures.append(f"{device['name']}: {output[:80]}")
    if restarted:
        time.sleep(4)
    return StepResult(
        "restart_device", "fixed" if restarted else "failed",
        f"Restarted {len(restarted)} adapter(s)" if restarted
        else "Could not restart the failed adapter",
        "; ".join(failures)[:300] if failures else ", ".join(restarted)[:300],
        changed=bool(restarted), duration_ms=int((time.time() - start) * 1000),
    )


def step_radio_on(ctx: dict) -> StepResult:
    """A software radio block makes an adapter present but unable to scan, and
    airplane mode blocks every radio at once."""
    start = time.time()
    if not wlanapi.available():
        return StepResult("radio", "skipped", "Native Wifi is unavailable, so radio state "
                          "cannot be checked", duration_ms=int((time.time() - start) * 1000))
    off = []
    try:
        with wlanapi.WlanHandle() as handle:
            for entry in handle.interfaces():
                try:
                    state = handle.radio_state(entry["_guid_struct"])
                except Exception:
                    continue
                if not state["on"]:
                    hardware_off = any(r["hardware"] == "off" for r in state["radios"])
                    off.append((entry["description"], hardware_off))
    except Exception as exc:
        return StepResult("radio", "skipped", f"Could not read radio state: {exc}",
                          duration_ms=int((time.time() - start) * 1000))

    if not off:
        return StepResult("radio", "no_action", "Every adapter's radio is on",
                          duration_ms=int((time.time() - start) * 1000))

    hardware_blocked = [name for name, hw in off if hw]
    if hardware_blocked:
        return StepResult(
            "radio", "manual",
            f"The radio on {hardware_blocked[0]} is switched off in hardware",
            "Look for a physical switch on the adapter or laptop, or a function key. "
            "Windows cannot override a hardware radio block.",
            duration_ms=int((time.time() - start) * 1000),
        )

    # Software block: airplane mode is the usual cause and needs the Settings app.
    return StepResult(
        "radio", "manual",
        f"The radio on {off[0][0]} is switched off in software",
        "Open Settings > Network & internet and turn Wi-Fi on, and check that "
        "airplane mode is off. Windows does not allow this to be changed "
        "programmatically.",
        duration_ms=int((time.time() - start) * 1000),
    )


def step_restart_wlansvc(ctx: dict) -> StepResult:
    """Last resort before manual work: bounce WLAN AutoConfig so it re-enumerates
    adapters that came up after it started."""
    start = time.time()
    if not ctx["admin"]:
        return StepResult("refresh_wlansvc", "needs_admin",
                          "Restarting WLAN AutoConfig needs administrator rights",
                          duration_ms=int((time.time() - start) * 1000))
    before = wlan_interface_count()
    code, output = powershell("Restart-Service wlansvc -Force -ErrorAction Stop", timeout=90)
    if code != 0:
        return StepResult("refresh_wlansvc", "failed",
                          "Could not restart WLAN AutoConfig", output[:200],
                          duration_ms=int((time.time() - start) * 1000))
    time.sleep(5)
    after = wlan_interface_count()
    gained = after - before
    return StepResult(
        "refresh_wlansvc", "fixed" if gained > 0 else "no_action",
        f"Restarted WLAN AutoConfig; {after} interface(s) now present"
        + (f", {gained} more than before" if gained > 0 else ""),
        changed=True, duration_ms=int((time.time() - start) * 1000),
    )


# Order matters: cheapest and least invasive first, and anything that changes
# device state only after the read-only checks have run.
STEPS: list[tuple[str, Callable[[dict], StepResult], bool]] = [
    ("Re-scan for hardware", step_scan_devices, False),
    ("WLAN AutoConfig service", step_wlansvc, True),
    ("Virtual machine claim", step_virtualisation_claim, False),
    ("Enable disabled adapters", step_enable_disabled, True),
    ("Restart failed adapters", step_restart_failed, True),
    ("Install a driver", step_bind_driver, True),
    ("Radio switched off", step_radio_on, False),
    ("Refresh the WLAN service", step_restart_wlansvc, True),
]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def snapshot() -> dict:
    """What the system looks like right now, from both angles."""
    devices = usbwifi.list_usb_wifi_devices()
    summary = usbwifi.summarise(devices)
    return {
        "interfaces": wlan_interface_count(),
        "usb_wifi_devices": summary["wifi_functions"],
        "healthy": summary["healthy"],
        "broken": summary["broken"],
        "problems": [
            {"name": d["name"], "problem": d["problem"], "code": d["problem_code"],
             "model": d.get("model"), "instance_id": d["instance_id"]}
            for d in summary["problems"]
        ],
        "recognised": [d.get("model") or d["name"] for d in summary["recognised"]],
    }


def diagnose() -> dict:
    """Read-only. Says what is wrong and what would be attempted, changing nothing."""
    state = snapshot()
    devices = usbwifi.unhealthy_adapters()
    admin = runtime.is_admin()

    planned = []
    for label, function, needs_admin in STEPS:
        applies = True
        if function is step_enable_disabled:
            applies = any(d["problem_code"] == 22 for d in devices)
        elif function is step_bind_driver:
            applies = any(d["problem_code"] in (28, 1, 31, 18) for d in devices)
        elif function is step_restart_failed:
            applies = any(d["problem_code"] in (10, 43, 31, 14, 38) for d in devices)
        if applies:
            planned.append({"name": label, "needs_admin": needs_admin,
                            "blocked": needs_admin and not admin})

    return {
        "state": state,
        "admin": admin,
        "planned": planned,
        "needs_admin": any(p["blocked"] for p in planned),
        "worth_running": bool(devices) or state["interfaces"] == 0,
        "verdict": _verdict(state, devices, admin),
    }


def _verdict(state: dict, devices: list[dict], admin: bool) -> str:
    if state["interfaces"] > 0 and not devices:
        return "Everything looks healthy."
    if not state["usb_wifi_devices"] and state["interfaces"] == 0:
        return ("No wireless adapter of any kind is visible. Check it is plugged into "
                "a USB 3.0 port and try a different cable.")
    if devices:
        first = devices[0]
        model = first.get("model") or first["name"]
        return f"{model} is plugged in but not usable: {first['problem_detail']}"
    if state["interfaces"] == 0:
        return "A wireless adapter is present but Windows is not offering it for scanning."
    return "Some adapters need attention."


def repair(dry_run: bool = False) -> dict:
    """Walk the repair steps, stopping as soon as a new interface appears."""
    result = Recovery(admin=runtime.is_admin())
    result.before = snapshot()

    if not IS_WINDOWS:
        result.add(StepResult("platform", "skipped",
                              "Adapter recovery only applies on Windows"))
        result.after = result.before
        return result.as_dict()

    if dry_run:
        plan = diagnose()
        for entry in plan["planned"]:
            result.add(StepResult(
                entry["name"], "needs_admin" if entry["blocked"] else "skipped",
                "Would run this step" if not entry["blocked"]
                else "Would run this step, but it needs administrator rights",
            ))
        result.after = result.before
        return result.as_dict()

    baseline = result.before["interfaces"]

    for label, function, _ in STEPS:
        context = {
            "admin": result.admin,
            "all_devices": usbwifi.list_usb_wifi_devices(),
        }
        context["devices"] = usbwifi.unhealthy_adapters(context["all_devices"])

        try:
            step = function(context)
        except Exception as exc:
            log.exception("Recovery step %s raised", label)
            step = StepResult(label, "failed", f"This step failed unexpectedly: {exc}")
        step.name = label
        result.add(step)

        # Stop as soon as we have gained an interface; no point poking further.
        if step.changed:
            time.sleep(2)
            if wlan_interface_count() > baseline:
                result.add(StepResult(
                    "verify", "fixed",
                    "A new wireless interface appeared, so recovery stopped here",
                ))
                break

    result.after = snapshot()
    result.resolved = (
        result.after["interfaces"] > baseline
        or (result.after["interfaces"] > 0 and result.after["broken"] == 0)
    )
    return result.as_dict()


def repair_elevated(timeout: int = 240) -> dict:
    """Run the repair in a short-lived elevated helper process.

    The app itself keeps running unelevated. Windows will not let a process
    raise its own privileges, but it will let us start a new one, so the helper
    does the privileged work, writes its result to a file and exits. One UAC
    prompt, no restart, no lost session.
    """
    if not IS_WINDOWS:
        return {"ok": False, "error": "Only applies on Windows"}
    if runtime.is_admin():
        # Already elevated, so just do it here.
        return {"ok": True, "elevated": False, "report": repair()}

    import json
    import tempfile

    handle, output_path = tempfile.mkstemp(prefix="wifirecon-repair-", suffix=".json")
    os.close(handle)
    output = Path(output_path)
    try:
        output.unlink()
    except OSError:
        pass

    argv = runtime.relaunch_argv(["--repair-worker", "--repair-output", str(output)])
    target = argv[0]
    quoted = ",".join("'" + a.replace("'", "''") + "'" for a in argv[1:])
    script = (
        f"$p = Start-Process -FilePath '{target}' "
        + (f"-ArgumentList {quoted} " if quoted else "")
        + f"-WorkingDirectory '{runtime.install_dir()}' -Verb RunAs "
        "-WindowStyle Hidden -PassThru -Wait; "
        "if ($p) { exit $p.ExitCode } else { exit 1 }"
    )

    log.info("Launching elevated repair helper")
    code, out = powershell(script, timeout=timeout)

    if not output.exists():
        lowered = (out or "").lower()
        if "canceled" in lowered or "cancelled" in lowered or "operator" in lowered:
            return {"ok": False, "declined": True,
                    "error": "You declined the Windows permission prompt, so nothing "
                             "was changed."}
        return {"ok": False,
                "error": "The elevated helper did not report back. "
                         + (out[:200] if out else "No output was produced.")}

    try:
        report = json.loads(output.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "error": f"The helper's result could not be read: {exc}"}
    finally:
        try:
            output.unlink()
        except OSError:
            pass

    return {"ok": True, "elevated": True, "report": report}


def run_worker(output_path: str) -> int:
    """Entry point for the elevated helper. Writes the repair report and exits."""
    import json

    try:
        report = repair()
    except Exception as exc:
        log.exception("Elevated repair failed")
        report = {
            "steps": [{"name": "repair", "status": "failed",
                       "message": f"The repair failed: {exc}", "detail": "",
                       "changed": False, "duration_ms": 0}],
            "resolved": False, "admin": True, "before": {}, "after": {},
            "summary": f"The repair could not run: {exc}", "changed": False,
        }
    try:
        Path(output_path).write_text(json.dumps(report, default=str), encoding="utf-8")
    except Exception:
        log.exception("Could not write the repair report to %s", output_path)
        return 1
    return 0 if report.get("resolved") else 0


def relaunch_elevated(extra_args: list[str] | None = None) -> dict:
    """Restart wifirecon with a UAC prompt so the admin-only steps can run.

    The desktop application binds no port, so there is nothing for the new
    instance to wait for. This one exits once the elevated copy is up.
    """
    if not IS_WINDOWS:
        return {"ok": False, "error": "Only applies on Windows"}
    if runtime.is_admin():
        return {"ok": False, "error": "Already running as administrator"}

    args = list(extra_args) if extra_args else []
    argv = runtime.relaunch_argv(args)
    target = argv[0]
    # Each argument is quoted separately so PowerShell passes them through intact.
    quoted = ",".join("'" + a.replace("'", "''") + "'" for a in argv[1:])
    script = (
        f"Start-Process -FilePath '{target}' "
        + (f"-ArgumentList {quoted} " if quoted else "")
        + f"-WorkingDirectory '{runtime.install_dir()}' -Verb RunAs"
    )
    code, output = powershell(script, timeout=90)
    if code != 0:
        lowered = (output or "").lower()
        if "canceled" in lowered or "cancelled" in lowered or "operator" in lowered:
            reason = "You declined the Windows permission prompt."
        else:
            reason = f"Windows would not start an elevated copy: {output[:180]}"
        return {"ok": False, "error": reason}
    return {
        "ok": True,
        "message": "An elevated copy is starting. This one will close once it "
                   "is up.",
    }

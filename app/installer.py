"""
Install and uninstall for the packaged build.

Registering under Add/Remove Programs means the app uninstalls the way any other
Windows program does, rather than through a script the person has to go find.
Everything here is per-user (HKCU), so no elevation is needed.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import runtime
from .config import data_dir

log = logging.getLogger(__name__)

APP_NAME = "wifirecon"
DISPLAY_NAME = "wifirecon"
PUBLISHER = "wifirecon"
REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\wifirecon"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK_NAME = "wifirecon"

IS_WINDOWS = sys.platform == "win32"


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise RuntimeError("Install and uninstall are Windows-only operations")


def default_install_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "Programs" / APP_NAME


def start_menu_dir() -> Path:
    return Path(os.environ.get("APPDATA", Path.home())) / (
        r"Microsoft\Windows\Start Menu\Programs"
    )


def desktop_dir() -> Path:
    return Path(os.environ.get("USERPROFILE", Path.home())) / "Desktop"


# ---------------------------------------------------------------------------
# Shortcuts
# ---------------------------------------------------------------------------


def _powershell(script: str, timeout: int = 40) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=runtime.NO_WINDOW,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, output.strip()
    except Exception as exc:
        return False, str(exc)


def create_shortcut(path: Path, target: Path, arguments: str = "",
                    description: str = "") -> bool:
    script = (
        f"$s = New-Object -ComObject WScript.Shell;"
        f"$l = $s.CreateShortcut('{path}');"
        f"$l.TargetPath = '{target}';"
        f"$l.Arguments = '{arguments}';"
        f"$l.WorkingDirectory = '{target.parent}';"
        f"$l.Description = '{description}';"
        f"$l.IconLocation = '{target},0';"
        f"$l.Save()"
    )
    ok, output = _powershell(script)
    if not ok:
        log.warning("Could not create the shortcut at %s: %s", path, output)
    return ok


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def _directory_size_kb(path: Path) -> int:
    total = 0
    try:
        for item in path.rglob("*"):
            if item.is_file():
                total += item.stat().st_size
    except OSError:
        pass
    return max(1, total // 1024)


def register_uninstaller(target: Path, version: str) -> bool:
    """Add the Add/Remove Programs entry."""
    _require_windows()
    import winreg

    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, REGISTRY_KEY, 0,
                                winreg.KEY_WRITE) as key:
            values = {
                "DisplayName": DISPLAY_NAME,
                "DisplayVersion": version,
                "Publisher": PUBLISHER,
                "DisplayIcon": str(target),
                "InstallLocation": str(target.parent),
                "UninstallString": f'"{target}" --uninstall',
                "QuietUninstallString": f'"{target}" --uninstall --quiet',
                "URLInfoAbout": "https://github.com/Seth-Smithey/wifirecon-win",
                "Comments": "Passive wireless reconnaissance for Windows",
            }
            for name, value in values.items():
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD,
                              _directory_size_kb(target.parent))
        return True
    except OSError as exc:
        log.warning("Could not write the uninstall entry: %s", exc)
        return False


def unregister_uninstaller() -> bool:
    if not IS_WINDOWS:
        return False
    import winreg

    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY)
        return True
    except FileNotFoundError:
        return True
    except OSError as exc:
        log.warning("Could not remove the uninstall entry: %s", exc)
        return False


def is_registered() -> bool:
    if not IS_WINDOWS:
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY):
            return True
    except OSError:
        return False


def registered_version() -> str | None:
    if not IS_WINDOWS:
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_KEY) as key:
            return winreg.QueryValueEx(key, "DisplayVersion")[0]
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Autostart
# ---------------------------------------------------------------------------


def enable_autostart(target: Path) -> bool:
    """Prefer a scheduled task (it can restart on failure); fall back to Run."""
    _require_windows()
    script = (
        f"$a = New-ScheduledTaskAction -Execute '{target}' "
        f"-WorkingDirectory '{target.parent}';"
        "$t = New-ScheduledTaskTrigger -AtLogOn;"
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries "
        "-DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 "
        "-RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0;"
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t "
        "-Settings $s -Description 'wifirecon passive wireless survey' -Force | Out-Null"
    )
    ok, output = _powershell(script)
    if ok:
        return True
    log.info("Scheduled task unavailable (%s); using the Run key instead", output[:120])

    import winreg

    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ,
                              f'"{target}"')
        return True
    except OSError as exc:
        log.warning("Could not enable autostart: %s", exc)
        return False


def disable_autostart() -> bool:
    if not IS_WINDOWS:
        return False
    _powershell(
        f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false "
        "-ErrorAction SilentlyContinue"
    )
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_WRITE) as key:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
    except OSError:
        pass
    return True


def autostart_enabled() -> bool:
    if not IS_WINDOWS:
        return False
    ok, output = _powershell(
        f"if (Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue) "
        "{ 'yes' } else { 'no' }"
    )
    if ok and "yes" in output:
        return True
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


def install(
    target_dir: Path | None = None,
    autostart: bool = False,
    desktop_shortcut: bool = False,
    quiet: bool = False,
) -> dict:
    """Copy the executable into place and wire up shortcuts and the registry."""
    _require_windows()
    if not runtime.is_frozen():
        return {"ok": False, "error": "Only the packaged build installs itself. "
                                      "Run build.ps1 first."}

    source = runtime.executable_path()
    target_dir = Path(target_dir) if target_dir else default_install_dir()
    target = target_dir / source.name
    steps: list[str] = []

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"Could not create {target_dir}: {exc}"}

    already_there = source.resolve() == target.resolve()
    if not already_there:
        # If an older copy is running from the target, stop it first.
        stopped = stop_running_instances(exclude_pid=os.getpid())
        if stopped:
            steps.append(f"Stopped {stopped} running instance(s)")
        aside = target.with_name(target.name + runtime.OLD_SUFFIX)
        try:
            if target.exists():
                if aside.exists():
                    try:
                        aside.unlink()
                    except OSError:
                        pass
                os.replace(target, aside)
            payload = source.parent / "_internal"
            if payload.is_dir():
                # A folder build: the exe alone is a stub that cannot start.
                shutil.copytree(source.parent, target.parent, dirs_exist_ok=True)
                steps.append(f"Installed {source.parent.name}\\ to {target.parent}")
            else:
                shutil.copy2(source, target)
                steps.append(f"Installed to {target}")
        except OSError as exc:
            return {"ok": False, "error": f"Could not copy the executable: {exc}"}
    else:
        steps.append(f"Already running from {target}")

    version = runtime.version()

    if create_shortcut(start_menu_dir() / f"{DISPLAY_NAME}.lnk", target,
                       description="Passive wireless recon"):
        steps.append("Start Menu shortcut created")
    if desktop_shortcut and create_shortcut(
        desktop_dir() / f"{DISPLAY_NAME}.lnk", target,
        description="Passive wireless recon"
    ):
        steps.append("Desktop shortcut created")

    if register_uninstaller(target, version):
        steps.append("Listed in Apps & features")

    if autostart and enable_autostart(target):
        steps.append("Set to start at logon")

    data_dir()  # make sure the data directory exists before first run
    return {"ok": True, "target": str(target), "version": version, "steps": steps}


def stop_running_instances(exclude_pid: int | None = None) -> int:
    """Stop other copies of the app so files can be replaced."""
    if not IS_WINDOWS:
        return 0
    exe_name = runtime.executable_path().name
    script = (
        f"Get-Process -Name '{Path(exe_name).stem}' -ErrorAction SilentlyContinue | "
        + (f"Where-Object {{ $_.Id -ne {exclude_pid} }} | " if exclude_pid else "")
        + "ForEach-Object { $_.Id; Stop-Process -Id $_.Id -Force }"
    )
    ok, output = _powershell(script)
    if not ok:
        return 0
    return len([line for line in output.splitlines() if line.strip().isdigit()])


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def uninstall(keep_data: bool = False, quiet: bool = False) -> dict:
    """Remove shortcuts, autostart, the registry entry and optionally the data,
    then schedule the executable itself for deletion."""
    _require_windows()
    steps: list[str] = []

    stopped = stop_running_instances(exclude_pid=os.getpid())
    if stopped:
        steps.append(f"Stopped {stopped} running instance(s)")

    disable_autostart()
    steps.append("Autostart removed")

    for shortcut in (start_menu_dir() / f"{DISPLAY_NAME}.lnk",
                     desktop_dir() / f"{DISPLAY_NAME}.lnk"):
        try:
            if shortcut.exists():
                shortcut.unlink()
                steps.append(f"Removed {shortcut.name}")
        except OSError:
            pass

    if unregister_uninstaller():
        steps.append("Removed from Apps & features")

    to_delete: list[Path] = []
    if not keep_data:
        to_delete.append(data_dir())
        steps.append(f"Data at {data_dir()} queued for removal")
    else:
        steps.append(f"Data kept at {data_dir()}")

    if runtime.is_frozen():
        exe = runtime.executable_path()
        to_delete.append(exe)
        # Only take the whole folder if it is ours and holds nothing else.
        parent = exe.parent
        try:
            leftovers = [p for p in parent.iterdir() if p != exe
                         and not p.name.endswith(runtime.OLD_SUFFIX)]
            if parent.name == APP_NAME and not leftovers:
                to_delete.append(parent)
        except OSError:
            pass
        for stale in parent.glob(f"*{runtime.OLD_SUFFIX}"):
            to_delete.append(stale)

        if runtime.schedule_self_delete(to_delete):
            steps.append("Executable will be removed a moment after this exits")
        else:
            steps.append(f"Delete {exe} by hand; it could not be scheduled")
    elif to_delete:
        for path in to_delete:
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
            except OSError:
                pass

    return {"ok": True, "steps": steps}


def status() -> dict:
    """What the installer knows about the current state."""
    exe = runtime.executable_path()
    target = default_install_dir() / exe.name
    return {
        "frozen": runtime.is_frozen(),
        "executable": str(exe),
        "install_dir": str(runtime.install_dir()),
        "expected_dir": str(default_install_dir()),
        "installed": runtime.is_frozen() and exe.resolve() == target.resolve(),
        "registered": is_registered(),
        "registered_version": registered_version(),
        "autostart": autostart_enabled(),
        "data_dir": str(data_dir()),
        "version": runtime.version(),
    }

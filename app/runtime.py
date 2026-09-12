"""
Frozen-build runtime helpers.

The app runs two ways: from source during development, and as a single
PyInstaller executable in normal use. Everything that differs between those two
lives here so no other module has to care.
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
DETACHED = 0x00000008 | 0x00000200 if IS_WINDOWS else 0   # DETACHED_PROCESS|NEW_GROUP
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def is_frozen() -> bool:
    """True when running from a PyInstaller build."""
    return bool(getattr(sys, "frozen", False))


def resource_dir() -> Path:
    """Where bundled read-only assets live (static files, VERSION)."""
    if is_frozen():
        # onefile unpacks to _MEIPASS; onedir puts assets beside the exe.
        base = getattr(sys, "_MEIPASS", None)
        if base:
            return Path(base)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def install_dir() -> Path:
    """The directory the app is installed in. For a frozen build that is where
    the executable sits, not the temporary unpack directory."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def executable_path() -> Path:
    """The thing to run to start the app again."""
    if is_frozen():
        return Path(sys.executable).resolve()
    return Path(sys.executable).resolve()      # the interpreter


def relaunch_argv(extra: list[str] | None = None) -> list[str]:
    """Command line that starts a fresh instance of this app."""
    extra = extra or []
    if is_frozen():
        return [str(executable_path()), *extra]
    return [sys.executable, "-m", "app", *extra]


def version() -> str:
    for candidate in (resource_dir() / "VERSION", install_dir() / "VERSION"):
        try:
            text = candidate.read_text(encoding="utf-8").strip()
            if text:
                return text
        except OSError:
            continue
    return "0.0.0"


# ---------------------------------------------------------------------------
# Console visibility
# ---------------------------------------------------------------------------


def hide_console() -> bool:
    """Hide our own console window.

    The build is a console executable so that --doctor, --scan-once and the rest
    of the CLI actually print somewhere. When it is launched from the shortcut
    with no arguments there is nothing to read, so the window gets hidden rather
    than left sitting on the taskbar.
    """
    if not IS_WINDOWS:
        return False
    try:
        window = ctypes.windll.kernel32.GetConsoleWindow()
        if not window:
            return False
        # Only hide a console we own. If the user started us from an existing
        # prompt, hiding it would take their shell away with us.
        pid = ctypes.c_ulong()
        ctypes.windll.user32.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if pid.value != os.getpid():
            return False
        ctypes.windll.user32.ShowWindow(window, 0)  # SW_HIDE
        return True
    except Exception:
        return False


def is_admin() -> bool:
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Self-replacement
# ---------------------------------------------------------------------------

OLD_SUFFIX = ".old"


def sweep_old_binaries() -> int:
    """Delete the leftovers from a previous update. Called on every start."""
    removed = 0
    try:
        for stale in install_dir().glob(f"*{OLD_SUFFIX}"):
            try:
                stale.unlink()
                removed += 1
                log.info("Cleaned up %s from a previous update", stale.name)
            except OSError:
                # Still locked; the next start will get it.
                pass
    except OSError:
        pass
    return removed


def replace_self(new_binary: Path) -> tuple[bool, str]:
    """Swap the running executable for a downloaded one.

    Windows will not let you overwrite a running image, but it will let you
    rename it. So the current exe is renamed aside, the new one takes its place,
    and the stale copy is removed on the next start.
    """
    if not is_frozen():
        return False, "Self-replacement only applies to the packaged build"
    if not new_binary.exists():
        return False, f"{new_binary} is missing"

    current = executable_path()
    aside = current.with_name(current.name + OLD_SUFFIX)

    try:
        if aside.exists():
            try:
                aside.unlink()
            except OSError:
                aside = current.with_name(f"{current.name}.{int(time.time())}{OLD_SUFFIX}")
        os.replace(current, aside)
    except OSError as exc:
        return False, f"Could not move the current version aside: {exc}"

    try:
        shutil.copy2(new_binary, current)
    except OSError as exc:
        # Put things back the way they were rather than leaving no executable.
        try:
            os.replace(aside, current)
        except OSError:
            return False, (
                f"Update failed and the original could not be restored: {exc}. "
                f"Rename {aside.name} back to {current.name} by hand."
            )
        return False, f"Could not install the new version: {exc}"

    return True, "Installed"


def spawn_detached(argv: list[str], cwd: Path | None = None) -> bool:
    """Start a process that outlives this one."""
    try:
        subprocess.Popen(
            argv,
            cwd=str(cwd or install_dir()),
            creationflags=DETACHED if IS_WINDOWS else 0,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=not IS_WINDOWS,
        )
        return True
    except Exception:
        log.exception("Could not start %s", argv[0] if argv else "?")
        return False


def schedule_self_delete(paths: list[Path], delay_seconds: int = 3) -> bool:
    """Queue deletion of files we are currently holding open, including our own
    executable. A detached cmd waits for this process to exit, then removes them."""
    if not IS_WINDOWS:
        return False
    targets = [p for p in paths if p]
    if not targets:
        return False
    # ping is the portable "sleep" that exists on every Windows install.
    parts = [f"ping -n {max(2, delay_seconds)} 127.0.0.1 >nul"]
    for path in targets:
        if path.is_dir():
            parts.append(f'rmdir /s /q "{path}"')
        else:
            parts.append(f'del /f /q "{path}"')
    command = " & ".join(parts)
    try:
        subprocess.Popen(
            ["cmd", "/c", command],
            creationflags=DETACHED | NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        return True
    except Exception:
        log.exception("Could not schedule cleanup")
        return False

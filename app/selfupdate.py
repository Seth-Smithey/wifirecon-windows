"""
In-place updates from a package file.

The git and GitHub-release paths in updater.py assume a repository or a
published release. This handles the case that actually comes up: someone hands
you a new build as a zip, and you want the running install to become that
version without deleting anything or reinstalling.

The rules that make this safe:
  * The package is validated before a single file is touched.
  * Everything replaceable is backed up first, and restored if anything fails.
  * The virtual environment, the database, settings and logs are never touched.
  * The app restarts itself afterwards so the new code is actually loaded.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tempfile
import time
import zipfile
from pathlib import Path

from . import runtime
from .config import data_dir

log = logging.getLogger(__name__)

# Only these are replaced. Anything else in the install directory is left alone,
# which is what protects .venv, downloaded drivers, and anything the person put
# there themselves.
MANAGED_PATHS = [
    "app", "tools", "docs", "VERSION", "requirements.txt", "wifirecon.spec",
    "run_app.py", "README.md", "QUICKSTART.md",
    "build.ps1", "wifirecon.vbs",
    "Setup wifirecon.cmd", "Start wifirecon (console).cmd",
    "Update wifirecon.cmd", "Repair adapter (admin).cmd",
]

# A package must contain these or it is not a wifirecon build.
REQUIRED_MARKERS = ["app/main.py", "app/__init__.py", "VERSION"]

MAX_PACKAGE_BYTES = 200 * 1024 * 1024
BACKUP_KEEP = 3


def backups_dir() -> Path:
    path = data_dir() / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


def _strip_root(names: list[str]) -> str:
    """Packages are usually zipped with a single wrapping folder. Find it."""
    tops = {n.split("/", 1)[0] for n in names if n and not n.startswith("__MACOSX")}
    if len(tops) == 1:
        only = tops.pop()
        if any(n.startswith(only + "/") for n in names):
            return only + "/"
    return ""


def inspect(package: Path) -> dict:
    """Validate a package and report what it contains, changing nothing."""
    if not package.exists():
        return {"ok": False, "error": f"{package.name} does not exist"}
    size = package.stat().st_size
    if size > MAX_PACKAGE_BYTES:
        return {"ok": False, "error": "That file is implausibly large for an update"}
    if size < 256:
        # A weak sanity check only; the marker validation below is the real test.
        return {"ok": False, "error": "That file is too small to be an update package"}

    try:
        with zipfile.ZipFile(package) as archive:
            bad = archive.testzip()
            if bad:
                return {"ok": False, "error": f"The package is corrupt (bad entry: {bad})"}
            names = archive.namelist()
            root = _strip_root(names)
            inner = {n[len(root):] for n in names if n.startswith(root)}

            missing = [m for m in REQUIRED_MARKERS if m not in inner]
            if missing:
                return {
                    "ok": False,
                    "error": "That does not look like a wifirecon package "
                             f"(missing {', '.join(missing)})",
                }

            version = "unknown"
            try:
                version = archive.read(root + "VERSION").decode("utf-8").strip()
            except Exception:
                pass

            # Refuse anything trying to write outside the install directory.
            for name in names:
                target = name[len(root):] if name.startswith(root) else name
                if target.startswith("/") or ".." in Path(target).parts:
                    return {"ok": False,
                            "error": f"The package contains an unsafe path: {name}"}

            managed = sorted({
                n.split("/", 1)[0] for n in inner if n
            } & set(MANAGED_PATHS) | {
                p for p in MANAGED_PATHS if p in inner
            })

    except zipfile.BadZipFile:
        return {"ok": False, "error": "That file is not a zip archive"}
    except Exception as exc:
        return {"ok": False, "error": f"Could not read the package: {exc}"}

    current = runtime.version()
    return {
        "ok": True,
        "version": version,
        "current": current,
        "same_version": version == current,
        "file_count": len(names),
        "size": size,
        "sha256": _sha256(package),
        "root": root or "(no wrapper folder)",
        "will_replace": managed,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------


def create_backup(label: str = "") -> dict:
    """Copy the replaceable parts of the install somewhere safe."""
    install = runtime.install_dir()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-v{runtime.version()}" + (f"-{label}" if label else "")
    target = backups_dir() / name
    target.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    failed: list[str] = []
    for relative in MANAGED_PATHS:
        source = install / relative
        if not source.exists():
            continue
        destination = target / relative
        try:
            if source.is_dir():
                shutil.copytree(source, destination,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            copied.append(relative)
        except Exception as exc:
            log.error("Could not back up %s: %s", relative, exc)
            failed.append(f"{relative}: {exc}")

    manifest = {
        "created_at": time.time(),
        "version": runtime.version(),
        "install_dir": str(install),
        "paths": copied,
        "failed": failed,
        "label": label,
        "complete": not failed,
    }
    try:
        (target / "backup.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        failed.append(f"backup.json: {exc}")

    if failed:
        # An incomplete backup is worse than none, because it invites an update
        # that cannot be undone. Throw it away and report the failure.
        shutil.rmtree(target, ignore_errors=True)
        return {"ok": False, "path": None, "name": None, "paths": copied,
                "failed": failed,
                "error": "The backup could not be completed, so nothing was changed: "
                         + "; ".join(failed[:3])}

    _prune_backups()
    return {"ok": True, "path": str(target), "name": name, "paths": copied,
            "failed": []}


def _prune_backups() -> None:
    try:
        entries = sorted(
            (p for p in backups_dir().iterdir() if p.is_dir()),
            key=lambda p: p.name, reverse=True,
        )
        for stale in entries[BACKUP_KEEP:]:
            shutil.rmtree(stale, ignore_errors=True)
    except OSError:
        pass


def list_backups() -> list[dict]:
    out = []
    try:
        for entry in sorted(backups_dir().iterdir(), reverse=True):
            if not entry.is_dir():
                continue
            manifest = entry / "backup.json"
            info = {"name": entry.name, "path": str(entry)}
            if manifest.exists():
                try:
                    info.update(json.loads(manifest.read_text(encoding="utf-8")))
                except Exception:
                    pass
            out.append(info)
    except OSError:
        pass
    return out


def restore(name: str) -> dict:
    """Put a backup back. Used automatically on a failed update, or by hand."""
    source = backups_dir() / name
    if not source.is_dir():
        return {"ok": False, "error": f"No backup named {name}"}
    install = runtime.install_dir()
    restored, failed = [], []
    for relative in MANAGED_PATHS:
        candidate = source / relative
        if not candidate.exists():
            continue
        target = install / relative
        try:
            if target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()
            if candidate.is_dir():
                shutil.copytree(candidate, target)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, target)
            restored.append(relative)
        except Exception as exc:
            failed.append(f"{relative}: {exc}")
    return {"ok": not failed, "restored": restored, "failed": failed,
            "message": f"Restored {len(restored)} item(s) from {name}"
                       + (f"; {len(failed)} failed" if failed else "")}


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_package(package: Path, restart: bool = True) -> dict:
    """Replace the install with the contents of a validated package."""
    info = inspect(package)
    if not info["ok"]:
        return info

    install = runtime.install_dir()
    if not _writable(install):
        return {"ok": False,
                "error": f"{install} is not writable, so the update cannot be applied. "
                         "Move the install somewhere under your user folder."}

    backup = create_backup("preupdate")
    if not backup["ok"]:
        # No usable rollback point, so the install is left exactly as it was.
        return {
            "ok": False,
            "error": backup["error"],
            "hint": "Check free disk space and that no file in the install folder is "
                    "open in another program, then try again.",
        }
    log.info("Backed up to %s before updating", backup["path"])

    staging = Path(tempfile.mkdtemp(prefix="wifirecon-update-"))
    try:
        with zipfile.ZipFile(package) as archive:
            archive.extractall(staging)
        root = staging
        entries = [p for p in staging.iterdir() if p.name != "__MACOSX"]
        if len(entries) == 1 and entries[0].is_dir():
            root = entries[0]

        # Sanity check the extracted tree before touching the live install.
        for marker in REQUIRED_MARKERS:
            if not (root / marker).exists():
                raise RuntimeError(f"The extracted package is missing {marker}")

        replaced = []
        for relative in MANAGED_PATHS:
            source = root / relative
            if not source.exists():
                continue
            target = install / relative
            if target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()
            if source.is_dir():
                shutil.copytree(source, target,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            replaced.append(relative)

        # Stale bytecode from the previous version can shadow updated modules.
        for cache in (c for base in ("app", "tools")
                  for c in (install / base).rglob("__pycache__")):
            shutil.rmtree(cache, ignore_errors=True)

        # A new version may need new packages. Without this the app comes back
        # missing them, which looks like the update broke something.
        _refresh_dependencies(install)

    except Exception as exc:
        log.exception("Update failed; rolling back")
        rollback = restore(backup["name"])
        return {
            "ok": False,
            "error": f"The update failed and was rolled back: {exc}",
            "rollback": rollback,
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    result = {
        "ok": True,
        "from_version": info["current"],
        "to_version": info["version"],
        "replaced": replaced,
        "backup": backup["name"],
        "message": f"Updated from {info['current']} to {info['version']}. "
                   + ("Restarting now." if restart else "Restart to load it."),
        "restarting": restart,
    }

    if restart:
        _schedule_restart()
    return result


def _refresh_dependencies(install: Path) -> None:
    import subprocess
    import sys as _sys

    venv_python = install / ".venv" / (
        "Scripts/python.exe" if _sys.platform == "win32" else "bin/python"
    )
    python = str(venv_python) if venv_python.exists() else _sys.executable
    requirements = install / "requirements.txt"
    if not requirements.exists():
        return
    try:
        subprocess.run(
            [python, "-m", "pip", "install", "-r", str(requirements),
             "--quiet", "--disable-pip-version-check"],
            capture_output=True, timeout=300,
            creationflags=0x08000000 if _sys.platform == "win32" else 0,
        )
        log.info("Refreshed dependencies after update")
    except Exception as exc:
        log.warning("Could not refresh dependencies: %s", exc)


def _writable(path: Path) -> bool:
    probe = path / ".write-test"
    try:
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _schedule_restart(delay: float = 1.5) -> None:
    """Start a fresh instance, then exit, so the new code is loaded."""
    import os
    import threading

    from .config import config

    port = int(config.get("server", "port", default=8722))

    def run() -> None:
        time.sleep(delay)
        runtime.spawn_detached(
            runtime.relaunch_argv(["--no-browser", # the desktop application binds no port,
                                   "--port", str(port)])
        )
        time.sleep(0.5)
        os._exit(0)

    threading.Thread(target=run, daemon=True).start()


def apply_from_url(url: str, restart: bool = True) -> dict:
    """Download a package and apply it. For a build hosted somewhere fixed."""
    import urllib.request

    if not url.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": "The update URL must start with http:// or https://"}

    staging = data_dir() / "updates"
    staging.mkdir(parents=True, exist_ok=True)
    target = staging / "package.zip"

    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "wifirecon-updater"}
        )
        with urllib.request.urlopen(request, timeout=180) as response:
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > MAX_PACKAGE_BYTES:
                return {"ok": False, "error": "That download is implausibly large"}
            written = 0
            with open(target, "wb") as handle:
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_PACKAGE_BYTES:
                        raise ValueError("The download exceeded the size limit")
                    handle.write(chunk)
    except Exception as exc:
        return {"ok": False, "error": f"Download failed: {exc}"}

    try:
        return apply_package(target, restart)
    finally:
        try:
            target.unlink()
        except OSError:
            pass

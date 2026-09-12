"""
Updates.

Two modes, picked automatically:

* **Packaged build** - asks the GitHub Releases API what the newest version is,
  downloads the executable, verifies its SHA-256 against the release's checksum
  asset, swaps it in and restarts. This is the normal path.
* **Source checkout** - git fetch and fast-forward, for development.

Version comparison is semantic, so a release tagged v1.10.0 correctly beats
v1.9.0 rather than losing a string comparison.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import runtime
from .config import data_dir

log = logging.getLogger(__name__)

REPO = "Seth-Smithey/wifirecon-windows"
API_ROOT = f"https://api.github.com/repos/{REPO}"
USER_AGENT = "wifirecon-win-updater"
DOWNLOAD_TIMEOUT = 300
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024

_state: dict = {
    "checked_at": 0.0,
    "mode": "unknown",
    "current": None,
    "latest": None,
    "available": False,
    "changelog": [],
    "error": None,
    "applying": False,
    "progress": None,
    "asset": None,
}
_lock = threading.RLock()


def version() -> str:
    return runtime.version()


def mode() -> str:
    if runtime.is_frozen():
        return "release"
    return "git" if is_git_checkout() else "source"


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------


def parse_version(text: str) -> tuple:
    """Turn '1.10.2' or 'v1.10.2-beta.1' into something sortable."""
    if not text:
        return (-1, 0, 0, 1, "")
    cleaned = str(text).strip().lstrip("vV")
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+](.*))?$", cleaned)
    if not match:
        return (0, 0, 0, 1, cleaned)
    major, minor, patch, pre = match.groups()
    # Semver: a final release outranks any pre-release of the same number, so
    # the flag has to sort HIGHER when there is no pre-release tag.
    return (int(major), int(minor or 0), int(patch or 0), 0 if pre else 1, pre or "")


def is_newer(candidate: str, current: str) -> bool:
    return parse_version(candidate) > parse_version(current)


# ---------------------------------------------------------------------------
# Git mode
# ---------------------------------------------------------------------------


def _git(*args: str, timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=str(runtime.install_dir()), capture_output=True,
            text=True, timeout=timeout, creationflags=runtime.NO_WINDOW,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "git is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "git timed out"


def is_git_checkout() -> bool:
    return (runtime.install_dir() / ".git").exists()


def has_local_changes() -> bool:
    code, out, _ = _git("status", "--porcelain", "--untracked-files=no")
    return code == 0 and bool(out)


def _check_git(channel: str) -> dict:
    result = {
        "mode": "git", "current": version(), "latest": None, "available": False,
        "changelog": [], "error": None, "behind": 0, "asset": None,
        "local_changes": has_local_changes(),
    }
    code, _, err = _git("fetch", "--quiet", "origin", channel, timeout=90)
    if code != 0:
        result["error"] = f"Could not reach the update server: {err or 'unknown error'}"
        return result
    code, out, _ = _git("rev-list", "--count", f"HEAD..origin/{channel}")
    result["behind"] = int(out) if code == 0 and out.isdigit() else 0
    result["available"] = result["behind"] > 0
    code, out, _ = _git("rev-parse", "--short", f"origin/{channel}")
    if code == 0:
        result["latest"] = out
    if result["behind"]:
        code, out, _ = _git("log", "--no-merges", "--pretty=format:%h\t%s",
                            f"HEAD..origin/{channel}")
        if code == 0 and out:
            result["changelog"] = [
                {"commit": line.split("\t", 1)[0], "subject": line.split("\t", 1)[-1]}
                for line in out.splitlines()[:40]
            ]
    return result


# ---------------------------------------------------------------------------
# Release mode
# ---------------------------------------------------------------------------


def _http_json(url: str, timeout: int = 30) -> dict:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _pick_asset(assets: list) -> dict | None:
    """Prefer an exe matching our own filename, then any exe, then a zip."""
    wanted = runtime.executable_path().name.lower()
    exes = [a for a in assets if str(a.get("name", "")).lower().endswith(".exe")]
    for asset in exes:
        if asset["name"].lower() == wanted:
            return asset
    if exes:
        return exes[0]
    zips = [a for a in assets if str(a.get("name", "")).lower().endswith(".zip")]
    return zips[0] if zips else None


def _find_checksums(assets: list) -> dict | None:
    for asset in assets:
        name = str(asset.get("name", "")).lower()
        if "sha256" in name or name in ("checksums.txt", "sha256sums.txt"):
            return asset
    return None


def _check_release() -> dict:
    result = {
        "mode": "release", "current": version(), "latest": None, "available": False,
        "changelog": [], "error": None, "asset": None, "published_at": None,
    }
    try:
        release = _http_json(f"{API_ROOT}/releases/latest")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result["error"] = "No releases have been published yet."
        elif exc.code == 403:
            result["error"] = ("GitHub is rate limiting update checks. "
                               "It will work again shortly.")
        else:
            result["error"] = f"Update server returned HTTP {exc.code}"
        return result
    except Exception as exc:
        result["error"] = f"Could not reach the update server: {exc}"
        return result

    tag = release.get("tag_name") or release.get("name") or ""
    result["latest"] = str(tag).lstrip("vV")
    result["published_at"] = release.get("published_at")
    result["available"] = is_newer(tag, version())

    body = (release.get("body") or "").strip()
    if body:
        result["changelog"] = [
            {"commit": "", "subject": line.lstrip("-*# ").strip()}
            for line in body.splitlines() if line.strip()
        ][:40]

    assets = release.get("assets") or []
    asset = _pick_asset(assets)
    if asset:
        result["asset"] = {
            "name": asset["name"],
            "url": asset["browser_download_url"],
            "size": asset.get("size"),
        }
        checksums = _find_checksums(assets)
        if checksums:
            result["asset"]["checksums_url"] = checksums["browser_download_url"]
    elif result["available"]:
        result["error"] = ("A new version exists but the release has no executable "
                           "attached. Download it manually from GitHub.")
        result["available"] = False
    return result


def _download(url: str, destination: Path, expected_size: int | None = None) -> Path:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    written = 0

    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
        declared = response.headers.get("Content-Length")
        total = int(declared) if declared and str(declared).isdigit() else expected_size
        if total and total > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"The download is {total} bytes, which is implausibly large")
        with open(temporary, "wb") as handle:
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise ValueError("The download exceeded the size limit")
                handle.write(chunk)
                if total:
                    with _lock:
                        _state["progress"] = round(written / total * 100, 1)

    if written == 0:
        temporary.unlink(missing_ok=True)
        raise ValueError("The download was empty")
    temporary.replace(destination)
    with _lock:
        _state["progress"] = 100.0
    return destination


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify(binary: Path, checksums_url: str | None, asset_name: str):
    """Check the download against the release's published checksum."""
    actual = _sha256(binary)
    if not checksums_url:
        return True, (f"No checksum file was published, so the download could not be "
                      f"verified. SHA-256 is {actual}")
    try:
        request = urllib.request.Request(checksums_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read(1024 * 512).decode("utf-8", "replace")
    except Exception as exc:
        return True, f"Could not fetch the checksum file ({exc}). SHA-256 is {actual}"

    expected = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*").lower() == asset_name.lower():
            expected = parts[0].lower()
            break
    if expected is None:
        # Only fall back to a bare hash when the file holds exactly one. Picking
        # the first of several would compare against some other asset and report
        # a mismatch that is really a lookup failure.
        hashes = [
            parts[0].strip().lower()
            for parts in (line.split() for line in text.splitlines())
            if parts and len(parts[0].strip()) == 64
        ]
        if len(hashes) == 1:
            expected = hashes[0]
    if expected is None:
        return True, (f"The checksum file has no entry for {asset_name}, so the "
                      f"download could not be verified. SHA-256 is {actual}")
    if expected != actual:
        return False, (f"Checksum mismatch. Expected {expected}, got {actual}. "
                       "The download was discarded.")
    return True, "Checksum verified"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def check(channel: str = "main", force: bool = False) -> dict:
    with _lock:
        if not force and time.time() - _state["checked_at"] < 60:
            return dict(_state)

    if runtime.is_frozen():
        result = _check_release()
    elif is_git_checkout():
        result = _check_git(channel)
    else:
        result = {
            "mode": "source", "current": version(), "latest": None, "available": False,
            "changelog": [], "asset": None,
            "error": "This copy was not installed with git and is not a packaged "
                     "build, so it cannot update itself.",
        }
    result["checked_at"] = time.time()
    with _lock:
        applying = _state["applying"]
        _state.update(result)
        _state["applying"] = applying
        _state.setdefault("progress", None)
        return dict(_state)


def apply(channel: str = "main", restart: bool = True) -> dict:
    with _lock:
        if _state["applying"]:
            return {"ok": False, "error": "An update is already running"}
        _state["applying"] = True
        _state["progress"] = 0.0

    try:
        if runtime.is_frozen():
            return _apply_release(restart)
        return _apply_git(channel)
    except Exception as exc:
        log.exception("Update failed")
        return {"ok": False, "error": str(exc)}
    finally:
        with _lock:
            _state["applying"] = False


def _apply_release(restart: bool) -> dict:
    info = check(force=True)
    if info.get("error") and not info.get("available"):
        return {"ok": False, "error": info["error"]}
    if not info.get("available"):
        return {"ok": False, "error": f"Version {version()} is already current"}
    asset = info.get("asset")
    if not asset:
        return {"ok": False, "error": "The release has no executable attached"}

    staging = data_dir() / "updates"
    staging.mkdir(parents=True, exist_ok=True)
    target = staging / asset["name"]

    log.info("Downloading %s", asset["url"])
    try:
        _download(asset["url"], target, asset.get("size"))
    except Exception as exc:
        return {"ok": False, "error": f"Download failed: {exc}"}

    ok, message = _verify(target, asset.get("checksums_url"), asset["name"])
    if not ok:
        target.unlink(missing_ok=True)
        return {"ok": False, "error": message}
    log.info("Update verification: %s", message)

    if target.suffix.lower() != ".exe":
        return {
            "ok": False,
            "error": f"Downloaded {target.name} to {staging}, but only .exe assets "
                     "can be installed automatically. Unpack it by hand.",
        }

    swapped, detail = runtime.replace_self(target)
    if not swapped:
        return {"ok": False, "error": detail}

    log.info("Updated from %s to %s", version(), info["latest"])
    try:
        target.unlink()
    except OSError:
        pass

    if restart:
        runtime.spawn_detached(runtime.relaunch_argv(["--no-browser"]))
        threading.Timer(1.5, _exit_now).start()
        return {
            "ok": True,
            "message": f"Updated to {info['latest']}. Restarting now.",
            "restarting": True,
            "verification": message,
        }
    return {
        "ok": True,
        "message": f"Updated to {info['latest']}. Restart to load it.",
        "restarting": False,
        "verification": message,
    }


def _exit_now() -> None:  # pragma: no cover - process teardown
    os._exit(0)


def _apply_git(channel: str) -> dict:
    if not is_git_checkout():
        return {"ok": False, "error": "Not a git checkout"}
    if has_local_changes():
        return {"ok": False,
                "error": "There are uncommitted local changes. Commit or stash them first."}
    code, out, err = _git("merge", "--ff-only", f"origin/{channel}", timeout=120)
    if code != 0:
        return {"ok": False, "error": err or out or "Fast-forward merge failed"}
    return {"ok": True, "message": "Updated. Restart to load the new version.",
            "output": out, "restarting": False}


def state() -> dict:
    with _lock:
        return dict(_state)


class UpdateChecker:
    """Background poller so the interface can show a badge without blocking."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self, channel: str, interval_hours: float) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def run() -> None:
            interval = max(interval_hours, 0.25) * 3600
            if self._stop.wait(20):
                return
            while not self._stop.is_set():
                try:
                    check(channel, force=True)
                except Exception:
                    log.exception("Update check failed")
                if self._stop.wait(interval):
                    return

        self._thread = threading.Thread(target=run, name="update-checker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3)
        self._thread = None


checker = UpdateChecker()

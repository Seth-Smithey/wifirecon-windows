"""
wifirecon-win entry point.

    python -m app                open the desktop application
    python -m app --server       run the web server for remote access
    python -m app --doctor       print diagnostics and exit
    python -m app --scan-once    run one scan, print the result, exit
    python -m app --mock         force the synthetic source
"""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import adapter_probe, alerts, db, doctor, gps, installer, recovery, runtime, scanner, selfupdate, updater, window
from .config import config, data_dir, log_path
from .services import lifecycle

log = logging.getLogger("wifirecon")

def setup_logging() -> None:
    level = getattr(logging, str(config.get("logging", "level", default="INFO")).upper(),
                    logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)-22s %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_path(),
            maxBytes=int(config.get("logging", "max_bytes", default=5_000_000)),
            backupCount=int(config.get("logging", "backup_count", default=5)),
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:
        print(f"Could not open the log file: {exc}", file=sys.stderr)

    # Under pythonw there is no stdout and no stderr, and a StreamHandler
    # bound to None raises on every record for the life of the process.
    if sys.stdout is not None:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        root.addHandler(console)

    # Uvicorn's access log is noisy for a polling UI.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _port_in_use(host: str, port: int) -> bool:
    target = "127.0.0.1" if host == "0.0.0.0" else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.6)
        return sock.connect_ex((target, port)) == 0


def _wait_for_port(host: str, port: int, seconds: float) -> bool:
    """Wait for a previous instance to let go of the port.

    A relaunch - after an update, or when elevating - starts the new process
    before the old one has finished closing its socket. Without this the new
    instance dies on startup and the person sees nothing come back.
    """
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not _port_in_use(host, port):
            return True
        time.sleep(0.5)
    return not _port_in_use(host, port)


def _run_desktop(keep_console: bool = False) -> int:
    """Start the desktop application and block until its window closes."""
    ok, reason = window.available()
    if not ok:
        print(reason, file=sys.stderr)
        print(
            "\nThe web interface still works in the meantime:\n"
            "    python -m app --server\n",
            file=sys.stderr,
        )
        return 3

    log.info("wifirecon-win %s starting", updater.version())
    log.info("Data directory: %s", data_dir())

    # A window is its own console, so the one a shortcut opened goes away.
    # It is hidden only once the interface is up: hiding it first means a Qt
    # startup failure prints into a console that is already gone, which is
    # exactly the "it starts and no window appears" case nobody can report.
    hide = runtime.is_frozen() and not keep_console
    return window.run(hide_console_when_ready=hide)


def _open_browser_later(url: str) -> None:
    def run() -> None:
        time.sleep(1.5)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=run, daemon=True).start()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wifirecon", description="Passive wireless recon for Windows"
    )
    parser.add_argument("--doctor", action="store_true", help="run diagnostics and exit")
    parser.add_argument("--scan-once", action="store_true", help="run a single scan and exit")
    parser.add_argument("--mock", action="store_true", help="use synthetic data")
    parser.add_argument("--host", help="override the bind address")
    parser.add_argument("--port", type=int, help="override the port")
    parser.add_argument("--no-browser", action="store_true",
                        help="with --server, do not open a browser")
    # --window is the default and kept only so old shortcuts keep working.
    parser.add_argument("--window", action="store_true",
                        help="open the desktop application (the default)")
    parser.add_argument("--server", action="store_true",
                        help="run the web server instead, so other machines can "
                             "reach this survey")
    parser.add_argument("--browser", action="store_true",
                        help="with --server, open the web interface in a browser")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    parser.add_argument("--install", action="store_true",
                        help="install to the user program folder and register the uninstaller")
    parser.add_argument("--uninstall", action="store_true",
                        help="remove shortcuts, autostart, registry entry and data")
    parser.add_argument("--update", action="store_true",
                        help="check for an update, install it, and exit")
    parser.add_argument("--keep-data", action="store_true",
                        help="with --uninstall, leave the database and settings in place")
    parser.add_argument("--autostart", action="store_true",
                        help="with --install, also start at logon")
    parser.add_argument("--desktop-shortcut", action="store_true",
                        help="with --install, also put a shortcut on the desktop")
    parser.add_argument("--install-dir", help="with --install, where to put the executable")
    parser.add_argument("--quiet", action="store_true", help="suppress prompts")
    parser.add_argument("--console", action="store_true",
                        help="keep the console window visible")
    parser.add_argument("--wait-for-port", type=float, default=0, metavar="SECONDS",
                        help="wait this long for a previous instance to release the port")
    parser.add_argument("--repair-worker", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--repair-output", metavar="PATH", help=argparse.SUPPRESS)
    parser.add_argument("--probe-adapters", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe-output", metavar="PATH", help=argparse.SUPPRESS)
    parser.add_argument("--update-from", metavar="ZIP",
                        help="update this install from a wifirecon package file")
    parser.add_argument("--rollback", metavar="NAME",
                        help="restore a previous version by backup name")
    parser.add_argument("--list-backups", action="store_true",
                        help="list the versions that can be rolled back to")
    parser.add_argument("--status", action="store_true",
                        help="print install status as JSON and exit")
    parser.add_argument("--fix-adapter", action="store_true",
                        help="diagnose and repair a wireless adapter that is not "
                             "coming online, then exit")
    parser.add_argument("--check-adapter", action="store_true",
                        help="report why an adapter is unavailable, changing nothing")
    args = parser.parse_args(argv)

    if args.version:
        print(updater.version())
        return 0

    if args.mock:
        os.environ["WIFIRECON_MOCK"] = "1"

    setup_logging()

    # The adapter probe child does one job and exits. It runs the native calls
    # inline, because isolating them is the parent's job, not its own.
    if args.probe_adapters:
        if not args.probe_output:
            print("--probe-adapters needs --probe-output", file=sys.stderr)
            return 2
        os.environ["WIFIRECON_PROBE_INLINE"] = "1"
        return adapter_probe.run_child(args.probe_output)

    # The elevated helper does one job and exits, so it skips the usual bootstrap.
    if args.repair_worker:
        if not args.repair_output:
            print("--repair-worker needs --repair-output", file=sys.stderr)
            return 2
        return recovery.run_worker(args.repair_output)

    lifecycle.bootstrap()

    if args.status:
        import json as _json

        print(_json.dumps(installer.status(), indent=2))
        return 0

    if args.install:
        return _do_install(args)

    if args.uninstall:
        return _do_uninstall(args)

    if args.update:
        return _do_update()

    if args.list_backups:
        backups = selfupdate.list_backups()
        if not backups:
            print("No backups yet. One is made automatically before each update.")
            return 0
        print("\nAvailable versions to roll back to:\n")
        for entry in backups:
            print(f"  {entry['name']}")
            if entry.get("version"):
                print(f"      version {entry['version']}, "
                      f"{len(entry.get('paths', []))} item(s)")
        print()
        return 0

    if args.rollback:
        result = selfupdate.restore(args.rollback)
        print(result.get("message") or result.get("error"))
        if result.get("failed"):
            for failure in result["failed"]:
                print(f"  {failure}")
        return 0 if result["ok"] else 1

    if args.update_from:
        package = Path(args.update_from)
        info = selfupdate.inspect(package)
        if not info["ok"]:
            print(f"That package cannot be used: {info['error']}", file=sys.stderr)
            return 1
        print(f"\n  Package version : {info['version']}")
        print(f"  Installed now   : {info['current']}")
        print(f"  Replaces        : {', '.join(info['will_replace'])}")
        print(f"  SHA-256         : {info['sha256'][:32]}...\n")
        result = selfupdate.apply_package(package, restart=False)
        if not result.get("ok"):
            print(f"  Update failed: {result.get('error')}", file=sys.stderr)
            if result.get("hint"):
                print(f"  {result['hint']}", file=sys.stderr)
            return 1
        print(f"  {result['message']}")
        print(f"  Previous version backed up as {result['backup']}")
        print("  Roll back with: --rollback " + result["backup"] + "\n")
        return 0

    if args.check_adapter:
        return _print_adapter_check(dry_run=True)

    if args.fix_adapter:
        return _print_adapter_check(dry_run=False)

    if args.doctor:
        return doctor.print_report()

    if args.scan_once:
        scanner.engine.source = scanner.build_source()
        try:
            adapter = scanner.engine.select_interface()
            if adapter:
                print(f"Using {adapter.get('label') or adapter.get('description')}"
                      f"{' - ' + adapter['band_label'] if adapter.get('band_label') else ''}")
            result = scanner.engine.run_once()
            print(
                f"Scanned {result['count']} networks "
                f"({result['new']} new, {result['findings']} findings) "
                f"in {result['duration_ms']} ms"
            )
            return 0
        except Exception as exc:
            print(f"Scan failed: {exc}", file=sys.stderr)
            return 1
        finally:
            alerts.dispatcher.stop()

    # The desktop application is the product. It calls the service layer in
    # this process, so there is no port to bind and no browser to hand off to.
    # The server is for reaching a running survey from another machine.
    if not args.server:
        return _run_desktop(keep_console=args.console)

    host = args.host or config.get("server", "host", default="127.0.0.1")
    if config.get("server", "allow_lan", default=False) and not args.host:
        host = "0.0.0.0"
        config.ensure_token()
    port = args.port or int(config.get("server", "port", default=8722))

    if _port_in_use(host, port):
        wait = float(args.wait_for_port or 0)
        if wait > 0:
            print(f"Port {port} is busy; waiting up to {wait:.0f}s for it to free up...")
            if not _wait_for_port(host, port, wait):
                print(
                    f"Port {port} is still in use after {wait:.0f}s. Close the other "
                    f"instance, or start this one with --port on a different number.",
                    file=sys.stderr,
                )
                return 2
        else:
            print(
                f"Port {port} is already in use. Either wifirecon is already running "
                f"(open http://127.0.0.1:{port}) or something else has the port. "
                f"Change it with --port.",
                file=sys.stderr,
            )
            return 2

    url = f"http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}"

    if args.browser or (config.get("server", "open_browser", default=True)
                        and not args.no_browser):
        _open_browser_later(url)

    print(f"wifirecon-win {updater.version()} - {url}")
    if not config.get("scan", "autostart_on_launch", default=False):
        print("Idle until you press Start scanning in the interface.")
    # Launched from a shortcut there is nothing to read in the console, so it
    # gets hidden. --console keeps it, and a console we did not create is left
    # alone so we never close someone's shell.
    if runtime.is_frozen() and not args.console:
        if runtime.hide_console():
            log.info("Console hidden; the interface is at %s", url)
    if host == "0.0.0.0":
        token = config.get("server", "api_token", default="")
        print(f"Listening on all interfaces. API token: {token}")

    import uvicorn

    from .server import create_app

    uvicorn.run(
        create_app(),
        host=host,
        port=port,
        log_config=None,
        access_log=False,
        timeout_graceful_shutdown=10,
    )
    return 0


def _print_adapter_check(dry_run: bool) -> int:
    """CLI front end for adapter recovery."""
    if sys.platform != "win32":
        print("Adapter recovery only applies on Windows.", file=sys.stderr)
        return 1

    report = recovery.diagnose()
    state = report["state"]
    print("\nAdapter check")
    print(f"  Wireless interfaces available : {state['interfaces']}")
    print(f"  USB wireless devices present  : {state['usb_wifi_devices']}")
    print(f"  Not working                   : {state['broken']}")
    for problem in state["problems"]:
        print(f"    - {problem['model'] or problem['name']}: {problem['problem']} "
              f"(code {problem['code']})")
    print(f"\n  {report['verdict']}\n")

    if dry_run:
        if report["planned"]:
            print("  Repair would try:")
            for step in report["planned"]:
                flag = " (needs administrator)" if step["blocked"] else ""
                print(f"    - {step['name']}{flag}")
            print("\n  Run with --fix-adapter to apply.\n")
        return 0 if state["interfaces"] else 1

    if report["needs_admin"] and not report["admin"]:
        print("  Some repairs need administrator rights.")
        print("  Re-run this from an elevated prompt:\n")
        print(f'    Start-Process "{runtime.executable_path()}" '
              '-ArgumentList "--fix-adapter" -Verb RunAs\n')
        return 1

    print("  Working through the repair steps...\n")
    result = recovery.repair()
    marks = {"fixed": "[fixed]", "no_action": "[  ok ]", "skipped": "[ n/a ]",
             "failed": "[fail ]", "needs_admin": "[admin]", "manual": "[ you ]"}
    for step in result["steps"]:
        print(f"  {marks.get(step['status'], '[?????]')} {step['name']}: {step['message']}")
        if step["detail"]:
            print(f"          {step['detail'][:160]}")
    print(f"\n  {result['summary']}\n")
    return 0 if result["resolved"] else 1


def _do_install(args) -> int:
    if sys.platform != "win32":
        print("Installing is a Windows-only operation.", file=sys.stderr)
        return 1
    if not runtime.is_frozen():
        print("Only the packaged build installs itself. Build it with build.ps1 first.",
              file=sys.stderr)
        return 1
    result = installer.install(
        target_dir=Path(args.install_dir) if args.install_dir else None,
        autostart=args.autostart,
        desktop_shortcut=args.desktop_shortcut,
        quiet=args.quiet,
    )
    if not result.get("ok"):
        print(f"Install failed: {result.get('error')}", file=sys.stderr)
        return 1
    print(f"\nwifirecon {result['version']} installed")
    for step in result["steps"]:
        print(f"  - {step}")
    print("\nStart it from the Start Menu, or run:")
    print(f"  \"{result['target']}\"")
    print("Uninstall from Settings > Apps, or run the executable with --uninstall\n")
    return 0


def _do_uninstall(args) -> int:
    if sys.platform != "win32":
        print("Uninstalling is a Windows-only operation.", file=sys.stderr)
        return 1
    if not args.quiet:
        target = "settings and shortcuts" if args.keep_data else (
            f"everything, including the database at {data_dir()}"
        )
        print(f"\nThis removes {target}.")
        try:
            answer = input("Continue? [y/N] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            print("Cancelled.")
            return 1

    scanner.engine.stop()
    gps.reader.stop()
    alerts.dispatcher.stop()
    db.close_thread_connection()

    result = installer.uninstall(keep_data=args.keep_data, quiet=args.quiet)
    print("\nwifirecon removed")
    for step in result["steps"]:
        print(f"  - {step}")
    print()
    return 0


def _do_update() -> int:
    channel = config.get("updates", "channel", default="main")
    info = updater.check(channel, force=True)
    if info.get("error"):
        print(f"Update check failed: {info['error']}", file=sys.stderr)
        return 1
    if not info.get("available"):
        print(f"Version {info['current']} is current.")
        return 0
    print(f"Updating {info['current']} -> {info['latest']}")
    result = updater.apply(channel, restart=False)
    if not result.get("ok"):
        print(f"Update failed: {result.get('error')}", file=sys.stderr)
        return 1
    print(result["message"])
    if result.get("verification"):
        print(f"  {result['verification']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

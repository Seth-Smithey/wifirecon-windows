"""
Alert delivery.

Findings are always written to the database. These sinks push them outward:
Windows toast, an HTTP webhook, syslog (CEF / JSON / RFC5424) for Splunk or
Wazuh, and the Windows event log. Every sink runs on a worker thread so a slow
or dead endpoint never stalls a scan.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .detections import SEVERITY_ORDER, Finding

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"

CEF_SEVERITY = {"info": 2, "low": 4, "medium": 6, "high": 8, "critical": 10}
SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}
SYSLOG_FACILITY = 13  # log audit

_MAX_QUEUE = 500


def _meets(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


def _escape_cef(value: Any) -> str:
    text = str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("=", "\\=")


class AlertDispatcher:
    """Fan findings out to the configured sinks on a background worker."""

    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=_MAX_QUEUE)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._settings: dict = {}
        self._lock = threading.RLock()
        self.stats = {"sent": 0, "dropped": 0, "failed": 0, "queued": 0}
        self._last_error: dict[str, str] = {}
        self._session: Any = None

    def configure(self, settings: dict) -> None:
        with self._lock:
            self._settings = settings or {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="alert-dispatcher", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    def submit(self, findings: list[Finding]) -> None:
        for finding in findings:
            try:
                self._queue.put_nowait(finding)
                self.stats["queued"] = self._queue.qsize()
            except queue.Full:
                self.stats["dropped"] += 1
                log.warning("Alert queue is full; dropped %s for %s",
                            finding.rule, finding.bssid)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is None:
                break
            try:
                self._deliver(item)
                self.stats["sent"] += 1
            except Exception:
                self.stats["failed"] += 1
                log.exception("Failed to deliver alert %s", item.rule)
            finally:
                self._queue.task_done()
                self.stats["queued"] = self._queue.qsize()

    def _deliver(self, finding: Finding) -> None:
        with self._lock:
            settings = dict(self._settings)

        for name, sink in (
            ("toast", self._send_toast),
            ("webhook", self._send_webhook),
            ("syslog", self._send_syslog),
            ("eventlog", self._send_eventlog),
        ):
            conf = settings.get(name) or {}
            if not conf.get("enabled"):
                continue
            if not _meets(finding.severity, conf.get("min_severity", "info")):
                continue
            try:
                sink(finding, conf)
                self._last_error.pop(name, None)
            except Exception as exc:
                self._last_error[name] = "Delivery failed. See the local log for details."
                log.warning("%s sink failed: %s", name, exc)

    # -- sinks --------------------------------------------------------------

    def _send_toast(self, finding: Finding, conf: dict) -> None:
        if not IS_WINDOWS:
            log.debug("Toast skipped: not running on Windows")
            return
        title = finding.title[:120].replace('"', "'")
        body = finding.detail[:250].replace('"', "'")
        script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
            " ContentType=WindowsRuntime] > $null;"
            "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
            "$n=$t.GetElementsByTagName('text');"
            f"$n.Item(0).AppendChild($t.CreateTextNode(\"wifirecon: {title}\")) > $null;"
            f"$n.Item(1).AppendChild($t.CreateTextNode(\"{body}\")) > $null;"
            "$toast=[Windows.UI.Notifications.ToastNotification]::new($t);"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
            "'wifirecon').Show($toast);"
        )
        creation_flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
             "-Command", script],
            capture_output=True,
            timeout=15,
            creationflags=creation_flags,
        )

    def _send_webhook(self, finding: Finding, conf: dict) -> None:
        url = conf.get("url")
        if not url:
            raise ValueError("Webhook is on but no URL is set")
        import urllib.error
        import urllib.request

        payload = json.dumps(
            {
                "source": "wifirecon-win",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "rule": finding.rule,
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "bssid": finding.bssid,
                "ssid": finding.ssid,
                "evidence": finding.evidence,
                "text": f"[{finding.severity.upper()}] {finding.title} - {finding.detail}",
            },
            default=str,
        ).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "wifirecon-win"},
            method="POST",
        )
        timeout = float(conf.get("timeout", 8))
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status >= 400:
                raise RuntimeError(f"Webhook returned HTTP {response.status}")

    def _send_syslog(self, finding: Finding, conf: dict) -> None:
        host = conf.get("host")
        if not host:
            raise ValueError("Syslog is on but no host is set")
        port = int(conf.get("port", 514))
        fmt = conf.get("format", "cef")
        message = self._format_syslog(finding, fmt)

        if conf.get("protocol", "udp").lower() == "tcp":
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.sendall(message.encode("utf-8") + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(8)
                sock.sendto(message.encode("utf-8"), (host, port))

    def _format_syslog(self, finding: Finding, fmt: str) -> str:
        priority = SYSLOG_FACILITY * 8 + SYSLOG_SEVERITY.get(finding.severity, 6)
        hostname = socket.gethostname()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if fmt == "json":
            body = json.dumps(
                {
                    "rule": finding.rule,
                    "severity": finding.severity,
                    "title": finding.title,
                    "detail": finding.detail,
                    "bssid": finding.bssid,
                    "ssid": finding.ssid,
                    "evidence": finding.evidence,
                },
                default=str,
            )
            return f"<{priority}>1 {timestamp} {hostname} wifirecon - - - {body}"

        if fmt == "rfc5424":
            return (
                f"<{priority}>1 {timestamp} {hostname} wifirecon - {finding.rule} - "
                f"{finding.title} | {finding.detail}"
            )

        # CEF, which is what Splunk and Wazuh parse most cleanly.
        extensions = {
            "rt": int(time.time() * 1000),
            "cs1Label": "rule",
            "cs1": finding.rule,
            "cs2Label": "ssid",
            "cs2": finding.ssid or "",
            "dvchost": hostname,
            "smac": finding.bssid or "",
            "msg": finding.detail,
        }
        for key, value in list(finding.evidence.items())[:6]:
            extensions[f"flexString_{key}"] = value
        ext = " ".join(f"{k}={_escape_cef(v)}" for k, v in extensions.items())
        header = (
            f"CEF:0|Anthropic|wifirecon-win|1.0|{finding.rule}|"
            f"{_escape_cef(finding.title)}|{CEF_SEVERITY.get(finding.severity, 5)}|"
        )
        return f"<{priority}>{timestamp} {hostname} {header}{ext}"

    def _send_eventlog(self, finding: Finding, conf: dict) -> None:
        if not IS_WINDOWS:
            return
        entry_type = {"critical": "Error", "high": "Error", "medium": "Warning"}.get(
            finding.severity, "Information"
        )
        message = f"{finding.title}\n\n{finding.detail}\n\nBSSID: {finding.bssid or 'n/a'}"
        message = message.replace("'", "''")
        script = (
            "if (-not [System.Diagnostics.EventLog]::SourceExists('wifirecon')) "
            "{ New-EventLog -LogName Application -Source 'wifirecon' };"
            f"Write-EventLog -LogName Application -Source 'wifirecon' -EntryType {entry_type} "
            f"-EventId 1000 -Message '{message}'"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=20,
            creationflags=0x08000000,
        )

    # -- diagnostics --------------------------------------------------------

    def test(self, sink: str) -> dict:
        """Send a synthetic alert through one sink and report what happened."""
        with self._lock:
            conf = dict(self._settings.get(sink) or {})
        conf["enabled"] = True
        conf["min_severity"] = "info"
        finding = Finding(
            rule="test_alert",
            severity="high",
            title="Test alert from wifirecon",
            detail="If you are reading this, the sink is wired up correctly.",
            bssid="00:00:00:00:00:00",
            ssid="test",
            evidence={"source": "manual test"},
        )
        sinks = {
            "toast": self._send_toast,
            "webhook": self._send_webhook,
            "syslog": self._send_syslog,
            "eventlog": self._send_eventlog,
        }
        if sink not in sinks:
            return {"ok": False, "error": f"'{sink}' is not a known alert channel"}
        try:
            sinks[sink](finding, conf)
            return {"ok": True, "message": f"Sent a test alert through {sink}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def status(self) -> dict:
        with self._lock:
            settings = dict(self._settings)
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "queue_depth": self._queue.qsize(),
            "stats": dict(self.stats),
            "last_errors": dict(self._last_error),
            "enabled_sinks": [
                name for name in ("toast", "webhook", "syslog", "eventlog")
                if (settings.get(name) or {}).get("enabled")
            ],
        }


dispatcher = AlertDispatcher()

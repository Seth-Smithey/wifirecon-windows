"""Failure responses must not disclose internal exception details."""

import asyncio
import ssl
import unittest
from unittest.mock import patch

from app import netaudit
from app.alerts import AlertDispatcher
from app.api import routes
from app.detections import Finding


class SecurityErrorTests(unittest.TestCase):
    def test_install_failure_keeps_exception_in_local_log(self):
        private_detail = "private-path-and-sensitive-diagnostic"
        with (
            patch.object(routes.installer, "status", side_effect=RuntimeError(private_detail)),
            self.assertLogs(routes.log, level="WARNING") as captured,
        ):
            result = asyncio.run(routes.install_status())
        self.assertNotIn(private_detail, str(result))
        self.assertTrue(result["error"])
        self.assertIn(private_detail, " ".join(captured.output))

    def test_failed_delivery_does_not_publish_exception(self):
        dispatcher = AlertDispatcher()
        dispatcher._settings = {"webhook": {"enabled": True}}
        finding = Finding("test", "info", "Example", "Example")
        private_detail = "private-webhook-diagnostic"
        with (
            patch.object(dispatcher, "_send_webhook", side_effect=RuntimeError(private_detail)),
            self.assertLogs("app.alerts", level="WARNING") as captured,
        ):
            dispatcher._deliver(finding)
        result = dispatcher.status()
        self.assertNotIn(private_detail, str(result))
        self.assertTrue(result["last_errors"]["webhook"])
        self.assertIn(private_detail, " ".join(captured.output))

    def test_tls_probe_explicitly_disallows_legacy_tls(self):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        with (
            patch.object(netaudit.ssl, "create_default_context", return_value=context),
            patch.object(netaudit.socket, "create_connection", side_effect=OSError("offline")),
        ):
            self.assertEqual(netaudit._tls_summary("example.invalid", 443, 0.1), "")
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

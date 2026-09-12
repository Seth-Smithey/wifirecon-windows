"""A completed status refresh must not update a detached window."""

import unittest

from PySide6.QtCore import QCoreApplication

from app.ui.bridge import ScanBridge


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def test_status_delivery_stops_after_detach(self):
        bridge = ScanBridge()
        delivered = []
        bridge.status_ready.connect(delivered.append)
        bridge._attached = True
        bridge._deliver_status({"engine": {"phase": "idle"}})
        bridge.detach()
        bridge._deliver_status({"engine": {"phase": "scanning"}})
        self.assertEqual(delivered, [{"engine": {"phase": "idle"}}])

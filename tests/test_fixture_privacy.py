"""Demo data must never be copied from an actual network survey."""

import unittest

from tools.mock_source import FIXTURES


class FixturePrivacyTests(unittest.TestCase):
    def test_demo_networks_use_generic_names_and_local_mac_addresses(self):
        for fixture in FIXTURES:
            with self.subTest(bssid=fixture["bssid"]):
                self.assertTrue(not fixture["ssid"] or fixture["ssid"].startswith("Example_"))
                self.assertTrue(int(fixture["bssid"][:2], 16) & 2)

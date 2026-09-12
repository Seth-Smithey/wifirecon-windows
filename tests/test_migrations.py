"""Regression checks for upgrading older survey databases without losing data."""

import sqlite3
import unittest

from app.db import _add_missing_columns


class MigrationTests(unittest.TestCase):
    def test_legacy_columns_are_added_and_existing_data_survives(self):
        with sqlite3.connect(":memory:") as conn:
            conn.row_factory = sqlite3.Row
            for table in ("bss", "observations", "alerts", "sessions", "scans"):
                conn.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO bss (id) VALUES (42)")

            _add_missing_columns(conn)
            _add_missing_columns(conn)  # Reopening an upgraded database is safe.

            columns = {row["name"] for row in conn.execute("PRAGMA table_info(bss)")}
            self.assertTrue({
                "station_count", "utilization_pct", "wps_manufacturer", "wps_model",
                "wps_device_name", "randomized_mac", "ie_fingerprint", "ie_elements",
                "notes", "rssi_min", "first_session_id",
            }.issubset(columns))
            row = conn.execute("SELECT id, randomized_mac FROM bss").fetchone()
            self.assertEqual(tuple(row), (42, 0))


if __name__ == "__main__":
    unittest.main()

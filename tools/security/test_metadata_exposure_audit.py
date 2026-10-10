"""Regression tests for the aggregate-only RT0 server metadata audit."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from metadata_exposure_audit import collect_counts


def schema(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TABLE calls (id TEXT);
        CREATE TABLE call_participants (id TEXT);
        CREATE TABLE call_signals (id TEXT);
        CREATE TABLE conference_join_grants (id TEXT);
        CREATE TABLE events (event_type TEXT, payload BLOB);
        CREATE TABLE group_memberships (id TEXT);
    """)


class MetadataExposureAuditTest(unittest.TestCase):
    def test_empty_server_database_has_no_indexed_graph(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            schema(connection)
            counts = collect_counts(connection)
            self.assertTrue(all(count == 0 for count in counts.values()))

    def test_call_and_attendance_are_detected_without_reading_private_payload(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            schema(connection)
            connection.execute("INSERT INTO calls VALUES ('private-call-id')")
            connection.execute(
                "INSERT INTO conference_join_grants VALUES ('sensitive-device-to-call')"
            )
            connection.execute(
                "INSERT INTO events VALUES (?, ?)",
                ("ucr.conference.attendance.joined.v1", b"encrypted-or-sensitive-payload"),
            )
            counts = collect_counts(connection)
            self.assertEqual(counts["calls"], 1)
            self.assertEqual(counts["conference_join_grants"], 1)
            self.assertEqual(counts["attendance_events"], 1)
            self.assertNotIn("private-call-id", repr(counts))
            self.assertNotIn("sensitive-device-to-call", repr(counts))

    def test_unrecognized_database_does_not_pass_certification(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            connection.execute("CREATE TABLE events (event_type TEXT)")
            with self.assertRaisesRegex(ValueError, "not a recognized"):
                collect_counts(connection)

    def test_cli_strict_refuses_leaky_snapshot_without_exposing_row_values(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ucr-test.sqlite"
            with sqlite3.connect(path) as connection:
                schema(connection)
                connection.execute("INSERT INTO calls VALUES ('top-secret-person')")
            output = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("metadata_exposure_audit.py")),
                 str(path), "--strict"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(output.returncode, 2, output.stderr)
            self.assertEqual(json.loads(output.stdout)["surface_counts"]["calls"], 1)
            self.assertNotIn("top-secret-person", output.stdout)
            with sqlite3.connect(path) as connection:
                connection.execute("DELETE FROM calls")
            clean = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("metadata_exposure_audit.py")),
                 str(path), "--strict"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(clean.returncode, 0, clean.stdout)


if __name__ == "__main__":
    unittest.main()

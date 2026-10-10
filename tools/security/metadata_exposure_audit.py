#!/usr/bin/env python3
"""Read-only UCR server-side social-graph disclosure probe.

Prints ONLY aggregate counts; never extracts identities, call IDs, IP addresses,
payloads, phone numbers or key material. This tool is deliberately a *negative*
release gate: it cannot certify absence of recovered deleted data in SQLite WAL,
filesystem snapshots, backups, network captures, compromised browsers or caches.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

# All identifiers are fixed, known table names; never interpolate user input
# as SQL. A missing table is not proof of privacy on an unrecognized schema.
SENSITIVE_TABLES = (
    "calls",
    "call_participants",
    "call_signals",
    "conference_join_grants",
    "universal_conference_participants",
    "group_memberships",
    "group_mls_transition_admissions",
)
EVENT_PREFIX = "ucr.conference.attendance."


def collect_counts(connection: sqlite3.Connection) -> dict[str, int]:
    table_names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    if not {"calls", "events", "conference_join_grants"}.issubset(table_names):
        raise ValueError("not a recognized canonical UCR server database")
    result: dict[str, int] = {}
    for name in SENSITIVE_TABLES:
        if name in table_names:
            result[name] = int(
                connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            )
    result["attendance_events"] = int(
        connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type LIKE ?",
            (EVENT_PREFIX + "%",),
        ).fetchone()[0]
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="UCR SQLite database to inspect read-only")
    parser.add_argument("--strict", action="store_true",
                        help="fail if ANY call/social-graph evidence is still persisted")
    args = parser.parse_args()
    try:
        # A read-only connection does not checkpoint, vacuum, delete or alter
        # the user's store. This does not inspect binary WAL residue/backups.
        with sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            counts = collect_counts(connection)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({
            "status": "audit_unavailable",
            "error_category": type(exc).__name__,
        }, sort_keys=True))
        return 3
    findings = sum(counts.values())
    print(json.dumps({
        "status": "sensitive_records_present" if findings else "no_indexed_records_observed",
        "surface_counts": counts,
        "strict_pass": findings == 0,
        "limitations": [
            "Does not inspect WAL free pages, backups, filesystem snapshots or crash dumps",
            "Does not assess IP/time correlation, live process memory or network observers",
            "Does not prove end-to-end encryption or security of client code delivery",
            "A nonzero count blocks strict post-call metadata privacy certification",
        ],
    }, sort_keys=True))
    return 2 if args.strict and findings else 0


if __name__ == "__main__":
    sys.exit(main())

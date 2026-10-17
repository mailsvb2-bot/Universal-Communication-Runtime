#!/usr/bin/env python3
"""Read-only, privacy-preserving local UCR Call state diagnosis.

Never prints identity IDs, device IDs, signing material, cookies or call IDs.
Does not mutate SQLite, repair rows, or bypass canonical validation.
"""
import argparse
import sqlite3
from collections import Counter
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error("SQLite database not found")
    db = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    errors = Counter()
    try:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"calls", "call_participants"}.issubset(tables):
            print("UCR_CALL_DIAG schema_missing")
            return 2
        rows = db.execute("""
            SELECT c.tenant_id, c.namespace_present, c.namespace_id, c.call_id,
                   c.initiated_by_principal_id, c.initiated_by_principal_kind,
                   c.signalling_state, c.termination_reason,
                   c.revision, c.replication_generation,
                   c.reconnecting_principal_id
            FROM calls c
        """).fetchall()
        for row in rows:
            scope = (row["tenant_id"], row["namespace_present"], row["namespace_id"], row["call_id"])
            participants = db.execute("""
                SELECT principal_id, principal_kind, state, joined_revision, left_revision
                  FROM call_participants
                 WHERE tenant_id=? AND namespace_present=? AND namespace_id=? AND call_id=?
            """, scope).fetchall()
            try:
                revision = int.from_bytes(row["revision"], "big")
                generation = int.from_bytes(row["replication_generation"], "big")
            except (TypeError, ValueError):
                errors["invalid_revision_encoding"] += 1
                continue
            if revision != generation:
                errors["revision_generation_mismatch"] += 1
            if len(participants) < 2:
                errors["participant_count_less_than_two"] += 1
            initiator = (row["initiated_by_principal_id"], row["initiated_by_principal_kind"])
            origin = [p for p in participants if (p["principal_id"], p["principal_kind"]) == initiator]
            if len(origin) != 1 or origin[0]["state"] != "accepted":
                errors["initiator_not_accepted"] += 1
            for p in participants:
                if int.from_bytes(p["joined_revision"], "big") > revision:
                    errors["joined_revision_in_future"] += 1
                if p["left_revision"] is not None and int.from_bytes(p["left_revision"], "big") > revision:
                    errors["left_revision_in_future"] += 1
            remote = [p for p in participants if (p["principal_id"], p["principal_kind"]) != initiator]
            any_accepted = any(p["state"] == "accepted" for p in remote)
            any_ringing = any(p["state"] == "ringing" for p in remote)
            any_pending = any(p["state"] in ("invited", "ringing") for p in remote)
            state = row["signalling_state"]
            if state == "inviting" and (any_accepted or any_ringing or not any_pending):
                errors["invalid_inviting_participants"] += 1
            if state == "ringing" and (any_accepted or not any_ringing):
                errors["invalid_ringing_participants"] += 1
            if state in ("active", "reconnecting") and not any_accepted:
                errors["active_without_accepted_remote"] += 1
            if (state == "terminated") != (row["termination_reason"] is not None):
                errors["termination_reason_mismatch"] += 1
            if (state == "reconnecting") != (row["reconnecting_principal_id"] is not None):
                errors["reconnecting_owner_mismatch"] += 1
        print(f"UCR_CALL_DIAG total_calls={len(rows)} structural_issue_count={sum(errors.values())}")
        for kind, count in sorted(errors.items()):
            print(f"UCR_CALL_DIAG {kind}={count}")
        print("Read-only structural preflight only: creation fingerprints and full canonical invariants require runtime checks.")
        return 1 if errors else 0
    finally:
        db.close()

if __name__ == "__main__":
    raise SystemExit(main())

# Contact transfer and call-metadata privacy boundary — 2026-10-12

Status: **Local contacts library added; production/privacy sign-off NOT established.**
Audited base: main at f02801b45b5d1a0a7b8305eb93a65d2ba38269ce.

## User outcomes and boundaries

- People need a personal address book, a simple choice of a known peer, and eventually one-click calling.
- Contact labels and peer identifiers are USER PRIVATE data. Infrastructure must not silently acquire a central address book or social graph from a browser contact book.
- An accountless canonical Identity is not a telephone number (spec/identity-addressing.md).
- Device trust/recovery and contact backup are intentionally separate.
- This slice adds **no HTTP endpoint, central directory, server table, cloud backup, new SQLite owner, new browser database, telephone identifier, or alternate Identity/Call owner**.
- Host application MUST authenticate ownership of tenant/namespace/Identity scope. A client-selected scope alone is not authorization.

## Implemented local mechanism

See sdk/typescript/src/private_contacts.ts.
- list/add/rename/remove for id, displayName and peerIdentityId.
- The **existing** browser ucr-endpoint-state-v1 IndexedDB, version 2: sealed-snapshots stores one AES-256-GCM encrypted book; wrapping-key-vault stores an independent non-extractable AES contact key with distinct prefixed keys (never the Device signing key).
- Fresh random 96-bit IV for each encryption, owner-scoped authenticated additional data, integrity checks, and compare-and-swap revisions to avoid silent lost updates. Contact names and peer identifiers do not appear in IndexedDB keys.
- Explicit user-triggered encrypted export/import via AES-256-GCM with PBKDF2-SHA256 (600,000 iterations and random 128-bit salt), versioned backup and scope binding; wrong password/tampering/wrong identity are rejected. Import never silently overwrites conflicting contacts.
- Export is **not automatic sync**: changes on one device do not appear on another without another user export/import.
- Exports contain **no Device signing, E2EE or trust keys**. A new device needs independent canonical enrollment/recovery.

Conformance command: node --experimental-strip-types sdk/typescript/private_contacts_conformance.ts.
Current conformance tests use an in-memory backing adapter; a real browser IndexedDB integration test is still required.

## Known limitations

- A compromised origin, XSS, malware and hostile extensions may access plaintext while it is used; browser at-rest encryption alone cannot prevent this.
- A cleared browser profile, lost device without backup, or forgotten backup passphrase makes contacts unrecoverable.
- Low-entropy backup passphrases are vulnerable to offline guessing despite PBKDF2. Do not log or transmit the password.
- The new library is NOT connected to a finished first-party contact picker, independent peer verification, protected Call initiation or production delivery.
- No cloud backup, telephone-number discovery, native app integration, accessibility UX or automatic device sync is claimed.
- Do not copy names to Call metadata or audit logs.

## CRITICAL separate finding: durable call participants and metadata

The existing SQLite reference in crates/ucr-storage-sqlite/src/call_store.rs defines:
- calls: Call ID, Conversation ID, initiator Principal ID, signalling state.
- call_participants: Call ID plus participant Principal IDs/kinds and participation state.
- call_signals: Call ID, event ID, actor Principal ID and fingerprints.

The durable participants-to-Call relationship can reveal an interaction graph **if deployed centrally with records retained**. E2EE content protection does not hide these relations by itself.

IMPORTANT: crates/ucr-runtime/src/lib.rs constructs ProductionRuntime around SqliteLocalStore, and crates/ucr-runtime/src/main.rs requires a --database path for the production runtime command. Hence the standard UCR production binary can persist this graph on the machine where it is deployed. This is confirmed source behavior, not a claim that any particular remote deployment is active.

spec/local-storage.md and spec/metadata-visibility.md define classifications and intended trust boundaries. They are not deployment evidence.

| Claim | Status |
| --- | --- |
| Durable Call and participants records are implemented in source | CONFIRMED |
| They are stored on a central production server | NOT VERIFIED (deployment not inspected) |
| Production retention and deletion satisfy the no-social-graph constraint | NOT VERIFIED |
| Complete user-facing book/transfer/one-click Call journey exists | NOT VERIFIED |
| New local contacts module creates a network route or server database | NO |

## Priority follow-ups before claiming privacy or product readiness

1. Determine the actual store and runtime placement for CallStore (device-local vs server) and document data owners. No server inspection is authorized by this repository's AGENTS.md without naming the exact server.
2. Identify mandatory Call/participant/signal retention windows; design secure purge with lifecycle/correctness guarantees and verify restart, replay, revocation and security audit regressions before modifying schema.
3. Inspect all logs, traces, backups, event journals and relays to ensure they do not permit long-lived centrally queryable social graphs beyond explicitly approved policy. Check transport metadata observability independently.
4. Wire contact selection -> verified canonical peer Identity -> authorized Call -> real two-device audio and end-call, proving the full route with non-mock devices.
5. Execute browser IndexedDB tests, real-device backup/restore trials and UI accessibility tests; only then declare an end-user contacts feature ready.

**This document is an identified boundary and implementation slice, not a claim of production readiness.**

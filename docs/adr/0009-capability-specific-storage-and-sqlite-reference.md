# ADR-0009: Capability-specific storage with a SQLite reference store

Status: Accepted

## Context

UCR is local-first and must preserve durable state across restart without turning one database implementation into the canonical model. The Canon requires SQLite, a memory test store, server durable stores, and future embedded stores, while explicitly rejecting a lowest-common-denominator storage design.

Command idempotency from Phase 5 is not restart-safe if acceptance exists only in process memory. Returning `Accepted` before durable commit would reintroduce silent loss after crash.

## Decision

`StorageProvider` is the base storage capability. Domain-specific persistence is expressed through narrower interfaces such as `CommandAcceptanceStore` rather than a generic byte-record database API.

The reference local implementation is `ucr-storage-sqlite`; tests also use `ucr-storage-memory`. Core/model/protocol crates do not depend on `rusqlite` or SQLite schemas.

The SQLite implementation uses a pinned bundled library, explicit application/schema IDs, WAL, `synchronous=FULL`, finite lock waiting, strict open-time validation, and atomic immediate transactions for command acceptance.
An `Accepted` receipt is emitted only after commit. Duplicate/conflict resolution is scoped by tenant, namespace, and idempotency key and remains stable after reopen. Foreign databases and newer schemas fail closed.

## Consequences

- SQLite can be replaced or complemented without changing canonical communication types.
- Memory tests exercise the same storage capability contract without pretending to prove restart durability.
- Storage failures remain explicit and cannot become successful command acceptance.
- Future message/sync/delivery storage may use richer interfaces instead of being forced through opaque bytes.
- Schema migration becomes a reviewed compatibility concern.

## Security and privacy

External applications never access the local database directly. Persisted payload classification is inherited from the command and is not eligible for telemetry by being stored. Unix database files are owner-only; platform-specific private storage remains required elsewhere.

This ADR does not claim Phase-7 cryptographic key management or general encrypted-at-rest storage has been implemented.

## Rejected alternatives

A single `persist(scope, bytes)` interface was rejected because it erases atomicity, query, ordering, recovery, and migration semantics. Making SQLite schema the public API was rejected because it creates a second protocol. In-memory-only idempotency was rejected because restart loses deduplication evidence.

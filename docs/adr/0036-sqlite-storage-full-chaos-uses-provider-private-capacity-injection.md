# ADR-0036: SQLite storage-full chaos uses provider-private capacity injection

Status: Accepted

## Context

The Canon requires storage-full chaos evidence that proves durable-state invariants, not merely an error-code mapping. The existing `SQLITE_FULL` mapping unit test showed canonical error translation but did not prove the transaction outcome of a real `SqliteLocalStore` mutation under exhausted capacity.

A second SQLite connection cannot reliably constrain an already-open store because `max_page_count` is connection-local. Adding a public testing constructor or fake storage implementation only to inject the failure would pollute the production boundary and risk a second storage-policy owner.

## Decision

The SQLite provider owns this provider-specific fault injection inside its own test module, where the existing private production `Connection` is available. The test checkpoints the store, sets SQLite `max_page_count` to the database's current page count, and then submits a protocol-valid maximal Command through the normal `CommandAcceptanceStore::accept_command` implementation.

The required outcome is `DurableStoreError::Full`. The store is then dropped and reopened through the normal production constructor, must report `StorageHealth::Healthy`, and must accept a new Command with the same idempotency key before deduplicating its retry. This proves that the failed capacity-exhausted transaction left no ghost or partial command acceptance.

No public fault-injection API, alternate store, or second storage-policy owner is added. `docs/architecture/CHAOS_SCENARIOS.md` remains the evidence index and may point to provider-owned tests when the fault must be injected at a provider-private boundary.

## Limits

This evidence covers SQLite-engine page-capacity exhaustion for the implemented local durable provider. It does not claim platform-specific filesystem quota or OS-level `ENOSPC` behavior, deterministic mid-operation process kill, or behavior of future durable providers. Those boundaries require their own evidence when applicable.

## Rejected alternatives

Treating the existing synthetic `SQLITE_FULL` error mapping as end-to-end chaos evidence was rejected because it never exercised a durable mutation. Setting `max_page_count` from a second connection was rejected after proving that it did not constrain the already-open production store. Exposing a public capacity/fault hook only for tests was rejected because it would expand the runtime API for non-production semantics. `RLIMIT_FSIZE` was not relabeled as storage-full evidence because SQLite reports that condition as an I/O-write failure rather than `SQLITE_FULL`.

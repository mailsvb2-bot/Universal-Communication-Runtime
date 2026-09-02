# ADR-0010: Append-only Event journal and terminal Command outcomes

- Status: Accepted
- Date: 2026-09-02
- Owners: UCR Core / Storage

## Problem

Phase 6 can durably accept and deduplicate Commands, but acceptance alone does not record what UCR later established as fact. Without a canonical append-only Event journal, restart can lose outcome evidence or encourage products to create their own persistence model.

A second risk is treating a terminal Event as proof that an arbitrary external side effect happened exactly once. UCR cannot make that claim without downstream idempotency and formal evidence.

## Current state

SQLite schema v1 stores scoped command acceptance and idempotency data. The canonical Event model already requires provenance, ordering, schema version, and integrity metadata, but no durable Event/outcome capability exists yet.
## Decision

1. `ProtocolVersion` is a canonical value type owned once by `ucr-model`; negotiation remains in `ucr-protocol`.
2. Canonical Events require actor, source device, wall-clock context, logical order, correlation/causation, schema version, and integrity metadata.
3. `EventJournalStore` is a capability-specific storage interface. Events are append-only and scoped by Tenant/Namespace.
4. Reusing a scoped Event ID with identical semantics is Duplicate; different semantics is Conflict.
5. `CommandOutcomeStore` atomically links one terminal Event to a previously accepted scoped Command.
6. The terminal Event must have matching scope and causation pointing to that Command ID.
7. A second different terminal Event for the same Command is Conflict.
8. SQLite schema v2 migrates v1 transactionally and adds scoped Command ID uniqueness, Events, and terminal links.
9. A terminal Event is UCR processing evidence, not universal exactly-once evidence for external effects.

## Rationale

The Event journal becomes the durable source of canonical facts without turning SQLite rows into a public protocol. Atomic terminal linkage removes the crash window between persisting a terminal fact and recording which accepted Command it terminates.
## Advantages

- restart-safe Event deduplication;
- one canonical Event persistence model for all consumers;
- terminal outcome relation is atomic with Event persistence;
- conflicting Command/Event identity reuse fails closed;
- v1 durable acceptance records are preserved by migration.

## Disadvantages

- SQLite schema and storage code become more complex;
- terminal outcome does not yet provide a crash-safe worker lease/claim model;
- downstream external effects still require their own idempotency/evidence.

## Security and privacy

Event provenance and payload may contain sensitive metadata/content. They remain inside the private storage boundary, inherit retention/classification policy, and are not telemetry. Integrity metadata is bounded but is not treated as cryptographically trustworthy until Phase 7 defines and implements its semantics.
## Compatibility and migration

Public protobuf Event fields 1–9 remain unchanged. New provenance/time fields use numbers 10–12. Rust `ProtocolVersion` changes owner but remains re-exported by `ucr-protocol` for source compatibility.

SQLite v1→v2 migration is one transaction. If scoped Command IDs are already ambiguous, migration fails without raising `user_version`; no row is selected as authoritative.

## Rollback

A binary that only understands schema v1 must not open schema v2. Rollback therefore requires either a compatible v2 binary or a separately reviewed export/downgrade procedure; silent schema downgrade is forbidden.

## Testing

Required evidence includes Event append/dedup/conflict, restart persistence, terminal-event retry, wrong/missing causation rejection, concurrent terminal races, v1 migration preservation, duplicate-ID migration rollback, schema verification, and foreign-key corruption rejection.

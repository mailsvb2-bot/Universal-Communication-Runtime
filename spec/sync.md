# Sync Contract

Status: Experimental / Phase 11 foundation.

## 1. Scope

Sync is a provider-independent UCR subsystem for propagating current canonical state between authorized endpoints. It must support device-device, device-node, peer-peer, and device-cloud links, including delayed and partial synchronization.

SYNC != BACKUP. Sync propagates current state; Backup exists for recovery and has separate encryption, integrity, versioning, ownership, and restore requirements.

A server, cloud, relay, provider, or external consumer is never the canonical source of truth merely because it participates in Sync.

## 2. Session model

A `SyncSession` is one-directional and bound to one exact Tenant/Namespace scope, one source endpoint, one target endpoint, one link kind, and one selection. Endpoint equality is invalid; a session is not a loopback alias. Bidirectional synchronization uses two independent sessions/checkpoint streams so each resume token has one unambiguous source owner.

States are `PREPARED`, `ACTIVE`, `PAUSED`, `COMPLETED`, `CANCELLED`, and `FAILED`. `COMPLETED`, `CANCELLED`, and `FAILED` are terminal. A terminal session cannot be reopened.

`PAUSED` is durable state for delayed synchronization. Resume is an explicit `PAUSED -> ACTIVE` transition, not a new hidden session identity.

## 3. Full and partial selection

`FULL` means no explicit Conversation selection. `PARTIAL` requires a non-empty bounded set of canonical Conversation IDs. Duplicate IDs are invalid and canonical order is lexical by opaque ID representation.

The current bound is 256 Conversation IDs per partial SyncSession. This is a protocol/resource budget, not a business-domain limit.

Selection does not import provider folders, CRM segments, or product-specific synchronization semantics into Core.

## 4. Durable checkpoints

A `SyncCheckpoint` is bound to the exact session ID and Tenant/Namespace scope. `generation` starts at 1 and advances exactly by one. `applied_items` may stay equal or increase; regression is a conflict.

The resume token is opaque, bounded to 4096 bytes, and source-issued. UCR stores and returns it but does not infer provider, event, clock, or business meaning from its bytes.

The token is not a global logical clock, not Identity evidence, not authorization, and not proof that the remote peer possesses any particular Event or Message.

## 5. Durable storage boundary

`SyncStore` is a capability-specific Core interface. Memory and SQLite stores implement the same Protocol validation; neither owns a separate Sync model.

SQLite schema v7 adds normalized `sync_sessions`, `sync_session_conversations`, and append-only `sync_checkpoints`. Migration from v6 is additive and preserves all earlier durable state.

Session creation, state transitions, and checkpoint writes are explicit durable operations. Concurrent stale transitions or conflicting reuse of one checkpoint generation are `CONFLICT`; they never silently overwrite the winner.

On reopen, malformed selections, invalid session states, checkpoint generation gaps, scope/session mismatches, or progress regression are corruption and fail closed.

## 6. Phase boundary and nonclaims

Phase 11 does not perform Anti-Entropy. It does not claim summaries, missing-event detection, partial reconciliation, damaged-state repair, or duplicate-suppression proof across divergent replicas. Those belong to Phase 12.

A resume token must never be promoted into an Anti-Entropy summary or remote-state proof. Network transport, routing, authentication of remote sync payloads, authorization policy integration, cancellation plumbing, and production timeout/deadline policy remain separate work.

Sync must not make cloud infrastructure mandatory and must not make a server the sole source of truth.

## 7. Required reference evidence

Reference implementations must prove:

- canonical Full/Partial selection validation and deduplication;
- durable pause/resume and checkpoint recovery after restart;
- stale state transitions fail closed;
- checkpoint generation and applied-count monotonicity;
- concurrent state/checkpoint races have one winner;
- semantic corruption is rejected on reopen;
- v6-to-v7 migration preserves pre-existing Message and earlier durable state;
- no provider/product-specific Sync model exists in Core or public contract.

The public protobuf contract mirrors the same provider-independent link, selection, state, session, and checkpoint model.

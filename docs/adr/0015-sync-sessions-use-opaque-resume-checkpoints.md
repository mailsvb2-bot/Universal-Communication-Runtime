# ADR-0015: Sync sessions use opaque durable resume checkpoints

Status: Accepted

## Context

After durable local Message and Delivery state, UCR needs multi-device synchronization across device-device, device-node, peer-peer, and device-cloud relationships. The Canon requires delayed and partial Sync, but Anti-Entropy is a later independent phase.

A tempting design is one global sequence/cursor that claims to describe all replica state. That would accidentally assume a single authority/order and would couple Sync to one server or storage topology.

## Decision

UCR defines a provider-independent one-directional `SyncSession` with exact scope, source endpoint, target endpoint, link kind, selection, and monotonic lifecycle. Bidirectional synchronization uses two independent sessions/checkpoint streams.

Delayed Sync uses durable `PAUSED`; terminal sessions cannot reopen. Partial selection is a bounded canonical set of Conversation IDs.

Progress is represented by append-only `SyncCheckpoint` records. Each checkpoint has an exact session/scope binding, sequential generation, non-regressing applied count, and an opaque bounded resume token.

The resume token is deliberately opaque. It is not a global clock, authorization credential, Identity evidence, or proof of remote possession. Its interpretation belongs to the synchronization producer/consumer contract that issued it.

Memory and SQLite implement the same `SyncStore` capability. SQLite schema v7 stores normalized sessions, partial-selection rows, and append-only checkpoints.

## Consequences

This permits restart-safe pause/resume without choosing a server-centric global ordering model. A future Anti-Entropy implementation can add summaries and reconciliation without replacing Phase-11 session identity or checkpoint persistence.

Concurrent stale state transitions and conflicting checkpoint generation are explicit conflicts rather than last-write-wins mutation.

## Rejected alternatives

- Server sequence as canonical Sync clock: rejected because server infrastructure is optional and must not become source of truth.
- Provider-specific cursor in Core types: rejected by the no-second-brain rule.
- Treat resume token as Anti-Entropy proof: rejected because an opaque continuation token does not prove remote replica contents.
- Merge Sync and Backup: rejected because Sync propagates current state while Backup exists for recovery.
- Implement reconciliation inside Phase 11: rejected because summaries/missing-event detection/damaged-state repair belong to Phase 12.

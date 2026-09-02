# ADR-0016: Event Anti-Entropy uses versioned fingerprints and snapshot cursors

Status: Accepted

## Context

Phase 11 established durable one-directional Sync sessions and opaque restart checkpoints, but a checkpoint cannot prove that two replicas contain the same immutable Events. Phase 12 therefore needs provider-independent reconciliation after partitions without inventing a server-owned global sequence or treating opaque Event IDs as sortable clocks.

Wire-parity review also exposed a pre-existing semantic-loss defect: public protobuf `EventEnvelope` already carries repeated protocol extensions, while the Rust Event model and SQLite Event journal discarded them. Any fingerprint or reconciliation layer built on that incomplete model would certify unequal Events as equal.

## Decision

UCR defines a versioned canonical Event fingerprint. `SHA256_V1` uses explicit domain separation and a deterministic protocol-owned field encoding over the complete canonical Event, including actor/source-device provenance, correlation, schema/integrity metadata, and canonical protocol extensions. Extension input order is non-semantic; duplicate extension names are invalid and canonical order is lexical by extension name. A golden vector is a required conformance artifact.

Anti-Entropy compares scoped `EventId + fingerprint` summaries and classifies target state as `MISSING`, `MATCHING`, or `DAMAGED`. Missing Events may pass through the normal append-only Event journal. Matching Events are duplicate-suppressed. Damaged state is a conflict and is never silently overwritten or automatically repaired.

Enumeration uses an opaque cursor bound to the exact SyncSession, Tenant/Namespace, source endpoint, and target endpoint. The first page captures a snapshot boundary. Events appended after that boundary are excluded from the current pass and appear in a later fresh pass. EventId ordering is explicitly non-canonical.

Reference stores may encode private local ordering inside the opaque cursor. SQLite uses its existing internal `journal_seq`, but Core and protobuf do not expose that sequence and callers must not compare cursor bytes.

Conversation-selected Partial Sync fails closed for Event-level reconciliation until UCR defines canonical Event-to-Conversation applicability. Payload parsing or product-specific inference is not an acceptable substitute.

The canonical Rust `EventEnvelope` now carries protocol extensions. SQLite schema v8 adds normalized `event_extensions`; v7-to-v8 migration is additive and preserves all existing Events as having an empty extension list.

## Consequences

Independent implementations can prove Event equality without sharing a database layout, provider cursor, or mandatory cloud authority. Partition recovery no longer depends on lexical EventId ordering, and mid-pass appends cannot disappear between reconciliation passes.

The system detects damaged replica state but deliberately does not guess which conflicting payload is authoritative. Repair policy, remote peer authentication/authorization, concrete transports, and operator/user recovery UX remain separate work.

Adding an Event field that affects canonical semantics now requires corresponding fingerprint and persistence parity. Silent omission is a protocol defect, not a compatible optimization.

## Rejected alternatives

- Sort Event IDs and resume lexically: rejected because opaque IDs are identity, not canonical chronology.
- Expose SQLite `journal_seq` as the Sync clock: rejected because a reference-store implementation detail must not become protocol authority.
- Last-write-wins damaged Events: rejected because it destroys immutable evidence and can silently corrupt replicas.
- Hash only Event payload/type: rejected because provenance, scope, schema, integrity metadata, and extensions are semantic.
- Ignore unknown Event extensions in persistence/fingerprints: rejected because it creates silent cross-implementation semantic loss.
- Infer Event-to-Conversation mapping by parsing payloads: rejected by the single canonical model/no-second-brain rule.

# Sync and Anti-Entropy Contract

Status: Experimental / Phase 12 foundation.

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

Phase 12 Event-level reconciliation supports `FULL` selection. Conversation-selected Partial Sync fails closed for Event-level reconciliation because UCR does not yet define canonical Event-to-Conversation applicability. Implementations MUST NOT parse Event payloads or guess business meaning to synthesize that mapping.

## 4. Durable Phase-11 checkpoints

A `SyncCheckpoint` is bound to the exact session ID and Tenant/Namespace scope. `generation` starts at 1 and advances exactly by one. `applied_items` may stay equal or increase; regression is a conflict.

The resume token is opaque, bounded to 4096 bytes, and source-issued. UCR stores and returns it but does not infer provider, event, clock, or business meaning from its bytes.

The token is not a global logical clock, not Identity evidence, not authorization, and not proof that the remote peer possesses any particular Event or Message.

## 5. Canonical Event fingerprint

Phase 12 defines `SHA256_V1`, a versioned canonical Event fingerprint. The hash uses explicit domain separation and a deterministic field encoding owned by `ucr-protocol`. It covers the complete canonical Event semantics, including exact Tenant/Namespace scope, Event type and payload, actor provenance, source device, wall/logical ordering metadata, correlation, schema version, integrity metadata, and canonical protocol extensions.

Extension order is not semantic. Extensions are validated, duplicate names are rejected, and canonical order is lexical by extension name before hashing or persistence. A golden vector is required so independent implementations can prove byte-for-byte parity.

A fingerprint is an equality/integrity summary, not a digital signature, authorization decision, peer identity proof, or global clock.

### SHA256_V1 canonical byte encoding

Independent implementations MUST produce exactly the same bytes before SHA-256:

- prepend the ASCII domain bytes `ucr:event-fingerprint:sha256:v1\0`;
- encode every byte string as unsigned 64-bit big-endian length followed by the raw bytes; strings are UTF-8 and use that byte-string encoding;
- encode optional strings/IDs as one byte `0x00` for absent, or `0x01` followed by the encoded string for present;
- encode booleans as one byte `0x00` or `0x01`;
- encode `u32` and `u64` as fixed-width unsigned big-endian; encode `i64` as its fixed-width two's-complement big-endian representation;
- encode scope as tenant ID string, then namespace-presence byte, then namespace ID string only when present;
- encode `ActorKind` as one byte: Person=`1`, AiAgent=`2`, Bot=`3`, Organization=`4`, System=`5`; these codes are fingerprint-format constants and do not depend on language enum layout;
- after canonical extension sorting, encode extension count as `u64` big-endian, then each extension as name string, critical byte, payload bytes.

The field sequence after the domain is: `event_id`, scope, `event_type`, payload, actor ID, ActorKind code, actor `on_behalf_of`, source device ID, source identity ID, `wall_time_unix_ms`, `logical_order`, correlation ID, causation ID, idempotency key, schema major, schema minor, integrity metadata, extension count, extensions. No protobuf serialization bytes, local database row IDs, map iteration order, or language-native struct layout participate in the fingerprint.

The Phase-12 golden vector in the reference implementation hashes the canonical test Event to `efc6bb9fdc495ccb4e812ab4d8cd68816271983f7aaf8b62a9c3d7359ea82e61`. Any implementation that produces another digest for that vector is non-conformant.

## 6. Anti-Entropy classification and reconciliation

For each scoped `EventId`, a target classifies a source summary as:

- `MISSING`: no local Event exists with that scoped EventId;
- `MATCHING`: the local Event has the same versioned canonical fingerprint;
- `DAMAGED`: the scoped EventId exists locally but the canonical fingerprint differs.

`MATCHING` is duplicate suppression. `MISSING` may be appended through the normal canonical Event validation/journal boundary. `DAMAGED` is fail-closed: the local Event MUST NOT be silently overwritten or repaired automatically. Recovery of damaged state requires a separate explicit policy/evidence path.

Reusing one scoped `EventId` with different semantics remains a conflict. Anti-Entropy does not weaken Event immutability.

## 7. Snapshot/resume semantics

Anti-Entropy enumeration is snapshot-bound. The first page captures a source-local snapshot boundary. A cursor resumes only inside that immutable pass. Events appended after the snapshot boundary are intentionally excluded from the current pass and MUST appear in a later fresh reconciliation pass.

EventId is never a canonical ordering key. Implementations MUST NOT resume by sorting opaque Event IDs. A reference store may use private append order such as SQLite `journal_seq`, but that ordering is implementation-private and MUST NOT appear in Core or the public protobuf contract.

`AntiEntropyCursor` is opaque and bounded. Its binding covers the exact `SyncSession`, Tenant/Namespace scope, source endpoint, and target endpoint. A cursor from another session, scope, or direction is invalid. Cursor bytes are not remotely comparable and do not prove replica contents.

## 8. Durable storage boundary and SQLite v8

`SyncStore`, `EventJournalStore`, and `AntiEntropyStore` are capability-specific Core interfaces. Memory and SQLite stores implement the same Protocol validation; neither owns a second Sync/Event model.

SQLite schema v7 adds normalized `sync_sessions`, `sync_session_conversations`, and append-only `sync_checkpoints`. SQLite schema v8 adds normalized `event_extensions` linked to the existing append-only Event journal. Migration from v7 to v8 is additive and transactional: every pre-v8 Event is preserved and canonically represents an empty extension list.

SQLite may use its internal `journal_seq` to implement a stable snapshot cursor. `journal_seq` is not exported as canonical ordering and is not present in public UCR protobuf or Core model contracts.

On reopen, malformed extension rows, invalid canonical extension ordering, foreign-key damage, malformed Sync selections/states, checkpoint gaps, or other semantic corruption fail closed.

## 9. Phase boundary and nonclaims

Phase 12 establishes local/reference Anti-Entropy summaries, missing/matching/damaged detection, duplicate suppression, snapshot-safe resume, and reconciliation behavior. It does not by itself authenticate or authorize arbitrary remote peers, define network framing for a concrete transport, select routes, provide production timeout/retry policy, or automatically repair damaged replicas.

The Phase-11 `SyncCheckpoint.resume_token` and Phase-12 `AntiEntropyCursor` remain distinct concepts. Neither is a source-of-truth claim or global logical clock.

Sync must not make cloud infrastructure mandatory and must not make a server the sole source of truth.

## 10. Required reference evidence

Reference implementations must prove:

- canonical Full/Partial Sync selection validation and durable pause/resume;
- versioned Event fingerprint golden-vector parity;
- protocol extensions survive Event persistence and affect fingerprints;
- identical extension sets deduplicate regardless of input order;
- missing, matching, and damaged Event states are distinguished;
- incoming summary classification batches above the 256-item budget fail before allocation-heavy classification;
- damaged Events are never silently overwritten;
- a mid-pass append is excluded from the old snapshot and included in the next pass;
- cursor reuse across another session/direction fails closed;
- conversation-selected partial Event reconciliation fails closed;
- SQLite v7-to-v8 migration preserves existing Events as empty-extension Events;
- older SQLite migration chains still reach current schema without state loss;
- no provider/product-specific Sync model or public `journal_seq` ordering exists.

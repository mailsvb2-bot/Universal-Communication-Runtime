# ADR 0111: Durable Attachment resume state is derived from canonical chunk persistence

## Status

Accepted.

## Problem

ADR 0110 establishes canonical Attachment descriptors, content identity, chunks and streaming integrity verification. A resumable transfer still needs durable metadata and independently persisted chunks that survive process restart.

Creating a separate provider-specific transfer database or mutable resume cursor would duplicate Attachment truth and could drift from the actual persisted chunk set.

## Decision

The existing UCR storage boundary gains `AttachmentStore`.

Reference Memory and SQLite stores persist:

- immutable `AttachmentDescriptor` keyed by exact TenantScope + AttachmentId;
- individually verified `AttachmentChunk` keyed by exact scope + AttachmentId + canonical chunk index.

Resume state is derived as the earliest missing canonical chunk index. A value equal to `chunk_count` means every chunk is durably present; it does not by itself replace complete-content verification.

SQLite schema v45 adds `attachments` and `attachment_chunks`. The v44→v45 migration is additive and leaves existing canonical data untouched.

Chunks may be persisted out of order. Final complete-content verification reads owned chunks back in canonical order and reuses the protocol verifier from ADR 0110.

## Rationale

The persisted chunk set is already the authoritative fact needed to resume. Deriving resume from it removes a second mutable checkpoint that could become inconsistent after a crash.

Reusing `StorageProvider` preserves one local persistence owner and applies the same schema migration, corruption, capacity and restart discipline as Messages, Sync, Delivery and other canonical state.

## Security and privacy

Every chunk is verified against its descriptor before persistence and again when loaded. Corrupt persisted payload/hash/offset data fails closed as storage corruption.

This storage slice does not claim encryption at rest, malware scanning, authorization, retention or secure deletion. Those remain separate layers and must not be inferred from integrity.

## Compatibility

The SQLite schema advances from 44 to 45 through an additive migration. Existing v44 data is preserved. The public Message wire contract is unchanged.

## Testing

Executable tests cover:

- Memory descriptor/chunk idempotency and semantic conflicts;
- out-of-order chunk persistence and earliest-gap resume;
- SQLite restart-safe resume;
- v44→v45 migration;
- corrupted persisted chunk rejection;
- final streaming full-content verification over chunks loaded in canonical order.

# ADR 0111: Attachment resume state uses canonical StorageProvider owners

## Status

Accepted.

## Problem

The Attachment integrity foundation defines descriptor/chunk semantics, but resume after process restart requires durable state. A separate file-transfer database would create another persistence brain and bypass the existing UCR storage ownership/migration rules.

## Decision

Add one `AttachmentStore` capability to the existing `StorageProvider` boundary.

It owns:

- immutable scoped `AttachmentDescriptor` persistence;
- verified chunk persistence keyed by exact scope + Attachment ID + chunk index;
- idempotent equal retries;
- fail-closed conflict/rejection for changed metadata or invalid chunk bytes;
- exact chunk reads by canonical index for restart-safe resume and final streaming verification.

`MemoryLocalStore` implements the same contract for deterministic tests/dev composition.

`SqliteLocalStore` implements the contract in the existing UCR database through schema v45. It does not create a second database or separate migration owner.

## Storage schema

SQLite v45 adds:

- `attachments` — canonical descriptor metadata and full-content SHA-256;
- `attachment_chunks` — exact chunk index/offset/payload/per-chunk SHA-256 with an FK to the descriptor.

Deleting a descriptor cascades its chunks at the schema boundary, though public deletion/retention semantics remain follow-up policy work.

## Integrity boundary

Stores must validate descriptors before persistence and must validate every chunk against its persisted descriptor before accepting it.

Loading persisted chunks revalidates the chunk against the descriptor. Corrupt on-disk state fails closed as `DurableStoreError::Corrupt`.

The store does not claim delivery, authorization, malware safety, encryption, or Message ownership. Message continues to carry Attachment IDs only.

## Restart/resume semantics

A partially persisted attachment may contain any subset of valid canonical chunk indexes. After restart, callers can query exact indexes and continue transfer without reaccepting different bytes for an already persisted index.

Final complete-content verification remains owned by the protocol verifier and reads chunks in canonical order.

## Compatibility and migration

Existing SQLite schema v44 migrates transactionally to v45 by creating only the new Attachment tables and advancing `user_version`.

Existing Message rows and `message_attachments` references are not rewritten.

## Testing

Executable tests prove:

- MemoryStore descriptor/chunk deduplication;
- invalid conflicting chunk retry rejection;
- SQLite descriptor/chunk persistence;
- partial chunk state survives close/reopen;
- resume can continue with the next chunk after restart;
- current schema reports v45 and reopens cleanly.

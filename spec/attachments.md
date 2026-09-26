# Attachment Integrity and Content Addressing

Status: **Prepared integrity foundation**. Durable Attachment storage, transfer scheduling, transport execution, public upload/download APIs and full file-transfer UX remain separate work.

## Canonical ownership

An Attachment is a canonical UCR object separate from Message/Event payload bytes.

A Message carries ordered `AttachmentId` references only. This preserves the Canon large-object separation rule: giant binary payloads do not become Message Events and no transport/provider owns Attachment identity.

The initial model consists of:

- `AttachmentDescriptor`: exact scope, canonical Attachment ID, stable content identity, total size, bounded chunk layout and optional presentation metadata;
- `AttachmentContentId`: SHA-256 of the exact complete attachment byte sequence;
- `AttachmentChunk`: Attachment ID, canonical chunk index, exact byte offset, payload and SHA-256 of that chunk.

## Content addressing

UCR v1 attachment content identity is:

`SHA-256(exact attachment bytes)`

The digest is content identity, not authorization and not ownership evidence. Equal content bytes may have equal content identity while distinct `AttachmentId` values remain distinct canonical objects in different scopes/messages/lifecycles.

File name, media type, provider path, local path, URL and storage location are never content identity.

## Bounded chunking

The v1 reference bounds are:

- maximum chunk payload: 1 MiB;
- maximum chunks per Attachment: 65,536;
- maximum represented Attachment size: 64 GiB;
- maximum media-type metadata: 255 UTF-8 bytes;
- maximum file-name metadata: 1,024 UTF-8 bytes.

A descriptor's `chunk_count` must exactly equal the ceiling of `size_bytes / chunk_size_bytes`. Empty content is valid and has zero chunks plus the standard SHA-256 empty-content digest.

Each non-final chunk must have exactly `chunk_size_bytes` bytes. The final chunk carries exactly the remaining bytes. Chunk offset is deterministic:

`offset_bytes = index * chunk_size_bytes`

No sparse, overlapping or provider-defined layout is accepted by this v1 contract.

## Integrity verification

Each chunk is independently verified before it contributes to complete-content verification.

Complete verification:

1. validates the descriptor and fixed bounds;
2. consumes a canonical-order chunk iterator/reader; transfer and persistence layers may receive chunks out of order for retry/resume, but complete verification reads them back by canonical index;
3. requires every canonical chunk index exactly once;
4. verifies Attachment identity, index, offset, length and chunk SHA-256;
5. hashes and releases each verified chunk before requesting the next one;
6. requires the resulting SHA-256 to equal `AttachmentContentId`.

Recomputing a forged per-chunk hash after payload tampering cannot defeat the final content identity check.

Verification consumes owned chunks one at a time and does not require the complete Attachment payload to be resident in memory. A durable resume store is expected to expose verified chunks in canonical index order for the final pass.

## Security and privacy

Attachment hashes are integrity/content-addressing evidence only. They do not prove author identity, permission, delivery, read state, malware safety or confidentiality.

Optional file name and media type may contain private user metadata. Reference Debug output must redact them, and Attachment payload bytes/hashes must not be logged as plaintext diagnostics.

Encryption, malware scanning, retention, cryptographic erasure, device-bound content delivery and storage-at-rest policy remain separate security/data-lifecycle layers.

## Nonclaims

This slice does **not** claim that Canon file transfer is complete.

Still required before the main Canon file-transfer/DoD path is closed:

- durable Attachment metadata/content storage;
- chunk persistence and restart-safe resume state;
- upload/download public API/SDK surface;
- transport execution and cancellation;
- retry/backpressure/resource policy;
- local/direct and Internet transfer composition;
- Message-to-Attachment existence/authorization binding;
- attachment retention/deletion/export behavior;
- end-to-end file delivery tests through the Reference consumer.

The purpose of this slice is to establish one canonical integrity/content-addressing contract that all later storage, APIs and transports must reuse.

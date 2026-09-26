# ADR 0110: Attachment integrity is content-addressed and separate from Message identity

## Status

Accepted.

## Problem

The Canon requires file transfer, content addressing, chunking, resume and Attachment integrity, while the existing implementation contains only ordered `AttachmentId` references in `MessageEnvelope`. No canonical Attachment payload descriptor or integrity verifier exists.

Adding file bytes directly to Message/Event payloads would violate large-object separation and would couple Message identity to storage/transport mechanics. Letting each transport or provider invent its own hash/chunk format would create parallel Attachment brains and make resume/integrity semantics provider-specific.

## Current state

`MessageEnvelope.attachment_ids` preserves user-visible attachment order, but `spec/conversation-message.md` explicitly states that Phase 9 did not implement Attachment storage/transfer.

No workspace crate currently owns file-transfer storage or transport. There is therefore no existing Attachment owner to reuse beyond the canonical `AttachmentId`.

## Alternatives considered

### Put attachment bytes inside Message

Rejected. It violates the Canon large-object separation rule, expands Message/Event budgets and turns Message persistence into a file store.

### Let transports/providers define their own file identity and chunking

Rejected. Provider paths, URLs and transport-specific IDs are temporary endpoints, not canonical content identity. This would create provider-specific file cores.

### Canonical Attachment descriptor + content hash + bounded chunks

Selected. Message continues to carry only Attachment IDs. A separate canonical integrity contract defines exact content identity and chunks, while later durable storage/API/transport layers compose it.

## Decision

UCR v1 defines:

- `AttachmentContentId = SHA-256(exact complete attachment bytes)`;
- `AttachmentDescriptor` with exact TenantScope, Attachment ID, content identity, size and bounded chunk layout;
- `AttachmentChunk` with exact Attachment ID, index, offset, payload and per-chunk SHA-256;
- deterministic chunk offsets and lengths;
- complete verification that accepts out-of-order arrival but requires each canonical index exactly once;
- independent chunk verification followed by full-content hash verification.

The initial reference ceiling is 1 MiB per chunk, 65,536 chunks and therefore 64 GiB represented content.

This ADR does not choose a durable storage schema, transport, retry owner, API method, encryption-at-rest scheme or deletion/retention policy. Those remain follow-up layers and must reuse this canonical integrity contract.

## Rationale

Content addressing makes Attachment identity independent of server path, provider ID and route. Per-chunk hashes detect corruption early; the complete content hash prevents an attacker or broken transport from hiding whole-file tampering by recomputing a chunk hash.

Keeping Attachment bytes outside Message preserves one Message owner and keeps large-object mechanics independently evolvable.

## Advantages

- closes the missing canonical integrity/content-addressing primitive;
- preserves Message/Event size boundaries;
- supports retry/resume and out-of-order chunk arrival;
- makes integrity transport/provider independent;
- avoids full-file concatenation during verification;
- creates a stable basis for local, Internet, P2P and future multi-source transfer.

## Disadvantages

- SHA-256 content identity can reveal equality of identical plaintext content if exposed;
- the first slice does not provide durable file transfer by itself;
- fixed v1 chunk layout is intentionally simple and does not yet implement multi-source scheduling.

## Risks

A later implementation could incorrectly treat content hash as authorization, authorship or delivery proof. Tests/spec must keep these semantics separate.

Optional file-name/media-type metadata may leak user information if logged.

## Security impact

Chunk and full-content integrity fail closed on mismatch. Hashes are not authentication; Message authorship/device trust remains separately verified.

Payload bytes, file names and content hashes must not be emitted into plaintext telemetry.

## Privacy impact

Content hashes can act as equality fingerprints and therefore should be exposed only where required. File name and media type remain private metadata subject to minimum disclosure.

## Compatibility impact

The public contract adds a new standalone `attachment.proto`; existing Message wire fields and field numbers are unchanged. Old clients can continue treating Attachment IDs as opaque references.

## Migration strategy

No existing durable data migration is required because no canonical Attachment payload store exists. Existing Message `attachment_ids` remain unchanged.

Future Attachment stores must persist descriptors without inventing content identity from provider paths or Message metadata.

## Rollback strategy

The new standalone Attachment contract can be removed before any durable/API adoption without rewriting existing Message data. Once durable Attachment records exist, rollback must preserve those records or explicitly declare compatibility loss through normal version governance.

## Testing strategy

Executable tests cover:

- stable SHA-256 content identity including empty content;
- bounded descriptor validation;
- out-of-order/resumed chunk verification;
- chunk payload tampering;
- forged recomputed chunk hash still failing full-content verification;
- missing/duplicate chunk rejection;
- architecture guards proving Message remains reference-only and the public Attachment contract exists.

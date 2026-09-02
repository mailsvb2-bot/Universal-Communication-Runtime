# ADR-0013: Provider-independent Conversation and durable Message

Status: Accepted

## Context

UCR already had Conversation taxonomy and an early wire Message shape, but no complete canonical Rust Message entity, no Conversation/Message validation contract, and no durable local Message store.

The Canon requires Conversation to outlive providers and Message to remain the single user-visible entity even when future routing uses multiple transports.

Provider-specific Conversation or Message stores would violate the no-second-brain rule. Treating local persistence as delivery would also collapse the required Delivery state machine.
## Decision

UCR defines one provider-independent `ConversationRecord` and one canonical `MessageEnvelope`. Provider identifiers appear only as explicit external mappings.

Conversation hierarchy is constrained to root Conversation -> Topic -> Thread. Stores must require an existing same-scope parent of the correct kind.

`MessageStore` canonicalizes semantic set-like fields, atomically persists the Message, and advances only `CREATED -> PERSISTED`. Later Delivery states are owned by the Delivery Engine.

Scoped Message ID reuse is idempotent only for identical canonical semantics. Different semantics under the same scoped ID are a conflict; Message persistence never overwrites history.
## Storage decision

SQLite schema v5 uses normalized Conversation, Message, attachment-reference, relation, and external-mapping tables. Rust structs are not serialized as an opaque database protocol.

The schema is additive from v4. A same-scope parent foreign key protects Conversation hierarchy, and Message/child rows are foreign-keyed to their canonical owners.

The memory store implements the same Core interfaces as the SQLite reference store and remains the semantic test oracle rather than a separate behavior model.

## Security boundary

Signature metadata is preserved and structurally validated, but storage is not signature verification. Message authenticity is not claimed until canonical signing bytes and verification are integrated.
Local persistence may contain plaintext Message content before transport encryption. Phase 9 therefore does not claim encrypted-at-rest SQLite storage.

Group membership/MLS, Attachment storage/transfer, Sync/Anti-Entropy, edit-history projection, reactions, and post-persist Delivery transitions remain separate work.

## Rejected alternatives

- Provider-owned conversations/messages: rejected because Conversation outlives Provider.
- Opaque Rust-blob persistence: rejected because storage must not become a private second protocol.
- Treating `PERSISTED` as delivered: rejected because relay/transport/user delivery evidence are distinct.
- In-place Message overwrite for edits: rejected because edits must preserve immutable history semantics.

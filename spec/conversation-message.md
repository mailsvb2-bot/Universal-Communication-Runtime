# Conversation and Message Contract

Status: Experimental / Phase 9 foundation.

## 1. Fundamental rule

A Conversation is a canonical UCR entity and outlives any provider, route, relay, or device. Provider IDs are external mappings, never Conversation ownership.

The canonical taxonomy is: `DIRECT`, `PRIVATE_GROUP`, `PUBLIC_GROUP`, `BROADCAST`, `COMMUNITY`, `ROOM`, `TOPIC`, `THREAD`, and `SYSTEM`.

Group, Broadcast, and Community engines remain richer later subsystems; the Phase-9 data model must already preserve their distinct kinds without reducing them to flags.

## 2. Conversation hierarchy

Root Conversation kinds do not carry `parent_conversation_id`.

A `TOPIC` requires one existing parent root Conversation in the same Tenant/Namespace. A `THREAD` requires one existing `TOPIC` parent in the same Tenant/Namespace.

Self-parenting, missing parents, cross-scope parents, `TOPIC -> TOPIC`, and `THREAD -> root` are invalid. SQLite additionally enforces a same-scope parent foreign key.
## 3. Canonical Message

A Message carries: scoped `message_id`, Conversation, author Actor, author Device, wall-clock creation time, logical order, content, attachment IDs, reply projection, typed relations, crypto metadata, delivery policy/state, origin, correlation, protocol extensions, external mappings, and optional signature metadata.

The protobuf `author_device` field is optional only as a wire-presence mechanism. Canonical Message semantic decoding requires an author Device; absence is invalid rather than permission to invent, infer, or drop device provenance.

Canonical IDs are offline-capable opaque IDs. No Message or Conversation identity depends on provider IDs, IP addresses, hostnames, or a server database sequence.

`created_at_unix_ms` is display/context time. Security or durable ordering must not trust wall-clock time; `logical_order` is the canonical ordering field available in this foundation.

Attachments are ordered references because user-visible attachment order can matter. Phase 9 does not yet implement Attachment storage/transfer.

Relations support `REPLY`, `QUOTE`, `EDIT`, `REACTION`, `THREAD_PARENT`, `FORWARD`, and `REFERENCE`. Relations are immutable references; reuse of one scoped Message ID with different semantics is a conflict, not an overwrite.
## 4. Canonicalization and validation

Message content is bounded by the protocol frame payload budget. Attachments, relations, crypto metadata, external mappings, and external message IDs have explicit limits before persistence.

Duplicate attachments, duplicate relations, self-relations, empty external mapping IDs, and duplicate integration mappings fail closed. `reply_to` is a projection and must exactly match the single `REPLY` relation when present.

Relation order, external-mapping order, and protocol-extension order are not semantic and are canonicalized deterministically before durable comparison. Attachment order remains semantic. Message extensions use the shared namespace, duplicate-name, count, and payload limits.

An empty Message with no content, attachments, or relations is invalid. Origin must contain at least one canonical Principal, Endpoint, or Integration reference.

Optional signature metadata is validated for the configured suite-v1 algorithm/version/length. Merely storing signature metadata is not authenticity proof. Authorship verification is an explicit cryptographic operation against an already trusted signing-key descriptor.

### Canonical Message signing binding v1

`MessageSigningBinding` v1 is SHA-256 over the ASCII domain `UCR-MESSAGE-SIGNING-BINDING-V1\0` followed by deterministic authored-Message encoding. Byte strings use unsigned 64-bit big-endian length followed by exact bytes. Optional values use one byte `0x00` for absent or `0x01` followed by the encoded value. Integers use big-endian representation. Protobuf serialization and language-native struct layout are never signing inputs.

The exact field sequence is: `message_id`; scope tenant ID and optional namespace ID; Conversation ID and ConversationKind code; author Actor ID, ActorKind code, and optional `on_behalf_of`; author Device ID and Identity ID; `created_at_unix_ms`; `logical_order`; content; attachment count and attachment IDs in authored order; optional `reply_to`; canonical relation count and each relation kind/target; optional crypto metadata containing suite code, optional key ID, and opaque metadata; DeliveryPolicy code; optional origin Principal/Endpoint/Integration IDs; correlation ID, optional causation ID, optional idempotency key; canonical extension count and each extension name, critical byte, and payload.

Stable v1 codes are: Actor `PERSON=1, AI_AGENT=2, BOT=3, ORGANIZATION=4, SYSTEM=5`; Conversation `DIRECT=1, PRIVATE_GROUP=2, PUBLIC_GROUP=3, BROADCAST=4, COMMUNITY=5, ROOM=6, TOPIC=7, THREAD=8, SYSTEM=9`; Relation `REPLY=1, QUOTE=2, EDIT=3, REACTION=4, THREAD_PARENT=5, FORWARD=6, REFERENCE=7`; DeliveryPolicy `BEST_EFFORT=1, DURABLE=2, URGENT=3, EXPIRING=4, LOCAL_ONLY=5, DIRECT_ONLY=6, NO_RELAY=7, NO_EXTERNAL_BRIDGE=8, PRIVATE_NETWORK_ONLY=9`. Crypto Suite UCR v1 keeps its public numeric suite code `1`.

`delivery_state`, `external_mappings`, and `signature` are excluded from the authored binding. Delivery progression belongs to `DeliveryAttempt`; provider mappings are integration results; signature metadata is the verification result itself. Relation and extension input ordering is first canonicalized using the normal Message rules; attachment ordering remains authored semantics.

Ed25519 signs the ASCII domain `UCR-MESSAGE-SIGNATURE-V1\0` followed by the 32-byte signing binding. Verification requires an already trusted suite-v1 Signing `PublicKeyDescriptor`, exact signature `key_id` match, exact descriptor Device ID / Message author Device ID match, and valid Ed25519 verification. `key_id` inside a Message never establishes trust by itself. The reference golden binding is `d71367107172322ca408610f8a1de9b00fff44383f33ee56e4316fd5043d09d2`.
## 5. Persistence boundary

`ConversationStore` and `MessageStore` are capability-specific Core interfaces. Core does not depend on SQLite.

The local reference store accepts a Message only in `CREATED` or already-`PERSISTED` state. Successful durable insertion returns only after commit and stores the Message as `PERSISTED`.

The Phase-9 boundary intentionally stops at `PERSISTED`. `ENCRYPTED`, `QUEUED`, route planning, transmission, acknowledgements, delivery, read state, retry, and expiry belong to the Delivery Engine and must not be inferred from local persistence.

A Message requires its exact Conversation to exist in the same scope and with the same Conversation kind. The same scoped Message ID plus identical canonical semantics is a duplicate; the same ID with different semantics is `CONFLICT`.

SQLite schema v5 stores Conversations and Messages in normalized tables, including ordered attachments and relations plus external mappings. Migration from v4 is additive and preserves existing durable state. Post-Phase-12 schema v10 adds normalized `message_extensions`; migration from v9 preserves every existing Message as having the empty extension set, matching the only Message extension semantics representable before v10.
## 6. Security and privacy nonclaims

Phase 9 may persist Message content locally before transport encryption, matching `Create -> Persist -> Encrypt -> Queue`. The SQLite reference store therefore does not claim message-content encryption at rest; filesystem/database protection and a future at-rest key policy remain explicit deployment/security work.

External message IDs remain scoped Integration mappings. They never become canonical Message IDs and cannot create provider-specific message brains.

Ordinary Rust `Debug` output redacts Message plaintext, correlation idempotency keys, external provider message IDs, crypto metadata bytes, signature bytes, and extension payloads. The same nested metadata types redact themselves when formatted directly; safe structure, presence, algorithms, and byte lengths may remain visible. This is model-level diagnostic hardening, not a claim that all telemetry/crash-report pipelines have end-to-end plaintext-leak coverage.

Edit and reaction relations establish canonical relationship vocabulary, but Phase 9 does not yet claim a complete edit-history projection, reaction engine, group membership/MLS state, Attachment engine, Sync/Anti-Entropy, or Delivery Engine.

## 7. Required evidence

Reference implementations must prove restart-safe Message round-trip, exact duplicate/conflict behavior including extension semantics, valid Conversation hierarchy, concurrent conflicting Message single-winner behavior, v4-to-v5 migration without loss of pre-existing durable state, v9-to-v10 migration preserving legacy Messages as empty-extension Messages, canonical Message-signing golden vectors/order invariants, and adversarial signature verification against trusted author-device signing descriptors.

Protobuf compatibility is additive: the original `MessageEnvelope` fields 1-11 remain unchanged; Phase-9 fields use numbers 12-19.

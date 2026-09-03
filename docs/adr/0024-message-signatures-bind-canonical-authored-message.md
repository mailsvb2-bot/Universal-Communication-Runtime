# ADR-0024: Message signatures bind canonical authored Message semantics

Status: Accepted

## Problem

Message signature metadata has been preserved since Phase 9, but structural validation alone does not prove authorship. UCR needs language-independent canonical signing bytes and cryptographic verification without making protobuf serialization, provider mappings, delivery state, or key discovery into hidden sources of truth.

Trusted signing-key provisioning and lifecycle are a separate security boundary and remain a production blocker. A verifier must therefore consume an already trusted public-key descriptor rather than treating `MessageSignature.key_id` as proof of trust.

## Decision

UCR defines `MessageSigningBinding` version 1 as SHA-256 over a domain-separated deterministic encoding of canonical authored Message fields. The binding domain is `UCR-MESSAGE-SIGNING-BINDING-V1\0`. Ed25519 signs a second domain, `UCR-MESSAGE-SIGNATURE-V1\0`, followed by the 32-byte binding.

The authored binding includes Message ID and scope, Conversation ID/kind, author Actor and delegation, author Device/Identity, creation time, logical order, content, ordered attachments, reply projection, canonical relations, crypto metadata, delivery policy, origin, correlation metadata, and canonical protocol extensions.

`delivery_state`, `external_mappings`, and `signature` are excluded. Delivery progress belongs to `DeliveryAttempt`; provider mappings are integration results; signature metadata is the result being verified. Changing any of those fields therefore does not invalidate the authored signature, while changing authored fields does.

The encoding uses explicit field order, big-endian integers, one-byte optional presence markers, u64 byte-string lengths, explicit stable enum codes, and canonical collection order. Protobuf serialization and Rust struct layout are not signing inputs.

`verify_message_signature` accepts a Message and an already trusted `PublicKeyDescriptor`. It requires a Signing-purpose suite-v1 descriptor, exact `MessageSignature.key_id` match, exact descriptor-device / author-device match, and valid Ed25519 verification. It does not provision, discover, rotate, revoke, or trust keys.

## Consequences

Independent SDKs can reproduce one signing binding. Provider delivery/mapping changes do not break authorship verification. Key substitution and author-device substitution fail before cryptographic success can be treated as valid authorship.

## Security impact

Positive. Authored Message tampering is detected cryptographically when a trusted signing descriptor is supplied. Missing signatures, wrong keys, wrong key IDs, wrong author devices, malformed trusted descriptors, and invalid Ed25519 signatures fail closed. This does not make an untrusted descriptor trusted.

## Privacy impact

Neutral to positive. The signing binding is a SHA-256 digest and its ordinary Debug surface is redacted. Signing does not add provider, network, or server metadata.

## Compatibility impact

No protobuf field, SQLite schema, Message persistence format, or inbound OpaqueId rule changes. Existing unsigned Messages remain structurally valid; authenticity verification is an explicit security operation.

## Migration strategy

No durable migration is required. Consumers that require authenticated Message authorship resolve a trusted signing descriptor through their key-lifecycle layer and call the verifier. Existing unsigned or unverifiable historical Messages must not be retrospectively claimed authentic.

## Testing strategy

Required evidence includes a stable cross-language SHA-256 golden vector, canonical relation/extension order invariance, authored-field mutation sensitivity, delivery/provider/signature-field exclusion, valid Ed25519 verification, content tamper rejection, wrong-key rejection, key-ID mismatch, author-device mismatch, malformed trusted descriptor rejection, and stable canonical error categories.

## Rejected alternatives

- Sign protobuf serialization bytes: rejected because unknown fields/library encoders can create language/version drift.
- Sign the complete persisted Message struct: rejected because delivery state and provider mappings are runtime/integration results, not authored content.
- Trust the `key_id` embedded in Message metadata: rejected because an identifier is not a trust decision.
- Resolve keys inside the verifier: rejected because provisioning/lifecycle/revocation are separate trust boundaries.

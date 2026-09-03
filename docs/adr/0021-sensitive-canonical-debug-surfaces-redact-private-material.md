# ADR-0021: Sensitive canonical Debug surfaces redact private material

Status: Accepted

Date: 2026-09-03

## Context

The threat model already forbids plaintext messages, decrypted attachments, recovery secrets, and authentication secrets from telemetry, and requires diagnostics to expose only the minimum data needed for their declared purpose. The Rust reference model had partial protection: `OpaqueId`, `CommandEnvelope`, `ProtocolExtension`, Anti-Entropy cursors, endpoint addresses/external bindings, sync resume tokens, and recovery packages already used custom redacted `Debug` implementations.

Other canonical types still derived `Debug` over fields that may contain private or payload-derived material. In particular, direct formatting could expose correlation idempotency keys, Event payload/integrity bytes, Event fingerprints, Message plaintext, external provider message IDs, Message crypto metadata/signatures, Communication Intent payloads, and private routing/policy constraints. Relying on every caller or logger to remember which fields to suppress creates a second privacy policy outside the canonical owner.

## Decision

Sensitive canonical Rust model types own their ordinary `Debug` redaction. `CorrelationContext`, `EventEnvelope`, `EventFingerprint`, `ExternalMessageMapping`, `MessageCryptoMetadata`, `MessageSignature`, `MessageEnvelope`, `IntentConstraints`, and `CommunicationIntent` use explicit `Debug` implementations instead of derived field dumps.

Plaintext, idempotency keys, opaque provider IDs, integrity/crypto/signature bytes, payload-derived fingerprints, and private Intent policy values are replaced by stable `<redacted>` or `<opaque>` markers. Lengths, presence booleans, safe enum/type metadata, and already-redacted canonical IDs remain available where useful for diagnostics. Nested `ProtocolExtension` values continue to expose extension names/criticality while redacting extension payload bytes.

This decision is classification-driven rather than type-driven. Public key bytes remain public material and are not redacted merely because they are represented as bytes. Explicit authorized diagnostic tooling may intentionally expose otherwise redacted material through a purpose-specific path; ordinary `Debug` is not that path.

## Consequences

An ordinary `format!("{value:?}")`, generic logger, assertion failure, or crash diagnostic using these model types no longer receives the covered private material by default. Redaction composes through Message/Event/Intent envelopes because their sensitive nested types are also safe when formatted independently.

This ADR changes no protobuf field, canonical semantic equality, storage layout, persistence behavior, cryptographic algorithm, or transport contract. It also does not close the broader threat-model blocker for secret/plaintext telemetry regression testing: real telemetry, tracing, crash-report, and integration pipelines still require end-to-end evidence before that blocker can be removed.

## Rejected alternatives

- Redact only in one logging framework: rejected because every other `Debug` consumer would remain a leak path.
- Keep derived `Debug` and document "do not log": rejected because privacy must fail safe at the canonical owner instead of relying on caller discipline.
- Redact only top-level Message/Event/Intent envelopes: rejected because nested sensitive types can be logged directly.
- Hide every byte vector, including public keys: rejected because classification, not representation type, determines confidentiality.
- Remove the telemetry blocker after these unit tests: rejected because model-level `Debug` evidence is not end-to-end telemetry/crash-report evidence.

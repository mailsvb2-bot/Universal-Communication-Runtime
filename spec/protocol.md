# UCR Protocol v0 — foundational contract

Status: **Experimental / Phase 0**

Normative detail documents include `framing.md`, `negotiation.md`, `errors.md`, `identity-addressing.md`, `principal-actor-device.md`, `tenant-scope.md`, `permissions.md`, `commands-events.md`, and `local-storage.md`.

## 1. Namespaces and versioning

Stable canonical identifiers use `ucr.*`. Experimental extensions use `experimental.*`. Vendor and organization extensions use `vendor.<name>.*` and `organization.<id>.*`.

Every protocol envelope carries an explicit schema/protocol version. Runtime response envelopes such as `CommandReceipt` and `AcknowledgementEnvelope`, negotiation Hello/Result, and public Capability descriptors preserve their version/extension boundary in both protobuf and the Rust reference implementation. `ProtocolExtension` is the single payload-bearing Rust extension value; a payload-less parallel extension model is forbidden. Unknown optional extensions are tolerated according to the enclosing schema. Unknown critical extensions fail explicitly when support is evaluated.

## 2. Canonical IDs and scope

IDs are opaque protocol values. Their meaning must not be inferred from phone numbers, emails, IP addresses, hostnames, provider IDs, or server database sequences. Canonical IDs are generated offline; the concrete generation algorithm remains a separate ADR decision.

The public `ucr.v1.OpaqueId.value` field remains protobuf `bytes` in v1, but its semantic domain is explicit: an ID is an exact, non-empty UTF-8 token whose encoded length is at most 128 bytes. Semantic decoding rejects invalid UTF-8 and over-budget values. Implementations MUST preserve the exact UTF-8 bytes and MUST NOT normalize Unicode, case-fold, trim, transliterate, or otherwise rewrite an ID. Distinct byte sequences remain distinct opaque IDs even when they could render similarly.

The Rust reference `OpaqueId` is the single representation owner and exposes semantic wire-byte decode/encode without creating a second binary-ID model. A future decision to admit arbitrary non-UTF-8 IDs requires an explicit versioned compatibility/storage/fingerprint ADR; protobuf syntactic ability to carry arbitrary bytes is not by itself canonical validity.

Security-sensitive envelopes carry `tenant_id`; namespace is explicit where additional separation is required. Tenant scope is never inferred from transport metadata.

## 3. Command/Event boundary

A `Command` requests an action. An accepted command is not evidence that its requested real-world effect happened. An `Event` records a fact in UCR state.

Commands and events carry correlation/idempotency data for effectively-once user experience without claiming universal exactly-once execution.

## 4. Communication Intent

Communication Intent is a first-class primitive. External consumers express target, payload, policy constraints, correlation, and protocol extensions; they do not control the internal routing graph. The optional `privacy_profile` is preserved as an opaque string at the public boundary so unknown future profiles are not silently discarded. Transport capability allow/forbid constraints are namespaced, bounded, duplicate-free, and contradictory declarations fail closed.

Ordinary Rust `Debug` output for a Communication Intent redacts its payload, idempotency key, extension payloads, transport capability values, privacy/region values, and cost/priority values. Diagnostics retain only non-sensitive structure such as counts, presence flags, and payload length.

## 5. Framing

The canonical byte-stream frame is specified in [framing.md](framing.md). Framing is versioned independently from message schema and fails closed on unsupported reserved flags or unsafe lengths.

## 6. Negotiation

Version, capability, and extension negotiation is specified in [negotiation.md](negotiation.md). Parameter negotiation is not authentication; production handshake must cryptographically bind the transcript using reviewed primitives.

## 7. Error semantics

Canonical machine-readable errors are specified in [errors.md](errors.md) and `proto/ucr/v1/errors.proto`. External failures map into canonical categories; diagnostics do not become canonical branching logic.

## 8. Compatibility

Stable public fields are not removed or repurposed without versioning. Critical unsupported extensions fail explicitly. The public contract is protobuf under versioned package `ucr.v1`; Rust structs are the reference implementation, not the source of protocol truth.

## 9. Local storage

Local persistence follows [local-storage.md](local-storage.md). Storage is capability-specific, local-first, explicit on failure, and not a public database API. Durable command acceptance returns Accepted only after commit.

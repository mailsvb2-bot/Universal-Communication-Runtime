# UCR Protocol v0 — foundational contract

Status: **Experimental / Phase 0**

Normative detail documents include `framing.md`, `negotiation.md`, `errors.md`, `identity-addressing.md`, `principal-actor-device.md`, and `tenant-scope.md`.

## 1. Namespaces and versioning

Stable canonical identifiers use `ucr.*`. Experimental extensions use `experimental.*`. Vendor and organization extensions use `vendor.<name>.*` and `organization.<id>.*`.

Every protocol envelope carries an explicit schema/protocol version. Unknown optional extensions are tolerated according to the enclosing schema. Unknown critical extensions fail explicitly.

## 2. Canonical IDs and scope

IDs are opaque protocol values. Their meaning must not be inferred from phone numbers, emails, IP addresses, hostnames, provider IDs, or server database sequences.

Security-sensitive envelopes carry `tenant_id`; namespace is explicit where additional separation is required. Tenant scope is never inferred from transport metadata.

## 3. Command/Event boundary

A `Command` requests an action. An accepted command is not evidence that its requested real-world effect happened. An `Event` records a fact in UCR state.

Commands and events carry correlation/idempotency data for effectively-once user experience without claiming universal exactly-once execution.

## 4. Communication Intent

Communication Intent is a first-class primitive. External consumers express target, payload, and policy constraints; they do not control the internal routing graph.

## 5. Framing

The canonical byte-stream frame is specified in [framing.md](framing.md). Framing is versioned independently from message schema and fails closed on unsupported reserved flags or unsafe lengths.

## 6. Negotiation

Version, capability, and extension negotiation is specified in [negotiation.md](negotiation.md). Parameter negotiation is not authentication; production handshake must cryptographically bind the transcript using reviewed primitives.

## 7. Error semantics

Canonical machine-readable errors are specified in [errors.md](errors.md) and `proto/ucr/v1/errors.proto`. External failures map into canonical categories; diagnostics do not become canonical branching logic.

## 8. Compatibility

Stable public fields are not removed or repurposed without versioning. Critical unsupported extensions fail explicitly. The public contract is protobuf under versioned package `ucr.v1`; Rust structs are the reference implementation, not the source of protocol truth.

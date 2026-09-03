# ADR-0020: Message, Intent, and Error wire parity with Message extension storage

Status: Accepted

Date: 2026-09-03

## Context

The public `ucr.v1` contract already carried fields that the Rust reference implementation could not fully represent. `MessageEnvelope.extensions` were absent from the canonical Rust Message and therefore from durable Message comparison/storage. `CommunicationIntent` omitted public `correlation` and `extensions`, while `IntentConstraints.privacy_profile` narrowed an optional wire string into one closed Rust enum. `ErrorEnvelope.extensions` had no wire-faithful Rust owner, and typed `CanonicalErrorCode` alone could not preserve an unknown future protobuf enum value.

The public Message schema marks `author_device` optional at the protobuf presence layer, while the Phase-9 canonical Message contract requires an author Device. Wire optionality must not silently weaken the semantic invariant.

## Decision

`MessageEnvelope` carries canonical `ProtocolExtension` values in Rust. Shared extension namespace, duplicate-name, count, and payload limits apply before durable persistence. Extension ordering is non-semantic and canonicalized lexically by name; changed extension semantics under the same scoped Message ID are a conflict.

SQLite schema v10 adds one normalized `message_extensions` child table keyed to the canonical Message. Existing v9 Message rows migrate with no extension rows, which exactly represents the empty extension set that the pre-v10 Rust model could express. The v9-to-v10 migration is a distinct transaction and historical migrations retain their exact intermediate schema versions.

`CommunicationIntent` preserves the public correlation and extension fields. Intent transport constraints are bounded, namespaced, duplicate-free, and may not place the same capability in both allowed and forbidden sets. `privacy_profile` is preserved as `Option<String>`; absence and unknown future strings are representable rather than collapsed into a closed enum. This ADR does not add durable Intent storage.

The Rust public `ErrorEnvelope` preserves the protobuf error code as raw `i32`, retry metadata, diagnostic domain, and protocol extensions. Code zero/UNSPECIFIED is invalid. Unknown future non-zero values remain failures and retain their raw numeric value. Conversion from a known `CanonicalError` creates an extension-empty base response and does not infer diagnostic or extension semantics.

Canonical Message semantic decoding still requires an author Device. A missing protobuf `author_device` is a semantic decode failure; the Rust model is not weakened to `Option<DeviceRef>` merely because protobuf field presence is optional.

## Consequences

Message duplicate/conflict behavior is wire-complete across memory and restart-safe SQLite persistence. Corrupt/noncanonical Message extension rows fail store verification on reopen. Command, Event, and Message extension loaders enforce the shared count budget while iterating persisted rows instead of accumulating an unbounded corrupt extension set first. Intent policy evaluation can receive the complete public Intent instead of a lossy projection. Error handling remains forward-compatible with unknown failure codes without making unknown values successful.

SQLite advances from schema v9 to v10. No existing Message row is rewritten, and no v9 data is assigned semantics that the older implementation could not represent.

## Rejected alternatives

- Store Message extensions inside the existing Message row as an opaque blob: rejected because storage must not become a second private protocol.
- Treat missing v9 extension rows as unknown rather than empty: rejected because the old Rust Message type could only represent an empty extension set.
- Make canonical `author_device` optional: rejected because that weakens the accepted Phase-9 Message contract instead of interpreting wire presence correctly.
- Convert `privacy_profile` into the existing `SecurityProfile` enum: rejected because unknown public string values would be lost.
- Decode `ErrorEnvelope.code` directly into `CanonicalErrorCode`: rejected because unknown future protobuf values would be unrepresentable.
- Add Intent persistence in this change: rejected because persistence lifecycle/idempotency requires a separate storage contract and evidence set.

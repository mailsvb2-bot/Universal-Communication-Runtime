# ADR-0019: Negotiation and capabilities use one payload-bearing extension model

Status: Accepted

## Context

The public `ucr.v1.Extension` contract contains `name`, `critical`, and opaque `payload`. Before this hardening pass, Rust negotiation used a second `ExtensionDescriptor` containing only `name` and `critical`. `PeerHello` therefore discarded extension payload semantics. Public protobuf `Capability` also carried repeated extensions while Rust `CapabilityDescriptor` omitted them, and protobuf `NegotiationResult.extensions` had no wire-faithful Rust envelope owner.

This was security-relevant because Phase 7 authenticates exact Hello/Result frame bytes. A semantic implementation that drops extension payloads before policy/validation can reason about a different object from the one whose bytes are authenticated.

## Decision

`ProtocolExtension` is the single Rust owner for payload-bearing protocol extensions. The payload-less `ExtensionDescriptor` is removed. `PeerHello`, public Capability descriptors, NegotiationResult, CommandReceipt, Event/Command envelopes, and generic acknowledgements all use the same extension value type.

Public `CapabilityDescriptor` carries canonical protocol extensions. Endpoint validation therefore validates nested capability extension namespace, duplicate-name, count, and payload budgets instead of validating only the capability ID.

Capability negotiation continues to select capability identity and maturity only. Optional capability-level extensions are validated but are not implicitly copied into the negotiated capability result. Until an explicit capability-extension negotiation rule exists, any critical capability-level extension fails negotiation as unsupported rather than being silently ignored or treated as agreed.

Top-level Hello extensions are canonicalized and budget-checked for both peers before parameter negotiation. Unsupported critical remote Hello extensions continue to fail through the explicit locally-supported-extension allowlist. Full opaque payload bytes are retained in the Rust Hello model.

`NegotiationResultEnvelope` is a distinct wire-faithful Rust response type containing selected version, capabilities, response extensions, deprecated transcript-binding bytes, and crypto suite. Canonical results require the deprecated transcript-binding field to remain empty. Base results derived from `NegotiatedSession` do not infer or copy response extensions.

## Consequences

Rust no longer has a second payload-less extension brain for public negotiation. Endpoint Capability and runtime negotiation structures preserve the fields already promised by protobuf. Resource-limit and malformed-extension failures use stable canonical error categories.

The implementation deliberately does not invent capability-extension parameter merging. Optional nested extension metadata may be carried by an advertised Capability but is not automatically part of the negotiated capability. Critical nested metadata blocks negotiation until a governed rule defines how it is understood and agreed.

## Rejected alternatives

- Keep `ExtensionDescriptor`: rejected because it silently truncates the public Extension value.
- Ignore Capability extensions in Rust: rejected because EndpointDescriptor and negotiation would remain wire-incomplete.
- Automatically copy remote Capability extensions into the negotiated result: rejected because receipt of metadata is not agreement to its semantics.
- Infer NegotiationResult extensions from either Hello: rejected because no canonical selection rule currently defines that transformation.
- Accept critical Capability extensions while dropping them from negotiated state: rejected because must-understand semantics require fail-closed behavior.

# ADR 0100: Public API compatibility is versioned and conformance-gated

Status: Accepted

## Context

The Canon requires old/new interoperability, explicit version negotiation, Stable API discipline and a support window before 1.0.

## Decision

The stable public contract is the versioned language-independent `ucr.v1` protocol. Stable fields are not removed, repurposed or given incompatible semantics inside v1. Additive optional fields/extensions must preserve unknown-field/optional-extension behavior; unsupported critical extensions fail explicitly.

When a future `ucr.v2` becomes Stable, the immediately previous Stable major remains a supported compatibility target for at least the published v2 deprecation window. Removing that support requires a declared breaking version, migration guidance and a superseding ADR.

Rust ABI is never the public compatibility contract. SDKs are thin clients and must pass the language-independent Conformance Suite for their claimed stable contract.

## Consequences

A green Rust build cannot substitute for protocol compatibility evidence. Breaking Stable SDK/protocol behavior without declared versioning remains release-blocking.

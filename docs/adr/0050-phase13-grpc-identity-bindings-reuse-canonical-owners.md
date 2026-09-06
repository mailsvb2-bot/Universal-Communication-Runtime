# ADR-0050: Phase-13 gRPC Identity bindings reuse canonical owners

Status: Accepted
Date: 2026-09-06

## Context

ADR-0049 introduced the first concrete Tonic binding for `IntegrationService.SubmitCommand` while
keeping `IntegrationIngress` and the existing durable stores authoritative. The public protobuf service
already exposes four Identity-facing operations: `CreateIdentity`, `GetIdentity`, `LinkIdentity`, and
`ResolveIdentityBinding`. Their transport-neutral semantics, permissions, audit attribution, validation,
conflict rules, non-disclosing reads, and durable owners already exist in Core.

Leaving those RPCs generated but permanently `UNIMPLEMENTED` would withhold already-defined public
capability. Implementing them in the adapter must not create a parallel Identity mapping layer, normalize
opaque provider identifiers, weaken the Service Principal gate, or invent gRPC-specific errors.

## Decision

Bind the four Identity-facing gRPC methods in `ucr-api-grpc`. Each method decodes only the checked-in
protobuf shape, reads the same sensitive binary Service Principal metadata introduced by ADR-0049, and
delegates to the existing `IntegrationIngress`. No second Identity, authorization, audit, quota, or storage owner is introduced.

`CreateIdentity` and `GetIdentity` reuse the canonical `IdentityStore` path. `LinkIdentity` and
`ResolveIdentityBinding` reuse the canonical `ExternalIdentityBindingStore` path; resolution constructs
only the existing borrowed `ExternalIdentityBindingLookup` parameter bundle. The adapter neither gains
raw store access nor defines a provider-specific customer/contact table.

Protobuf `IdentityOwnership` and `IdentityEvidence` values are structural wire enums. `UNSPECIFIED` and
unknown numeric values map to canonical `INVALID_ARGUMENT` before persistence; known values map exactly
to the model enums. This is mapping, not a new validation authority: canonical record/key validation,
idempotency, conflict detection, missing-target checks and durable semantics remain in the existing owners.

`external_entity_id` stays an opaque byte sequence end-to-end. The adapter performs no UTF-8 conversion,
case folding, Unicode normalization, provider parsing, or application-level interpretation.

Canonical failures remain method-specific response-envelope errors. Authenticated/authorized absence for
reads is canonical `NOT_FOUND`; permission/authentication failure happens before existence disclosure. The
six remaining Integration RPCs continue to return gRPC `UNIMPLEMENTED` until separately bound and tested.

## Consequences

- Identity create/get and external binding link/resolve are usable over real Tonic HTTP/2 framing.
- Service Principal credential ID/secret stay outside protobuf bodies and durable Identity data.
- Existing `IdentityStore` and `ExternalIdentityBindingStore` remain the only durable owners.
- Equal create/link retries retain existing idempotent semantics; semantic identity reuse remains `CONFLICT`.
- Unauthorized reads cannot become an existence oracle merely because a gRPC transport exists.
- Opaque external entity bytes survive link/resolve bit-for-bit.
- No SQLite migration, permission change, audit-schema change, protobuf field change, Identity model change,
  or provider-specific normalization is required.

## Required evidence

The reference binding must prove over a real loopback gRPC client/server that:

1. create → retry → get returns the same canonical Root Identity;
2. reusing the same scoped `IdentityId` with changed semantics returns canonical `CONFLICT`;
3. link → retry → resolve returns the same binding and preserves non-UTF-8 external entity bytes exactly;
4. permission denial and an invalid credential secret cannot create ghost Root Identity state;
5. unauthorized Identity lookup does not distinguish present from absent, while authorized absence is `NOT_FOUND`;
6. protobuf `UNSPECIFIED` and unknown Identity enum values are `INVALID_ARGUMENT` and leave no ghost state;
7. a valid retry of the same Identity after malformed requests succeeds;
8. the unbound-RPC count is exactly six and an unbound method still returns gRPC `UNIMPLEMENTED`;
9. generated protobuf code is the only handwritten-Clippy exemption and Core remains free of Tonic/Prost;
10. normal debug/release, RustSec, fuzz, architecture, protocol, memory and SQLite gates remain green.

## Non-claims

This ADR does not add Identity listing/search, merge/delete, evidence transitions, expiry execution,
external-binding unlink/relink, Persona/Profile, provider account models, HTTP/local IPC/SDK packages,
production listener/TLS policy, Phase-14 Event API, Phase-15 Internet Transport, routing, delivery,
Attachments, Calls, or provider bridges. It does not bind the six remaining Integration RPCs.

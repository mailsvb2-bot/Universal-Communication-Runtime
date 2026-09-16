# ADR-0078: Phase 40 Reference Messenger is a public-API consumer

- Status: Accepted
- Date: 2026-09-16
- Phase: 40 — Reference Messenger

## Problem

The Canon requires a Reference Messenger that proves chat, groups, calls, multi-device, local, offline, P2P, recovery and accessibility. The repository already implements many of those capabilities internally, but not every canonical owner has a consumer-facing public service.

Using internal Rust crates to make the Reference Messenger appear complete would violate the Canon rule `Reference UI → Public UCR API → UCR`, create privileged product access and hide public-contract gaps from third-party consumers.

## Decision

The Reference Messenger is a standalone external-consumer crate outside the internal Core workspace. Its only UCR dependency is `ucr-sdk`.

Phase 40 keeps a machine-readable-in-code proof matrix. A capability is marked `PublicApiAvailable` only when a versioned consumer-facing service exists. Missing public surfaces remain `PublicApiGap`; presentation requirements without platform evidence remain `PresentationModelOnly`.

The existing public `CallService` is added to the Rust SDK facade using the same Service Principal binary metadata and the same transport message ceiling as Integration/Event services. No wire schema or canonical Call semantics are redefined.

## Consequences

The first Phase-40 slice can honestly exercise public chat and call surfaces while refusing hidden shortcuts for Groups, Sync, local/P2P transport, Store-and-Forward and Recovery.

Closing a remaining gap may require a new public service adapter, but that adapter must be thin and delegate to the existing canonical owner. A Reference Messenger feature may not justify a new product-specific Core branch.

## Rejected alternatives

### Import internal Chat/Group/Storage crates directly

Rejected because the Reference Messenger would gain authority unavailable to ordinary consumers and would cease to prove the public contract.

### Treat protobuf message definitions as an executable public API

Rejected because serializable types alone do not provide an authenticated consumer operation boundary.

### Mark internal implementation as Reference Messenger proof

Rejected because the Canon requires proof through the Reference Client boundary, not proof that lower layers exist.

## Security and privacy impact

The Reference Messenger gains no direct database, credential-store, policy-engine or tenant-isolation bypass. Service Principal credentials stay in gRPC metadata through `ucr-sdk`, and canonical response/error envelopes remain unchanged.

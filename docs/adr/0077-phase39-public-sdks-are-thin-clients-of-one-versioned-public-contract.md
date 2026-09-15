# ADR-0077: Phase 39 Public SDKs are thin clients of one versioned public contract

- Status: Accepted
- Date: 2026-09-15
- Phase: 39 — Public SDKs

## Problem

UCR needs Rust, Python, TypeScript, Kotlin and Swift SDKs without allowing each language to become a second communication brain.
Language convenience must not fork canonical models, policy, authorization, routing, retry or error semantics.

## Existing state

`ucr.v1` protobuf files already define the language-independent public contract.
`IntegrationService` exposes the external command/Identity/Conversation/Message/Intent boundary.
`EventService` exposes durable Event publication and consumption.
The Rust gRPC server binding already authenticates Service Principals with binary metadata outside protobuf bodies.

## Decision

Phase 39 treats SDKs as generated public-contract clients plus thin language-specific transport/authentication helpers.
The checked-in `.proto` files remain the source of wire truth.
The Rust SDK generates clients with server generation disabled, has no Core or storage dependency, and is built as a standalone external-consumer package rather than an internal workspace member.
All language surfaces use the same credential metadata keys and keep Event cursors opaque.
SDKs do not automatically retry UCR application operations.
A channel may reconnect, but an operation is resubmitted only when the caller explicitly chooses a retry allowed by canonical semantics.
Canonical `ErrorEnvelope`, acknowledgement, Delivery evidence and Event cursor semantics are never upgraded by SDK convenience code.

## Rejected alternatives

### Hand-written domain models per language

Rejected because they drift from protobuf and recreate Identity/Message/Delivery semantics outside the protocol owner.

### Rust ABI / FFI as the primary SDK contract

Rejected because the Canon requires a language-independent public contract rather than a Rust ABI dependency.

### SDK-owned retry and offline queue

Rejected because retry, Durable Delivery and offline state already have canonical owners and provider acceptance may be ambiguous.

## Security and privacy impact

Credentials remain outside protobuf payloads and secrets are redacted from SDK diagnostics.
SDKs gain no direct database access, tenant bypass, hidden API or provider credential authority.
The transport ceiling is a resource guard only and does not relax canonical semantic limits.

# ADR 0082: Phase-40 Local Transport service reuses the Phase-16 provider

## Context

The Canon requires the Reference Messenger to prove local/direct communication exclusively through the public UCR boundary. Phase 16 already owns a Prepared `LocalTransportProvider`/`LocalTransportServer` with local-address admission, authenticated handshake, bounded reconnect, deterministic attempt identity and transport-only acceptance evidence. Linking the Reference Messenger to that crate would violate Public Contract First.

## Decision

Add one versioned `LocalTransportService.Transmit` RPC. The gRPC binding accepts only exact scope, destination endpoint, transient `EndpointAddress` and an already-encrypted envelope; it fixes the capability to `ucr.transport.local.tcp` rather than exposing provider selection.

The binding performs the existing Service Principal authentication/quota/audit/authorization flow using `ucr.transport.local.use` before invoking the provider. It delegates the network operation to the existing `TransportProvider::transmit_classified` implementation through `spawn_blocking`. `NotAccepted` and `AcceptanceUnknown` remain explicit public failure evidence.

The SDK and Reference Messenger are thin clients only. They do not create listeners, discover peers, rank routes, retry application work, fall back to Internet/Relay, or reinterpret transport acceptance as Delivery/Read success.

## Rejected alternatives

Directly importing `ucr-transport-internet` from Reference Messenger is rejected because it bypasses the public contract. Creating a second local transport in the gRPC/SDK layer is rejected because it creates a second communication brain. Exposing arbitrary transport capability selection is rejected because it turns this narrow Local proof into a provider dispatcher and bypasses Phase-24 orchestration ownership.

## Consequences

Phase 40 can mark Local as `PublicApiAvailable` only with executable gRPC-to-real-loopback-provider evidence. P2P/mesh, Recovery and concrete accessibility remain explicit gaps.

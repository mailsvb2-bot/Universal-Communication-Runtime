# Phase 40 — Local Transport public API

## Status

**Prepared external-consumer adapter** over the existing Phase-16 local/direct transport owner. It is not a new transport implementation and does not make Phase 40 complete.

## Canonical ownership

`LocalTransportService` delegates one explicit direct transmit to the existing `LocalTransportProvider`, which remains the owner of local-address admission, authenticated handshake, deterministic attempt identity, bounded reconnect and encrypted transport receipt validation. The service does not own Message, Delivery, Endpoint discovery, route planning or retry policy.

The public client supplies an exact `TenantScope`, destination `EndpointId`, one transient canonical `EndpointAddress` and an already-encrypted envelope. The public request cannot choose a transport capability: the binding fixes `ucr.transport.local.tcp`. This is an explicit direct-route operation, not Phase-24 route planning.

## Service Principal boundary

Before any network side effect the binding authenticates, rate-limits, audits and authorizes `ucr.transport.local.use` for the exact scope. Audit metadata uses `ucr.transport.local.transmit` plus the destination endpoint ID. Authentication, quota or permission failure is classified as `NOT_ACCEPTED` and never invokes the provider.

## Execution and failure evidence

The synchronous Phase-16 provider runs through `spawn_blocking` so its bounded socket/reconnect work does not block the async gRPC executor. No retry is added above the provider, and the SDK/Reference Messenger add no hidden retry or fallback.

Success means only authenticated peer-side transport acceptance/deduplication. It is not `DELIVERED`, presented-to-user, read, or business-effect evidence. Provider failures preserve the canonical `NotAccepted` versus `AcceptanceUnknown` distinction so an external consumer cannot assume that an ambiguous failure is safe to replay.

The existing Phase-16 provider still rejects public Internet, CGNAT, multicast, unspecified, documentation and DNS routes before connection establishment. The public adapter does not duplicate or weaken that policy.

## Nonclaims

This API does not add peer discovery, mDNS/Bonjour, listener lifecycle, Wi-Fi Direct/hotspot control, Bluetooth, mesh/multi-hop P2P, NAT traversal, route ranking, cross-route failover, Relay, QUIC or firewall automation. P2P, Recovery and concrete platform accessibility remain separate Phase-40 proof work.

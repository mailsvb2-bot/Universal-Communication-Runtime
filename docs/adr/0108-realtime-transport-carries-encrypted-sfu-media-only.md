# ADR 0108: Realtime transport carries encrypted SFU media only

Status: Accepted

## Context

The SFU core already validates and forwards endpoint-encrypted MLS media but intentionally had no public production transport. Browser/mobile clients and remote deployments require a stable external boundary.

## Decision

`ucr.v1.RealtimeService` owns only authenticated realtime session liveness and transport of `SfuForwardEnvelope`. It never owns Call membership, Group membership, authorization policy, MLS keys, media plaintext, Delivery/Read evidence or recording.

Production remote bindings must terminate authenticated TLS and use bounded per-session queues with explicit backpressure. The existing plaintext daemon remains loopback-only. HTTP streaming/SSE and future WebRTC/ICE/TURN are transport-provider choices over the same service semantics, not separate communication cores.

Successful join/leave/reconnect/media-ready transitions append canonical EventEnvelope attendance events; heartbeats are liveness input rather than mandatory durable events.

## Consequences

A production gateway can scale independently while SFU security/authorization remains canonical. Browser/mobile transports can evolve without forking Conference semantics.

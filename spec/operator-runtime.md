# Operator Runtime Health API

Status: **private loopback operator contract introduced**.

The operator health surface is deliberately separate from the Universal Conference integration API.
It reports infrastructure/readiness evidence for the UCR deployment and is not a tenant or
integration capability endpoint.

## Access boundary

`ucr.v1.OperatorRuntimeService` is served only by the loopback `ucr-runtime` daemon. A public
HTTPS/WebRTC gateway MUST NOT forward or expose this service. Integration service credentials do not
grant operator access, and the operator response contains no tenant objects, participant identities,
join tokens, webhook secrets, TURN credentials, media keys, message plaintext or other business data.

## Components

`GetHealth` reports bounded status for:

- API: healthy when the private gRPC operator service is serving the request;
- storage: mapped from the canonical durable storage health check;
- SFU/realtime transport: available only when the live WebRTC provider backing the encrypted SFU
  path is running;
- TURN: `not_configured` when absent and `unverified` when deployment configuration is valid but
  no independent network probe has proved relay reachability;
- webhook worker: `not_configured` until a continuous delivery worker is actually attached to the
  daemon; the existing one-shot dispatcher is not reported as a running worker;
- recorder: `not_configured` until a recording provider is attached;
- capacity: current authenticated realtime session count against the live WebRTC session ceiling.

The contract must fail closed rather than promote configuration into stronger health evidence. In
particular, valid TURN configuration is not equivalent to TURN network health.

## Capacity

Capacity is ephemeral operator state. It is not a quota, billing counter, participant attendance
projection or durable Conference authority. Expired realtime sessions are pruned before the active
count is reported. When active sessions reach the live WebRTC ceiling, capacity is degraded rather
than falsely claiming the runtime is down.

## Product boundary

This API has no CRM, webinar-business, payment, ClientPlatform or other product-specific semantics.
External products continue to use the Universal Communication integration contract; operators use
this private surface to decide whether the deployment can safely accept realtime traffic.

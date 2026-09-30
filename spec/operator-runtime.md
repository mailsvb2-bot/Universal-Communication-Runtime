# Operator Runtime Health API

Status: **private loopback operator contract introduced**.

The operator health surface is deliberately separate from the Universal Conference integration API.
It reports infrastructure/readiness evidence for the UCR deployment and is not a tenant or
integration capability endpoint.

## Access boundary

`ucr.v1.OperatorRuntimeService` is served only by the loopback `ucr-runtime` daemon on a **separate
operator listener** from the public/integration upstream. The CLI defaults that private listener to
`127.0.0.1:50052` via `--operator-bind`; `--bind` remains the public API/realtime upstream that a TLS
edge may proxy. The runtime rejects an explicit nonzero operator bind equal to the public bind.
Because `ucr-https-edge` is intentionally a raw TLS-to-loopback byte proxy, this socket separation is
the enforcement boundary: a public HTTPS/WebRTC gateway MUST NOT point at or forward the operator
listener. Integration service credentials do not grant operator access, and the operator response
contains no tenant objects, participant identities,
join tokens, webhook secrets, TURN credentials, media keys, message plaintext or other business data.

## Components

`GetHealth` reports bounded status for:

- API: healthy when the private gRPC operator service is serving the request;
- storage: mapped from the canonical durable storage health check;
- SFU/realtime transport: available only when the live WebRTC provider backing the encrypted SFU
  path is running;
- TURN: `not_configured` when absent and `unverified` when deployment configuration is valid but
  no independent network probe has proved relay reachability;
- webhook worker: derived from the durable SQLite worker lease. An active unexpired lease is
  `healthy`; an expired lease is `unavailable`; absence is `not_configured`. The holder ID is
  never exposed. The existing one-shot dispatcher does not acquire the worker lease and therefore is
  never reported as a running continuous worker;
- recorder: `not_configured` until a recording provider is attached;
- capacity: current authenticated realtime session count against the live WebRTC session ceiling.

The contract must fail closed rather than promote configuration into stronger health evidence. In
particular, valid TURN configuration is not equivalent to TURN network health. Webhook worker health
is also not inferred from process configuration: only a currently unexpired durable lease is healthy.

## Horizontal SFU worker control

The same private loopback service now owns the prepared horizontal-SFU worker control plane:

- `HeartbeatSfuNode` registers or refreshes one bounded worker record with opaque node ID, deployment
  region, health/draining state, active/max session counters, a short lease TTL, and one validated
  private media `IP:port`;
- `DrainSfuNode` atomically marks a known worker draining so fresh placement stops selecting it while
  existing sticky placements may finish;
- `ListSfuNodes` returns only bounded infrastructure metadata and the absolute lease expiry.

Heartbeat TTL is bounded to 1–120 seconds and the in-process directory is capped at 256 workers.
The API daemon without realtime/SFU runtime returns `failed_precondition` instead of pretending the
cluster exists. This state is intentionally ephemeral: process restart requires workers to
re-register. Expired workers are pruned before heartbeat/list/drain operations, including any stale
sticky placements that referenced them, so bounded node capacity is reclaimed instead of leaking
across worker churn.

These operator RPCs do not expose Conference IDs, participants, tenant business data, join grants,
media keys, plaintext media, TURN credentials, or provider secrets. They also do **not** make the
public `horizontal_sfu` capability Production-ready. Concrete inter-node encrypted-media transport
and runtime placement/failover evidence remain required before that capability can become true.

## Capacity

Capacity is ephemeral operator state. It is not a quota, billing counter, participant attendance
projection or durable Conference authority. Expired realtime sessions are pruned before the active
count is reported. When active sessions reach the live WebRTC ceiling, capacity is degraded rather
than falsely claiming the runtime is down.

## Product boundary

This API has no CRM, webinar-business, payment, ClientPlatform or other product-specific semantics.
External products continue to use the Universal Communication integration contract; operators use
this private surface to decide whether the deployment can safely accept realtime traffic.

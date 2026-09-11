# Phase 24 Transport Orchestrator

## Scope

Phase 24 adds one Prepared/reference Transport Orchestrator above the existing provider-independent
`CommunicationIntent`, `PolicyEvaluator`, `EndpointDescriptor` and `TransportProvider` owners. It
builds a bounded transient route plan and can invoke the primary selected provider once. It does not
create a second transport implementation, durable routing graph, Delivery owner, retry queue, Relay,
or Automatic Failover.

The Canon-required decision inputs are represented explicitly: provider availability, RTT, jitter,
bandwidth, packet loss, cost, battery, thermal state, privacy, reliability, priority, recipient
reachability, device/Endpoint capabilities and policy. Availability is read from
`TransportProvider::health()` rather than accepted from an external caller. Recipient Identity,
address and device capability are validated against the existing `EndpointDescriptor`.

## Filtering before ranking

Hard constraints always run before preference scoring. A candidate is ineligible when its provider
is unavailable, the recipient is unreachable, its Endpoint does not belong to the Intent target
Identity, its exact address is not advertised by that Endpoint, the provider or Endpoint does not
advertise the route capability at Prepared/Beta/Production maturity, or the Intent allow/forbid,
privacy, region or maximum-cost constraints reject it. `PolicyEvaluator::Deny` and
`PendingNoAllowedRoute` fail closed before route ranking.

Candidate count is bounded to 64. Duplicate `(EndpointId, transport capability, exact opaque
address)` candidates are rejected rather than producing ambiguous ranking state.

## Deterministic ranking

After filtering, ranking considers provider health, RTT+jitter, packet loss, bandwidth, reliability,
cost and local resource pressure. Resource pressure combines route energy cost with the existing
bounded battery/thermal signal model. Canon P0/P1 or an `Urgent` hint favors latency/loss/reliability;
P6/P7 favors energy/cost; ordinary priorities favor reliability/loss before latency. `PreferLocal`
and `AvoidExpensive` are bounded preference hints only.

External hints are exactly `Urgent`, `PreferLocal`, and `AvoidExpensive`. They contain no EndpointId,
provider identifier, rank, edge, or arbitrary routing graph. Equal scores use a deterministic stable
tie-breaker internal to UCR. Public decisions expose EndpointId, transport capability and UCR-derived
rank, but never the opaque EndpointAddress.

## Execution and Phase 25 boundary

`transmit_primary` revalidates the route-relevant Intent binding and current policy, provider health,
and provider capability immediately before invoking `TransportProvider::transmit`. The
Runtime-to-Transport payload boundary is bounded by the existing 16 MiB framing ceiling.

The orchestrator invokes only the primary planned route. If that provider returns Timeout,
Unavailable, Rejected, or another canonical transport error, Phase 24 returns the error directly and
**does not try the next ranked route**. Provider-internal finite reconnect behavior remains owned by
the provider. Cross-provider automatic failover is Phase 25.

The plan may expose multiple ranked eligible routes for later phases, but Phase 24 does not execute
multipath delivery. This avoids claiming duplicate-free multipath or exactly-once semantics without
the Delivery/idempotency evidence required for those behaviors.

## Persistence and security

Route plans, telemetry, hints and resource snapshots are ephemeral. No SQLite migration is
introduced; schema remains v22. Endpoint addresses remain locator material and are redacted from
ordinary Debug/public route decisions. Route telemetry is not Identity, authorization, delivery or
security evidence. Peer-supplied CPU/battery/thermal claims must not replace local resource truth.

Phase 24 does not weaken E2EE, does not reinterpret transport acceptance as user delivery, and does
not let route selection grant authorization. Phase 25 Automatic Failover, Phase 27 Store-and-Forward,
Phase 28 Mesh is implemented separately for bounded signed Group Message propagation; Relay/NAT traversal, provider bridges and production discovery remain later owners.

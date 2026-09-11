# ADR-0062: Phase 24 Transport Orchestrator reuses canonical Intent, Endpoint, Policy and Transport owners

- Status: Accepted
- Scope: Phase 24 Prepared/reference Transport Orchestrator

## Context

The Canon makes Transport Orchestrator a central component and requires it to consider availability,
RTT, jitter, bandwidth, packet loss, cost, battery, thermal state, privacy, reliability, priority,
recipient reachability, device capabilities and policy. The Canon also states that external routing
hints such as urgent/prefer-local/avoid-expensive are not routing orders. Phase 25 separately owns
Automatic Failover.

## Decision

Add `ucr-transport-orchestrator` as an ephemeral planning/execution layer over the existing
`CommunicationIntent`, `PolicyEvaluator`, `EndpointDescriptor`, `RouteCandidate` and
`TransportProvider` boundaries. Hard policy/identity/capability/privacy/region/cost/reachability
constraints filter before ranking. Availability comes from the concrete provider itself. The
reference ranking is deterministic and bounded; hints can alter preference classes but cannot name
or order graph edges.

The selected plan is bound to the route-relevant canonical Intent fields. Primary execution
revalidates current policy, provider health/capability and the existing framing/backpressure ceiling.
It invokes one provider and returns that provider's canonical error directly. It never automatically
tries the next route; that behavior belongs to Phase 25.

Public route decisions omit EndpointAddress. Planning state and telemetry are not persisted. No
SQLite migration is introduced; schema remains v22.

## Rejected alternatives

1. Put route choice inside Internet/Local providers: rejected because each provider would become a competing routing brain.
2. Let external callers supply an ordered endpoint list: rejected because a routing hint is not a routing order.
3. Persist the ranking graph in Delivery or Intent rows: rejected because route plans are replaceable transient state and Intent outlives Transport.
4. Treat transport acceptance as Delivered: rejected because Delivery Evidence has distinct transport/device/user states.
5. Automatically try the second route on failure: rejected because Phase 25 owns Automatic Failover.
6. Execute multipath immediately: rejected until duplicate/effectively-once semantics have explicit cross-path evidence.
7. Let peer telemetry define local battery/thermal truth: rejected because untrusted measurements cannot become local resource authority.

## Evidence

Protocol tests lock bounded telemetry, hints, P0..P7 priority and candidate counts. Orchestrator tests
prove hard filtering before ranking, hint-vs-order separation, priority/resource trade-offs,
recipient/Identity/capability checks, stale-policy/backpressure revalidation and the explicit
single-primary/no-Phase-25 behavior. Public protobuf, architecture guards and bounded fuzzing keep
the boundary language-independent and fail closed.

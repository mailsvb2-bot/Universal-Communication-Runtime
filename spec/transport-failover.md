# Phase 25 Automatic Failover

## Scope

Phase 25 extends the existing Prepared Transport Orchestrator with bounded sequential cross-route
failover over the already-ranked `TransportPlan`. It does not create a second routing brain,
transport implementation, Delivery owner, durable retry queue, Offline Groups, Store-and-Forward,
Mesh, Relay, or exactly-once claim.

The Canon requires failover not to create duplicates. A canonical transport failure therefore carries
a minimum acceptance disposition: `NotAccepted` proves that no application envelope could have been
accepted by the peer; `AcceptanceUnknown` means acceptance cannot be ruled out. Providers that do not
implement this evidence explicitly default to `AcceptanceUnknown`.

## Duplicate-safe execution

A later route is eligible only after `NotAccepted`. `Timeout`, `Unavailable`, or any other error code
alone is insufficient evidence. If a provider may have sent application bytes or is waiting for an
authenticated receipt, a failure is `AcceptanceUnknown`; the failover executor stops immediately and
never invokes another route. This is intentionally conservative and does not promise exactly-once.

The Prepared Internet and Local TCP providers classify connect/configuration/handshake failures as
`NotAccepted`, because the application envelope has not started. Once encrypted envelope transmission
begins, subsequent send/receipt failures are `AcceptanceUnknown`. Their existing same-route reconnect
loop retains the deterministic transport attempt ID and receiver deduplication; Phase 25 does not
multiply that provider-owned retry loop.

## Bounds and authority revalidation

`TransportFailoverPolicy.max_route_attempts` is mandatory, non-zero, and capped at 64, matching the
bounded Phase-24 candidate plan. An optional absolute expiry deadline stops execution before a later
route is attempted. The existing Intent binding, payload ceiling, PolicyEvaluator decision, provider
health, and exact provider capability are revalidated at execution time. Policy denial, terminal
errors, attempt-budget exhaustion, or deadline expiry stop fail closed.

Unavailable or capability-disabled routes may be skipped without consuming a provider invocation.
Actual cross-route provider calls consume the attempt budget. Execution is sequential; Phase 25 does
not execute multipath delivery.

## Public decision and privacy

The public decision records only the existing redacted `TransportRouteDecision` plus an outcome and
final stop reason. It does not expose `EndpointAddress`, provider-private diagnostics, encrypted
payload bytes, or receipt material. Route telemetry remains non-authoritative ranking evidence.

## Persistence and later phases

Failover policy and decision state are ephemeral in Phase 25. No SQLite migration is introduced;
schema remains v22. Phase 26 Offline Groups, Phase 27 Store-and-Forward and Phase 28 Mesh remain separate owners; Relay/NAT
traversal and multipath execution remain later owners.

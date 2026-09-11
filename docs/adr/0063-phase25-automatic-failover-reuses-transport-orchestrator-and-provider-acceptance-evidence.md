# ADR-0063: Phase 25 Automatic Failover reuses Transport Orchestrator and provider acceptance evidence

## Status
Accepted

## Context
The Canon schedules Automatic Failover after Transport Orchestrator and requires failover not to
create duplicates. Canonical transport errors such as Timeout or Unavailable cannot by themselves
prove whether an application envelope was accepted, so blindly trying the next ranked route would
violate that requirement.

## Decision
Extend the existing `TransportProvider` boundary with conservative classified failure evidence:
`NotAccepted` or `AcceptanceUnknown`. The default implementation maps every ordinary provider error
to `AcceptanceUnknown`. Existing Internet and Local TCP providers prove `NotAccepted` only before
application-envelope transmission begins; after send begins, ambiguous failures remain unknown.

Add bounded sequential `transmit_with_failover` to the existing `ucr-transport-orchestrator`. It
reuses the Phase-24 ranked plan, canonical Intent/Policy/Endpoint/Transport owners and provider-owned
same-route reconnect/deduplication. A later route is invoked only after proven non-acceptance. Policy,
health, capability, deadline and attempt budget are rechecked. No second Delivery store, retry queue,
route graph, transport service, or exactly-once claim is introduced.

## Consequences
Failover is deliberately unavailable when a provider cannot prove non-acceptance. This may reduce
availability but preserves the Canon's duplicate-safety requirement. Public decisions remain
address-redacted. State is ephemeral and SQLite stays at schema v22. Phase 26 Offline Groups, Phase 27 Store-and-Forward, and Phase 28 Mesh are separate later owners and are not implemented by Phase 25.

## Rejected alternatives
1. Fail over on Timeout/Unavailable alone: rejected because acceptance can be ambiguous.
2. Treat all provider errors as retryable: rejected because policy/rejection/integrity failures are terminal.
3. Add a durable failover queue: rejected because Store-and-Forward is Phase 27.
4. Execute two routes concurrently: rejected because multipath duplicate semantics are not proven.
5. Claim exactly-once: rejected because the Canon explicitly forbids that claim without proof.

## Evidence
Phase-25 regression tests cover proven pre-accept failure, ambiguous acceptance, conservative legacy
provider defaults, bounded attempts, deadline expiry, policy changes, and terminal failure. Existing
Internet/Local transport tests continue to cover authenticated receipts, lost-receipt reconnect and
deduplication.

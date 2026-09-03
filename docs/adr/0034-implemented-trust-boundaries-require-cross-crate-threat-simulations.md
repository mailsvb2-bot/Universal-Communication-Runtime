# ADR-0034: Implemented trust boundaries require cross-crate threat simulations

Status: Accepted

## Context

The threat model requires explicit replay, MITM, forged-identity, malicious-tenant, malicious-peer, compromised-Bridge, invalid-permission, and revoked-Device scenarios. Many component unit tests already prove local invariants, but the Canon explicitly rejects counting a same-word unit test as threat-simulation evidence. At the same time, inventing a mock Bridge or transport that has no production implementation would create false confidence.

## Decision

A dedicated non-published workspace crate, `ucr-security-tests`, owns executable cross-crate threat simulations for implemented trust boundaries. It imports public UCR APIs rather than private test helpers and composes Core, Crypto, Protocol, Memory, and SQLite behavior across the relevant boundary. The crate contains no alternate runtime/security semantics; it is evidence only.

The initial suite covers durable replay across SQLite restart; MITM signature substitution at the authenticated-session boundary; valid-key/forged-Identity rejection through the Device→Identity resolver; cross-tenant mutation denial with storage-untouched evidence; malicious peer descriptor self-provision denial; ServiceAccount direct-runtime bypass denial without admission proof; permission-type confusion denial before storage; and revoked-Device denial of existing signatures and future trusted-key access.

The evidence matrix lives in `docs/architecture/THREAT_SIMULATIONS.md`. Architecture CI locks the crate membership, exact scenario set, cross-crate dependencies, matrix, and the continued absence of a claimed compromised-Bridge simulation while Bridge remains unimplemented. Normal workspace debug/release jobs execute the simulations automatically.

## Consequences

Security evidence now fails with the same CI as the runtime when a cross-boundary invariant regresses. A storage or crypto implementation cannot silently pass local unit tests while breaking the composed threat scenario. The generic threat-simulation release blocker can be narrowed to not-yet-implemented Bridge/remote-transport boundaries and future trust boundaries, rather than pretending already implemented boundaries have no executable evidence.

This ADR does not claim production network transports, Bridge, Relay, SFU, attachment processing, or remote peer integration. The MITM simulation is explicitly limited to the current local/reference authenticated-session boundary. A future Bridge/transport must add its own real negative simulations before Production maturity.

## Rejected alternatives

Count existing component unit tests by keyword: rejected because it violates the threat-model evidence rule. Duplicate security logic inside the test crate: rejected by the no-second-brain rule. Create placeholder Bridge/transport implementations only for tests: rejected as false evidence. Remove the threat-simulation blocker entirely: rejected because required unimplemented trust boundaries remain.

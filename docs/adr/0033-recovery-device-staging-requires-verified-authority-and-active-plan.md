# ADR-0033: Recovery Device staging requires verified authority and the still-active plan

Status: Accepted

## Context

`RecoveryRequest` and `validate_recovery_request` already bind a request to an explicit Recovery Plan, scope, Identity, authority kind, and target Device. The protocol contract intentionally states that this validates policy shape only; treating it as proof of a recovery key, trusted Device, hardware authority, encrypted backup capability, or organization authority would be fail-open. A second race also exists if the runtime verifies a plan and later writes Device state after that plan has been revoked or rotated.

## Decision

Core owns a `RecoveryAuthorityVerifier` provider boundary and a private-field `RecoveryAdmissionProof`. `RecoveryRequestGate` first resolves the current active plan, applies canonical request validation, and only then invokes the trusted verifier for the concrete selected authority. A successful protocol validation alone can never mint the proof. Missing/mismatched plans and denied authority proofs remain non-disclosing permission failures; verifier unavailability fails closed.

The durable staging API accepts only `RecoveryAdmissionProof`. Memory and SQLite re-check the proof's exact plan/scope/Identity against the still-active Recovery Plan in the same atomic action that inserts the target Device. SQLite uses an immediate transaction, closing the revoke/rotate TOCTOU window. Staging is idempotent only for the identical already-staged descriptor and conflicts with an existing different Device binding/state.

The proof carries the plan-required recovered Device state, which canonical validation restricts to `REVERIFICATION_REQUIRED`. No recovery staging path can create `ACTIVE`. Registering/staging any non-Active Device also revokes a residual Active trusted signing key in the same durable action, and SQLite reopen validation rejects non-Active Device + Active key state. This prevents preserved v14 trusted-key history from becoming latent trust when a Device identity is later established.

Recovery execution is a distinct security-authority path, not a PermissionGrant. Recovery Plan administration remains permission-authorized through `AuthorizedDurableRuntime`; execution authority comes only from the active plan plus its trusted verifier. No second recovery identity or authorization model is introduced.

## Consequences

A stale proof cannot stage a Device after plan revocation/rotation wins the durable race. Recovery can now safely stage an exact Device into mandatory re-verification and preserve that state across restart without auto-trusting any key. The proof boundary is reusable by future concrete recovery providers without changing canonical Recovery Plan semantics.

This ADR does **not** claim that all RecoveryMethod authority providers exist, does not implement credential re-issuance, device-bound content/key delivery, backup restore conformance, historical-key archive policy, or production re-verification providers/UX. ADR-0039 now defines the separate Core-owned re-verification-to-Active transition, while the end-to-end recovery blocker remains explicit.

## Rejected alternatives

Treat `validate_recovery_request` as authority proof: rejected as fail-open. Pass raw plan/request fields directly into storage staging: rejected because callers could fabricate the security transition. Check active plan and insert Device in separate operations: rejected because revoke/rotation creates a TOCTOU race. Auto-activate the recovered Device: rejected by the Canon. Reuse ordinary PermissionGrants as recovery authority: rejected because it creates a second recovery brain and changes the Canon's typed authority semantics.

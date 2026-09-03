# ADR-0031: Service Principal requests require quota and append-only audit

Status: Accepted

## Context

ADR-0030 established credential authentication that resolves the existing canonical Service Account `ScopedPrincipal`, and ADR-0028 established deny-by-default authorization through `AuthorizedDurableRuntime`. The remaining production Service Principal blocker requires quotas and auditability without creating a second identity, authorization, or persistence brain.

A naive API wrapper that merely checks a counter before returning `ScopedPrincipal` is insufficient: callers could reuse the principal outside that wrapper. A quota hidden inside SQLite wall-clock calls would also be difficult to test and could fail open on clock rollback. Audit cannot contain authentication secrets or user payload and cannot be a mutable log table.

## Decision

UCR introduces `ServiceQuotaPolicy`, `ServiceQuotaStore`, `ServiceAuditRecord`, and `ServiceAuditStore` as separate security capabilities. Quota policy binds to the existing exact Service Account `ScopedPrincipal`; no new service identity type is introduced. Absence of quota policy is deny-by-default.

`ServicePrincipalRequestGate` authenticates a credential and returns a single-use `AuthorizationEvaluator` bound to exactly one permission/resource tuple. Its authorization call atomically consumes the Service Principal quota before delegating to the existing authorization evaluator. It durably appends an admission audit decision before returning authorization success. Audit failure therefore fails closed before the durable runtime operation executes.

The returned evaluator owns a `ServicePrincipalAdmissionProof` that external code cannot construct because its fields are private to Core. `AuthorizedDurableRuntime` requires a matching proof for `PrincipalKind::ServiceAccount` before delegating authorization. A raw `ScopedPrincipal` returned by the lower-level credential verifier therefore cannot be used to bypass this admission path.

Time is injected through `ServiceQuotaClock`. The reference fixed-window accounting persists the last observed Unix time and fails closed on rollback. Wall time remains quota/audit context only and never becomes authentication, replay, identity, permission, or canonical ordering evidence.

Audit records are metadata-only and protocol-bound by `UCR-SERVICE-AUDIT-HASH-V1`, chaining every record to the preceding hash. SQLite v14 adds quota policy/usage plus audit rows, rejects audit UPDATE/DELETE through triggers, and validates the complete chain on reopen. This is tamper-evident application/storage integrity, not an external hardware-signed audit anchor.

Quota administration and audit read use protocol-owned permissions. Quota consumption and audit append are internal security capabilities and are deliberately not externally grantable operations.

## Consequences

- An authenticated Service Principal cannot execute through the reference external-request path without an explicit quota policy.
- Authenticated unauthorized traffic consumes the same quota before permission denial.
- A request authorization object cannot be reused for a second runtime operation or a different permission/resource tuple.
- Quota use, clock rollback and rate-limit state survive restart.
- Admission decisions are append-only, bounded on read, metadata-only, and tamper-evident across restart.
- Existing `AuthorizedDurableRuntime` and canonical `authorize` remain the single authorization owners.
- SQLite v13-to-v14 migration is additive and does not infer quota/audit state.

This closes the production blocker `Service Principal quota and audit enforcement` for the currently implemented local/reference external Service Principal request boundary. It does not claim distributed multi-node global rate limiting, anonymous network-edge throttling, operation-success auditing, or cryptographically externally anchored audit logs. Production OS/hardware-backed key providers, Device revocation, remote peer security and broader transport/chaos work remain separate blockers.

## Rejected alternatives

- Put quota fields in `PermissionGrant`: rejected because authorization grants are not usage counters or authentication state.
- Trust caller timestamps: rejected because the caller must not control security accounting time.
- Call `SystemTime` directly from each store: rejected because clock ownership becomes hidden and deterministic rollback tests become impossible.
- Return a reusable authenticated `ScopedPrincipal` from the quota boundary: rejected because quota could then be bypassed for later operations.
- Store plaintext request bodies in audit: rejected because audit is security metadata, not a content archive.
- Mutable audit rows without a chain: rejected because deletion/rewrite would be difficult to detect and contradict append-only audit requirements.

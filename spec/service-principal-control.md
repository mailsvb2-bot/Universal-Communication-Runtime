# Service Principal Quota and Audit Control

Status: **Implemented local/reference security boundary**.

A production external Service Principal request uses one canonical path: credential authentication resolves the persisted `ScopedPrincipal`, a single-use request evaluator consumes quota, the existing `AuthorizationEvaluator` decides least privilege, and an admission audit record is durably appended before an authorized runtime operation is allowed to reach storage.

## Quota policy

`ServiceQuotaPolicy` is bound to one exact canonical Service Account `ScopedPrincipal`. `max_requests` and `window_ms` are explicit, non-zero values. There is no implicit unlimited default: an authenticated Service Principal with no quota policy is denied with canonical rate-limit semantics.

The reference algorithm is a durable fixed Unix-time window. Accounting is atomic per Service Principal and survives restart. Re-applying an identical policy is idempotent and MUST NOT reset usage. Replacing the policy explicitly resets the old accounting state. A quota policy is administration state, not identity, authentication proof, or permission.

Time comes from the injected `ServiceQuotaClock`. The system-clock implementation is only a quota/audit time source; wall time is never authentication, authorization, replay, identity, or message-order evidence. Durable accounting remembers the last observed time. Backward clock movement fails closed as temporary unavailability instead of silently granting a fresh window.

Authenticated but unauthorized requests consume quota before the permission decision, so a caller cannot bypass abuse controls by repeatedly requesting operations it does not have permission to perform. Credential-authentication failures are not charged to a resolved Service Principal because no principal has been authenticated; unauthenticated network-edge rate limiting remains a transport/API deployment responsibility.

## Single-use request authorization

`ServicePrincipalRequestGate` authenticates one credential and returns a `ServicePrincipalRequestAuthorization` bound to exactly one permission and resource scope. That object implements the existing `AuthorizationEvaluator` interface and is intentionally single-use.

The gate also creates a Core-owned `ServicePrincipalAdmissionProof` whose fields are private. `AuthorizedDurableRuntime` rejects every `ServiceAccount` subject when its evaluator cannot supply a matching proof. Therefore calling the lower-level credential verifier and obtaining a raw `ScopedPrincipal` cannot bypass quota/audit by feeding that principal directly to the runtime. Ordinary Person/Device/Agent authorization evaluators are unaffected by this ServiceAccount-specific ingress requirement.

`AuthorizedDurableRuntime` therefore remains the only durable operation façade and the protocol `authorize` function remains the semantic permission owner. The Service Principal request evaluator adds authentication provenance, quota and audit around that existing owner; it does not create a second authorization brain.

Reusing the request evaluator, changing its subject, permission, or resource scope, exhausting quota, or detecting clock rollback all fail closed.

## Audit record

A Service Principal admission audit record contains only security metadata: audit ID, credential ID, presented scope, optional resolved canonical Service Principal, requested permission, resource scope, admission outcome, and audit wall time. It contains no credential secret, secret digest, message content, attachment content, request payload, decrypted material, or provider credential.

Authentication failures retain no resolved subject. Successful authentication and all later quota/authorization outcomes carry the independently resolved canonical Service Account subject.

The protocol-owned `UCR-SERVICE-AUDIT-HASH-V1` binding hashes every semantic audit field plus the previous record hash. SQLite v14 stores this chain and enforces append-only application access with UPDATE/DELETE rejection triggers. Reopen validates the schema, quota state, and complete audit chain. Exact duplicate audit-ID retries are idempotent; conflicting reuse fails closed.

This provides application-level append-only integrity and tamper evidence for partial/offline corruption. It is not a claim that an attacker with privileged filesystem control who can rewrite the entire database and recompute every unkeyed hash is defeated. Deployments requiring a cryptographically anchored audit trail must bind the chain to an independently protected signing/HMAC root; production OS/hardware-backed key-provider work remains a separate release blocker.

## Administration permissions

Quota and audit administration reuse the canonical permission model:

- `ucr.authorization.service_quota.read` reads one Service Principal quota policy;
- `ucr.authorization.service_quota.write` installs or replaces a quota policy;
- `ucr.audit.service_principal.read` reads bounded recent admission audit records for an authorized scope.

Quota consumption and audit append are internal security actions, not permissions that an external principal can grant itself. Raw storage methods remain trusted local implementation capabilities and are not public SDK/API escape hatches.

## SQLite v14

SQLite schema v14 adds `service_quota_policies`, restart-safe `service_quota_usage`, and `service_audit_records` with a scope index and append-only triggers. Migration from v13 is additive: credentials, permission grants, trusted keys, messages, sync state, recovery state and all earlier durable state are preserved; quota policies, usage and audit start empty because no prior schema contained evidence from which they could be inferred safely.

## Non-claims

The local/reference quota is per durable store. It is not a distributed global rate limiter across multiple independent nodes, and it does not replace unauthenticated network-edge throttling, transport backpressure, billing limits, or organization-specific quotas. Audit admission means a request passed or failed the security gate; `Authorized` does not claim the later business/storage operation succeeded.

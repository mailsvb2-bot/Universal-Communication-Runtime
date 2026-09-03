# ADR-0027: Permission grants are durable and runtime-enforced

Status: Accepted

## Context

Phase 4 already defines deny-by-default authorization over canonical `PermissionGrant` values, but a pure `authorize(request, grants)` function is not a runtime authorization system. The specification requires persisted grants, and security-sensitive mutations must not rely on callers manually remembering to invoke authorization.

At the same time, authentication credentials, roles, audit history, Device lifecycle, and product-specific access models must not be folded into the grant store. Doing so would create a second identity/security brain.

## Decision

`PermissionGrantStore` is the durable owner of the current explicit grant set. An identical canonical grant is an idempotent set insertion. Revoking that exact grant is an idempotent set removal. Grant audit history remains a separate audit capability rather than an invented lifecycle field on `PermissionGrant`.

Memory and SQLite reference stores implement both `PermissionGrantStore` and `AuthorizationEvaluator`. Evaluation loads persisted grants for the exact `ScopedPrincipal` and delegates the decision to the existing single-owner `ucr_protocol::authorize`. Invalid persisted grant state fails closed; it is never skipped to search for a permissive row.

SQLite schema v12 stores normalized grantee scope, Principal kind/ID, permission identifier, and exact or tenant-wide resource scope. Migration from v11 is additive and starts with an empty grant set because earlier schemas contained no durable authorization state that could be safely inferred.

The first enforced runtime mutation boundary is trusted signing-key lifecycle. `AuthorizedTrustedSigningKeyMutations` requires an already authenticated `ScopedPrincipal` and one of three protocol-owned permissions before provision, rotate, or revoke can reach the raw key store:

- `ucr.crypto.trusted_signing_key.provision`
- `ucr.crypto.trusted_signing_key.rotate`
- `ucr.crypto.trusted_signing_key.revoke`

These permissions are deliberately distinct. A grant for one operation does not authorize either of the others.

## Consequences

Authorization state is restart-safe, exact-scope, deny-by-default, and shared by people, Service Principals, Devices, agents, bots, organizations, automations, and external-platform principals through the existing Principal model. Tenant-wide authority remains an explicit grant available only to a tenant-root scoped principal.

Raw storage capabilities remain internal persistence boundaries. External/runtime code must use authorization-enforcing operation façades rather than direct database access.

This ADR does not define authentication credentials, Service Principal authentication, quotas, audit persistence, or Device revocation. It also does not claim every Command/Message/Sync/Delivery/runtime operation is already routed through an authorization façade. Therefore the broader `tenant-scoped authorization enforcement` production blocker remains until all applicable external/runtime mutation and read paths have explicit permission ownership and enforcement evidence.

## Evidence

Memory tests prove deny-before-mutation, idempotent grant/revoke, independent provision/rotate/revoke permissions, and tenant-wide same-tenant behavior. SQLite tests prove restart persistence, revocation persistence, v11-to-v12 migration preserving trusted-key state, malformed persisted-grant rejection, tenant isolation, and a real authorized trusted-key mutation after restart.

## Rejected alternatives

- Product roles in Core: rejected because roles are integration policy, not canonical UCR permissions.
- Embed credentials in grants: rejected because authorization state is not authentication proof.
- Make SQLite decide permissions independently: rejected because `ucr_protocol::authorize` is the single semantic owner.
- Add grant IDs/lifecycle timestamps now: rejected because the public canonical grant has no such semantics and audit persistence is a separate concern.
- Treat missing namespace as an implicit wildcard: rejected; tenant-wide authority is always an explicit grant.

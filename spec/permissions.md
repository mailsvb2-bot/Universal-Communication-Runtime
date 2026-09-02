# Permissions and Service Accounts

Status: **Phase 4 foundational contract**.

Authorization is deny-by-default. A principal may perform an operation only when an explicit, valid permission grant applies to that principal, permission identifier, and resource scope.

Permissions use namespaced identifiers such as `ucr.message.send`. Product/provider role names are not canonical authorization primitives.

## Service accounts

A Service Principal uses the existing canonical `PrincipalKind::ServiceAccount` / `PRINCIPAL_KIND_SERVICE_ACCOUNT` vocabulary together with `ScopedPrincipal`. UCR does not create a second service-account identity model.

Authentication credentials are intentionally outside this authorization contract. A permission grant is not a credential, bearer token, API key, session, or proof of authentication.
## Grant scope

`Exact` grants apply only to one exact `TenantScope`.

`TenantWide` grants are an explicit widening mechanism. They may be granted only to a principal whose own `ScopedPrincipal.scope` is tenant-root (`namespace_id` absent) for the same tenant. A namespace-bound principal cannot receive tenant-wide authority.

A tenant-root principal may receive an explicit exact grant for a named namespace. This is authorization state, not an inference from the missing namespace in the principal scope.

No grant may cross tenant boundaries. A namespace-bound principal may receive exact grants only inside its bound namespace.
## Evaluation

Authorization evaluates the authenticated/scoped subject, requested permission, resource scope, and persisted grants. Absence of a matching grant is `PERMISSION_DENIED`.

A malformed permission identifier is invalid input. Corrupted/malformed persisted grant state is an internal authorization failure and must fail closed; it must never be skipped in a way that accidentally permits access.

Actor identity, message authorship, `on_behalf_of`, Identity membership, Endpoint, external provider binding, route selection, network origin, and process identity are not permission grants by themselves.

Authentication, credential issuance/rotation, quotas, audit persistence, and revocation enforcement remain separate layers and must not be claimed complete merely because authorization semantics exist.

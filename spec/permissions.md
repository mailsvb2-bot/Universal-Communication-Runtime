# Permissions and Service Accounts

Status: **Phase 4 foundational contract**.

Authorization is deny-by-default. A principal may perform an operation only when an explicit, valid permission grant applies to that principal, permission identifier, and resource scope.

Permissions use namespaced identifiers such as `ucr.message.send`. Product/provider role names are not canonical authorization primitives.

## Service accounts

A Service Principal uses the existing canonical `PrincipalKind::ServiceAccount` / `PRINCIPAL_KIND_SERVICE_ACCOUNT` vocabulary together with `ScopedPrincipal`. UCR does not create a second service-account identity model.

Authentication credentials remain outside the authorization contract. A permission grant is not a credential, bearer token, API key, session, or proof of authentication. The reference Service Principal credential lifecycle is defined separately in `service-principal-authentication.md` and resolves back into this same canonical `ScopedPrincipal`.
## Grant scope

`Exact` grants apply only to one exact `TenantScope`.

`TenantWide` grants are an explicit widening mechanism. They may be granted only to a principal whose own `ScopedPrincipal.scope` is tenant-root (`namespace_id` absent) for the same tenant. A namespace-bound principal cannot receive tenant-wide authority.

A tenant-root principal may receive an explicit exact grant for a named namespace. This is authorization state, not an inference from the missing namespace in the principal scope.

No grant may cross tenant boundaries. A namespace-bound principal may receive exact grants only inside its bound namespace.
## Evaluation

Authorization evaluates the authenticated/scoped subject, requested permission, resource scope, and persisted grants. Absence of a matching grant is `PERMISSION_DENIED`.

A malformed permission identifier is invalid input. Corrupted/malformed persisted grant state is an internal authorization failure and must fail closed; it must never be skipped in a way that accidentally permits access.

Actor identity, message authorship, `on_behalf_of`, Identity membership, Endpoint, external provider binding, route selection, network origin, and process identity are not permission grants by themselves.

Authentication, quotas, audit persistence, Device revocation, and remote-peer authentication remain separate layers from permission semantics. Service Principal credential authentication is now implemented as a distinct owner; it must not be folded into grants.
## Durable reference authorization state

The Rust reference runtime persists the current explicit grant set through `PermissionGrantStore`. Identical grant insertion and exact grant removal are idempotent set operations. SQLite schema v12 is the restart-safe reference representation; migration from v11 starts with no grants because earlier storage contained no authorization evidence that could be safely inferred.

`AuthorizationEvaluator` implementations load grants for the exact authenticated `ScopedPrincipal` and delegate semantic evaluation to the canonical `authorize` function. Malformed persisted grant state fails closed as an internal authorization failure; implementations must not skip corrupt grants in order to find an allowing grant.

`AuthorizedDurableRuntime` is the authorization-enforcing runtime boundary for every currently implemented tenant-scoped durable capability. Raw persistence traits remain internal storage/bootstrap capabilities and are not external authorization APIs. The runtime façade covers all current methods for permission grants, trusted signing keys, recovery plans, command acceptance/outcomes, conversations, messages, delivery, sync, events, and Anti-Entropy.

The protocol-owned `RUNTIME_PERMISSION_IDS` registry is the canonical current runtime vocabulary. It includes Service Principal credential provision/revoke plus independent read/write or lifecycle permissions as applicable: `ucr.authorization.grant.read`, `ucr.authorization.grant.create`, `ucr.authorization.grant.revoke`; trusted signing-key read/provision/rotate/revoke; recovery-plan read/install/rotate/revoke; command accept and outcome read/write; conversation read/write; message read/write; delivery read/write; sync read/write; Anti-Entropy read/reconcile; and event append. Every identifier is namespaced and duplicate-free.

Permission administration is not a bypass. Runtime grant listing, creation, and revocation require their own explicit permissions, evaluated against the grant's resource scope. A runtime caller with no grant-management authority cannot bootstrap that authority by granting it to itself. The first authorization trust-root grant is seeded only by trusted local deployment/bootstrap code through the raw grant store; remote/runtime code never receives that escape hatch.

Every new tenant-scoped durable runtime method must add an explicit protocol-owned permission and authorization-enforcing façade method in the same change. Current architecture tests require complete method-for-method coverage. This closes tenant-scoped authorization enforcement for the implemented durable runtime surface. Service Principal credential authentication now feeds an authenticated `ScopedPrincipal` into this same boundary; quotas, audit persistence, Device revocation, and remote-peer/transport authentication remain separate layers.

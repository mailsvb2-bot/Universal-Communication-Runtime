# Tenant / Namespace / Principal security scope

Status: **Phase 2 foundational contract**.

`Tenant` is a UCR security boundary. `Namespace` is an optional explicit subdivision inside one tenant. `Principal` is the entity to which authentication and authorization can be attached.

The canonical runtime never infers tenant or namespace from transport metadata, provider account identifiers, network address, process identity, database connection, or application name.

## TenantScope

Every security-sensitive canonical operation carries an explicit `TenantScope` containing `tenant_id` and, when applicable, `namespace_id`.

A missing namespace means only "no namespace selected". It does **not** mean "all namespaces" and is not a wildcard.
## Default scope rule

The default authorization precondition is exact scope equality: the same `tenant_id` and the same optional `namespace_id`.

Cross-tenant access fails closed. Same-tenant but different-namespace access also fails closed. Tenant-wide or cross-namespace authority may exist only through an explicit authorization grant defined by the permissions layer; it is never inferred from an absent namespace.

Scope mismatch is exposed across the public contract as `PERMISSION_DENIED`, not `NOT_FOUND`, so callers cannot use the error category to probe whether a resource exists outside their authorized scope.

## ScopedPrincipal

`ScopedPrincipal` binds a canonical `PrincipalRef` to exactly one explicit `TenantScope`. Authentication proves/control-establishes a principal; authorization decides what that principal may do in that scope. Neither step is inferred from Actor, Identity, Endpoint, Route, or transport metadata.
## Non-authority relationships

Identity membership, device ownership, message authorship, endpoint association, conversation membership, provider account ownership, and route selection are not authorization grants by themselves.

An `ActorRef.on_behalf_of` relationship records provenance/delegation context; it does not create permission. An external identity binding maps an external entity to canonical Identity; it does not grant tenant access.

## Compatibility and failure semantics

Older clients that do not supply required scope cannot be treated as tenant-wide clients. Security-sensitive operations requiring scope fail explicitly rather than being upgraded to a broader implicit scope.

Namespace-policy evolution must remain backward-compatible or be versioned. A server must not silently reinterpret an existing tenant-only scope as authority over newly introduced namespaces.

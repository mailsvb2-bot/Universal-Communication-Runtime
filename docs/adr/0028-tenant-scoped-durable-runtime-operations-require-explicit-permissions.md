# ADR-0028: Tenant-scoped durable runtime operations require explicit permissions

Status: Accepted

## Context

ADR-0027 made explicit PermissionGrants restart-safe and protected trusted signing-key mutations, but intentionally left the broader tenant-scoped authorization blocker open. The reference runtime now has durable capabilities for permission administration, trusted signing keys, recovery plans, command acceptance/outcomes, conversations, messages, delivery, sync, events, and Anti-Entropy. Leaving any of those runtime-facing operations outside one authorization boundary would create a bypass around the deny-by-default permission model.

Authentication remains a separate trust boundary. This ADR assumes the caller supplies an already authenticated `ScopedPrincipal`; it does not turn a Principal ID into authentication proof.

## Decision

`AuthorizedDurableRuntime` is the authorization-enforcing runtime façade for every currently implemented tenant-scoped durable capability. It mirrors all 32 methods owned by `PermissionGrantStore`, `TrustedSigningKeyStore`, `RecoveryPlanStore`, `CommandAcceptanceStore`, `ConversationStore`, `MessageStore`, `DeliveryStore`, `SyncStore`, `EventJournalStore`, `AntiEntropyStore`, and `CommandOutcomeStore`.

Every façade method performs an explicit permission check against the operation's exact resource `TenantScope` before calling the raw persistence capability. Reads and writes use distinct permission IDs where their authority differs. Trusted signing-key provision/rotate/revoke remain distinct operations. The protocol crate owns the complete current permission vocabulary in `RUNTIME_PERMISSION_IDS`; every ID is namespaced and unique.

Permission administration is itself authorized. Runtime grant listing, grant creation, and grant revocation require `ucr.authorization.grant.read`, `ucr.authorization.grant.create`, and `ucr.authorization.grant.revoke` respectively. Create/revoke authority is evaluated against the resource scope carried by the grant; a tenant-wide grant is administered at that tenant's root scope. A runtime caller cannot grant itself grant-management authority through the same path.

The initial authorization trust root is an explicit deployment/bootstrap responsibility. Trusted local installation or administrative bootstrap code may seed the first grant through the raw `PermissionGrantStore`; that raw capability is not a remote/runtime API and must not be exposed as one. All normal external/runtime adapters must enter through `AuthorizedDurableRuntime`.

`AuthorizedTrustedSigningKeyMutations` remains for compatibility but delegates to `AuthorizedDurableRuntime`; it is not a second permission-policy owner.

New tenant-scoped durable methods must add a protocol-owned permission and an authorization-enforcing façade method in the same change. Architecture tests compare the durable trait surface with the façade surface and fail if coverage diverges.

## Consequences

The implemented durable runtime is deny-by-default across tenant-scoped reads and mutations, including permission administration itself. Exact-scope and explicit tenant-wide grant semantics remain owned by `ucr_protocol::authorize`; storage and runtime façades do not invent parallel role logic.

The production blocker `tenant-scoped authorization enforcement` can be removed for the currently implemented durable runtime surface because every applicable method is covered by one enforced façade and executable integration evidence. This does not close Service Principal authentication/least-privilege enforcement, credential issuance, Device revocation, transport/remote-peer authentication, quotas, or audit persistence.

Non-tenant operational diagnostics such as storage schema/health remain outside this permission map. Internal transport selection and policy evaluation also remain separate layers and cannot be exposed as an authorization bypass.

## Evidence

Protocol tests prove the runtime permission registry is namespaced and duplicate-free. Memory integration tests prove deny-before-store behavior, independent read/write permissions, permission-administration self-bootstrap denial, grant read/create/revoke separation, and cross-tenant denial. Existing SQLite v12 tests prove grants are restart-safe and malformed persisted authorization state fails closed. Architecture tests prove the complete current durable trait method set is mirrored by `AuthorizedDurableRuntime`, the compatibility key façade delegates to it, and the broader authorization blocker is removed only while the neighboring authentication blocker remains.

## Rejected alternatives

- Put permission checks inside every storage implementation: rejected because that duplicates authorization policy and makes alternate stores separate policy brains.
- Treat raw store traits as externally callable authorization APIs: rejected; they are persistence capabilities and explicit bootstrap/internal boundaries.
- Use one broad `admin` permission: rejected because read, grant creation, revocation, key lifecycle, and domain operations require independent least-privilege authority.
- Infer authority from tenant-root scope or Principal kind: rejected; scope and kind are identity context, not grants.
- Fold authentication into PermissionGrant: rejected because a grant is authorization state, not proof of identity or possession.

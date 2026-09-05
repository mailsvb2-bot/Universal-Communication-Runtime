# Integration API Contract

Status: **Experimental / Phase 13 foundation**.

## 1. Public boundary

Integration API is the public, language-independent boundary for external UCR consumers. It is not
the Rust ABI, `AuthorizedDurableRuntime`, a storage trait, or direct database access. The canonical
v1 request/response shape is defined in `proto/ucr/v1/integration.proto`.

The implemented Phase-13 vertical surface exposes:

- `IntegrationService.SubmitCommand` over canonical `CommandEnvelope`/`CommandReceipt`;
- `IntegrationService.CreateIdentity` over canonical `IdentityRecord`;
- `IntegrationService.LinkIdentity` over canonical `ExternalIdentityBinding`;
- `IntegrationService.GetIdentity` over exact canonical Root Identity lookup;
- `IntegrationService.ResolveIdentityBinding` over the exact external binding key.

These methods reuse existing canonical owners. They do not create Integration-specific Command,
Identity, audit, permission, or provider-specific communication models. Concrete gRPC, HTTP,
local-IPC, sidecar, or embedded bindings may differ in framing and credential presentation, but
MUST preserve the same authentication, authorization, quota/audit, idempotency, error, and durable
semantics.

## 2. Authentication and request admission

External consumers authenticate as the existing canonical Service Principal. Credentials are
binding metadata and MUST NOT be copied into canonical Commands, Identity records, external binding
records, extensions, Events, logs, or business payloads.

Every implemented external operation follows:

`credential authentication -> quota consumption/audit -> permission evaluation -> canonical durable operation`.

The authenticated Service Principal scope is resolved from durable credential state rather than
trusted from caller-supplied identity. Adapters receive no raw store access.

- `SubmitCommand` requires `ucr.command.accept`;
- `CreateIdentity` requires `ucr.identity.create`;
- `LinkIdentity` requires `ucr.identity.external_binding.link`;
- `GetIdentity` requires `ucr.identity.read`;
- `ResolveIdentityBinding` requires `ucr.identity.external_binding.read`.

Audit attribution is generic security metadata bound before authentication: `ucr.command` +
canonical `CommandId`, `ucr.identity.create` + canonical `IdentityId`, or
`ucr.identity.external_binding.link` + target canonical `IdentityId`, `ucr.identity.read` +
canonical `IdentityId`, or `ucr.identity.external_binding.read` + canonical `IntegrationId`.
External namespace/entity bytes are not copied, encoded, or hashed into generic admission audit
operation references. An Authorized admission record proves only that the
security gate passed; later durable validation/conflict may still fail.

## 3. Command semantics

`SubmitCommand` returns only `ACCEPTED` or `DUPLICATE` receipt semantics after durable commit. A
receipt is not an Event and is not proof that a requested real-world effect occurred. The existing
scoped command ID/idempotency contract remains the only command deduplication owner. Changed
semantics under the same durable identity fail with canonical `CONFLICT`.

## 4. Identity semantics

`CreateIdentity` persists the minimal accountless/provider-independent Root `IdentityRecord` through
the single `IdentityStore`. Equal retries are idempotent. Reusing the same `(TenantScope,
IdentityId)` with changed ownership, evidence, or expiry conflicts rather than silently mutating
Identity semantics.

`LinkIdentity` persists the canonical external mapping through the single
`ExternalIdentityBindingStore`. A new external key requires its exact target Root Identity to
already exist. Equal retries are idempotent; changing the target of an existing exact external key
conflicts. No public relink/unlink or direct SQL overwrite is defined.

A successful `CreateIdentity`/`LinkIdentity` response returns the canonical record that was durably
accepted. `GetIdentity` and `ResolveIdentityBinding` return the canonical existing record from those
same owners. No parallel Integration receipt/status or mapping model is introduced.

Read-side absence is canonical non-retryable `NOT_FOUND`, but only after successful credential,
quota/audit, and permission admission. Authentication and permission failures do not disclose
whether an Identity or external binding exists. Binding lookup audit intentionally identifies the
`IntegrationId` but not the sensitive external namespace/entity bytes.

## 5. Errors and maturity

Validation failures map to `INVALID_ARGUMENT`; authorized lookup absence to `NOT_FOUND`; semantic identity/idempotency reuse to `CONFLICT`;
storage-full to `RESOURCE_EXHAUSTED`; temporary storage failure to `TEMPORARILY_UNAVAILABLE`;
permission denial remains `PERMISSION_DENIED`; internal/corrupt/foreign-store failures map to
`INTERNAL` without exposing storage internals. Binding-specific transport status MUST NOT replace or
weaken canonical UCR error semantics after successful request decoding.

The Phase-13 API remains `Experimental`. Stable compatibility rules apply only after a separate
Public API Governance promotion decision. Existing `SubmitCommand` wire fields remain unchanged.

This slice does not claim a production gRPC/HTTP server, SDK generation, Event subscriptions,
webhook delivery, Command execution/dispatch, routing, Message delivery, identity/binding listing or discovery, Persona/Profile APIs, Identity evidence transitions,
Identity merge/delete, external-binding unlink/relink,
or expiry execution. Phase 14 owns Event API semantics; later phases own network transport.

## 6. Required evidence

Reference evidence must prove Service Principal authentication, mandatory quota/audit, exact
permission enforcement, stable error mapping, restart-safe durable ownership, duplicate/conflict
semantics, and no ghost state after denied/unauthenticated/rate-limited/invalid requests. Identity
evidence additionally proves v18→v19 migration invents no Root Identity, new external binding keys
reject missing targets, historical exact v18 bindings remain readable/idempotently retryable, and
public Identity/binding reads survive restart without direct DB access or a parallel mapping owner.

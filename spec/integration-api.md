# Integration API Contract

Status: **Experimental / Phase 13 foundation**.

## 1. Public boundary

Integration API is the public, language-independent boundary for external UCR consumers.
It is not the Rust ABI, `AuthorizedDurableRuntime`, a storage trait, or direct database access.
The canonical v1 request/response shape is defined in `proto/ucr/v1/integration.proto`.

The first Phase-13 vertical slice exposes `IntegrationService.SubmitCommand`.
It reuses the canonical `CommandEnvelope`, `CommandReceipt`, and `ErrorEnvelope`; it does not
create an Integration-specific Command model or provider-specific message core.

Concrete gRPC, HTTP, local-IPC, sidecar, or embedded bindings may differ in framing and
credential presentation, but MUST preserve the same authentication, authorization,
idempotency, error, and command-acceptance semantics.

## 2. Authentication and request admission

External consumers authenticate as the existing canonical Service Principal.
Credentials are binding metadata and MUST NOT be copied into `CommandEnvelope`, correlation,
extensions, events, logs, or durable command state.

A conforming request path is:

`credential authentication -> quota consumption/audit -> permission evaluation -> durable command acceptance`.

The command's `TenantScope` is the resource scope. The authenticated Service Principal scope
is resolved from durable credential state rather than trusted from caller-supplied identity.
Every `SubmitCommand` requires `ucr.command.accept`; no public adapter may call raw
`CommandAcceptanceStore` on behalf of an external Service Principal.

## 3. Command semantics

`SubmitCommand` returns only `ACCEPTED` or `DUPLICATE` receipt semantics after durable commit.
A receipt is not an Event and is not proof that a requested real-world effect occurred.
The existing scoped command ID/idempotency contract remains the only command deduplication owner.
Changed semantics under the same durable identity fail with canonical `CONFLICT`.

Validation failures map to `INVALID_ARGUMENT`; storage-full to `RESOURCE_EXHAUSTED`; temporary
storage failure to `TEMPORARILY_UNAVAILABLE`; permission denial remains `PERMISSION_DENIED`;
internal/corrupt/foreign-store failures do not disclose storage internals and map to `INTERNAL`.

The protobuf response uses exactly one result: canonical `CommandReceipt` or canonical
`ErrorEnvelope`. Binding-specific transport status MUST NOT replace or weaken canonical error
semantics for a successfully decoded UCR request.

## 4. Maturity and non-claims

The Phase-13 API is `Experimental`. Stable API compatibility rules still apply only after a
surface is explicitly promoted under Public API Governance; promotion cannot silently change
canonical Command semantics.

This slice does not claim an Internet communication transport, a production gRPC/HTTP server,
SDK generation, Event subscriptions, webhook delivery, Command execution/dispatch, routing,
or Message delivery. The existing admission audit proves the Service Principal admission decision
but does not yet add a dedicated `command_id` join field for end-to-end per-command audit queries.
Phase 14 owns Event API semantics; later phases own network transport.

## 5. Required evidence

The reference ingress MUST prove valid Service Principal command submission, restart-safe
acceptance/deduplication through the durable owner, fail-closed wrong credentials, independent
permission denial, quota enforcement, mandatory audit, stable canonical error mapping, and that
denied/failed requests cannot create a ghost accepted command.

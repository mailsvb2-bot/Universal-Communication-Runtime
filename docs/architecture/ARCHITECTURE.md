# UCR architecture — Phase 0

## Boundary

UCR answers **how communication is established and delivered**. External systems answer **why the communication exists**.

No product-specific business graph belongs in UCR Core.

## Layers

```text
External Products / Applications
            │
      Public UCR Contract
    Commands / Events / Intent
            │
            ▼
 Universal Communication Runtime
            │
      Transport Contract
            │
 ┌──────────┼───────────┐
Internet   Direct     External bridges
            │
 Store-and-Forward / Mesh (later phases)
```

## Canonical invariants

- `Identity` is not a phone number, email address, provider ID, hostname, IP address, or database sequence. The Root Identity owner is exact-scope, durable, accountless, and provider-independent.
- `Endpoint` is replaceable and can disappear without destroying `Identity`.
- `Conversation` is not owned by a transport/provider.
- `CommunicationIntent` is persisted independently from route availability through one capability-specific durable owner; Transport, Message, and Delivery do not own or recreate Intent state.
- `Policy` is evaluated independently from a selected route.
- Transport/provider implementations may declare capabilities; they may not redefine Message, Conversation, Identity, Delivery, or Policy.
- External consumers do not get direct database access or hidden APIs.
- Multi-tenancy is a security boundary from the first implementation.
- Protocol and public API are language-independent and versioned from the first version.
- Rust is the reference implementation language, not the protocol definition language.

## Public contract boundary

The public contract is represented first as a versioned protocol specification plus protobuf schemas. Rust types are a reference mapping of the specification, not the specification itself. SQLite v19 now provides one exact-scope durable Root `IdentityStore`; the minimal Root Identity is accountless/provider-independent and keeps ownership/evidence/lifecycle metadata separate from addresses, endpoints, profiles, and external entities. Phase 13 reuses that owner plus the canonical `ExternalIdentityBinding` owner through `IntegrationService.CreateIdentity`, `IntegrationService.LinkIdentity`, `IntegrationService.GetIdentity`, and `IntegrationService.ResolveIdentityBinding`, while `IntegrationService.SubmitCommand` continues to reuse canonical Command/Receipt/Error envelopes. All operations pass through the same Service Principal authentication, quota/audit and permission boundary; integration-specific business mappings and direct database access remain outside Core. Read-side `NOT_FOUND` is emitted only after authorization. Generic audit operation references bind canonical IDs rather than copying business payload or opaque external entity bytes into audit; binding resolution attributes only the canonical `IntegrationId`.

Supported contract surfaces are expected to include protobuf/gRPC, HTTP where appropriate, event streams, local IPC and embedded APIs. They must express the same canonical semantics.

## Provider boundary

A future transport must be addable through a `TransportProvider`-style boundary containing capabilities, addressing, delivery semantics, health, failure mapping and conformance behavior without changing the meaning of canonical entities.

An external platform integrates through Service Principal authentication, quotas/audit, permissions, the public Integration API, events, Root Identity/external identity bindings and policies. The implemented Phase-13 ingress exposes canonical SubmitCommand/CreateIdentity/LinkIdentity operations without granting raw `AuthorizedDurableRuntime` or storage access.

## Deferred implementation

Phase 0 deliberately does not claim production implementations for storage, cryptography, sync, calls, media, Internet transport, local transport, bridges, store-and-forward, mesh, federation or SDK language bindings.

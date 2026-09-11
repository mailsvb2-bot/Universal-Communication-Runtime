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

The public contract is represented first as a versioned protocol specification plus protobuf schemas. Rust types are a reference mapping of the specification, not the specification itself. SQLite v20 retains the exact-scope durable Root `IdentityStore` from v19 and adds durable Event subscription/cursor/retry/dead-letter state layered over the pre-existing append-only Event journal; the minimal Root Identity is accountless/provider-independent and keeps ownership/evidence/lifecycle metadata separate from addresses, endpoints, profiles, and external entities. Phase 13 reuses that owner plus the canonical `ExternalIdentityBinding` owner through `IntegrationService.CreateIdentity`, `IntegrationService.LinkIdentity`, `IntegrationService.GetIdentity`, and `IntegrationService.ResolveIdentityBinding`; the same Phase-13 boundary exposes canonical `IntegrationService.CreateConversation`/`GetConversation` through the existing `ConversationStore`, `IntegrationService.SendMessage`/`GetMessage` through the existing `MessageStore`, and `IntegrationService.CreateCommunicationIntent`/`GetCommunicationIntent` through the existing `CommunicationIntentStore`, while `IntegrationService.SubmitCommand` continues to reuse canonical Command/Receipt/Error envelopes. `SendMessage` and `CreateCommunicationIntent` return the existing generic acknowledgement rather than inventing delivery/routing evidence. All operations pass through the same Service Principal authentication, quota/audit and permission boundary; integration-specific business mappings and direct database access remain outside Core. Read-side `NOT_FOUND` is emitted only after authorization. Generic audit operation references bind canonical IDs rather than copying business payload or opaque external entity bytes into audit; binding resolution attributes only the canonical `IntegrationId`.

Supported contract surfaces include protobuf/gRPC, HTTP where appropriate, event streams, local IPC and embedded APIs. They must express the same canonical semantics. The experimental `ucr-api-grpc` crate binds all eleven `IntegrationService` RPCs to `IntegrationIngress` and all eight `EventService` RPCs to `EventApiIngress`; generated protobuf Rust code and Tonic never become Core owners. Phase 13 is therefore complete at the local/reference Integration API layer. Phase 14 is complete at the local/reference Event API layer. Durable stream polling, reference webhook dispatch, retry, replay, backpressure, cursor idempotency and DLQ all use `EventSubscriptionStore` above the existing `EventJournalStore`. HTTP webhook networking, DNS discovery, production listener/service deployment, IPC and SDK packages remain separate work. Phase 15 now adds a Prepared `ucr-transport-internet` provider that reuses canonical Transport/Crypto/trust owners and accepts only public-IP TCP routes. Phase 24 supplies the separate Prepared Transport Orchestrator above all providers: it reuses canonical Intent/Policy/Endpoint/Transport owners and filters hard constraints before deterministic ranking. Phase 25 adds bounded sequential failover over that same plan and reuses a conservative `TransportProvider` acceptance-disposition boundary; a later route is attempted only after proven non-acceptance, while ambiguous acceptance stops fail closed.

## Provider boundary

Concrete transports are added through the existing `TransportProvider` boundary containing capabilities, addressing, transport-acceptance semantics, health, failure mapping and conformance behavior without changing canonical entities. Phase 15 proves that boundary with `ucr-transport-internet`; later transports must obey the same owner separation.

An external platform integrates through Service Principal authentication, quotas/audit, permissions, the public Integration API, events, Root Identity/external identity bindings and policies. The reference gRPC adapters carry credential ID/secret in sensitive binary metadata outside canonical request bodies and return canonical application errors in each existing response envelope. Identity creation/read and external binding link/read remain thin mappings over the canonical `IdentityStore` / `ExternalIdentityBindingStore` paths, and external entity bytes are never normalized by the adapter. The implemented Phase-13 ingress exposes canonical SubmitCommand, Identity, Conversation, Message send/read, and Communication Intent create/read operations without granting raw `AuthorizedDurableRuntime` or storage access. Service Account Message writes preserve the authenticated API source in `Message.origin.principal_id`; this does not turn Actor authorship into authorization.

## Deferred implementation

Phase 0 did not claim those implementations. The current repository now has Prepared Internet/local transports, Call signalling, Audio, Video, Phase-22 direct-call E2EE media protection, Phase-23 Adaptive Media policy, Phase-24 Transport Orchestrator planning, and Phase-25 bounded duplicate-safe Automatic Failover. Offline Groups, standardized group/SFU key management, conferences, bridges, store-and-forward execution, mesh, federation, SDK language bindings, and production deployment remain later work.

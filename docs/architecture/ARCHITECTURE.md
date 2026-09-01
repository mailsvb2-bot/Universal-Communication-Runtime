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

- `Identity` is not a phone number, email address, provider ID, hostname, IP address, or database sequence.
- `Endpoint` is replaceable and can disappear without destroying `Identity`.
- `Conversation` is not owned by a transport/provider.
- `CommunicationIntent` is persisted independently from route availability.
- `Policy` is evaluated independently from a selected route.
- Transport/provider implementations may declare capabilities; they may not redefine Message, Conversation, Identity, Delivery, or Policy.
- External consumers do not get direct database access or hidden APIs.
- Multi-tenancy is a security boundary from the first implementation.
- Protocol and public API are language-independent and versioned from the first version.
- Rust is the reference implementation language, not the protocol definition language.

## Public contract boundary

The public contract is represented first as a versioned protocol specification plus protobuf schemas. Rust types are a reference mapping of the specification, not the specification itself.

Supported contract surfaces are expected to include protobuf/gRPC, HTTP where appropriate, event streams, local IPC and embedded APIs. They must express the same canonical semantics.

## Provider boundary

A future transport must be addable through a `TransportProvider`-style boundary containing capabilities, addressing, delivery semantics, health, failure mapping and conformance behavior without changing the meaning of canonical entities.

A future external platform must integrate through service principal/auth, permissions, commands, events, identity bindings and policies.

## Deferred implementation

Phase 0 deliberately does not claim production implementations for storage, cryptography, sync, calls, media, Internet transport, local transport, bridges, store-and-forward, mesh, federation or SDK language bindings.

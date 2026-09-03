# Universal Communication Runtime (UCR)

Universal Communication Runtime is a product-agnostic communication protocol and Rust-first runtime.

The project is built around durable **Communication Intent**, **Identity**, **Conversation**, **Policy**, and **Delivery** rather than around any specific messenger, cloud, server, operating system, or transport.

## Canonical formula

**Protocol + Runtime + SDK + Reference Implementation + Optional Infrastructure**

```text
UCR Specification
      ↓
UCR Protocol
      ↓
UCR Core Runtime
      ↓
SDK / API / IPC
      ↓
Applications / Platforms
      ↓
Optional Infrastructure
```

## Fundamental laws

1. Intent outlives Transport.
2. Identity outlives Endpoint.
3. Conversation outlives Provider.
4. Policy outlives Route.
5. Specification outlives Implementation.
6. There is one canonical communication model.
7. External products use only the public UCR contract.
8. Native UCR communication has zero mandatory cloud dependency.
9. Security/privacy policy must not silently degrade for availability.
10. Fundamental changes require ADR/RFC governance.

## Current architectural layer

**Phase 12 — Anti-Entropy (completed local/reference foundation; parity hardening continues without inventing a new phase).**

Phases 0–12 now have canonical/local-reference contracts and regression invariants. Phase 12 established versioned canonical Event fingerprints, snapshot-safe Anti-Entropy enumeration, missing/matching/damaged reconciliation semantics, and complete Event extension persistence parity. Post-Phase-12 hardening now restores `CommandEnvelope` schema-version/extension parity across protobuf, Rust, memory, and SQLite schema v9, and restores complete Rust/protobuf parity for versioned `CommandReceipt`, generic `AcknowledgementEnvelope`, payload-bearing negotiation Hello/Result, public Capability extension semantics, Message extensions with SQLite schema v10, complete Communication Intent correlation/extension fields, and forward-compatible public ErrorEnvelope semantics. The same hardening also makes ordinary Rust `Debug` model-owned and redacted for sensitive Event/Message/Intent material. Network transports, remote peer authentication/authorization, routing, and automatic damaged-replica repair remain separate layers.

Canonical `OpaqueId` semantics are also explicit: the v1 protobuf `bytes` field carries a non-empty exact UTF-8 token of at most 128 bytes. Invalid UTF-8 is rejected semantically; IDs are never normalized or rewritten, preserving the existing fingerprint and SQLite reference semantics.

This repository intentionally does not begin with chat UI, messenger adapters, WebRTC, mesh, or a cloud service. Those are consumers/providers of the canonical model and must not become alternative sources of truth.

## Repository layout

- `docs/canon/` — provenance of the canonical UCR Canon.
- `docs/architecture/` — architecture and trust-boundary documentation.
- `docs/adr/` — accepted architecture decisions.
- `docs/rfc/` — proposals for substantial changes.
- `spec/` — language-independent protocol specification.
- `proto/` — language-independent public contract schemas.
- `crates/ucr-model/` — canonical Rust model vocabulary.
- `crates/ucr-protocol/` — protocol/version negotiation reference logic.
- `crates/ucr-core/` — runtime boundary contracts; no product-specific logic.
- `crates/ucr-crypto/` — versioned cryptographic reference implementation and non-exporting key-operation boundaries.
- `crates/ucr-storage-memory/` — storage contract test implementation.
- `crates/ucr-storage-sqlite/` — local SQLite reference implementation.
- `crates/ucr-architecture-tests/` — architectural regression gates.

## Quality gate

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --release --locked
cargo audit --deny warnings
```

## Non-goals

UCR is not CRM, ERP, payment processing, booking, marketing automation, medical business logic, DecisionCore, World Model, or a product-specific SaaS platform.

## Licensing

The licensing boundary is intentionally **not decided yet**. Protocol, Core, SDKs, Reference Client, Managed Infrastructure and Enterprise features require a dedicated ADR/RFC before a public release license is selected.

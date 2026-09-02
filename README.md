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

**Phase 6 — Local Storage (active implementation layer).**

Phases 0–5 now have canonical contracts and reference invariants in `main`; Phase 6 is adding restart-safe local persistence without treating the database as a second protocol.

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
```

## Non-goals

UCR is not CRM, ERP, payment processing, booking, marketing automation, medical business logic, DecisionCore, World Model, or a product-specific SaaS platform.

## Licensing

The licensing boundary is intentionally **not decided yet**. Protocol, Core, SDKs, Reference Client, Managed Infrastructure and Enterprise features require a dedicated ADR/RFC before a public release license is selected.

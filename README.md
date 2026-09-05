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

**Phase 13 — Integration API (in progress; Phases 0–12 local/reference foundation complete).**

Phases 0–12 now have canonical/local-reference contracts and regression invariants. Phase 12 established versioned canonical Event fingerprints, snapshot-safe Anti-Entropy enumeration, missing/matching/damaged reconciliation semantics, and complete Event extension persistence parity. Post-Phase-12 hardening now restores `CommandEnvelope` schema-version/extension parity across protobuf, Rust, memory, and SQLite schema v9, and restores complete Rust/protobuf parity for versioned `CommandReceipt`, generic `AcknowledgementEnvelope`, payload-bearing negotiation Hello/Result, public Capability extension semantics, Message extensions with SQLite schema v10, complete Communication Intent correlation/extension fields, and forward-compatible public ErrorEnvelope semantics. The same hardening also makes ordinary Rust `Debug` model-owned and redacted for sensitive Event/Message/Intent material. Trusted Ed25519 device signing keys have exact-scope provision/rotate/revoke lifecycle with restart-safe SQLite v11 state and resolver-backed Message/handshake verification. Explicit PermissionGrants are restart-safe in SQLite v12, and `AuthorizedDurableRuntime` enforces protocol-owned permissions across all currently implemented permission-authorized tenant-scoped durable operations, including permission and Service Principal credential administration. Service Principal credentials authenticate the persisted canonical `ScopedPrincipal` with restart-safe SQLite v13 revocation before that same least-privilege permission boundary. SQLite v14 adds mandatory restart-safe fixed-window Service Principal quotas plus metadata-only append-only hash-chained admission audit through a single-use request evaluator with a Core-owned admission proof that prevents raw ServiceAccount runtime bypass. SQLite v15 now adds the separate exact-scope canonical Device lifecycle owner: only registered Active Devices can provision/rotate/resolve trusted signing keys, Message verification binds Device to persisted Identity, and Device revocation atomically revokes the current trusted signing key without allowing registration-based resurrection. SQLite v16 now makes canonical Communication Intent independently restart-safe through one `CommunicationIntentStore`: Memory/SQLite preserve target, payload, private policy, correlation, transport constraints and extensions; scoped `IntentId` reuse is duplicate-or-conflict deterministic; independent `ucr.intent.read`/`ucr.intent.write` permissions guard the runtime façade; and v15 migration invents no Intent from Message, Delivery, Event, or provider state. SQLite v17 extends the existing Service Principal audit owner with an optional generic `ServiceAuditOperationRef`: legacy no-operation records retain the exact V1 hash, operation-bound rows use a V2 hash in the same append-only chain, and the normalized child/index/triggers provide restart-safe exact-operation lookup without a Command-specific audit brain; v16 migration neither rehashes legacy evidence nor invents operation attribution. SQLite v18 now makes canonical `ExternalIdentityBinding` restart-safe through one exact-scope owner: the durable key includes `IntegrationId`, external namespace, and exact opaque external entity bytes; equal retries deduplicate, conflicting Identity reassignment fails closed, independent link/read permissions guard the runtime façade, and v17 migration invents no bindings. SQLite v19 now adds the canonical accountless/provider-independent Root `IdentityStore`: exact `(TenantScope, IdentityId)` rows persist Canon ownership, typed evidence, and optional expiry metadata; equal retries deduplicate, changed Root Identity semantics conflict, independent `ucr.identity.create`/`ucr.identity.read` permissions guard the runtime façade, and v18 migration invents no Identity from existing references. New external binding keys require an existing Root Identity while exact legacy v18 bindings remain readable/idempotently retryable. Recovery execution now also has a Core-owned authority-verifier gate and unforgeable admission proof; Memory/SQLite staging atomically re-checks the active Recovery Plan and can create only a `REVERIFICATION_REQUIRED` Device while invalidating residual Active trusted keys. Recovery now also has an independent Core-owned re-verification proof and atomic exact-Identity `REVERIFICATION_REQUIRED`→`ACTIVE` transition that cannot resurrect a revoked Device. Concrete production recovery-authority/re-verification providers, device-bound credential/content delivery, distributed/global edge throttling, and production hardware-backed private-key providers remain separate layers. Infrastructure metadata visibility is now explicitly inventoried and machine-checked against every canonical trust boundary; future Relay/Bridge/SFU/Cloud rows are privacy ceilings rather than implementation claims. A dedicated `ucr-security-tests` workspace crate now cross-checks eight implemented threat scenarios across Core/Crypto/Memory/SQLite boundaries; compromised Bridge and production-transport simulations remain open until those components actually exist. The same evidence set also runs seven cross-crate local/reference chaos scenarios for restart, duplicate ingress, clock rollback, local replica merge, old-client downgrade, authenticated-content corruption, and revoked-Device restart; the SQLite provider additionally has end-to-end page-capacity exhaustion evidence that returns `Full`, preserves atomic rollback, and reopens healthy, plus deterministic mid-operation process-kill evidence that terminates a separate process after real production inserts and before commit without leaving ghost acceptance. Future network infrastructure failures remain explicit open work. Network transports, remote peer authorization, routing, and automatic damaged-replica repair remain separate layers. Phase 13 now has a language-independent `IntegrationService` protobuf surface for `SubmitCommand`, `CreateIdentity`, and `LinkIdentity` plus a Core `IntegrationIngress` (with the original command-ingress alias retained) that composes existing Service Principal authentication, quota/audit, permission enforcement, and canonical durable owners without exposing raw storage or Rust ABI.

Canonical `OpaqueId` semantics are also explicit: the v1 protobuf `bytes` field carries a non-empty exact UTF-8 token of at most 128 bytes. Invalid UTF-8 is rejected semantically; IDs are never normalized or rewritten. Native UCR IDs now have one offline production default: `ucr.id.random_hex.v1`, using 128 bits from the OS CSPRNG encoded as 32 lowercase hex characters, with no time/server/provider fallback or ordering semantics. Canonical Message authorship now has versioned signing bytes plus Ed25519 verification through an exact-scope trusted signing-key resolver that also requires an Active durable Device and exact author Identity binding; public-key and Device lifecycle changes are restart-safe, while device-bound credential/content delivery and private-key provider lifecycle remain separate security work.

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
- `fuzz/` — isolated bounded libFuzzer/ASan targets for implemented untrusted parser/wrapper boundaries.

## Quality gate

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --release --locked
cargo audit --deny warnings
# fuzzing uses separately pinned nightly/cargo-fuzz; see fuzz/README.md
./fuzz/run-smoke.sh
```

## Non-goals

UCR is not CRM, ERP, payment processing, booking, marketing automation, medical business logic, DecisionCore, World Model, or a product-specific SaaS platform.

## Licensing

The licensing boundary is intentionally **not decided yet**. Protocol, Core, SDKs, Reference Client, Managed Infrastructure and Enterprise features require a dedicated ADR/RFC before a public release license is selected.

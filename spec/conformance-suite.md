# Phase 41 — Conformance Suite

## Status

Phase 41 defines the **Prepared** UCR Conformance Suite. It is an evidence layer over the existing public `ucr.v1` contract; it is not a new runtime, protocol, retry engine, permission engine, or communication brain.

The Canon requires conformance testing for SDKs, transports, bridges, and compatible nodes. SDK conformance covers exactly eight semantic areas: authentication, commands, events, retries, permissions, version negotiation, errors, and idempotency.

## Canonical rule

A candidate is called UCR-conformant only for the profile and evidence level that it actually passes. A partial or skipped profile is never promoted to a pass. Missing toolchains, missing vectors, unknown results, or silently skipped checks are failures of the claimed evidence level.

Conformance does not redefine canonical behavior. The checked-in protobuf files remain the wire source of truth and the canonical Core/runtime owners remain authoritative for domain semantics.

## SDK profile

The Phase-41 SDK profile applies to Rust, Python, TypeScript, Kotlin, and Swift and checks the same eight areas for every language surface.

1. **auth** — exact binary Service Principal metadata keys are used, opaque credential bytes are preserved, and secrets are redacted from diagnostics.
2. **commands** — canonical command request/response shapes come from `ucr.v1`; SDK code does not invent a second command model.
3. **events** — canonical EventService shapes are preserved and consumer cursor bytes remain opaque.
4. **retries** — an SDK call performs no hidden application-operation retry. Retryability is canonical evidence, not permission for an SDK to resubmit by itself.
5. **permissions** — permission denial remains a canonical server-owned outcome. SDKs neither grant permissions nor turn denial into success.
6. **version_negotiation** — `NegotiationHello` and `NegotiationResult` remain canonical protobuf types; SDKs do not guess, downgrade, or rewrite negotiated protocol state.
7. **errors** — canonical `ErrorEnvelope` values remain observable and are not translated into successful application outcomes.
8. **idempotency** — caller/canonical identifiers are preserved. SDKs do not mint replacement command/event/message identities during a retry path.

## Integration profile

The integration profile is the fail-closed contract used by an external SaaS or other product before it is treated as a compatible UCR consumer. It is separate from the language SDK profile and does not create new runtime owners.

It requires evidence for nine areas:

1. **auth** — the integration authenticates as the exact canonical Service Account / integration identity;
2. **create** — conference creation uses the stable Universal Conference contract and external reference IDs;
3. **join** — participant resolution and join-grant issuance use the canonical integration-scoped boundary;
4. **leave** — participant removal/revocation and realtime leave semantics remain canonical operations;
5. **webhook** — integrations use the canonical Event/Webhook subscription surface; executable conference evidence includes atomic `ucr.conference.started` / `ucr.conference.ended` lifecycle Events plus attendance `joined`, `left`, `reconnected`, and `media_ready` Events. Recording lifecycle webhook coverage remains required before Production integration certification;
6. **idempotency** — create and mutate retries preserve exact idempotency semantics and changed-request conflicts;
7. **expiry** — join grants remain bounded by their canonical expiry and event schedule constraints;
8. **permissions** — integration permissions remain server-owned and fail closed;
9. **tenant isolation** — one integration cannot read, mutate, join, or subscribe to another integration's conference state; Event subscriptions are durably owner-bound so an integration cannot poll or receive webhook delivery of another Service Account's attributed Events.

Prepared evidence for this profile is `contract + runtime-binding`. Static contract anchors alone cannot certify tenant isolation or expiry behavior as Production evidence; executable runtime proofs remain required before a deployment may claim full integration certification.

## Evidence levels

Phase 41 uses cumulative evidence levels:

- **contract** — the candidate is bound to the checked-in `ucr.v1` schemas and Phase-39 semantic manifest.
- **host-probe** — executable code in the candidate language proves the credential helper and Phase-41 policy markers on a real CI host.
- **runtime-binding** — executable client code crosses the public binding and demonstrates the same semantics against a UCR endpoint or equivalent binding test double without hidden Core/storage access.

The Prepared Phase-41 cross-language SDK proof requires `contract + host-probe` for all five language surfaces and `runtime-binding` for the Rust reference SDK. Later package/release work may raise the evidence level without changing this semantic matrix.

## Conformance artifacts

- `sdk/conformance/matrix.json` is the machine-readable matrix.
- `sdk/conformance/validate.py` is the dependency-free fail-closed validator.
- each language directory contains an executable `phase41_conformance` host probe that imports or compiles the actual Service Credential helper rather than copying credential behavior into the validator;
- `crates/ucr-sdk/tests/phase41_conformance.rs` is the Rust runtime-binding proof;
- `.github/workflows/conformance.yml` runs the five language probes independently on the same Ubuntu runner family used by repository CI.

## No second brain

Conformance code may inspect or call public SDK surfaces. It must not import UCR Core, direct storage providers, internal schedulers, route owners, provider workers, or privileged test-only bypasses into an SDK.

The suite may use deterministic test vectors and binding doubles, but those doubles never become product state or alternate canonical owners.

## Fail-closed behavior

The suite fails if:

- a required language or one of the eight SDK categories disappears;
- one of the required integration-profile categories disappears;
- a host probe is missing;
- credential metadata names drift;
- secret redaction disappears;
- automatic application retry is enabled;
- Event cursor semantics cease to be opaque;
- direct database access is enabled;
- canonical errors are no longer preserved;
- required command/event/negotiation/error protocol anchors disappear;
- a required conformance workflow or architecture lock disappears.

No `allow_failure`, best-effort, toolchain-skip, or “unsupported means pass” path is permitted for claimed Phase-41 evidence.

## Other conformance profiles

Transport, Bridge, and compatible Node profiles remain language-independent suite profiles. Their canonical dimensions come from Canon sections 206–207 and the relevant protocol/transport/bridge specifications. Phase 41 establishes the common fail-closed framework without moving transport, bridge, or node domain ownership into SDK code.

Existing executable transport/bridge/reference-node tests remain valid evidence and can be registered into the matrix incrementally without changing the SDK semantic contract.

## Non-claims

Phase 41 is **Prepared**, not Production certification. It does not claim registry publication, package signing, reproducible release artifacts, SBOM/provenance completion, long-term support policy, production SLA, or hardened production deployment. Supply-chain hardening belongs to Phase 44 and Production Hardening belongs to Phase 45.

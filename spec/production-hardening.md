# UCR Production Hardening — Phase 45

Status: **Production Candidate boundary under construction**. Candidate ≠ Production.

## Purpose

Phase 45 is the final Canon roadmap hardening phase. It does not create another Communication Core and it does not convert a Prepared capability into Production by changing a label. Production maturity is an evidence-backed release decision over the existing canonical runtime, protocol, SDK and provider boundaries.

A release is Production only when every mandatory gate in this specification is proven for the exact source commit and exact production artifact set. Unknown, skipped, stale, partial or failed evidence is release-blocking.

## Canonical build profiles

The workspace defines four explicit build profiles required by the Canon:

- `development` — developer mechanics only;
- `test` — executable verification;
- `staging` — release-like pre-production validation;
- `production` — optimized production build mechanics.

Selecting the `production` Cargo profile is **not** a Production maturity claim. Build profile and maturity state are independent dimensions.

`ucr dev` remains development-only. It uses a memory test store, test transport, loopback API and development bootstrap credentials. Phase 45 MUST NOT package or describe that development environment as the production runtime.

## Fail-closed readiness evidence

`tools/production_readiness.py` validates `ucr.production-readiness.v1` evidence. Each gate has a status (`pass`, `fail`, `not-run`) and evidence text. A `pass` without evidence is invalid.

Every candidate must prove:

- `security`;
- `data_safety`;
- `compatibility`;
- `conformance`;
- `critical_chaos`;
- `public_contract`.

A Production release must additionally prove:

- `performance`;
- `metrics`;
- `diagnostics`;
- `telemetry_privacy`;
- `production_runtime`;
- `platform_signing`.

Production validation rejects any mandatory `fail` or `not-run` status.

## Security release gate

Release is blocked by the Canon for a critical vulnerability, auth failure, tenant-isolation failure, replay vulnerability, signature-verification failure, private-key exposure, broken revocation, broken recovery, plaintext telemetry or an unsigned artifact.

Phase 45 reuses existing canonical security tests and Phase 44 dependency/supply-chain evidence; it must not introduce a second authorization, crypto, identity, revocation or recovery owner.

## Data-safety release gate

Release is blocked for silent message loss, silent attachment loss, a user-visible duplicate, crash-corrupted DB, destructive migration or unbounded queue growth.

Existing SQLite process-kill/storage-full evidence and Chaos Lab scenarios are inputs to this gate. Their existence does not remove the need for an exact Phase-45 release run.

## Compatibility release gate

Release is blocked if a supported old client is broken without a declared breaking version, an event schema becomes unreadable, a migration loses unsynced state, or a Stable SDK is broken without versioning.

Conformance and public-contract checks remain independent release evidence and are not replaced by Rust unit tests.

## Performance release gate

The Canon forbids weakening a fixed SLO merely to make CI green without an ADR and evidence.

ADR 0092 fixes the initial Phase-45 production-profile performance regression contract:

- canonical workload: `1000-person-sfu-conference-lifecycle`;
- existing reference test: `thousand_person_sfu_conference_fits_bounded_call_ceiling`;
- three measured samples;
- **10.0 seconds maximum per sample**;
- GitHub-hosted Ubuntu 24.04 with the repository-pinned Rust toolchain;
- machine-readable evidence tied to the exact source commit.

`tools/performance_gate.py` owns the threshold as source code. It is intentionally not a workflow parameter. Changing the workload, sample count or threshold requires a follow-up ADR and replacement evidence; a red CI run alone is not a reason to relax it.

The existing 1000-person test remains a bounded functional-scale model rather than a public Internet/media latency SLA. Phase 45 adds a concrete production-profile regression budget without overclaiming WAN throughput, codec density or hardware-wide capacity planning.

## Observability and telemetry privacy

The Definition of Done requires metrics and diagnostics to be available and plaintext to stay out of telemetry. Development diagnostics do not satisfy the production requirement.

The dedicated `ucr-runtime` local-daemon candidate exposes bounded operational evidence only:

- runtime mode;
- durable SQLite schema version;
- durable-store health;
- `ucr_runtime_up`;
- `ucr_storage_schema_version`;
- `ucr_storage_healthy`.

The exact Phase-45 operator smoke initializes a fresh durable database, reopens it through `check`, reads `metrics`, rejects sensitive-data markers in those outputs and proves that a non-loopback plaintext bind is refused. Candidate evidence may mark `metrics`, `diagnostics`, `telemetry_privacy` and `production_runtime` as `pass` only after those executable steps succeed on the same source commit.

No plaintext messages, decrypted attachments, private keys, recovery secrets or authentication secrets belong in this observability surface.

## Production runtime boundary

`ucr-runtime` is a distinct durable local-daemon runtime candidate. It reuses the canonical public gRPC service layer, authorization owners and `SqliteLocalStore`; it does not copy Communication Core domain ownership.

The runtime requires an explicitly initialized SQLite database before `serve`. It does not auto-create development credentials, identities or test transports. Plaintext service binding is loopback-only. Remote service mode is not claimed until an explicit authenticated TLS/public-listener boundary exists.

The runtime must not depend on `TestTransport`, `MemoryLocalStore`, sandbox fault injection or dev credential printing.

## Platform signing boundary

Phase 44 supplies cryptographic source-to-artifact provenance and SBOM attestations through GitHub OIDC/Sigstore. That is required supply-chain evidence but it is not the platform executable/package signature required for Production artifacts.

Phase 45 `platform_signing` can pass only on independently verifiable platform-appropriate signing evidence bound to the exact production artifacts. `not-claimed-phase44` or Sigstore-only evidence is rejected by the readiness verifier.

No ephemeral CI key may be presented as long-lived production publisher identity.

## Candidate CI

The Phase-45 workflow builds and validates release-like profiles and reruns the candidate-critical security/data-safety/compatibility/conformance/chaos/public-contract evidence. It also executes the durable runtime/observability boundary and the fixed production-profile performance contract.

The evidence document remains a **candidate** claim. Platform signing stays explicit and independent; until real publisher signing is configured and verified, Production promotion must fail closed.

A green Phase-45 candidate workflow therefore means the implemented candidate gates passed on one exact source commit. It does **not** by itself mean UCR is Production.

## Promotion rule

Production promotion requires all of the following on the same exact source/artifact release candidate:

1. candidate-required gates pass;
2. the fixed performance contract passes without threshold weakening;
3. production metrics and diagnostics are available;
4. telemetry privacy is proven;
5. the production runtime boundary is proven independently of dev/test mode;
6. platform signing is cryptographically verified;
7. Phase 44 provenance/SBOM evidence remains valid;
8. the final `production` readiness validation passes.

Anything less remains Candidate/Prepared/Beta according to the capability's actual maturity evidence.

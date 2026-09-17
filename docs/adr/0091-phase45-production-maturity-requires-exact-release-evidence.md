# ADR 0091: Production maturity requires exact release evidence

Status: Accepted

## Context

The Canon distinguishes build profiles from maturity states and explicitly states `Prepared ≠ Production`. It also defines independent Security, Data Safety, Compatibility and Performance release gates, requires production metrics/diagnostics, forbids plaintext telemetry, and requires signed Production artifacts.

Phase 44 added exact dependency state, SBOM, build provenance and Sigstore-backed artifact attestations. Those controls prove supply-chain provenance but do not prove runtime operational maturity or platform executable/package signing.

The repository also contains `ucr dev`, a deliberately development-only environment using memory/test providers. Treating that binary or a `cargo build --profile production` result as a Production runtime would collapse the Canon's maturity boundary.

## Decision

Production maturity is an explicit fail-closed evidence decision for one exact source commit and release artifact set.

The repository owns one machine-readable readiness schema, `ucr.production-readiness.v1`, validated by `tools/production_readiness.py`.

Candidate evidence must already prove the existing release-critical security, data-safety, compatibility, conformance, critical-chaos and public-contract gates. Production promotion additionally requires performance, metrics, diagnostics, telemetry privacy, production runtime and platform-signing evidence.

A missing, skipped or unknown mandatory Production gate is not success. The verifier rejects it.

The Cargo `production` profile defines build mechanics only. It cannot change capability maturity.

`ucr dev` remains development-only and cannot satisfy the `production_runtime` gate.

Phase-44 Sigstore/GitHub attestations cannot satisfy `platform_signing`; that gate requires separately verifiable platform-appropriate publisher signing bound to the exact Production artifacts. Ephemeral CI signing identities are insufficient as a long-lived production publisher identity.

Performance thresholds become release contracts once committed. Weakening a fixed threshold solely to restore green CI requires a separate ADR and evidence, matching the Canon.

## Consequences

- Phase-45 candidate CI can be green while explicitly reporting production-only gates as `not-run`; it must not claim Production.
- Production promotion has a single fail-closed machine-readable decision rather than a prose checklist.
- Existing security/storage/chaos/conformance owners are reused; Phase 45 does not create parallel Communication Core logic.
- A real production runtime, redaction-safe observability, fixed load/SLO proof and platform publisher signing must be implemented before the Production claim can pass.
- Supply-chain provenance remains necessary but is not confused with executable/package signing.

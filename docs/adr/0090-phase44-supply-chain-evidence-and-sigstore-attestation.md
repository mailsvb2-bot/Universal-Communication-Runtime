# ADR 0090: Phase 44 supply-chain evidence and Sigstore attestation

- Status: Accepted
- Phase: 44 — Supply-chain Hardening

## Context

The Canon requires dependency audit, lockfiles, vulnerability scanning, secret scanning, SBOM, build provenance and artifact signing, while separately requiring real production binaries to be signed by the appropriate platform mechanism. Treating a CI boolean or a checksum as a signature would create false release evidence.

UCR already pins GitHub Actions by commit in established workflows and audits the main/fuzz/Public SDK/Reference Messenger dependency states. Phase 44 extends this into one explicit source-to-artifact evidence boundary without introducing a second build system or claiming Phase 45 production readiness.

## Decision

1. Keep supply-chain validation in a pure-stdlib repository helper plus a dedicated CI workflow.
2. Require full-commit pinning for external GitHub Actions.
3. Perform a high-confidence secret scan without echoing candidate secret values.
4. Commit the lockfile for every current Rust build surface and consume those lockfiles with `--locked`.
5. Generate deterministic SPDX 2.3 SBOM evidence from Cargo metadata.
6. Record commit, dependency hashes, environment, tests, artifact hashes and signing state in machine-readable build evidence.
7. Protect candidate update sets with a complete release manifest, exact source commit, monotonic release sequence, SHA-256/size verification and adversarial tamper/rollback/wrong-source/partial-update tests.
8. On `main`, use the official SHA-pinned `actions/attest` action with GitHub OIDC to create Sigstore-backed build/SBOM attestations and independently verify them with `gh attestation verify` constrained to repository, signer workflow, source ref and source commit.
9. Keep `platform_binary_status` explicit and `not-claimed-phase44`. Sigstore provenance is not Authenticode, notarization or package signing.

## Consequences

Phase 44 provides cryptographically verifiable supply-chain identity for exact `main` artifacts and their SBOM/evidence while preserving the distinction between provenance signing and platform executable signing.

A future Phase 45 production release must still supply and verify the platform-appropriate executable/package signature. It may consume the Phase 44 manifest and attestations, but it must not weaken or reinterpret them.

The helper and workflow are evidence infrastructure only. They do not own Message, Delivery, Transport, storage, update rollout policy or communication-domain state.

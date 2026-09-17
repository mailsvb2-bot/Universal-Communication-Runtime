# UCR Supply-chain Hardening — Phase 44

Status: **Prepared**. Prepared ≠ Production.

## Purpose

Phase 44 makes the source-to-artifact chain explicit and machine-verifiable without changing the UCR communication domain model. The supply-chain boundary must fail closed on dependency vulnerability evidence, leaked high-confidence credentials, unpinned third-party GitHub Actions, artifact tampering, rollback, partial update sets, or unverifiable build provenance.

Phase 44 does not turn a Prepared Linux release candidate into a Production release. In particular, a Sigstore/GitHub Artifact Attestation is supply-chain provenance and **does not satisfy the platform executable signature requirement** for production binaries. Platform-specific executable/package signing remains a Phase 45 production release gate.

## Dependency state

The canonical root, fuzz and standalone Prepared Rust surfaces use committed lockfiles. The Phase 44 workflow consumes them with `--locked`; it must not silently resolve a new dependency graph during release evidence generation.

The gate audits:

- root `Cargo.lock`;
- `fuzz/Cargo.lock`;
- Public SDK `Cargo.lock`;
- Reference Messenger `Cargo.lock`;
- AI Actor `Cargo.lock`;
- Chaos Lab `Cargo.lock`.

A dependency vulnerability failure is fatal. The gate does not use `continue-on-error` or success-masking shell fallbacks.

## Workflow dependency pinning

Every external GitHub Action used by `.github/workflows` must be pinned to a full 40-hex commit SHA. Floating tags such as `@main`, `@v4` or partial SHAs are rejected. Local repository actions may use `./...`.

The rule is enforced both by `tools/supply_chain.py scan-actions` and by a workspace architecture regression test.

## Secret scanning

`tools/supply_chain.py scan-secrets` performs a high-confidence repository scan for private-key material and selected credential/token formats. Findings report only rule, path and line; the suspected secret value itself is never printed.

This is an in-repository release gate, not a claim to replace GitHub secret scanning or organization-wide credential monitoring.

## SBOM

The Phase 44 workflow captures Cargo metadata for the root and all standalone Prepared Rust surfaces and emits a deterministic SPDX 2.3 JSON document. The SBOM is treated as build evidence and, on `main`, is attached to a signed GitHub/Sigstore SBOM attestation for the exact rebuilt binary.

## Build evidence

Each candidate records:

- source commit;
- dependency lock-state hashes;
- build environment and tool versions;
- build/test evidence labels;
- artifact SHA-256 and size;
- supply-chain signing identity/status;
- an explicit platform-binary-signing status.

Validation builds use `platform_binary_status = not-claimed-phase44`. Phase 44 intentionally cannot set this to a production-signed claim.

## Provenance and supply-chain signature

For `main`, the dedicated workflow rebuilds the exact commit and uses the SHA-pinned official `actions/attest` action to create Sigstore-backed GitHub Artifact Attestations:

- SLSA-style build provenance for the binary;
- an SPDX 2.3 SBOM attestation binding the generated SBOM to that binary;
- provenance for the supporting build evidence and release manifest.

The workflow then verifies the attestations with `gh attestation verify`, constrained to this repository, the Phase 44 signer workflow, the exact source commit and `refs/heads/main`. Failure is fatal.

## Update-integrity evidence

The Prepared release manifest contains a monotonic release sequence, exact source commit and the complete required artifact set with size and SHA-256. The verifier rejects:

- artifact hash/size mismatch;
- missing required artifact;
- inconsistent/partial artifact sets;
- a source commit different from the caller's expected commit;
- a release sequence below the caller's minimum accepted sequence;
- unsafe artifact names.

The adversarial self-test proves tamper, rollback, wrong-source and partial-update rejection. The attested manifest is the reusable integrity boundary for later updater integration; Phase 44 does not claim a production updater already exists.

## Signing boundary

There are two distinct meanings of "signed":

1. **Supply-chain attestation** — Phase 44: GitHub OIDC identity + Sigstore-backed attestation of provenance/SBOM/evidence.
2. **Platform executable/package signature** — Phase 45 production hardening: Authenticode/notarization/package signing or the platform-appropriate production signature.

A successful Phase 44 attestation MUST NOT be presented as proof that requirement 2 is complete.

## Evidence retention

The workflow uploads the binary candidate, SPDX SBOM, build-evidence JSON and release-manifest JSON. Pull-request validation evidence is short-lived; attested `main` evidence is retained longer. GitHub attestations remain independently verifiable through the repository attestation trust chain.

## Non-claims

Phase 44 does not claim:

- platform production signing;
- production update rollout;
- reproducible bit-for-bit builds across every OS/toolchain;
- organization-wide secret management;
- replacement of platform stores, notarization services or package-signing systems.

Those production claims remain subject to Phase 45 gates.

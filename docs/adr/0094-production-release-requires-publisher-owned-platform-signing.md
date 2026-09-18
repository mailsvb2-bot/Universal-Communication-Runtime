# ADR 0094: Production release requires publisher-owned platform signing

## Status

Accepted for the first Linux Production release path.

## Context

UCR Canon 1.0 requires signed Production artifacts and treats an unsigned artifact as a
release-blocking security failure. Phase 44 already proves source-to-artifact provenance,
SBOM integrity, exact source commit, rollback/tamper resistance, and GitHub/Sigstore
attestation. Phase 45 adds live native signature verification and deliberately rejects
Sigstore-only evidence as a substitute for platform signing.

What remained missing was the actual release path that consumes a publisher-owned signing
identity and applies it to the exact Production runtime artifact.

The release path must not:

- keep a private publisher key in the repository;
- generate an ephemeral CI identity and present it as the publisher;
- sign an arbitrary branch or stale commit;
- accept pull-request-only checks as Production evidence;
- trust a self-reported `platform_signing=pass`;
- attest one source commit while signing another checkout.

## Decision

The first concrete Production release path targets the Linux `ucr-runtime` artifact.

A manual GitHub Actions workflow may create a signed Production bundle only when all of the
following hold:

1. the workflow is dispatched from `refs/heads/main`;
2. the requested source is a lowercase 40-hex commit;
3. `GITHUB_SHA`, checked-out `HEAD`, requested source, and current `origin/main` are exactly
   the same commit;
4. exact-main push runs for CI, Conformance, Phase 42, Phase 43, Phase 44, and Phase 45 are all
   successful for that same commit;
5. the `production` GitHub Environment grants access to an externally provisioned
   publisher-owned OpenPGP private key and expected fingerprint;
6. the runtime is rebuilt with Cargo's locked `production` profile;
7. the detached OpenPGP signature is verified by `tools/platform_signing.py` against the
   configured publisher fingerprint;
8. `tools/production_readiness.py` performs its own live signature verification while
   validating the Production maturity claim;
9. the signed binary, detached signature, signing receipt, readiness evidence, SBOM,
   exact-main proof, and release manifest are included in one complete manifest;
10. the complete bundle is GitHub/Sigstore-attested and independently verified before upload.

The signing key is supplied only through GitHub Environment secrets. The workflow references
secret names but never stores private key material in source control.

## Publisher secret contract

The `production` environment is expected to provide:

- `UCR_LINUX_GPG_PRIVATE_KEY_BASE64` — base64-encoded publisher private key export;
- `UCR_LINUX_GPG_FINGERPRINT` — full expected publisher key fingerprint;
- `UCR_LINUX_GPG_PASSPHRASE` — optional key passphrase.

A missing key or fingerprint is an intentional fail-closed release blocker.

## Consequences

- Main can stay fully green without production signing secrets.
- A release cannot be silently produced by a pull request or arbitrary branch.
- Re-running a release for an old main commit is blocked once main advances.
- Source provenance and platform publisher identity remain independent evidence layers.
- The repository becomes technically ready to create a signed Linux Production artifact once
  the publisher identity is provisioned.
- Production 1.0 is still not claimed merely because this workflow exists; an actual successful
  publisher-signed release execution is required.

## Follow-up

Windows Authenticode and macOS codesign verifiers already exist in
`tools/platform_signing.py`. Equivalent protected signing workflows may be added when those
platform artifacts are selected for Production distribution.

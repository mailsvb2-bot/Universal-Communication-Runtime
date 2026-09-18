# Production Release Signing

This specification defines the first concrete Production artifact signing path for UCR.

## Scope

The initial signed Production target is:

- platform: Linux x86_64 GitHub-hosted runner;
- artifact: `ucr-runtime-linux-x86_64`;
- build profile: Cargo `production`;
- platform signature: detached OpenPGP signature;
- publisher identity: externally provisioned long-lived OpenPGP key fingerprint.

Windows Authenticode and macOS codesign verification remain supported by
`tools/platform_signing.py`, but this workflow does not claim that Windows or macOS
Production artifacts exist yet.

## Release source boundary

A signed release may be created only for the exact current `main` head.

The release workflow must prove all of the following before executing repository code that can
claim Production:

- `source_commit` is a lowercase full 40-hex SHA;
- `GITHUB_REF == refs/heads/main`;
- `GITHUB_SHA == source_commit`;
- checked-out `HEAD == source_commit`;
- current `origin/main == source_commit`.

This deliberately blocks signing a stale, detached, pull-request, feature-branch, or arbitrary
historical source through the standard Production release path.

## Exact-main quality proof

The signing workflow must query GitHub Actions for the exact source commit and require
successful `push` runs for:

- CI;
- Conformance;
- Phase 42 AI Actor;
- Phase 43 Chaos Lab;
- Phase 44 Supply Chain;
- Phase 45 Production Hardening.

A pull-request run does not satisfy this boundary. A successful run for another SHA does not
satisfy this boundary.

## Publisher key boundary

Publisher credentials are external deployment secrets, not source files.

The protected `production` GitHub Environment supplies:

- `UCR_LINUX_GPG_PRIVATE_KEY_BASE64`;
- `UCR_LINUX_GPG_FINGERPRINT`;
- optionally `UCR_LINUX_GPG_PASSPHRASE`.

The imported secret-key fingerprint must exactly equal the configured publisher fingerprint
after normalization. Missing, malformed, or mismatched signing material blocks release.

The temporary key file is removed immediately after import. The temporary GnuPG home is
removed in an `always()` cleanup step.

## Build and signing sequence

1. Verify exact current-main source and publisher secret presence.
2. Verify exact-main workflow proof.
3. Build `ucr-runtime` with `cargo build --locked --profile production`.
4. Run `ucr-runtime` unit tests.
5. Generate a deterministic SPDX 2.3 SBOM from locked Cargo metadata.
6. Create a detached armored OpenPGP signature over the exact production binary.
7. Verify that signature through `tools/platform_signing.py`.
8. Validate `ucr.production-readiness.v1` through
   `tools/production_readiness.py --mode production`, which repeats live native signature
   verification.
9. Create and verify a complete release manifest.
10. Sigstore-attest the complete signed release bundle.
11. Verify those attestations against the repository, main workflow identity, source ref, and
    exact source digest.
12. Upload the bundle only after every prior step succeeds.

## Signed release bundle

The release manifest requires exactly:

- `ucr-runtime-linux-x86_64`;
- `ucr-runtime-linux-x86_64.asc`;
- `ucr-platform-signing.json`;
- `ucr-production-readiness.json`;
- `ucr.spdx.json`;
- `main-proof.json`.

The release manifest itself is also included in the uploaded and attested bundle.

## Production maturity boundary

Having the workflow in source control does **not** satisfy Canon Definition of Done item 31 by
itself.

Production artifact signing is proven only by a successful protected workflow execution using
the real publisher identity, producing a native signature that verifies against the configured
fingerprint for the exact artifact.

GitHub/Sigstore attestation remains supply-chain provenance. It is required in the release
bundle but is not substituted for the publisher's platform signature.

## Failure policy

The release is blocked on:

- non-main or stale source;
- missing exact-head workflow proof;
- any required workflow not successful;
- missing publisher secrets;
- malformed or mismatched fingerprint;
- signing failure;
- native signature verification failure;
- Production readiness failure;
- incomplete or tampered release manifest;
- Sigstore attestation or verification failure.

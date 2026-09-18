# ADR 0093: Production readiness requires live platform signature verification

## Status

Accepted for Phase 45.

## Context

The Canon requires signed Production artifacts and release evidence that records the signing
identity. Phase 44 Sigstore/GitHub attestations prove source-to-artifact provenance and SBOM
integrity, but the Canon separately requires Production binaries to be signed by an available
platform mechanism.

A readiness document containing only `platform_signing.status = pass` plus free-form evidence
is not sufficient. Such a record is self-asserted metadata and could be fabricated without
verifying the artifact.

## Decision

Production validation MUST execute a native platform verifier against the exact artifact in the
same validation path that accepts the Production claim.

Supported verification modes are:

- **Windows Authenticode**: `signtool verify /pa /all /v` plus exact signer certificate
  thumbprint verification through `Get-AuthenticodeSignature`.
- **macOS codesign**: `codesign --verify --deep --strict` plus exact TeamIdentifier matching.
- **Linux OpenPGP**: detached signature verification through `gpg --verify` plus exact
  `VALIDSIG` fingerprint matching.

The verification result is bound to:

- exact 40-hex source commit;
- exact artifact SHA-256;
- platform verification mode;
- signing identity;
- native verifier method.

Missing verifier tooling, missing signature material, a mismatched identity, an unsigned
artifact, or a failed native verifier blocks Production.

`tools/production_readiness.py` therefore cannot accept a Production claim merely because the
evidence document says that `platform_signing` passed. When that gate is marked pass, the
validator requires live platform-verification arguments and calls
`tools/platform_signing.py`.

## Consequences

- Phase 45 can remain green as a **Candidate** before a publisher certificate/key exists.
- A fake JSON receipt or manually edited readiness document cannot by itself produce a
  Production result.
- Phase 44 Sigstore provenance remains mandatory supply-chain evidence but is not relabeled as
  platform signing.
- Real Production promotion will require publisher-owned signing material provisioned outside
  the repository and an OS-appropriate signing step before the live verification step.
- The signing identity becomes explicit evidence, satisfying the Canon build-evidence
  requirement instead of being implied by CI configuration.

## Non-goals

This ADR does not choose or provision the publisher certificate/key and does not put signing
secrets in GitHub. It defines the verification boundary that any future signing workflow must
satisfy.

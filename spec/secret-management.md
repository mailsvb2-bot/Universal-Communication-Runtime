# Secret and key provider boundary

UCR secret material uses one replaceable `SecretProvider` boundary. The provider owns retrieval and
rotation of opaque secret material; it must not become a second authentication, authorization,
Conference, Recording, TLS policy, webhook delivery, or media-crypto state owner.

The canonical handle consists of an opaque secret identifier plus an explicit purpose. Supported
purposes cover Service/Join signing integration, webhook signing, TLS certificate/private key,
media crypto, and TURN credentials. Secret material is bounded, redacted from Debug output, and
zeroized on drop in the Rust reference implementation.

Rotation is overlap-safe. One handle exposes a current version and at most one previous version.
Writers/signers use current; verifiers may accept current or previous during a bounded deployment
overlap. Exact retries of the same version and material are idempotent; reusing a version identifier
with changed material conflicts. A second rotation discards the oldest version so the provider can
never become an unbounded key history database.

`InMemorySecretProvider` is executable reference evidence only. It does not make Production secret
management complete. Production adapters may use an OS keyring, HSM, cloud KMS, HashiCorp Vault, or
another operator-approved backend, but raw secret bytes must not be persisted in UCR's general
SQLite state or printed in logs.

This boundary is a prerequisite for zero-downtime rotation of join signing keys, webhook signing
keys, TLS private keys/certificates, media crypto roots, and TURN credential roots. Each consumer
must still prove its own overlap/reload semantics before the corresponding Production claim is
enabled.

## Join signing integration

`JoinTokenIssuer` retains its static-key constructor for compatibility, and also supports the shared
provider boundary. Provider-backed issuance always signs with the current JoinSigning secret version.
Verification accepts current and previous versions, so already-issued short-lived grants continue to
verify during one bounded rotation overlap without changing the token wire format. A second rotation
drops the oldest version, after which tokens signed by that oldest key fail signature verification.

Provider unavailability or malformed key length fails closed as `KeyUnavailable`; the issuer never
falls back to an unrelated key or silently re-enables a retired version.

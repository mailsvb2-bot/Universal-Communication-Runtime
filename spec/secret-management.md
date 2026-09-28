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


## TURN credential root integration

`TurnRestCredentialIssuer` supports the same shared provider boundary with a
`TurnCredentials` handle. Every short-lived credential issuance resolves the current provider
version, so a root rotation takes effect without reconstructing the WebRTC configuration factory.
Missing, unavailable, wrong-purpose, or malformed provider material fails closed; there is no
fallback to a stale static root.

This wiring does not by itself claim zero-downtime TURN rotation. The deployed TURN service must
also prove that its shared-secret reload/overlap behavior accepts the intended rotation window.
Short-lived TURN credentials remain scoped to the authenticated realtime `SessionId` and bounded
by the session lifetime.

## Webhook signing integration

`HardenedWebhookSink` supports the shared provider boundary with a `WebhookSigning` handle.
Provider-backed delivery resolves the current version for every request immediately before HMAC
construction, so a provider rotation affects new webhook signatures without reconstructing the
runtime worker. Missing, unavailable, wrong-purpose, or malformed provider material fails closed
through the retryable webhook-delivery path; the sink never falls back to a stale static key.

`ProductionRuntime` exposes provider-backed execution for both one-shot dispatch and the durable
webhook worker. The previous static-key entry points remain compatibility surfaces and therefore do
not constitute a silent public-contract break.

This slice does not yet claim complete Production secret management. The command-line deployment
path still accepts the compatibility environment key, and a durable external KMS/Vault/HSM adapter
with independently proven live reload/rotation remains required before the zero-downtime webhook
key-management Production claim is enabled.

## TLS edge integration

`ProviderBackedTlsAcceptor` binds the HTTPS edge to the shared `SecretProvider` with distinct
`TlsCertificate` and `TlsPrivateKey` handles. New inbound connections resolve active provider
material before handshake, so rotations can take effect without restarting the listener. Existing
TLS sessions retain the acceptor snapshot with which they already negotiated.

Certificate and private-key rotation may be staged independently. The edge prefers the
current/current pair, then tries the bounded previous versions exposed by the provider. This keeps
one valid pair available during the overlap window while preventing unbounded historical-key
fallback. If no active pair parses and matches, or the provider is unavailable, that new connection
fails closed rather than silently reusing material outside the provider's active set.

The existing file-based `run` and `tls_acceptor` surfaces remain compatibility paths, so this is
not a silent deployment-contract break. Complete Production secret management still requires a
durable external provider adapter and operator evidence for its availability, authorization,
rotation, and recovery behavior.

### Shipped HTTPS-edge provider mode

The shipped `ucr-https-edge` binary enters the provider-backed path through
`run_configured()`. Setting `UCR_HTTPS_EDGE_SECRET_PROVIDER=file-reload` selects the
`ReloadingFileTlsSecretProvider` compatibility adapter; current certificate/private-key files are
re-read for new connections, and optional previous files provide the bounded overlap pair during a
staged rotation. Secret IDs are configurable through the corresponding certificate/key secret-id
environment variables.

Provider lookup and PEM parsing do not run in the serial accept loop. Each accepted TCP connection
resolves its TLS material inside that connection task, so one slow provider operation cannot stop
the listener from accepting unrelated connections. A production KMS/Vault/HSM adapter should keep
the same non-blocking listener property and may add its own bounded cache/refresh strategy.

## Machine token signing integration

The OAuth2/M2M machine-auth service uses a distinct `MachineTokenSigning` secret purpose. In
provider-backed mode, every client-credentials exchange resolves the provider's current 32-byte
Ed25519 seed immediately before token issuance. The provider version identifier becomes the JWT
`kid`, so rotating material cannot silently reuse an old public-key identity.

The JWKS endpoint resolves the same active set on every request and publishes public keys for the
current version plus at most one previous version. New tokens are signed only by current while
tokens minted before rotation remain verifiable during the bounded overlap window. Missing,
wrong-purpose, unavailable, malformed, or duplicate-version provider state fails closed; the
machine-auth service does not fall back to a stale static seed.

`ucr-runtime serve-auth` exposes this path with
`UCR_MACHINE_TOKEN_SECRET_PROVIDER=file-reload`. The current manifest is configured through
`UCR_MACHINE_TOKEN_SIGNING_SECRET_FILE`; an optional previous manifest is configured through
`UCR_MACHINE_TOKEN_PREVIOUS_SIGNING_SECRET_FILE`. Each manifest is a bounded, non-symlink,
owner-protected text file with exactly:

```text
key_id=<opaque-key-id>
seed_hex=<64 lowercase-or-uppercase hex characters>
```

The manifests are re-read for issuance/JWKS resolution, so operators can rotate with atomic file
replacement without restarting the machine-auth listener. The legacy
`UCR_MACHINE_TOKEN_SIGNING_KEY_ID` + `UCR_MACHINE_TOKEN_SIGNING_KEY_FILE` startup path remains
available for compatibility.

This still does not claim a durable external KMS/Vault/HSM adapter. It closes the canonical UCR
consumer/runtime path and provides an executable reloadable deployment adapter; production
external-provider availability, authorization, and recovery evidence remains a separate gate.

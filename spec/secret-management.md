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

Provider-backed TURN material is additionally constrained to exactly 32 visible ASCII bytes. This is
an interoperability invariant, not a cryptographic downgrade: coturn's REST shared secret is a
string value, so arbitrary binary roots cannot be represented as the exact same HMAC key. The
provider validates both current and previous versions before issuance; a mixed rotation snapshot
with an unrepresentable previous root fails closed instead of claiming an overlap that coturn cannot
mirror. Operators should generate high-entropy visible-ASCII roots and encode those bytes as hex in
the shared provider manifest.

The legacy in-process `TurnRestSecret::from_bytes` constructor remains available for API
compatibility and tests, but it is not evidence that arbitrary binary deployment roots are coturn
portable.

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

The JWKS endpoint resolves the same active snapshot on every request and publishes public keys for
the current version plus at most one previous version. New tokens are signed only by current while
tokens minted before rotation remain verifiable during the bounded overlap window. Missing,
wrong-purpose, unavailable, malformed, or duplicate-version provider state fails closed; the
machine-auth service does not fall back to a stale static seed.

`ucr-runtime serve-auth` exposes this path with
`UCR_MACHINE_TOKEN_SECRET_PROVIDER=file-reload`. The signing snapshot is configured through
`UCR_MACHINE_TOKEN_SIGNING_SECRET_FILE` and is a bounded, non-symlink, owner-protected file.
Current and previous versions live in one atomically replaceable snapshot:

```text
current_key_id=<opaque-key-id>
current_seed_hex=<64 hex characters>
previous_key_id=<opaque-key-id>        # optional, paired with previous_seed_hex
previous_seed_hex=<64 hex characters> # optional, paired with previous_key_id
```

This single-file shape is required: current and previous must never be read from independently
rotated files because that creates an interval where the old token key disappears or the snapshot
conflicts.

The public API verifier has an independent public-only reload boundary. Setting
`UCR_MACHINE_TOKEN_VERIFICATION_PROVIDER=file-reload` makes `serve` and `serve-realtime`
re-read `UCR_MACHINE_TOKEN_VERIFICATION_JWKS_FILE` for each machine Bearer admission. The
Universal Conference and Recording ingress paths therefore observe the same refreshed public key
set without process restart.

A zero-downtime rotation follows this order:

1. Atomically publish verifier JWKS containing both `v2` and `v1` to API processes.
2. Atomically replace the signing snapshot with `current=v2, previous=v1`.
3. Keep both verification keys for at least the maximum access-token lifetime plus deployment
   skew.
4. Retire `v1` by atomically publishing verifier JWKS with only `v2`, then replace the signing
   snapshot with only `current=v2`.

The legacy startup-only signing-key and static JWKS paths remain compatibility surfaces. A durable
external KMS/Vault/HSM adapter and deployment authorization/availability/recovery evidence remain
separate Production gates.


## Shipped runtime file-reload wiring

The production CLI now exposes the same shared provider boundary for the realtime and webhook
consumers instead of forcing deployment secrets to remain static process configuration.

- Join signing: `UCR_REALTIME_JOIN_SECRET_PROVIDER=file-reload` with
  `UCR_REALTIME_JOIN_SECRET_FILE` and optional `UCR_REALTIME_JOIN_SECRET_ID`.
- TURN REST root: `UCR_WEBRTC_TURN_SECRET_PROVIDER=file-reload` with
  `UCR_WEBRTC_TURN_SECRET_FILE` and optional `UCR_WEBRTC_TURN_SECRET_ID`.
- Webhook signing: `UCR_WEBHOOK_SECRET_PROVIDER=file-reload` with
  `UCR_WEBHOOK_SIGNING_SECRET_FILE` and optional `UCR_WEBHOOK_SIGNING_SECRET_ID`.

The manifest is a single bounded, non-symlink file so current/previous rotation is observed as one
snapshot. Generic field names are `current_version_id`, `current_secret_hex`,
`previous_version_id`, and `previous_secret_hex`; the machine-token
`current_key_id/current_seed_hex` aliases remain accepted for compatibility. On Unix, group/other
file permissions fail closed. File contents and decoded secret bytes are zeroized after parsing.
Static `*_HEX` paths remain compatibility inputs, not the recommended rotation path.

Provider-backed Join signing resolves current/previous material through `JoinTokenIssuer`;
provider-backed TURN resolves the current root for each short-lived credential issuance; provider-backed
Webhook signing resolves the current root immediately before each delivery attempt. Provider
unavailability never falls back to the stale static compatibility secret.

## MediaCrypto scope

`MediaCrypto` must not be wired into direct-call or group endpoint E2EE merely to satisfy a
configuration checklist. Direct-call traffic keys are derived from authenticated UCR Crypto sessions
with fresh X25519 ephemerals; group-media keys are owned by the RFC-9420/OpenMLS epoch state. Injecting
one deployment-wide root into either path would create a second media-crypto authority and weaken the
existing trust model.

The `MediaCrypto` purpose is therefore reserved for concrete deployment/provider-owned media roots
that actually require secret management (for example a future server-side recording, composition, or
broadcast encryption provider). No such provider may advertise Production capability until it wires
this purpose through the shared provider boundary and proves rotation/recovery semantics. The absence
of such a concrete consumer is an explicit non-claim, not permission to alter endpoint E2EE key
derivation.


## coturn dynamic secret reconciliation

For coturn deployments that use the SQLite user database, UCR ships an explicit operator command:

```text
ucr-runtime reconcile-turn-secrets \
  --turn-database /path/to/turndb \
  --turn-realm turn.example \
  --exclusive-turn-realm
```

The command requires the same provider-backed TURN configuration used by `serve-realtime`
(`UCR_WEBRTC_TURN_SECRET_PROVIDER=file-reload`,
`UCR_WEBRTC_TURN_SECRET_FILE`, and optional `UCR_WEBRTC_TURN_SECRET_ID`). It reconciles
coturn's `turn_secret` rows for exactly one realm to the provider snapshot
`{current, previous?}`.

Safety invariants:

- the coturn database path must be a regular non-symlink file and is opened read-write without CREATE; a wrong, redirected, or missing database fails closed;
- the canonical `turn_secret(realm,value)` schema is verified before mutation;
- an IMMEDIATE SQLite transaction serializes concurrent reconciliation writers;
- UCR inserts desired roots, removes stale roots in the same realm, verifies the exact resulting
  set, and only then commits;
- rows for other realms are never touched;
- the command refuses to mutate unless `--exclusive-turn-realm` is explicit, because coturn does
  not store secret version/owner metadata and UCR otherwise cannot distinguish stale UCR roots from
  roots owned by another operator;
- secret values are not returned in command output or debug evidence;
- provider material must pass the same coturn-safe 32-byte base64url-compatible validation used by
  the TURN REST credential issuer.

The zero-downtime sequence for this SQLite mode is therefore: atomically publish provider
`{v2,v1}` -> reconcile coturn realm to `{v2,v1}` -> allow at least the maximum issued TURN
credential lifetime plus deployment skew -> atomically publish provider `{v2}` -> reconcile coturn
realm to `{v2}`. coturn documents that database-backed TURN REST shared secrets are read
dynamically and that multiple shared secrets may coexist.

This is **not** a claim that PostgreSQL, MySQL, Redis, or MongoDB coturn secret stores are already
reconciled by UCR. Those backends require dedicated adapters with equivalent transaction,
ownership, verification, retry, and secret-handling guarantees before they can claim the same
operational evidence.

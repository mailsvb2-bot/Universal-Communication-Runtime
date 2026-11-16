# RT0 reference browser E2EE adapter: integrated package and canonical trust boundary

## Shipped pieces

The reference browser loads `./endpoint-media/reference_browser_media_installer.js`
when its authenticated WebRTC E2EE DataChannel opens. The ESM bundle imports
the existing TypeScript `createUcrAuthorizedMediaInstaller` and WebCodecs/portable
media adapter. The browser also loads the Rust/OpenMLS WASM package from
`./endpoint-wasm/ucr_endpoint_wasm.js`, with no plaintext fallback.

Both assets are built from the **same source revision** by the dev Docker image.
Desktop Browser Compatibility builds the ESM module and WASM package and
exercises the actual browser import, plus an explicit fail-closed missing-authority
check. The `ucr-realtime-web` gateway serves exactly three public asset routes
with correct JavaScript/WASM MIME and `nosniff`; its
`UCR_REALTIME_WEB_ASSET_DIR` may point to the installed compiled assets.
Missing or empty files return an error. Neither artifact contains secrets.

The dev container now runs the actual `ucr-realtime-web` gateway behind the
existing development port 8080, rather than serving a static mock of realtime
HTTP endpoints. Only the development container uses this non-TLS port; external
or production ingress needs separately configured and authorized HTTPS.

## Automatic composition when the canonical host already exists

An embedding product that already owns authenticated Device/Call/MLS admission can
provide its **existing** `UcrCanonicalMediaAdmissionResolver` directly:

```ts
window.ucrCanonicalMediaAdmissionResolver = resolveFromCanonicalHost;
```

The reference browser detects this resolver at preflight and the bundled
reference installer composes `createUcrCanonicalBrowserMediaFactory` automatically.
The host no longer needs to manually construct and register a second factory.
The resolver must return independently authorized signing/trust descriptors,
current group and negotiation bindings, endpoint-owned seed and live revocation
guards. A missing resolver is rejected before device capture. A callable but
incomplete resolver is rejected during encrypted-media adapter activation,
**before any E2EE media publication**. Camera/microphone permission prompts and
local capture can occur before this validation; leave, revocation and adapter
failure must stop all active capture tracks. Mere function presence is not a
claim that canonical admission is already valid.

### Independently authenticated Device preparation (before and after Join)

The reference client may invoke the host's explicit
`window.ucrPrepareCanonicalDevice(binding)` hook **only before** redeeming the
signed realtime join grant. The hook must use independent first-party
authentication; the join fragment itself never authorizes registration.
After the server accepts Join and **before** media capture, the reference client
MUST validate already-active Device trust through
`window.ucrCanonicalDeviceAuthority`, never through the possibly registering
explicit hook. The canonical verifier uses `requireExistingTrust=true`,
so it can neither create nor re-enroll a Device if trust was deleted or revoked
during Join. Both steps bind tenant, namespace, participant, Device, Call and
session to existing canonical owners.

If `window.ucrCanonicalDeviceAuthority` is available, the browser loads its
same-origin pinned ESM bundle and composes
`createUcrCanonicalDevicePreparation` with
`window.ucrProtectedDeviceKeyVault`, creating the latter in its existing
encrypted IndexedDB vault if the host did not supply it. An explicit enrollment
hook remains allowed for the **pre-Join** step only; it is *never invoked*
after the signed Join is accepted, because a legacy one-argument callback could
silently ignore the inspection-only flag. Hosts supplying such an override MUST
also expose their independently authenticated canonical Device/Trust authority
(and compatible protected signer vault). Missing authority or trust fails closed,
terminating the accepted session before media capture. This is a deliberate
fail-closed integration-contract change for older hosts relying solely on
opaque enrollment callbacks.

The ESM bundle now exports `createUcrCanonicalDevicePreparation(authority, vault)`.
The host may assign it to `window.ucrPrepareCanonicalDevice`:

```ts
import {
  createUcrCanonicalDevicePreparation,
} from "./endpoint-media/reference_browser_media_installer.js";

window.ucrPrepareCanonicalDevice = createUcrCanonicalDevicePreparation(
  authenticatedCanonicalDeviceAuthority,
  existingProtectedDeviceKeyVault,
);
```

The preparation implementation performs an authenticated canonical trust read,
reuses the existing locally protected signer on subsequent joins, refuses
revocation/key mismatch, and requires a second canonical trust read after
first registration before admitting the new signer. If an approval request
fails after a signer was staged, a retry reuses the staged signer rather than
minting a different identity. A lost local signer for an active registered
Device fails closed and requires the canonical explicit recovery workflow.

The callback is an integration seam for the host's existing Device lifecycle,
trusted signing-key provisioning and endpoint secure key vault. A new Device
must first be enrolled through that authority BEFORE any participant-bound
join URL is issued: `createUcrCanonicalDevicePreparation` now accepts the
canonical tenant/participant/Device binding without optional Call/Session IDs.
Only AFTER a confirmed active trusted key should the existing canonical
Conference owner issue a signed session grant. The browser's extra pre-Join
check cannot substitute for this separate first-entry authorization flow. It should
idempotently check or register an authorized Device, recover the already owned
local signing seed on later joins, independently confirm the *active* trusted
public-key descriptor and reject revoked/mismatched key state. It must never
interpret the URL grant as permanent identity enrollment approval.

A missing hook does not invent keys or bypass trust: the downstream canonical
media resolver still enforces full signing/MLS admission. Neither browser
fragment nor temporary WebRTC peer is allowed to provision a Device. A supplied hook is
awaited before media capture, and a stale join lifecycle is rejected after its
completion. The hook is **not** yet a first-party registration implementation;
the host must supply its authenticated backend and device-key vault.

**Current first-party host status (2026-11-15).**
The reference UCR gateway now exposes the same-origin authenticated BFF routes
for signup, login, recovery, Device inspection/revocation and canonical direct
Calls. The `start.js` page composes the existing protected browser Device vault,
`createUcrFirstPartyHttpHost` and `createUcrContactCallJourney` against the
existing canonical Identity/Device/TrustedSigningKey, Call and SQLite owners.
This is one first-party authority, not a second identity or crypto store.
Self-service signup records `IdentityEvidence::SelfAsserted`; it proves
possession of the enrolled signing key, not externally verified real-world
identity.

This direct-contact path is separate from the webinar `/room` path. PR #359 adds
canonical authenticated Room routes, but its public `/room` browser lobby is
still on the legacy `/v1/room/enter` protocol and is not yet wired to those
routes. Keep #358 open until that UI uses the first-party BFF and canonical
Room/MLS/Call/Join flow.

## Required canonical host integration — cannot be replaced with synthetic trust

Before joining the conference, the embedding product must provide:

```ts
import {
  createUcrCanonicalBrowserMediaFactory,
} from "./endpoint-media/reference_browser_media_installer.js";

// resolveAdmission MUST read authenticated, active Call/Group/Device/MLS
// and trusted-signing-key state from the host's canonical identity owner.
// It must NOT use data solely copied from a remote SFU frame or join URL.
window.ucrCanonicalAuthorizedMediaFactory =
  createUcrCanonicalBrowserMediaFactory(resolveAdmission);
```

`resolveAdmission` returns one `UcrCanonicalBrowserMediaAdmission`:

- the exact authenticated `sessionId`, `deviceId`, `participantId` and principal
  kind, scoped `binding` (tenant/call/group, epoch, negotiation reference and
  generation), and an active synchronous `isCurrent()` guard;
- the endpoint device's existing private signing seed, trusted active key ID,
  and *independently authorized* matching public key from the canonical
  `TrustedSigningKeyResolver` owner;
- a trusted `resolve(header,keyId)` that rejects unknown/revoked device key
  descriptors, and live `authorizeFrame`/`authorizePublish` callbacks;
- the browser `AudioContext`, optional E2EE canvas, and only real measurement
  callbacks. No synthetic CPU/network/battery telemetry.

The factory passes the device seed only to the Rust/WASM media bridge, checks
that the resulting Ed25519 verifying key equals the active trusted descriptor,
and zeroes its temporary seed copy. It compares MLS crypto epoch to the
canonical negotiated binding, and wraps per-frame authorization in the same
live admission guard. Revocation before `start()` also permanently revokes the
bridge.

**Current integration boundary (2026-11-15).**
The first-party direct-contact browser path now installs the canonical
Device/Trust authority from the authenticated BFF and composes the existing
endpoint admission resolver for the accepted direct Call. It still fails closed
if the protected Device signer, active TrustedSigningKey, current MLS roster,
or live Call/negotiation binding cannot be independently verified.

The separate `/room` lobby is not yet wired to this host; it still uses the
legacy local-room enrollment protocol and must not be treated as a production
first-party path. Do not call `crypto.getRandomValues()` to create a new signing
key on each join and pretend it is registered/trusted by the server; do not
accept in-band source keys. A passing browser self-probe or repository
acceptance test is not a physical two-device A/V call, TURN/NAT traversal,
measured revoke/stop, or production-readiness evidence.

### First-party pre-Join OpenMLS orchestration (draft PR #330)

The `/start.js` contact journey now drives the endpoint-owned OpenMLS
lifecycle **before** requesting a signed media Join. Both browser identities
must already have independently authenticated, active canonical Device/Trust
sessions and an accepted direct Call. The BFF remains the only Call, Group,
Device, Trust, epoch and recipient-admission authority.

The initiator creates the private OpenMLS group locally, seals its epoch-zero
provider in the existing `ucr-endpoint-state-v1` IndexedDB, and publishes only
a Device-signed public state reference. After this canonical Group exists, the
recipient seals its original private KeyPackage provider, publishes its
Device-signed public KeyPackage and waits. The initiator reads the independently
verified single-device offer, stages a real OpenMLS Add, submits its signed
Commit/Welcome to the canonical Group CAS, merges only after server acceptance,
and seals the new epoch. The recipient restores its **original** private
KeyPackage, processes the recipient-bound Welcome/commits, verifies the exact
epoch/state reference, and seals the joined state. Both endpoints verify the
two-device local OpenMLS roster against the authenticated BFF's committed peer
Device before `join-accepted`. No server MLS host leaf or private seed is
created by this browser path.

The pre-Join and media pages intentionally use one scoped encrypted snapshot
key, `ucr-e2ee-state:fp-v1:[tenant,namespace,mediaCall,participant,device]`,
and the same IndexedDB stores, AES-GCM wrapping AAD and nonextractable KEK.
Any optional opaque media-adapter transport snapshot is stored under a distinct
`:media-adapter-v1` record key so it cannot overwrite the private OpenMLS
provider snapshot; this is not a second identity or crypto authority.
Cross-tab writes require the browser's Web Locks API; an unsupported browser
fails closed. A pending public offer is retried with the **same** sealed
KeyPackage, never silently replaced. Hangup, Device change and stale Call
inspection fence the final Join, including a delayed MLS preflight.

**Not yet proven by a physical call:** this is a first implementation of the
browser coordinator, not production evidence. Epoch-zero creator publication
uses a separate, authenticated prepublication snapshot domain. After an
uncertain create response or reload, the browser restores the **same** creator
Group and promotes the sealed state only after checking the canonical
authenticator. A forged or mismatched descriptor cannot promote it.

The initial endpoint-owned Add now also has a write-ahead recovery record in
the existing encrypted IndexedDB state store. Before sending the signed
Commit/Welcome, the creator seals its locally merged next-epoch OpenMLS
snapshot and persists the exact public Commit, Welcome, event ID, recipient
Device and expected canonical revision. After a lost acknowledgement or crash,
the creator checks the independently authenticated canonical epoch/state
reference: it retries the exact signed event only if the server still reports
the original epoch, or promotes the sealed snapshot only after confirming the
matching committed epoch and recipient Device. A conflicting epoch fails
closed; it never mints a replacement Commit or MLS identity. The first-party
BFF delegates replay decisions to the canonical SQLite transaction, which
permits the **identical** previously accepted signed event while refusing
stale, altered or unauthorized transitions. This is tested with an actual
SQLite-backed BFF acceptance test and a separate mock-backed browser restart
test. Neither proves power-loss durability on a physical device.

Still open: real A/B media transport, simultaneous capture revocation and
measured quality/latency across two physical devices and NAT/TURN. Browser
and CI conformance cannot substitute for those release gates.

### SFU sink acceptance is linearized with canonical revoke

The SFU does not treat a prepared batch or an earlier authorization check as
send authority. Immediately before each recipient handoff it captures the
canonical authorization revision, revalidates source Device, Call, Group/MLS
membership and both send/receive permissions, then invokes the sink only
inside `AuthorizationEvaluator::with_authorization_revision_fence`. The
SQLite implementation holds an IMMEDIATE transaction and checks the same
trigger-maintained revision used by Call, Call-participant, Group/MLS,
Device, trusted-key and permission writes. A revoke that commits first changes
the revision and the sink callback is not invoked; a sink acceptance already
inside the fence completes before another SQLite connection can commit revoke.
The in-memory store uses its existing canonical state mutex and revision.
Unrevisioned or non-atomic evaluators fail closed at this boundary. Sink
callbacks must be bounded and must not re-enter the canonical store. The live
WebRTC media handoff has a separate 2-second acceptance deadline (control and
signaling retain their longer timeout), bounding how long the SQLite writer
fence can be held under backpressure.

This establishes an ordering for SFU sink acceptance, not remote delivery.
A WebRTC provider Close separately cancels the in-flight send and drains every
still-open E2EE DataChannel before acknowledging closure. If a channel is
already `Closed`, its remaining local buffer cannot reach the recipient and
does not block cleanup; an open channel must still drain to zero before Close
is acknowledged. A timeout keeps the peer quarantined and retryable. None of
these local proofs substitutes for observing remote capture stop on a physical
second device.

### Durable recipient KeyPackage before Welcome (PR #330)

The browser WASM endpoint now provides `seal_unjoined_key_package` and
`restore_unjoined_key_package` for the **recipient's existing private OpenMLS
provider**, before a Welcome has arrived. The sealed snapshot uses the same
endpoint-only state encryption as active epochs, but a separate authenticated
AAD domain bound to canonical Tenant/Namespace/Group/Device. An active Group
snapshot cannot be restored as a pending offer, nor can an offer be restored
for a different Device or under a different wrapping key. The public
KeyPackage bytes remain identical across reload; publishing a replacement
KeyPackage after a transient delay must not silently orphan the accepted
Welcome. Browser Compatibility exercises a real endpoint-created OpenMLS
Add/Welcome with the recovered KeyPackage and negative cross-Device/key/domain
checks, not a simulated crypto handshake.

**First-call integration status:** the `/start` coordinator now seals
the recipient's original KeyPackage before publication, restores it for the
recipient-bound Welcome, and preserves the creator's epoch-zero Group through
uncertain create responses using a distinct authenticated snapshot domain.
The `/client.html` first-party restoration path checks the independently
authenticated BFF Group descriptor and the exact committed epoch/state
reference. It refuses to mint a replacement KeyPackage or use server-owned
MLS after signed Join. The creator's initial Add Commit now has a sealed write-ahead
recovery record and exact signed-event replay; this remains browser-local
recovery, not a measured physical-device power-loss test. Physical A/B
WebRTC/TURN/NAT media and measured revoke/stop are still missing. Browser-local
cryptography and a mock-backed coordinator are not evidence of a live one-click call.

### Authenticated endpoint MLS Group revision/epoch contract (PR #330)

The same first-party `POST /v1/first-party/call/mls-descriptor` now returns
`groupRevision`, `cryptoEpoch` and `cryptoStateRef` **from the existing
canonical Group owner**. All three are JSON `null` before the Group exists;
after endpoint-only creation they are `0`, `0` and the public MLS epoch
authenticator digest, respectively. A committed Add/Remove/Rekey advances the
canonical Group CAS revision independently of the accepted direct Call revision.
The browser rejects mixed null/non-null fields, malformed epochs and unsafe
revisions; the signed Add request must match the freshly inspected Group
revision and propose exactly the next epoch. A stale concurrent writer still
fails the server's atomic Group CAS. A Group with contradictory ownership,
scope, capability or retained server-held OpenMLS private state is refused.

The WASM `EndpointMlsState.crypto_state_ref()` returns only the locally
verified public hash of the current MLS epoch authenticator. It refuses
unjoined, pending or inconsistent states and does **not** expose the MLS
exporter, private signer or HPKE secrets. This is the required initial
`mls-create` signing input, not independent proof of the two-device roster.
The browser must still orchestrate the full authenticated KeyPackage,
Commit/Welcome, sealed state persistence, roster validation, media admission
and stop/revoke journey; these contract additions alone are **not** a live call.

### Endpoint-owned direct-Call MLS roster gate (PR #330)

For a first-party direct media Group (the deterministic `fp-mg-` prefix),
the endpoint media bridge now refuses to export a media key until its
**locally verified OpenMLS tree** contains exactly the current Device and
the independently authorized peer Device, with no extra, duplicate or
cross-scope leaves. The canonical browser admission resolver must supply
`expectedPeerDeviceId` from existing authenticated Call/Device/Trust state;
a Join fragment, SFU frame, or MLS Welcome cannot select that peer.
`authorize_direct_call_roster` is checked against the current MLS state
reference and own leaf, then fenced to the current local MLS generation.
Rekey, Commit, or restore requires a fresh roster authorization. Missing
resolver/peer/roster verification fails closed before the media exporter.

The shared Rust MLS layer also rejects duplicate canonical Device credentials
before an Add Commit and refuses exporter access to malformed/duplicate
credential trees. A real OpenMLS two-leaf/three-leaf regression and a browser
admission contract regression cover the checks. These are security
**preconditions**, not proof that the first-party browser currently supplies
a trusted peer Device or that a physical A↔B call works.

Still required: authenticated BFF delivery of the peer Device/Trust and live
negotiation binding to the canonical resolver; full endpoint-owned MLS
creation/KeyPackage/Commit/Welcome orchestration from the one-click user
journey; verified endpoint acceptance and revoke/stop; two real Devices
with measured WebRTC/TURN/NAT audio and video. Never claim production-ready
from roster checks or green CI alone.

## Verification scope

Current CI can prove module loading, WASM execution, local key package
generation, guard validation, codec encode/decode and deterministic
source/receiver races. It does not prove a real A->SFU->B video/audio call.

A production readiness sign-off requires signed device trust provisioning,
two independently authorized devices using current MLS/negotiation epoch,
real audio/video encryption and decryption across the SFU with TURN/NAT,
concurrent capture revocation, and measured full-HD quality and latency.

## First-entry ordering and no second identity database

1. Independently authenticate the owner with the existing canonical Identity/Device authority (not a realtime fragment).
2. On the endpoint, stage/reuse one protected Ed25519 signer keyed only to the canonical Tenant/Namespace/Device scope. The SDK passes only those three fields to the private-key vault; Call, Session and participant IDs never enter the vault identifier, so a new call cannot silently mint a second signing identity.
3. Confirm the active canonical trusted public-key descriptor using the existing Device/Trust owner. Protected key possession is challenged locally and trust is re-read after signing; revocation/rotation invalidates the attempt.
4. Only then request the canonical Conference service to issue the short-lived, device-bound Join URL. The issuer must independently revalidate active Device status and Call/Group policy.
5. Browser rechecks trust before and after redeeming Join; Rust/WASM MLS state and E2EE media adapter activate only after exact authenticated admission and crypto-epoch checks.
6. On restart, restore the endpoint-owned signer and sealed MLS state. A lost signer requires existing explicit Recovery, never silent self-enrollment from a link.

The host must provide a concrete authenticated enrollment/provisioning endpoint before this can become a standalone user journey. No second cryptographic authority, shadow Device table, persistent telephone directory, server-retained signing seed, or database of phone numbers is introduced by this integration. The existing canonical Device/Trust/Identity persistence remains in use; this is **not** a stateless/no-data product claim.

> **Integration status (PR #286).** This document contains the background
> device-vault and media-authority design. For the shipped first-party route
> and exact browser/server contracts, see
> [rt0-single-branch-first-call-integration.md](rt0-single-branch-first-call-integration.md).
> A Device-only signed Join is forbidden by the canonical first-party BFF.
> Earlier #285 samples requiring that Join must not be treated as evidence of
> working first-party calling.

## Browser-local protected Device signer (implemented, not user authentication)

The reference browser now builds the endpoint-owned `UcrCanonicalDeviceKeyVault`
automatically when — and **only when** — an independently authenticated
`window.ucrCanonicalDeviceAuthority` exists. The vault lives in the
**existing** `ucr-endpoint-state-v1` IndexedDB database,
`wrapping-key-vault` object store; its key is the canonical
tenant/namespace/Device tuple, **not** Call, Session, telephone or participant.
A device signer is staged with an atomic IndexedDB `add`: concurrent tabs
cannot silently rotate the original signer.

Only the 32-byte Ed25519 public descriptor and its key ID may be supplied for
canonical trusted-key registration. The private signing seed is AES-GCM
encrypted using an unextractable browser `CryptoKey`, and not sent to UCR
servers. The same local signer is restored after a page reload. Signer proof
uses real Ed25519, and the short-lived seed passed to a preauthorized
Rust/WASM media bridge is zeroed after use with a canonical trust recheck.

The transport-neutral `createUcrFirstPartyCallEntry` remains a historical
SDK seam, **not a first-party calling route**. It requests a Call-free Join,
which the actual Rust BFF forbids. It is intentionally not exported by the
reference browser bundle, and its first-party HTTP adapter always rejects the
operation before transport. The only first-party user flow is
`createUcrContactCallJourney`: contact selection, durable Call Start,
recipient acceptance, and a fresh signed Join scoped to that accepted Call.

**Limitations and release gates:** IndexedDB/WebCrypto are not a TPM,
hardware-backed keystore, browser-origin compromise defense or cross-device
recovery. The existing auth owner must still independently approve
registration; the grant fragment cannot authorize its own signer. The
first-party user-authenticated backend/BFF to register Identity and Device
before granting a Call, active negotiation bindings, two actual Device media
streams over TURN/NAT, and on-device A/V measurements are **not implemented**
by this vault and remain open under issue #274. A protected local key is not
a permission to start sending media.

## Canonical Service Principal Device trust RPC (P0 integration seam)

The versioned `DeviceService` now includes `ProvisionTrustedSigningKey` and
`GetActiveTrustedSigningKey`. Both reuse the existing `IntegrationIngress`
Service Principal authentication, quotas, append-only operation audit,
`AuthorizedDurableRuntime` permissions and the canonical
`TrustedSigningKeyStore`. Provisioning requires an independently authenticated
authorized service principal with `ucr.crypto.trusted_signing_key.provision` permission
(as defined by the canonical permission constant); reading requires its
`ucr.crypto.trusted_signing_key.read` permission. Active-Device preconditions and conflict/
revocation semantics remain owned by the existing Device and Trust stores.

These RPCs receive/return ONLY Ed25519 public-key descriptors, never local
signing seeds, MLS exporters, telephone numbers or endpoint encryption
snapshots. They are intended for a backend trusted by the owner; **do not
proxy machine Service Principal secrets directly to the browser**. A distinct
user-authenticated first-party host/BFF mapping verified users to the existing
canonical permissions is still needed before standalone self-enrollment.
The join URL fragment cannot act as device-registration authority.

This addition introduces no new database, identity/cryptography owner or
telephone lookup directory. Canonical durable Device/Trust state continues
to live in the existing reference stores. Passing gRPC conformance does not
prove two physical Device E2EE audio/video or TURN/NAT interoperability.


## RT0 canonical first-party BFF and browser admission (#286)

The actual Rust BFF lives in `crates/ucr-runtime/src/first_party_web.rs`
and shares the existing SQLite Identity, Device, Trust, Call, Conversation,
and Conference Join owners. It binds only to a loopback address behind a
separately provisioned HTTPS origin. The gateway serves `/start` and
`/start.js` with the existing, single reference-browser ESM bundle.
The authenticated first-party adapter is
`sdk/typescript/src/first_party_browser_http.ts`; the user journey lives in
`sdk/typescript/src/contact_call_journey.ts`.

The correct order is: local existing Device signer -> independent signed
login challenge -> HttpOnly Secure SameSite browser session -> canonical
Device inspection -> private contact selection -> durable Call Start ->
recipient-scoped incoming list -> recipient CAS acceptance -> two distinct
fresh, Device-bound accepted-Call Joins -> MLS/E2EE media -> canonical hangup.
User account or Device changes abort the browser coordinator.

### Public self-service signup abuse boundary (partial mitigation)

When `UCR_FIRST_PARTY_SELF_SERVICE_TENANT` is enabled, the BFF allows
self-signed first-entry accounts. Such signatures prove key possession, **not**
a prior trusted real-world Identity. Anonymous signup and successful recovery challenge
replay tags use separate bounded pools (1,024 each per challenge TTL), both
isolated from the login/Device replay budget. Recovery replay admission is
serialized with the existing canonical SQLite recovery-code comparison and
rotation: a self-signed proof with an invalid recovery code does not spend
recovery capacity, and a successful challenge cannot be reused after rotation.
The single BFF process admits at most 256 successfully signed signup attempts
per ten minutes before writing to canonical SQLite. Existing Device login and recovery do not consume signup
slots. This preserves the canonical stores; no alternate identity or key
database is introduced.

The canonical signup/recovery SQLite transaction can succeed even when the
separate bounded browser-session pool is full. After a committed credential
rotation, the BFF returns the new one-time recovery code in its normal success
body **without a Set-Cookie header** rather than discarding that sole new
credential through a late HTTP 429. The endpoint must retain the code and
independently sign in with its newly trusted Device when capacity is available;
a successful account mutation does not imply that a browser session exists.
A regression fills the unrelated-Identity session budget and confirms the
rotated code remains available and usable. This does not relax the global
session limit or permit unauthenticated calls.

**This is not a production-wide anti-abuse guarantee.** The budget is
process-local and resets on restart. It does not enforce cross-instance,
per-origin or per-Identity limits, stop previously registered attackers from
logging in, protect storage indefinitely, or replace ingress admission,
retention and abuse-response policies. Do not claim public self-service
production readiness from these unit tests alone.

The independently authenticated, existing trusted signer is **required
before login**. The BFF's enrollment proof is possession verification of the
already-canonically-trusted key; it **does not** create a new trusted Device,
recover a lost private signer, or authorize one from a Join fragment.

### Exact HTTP surfaces

All POST routes require exact `Origin`, `Content-Type: application/json`,
`X-UCR-First-Party-Request: v1`, bounded JSON and the same-origin secure
cookie after login. All POST request structs reject unexpected fields.

| Route | Request | Server decision |
|---|---|---|
| `POST /v1/first-party/login/challenge` | `{tenantId,namespaceId,participantId,deviceId}` | One-time scoped login challenge |
| `POST /v1/first-party/login/verify` | `{binding,challengeId,signatureBase64Url}` | Current canonical Device signer proof and secured session |
| `GET /v1/first-party/session` | Cookie | Independently authenticated Identity/Device |
| `POST /v1/first-party/device/inspect` | `{binding}` | Current canonical Device/Trust, never a bare binding |
| `POST /v1/first-party/device/challenge` | `{binding,keyId,publicKeyBase64Url}` | One-time proof of existing signer |
| `POST /v1/first-party/device/approve` | `{binding,keyId,publicKeyBase64Url,challengeId,signatureBase64Url}` | Approved only for already-trusted key |
| `POST /v1/first-party/call/start` | `{binding,intent:{peerIdentityId,media,idempotencyKey}}` | Persisted canonical direct Call |
| `POST /v1/first-party/call/get` | `{binding,callId}` | Participant-scoped snapshot |
| `POST /v1/first-party/call/incoming` | `{binding}` | Recipient-only pending Calls |
| `POST /v1/first-party/call/signal` | `{binding,callId,expectedRevision,action}` | Durable CAS accept/reject/busy/cancel/hangup |
| `POST /v1/first-party/call/join-accepted` | `{binding,callId,expectedRevision}` | Signed Join only after recipient acceptance |
| `POST /v1/first-party/call/join` | Any Device-only request | Always forbidden; SDK refuses before HTTP |

The `first_party_http_conformance.ts` and
`first_party_two_device_http_conformance.ts` tests exercise these exact
browser envelopes, independently bound simulated A/B sessions, encrypted
contacts, retry/idempotency, acceptance, distinct Joins, conflict,
termination, restart and revocation. They are **mock-backed contract tests**,
not production claims. Rust local tests and GitHub CI verify server/request
contract and build. Real HTTPS deployment, enrolled Devices, actual SFU,
ICE/TURN/NAT, MLS encryption/decryption, persisted SQLite restart recovery,
and two-physical-device audible/visible results remain release gates.
See the single-branch integration document for the promotion policy.

### Domain-separated first-entry enrollment proof (RT0)

The server challenge is not signed raw. The browser Ed25519 signer signs UTF-8
bytes: the literal string "ucr-first-party-device-enrollment.v1" followed by
one NUL byte followed by compact JSON array, in this exact ordered form:
[tenantId,namespaceId,participantId,deviceId,keyId,
 publicKeyBase64Url,challengeId,challengeBytesBase64Url].
The optional namespace is JSON null, not an omitted element. Base64url is
canonical unpadded RFC4648 with no alternate spellings; IDs are restricted
to printable ASCII. The BFF MUST reconstruct the message from its OWN
authenticated session and the previously issued server-held one-time
challenge. The BFF MUST NOT trust a message supplied by the browser, nor
accept a detached signature over raw challenge bytes. This prevents a
compromised or buggy challenge issuer from asking a Device signer to sign
another protocol's message with the same Ed25519 key.

Browser local verification against the proposed public key proves internal
vault consistency only. The BFF independently verifies that public key
against the signature, exact session binding and consumed challenge before
publishing it to the canonical TrustedSigningKeyStore. A replayed challenge,
retired session or mismatched Device must fail closed.

## Committed two-Device direct-call admission fence (PR #330)

For a first-party direct Call, the canonical SQLite Group MLS transition is
the source of the **exact creator/recipient Device pair**. The authenticated
BFF reads the committed transition and its Device admissions, checks that
each Device still belongs to the correct accepted Identity and retains an
active canonical trusted signing key, and refuses ambiguous or revoked pairs.
A signed Join for the media Call is now restricted to one of those exact
Devices, not any other Device owned by the same participant.

The `/v1/first-party/call/mls-descriptor` response includes
`expectedPeerDeviceId`, which is `null` before the endpoint-owned Add is
durably committed. The browser HTTP adapter rejects missing, malformed,
self-referential or pre-commit peer IDs. The reference media resolver fetches
this value through the independently authenticated same-origin first-party
session, checks its Call, Group, Device and MLS epoch against the signed media
Join and endpoint-local OpenMLS state, and requires one matching current
trusted peer signing descriptor. It never selects the peer from a Welcome,
SFU frame or join fragment. The Rust/WASM exact two-leaf roster check is a
separate, mandatory cryptographic enforcement layer.

**Current first-party direct-call browser integration (verified in repository code on
2026-11-15):** the endpoint-owned OpenMLS preflight is now implemented in
`start.js` and runs before the signed media Join:

- `prepareFirstPartyEndpointMls` rechecks the selected Call, authenticated
  Device, canonical Call state and UI generation after every asynchronous
  boundary. A stale Call, logout, Device switch or Hangup cancels preparation.
- The creator creates and seals its epoch-zero Group locally before publishing
  only the public crypto-state reference through the first-party BFF.
- The recipient creates and seals its own KeyPackage before publishing its
  signed offer. The creator accepts exactly one recipient offer, stages the
  MLS Add/Commit/Welcome, writes a sealed transition journal before the BFF
  commit, and rereads the canonical descriptor before promoting local state.
- The recipient obtains only its Device-bound Welcome and subsequent Commit
  chain, joins locally, and verifies the same canonical Group, epoch and state
  reference. Both endpoints enforce the exact two-Device direct-call roster.
- `beginMedia` requests the signed Join only after endpoint MLS is ready.
  `client.html` then reauthenticates the same Device, verifies the accepted
  Call/Group/epoch and restores the sealed local MLS snapshot. First-party
  `fp-m-*` Calls fail closed if the legacy server-owned MLS mode is returned.

Private MLS state remains in the existing Device-local protected IndexedDB
stores. The BFF stores signed public Commit/Welcome material and canonical
metadata, not an endpoint private seed or exporter. The browser uses the
first-party session; no ServicePrincipal secret is placed in browser code.

This is repository-level integration, **not proof of a real call**. Two
physical Devices, public NAT/TURN traversal, permission prompts, remote audio
and video playback, and measured revoke/stop are still unverified. The
webinar/Room UI is a separate path: `client.html` still uses the legacy
`/v1/room/enter` flow there; issue #358 tracks wiring that UI to the new
canonical first-party Room API. Do not conflate Room readiness with the
direct-contact E2EE path.

PR #330 merged on 2026-10-30; PR #335 merged on 2026-11-03. PR #329 is
closed without merge and is not an active implementation branch.

## Merged #335: canonical direct-Call / derived-media Hangup transaction

The first-party `hangup` route now delegates to the **existing** authorized
Call runtime and one `CallStore::terminate_direct_call_with_derived` operation.
SQLite applies the direct termination and any existing derived Group media
Call termination under the same `BEGIN IMMEDIATE` transaction. The Memory
provider uses the existing state mutex and rolls back the affected canonical
Call/signal records if either transition fails. The operation validates the
derived Call's exact scope, initiator and two-person roster; a mismatched
derived Call fails closed. A missing or already-terminated derived Call is
idempotent. The same independently authenticated Device/Trust and
`CALL_SIGNAL_PERMISSION` checks as ordinary signalling remain in force.

The transaction shares its SQLite lock with the existing
`create_call_if_parent_current` fence, so an accepted-Call Join cannot create
a new media Call *after* committed Hangup. Tests cover a conflicting derived
binding (neither termination may commit), an absent child and stale Join
creation from another SQLite connection.

**Verification boundary:** the merged transaction and exact Call-scoped
media grants do not prove that a remote WebRTC provider has physically stopped
transmitting, nor that an in-flight encrypted packet is cancelled at the
transport boundary. First-party self-service does not mint tenant-wide media
grants; the existing grant owner scopes media admission to the accepted direct
Call. Cross-process in-flight cancellation, confirmed provider close, two
physical Devices, public NAT/TURN traversal, remote A/V playback and measured
revoke/stop remain release blockers. No remote UCR host is authorized by this
document.

## PR #359: bounded E2EE DataChannel drain before provider Close

The WebRTC provider now treats local ciphertext-buffer drain as part of its
Close acknowledgement boundary. The active send observes the offer-scoped
Close signal and returns to the single peer worker; before that worker
acknowledges Close, it waits for the reliable E2EE DataChannel and any
negotiated unordered channel to report zero buffered bytes. The wait is
bounded by the original Close deadline. If a buffer does not drain, the
provider still attempts to close the peer, returns failure, and retains the
quarantined session handle for the existing retry path instead of reporting
successful cleanup.

Rust regressions cover successful drain and bounded fail-closed timeout; the
Windows first-party source contract checks that both channel buffers are
drained before the provider Close acknowledgement.

**Scope limit:** this is a local WebRTC DataChannel queue fence. It does not
prove that ciphertext already accepted by a remote network stack has been
played or discarded, that the SFU's cross-process sink has an atomic revoke
fence, or that the remote camera/microphone capture tracks have physically
stopped. Those remain explicit #336/#274 release gates. No production-ready
or physical two-device A/V claim follows from this code or its CI.

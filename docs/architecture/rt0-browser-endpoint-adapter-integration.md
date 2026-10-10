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

The reference client now invokes `window.ucrPrepareCanonicalDevice(binding)`, when supplied,
**before redeeming** the signed realtime join grant, then invokes it again
**after** the server has accepted Join and **before** media capture.
Both invocations require the host's independently authenticated canonical
Device/Trust backend. The join fragment itself is never registration authority.
The second check refuses trust revoked or rotated during join. The binding carries
the exact scoped tenant, namespace, call, session, participant and Device identifiers.
If the authenticated host already exposes `window.ucrCanonicalDeviceAuthority` and
`window.ucrProtectedDeviceKeyVault`, the reference browser now imports the
same pinned ESM bundle and composes the preparation callback **automatically**,
before the server redeems the join grant and then again before media capture. Existing hosts
may also provide an explicit `window.ucrPrepareCanonicalDevice` override.

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

**This still requires an independently authenticated first-party host.**
The UCR reference web gateway still has no standalone enrollment credential,
trusted first-party route to enroll a device, provision/recover a local
signing key, and publish its trusted descriptor. Such a
route must be implemented against the existing canonical Device/Identity/Trust
owners before an unembedded user can complete a real two-device media call.

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

**Important:** the repository currently does NOT yet provide a first-party
authenticated browser route that provisions/recovers the device signing seed,
publishes the device's trusted key, or supplies the complete live negotiation
binding and source trust map. The already-implemented server MLS bootstrap
alone does not supply those identity and authorization values. Do not
`crypto.getRandomValues()` a new signing key on each join and pretend it is
registered/trusted by the server; do not accept in-band source keys.

Until a host supplies this canonical authority, the bundled installer emits
`Canonical device media signing/trust authority is not wired` and the DataChannel
is closed. That is deliberate and secure, **not a passing two-device test**.

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
2. On the endpoint, stage/reuse one protected Ed25519 signer keyed to the canonical Device, not to a Call, Session, telephone number, or temporary route.
3. Confirm the active canonical trusted public-key descriptor using the existing Device/Trust owner. Protected key possession is challenged locally and trust is re-read after signing; revocation/rotation invalidates the attempt.
4. Only then request the canonical Conference service to issue the short-lived, device-bound Join URL. The issuer must independently revalidate active Device status and Call/Group policy.
5. Browser rechecks trust before and after redeeming Join; Rust/WASM MLS state and E2EE media adapter activate only after exact authenticated admission and crypto-epoch checks.
6. On restart, restore the endpoint-owned signer and sealed MLS state. A lost signer requires existing explicit Recovery, never silent self-enrollment from a link.

The host must provide a concrete authenticated enrollment/provisioning endpoint before this can become a standalone user journey. No second cryptographic authority, shadow Device table, persistent telephone directory, server-retained signing seed, or database of phone numbers is introduced by this integration. The existing canonical Device/Trust/Identity persistence remains in use; this is **not** a stateless/no-data product claim.

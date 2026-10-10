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
guards. A missing resolver is rejected before device capture. A callable but\nincomplete resolver is rejected during encrypted-media adapter activation,\n**before any E2EE media publication**; browser permission prompts or temporary\nlocal capture can occur before that validation, and teardown must stop them.

**This is not automatic device enrollment or key provisioning.** The UCR reference
web gateway still has no authenticated first-party route to enroll a device,
provision/recover a local signing key, and publish its trusted descriptor. Such a
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

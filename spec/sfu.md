# Phase 29 SFU Routing

Status: **Prepared/reference**.

Phase 29 adds an SFU infrastructure boundary for already-encrypted, source-authenticated **MLS-backed group Audio/Video media**. It reuses the canonical Group, CallSession, Device lifecycle, Principal→Identity association, trusted Device signing-key, Audio/Video permission and Capability owners. It does not create a second Group, Call, Identity, Delivery, transport or Conference authority.

## Group crypto and device admission

Phase 29 uses OpenMLS (RFC 9420) rather than a home-grown group KDF. UCR `GroupCryptoState` remains the canonical Group-side reference to the standardized crypto owner: the real MLS epoch and a state reference derived from the exact MLS epoch authenticator are stored with canonical Group state.

MLS leaves are Device-sensitive. Group membership remains Principal-sensitive. The runtime therefore never infers Person/Organization→Device authority from matching opaque IDs. A non-Device Group/Call Principal is associated with a Root Identity through an explicit immutable `PrincipalIdentityBinding`; an admitted Device must be Active and its canonical `DeviceDescriptor.identity_id` must match that binding. Device principals continue to use `DeviceDescriptor` directly so Device→Identity has one owner.

SQLite schema v26 adds the explicit Principal→Identity association owner and Group/MLS transition evidence. The official OpenMLS SQLite storage backend shares the same `rusqlite` connection. Security-sensitive Group Add/Remove/role/ownership transitions stage OpenMLS state, derive the next real epoch/state reference, apply canonical Group state, merge the pending MLS commit and commit all writes inside one `BEGIN IMMEDIATE` transaction. Stale canonical revision therefore rolls back staged OpenMLS writes. Exact retries survive restart without advancing the MLS epoch; changed retries conflict. A removed Principal loses all explicitly admitted MLS Device leaves in one removal transition.

Phase 29 does not infer that every Device owned by an Identity is automatically an MLS member. Device admission is explicit. Automatic global MLS rekey merely because a new Device appears outside a canonical Group change is not claimed in this phase.

## Group-media E2EE boundary

Endpoints derive a group-media epoch secret through the MLS exporter. UCR derives source/stream-specific XChaCha20-Poly1305 traffic keys with HKDF-SHA256 bound to exact TenantScope, Group, Call, media negotiation, MLS epoch/state reference, source Principal, source Device, stream and media kind.

Because all current MLS members can derive the epoch exporter, key derivation alone is not source authentication. Every encrypted group-media frame therefore carries a separate Ed25519 signature from the claimed source Device over the authenticated header, nonce and ciphertext. The runtime resolves that key through the existing Active Device/trusted-signing-key owner. A different group member cannot legitimately emit an Alice frame merely by knowing Alice's public Device ID.

The SFU receives no MLS exporter secret, stream traffic key or plaintext. Endpoint AEAD and replay state remain authoritative.

## SFU fan-out authority

Capability `ucr.media.sfu` is Prepared. The authenticated source Principal and authenticated source Device must equal the frame claims. Before any sink side effect, the runtime revalidates:

- the current active Group-backed Call;
- current media-negotiation reference/generation;
- exact current Group MLS epoch/state reference;
- source active Group membership;
- Principal→Identity→Active Device association;
- current trusted source Device signing key and frame signature;
- source Audio/Video send permission;
- every current accepted recipient's active Group membership and receive permission.

Recipients are derived only from the current canonical Call participant set. The SFU does not persist a recipient roster or subscription graph. All recipient preflight checks finish before the first sink invocation.

`SfuForwardSink` receives the same canonical encrypted frame for each ephemeral `SfuForwardTarget`. Successful sink acceptance is infrastructure routing acceptance only. It is not Device receipt, decrypt evidence, canonical Delivery state, user presentation or Read evidence. If a later sink invocation fails, the result reports the number already accepted; Phase 29 does not claim rollback or exactly-once fan-out.

## State, restart and metadata visibility

SFU forwarding state is ephemeral. Durable Phase-29 additions exist only for canonical Principal→Identity association and endpoint-local MLS state/transition evidence; there is no durable SFU route topology, conference roster, ciphertext archive or Delivery owner.

The SFU may observe only exact scope, Group/Call/stream identifiers, source/recipient routing principals, source Device ID, current MLS epoch/state reference, media kind, sequence/timing/keyframe metadata, signature metadata and encrypted packet size/timing required for routing. It must not receive media plaintext, MLS exporter/traffic/private keys, recovery/authentication secrets, unrelated Group roster/history, Message plaintext or provider credentials.

## Explicit nonclaims

Phase 29 does not implement Conference coordination/state/UX, mixer/compositor behavior, recording, transcoding, RTP/SRTP/WebRTC/ICE/STUN/TURN, Relay/NAT traversal, discovery, durable topology, simultaneous multipath, production listener/deployment lifecycle or Production maturity. Conference ownership and lifecycle remain Phase 30.

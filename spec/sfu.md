# SFU Routing

Status: **encrypted routing core implemented; public realtime binding defined separately**.

The SFU infrastructure boundary forwards already-encrypted, source-authenticated **MLS-backed group Audio/Video media**. It reuses the canonical Group, CallSession, Device lifecycle, Principal→Identity association, trusted Device signing-key, Audio/Video permission and Capability owners. It does not create a second Group, Call, Identity, Delivery, transport, Conference or recording authority.

## Group crypto and device admission

UCR uses OpenMLS (RFC 9420) rather than a home-grown group KDF. `GroupCryptoState` remains the canonical Group-side reference to the standardized crypto owner: the real MLS epoch and a state reference derived from the exact MLS epoch authenticator are stored with canonical Group state.

MLS leaves are Device-sensitive. Group membership remains Principal-sensitive. The runtime therefore never infers Person/Organization→Device authority from matching opaque IDs. A non-Device Group/Call Principal is associated with a Root Identity through an explicit immutable `PrincipalIdentityBinding`; an admitted Device must be Active and its canonical `DeviceDescriptor.identity_id` must match that binding. Device principals continue to use `DeviceDescriptor` directly so Device→Identity has one owner.

SQLite schema v26 adds the explicit Principal→Identity association owner and Group/MLS transition evidence. The official OpenMLS SQLite storage backend shares the same `rusqlite` connection. Security-sensitive Group Add/Remove/role/ownership transitions stage OpenMLS state, derive the next real epoch/state reference, apply canonical Group state, merge the pending MLS commit and commit all writes inside one `BEGIN IMMEDIATE` transaction. Stale canonical revision therefore rolls back staged OpenMLS writes. Exact retries survive restart without advancing the MLS epoch; changed retries conflict. A removed Principal loses all explicitly admitted MLS Device leaves in one removal transition.

The runtime does not infer that every Device owned by an Identity is automatically an MLS member. Device admission is explicit.

## Group-media E2EE boundary

Endpoints derive a group-media epoch secret through the MLS exporter. UCR derives source/stream-specific XChaCha20-Poly1305 traffic keys with HKDF-SHA256 bound to exact TenantScope, Group, Call, media negotiation, MLS epoch/state reference, source Principal, source Device, stream and media kind.

Because all current MLS members can derive the epoch exporter, key derivation alone is not source authentication. Every encrypted group-media frame therefore carries a separate Ed25519 signature from the claimed source Device over the authenticated header, nonce and ciphertext. The runtime resolves that key through the existing Active Device/trusted-signing-key owner.

The SFU receives no MLS exporter secret, stream traffic key or plaintext. Endpoint AEAD and replay state remain authoritative.

The transport-neutral SFU envelope has a backward-compatible wire version. Wire v1 is retained for
legacy authenticated frames and canonicalizes audio to microphone and video to camera. Wire v2 adds
one authenticated source-kind byte for microphone, camera, or screen share. Decoders accept both
versions; a decoded v1 envelope re-encodes byte-for-byte as v1, while newly explicit screen-share
frames use v2. The same metadata is preserved through the public realtime protobuf binding.

## SFU fan-out authority

Before any sink side effect, the runtime revalidates the current active Group-backed Call, media-negotiation reference/generation, exact Group MLS epoch/state reference, source active Group membership, Principal→Identity→Active Device association, current trusted source Device signing key/signature, source send permission, and every selected recipient's current membership/receive permission.

Recipients are derived only from current canonical Call participants plus recipient-owned Conference subscription preference. The SFU does not persist a recipient roster.

`SfuForwardSink` receives the same canonical encrypted frame for each ephemeral target. Successful sink acceptance is infrastructure routing acceptance only. It is not Device receipt, decrypt evidence, canonical Delivery state, user presentation or Read evidence. Partial acceptance is reported truthfully; there is no rollback or exactly-once fan-out claim.

## Public realtime transport

`ucr.v1.RealtimeService` is the stable external binding over the SFU. It authenticates a short-lived Conference session and then delegates encrypted uplink/downlink to the same runtime. A concrete production sink uses bounded per-session queues and explicit backpressure; no unbounded media buffer is allowed.

The existing loopback plaintext local daemon remains local-only. A remotely reachable realtime gateway must use an authenticated TLS edge. Browser/mobile bindings may use protobuf POST plus authenticated server-streaming/SSE or HTTP/2. WebRTC/ICE/TURN can be added as a transport provider later without changing the public Conference/SFU ownership model.

## State, restart and metadata visibility

SFU forwarding state is ephemeral. Durable additions exist only in canonical stores such as Principal→Identity association, Call/Group/MLS state and canonical attendance Events. There is no durable SFU route topology, conference roster, implicit ciphertext archive or Delivery owner.

The SFU may observe only exact scope, Group/Call/stream identifiers, source/recipient routing principals, source Device ID, current MLS epoch/state reference, media kind, sequence/timing/keyframe metadata, signature metadata and encrypted packet size/timing required for routing. It must not receive media plaintext, MLS exporter/traffic/private keys, recovery/authentication secrets, unrelated Group roster/history, Message plaintext or provider credentials.

Recording is a separate explicit capability and service. Realtime forwarding must not enable it implicitly.

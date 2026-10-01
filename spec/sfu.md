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

The authenticated group-media header is versioned. Legacy **wire v1** remains readable byte-for-byte: audio is interpreted with no video source kind and legacy video is canonically interpreted as camera. Wire v1 can never claim screen-share authority because that distinction was not present in its authenticated header. The **wire v2** format uses a distinct AEAD associated-data domain and carries an explicit authenticated video source kind: camera or screen-share. Relabelling a v2 screen-share frame as camera (or the reverse) invalidates the Device signature/AEAD binding before SFU fan-out. For rolling-upgrade compatibility, ordinary audio/camera endpoint sealing remains on v1. Emitting a v2 screen-share frame is a separate fail-closed path that requires an opaque proof from canonical capability negotiation containing `ucr.media.video.screen_share`; callers cannot substitute a boolean flag. New decoders accept both versions under those narrower semantics.

The SFU receives no MLS exporter secret, stream traffic key or plaintext. Endpoint AEAD and replay state remain authoritative.

## SFU fan-out authority

Before any sink side effect, the runtime revalidates the current active Group-backed Call, media-negotiation reference/generation, exact Group MLS epoch/state reference, source active Group membership, Principal→Identity→Active Device association, current trusted source Device signing key/signature, source send permission, and every selected recipient's current membership/receive permission.

Recipients are derived only from current canonical Call participants plus recipient-owned Conference subscription preference. The SFU does not persist a recipient roster.

`ConferenceRuntime` performs the canonical Conference subscription selection first, then `SfuRuntime` produces an immutable validated forward batch after all canonical source and recipient checks pass. The batch constructor is private, so callers cannot manufacture pre-authorized routing work or bypass canonical Conference subscription selection. The existing synchronous `SfuForwardSink` path dispatches that batch locally and preserves exact partial-acceptance semantics. Horizontal transports must consume the same validated batch and await the destination node's concrete receipt; local queue admission or connection write alone must never be reported as remote `Accepted`. Successful sink/node acceptance is infrastructure routing acceptance only. It is not Device receipt, decrypt evidence, canonical Delivery state, user presentation or Read evidence. Partial acceptance is reported truthfully; there is no rollback or exactly-once fan-out claim.

## Horizontal placement foundation

`SfuClusterDirectory` is the prepared horizontal control-plane boundary. It stores only ephemeral
worker metadata: opaque node ID, deployment region, health/draining state, active/max session
capacity, a bounded lease expiry, and an optional private routable node endpoint. Placement is deterministic for the canonical
`TenantScope + CallId` pair so reconnects can remain sticky without inventing a second Conference
identity or durable route store.

Draining is fail-safe: an explicitly current session may remain on a live draining worker, but
draining workers never receive fresh placements. Fresh placement creates a coordinator-owned
reservation before returning, and explicit release returns that reservation. Worker heartbeat
`active_sessions` is observational load reported by the worker; it never overwrites placement
reservations. Because the aggregate heartbeat does not identify which Calls overlap existing
coordinator reservations, the directory must not guess that overlap. Until the later session-routing
boundary provides explicit admission/reconciliation evidence, effective capacity consumption is the
bounded sum of worker-reported active sessions plus pending coordinator reservations. This may
temporarily under-utilize a node, but a stale/lower heartbeat can never erase a reservation and
reopen a full node. Sequential placement through one directory therefore cannot overbook the last
advertised capacity unit across heartbeat refreshes. Expired, unavailable, and full workers are
excluded. If the sticky worker becomes unavailable, the directory deterministically selects a
healthy replacement. Region preference is a routing hint only; strict policy fails closed when no capacity
exists in-region, while an explicitly enabled cross-region policy may choose a healthy worker
elsewhere and reports that fact in the placement decision.

The private loopback `OperatorRuntimeService` now wires worker registration/heartbeat, bounded
node listing, explicit draining, and one validated private `IP:port` media endpoint into this same
directory. Operator node snapshots expose worker-reported `active_sessions`, coordinator
`reserved_sessions`, and their conservative `effective_sessions` sum so operational capacity
cannot disagree silently with placement admission. This remains infrastructure-only observability
and creates no second capacity owner.

Heartbeats carry only node ID, region, state, active/max session counters, bounded lease TTL, and
that infrastructure endpoint; API-only runtimes fail closed because they do
not own an SFU directory. Unspecified/multicast/broadcast addresses and port zero are rejected. Expired leases remain ineligible for fresh
placement; operator operations prune expired workers plus stale sticky placements so the bounded
directory remains reusable across node churn. Workers must re-register after process restart.

The realtime daemon also exposes a separate private `SfuPlacementService` on the same **private
operator listener**, never on the public realtime listener used as the HTTPS-edge upstream. The CLI
default is `127.0.0.1:50052` via `--operator-bind`; the runtime rejects reusing the public bind for
this listener. It accepts only canonical tenant scope, Call ID, optional preferred region and the
cross-region failover policy, then returns the opaque selected SFU node ID plus sticky/cross-region
placement facts. `ResolveNode` separately resolves a selected opaque node ID to the currently live
private `IP:port` endpoint; callers still cannot supply a node ID to `PlaceCall`. `ReleaseCall`
releases the directory reservation when the infrastructure owner knows that Call placement is
finished. Endpoint state is pruned with the same lease/remove path as node health and sticky
placement. The same in-process `SfuClusterDirectory` instance is shared with the operator
heartbeat/drain control, so node health, endpoint resolution, and placement cannot silently diverge
into separate routing brains.

This service is infrastructure-only and is not added to the Universal Conference protobuf or REST
adapter. It does not accept participant IDs, join tokens, media payloads, endpoint URLs or provider
credentials. The private resolver returns only the endpoint registered by the trusted operator
heartbeat for a currently live selected node. This enables a later gateway/worker-routing layer to
reach that node, but the prepared placement service still does not claim cross-node
participant/media transport.

## Private node media contract

The next horizontal data-plane boundary is `SfuNodeMediaService`, a private bidirectional stream
for already-encrypted SFU routing items. Each item contains only a connection-local
`stream_sequence`, one `SfuForwardTarget`, and the canonical `SfuForwardEnvelope`. Its receipt
can report only `Accepted`, `Backpressure`, or `Rejected` at the destination SFU ingress; it is
not canonical Delivery, device receipt, decrypt, presentation, or read evidence.

This service is **not** authorized by tenant Device, Principal, Service Account or public M2M
identity. The realtime runtime now has an optional private mTLS node listener for this exact service.
It accepts only loopback/private-network binds, requires a server certificate/private key resolved
through the shared `SecretProvider`, installs only explicitly configured client CA roots, and the
service still requires a non-empty TLS peer-certificate chain before decoding media. The deployment
CLI wires this through `UCR_SFU_NODE_BIND`, `UCR_SFU_NODE_CERT_FILE`,
`UCR_SFU_NODE_KEY_FILE`, and `UCR_SFU_NODE_CLIENT_CA_FILE`; optional previous certificate/key
and CA files provide bounded migration overlap. The public realtime listener never serves this
service.

Possession of an accepted cluster TLS credential authenticates an SFU process only; it does not
grant participant membership or media permission. The receiver revalidates canonical Group/Call,
Device, capability and media permissions before its local sink can accept the encrypted envelope.
Endpoint E2EE remains unchanged. See ADR-0113.

The receiving network boundary is now concrete, and the outbound mTLS node client foundation is
now concrete as well. It accepts only a
`SfuValidatedForwardBatch`, resolves its client certificate/private key through the shared
`SecretProvider`, trusts only explicitly configured server CA material, supports bounded
current/previous credential overlap, and waits for an exact monotonic receipt for every submitted
target. `Accepted`, `Backpressure`, and `Rejected` remain destination-ingress facts; partial
acceptance is preserved and no connection write is upgraded to remote success.

The outbound node client tied to `SfuPlacementService.ResolveNode` is now represented by a
placement-aware outbound router that binds the two private boundaries without creating a new
authority: it derives only canonical `TenantScope + CallId` from `SfuValidatedForwardBatch`,
calls `PlaceCall`, resolves only that selected node through `ResolveNode`, revalidates the
returned node identity plus private-network endpoint, then uses the deployment-scoped mTLS node
client and waits for destination receipts. The plaintext placement control connection is restricted
to loopback. It does not accept caller-supplied media endpoints and does not release placement after
each frame.

The realtime-session binding now has an explicit optional lifecycle gate. The existing
`RealtimeSessionRegistry` remains the only active-session roster: after an authenticated join is
accepted into that registry, `RealtimeSfuPlacementLifecycle` ensures one sticky placement for the
canonical `TenantScope + CallId`. A placement failure rolls the just-opened realtime session back.
Reconnects and additional participants reuse the same Call placement without reserving another
worker slot. On explicit leave, the registry is queried for the remaining non-expired sessions of
that same Call and the placement is released only when the count reaches zero. Release is
idempotent so retry/rollback cleanup cannot turn an already-absent placement into a second failure.
The production runtime wires this only behind the explicit
`UCR_SFU_PLACEMENT_LIFECYCLE_ENABLED` gate and refuses that gate without the private operator
plane. Enabling this pre-production gate still does not change the advertised public capability.

This foundation deliberately does **not** set the public `horizontal_sfu` runtime capability to
true. Production horizontal SFU still requires the placement-aware validated media path to be wired
into realtime publication, bounded node-failure/drain migration, deterministic release for sessions
that expire without an explicit leave, live credential reload evidence in the runtime path, and
load/adversity evidence. The placement directory must never become a Call, Conference,
membership, authorization, media-key, plaintext-media, Delivery, or recording owner.

## Public realtime transport

`ucr.v1.RealtimeService` is the stable external binding over the SFU. It authenticates a short-lived Conference session and then delegates encrypted uplink/downlink to the same runtime. A concrete production sink uses bounded per-session queues and explicit backpressure; no unbounded media buffer is allowed.

The existing loopback plaintext local daemon remains local-only. A remotely reachable realtime gateway must use an authenticated TLS edge. Browser/mobile bindings may use protobuf POST plus authenticated server-streaming/SSE or HTTP/2. WebRTC/ICE/TURN can be added as a transport provider later without changing the public Conference/SFU ownership model.

## State, restart and metadata visibility

SFU forwarding state is ephemeral. Durable additions exist only in canonical stores such as Principal→Identity association, Call/Group/MLS state and canonical attendance Events. There is no durable SFU route topology, conference roster, implicit ciphertext archive or Delivery owner.

The SFU may observe only exact scope, Group/Call/stream identifiers, source/recipient routing principals, source Device ID, current MLS epoch/state reference, media kind, authenticated camera/screen-share source kind where the current wire version carries it, sequence/timing/keyframe metadata, signature metadata and encrypted packet size/timing required for routing. It must not receive media plaintext, MLS exporter/traffic/private keys, recovery/authentication secrets, unrelated Group roster/history, Message plaintext or provider credentials.

Recording is a separate explicit capability and service. Realtime forwarding must not enable it implicitly.

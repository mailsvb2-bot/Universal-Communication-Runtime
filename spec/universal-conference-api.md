# Universal Conference Integration API

Status: **v1 public contract introduced; runtime wiring follows the existing canonical owners**.

This boundary exists so an external product can use UCR without understanding internal Group, Call, Principal or Device mechanics. It is business-neutral and must not contain product-specific names.

## External identity and room references

The integration key is `(TenantScope, IntegrationId, external reference bytes)`. Conference room references are owned by the durable Universal Conference coordinator metadata and reserve the eventual canonical Group handle; they do not reuse `GroupBridgeMapping`, because bridge mappings require a real bridge registration and have different semantics. Participant identity resolution reuses the existing durable `ExternalIdentityBinding` owner. UCR must not create a second user registry or require an integrator to persist internal UCR IDs. Participant ensure, update, removal and join issuance are addressed by the integration's `external_user_id`; internal `PrincipalId` and `DeviceId` never become required fields of the universal conference facade.

`UniversalConferenceDescriptor.conference_id` is the stable UCR-facing conference handle. Internal Group/Call/MLS identifiers remain implementation details of the coordinator.

## Conference modes and lifecycle

The same Conference system supports `meeting`, `webinar`, `broadcast` and `audio_room`. Webinar is therefore a configuration, not a separate product or second communication engine.

Lifecycle metadata is separate from Call signalling:

`scheduled -> waiting -> live -> ending -> ended`

The lifecycle coordinator may project into canonical Group/Call state but must never become a second CallSession authority. Scheduled rooms may exist before a realtime Call is started.

### Lifecycle integration Events

Crossing into `live` emits canonical Event type `ucr.conference.started`; crossing into `ended`
emits `ucr.conference.ended`. Waiting and ending remain coordinator states and do not manufacture
additional public lifecycle webhook types.

The Event payload is `UniversalConferenceLifecycleEvent` and contains only integration-facing
scope, conference/integration IDs, the integrator's external conference reference, previous/current
lifecycle, resulting revision and occurrence timestamp. The Event actor is `System` on behalf of
the authenticated Service Account whose principal ID equals `integration_id`, so the Event
subscription isolation boundary delivers the fact only to that integration.

Lifecycle transition and Event append are one durable atomic store operation. Memory performs both
under one mutex; SQLite performs the lifecycle compare-and-swap and canonical Event append in one
immediate transaction. A store that cannot provide this atomicity fails closed. A successful
transition therefore cannot become externally visible without its paired `ucr.conference.started` or
`ucr.conference.ended` Event, and an Event cannot commit without the corresponding lifecycle revision.


## Integration isolation

Every conference read or mutation is scoped by both `TenantScope` and `IntegrationId`. Universal Conference credentials are canonical Service Account credentials whose authenticated principal ID must exactly match the presented `IntegrationId`; a tenant permission by itself is not sufficient to impersonate another integration. A caller that presents another integration's `conference_id` receives `NOT_FOUND` after integration admission; the public API must not expose cross-integration existence or permit management by handle alone. External references remain integration-scoped and no integration credential is a tenant-wide conference superuser by default.

The gRPC facade accepts exactly one machine-authentication scheme per request: the existing binary Service Credential metadata or a standard `Authorization: Bearer <access-token>` value. Presenting both schemes, duplicate authorization values, partial Service Credential metadata or malformed Bearer syntax fails closed as unauthenticated. Bearer verification and OAuth scope attenuation remain owned by the shared machine-auth runtime; the Universal Conference adapter still re-evaluates the exact canonical permission, integration identity, request-rate quota and durable audit path for every RPC. Broader OAuth scope `conference:manage` may attenuate participant/device management calls, but it never replaces the exact `ucr.conference.participant.*` or `ucr.identity.device.register` Permission Grant required by the route. Production API/realtime modes load only the bounded public JWKS configured by `UCR_MACHINE_TOKEN_VERIFICATION_JWKS_FILE`; private machine-token signing material remains isolated to the machine-auth daemon.

## Participant roles and media policy

The public role vocabulary is `owner`, `host`, `moderator`, `speaker`, `attendee`. Role and media policy must be server-enforced; UI labels are never authorization evidence. Group membership remains canonical membership. Any role projection must fail closed if it conflicts with current membership. Exactly one active owner may exist. Ordinary participant ensure/update operations never transfer ownership: once a participant profile exists, changing into or out of `owner` is denied and ownership transfer requires a dedicated canonical operation. The single-active-owner invariant is also enforced atomically by every canonical `UniversalConferenceStore` mutation; caller-side read-before-write checks are defense in depth, not the concurrency authority.

The live participant ceiling is the canonical Call ceiling of **1024 active participants**. Storage enforces that live capacity atomically on creation and reactivation. Inactive historical participant projections remain durable but do not consume live capacity. Runtime reconciliation reads an active-only bounded projection with a 1025-item sentinel: exactly 1024 active participants is valid, while observing a 1025th active participant fails closed as resource exhaustion. Public participant listing remains capped at 1024 items per request.

## Participant removal and role reconciliation

Removing a non-owner participant first makes the Universal profile inactive and revokes managed realtime permissions, then removes the participant from any non-terminated canonical Call and finally applies an MLS-backed Group `RemoveMember`. This ordering is fail-closed: access is denied before cryptographic membership cleanup, and a retry can complete any later canonical cleanup. The active conference owner cannot be removed through ordinary participant removal because doing so would orphan the Person-owned Group.

Role changes are reconciled into the canonical Group on the next runtime preparation. Host/moderator project to Group admin, speaker/attendee to Group member, and an actual Group role change is applied through the MLS-backed `ChangeRole` transition so the crypto epoch advances with the security-sensitive authorization change.

## Runtime materialization

`PrepareConferenceRuntime` is the integration-facing reconcile operation that turns coordinator metadata into canonical realtime state. It does not create a second Group, MLS, or Call owner: the stable `conference_id` is used as the canonical Group handle, OpenMLS state is created/advanced through `GroupMlsAtomicStore`, and signalling is created/updated through `CallStore`.

Exactly one active Universal participant with role `owner` is required. Only active participants with exactly one active canonical Device are admitted into MLS/Call state. The owner becomes the real Person-owned Group owner and Call initiator; the authenticated integration Service Account authorizes orchestration but never becomes a media participant. A first Call requires at least two device-ready participants because canonical group-call creation requires an initiator plus at least one invitee. With only the owner ready, Group/MLS preparation may succeed while `call_ready=false`; a later reconcile can add newly device-ready participants and create the Call.

## Participant authorization projection

Universal participant role/media policy is projected into the existing canonical Permission Grant owner after the participant profile is persisted. Active participants receive only the exact-scope permissions needed to observe the Call, manage their receive subscriptions and receive supported media; audio, camera-video and screen-share send grants exist only while the participant profile allows the corresponding publish direction. Screen sharing is an independent server-side policy: `screen_share_allowed` projects to `ucr.call.screen_share.send`, and neither `camera_allowed` nor `ucr.call.video.send` authorizes an authenticated `screen_share` source. Managed grants are revoked when policy removes that authority or the participant becomes inactive.

The ordering is fail-closed: profile/policy is written before permission synchronization. A grant failure can therefore leave a participant unable to perform an allowed action, but cannot make a disallowed or removed participant usable because Universal profile checks remain mandatory at realtime boundaries.

## Media subscriptions

`SetSubscriptions` exposes the existing Conference receive-subscription owner through the universal facade. The subscriber and every requested media source are addressed only by integration-owned `external_user_id`; UCR resolves those references to the current canonical participants and active Call internally. The integrator never supplies `PrincipalRef`, `CallId` or `DeviceId`.

The operation replaces the subscriber's complete bounded receive-subscription set. An empty set clears it. Canonical Conference validation still requires an accepted subscriber, a current accepted source, active Group membership and the exact audio/video receive permissions before routing can change. A subscription is routing preference only and never creates membership, publish authority or media permission.

Subscription state remains intentionally ephemeral in the existing shared `ConferenceRuntimeState`, not a second durable Conference store. Repeating the same full replacement is safe, but a process restart drops routing preferences and clients must re-establish them after reconnect. The low-level Conference API, universal facade, RealtimeService and SFU must share that same runtime state so a successful universal mutation changes the actual encrypted SFU routing path.

## Participant device enrollment

`EnsureParticipantDevice` gives an already ensured external participant exactly one canonical active UCR Device when no device lifecycle exists yet. The public response exposes only the integration's `external_user_id` and readiness state; canonical `DeviceId` remains internal.

Enrollment is deliberately conservative: multiple active devices are a conflict, and an existing stale/reverification-required/expired/revoked device is not silently replaced. Recovery and reverification remain explicit canonical flows. This server-managed device lifecycle is a prerequisite for MLS/Call orchestration, but it must not be presented as proof that browser WebRTC, TURN, or endpoint-held production E2EE is ready.

## Join grants

`IssueJoinGrant` accepts external user identity and resolves canonical Identity/Principal/Device inside UCR. The integrator is not required to submit `PrincipalRef` or `DeviceId`.

Join grants are short-lived and conference-scoped. The contract reserves single-use/reusable policy, explicit not-before/not-after bounds and revocation. An eligible canonical Call participant may be `invited`, `ringing` or already `accepted` when a grant is issued; presenting a valid grant at the realtime join boundary performs the participant's canonical `Accept` transition before the media session is opened. Rejected, busy, left, inactive or removed participants remain denied. Runtime implementations must reject unsupported semantics rather than silently weakening them.

Universal join issuance and revocation are durable idempotent mutations. The accepted idempotency command yields the stable session identifier; the signed token is reproducible from durable claims and is never stored as plaintext. Revocation and single-use redemption live in the canonical `ConferenceJoinGrantStore`, so a process restart does not reactivate a revoked grant or forget that a single-use grant was consumed. The older low-level Conference join URL path remains a compatibility boundary until it is migrated separately.

## Capability discovery

`GetCapabilities` exposes the canonical prepared media/conference capabilities plus explicit runtime-readiness flags. Those flags are deployment state, not compile-time constants: the service defaults fail closed, the realtime runtime projects only configured capabilities, and TURN is reported only when a validated TURN URL/credential issuer is actually configured. Browser-gateway availability requires explicit operator enablement because the gateway lives outside the private loopback runtime. The stronger production-WebRTC flag remains false until production evidence is wired into the runtime readiness boundary; an environment variable alone is not accepted as proof. Recording and horizontal-SFU remain false until corresponding providers are wired. Capability discovery must not claim production readiness for browser realtime, WebRTC, TURN, recording, or horizontal SFU until the corresponding implementation and conformance evidence exist. A prepared protocol capability is not the same thing as a production deployment feature.

## Waiting room and admission

A participant may establish the authenticated realtime session while a Universal Conference is in
`waiting`, but Conference media is not admitted until the lifecycle reaches `live`. The realtime
contract exposes `WAITING_ROOM`, `ADMITTED` and `CLOSED` admission states on join and heartbeat,
so a browser can render “the broadcast will start soon” and automatically begin media after the host
starts the Conference without minting a second business-specific room concept.

`entry_open` is an entry gate, not a retroactive media kill switch. A first attendee join is denied
while entry is closed, with bounded retry guidance. A session that was already admitted to the
realtime registry is not invalidated merely because the host later closes entry; removal/revocation
remain the explicit mechanisms for ejecting a participant. Host/moderator/speaker access continues
to be governed by canonical participant role and lifecycle policy.

WebRTC start, encrypted publish, downlink subscription and media-subscription mutation all fail
closed before `live`. Heartbeat remains available in the waiting room and reports the lifecycle
projection so clients can observe the transition to `ADMITTED`. Legacy non-Universal Conference
calls keep their existing behavior.

## Attendance

`GetParticipantAttendance` is integration-scoped and addressed by `external_user_id`. It returns first join, last leave, first media-ready time, join/reconnect/media-ready counts, current connection duration and total connected duration.

Attendance is a read-only projection over the canonical Event journal. The projection does not create a second attendance database or expose private Event journal positions. EventJournal filters by the exact canonical participant principal before applying the bounded projection, so unrelated conference/participant history cannot exhaust an attendance read. If the participant's own bounded projection cannot prove that it has the complete relevant history, it fails closed with resource exhaustion instead of returning partial totals as complete data.

## Idempotency

All create/mutate operations carry an explicit idempotency key where appropriate. Exact retries must deduplicate durably; changed requests under the same idempotency identity must conflict.

## Transport adapters

gRPC is the typed source contract. REST/JSON, OpenAPI, JavaScript/TypeScript, Python, Kotlin, Swift and Rust SDKs must remain thin adapters over the same contract. No REST-only business rules are allowed.

`ucr-conference-web` is that HTTP adapter. It binds loopback only and forwards each `/v1/...` route to exactly one `UniversalConferenceService` RPC. The JSON body is the RPC request: opaque identifiers stay UTF-8 tokens, and external reference bytes are standard Base64. `Authorization` is copied into gRPC metadata and is not interpreted by the adapter. Canonical permission, quota, audit, idempotency and integration isolation remain in the gRPC ingress. `GET /v1/openapi.yaml` publishes the route map. A loopback test posts `/v1/capabilities` without credentials and requires the canonical unauthenticated error from `UniversalConferenceService`, both directly and through `ucr-https-edge`, so the adapter is not only a JSON parser. A trusted HTTPS edge is still required before this listener is reachable outside the host.

## Product boundary

No CRM, funnel, payment, advertising, warm-up campaign or ClientPlatform-specific business concept belongs here. External products consume communication facts and apply their own business logic.

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

## Integration isolation

Every conference read or mutation is scoped by both `TenantScope` and `IntegrationId`. Universal Conference credentials are canonical Service Account credentials whose authenticated principal ID must exactly match the presented `IntegrationId`; a tenant permission by itself is not sufficient to impersonate another integration. A caller that presents another integration's `conference_id` receives `NOT_FOUND` after integration admission; the public API must not expose cross-integration existence or permit management by handle alone. External references remain integration-scoped and no integration credential is a tenant-wide conference superuser by default.

## Participant roles and media policy

The public role vocabulary is `owner`, `host`, `moderator`, `speaker`, `attendee`. Role and media policy must be server-enforced; UI labels are never authorization evidence. Group membership remains canonical membership. Any role projection must fail closed if it conflicts with current membership. Exactly one active owner may exist. Ordinary participant ensure/update operations never transfer ownership: once a participant profile exists, changing into or out of `owner` is denied and ownership transfer requires a dedicated canonical operation. The single-active-owner invariant is also enforced atomically by every canonical `UniversalConferenceStore` mutation; caller-side read-before-write checks are defense in depth, not the concurrency authority.

## Participant removal and role reconciliation

Removing a non-owner participant first makes the Universal profile inactive and revokes managed realtime permissions, then removes the participant from any non-terminated canonical Call and finally applies an MLS-backed Group `RemoveMember`. This ordering is fail-closed: access is denied before cryptographic membership cleanup, and a retry can complete any later canonical cleanup. The active conference owner cannot be removed through ordinary participant removal because doing so would orphan the Person-owned Group.

Role changes are reconciled into the canonical Group on the next runtime preparation. Host/moderator project to Group admin, speaker/attendee to Group member, and an actual Group role change is applied through the MLS-backed `ChangeRole` transition so the crypto epoch advances with the security-sensitive authorization change.

## Runtime materialization

`PrepareConferenceRuntime` is the integration-facing reconcile operation that turns coordinator metadata into canonical realtime state. It does not create a second Group, MLS, or Call owner: the stable `conference_id` is used as the canonical Group handle, OpenMLS state is created/advanced through `GroupMlsAtomicStore`, and signalling is created/updated through `CallStore`.

Exactly one active Universal participant with role `owner` is required. Only active participants with exactly one active canonical Device are admitted into MLS/Call state. The owner becomes the real Person-owned Group owner and Call initiator; the authenticated integration Service Account authorizes orchestration but never becomes a media participant. A first Call requires at least two device-ready participants because canonical group-call creation requires an initiator plus at least one invitee. With only the owner ready, Group/MLS preparation may succeed while `call_ready=false`; a later reconcile can add newly device-ready participants and create the Call.

## Participant authorization projection

Universal participant role/media policy is projected into the existing canonical Permission Grant owner after the participant profile is persisted. Active participants receive only the exact-scope permissions needed to observe the Call, manage their receive subscriptions and receive supported media; audio/video send grants exist only while the participant profile allows the corresponding publish direction. Managed grants are revoked when policy removes that authority or the participant becomes inactive.

The ordering is fail-closed: profile/policy is written before permission synchronization. A grant failure can therefore leave a participant unable to perform an allowed action, but cannot make a disallowed or removed participant usable because Universal profile checks remain mandatory at realtime boundaries.

## Participant device enrollment

`EnsureParticipantDevice` gives an already ensured external participant exactly one canonical active UCR Device when no device lifecycle exists yet. The public response exposes only the integration's `external_user_id` and readiness state; canonical `DeviceId` remains internal.

Enrollment is deliberately conservative: multiple active devices are a conflict, and an existing stale/reverification-required/expired/revoked device is not silently replaced. Recovery and reverification remain explicit canonical flows. This server-managed device lifecycle is a prerequisite for MLS/Call orchestration, but it must not be presented as proof that browser WebRTC, TURN, or endpoint-held production E2EE is ready.

## Join grants

`IssueJoinGrant` accepts external user identity and resolves canonical Identity/Principal/Device inside UCR. The integrator is not required to submit `PrincipalRef` or `DeviceId`.

Join grants are short-lived and conference-scoped. The contract reserves single-use/reusable policy, explicit not-before/not-after bounds and revocation. An eligible canonical Call participant may be `invited`, `ringing` or already `accepted` when a grant is issued; presenting a valid grant at the realtime join boundary performs the participant's canonical `Accept` transition before the media session is opened. Rejected, busy, left, inactive or removed participants remain denied. Runtime implementations must reject unsupported semantics rather than silently weakening them.

## Capability discovery

`GetCapabilities` exposes the canonical prepared media/conference capabilities plus explicit runtime-readiness flags. Capability discovery must not claim production readiness for browser realtime, WebRTC, TURN, recording, or horizontal SFU until the corresponding implementation and conformance evidence exist. A prepared protocol capability is not the same thing as a production deployment feature.

## Attendance

`GetParticipantAttendance` is integration-scoped and addressed by `external_user_id`. It returns first join, last leave, first media-ready time, join/reconnect/media-ready counts, current connection duration and total connected duration.

Attendance is a read-only projection over the canonical Event journal. The projection does not create a second attendance database or expose private Event journal positions. If the bounded projection cannot prove that it has the complete relevant history, it fails closed with resource exhaustion instead of returning partial totals as complete data.

## Idempotency

All create/mutate operations carry an explicit idempotency key where appropriate. Exact retries must deduplicate durably; changed requests under the same idempotency identity must conflict.

## Transport adapters

gRPC is the typed source contract. REST/JSON, OpenAPI, JavaScript/TypeScript, Python, Kotlin, Swift and Rust SDKs must remain thin adapters over the same contract. No REST-only business rules are allowed.

## Product boundary

No CRM, funnel, payment, advertising, warm-up campaign or ClientPlatform-specific business concept belongs here. External products consume communication facts and apply their own business logic.

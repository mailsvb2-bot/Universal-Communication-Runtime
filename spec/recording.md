# Conference Recording

Status: **public gRPC lifecycle binding present; separate opt-in capability remains disabled unless a concrete provider is advertised**.

Recording is intentionally independent from SFU forwarding. `ucr.conference.recording` must be explicitly advertised before `RecordingService` is available. A deployment that does not advertise the capability records nothing.

## Preconditions

Every recording has an explicit `RecordingPolicy` with finite retention. Media is encrypted at rest. Participant notification is explicit. When policy or applicable deployment rules require consent, recording cannot enter ACTIVE until the required current Conference participants have granted consent. DENIED or REVOKED consent blocks or terminates recording according to policy; the implementation must never reinterpret silence as consent.

The Recording owner stores recording lifecycle and consent evidence only. Group/Call membership stays canonical elsewhere. SFU must not silently archive ciphertext, and diagnostics/telemetry must not contain recorded media.

Recording lifecycle mutations are optimistic-revision operations. Start, stop and delete management requests may also carry an optional `idempotency_key`. When present, the public ingress reuses the canonical `CommandAcceptanceStore`; exact retries deduplicate durably across restart, while a changed request under the same key conflicts. Older clients that omit the key retain the legacy optimistic-revision contract and do not gain a new hidden retry guarantee.

Externally observable recording lifecycle facts use the one canonical Event journal:
- transition to `ACTIVE` emits `ucr.recording.started`;
- transition to `STOPPED` emits `ucr.recording.stopped`, including an ACTIVE recording stopped by participant denial/revocation;
- transition to `DELETED` emits `ucr.recording.deleted`.

The store contract provides an atomic `expire_recording_with_event` path and the runtime now has a bounded, lease-coordinated retention worker. It enumerates only non-final recordings whose durable `expires_at_unix_ms` has elapsed, then re-checks each exact revision inside the atomic expiry+Event transition. Concurrent lifecycle changes become stale work and are skipped rather than force-expired. Successful expiry emits `ucr.recording.expired` through the canonical Event journal.

The retention worker owns no media bytes and does not make recording Production-ready. It is finite-retention lifecycle enforcement only; controlled encrypted-media deletion still requires a concrete `RecordingMediaProvider` implementation and provider conformance evidence.

The Event payload is `RecordingLifecycleEvent` and contains only the scoped recording/call identifiers, previous/current state, resulting revision and occurrence timestamp. Recording snapshot mutation and Event append are one durable atomic store action. Memory performs both under one mutex with rollback on Event conflict; SQLite performs compare-and-swap plus Event append in one immediate transaction. A store that cannot prove this atomicity fails closed rather than performing two independent writes. This lifecycle evidence still does not make a concrete media recorder Production-ready.

Consent is participant-authenticated: `SetRecordingConsent` must verify the device-bound realtime bearer token and require its exact scope, Call and participant claims to match the Recording session and consent subject. Integration or Service Account authority may request/manage the recording lifecycle but is never evidence of an individual participant's consent.

An explicit `DENIED` or `REVOKED` decision always blocks starting the recording and immediately stops an ACTIVE lifecycle, even when the policy does not require every participant to affirmatively grant consent. Pending consent may be tolerated only when `require_all_participant_consent=false`; silence is never converted into a granted decision.

## Retention and deletion

`expires_at_unix_ms` is derived from the accepted retention policy and is durable. Expiry stops further recording and schedules deletion of controlled storage/key material. Delete acknowledgement means the controlled recording owner accepted/performed its defined deletion transition; it is not a claim that an already exported copy on an external or compromised system was physically erased.

Retention extension is not implicit. A future extension must be an explicit authorized lifecycle operation with audit evidence.

## Public API binding

The versioned `ucr.v1.RecordingService` is bound in `ucr-api-grpc` to the canonical
`RecordingStore`. Management requests reuse the same Service Credential / machine Bearer admission,
quota, audit and `ucr.conference.recording.manage` permission owner as the universal Conference API.
Participant consent does not accept Service Account authority: it reuses the device-bound realtime
join-token verifier and requires the verified token scope, Call and participant to match the durable
recording consent subject.

The binding is fail-closed when recording runtime capability is unavailable. Merely compiling or
serving this lifecycle contract is not permission to advertise Production recording.

## Pluggable provider boundary

Concrete recording side effects use one pluggable `RecordingMediaProvider` boundary. The provider receives only bounded canonical context: scope, Recording ID, Call ID, lifecycle revision, operation and retention expiry. It does not receive a second Conference/Call/Recording model, join credentials, media crypto keys or arbitrary integration metadata through this control contract.

The provider operation identity is the exact `(scope, recording_id, lifecycle_revision, operation)` tuple. Exact retries must be idempotent. A changed request that collides with an already-applied provider operation must fail closed rather than duplicating capture/finalization/deletion effects.

A provider may represent an in-process recorder, S3-compatible encrypted object pipeline, or an external media pipeline, but it must not become a second Recording lifecycle owner. Canonical lifecycle, participant consent, authorization, retention timestamps and Event evidence remain owned by the existing UCR Recording/Event boundaries.

This contract establishes the replaceable provider seam only. It does not enable `ucr.conference.recording` by itself and is not evidence of encryption-at-rest, retention deletion, export authorization, provider recovery, media composition or recording-ready delivery. Those require a concrete provider plus conformance evidence.

## Output/provider boundary

When an integration has `max_recording_minutes` configured, a concrete recording provider must reserve the accepted recording duration through the canonical Service resource-quota boundary before treating that duration as provider work. The quota counter is durable and integration-scoped; billing/calendar renewal semantics remain outside UCR and use an explicit authorized reset.

Concrete encoded-media capture, compositor/mixer behavior and object storage are provider boundaries behind the Recording lifecycle. They must not receive MLS keys or unrelated Conference state beyond what is required for the explicitly authorized recording path. A Production recording provider needs storage encryption, access authorization, integrity evidence, retention enforcement, failure recovery and export/delete conformance tests.

The durable lifecycle/store can be implemented and tested while `ucr.conference.recording` remains unadvertised. Capability discovery must continue to report recording unavailable until a concrete encrypted media provider is wired, participant-churn policy is enforced at the realtime boundary, and provider deletion/retention conformance is proven.

### Realtime participant-churn gate

Realtime admission now checks every ACTIVE Recording for the exact canonical Call before registering a
new/reconnected realtime session. The participant must already exist in that Recording's consent
set. When `require_all_participant_consent=true`, admission requires `GRANTED`; when the policy
does not require every affirmative grant, an existing `PENDING` consent may remain admissible, but
`DENIED`, `REVOKED`, or completely absent consent evidence fails closed with PolicyDenied.

This deliberately does not invent consent for a participant who joined after Recording creation.
Until dynamic roster-to-consent expansion is designed as an atomic canonical operation, a late
participant who is absent from an ACTIVE Recording consent set cannot enter its realtime media
session. The integration may stop/recreate the recording with the new roster rather than silently
recording a participant with no notification/consent evidence. Lookup is bounded; exceeding the
active-recording scan ceiling fails closed rather than skipping an active recording.

### Durable provider-operation outbox

Recording lifecycle transitions that require provider side effects now prepare a durable
`RecordingProviderOperationRecord` in the same atomic storage action as the Recording snapshot and
lifecycle Event. Start prepares `Start`; explicit stop and consent-triggered stop prepare `Stop`;
delete and retention expiry prepare `Delete`. This prevents the two unsafe split-brain cases:
committing ACTIVE without a durable recorder-start obligation, or invoking a recorder before the
canonical lifecycle commit is durable.

The provider-operation identity is exactly
`(scope, recording_id, lifecycle_revision, operation)`. Exact prepare retries deduplicate; changed
reuse conflicts. Pending operations survive restart in SQLite schema v47. A bounded dispatcher
applies only due pending operations, marks successful requests Applied, schedules bounded
exponential retry for transient provider failures, and marks permanent or retry-exhausted requests
Failed. The dispatcher never changes canonical Recording lifecycle state.

SQLite commits Recording snapshot + Event + provider operation in one IMMEDIATE transaction. The
memory store mirrors the same semantics under one mutex for conformance tests. Stores that cannot
prove this combined atomicity inherit fail-closed default methods rather than silently performing a
second non-atomic write.

The runtime now also exposes a durable single-owner provider dispatcher worker over this outbox.
It holds a SQLite-backed worker lease, renews that lease while active, drains only bounded due
Start/Stop/Delete operations through `dispatch_recording_provider_operations_once`, and leaves all
retry/terminal-failure semantics in the canonical outbox. A competing live worker fails closed and an
unsafe polling interval is rejected before provider side effects. Logs contain only aggregate sweep
counts plus the provider implementation ID at startup, never Recording/Call IDs or media/key data.
The worker does not make Recording capability available by itself.

The private operator health projection observes the provider registered by that same
ProductionRuntime worker. With no active worker/provider it reports NotConfigured; a running
provider maps its own Healthy, Degraded, or Unavailable state into the existing recorder health
component. Registration occurs only after the durable worker lease is acquired and is removed
automatically when the worker exits or loses its lease, so stale in-process provider state cannot
remain advertised as healthy. Provider IDs, Recording IDs, Call IDs and media/key material are not
copied into health details. This health wiring does not change the public recording capability flag.

This outbox and worker are infrastructure for a concrete recorder, not the recorder itself. The
shipped runtime still reports recorder NotConfigured and `ucr.conference.recording` remains
unavailable until a real encrypted media provider, provider health wiring, capture/finalization
behavior, access/export authorization, deletion proof and recovery/conformance evidence are present.

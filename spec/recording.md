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

### Validated encrypted-media observer seam

The realtime service now has one optional `RealtimeValidatedMediaObserver` seam on the canonical
Conference/SFU source path. The observer is invoked only after the exact source participant, Device,
Call/Group/MLS context, source signature and send permission validate. It receives the canonical
`SfuValidatedSourceFrame`, which contains ciphertext plus authenticated routing metadata but no
plaintext media or endpoint/MLS key material.

The observer runs before recipient fan-out and is deliberately independent from subscription
selection. Recording/composition infrastructure therefore does not disappear merely because no
participant currently subscribes to the source, and it does not need to duplicate recipient
authorization logic. Source validation produces a single-use token: the observer inspects that
token by reference and the same token is then consumed to derive the recipient batch, so
Call/Group/Device/MLS/signature/send authorization is not repeated on the frame-rate-sensitive
media path. A configured observer failure is fail-closed: the frame is not routed live after the
observer rejects it, preventing silent recording/composition loss while delivery continues.

Production runtime now binds this seam to the same registered `RecordingMediaProvider` used by
the durable lifecycle worker. For every validated frame it performs a bounded
`active_recordings_for_call` lookup. With no ACTIVE Recording it returns immediately and Conference
remains independent from any recorder. An ACTIVE row whose `expires_at_unix_ms` has already passed
is excluded on the media hot path even if the retention worker has not swept it yet. Every remaining
Recording must also have its newest matching provider `Start` operation at or before its current
canonical revision in durable `Applied` state. This matters because participant consent evidence may
advance an ACTIVE Recording revision without creating another provider Start side effect. A Pending
Start fails temporarily closed, while a missing or terminally Failed Start is treated as an internal
invariant failure. Runtime carries that provider Start revision into
`RecordingProviderCaptureContext`, preserving the capture idempotency domain across later consent
revisions. Only then does runtime require the exact registered provider holder to still own an
unexpired durable worker lease, reject an Unavailable provider, and invoke
`capture_encrypted_frame` once for each capturable Recording. Capture failure is fail-closed before live recipient fan-out so
the system cannot silently advertise a continuous recording while dropping media.

`RecordingProviderCaptureContext::capture_identity` builds the complete provider idempotency key
from Recording identity plus the authenticated media dimensions: scope, recording ID, Call ID,
lifecycle revision, Group, source principal/device, media kind, video source kind, stream ID,
negotiation reference/generation, crypto epoch/state and sequence. Media kind and negotiation
binding are explicit because valid audio/video streams can share a stream/sequence pair and a fresh
negotiation may restart sequence state. Exact retries must be idempotent at the provider boundary;
changed payload reuse for the same complete identity conflicts. The provider receives the already
source-authenticated encrypted frame and never receives endpoint/MLS exporter key material from this
path.

A concrete local encrypted-at-rest archive provider now exists in `ucr-recording`. It is still
infrastructure rather than a Production recorder: the trait default remains fail-closed, runtime
configuration does not automatically advertise Recording, and export/access authorization plus
end-to-end deletion/recovery evidence remain outstanding. `ucr.conference.recording` therefore
remains unavailable by default.

### Encrypted local archive provider

`EncryptedArchiveRecordingProvider` stores only already source-authenticated encrypted media frames
and provider-operation receipts. It applies a second, independent XChaCha20-Poly1305 at-rest layer
using the shared `SecretProvider` with the dedicated `RecordingAtRest` purpose. The archive
envelope carries only the bounded secret version identifier, nonce and ciphertext; associated data
binds the object to a domain-separated hashed provider identity.

Provider-owned directory and object names are SHA-256-derived and do not contain raw tenant,
namespace, Recording, Call, participant or stream identifiers. Unix provider-owned directories are
private and archive files are created privately; symlinks and unexpected filesystem object types are
rejected. New objects use no-clobber creation, exact retries decrypt and compare the existing
authenticated record, and changed payload reuse of one canonical provider/capture identity fails
with `Conflict`.

Key rotation is overlap-safe: new objects use the current at-rest key version, while an exact retry
may authenticate an existing object with the bounded previous version supplied by the same shared
secret owner. At-rest keys are exactly 32 bytes, are never persisted by the recording provider, and
copied key material is zeroized after AEAD use.

A provider `Delete` writes/verifies its encrypted idempotency receipt before deleting controlled
recording frame objects. This makes retry after an interrupted delete deterministic without retaining
raw media. It does not claim erasure of copies exported to another system and does not yet provide
the authorized export/read surface required for Production Recording.


### Opt-in realtime runtime wiring

`ucr-runtime serve-realtime` can now opt into the concrete archive with
`UCR_RECORDING_PROVIDER=encrypted-archive-v1`. Configuration is deliberately fail-closed:
`UCR_RECORDING_ARCHIVE_ROOT` must be an absolute path, the at-rest key must come from
`UCR_RECORDING_AT_REST_SECRET_PROVIDER=file-reload` with
`UCR_RECORDING_AT_REST_SECRET_FILE` and an optional
`UCR_RECORDING_AT_REST_SECRET_ID`, and the provider poll interval is bounded to 100 ms through
60 s. Recording-related dependent variables without the explicit provider selector are rejected
instead of silently ignored.

The provider worker and realtime server use the same `ProductionRuntime` instance. Startup
orchestration polls the worker first so it acquires the durable single-owner lease and registers the
provider before the realtime server can begin accepting media. The server and worker then run under
one `tokio::select!`: provider failure stops the combined command, while server termination cancels
the worker. A cancellation-safe lease guard unregisters the in-process provider and releases the
durable worker lease when the worker future is dropped, avoiding a stale lease after startup/bind
failure or coordinated shutdown.

This wiring is opt-in infrastructure only. No provider is configured by default and the public
`ucr.conference.recording` capability remains false. Provider finalization/readiness is now
durable and Event-backed, but access-controlled export/download, deletion/recovery conformance and
the remaining Production evidence are still required before the capability may be advertised.

### Durable provider-operation outbox

Recording lifecycle transitions that require provider side effects now prepare a durable
`RecordingProviderOperationRecord` in the same atomic storage action as the Recording snapshot and
lifecycle Event. Start prepares `Start`; explicit stop and consent-triggered stop prepare `Stop`;
delete and retention expiry prepare `Delete`. This prevents the two unsafe split-brain cases:
committing ACTIVE without a durable recorder-start obligation, or invoking a recorder before the
canonical lifecycle commit is durable.

The provider-operation identity is exactly
`(scope, recording_id, lifecycle_revision, operation)`. Exact prepare retries deduplicate; changed
reuse conflicts. Pending operations survive restart. SQLite schema v48 adds a storage-only
`ready_event_emitted` marker to Stop operations. A bounded dispatcher applies only due pending
operations, schedules bounded exponential retry for transient provider failures, and marks permanent
or retry-exhausted requests Failed. Start/Delete success uses the normal Applied transition. Stop
success instead commits Applied plus the canonical `ucr.recording.ready` Event in one SQLite
transaction. The dispatcher never changes canonical Recording lifecycle state.

SQLite commits Recording snapshot + Event + provider operation in one IMMEDIATE transaction. The
memory store mirrors the same semantics under one mutex for conformance tests. Stores that cannot
prove this combined atomicity inherit fail-closed default methods rather than silently performing a
second non-atomic write.

The runtime now also exposes a durable single-owner provider dispatcher worker over this outbox.
It holds a SQLite-backed worker lease, renews that lease while active, drains only bounded due
Start/Stop/Delete operations through the ready-aware dispatcher, and leaves all retry/terminal-failure
semantics in the canonical outbox. A competing live worker fails closed and an
unsafe polling interval is rejected before provider side effects. Logs contain only aggregate sweep
counts plus the provider implementation ID at startup, never Recording/Call IDs or media/key data.
The worker does not make Recording capability available by itself.

The private operator health projection observes the provider registered by that same
ProductionRuntime worker. With no active worker/provider it reports NotConfigured. Before trusting
the provider's own Healthy, Degraded, or Unavailable state, every health snapshot revalidates the
durable recording-provider worker lease and requires the exact registered holder plus an unexpired
lease. Expiry, takeover by another process, a missing lease, or lease-read failure reports
Unavailable even if the stale in-process provider still reports Healthy. Registration occurs only
after the durable worker lease is acquired and is removed when the worker exits. Provider IDs,
worker-holder IDs, Recording IDs, Call IDs and media/key material are not copied into health details.
This health wiring does not change the public recording capability flag.

### Provider finalization and recording-ready Event

`RecordingState::Ready` and `ucr.recording.ready` deliberately mean different things.
Lifecycle `Ready` means consent/policy gates are satisfied **before** Start. The
`ucr.recording.ready` Event means a provider Stop has successfully finalized the stopped
recording artifact.

The public payload is `RecordingReadyEvent`: scope, Recording ID, Call ID, the exact provider Stop
lifecycle revision, ready-observation timestamp and a `recovered_after_upgrade` flag. Event
identity, system actor and source-device identities are deterministically derived from the canonical
Stop identity, so exact retries do not invent a second fact. The Event is intentionally
provider-neutral: pre-v48 Applied Stop rows do not durably prove which provider implementation
performed finalization, so recovery must not attribute them to whichever provider happens to be
configured after upgrade. Actor attribution remains on behalf of the original recording requester.

Provider finalization is necessarily outside the local SQLite transaction, so the execution order is
provider Stop first, then local durable commit. Exact provider Stop requests are idempotent. If the
process crashes after provider success but before the local commit, the Stop remains Pending and the
same provider operation is retried safely. Once provider success is known, SQLite atomically marks
that Stop Applied, appends `ucr.recording.ready` to the canonical Event journal, and flips the
storage-only ready marker. Event conflict rolls the entire local transition back.

Upgrade recovery is explicit. v47 databases migrate to SQLite schema v48 with
`ready_event_emitted=0`. Already-Applied legacy Stop rows are discovered by a bounded recovery
view. The worker creates the same deterministic provider-neutral ready fact with
`recovered_after_upgrade=true` and atomically appends it plus the marker **without calling the
provider again**. Recovery remains valid even if the Recording has subsequently advanced from
STOPPED to EXPIRED or DELETED; the ready fact remains bound to the exact earlier Stop revision.
This closes the old-binary upgrade gap while preserving exactly one provider finalization.

Because `recording.ready` is in the same canonical Event journal, existing durable-stream and
Webhook subscriptions can receive it through the normal Event delivery machinery. No recording
media bytes, storage paths, encryption keys or export URLs are placed in this Event.

This outbox, worker, validated capture path, encrypted archive provider, opt-in runtime wiring and
durable provider-ready Event are still not a complete Production recorder. The shipped runtime has
no configured provider by default and `ucr.conference.recording` remains unavailable until
access/export authorization, deletion/recovery conformance and the remaining Production evidence
are present.

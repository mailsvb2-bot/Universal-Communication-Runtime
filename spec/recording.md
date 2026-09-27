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
- transition to `EXPIRED` emits `ucr.recording.expired`;
- transition to `DELETED` emits `ucr.recording.deleted`.

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

## Output/provider boundary

When an integration has `max_recording_minutes` configured, a concrete recording provider must reserve the accepted recording duration through the canonical Service resource-quota boundary before treating that duration as provider work. The quota counter is durable and integration-scoped; billing/calendar renewal semantics remain outside UCR and use an explicit authorized reset.

Concrete encoded-media capture, compositor/mixer behavior and object storage are provider boundaries behind the Recording lifecycle. They must not receive MLS keys or unrelated Conference state beyond what is required for the explicitly authorized recording path. A Production recording provider needs storage encryption, access authorization, integrity evidence, retention enforcement, failure recovery and export/delete conformance tests.

The durable lifecycle/store can be implemented and tested while `ucr.conference.recording` remains unadvertised. Capability discovery must continue to report recording unavailable until a concrete encrypted media provider is wired, participant-churn policy is enforced at the realtime boundary, and provider deletion/retention conformance is proven.

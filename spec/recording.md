# Conference Recording

Status: **separate opt-in contract; disabled unless capability is advertised**.

Recording is intentionally independent from SFU forwarding. `ucr.conference.recording` must be explicitly advertised before `RecordingService` is available. A deployment that does not advertise the capability records nothing.

## Preconditions

Every recording has an explicit `RecordingPolicy` with finite retention. Media is encrypted at rest. Participant notification is explicit. When policy or applicable deployment rules require consent, recording cannot enter ACTIVE until the required current Conference participants have granted consent. DENIED or REVOKED consent blocks or terminates recording according to policy; the implementation must never reinterpret silence as consent.

The Recording owner stores recording lifecycle and consent evidence only. Group/Call membership stays canonical elsewhere. SFU must not silently archive ciphertext, and diagnostics/telemetry must not contain recorded media.

Recording lifecycle mutations are optimistic-revision operations. Consent is participant-authenticated: `SetRecordingConsent` must verify the device-bound realtime bearer token and require its exact scope, Call and participant claims to match the Recording session and consent subject. Integration or Service Account authority may request/manage the recording lifecycle but is never evidence of an individual participant's consent.

An explicit `DENIED` or `REVOKED` decision always blocks starting the recording and immediately stops an ACTIVE lifecycle, even when the policy does not require every participant to affirmatively grant consent. Pending consent may be tolerated only when `require_all_participant_consent=false`; silence is never converted into a granted decision.

## Retention and deletion

`expires_at_unix_ms` is derived from the accepted retention policy and is durable. Expiry stops further recording and schedules deletion of controlled storage/key material. Delete acknowledgement means the controlled recording owner accepted/performed its defined deletion transition; it is not a claim that an already exported copy on an external or compromised system was physically erased.

Retention extension is not implicit. A future extension must be an explicit authorized lifecycle operation with audit evidence.

## Output/provider boundary

When an integration has `max_recording_minutes` configured, a concrete recording provider must reserve the accepted recording duration through the canonical Service resource-quota boundary before treating that duration as provider work. The quota counter is durable and integration-scoped; billing/calendar renewal semantics remain outside UCR and use an explicit authorized reset.

Concrete encoded-media capture, compositor/mixer behavior and object storage are provider boundaries behind the Recording lifecycle. They must not receive MLS keys or unrelated Conference state beyond what is required for the explicitly authorized recording path. A Production recording provider needs storage encryption, access authorization, integrity evidence, retention enforcement, failure recovery and export/delete conformance tests.

The durable lifecycle/store can be implemented and tested while `ucr.conference.recording` remains unadvertised. Capability discovery must continue to report recording unavailable until a concrete encrypted media provider is wired, participant-churn policy is enforced at the realtime boundary, and provider deletion/retention conformance is proven.

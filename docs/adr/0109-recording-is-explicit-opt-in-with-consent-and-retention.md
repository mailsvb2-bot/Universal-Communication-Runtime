# ADR 0109: Recording is explicit opt-in with consent and retention

Status: Accepted

## Context

Conference/SFU deliberately did not record media. Product webinar use may require recording, but hidden recording would violate privacy, lifecycle and minimum-disclosure requirements.

## Decision

Recording is a separate capability `ucr.conference.recording` and separate `RecordingService`. A deployment that does not advertise it records nothing.

Every recording has explicit policy, participant notification behavior, finite retention and encrypted-at-rest storage. Where policy requires consent, ACTIVE state is impossible until required current participants have granted consent. Denial/revocation fails closed according to policy; silence is never treated as consent.

SFU forwarding never archives media implicitly. A configured recorder observes only source-authenticated encrypted frames after canonical Conference/SFU validation. Provider capture is allowed only for an ACTIVE Recording that has not reached its expiry deadline and whose exact durable provider Start operation is already Applied. The realtime path remains recorder-independent when no capturable Recording exists. When capture is required, a pending/missing/failed Start, missing/stale/taken-over worker lease or unavailable provider fails closed before live fan-out rather than silently producing a partial recording. Recording lifecycle/consent evidence is durable and auditable, but Call/Group membership remains owned by canonical Call/Group state. Expiry/delete semantics apply only to controlled recording storage/key material and do not claim remote physical erasure of already exported copies.

## Consequences

Recording can be enabled for webinar products without weakening the default private realtime path or turning SFU into a hidden archive.

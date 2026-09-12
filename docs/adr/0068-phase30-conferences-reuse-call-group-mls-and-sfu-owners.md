## Context

The Canon places Conferences after SFU and defines the 1.1 Conference release around group audio, group video and SFU. It also defines `CallSession` as the transport-independent domain entity and requires idempotent participant update, media renegotiation and termination signalling. Creating a durable `ConferenceSession`/roster beside `CallSession` would therefore create a second realtime authority.

The Canon uses a 100-person video conference as the example where central SFU infrastructure is reasonable. The former canonical Call ceiling of 64 could not represent that scenario. Phase 30 also needs to avoid an O(N²) all-to-all media assumption if the participant ceiling is raised substantially.

## Decision

Phase 30 introduces a Prepared `ucr-conference` coordinator and public `ConferenceStart`/`ConferenceSnapshot` projection contract. Conference start derives one ordinary group `CallSession` from the existing Group and persists it only through `CallStore`. All invitees must be current active Group members. Signalling remains `CallSignal`; reads are derived from current Call + Group MLS state; encrypted forwarding delegates to Phase-29 `SfuRuntime`.

The common Call/Audio/Video/SFU participant ceiling becomes **1024**. Reference evidence drives a 1000-person Conference to 1000 accepted participants and rejects participant 1025. This remains a bounded protocol/reference ceiling rather than a Production throughput claim.

Conference media fan-out is selective. Each accepted recipient may own at most 32 ephemeral source/media subscriptions. The coordinator converts current subscriptions into a selected recipient set; `SfuRuntime::forward_selected` then revalidates canonical Call, Group membership and receive permission before forwarding ciphertext. Subscription state is routing preference only, bounded in memory, non-durable, restart-reconstructible and pruned on leave/removal/termination.

Conference permissions reuse the existing independent Call start/signal/observe permissions plus `ucr.conference.subscribe` for recipient-owned routing preferences. Internal coordination does not require observe permission merely to start, signal or forward.

## Consequences

Restart/idempotency and participant tombstones are inherited from the existing Memory/SQLite Call owner, so Phase 30 needs no schema v27 and no Conference migration. Group removal continues to reconcile linked Calls through the existing Group owner. MLS/member changes and source-Device revocation continue to invalidate media through Phase 29.

No new durable infrastructure trust boundary is introduced: the existing SFU remains the Conference media infrastructure boundary and still receives ciphertext/routing metadata only. Ephemeral subscription state is not membership, authorization, Delivery evidence or history.

The 1024 ceiling makes 500/1000-person Conferences representable, but Production operation at that scale remains contingent on load/SLA evidence and may require sharded/federated SFU deployment.

Recording is deliberately excluded because the Canon requires an explicit capability/policy/notification/consent/storage/retention/encryption model. Data channels, whiteboard/reactions, mixing/compositing/transcoding and production networking are also not silently folded into Conference coordination.

## Rejected alternatives

1. Persist a separate `ConferenceSession` and participant roster — rejected as a second Call/Group brain.
2. Keep the 64/128-participant Call ceiling and special-case larger Conferences — rejected because media/SFU/call bounds would disagree and larger bounded Conferences would remain artificially impossible.
3. Raise the ceiling to 1024 while broadcasting every stream to every participant — rejected because that encodes an avoidable O(N²) media-distribution assumption.
4. Make subscriptions durable Conference state — rejected because they are ephemeral routing preference; Call/Group remain the durable authorities.
5. Trust subscription selection as authorization — rejected; SFU must revalidate Call membership, Group membership and receive permission for every selected target.
6. Copy Group membership wholesale into a Conference roster — rejected because conference participation is a selected subset and Group remains the membership owner.
7. Make `call.observe` an implicit prerequisite for start/signal/forward — rejected because granular permissions must remain independent.
8. Add recording as a convenience Conference feature — rejected until its separate Canon consent/storage/retention contract is implemented.

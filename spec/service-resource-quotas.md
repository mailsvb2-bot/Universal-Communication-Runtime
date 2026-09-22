# Service resource quotas

Status: **concurrent participant, conference, and publisher quotas implemented; remaining resource dimensions are not yet implemented**.

This contract is deliberately separate from request-rate limiting. Request admission continues to use
`ServiceQuotaPolicy` / `ServiceRateLimitPolicy`; live communication resources use
`ServiceResourceQuotaPolicy`.

## Identity and scope

A resource policy is keyed by one exact `ScopedPrincipal` whose principal kind is
`ServiceAccount`. The Universal Conference API already requires the authenticated service
principal ID to equal the request `integration_id`, so the policy is simultaneously scoped to the
tenant/namespace and to the integration without creating a second integration identity owner.

## Concurrent participants

`max_concurrent_participants` limits active Universal Conference participant projections across
**all conferences owned by the same integration in the same exact tenant scope**.

Semantics:

- inactive historical participant projections do not consume quota;
- reactivation consumes quota again;
- different integrations do not consume one another's quota;
- absence of a resource policy means no integration-specific participant ceiling is configured;
- the existing per-conference hard safety ceiling of 1024 active participants remains independent
  and continues to apply;
- Memory enforcement happens under the canonical store mutex;
- SQLite enforcement happens inside the same `BEGIN IMMEDIATE` transaction that persists or
  reactivates the participant, so parallel admissions cannot use a caller-side read-before-write
  race to exceed the configured limit;
- SQLite schema v38 introduced durable participant policy storage; schema v39 extends the same policy with conference concurrency; schema v40 adds publisher concurrency while preserving existing rows across both migrations.

## Concurrent conferences

`max_concurrent_conferences` is optional and limits conferences that currently consume realtime capacity for the same integration and exact tenant scope.

Semantics:

- `Scheduled` conferences do not consume quota, so integrations may create rooms well before an event starts;
- `Waiting`, `Live`, and `Ending` conferences each consume one slot;
- `Ended` releases the slot;
- moving `Waiting` to `Live` or `Live` to `Ending` does not consume another slot;
- different integrations do not consume one another's conference quota;
- absence of `max_concurrent_conferences` means no integration-specific conference concurrency ceiling is configured;
- Memory enforcement is atomic under the canonical store mutex;
- SQLite enforcement runs inside the same `BEGIN IMMEDIATE` transaction as conference creation/lifecycle transition, preventing parallel admissions from exceeding the configured ceiling.

## Concurrent publishers

`max_concurrent_publishers` is optional and limits realtime sessions that have begun publishing encrypted media for the same integration and exact tenant scope.

Semantics:

- merely having audio, camera, or screen-share publish permission does not consume a publisher slot;
- the first policy-authorized encrypted media publish attempt claims one slot for that exact realtime session before SFU forwarding, so simultaneous first frames cannot race past the ceiling;
- audio, camera-video, and screen-share sources from one realtime session share one publisher slot;
- direct gRPC publication and WebRTC E2EE DataChannel publication use the same `forward_authenticated_e2ee_media` boundary and therefore the same publisher quota;
- a slot is released when the realtime session leaves, expires, or performs a full `join` reconnect; a resumed downlink alone does not create a second publisher;
- different integrations do not consume one another's publisher quota;
- absence of `max_concurrent_publishers` means no integration-specific publisher concurrency ceiling is configured;
- publisher admission is atomic under the bounded `RealtimeSessionRegistry` mutex, while SQLite schema v40 durably persists only the policy, not ephemeral realtime publisher presence.

The same `SERVICE_QUOTA_READ_PERMISSION` and `SERVICE_QUOTA_WRITE_PERMISSION` authorization
boundary used for request quotas also governs resource quota administration.

## Still required

This slice does **not** claim the complete resource-quota roadmap. The following dimensions remain
to be added through the same canonical resource policy path:

- aggregate bandwidth;
- recording minutes.

API RPS remains owned by the already separate class-aware request-rate limiting contract.

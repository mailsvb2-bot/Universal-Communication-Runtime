# Service Principal Request Rate Limits

Status: **durable independent request classes implemented**.

This specification covers external Service Account request-rate admission only. It extends the existing
canonical `ServiceQuotaStore`; it does not introduce a second limiter, authorization engine, audit
owner, conference owner, signaling owner, or media scheduler.

## Independent request classes

Every admitted Service Account request is charged to exactly one canonical rate class derived from
the permission being authorized:

- `management` — the default for management/read/write APIs and all permissions not explicitly
  assigned to a higher-volume class;
- `join_issuance` — `ucr.conference.join.issue`;
- `signaling` — `ucr.call.signal`;
- `media_transport` — audio/video/screen-share send/receive and canonical transport/SFU relay use.

The classes are intentionally independent. Exhausting join issuance, signaling, or media transport
must not consume management capacity, and a class-specific policy update must not reset another
class's current window.

## Policy compatibility

`ServiceQuotaPolicy` remains the backward-compatible base policy. Setting it installs the same
fixed-window values for all four classes. A `ServiceRateLimitPolicy` may then override one class
without creating another quota engine.

Missing class policy, clock rollback, corrupt state, or store failure fails closed. Authentication,
permission authorization, and append-only Service Principal audit semantics remain unchanged.

## Durability and migration

Memory uses one independent usage record per Service Account and rate class.

SQLite schema v37 adds `service_rate_limit_policies` and `service_rate_limit_usage`. Migration
from v36 copies every existing base policy into all four classes and conservatively copies the
current legacy usage into every class. Upgrade therefore never resets a consumed window or grants a
temporary burst merely because the runtime was restarted or upgraded.

## Non-claims: resource quotas

Request-rate separation does **not** complete UCR resource quotas. Concurrent participant,
conference, publisher, and aggregate-bandwidth ceilings are owned by the separate `ServiceResourceQuotaPolicy` contract
documented in `service-resource-quotas.md`. Recording minutes and other deployment capacity
budgets remain separate resource-governance work. Those limits must be enforced
by their canonical runtime/storage owners rather than approximated through API request counts.

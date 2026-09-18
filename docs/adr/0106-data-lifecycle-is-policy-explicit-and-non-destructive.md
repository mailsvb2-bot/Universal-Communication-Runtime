# ADR 0106: Data lifecycle is policy-explicit and non-destructive

Status: Accepted

## Context

The Canon requires retention, TTL, expiry, deletion and export to be defined for messages, attachments, identities, groups, devices, events and audit data. It separately forbids silent loss of undelivered messages/attachments and destructive migration.

## Decision

Lifecycle is explicit policy, not background best-effort deletion.

For every durable resource class the owning layer must distinguish retention, optional TTL/expiry, deletion semantics and export eligibility. No TTL exists by implication merely because data is old.

Baseline rules:

- undelivered user messages and required delivery evidence are protected from cache eviction until a terminal lifecycle outcome (delivered, explicit cancel/delete, explicit expiry or policy denial) is durable;
- attachment content/metadata may have separate retention, but silent deletion of content still required by a live durable message is forbidden;
- Identity/Group/Device canonical records are not age-evicted; lifecycle changes are explicit state transitions;
- Event retention may compact only while durable consumer/reconciliation guarantees remain satisfied;
- security/audit records follow explicit retention and are never rewritten to fabricate success;
- export is authorization/scoped and exposes only data the requester is allowed to read;
- deletion uses ADR 0099 and never equates local cleanup with guaranteed remote physical erasure.

Cache/log cleanup must identify protected versus evictable data. Storage pressure produces an explicit bounded failure/degraded state rather than silently discarding protected communication state.

## Consequences

Retention can evolve per deployment without turning cache policy into a source of truth. Restart/offline guarantees remain compatible with cleanup and export requirements.

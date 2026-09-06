# ADR-0047: Integration Communication Intent API reuses the canonical Intent owner and generic acknowledgement

- Status: Accepted
- Date: 2026-09-06
- Supersedes: none

## Problem

The Canon makes Communication Intent a first-class primitive: an external consumer expresses the target,
payload, privacy/cost/region/transport constraints and correlation context while UCR retains technical
routing authority. Phase 13 already exposes Identity, Conversation, Message and generic Command
operations, but an external Service Principal still cannot create or read the existing durable
`CommunicationIntent` through the public Integration API.

Adding an Integration-specific intent table/model would create a second routing/communication brain.
Treating successful intent persistence as route selection, delivery, provider acceptance or an Event
would also collapse architectural layers that the Canon keeps separate.

## Decision

`IntegrationService` adds two additive Experimental Phase-13 methods:

- `CreateCommunicationIntent`, carrying the canonical `CommunicationIntent` and returning the existing
  generic `AcknowledgementEnvelope` bound to `IntentId`;
- `GetCommunicationIntent`, keyed by exact `TenantScope + IntentId` and returning the canonical durable
  Intent.

Both methods reuse the single existing `CommunicationIntentStore` through `AuthorizedDurableRuntime`.
No Integration-specific Intent model, route selection state, provider mapping, cache, database table or
second policy owner is introduced.

`CreateCommunicationIntent` requires `ucr.intent.write`; `GetCommunicationIntent` requires
`ucr.intent.read`. Both use the normal Service Principal order:

`credential authentication -> quota consumption/audit -> permission evaluation -> canonical durable operation`.

Admission audit uses `ucr.intent.create + IntentId` or `ucr.intent.read + IntentId`. Intent payload,
privacy profile, region, cost, transport constraints, extensions and provider data are not copied into
generic audit metadata.

The generic ACK confirms durable persistence/deduplication only. It does not mean that UCR selected a
route, queued a transport, contacted a provider, created Delivery state, emitted an Event or completed
a real-world communication effect.

The canonical Intent owner remains authoritative for validation and canonicalization. Transport
capability/extension ordering that is explicitly non-semantic remains duplicate-equivalent; changed
semantics under the same scoped `IntentId` conflict. `GetCommunicationIntent` returns canonical stored
state. Authorized absence maps to non-retryable `NOT_FOUND`; authentication/permission failures occur
before existence is disclosed.

## Storage and compatibility

No storage schema changes are required. The existing Memory/SQLite `CommunicationIntentStore` remains
the only durable owner and SQLite stays at schema v19. The protobuf changes are additive and remain
Experimental; existing Integration methods and fields are unchanged.

## Security and privacy impact

The authenticated Service Principal remains outside the canonical Intent payload and is represented by
the existing admission/audit boundary rather than being smuggled into routing constraints. Generic audit
contains only the canonical `IntentId` operation reference. Sensitive payload/policy/constraint values
remain subject to the existing redaction and metadata-visibility rules.

## Testing strategy

Memory evidence covers authenticated create, canonical duplicate retry, semantic conflict,
permission/bad-secret/invalid-constraint failures without ghost state, authorized reads and
non-disclosing `NOT_FOUND`. SQLite evidence creates through the public ingress, reopens the database,
reads the canonical Intent, repeats an ordering-equivalent duplicate, rejects a changed payload and
verifies restart-safe exact-operation audit records. Architecture gates prohibit alternate storage,
provider-routing and Phase-14 Event API leakage.

## Alternatives rejected

A new Integration Intent model/table was rejected as a second brain. Direct database access was rejected
because it bypasses Service Principal authentication, quota/audit, permissions and canonical
validation. Returning a routing/delivery receipt was rejected because persistence is not execution.
Automatically selecting a provider in this API was rejected because external consumers express
constraints while routing remains a later UCR responsibility.

## Non-claims

This ADR does not implement route selection, policy execution, provider adapters, Delivery
creation/progression, Event subscriptions, attachment/file transfer, calls/media, production gRPC/HTTP
servers, SDK generation or network transport. Phase 14 still owns Event API semantics; later phases own
transport and communication execution.

# ADR 0072: Phase 34 MAX is a thin Bot API bridge over canonical UCR

- Status: Accepted
- Date: 2026-09-13

## Context

Phase 31 established the provider-agnostic Bridge boundary; Telegram and VK proved two concrete adapters. MAX needs equivalent text interoperability without creating a provider-specific communication brain or weakening Core policy, idempotency, scope and Delivery semantics.

## Decision

Add `ucr-bridge-max` as a Prepared Text-only provider. It uses the fixed MAX Bot API HTTPS origin, `Authorization` header credentials, explicit `user:<id>`/`chat:<id>` targets, `POST /messages` for outbound text, and bounded marker-based `GET /updates` only as development/test reference intake. The adapter keeps credentials local/redacted, disables redirects, bounds response material, maps only `message_created` text, and receives UCR scope/integration from Core.

Provider acknowledgement is not canonical Delivery/Read. Unknown or post-send-ambiguous outcomes remain `AcceptanceUnknown`; only proven non-acceptance participates in canonical retry. No MAX-specific Message, Delivery, Identity, Conversation, policy or durable retry owner is introduced.

## Consequences

MAX can participate in the same canonical Bridge runtime and policy/dedup ledger as other providers. Production Webhook ownership, webhook-secret verification, HA/restart-gap-free ingest, media and richer MAX operations remain explicitly outside Phase 34. Overlay Conversation normalization remains Phase 35.

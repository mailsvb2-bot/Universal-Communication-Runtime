# ADR 0071: Phase 33 VK is a thin API bridge over canonical UCR

- Status: Accepted
- Date: 2026-09-13

## Context

Phase 31 established a provider-neutral Bridge SDK and Phase 32 proved it with Telegram. The Canon explicitly forbids a VK-specific Message/Delivery/Identity brain. VK also has provider-specific idempotency (`messages.send.random_id`) and a dynamic Bots Long Poll endpoint, both of which must remain subordinate to canonical UCR policy and identity boundaries.

## Decision

Implement `ucr-bridge-vk` as a concrete `BridgeProvider`. Advertise only `Text`. Keep Message binding, authorization, policy, registration, durable action state and provider-acceptance semantics in the existing Core/Bridge runtime.

Use VK API 5.199 `messages.send` for admitted outbound text. Derive a stable non-zero provider `random_id` from a domain-separated SHA-256 binding of canonical tenant/namespace, integration, `BridgeActionId` and VK peer context, then reduce it to VK’s positive 31-bit provider field; never generate a fresh idempotency key for an ambiguous retry. VK message IDs remain provider acceptance metadata, not Delivery/Read evidence.

Use `groups.getLongPollServer` + Bots Long Poll for inbound text. UCR owns TenantScope/IntegrationId. The external cursor contains only decimal `ts`; the Long Poll key/server remain provider-local. Dynamic Long Poll URLs must be HTTPS and VK-host scoped before any request is made.

Credentials stay provider configuration, are redacted from `Debug`, and are not Bridge durable state. Fixed VK API and dynamic Long Poll HTTP responses are bounded, redirects are disabled, and form parameters are percent-encoded.

## Consequences

VK text now participates in the same UCR policy/idempotency model as Telegram without a second communication brain. A compromised provider boundary cannot select UCR scope. Dynamic Long Poll introduces provider-session lifecycle that is explicitly Prepared rather than falsely advertised as restart-gap-free Production intake.

## Rejected alternatives

- VK-specific Message/Conversation/Delivery persistence: rejected by the no-second-brain Canon.
- Fresh random `random_id` on every retry: rejected because it defeats provider duplicate suppression.
- Treat VK API success as Delivered/Read: rejected because provider acceptance is not recipient evidence.
- Follow arbitrary Long Poll URLs returned by provider data: rejected because it creates an SSRF/trust-boundary violation.
- Put Long Poll key into canonical identity/state: rejected; it is provider session credential material.
- Advertise all VK API features immediately: rejected; each UCR capability requires provider-neutral semantics and executable evidence.

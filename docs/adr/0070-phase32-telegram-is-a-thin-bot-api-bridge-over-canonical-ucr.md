# ADR 0070: Phase 32 Telegram is a thin Bot API bridge over canonical UCR

- Status: Accepted
- Date: 2026-09-13

## Context

Phase 31 created the provider-neutral Bridge SDK and explicitly forbids a provider-specific second Message/Delivery/Identity brain. Phase 32 must add a real Telegram integration without undoing that boundary. Telegram Bot API also places the bot token in the request path, which makes ordinary URL logging an authentication-secret risk.

## Decision

Implement `ucr-bridge-telegram` as a concrete `BridgeProvider` over the existing Bridge runtime. Phase 32 advertises only `Text`; all canonical Message binding, policy, authorization, registration, crash/idempotency ledger and acceptance semantics remain in Core/Phase 31.

Use Bot API `sendMessage` for admitted outbound text and bounded `getUpdates` long polling for inbound text. Inbound UCR scope and Integration are provided by Core, never by Telegram payload. Unsupported/non-text updates advance the Telegram offset but do not invent canonical Messages.

Bot credentials are provider configuration, not Bridge durable state. Token formatting is bounded/redacted, the HTTP client is built without its logging feature, redirects are disabled, the origin is fixed to `api.telegram.org`, and response headers/body are bounded.

Classify 429/4xx as proven non-acceptance where applicable. Treat outbound network/TLS/timeout/5xx/malformed-success uncertainty as acceptance-unknown so Core cannot issue a blind duplicate.

## Consequences

Telegram text can now participate in the same canonical UCR Bridge policy and idempotency semantics as future providers. Provider acceptance remains distinct from Delivery/Read. Adding Telegram features later requires extending the provider-neutral Bridge contract and evidence rather than creating provider-local state owners.

## Rejected alternatives

- Build a Telegram-specific Message/Conversation/Delivery database: rejected by the no-second-brain Canon.
- Treat Bot API success as canonical Delivered/Read: rejected because provider acceptance is not recipient evidence.
- Retry every network/5xx failure: rejected because acceptance may be ambiguous and duplicate external messages.
- Keep a general HTTP client that can log the token-bearing URL path at TRACE: rejected because authentication secrets must not enter telemetry.
- Advertise Telegram capabilities merely because Bot API has endpoints for them: rejected; manifest capabilities require implemented provider-neutral semantics and executable evidence.

# Telegram Bridge — Phase 32

Status: **Prepared**. This is a concrete Telegram Bot API provider over the Phase-31 Bridge SDK. It is not a second communication model and it is not a Production claim.

## Canonical ownership

Telegram is an external bridged participant. Canonical `Message`, `Delivery`, `Identity`, `Conversation`, `Group`, authorization, policy, idempotency and durable Bridge action state remain owned by existing UCR layers. `ucr-bridge-telegram` owns only Telegram protocol adaptation. It introduces no Telegram Message store, Delivery store, Identity store or Conversation store.

The provider identity is `vendor.telegram.bot_api`. The configured canonical `IntegrationId` remains the UCR owner of the provider registration.

## Prepared capability surface

Phase 32 declares only `BridgeCapability::Text`. The provider manifest does **not** claim edit, delete, reaction, files, audio, video, group, presence, typing, calls, threads or reply. Those capabilities require later provider-neutral contracts and executable evidence before they may be advertised.

The provider declares only the data permissions required by this surface: `MessageContent`, `ExternalIdentityReferences` and `InboundEvents`.

## Outbound text

Outbound text is admitted by the existing `BridgeRuntime` first. A production Telegram action must therefore remain bound to an existing canonical Message, pass current authorization/registration/capability/data-permission checks, and respect `LocalOnly`, `PrivateNetworkOnly` and `NoExternalBridge` before the Telegram client can observe content or target identifiers.

The Telegram adapter accepts only plain UTF-8 text containing 1..=4096 Unicode scalar values, no attachments, and a numeric non-zero chat ID or a bounded `@username` target. It maps the admitted action to Bot API `sendMessage`. Telegram `message_id` is stored only as provider acceptance metadata; it is not canonical Delivered/Read evidence.

## Failure and retry semantics

Telegram/HTTP 429 is provider-proven non-acceptance (`RateLimited`). Other 4xx responses are provider rejection. Network/TLS/timeout failure or 5xx/otherwise ambiguous outbound status after request execution is `AcceptanceUnknown`; Core must not blindly retry the same action. A malformed successful response is likewise conservative unknown acceptance for outbound execution.

This preserves the Phase-31 action ledger. The Telegram adapter owns no independent retry queue or exactly-once claim.

## Inbound text

Inbound reference operation uses Bot API `getUpdates` with a bounded limit of 1..=100, long-poll timeout 25 seconds and `allowed_updates=["message"]`. The continuation cursor is the decimal next Telegram offset. Every observed update advances the cursor to at least `update_id + 1`, including unsupported/non-text updates, so the provider does not become stuck replaying an event it intentionally does not normalize.

Only text messages are projected into `BridgeInboundEvent(Text)`. `TenantScope` and `IntegrationId` are supplied by the already-authorized Core call and are never accepted from Telegram response data. Telegram supplies only external update/chat/actor identifiers, text and provider event time. Polling does not itself create canonical UCR Messages; Overlay Conversation normalization remains Phase 35.

## Credential and HTTPS boundary

A Bot API token is explicit provider credential material. UCR does not persist it in the Bridge ledger. `TelegramBotToken` validates a bounded `digits:secret` form, rejects whitespace/control/path/query injection bytes and redacts `Debug`. The production HTTP dependency is compiled without its logging feature.

The provider targets the fixed HTTPS origin `api.telegram.org`, disables redirects, bounds response headers to 32 KiB and reads at most 4 MiB + 1 byte before rejecting an oversized response. Provider/library error strings are not propagated as UCR errors. Plaintext messages, targets and bot tokens must not enter generic telemetry.

## Bot API reference

The Phase-32 adapter is implemented against Telegram Bot API 10.3 (2026-08-24 reference state). The implementation uses the documented `sendMessage` text ceiling and `getUpdates` offset/limit semantics. Provider API evolution must be revalidated before changing the declared capability surface.

## Security evidence

`compromised_telegram_boundary_cannot_bypass_core_policy_or_choose_ucr_scope` proves the concrete adapter cannot bypass `NoExternalBridge` and cannot choose UCR tenant/scope from provider-controlled inbound data. Reference tests additionally prove Phase-31 accepted-action replay does not invoke Telegram twice, ambiguous outbound failure does not become proven retryable failure, invalid cursor/target/capability fail before the provider client, and provider acceptance never promotes canonical Delivery.

## Nonclaims

Phase 32 does not claim webhook deployment, production worker lifecycle, HA polling ownership, provider credential UX/secure-store integration, Telegram user-account/MTProto support, media/files, edits, deletes, reactions, replies/threads, Telegram calls, provider-native Delivery/Read equivalence, Overlay Conversations, VK/MAX support, or Production maturity.

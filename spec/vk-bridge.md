# VK Bridge — Phase 33

Status: **Prepared**. This is a concrete VK API provider over the Phase-31 Bridge SDK. It is not a second communication model and it is not a Production claim.

## Canonical ownership

VK is an external bridged participant. Canonical `Message`, `Delivery`, `Identity`, `Conversation`, `Group`, authorization, policy, idempotency and durable Bridge action state remain owned by existing UCR layers. `ucr-bridge-vk` owns only VK protocol adaptation. It introduces no VK Message store, Delivery store, Identity store or Conversation store.

The provider identity is `vendor.vk.api`. The configured canonical `IntegrationId` remains the UCR owner of the provider registration.

## Prepared capability surface

Phase 33 declares only `BridgeCapability::Text`. The provider manifest does **not** claim edit, delete, reaction, files, audio, video, group, presence, typing, calls, threads or reply. Those capabilities require later provider-neutral contracts and executable evidence before they may be advertised.

The provider declares only `MessageContent`, `ExternalIdentityReferences` and `InboundEvents`.

## Outbound text and idempotency

Outbound text is admitted by the existing `BridgeRuntime` before VK can observe content or target identifiers. The action remains bound to an existing canonical Message and current Core policy, including `NoExternalBridge`.

The adapter maps plain UTF-8 text containing 1..=4096 Unicode scalar values, no attachments, and a non-zero numeric VK `peer_id` to VK API `messages.send` using VK API 5.199. VK `random_id` is derived deterministically from a domain-separated SHA-256 binding of canonical tenant/namespace, integration, Bridge action and peer context, then reduced to a non-zero positive 31-bit provider value. Retries of the same admitted action therefore retain the same provider idempotency key while independent UCR contexts are cryptographically separated before the unavoidable provider-width reduction.
The Phase-31 durable action ledger remains the canonical retry/acceptance owner. A successful VK response contributes only provider acceptance metadata (`external_message_id`); it is not canonical Delivered/Read evidence.

## Failure and retry semantics

VK API rate-limit/flood errors are mapped to proven non-acceptance. Only provider error classes that prove rejection before acceptance are mapped as retryable rejection; VK internal/unknown errors remain conservative `AcceptanceUnknown`. Network/TLS/timeout failures after request execution and malformed successful responses are also `AcceptanceUnknown`; Core must not blindly duplicate the provider side effect.

The VK adapter owns no independent retry queue and makes no exactly-once claim.

## Inbound text

Inbound reference operation uses `groups.getLongPollServer` and Bots Long Poll `a_check`. The provider-local session retains the Long Poll server/key. The UCR cursor contains a bounded provider `ts`; when one VK response contains more supported text events than the requested UCR page size, a bounded opaque `ts:offset` continuation replays that same provider position until the full burst has been emitted, then advances to VK's next `ts` without dropping events.

Only non-empty `message_new` text is projected into `BridgeInboundEvent(Text)`. Structurally valid attachment-only/sticker/photo events with empty text are intentionally skipped because Phase 33 advertises Text only, while the provider cursor is still allowed to advance. `TenantScope` and `IntegrationId` are supplied by the already-authorized Core call and are never accepted from VK response data. VK supplies only bounded external event/message/peer/actor identifiers, text and provider event time.

Polling does not itself create canonical UCR Messages. Overlay Conversation normalization remains Phase 35. Phase 33 does not claim restart-gap-free or HA Long Poll ownership; provider session loss is handled conservatively rather than inventing canonical continuity.

## Credential, HTTPS and SSRF boundary

A VK access token and Long Poll key are provider credential/session material. They are not persisted in the Bridge durable ledger and are redacted from `Debug` surfaces.

Fixed API requests target `https://api.vk.com/method`. Redirects are disabled, headers are bounded, and response bodies are read only to the declared 4 MiB ceiling plus one rejection byte. Form encoding percent-escapes provider parameters so message text cannot inject `access_token`, `v`, `peer_id` or `random_id` fields.
The dynamic Long Poll server is accepted only after validating HTTPS, bounded authority/path material, no userinfo/fragment/control characters, and a host equal to `vk.com` or ending in `.vk.com`. This prevents provider response data from becoming an arbitrary SSRF target.

## VK API reference

The Phase-33 adapter is implemented against VK API 5.199. Provider API evolution must be revalidated before the declared capability, error, Long Poll or idempotency contracts are changed.

## Security evidence

`compromised_vk_boundary_cannot_bypass_core_policy_or_choose_ucr_scope` proves the concrete adapter cannot bypass `NoExternalBridge` and provider-controlled inbound data cannot select UCR tenant/scope/integration. Reference tests prove stable context-bound provider `random_id`, Phase-31 action-ledger replay without a second VK send, conservative ambiguous-acceptance handling, opaque cursor mapping, provider-secret redaction, form-parameter isolation and no provider acceptance → Delivery promotion.

`vk_bridge_boundary` feeds raw arbitrary bytes through the actual VK API envelope decoder, Long Poll JSON decoder, dynamic server/session validation, `message_new` wire mapping and provider cursor parser, in addition to token/peer/action projection, under the same bounded CI smoke budget as the existing untrusted boundaries.

## Nonclaims

Phase 33 does not claim provider credential UX/secure-store integration, webhook deployment, production worker lifecycle, restart-gap-free or HA Long Poll ownership, VK media/files, edits, deletes, reactions, replies/threads, calls, provider-native Delivery/Read equivalence, Overlay Conversations, MAX support, or Production maturity.

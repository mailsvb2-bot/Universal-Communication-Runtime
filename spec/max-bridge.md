# Phase 34 — MAX Bridge

## Status

Prepared reference adapter over the Phase-31 Bridge boundary. It is not a second Message, Delivery, Identity, Conversation, retry or authorization owner.

## Provider surface

The adapter targets MAX Bot API schema `0.0.33` at the fixed HTTPS origin `https://platform-api2.max.ru`; requests carry `v=0.0.33` so provider model drift is not silently accepted. Phase 34 declares only `BridgeCapability::Text`. Outbound text uses `POST /messages`; the provider token is supplied only through the `Authorization` header and is never placed in a URL, canonical object, Bridge ledger or ordinary `Debug` output. Redirects are disabled and response headers/body are bounded.

The opaque external target is intentionally explicit: `user:<positive-id>` maps to `user_id`, while `chat:<non-zero-id>` maps to `chat_id`. A bare number is rejected. UCR therefore does not infer whether a provider identifier denotes a user, chat or channel.

Outbound payloads are valid UTF-8 plain text from 1 through 4000 Unicode scalar values and must have no canonical attachments. Provider acceptance may return only the MAX message `mid`; that provider acknowledgement is not canonical Delivery or Read evidence. Only documented pre-acceptance HTTP rejection statuses and explicit rate limiting are treated as proven non-acceptance and may be retried under the Phase-31 action ledger rules; unknown 4xx, transport/server and malformed post-send outcomes remain ambiguous; ambiguous transport/server/malformed post-send outcomes become `AcceptanceUnknown` and must not cause blind duplicate sends.

## Inbound development/test polling

Phase 34 includes bounded `GET /updates` polling with an opaque positive `marker`, `limit`, timeout and `types=message_created`. This path exists for executable Prepared reference/testing evidence. MAX documentation recommends Webhook subscriptions for Production; Phase 34 does not claim Production Webhook ownership, a production polling worker, webhook receiver/secret verification, HA ownership or restart-gap-free ingest.

Only valid `message_created` text is normalized. Attachment-only or otherwise empty-text messages are unsupported by the Phase-34 Text-only manifest and are skipped while the provider marker is still allowed to advance. If an empty provider page returns a null marker while UCR already has a marker, the adapter preserves the prior marker instead of clearing the cursor and risking replay or a jump to the provider default. Provider message IDs become external event IDs, chat IDs become external conversation IDs, sender user IDs become external actor IDs, and provider millisecond timestamps remain millisecond timestamps. TenantScope and IntegrationId are supplied by Core to `BridgeRuntime::poll_events`; provider data cannot choose either.

## Ownership and privacy invariants

It introduces no MAX Message store, Delivery store, Identity store or Conversation store. `NoExternalBridge`, canonical Message binding, registration state, action deduplication and acceptance state remain Phase-31/Core-owned. MAX bot tokens remain provider-local configuration and are not persisted by the Bridge ledger. Provider plaintext visibility is restricted to the admitted target/text or one bounded inbound page.

Overlay Conversation normalization remains Phase 35. Media/files, edit/delete/reaction/callback surfaces, Webhook receiver/secret verification, credential UX/secure-store integration and Production maturity remain later work.

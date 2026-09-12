# Phase 31 — Bridge SDK

Phase 31 introduces the provider-agnostic Bridge extension boundary used by later Telegram/VK/MAX and future provider phases. It does **not** introduce a Telegram/VK/MAX Message core, a second Delivery engine, a provider-owned identity model, or a provider-selected routing API.

## Canonical ownership

`IntegrationId` remains the canonical identifier for one external integration. Canonical `Message`, `Conversation`, `Identity`, `Group`, `Call`, `CommunicationIntent`, Delivery and routing owners remain unchanged. A Bridge registration stores only provider manifest/security lifecycle metadata; a Bridge action ledger stores only action fingerprint/state/provider-result metadata and never provider plaintext.

The Bridge host is allowed to expose provider-visible content only for the exact admitted action. If an action references a canonical Message, Core reloads that Message and requires exact payload/attachment equality before the provider is called. `DeliveryPolicy::LocalOnly`, `DeliveryPolicy::PrivateNetworkOnly`, and `DeliveryPolicy::NoExternalBridge` all fail closed before any external provider side effect, even when no alternative route exists. Content without a canonical Message binding is not accepted by the Prepared outbound host.

## Manifest and capability model

Every provider declares an SDK/protocol compatibility range, explicit capabilities and explicit data permissions. Capabilities are: text, edit, delete, reaction, files, audio, video, group, presence, typing, calls, threads and reply. Capabilities are never inferred from provider name.

The durable registration is an admission ceiling, while the provider's live manifest is checked again on every operation. A capability that disappears at runtime therefore immediately fails closed. Registration lifecycle is `Active`, `Disabled`, `Revoked`; revoke is terminal. Disabled/revoked integrations cannot begin new provider actions.

Provider degradation is explicit `BridgeProviderAcceptance` metadata. A fallback must be declared by both the durable registration manifest and the current provider manifest, so live capability expansion cannot escape the registered admission ceiling, and it cannot pretend the requested capability succeeded unchanged. Provider acceptance/degradation is **not** canonical Delivery/Delivered/Read evidence.

## Crash, retry and backpressure semantics

Before an external side effect, the metadata-only action ledger moves `Prepared` or retryable `FailedNotAccepted` to `InFlight`. A provider success moves it to `Accepted`; a failure that proves non-acceptance moves it to `FailedNotAccepted`; ambiguous acceptance moves it to terminal `AcceptanceUnknown`.

An `Accepted` retry returns the persisted provider result without another provider call. `AcceptanceUnknown` is never automatically retried. A crash-left `InFlight` record is not replayed; an explicit recovery operation converts it to `AcceptanceUnknown` without calling the provider. This provides effectively-once user behavior where evidence permits it without claiming exactly-once provider execution.

`bridge → provider` backpressure is an explicit provider failure class. Retry is allowed only when the provider proves the action was not accepted.

## Inbound boundary

The SDK also exposes bounded provider event pages. Polling requires `ucr.bridge.events.read` and an active registration whose durable and live manifests both permit inbound events. Cursors are opaque and bounded; pages are capped at 256 events. Every returned event must preserve the requested scope/integration and declare a capability allowed by both manifests.

Provider events do not automatically become canonical Messages or Identities in Phase 31. Concrete provider adapters in later phases normalize them through existing UCR owners; Overlay Conversation composition remains a later phase.

## Permissions and privacy

Bridge registration read/manage, outbound execute and inbound event read use independent permissions: `ucr.bridge.registration.read`, `ucr.bridge.registration.manage`, `ucr.bridge.execute`, and `ucr.bridge.events.read`.

Bridge receives only configured provider/integration context and the content/reference material needed by the admitted action. Private/recovery keys, hidden permission grants, unrelated conversations/tenants and the general UCR database are outside the boundary. Ordinary Debug output redacts provider payload, external target/event IDs and event payload.

## Explicit non-goals

Phase 31 does not implement Telegram, VK, MAX, WhatsApp, email, SMS or web-chat providers. It does not implement Overlay Conversations, provider credential UI/storage, provider webhooks/listeners, automatic route selection, attachment transfer, edit/delete/reaction canonical workflows, production circuit breakers, production worker deployment or Production maturity. Those features must reuse this boundary rather than create provider-specific communication brains.

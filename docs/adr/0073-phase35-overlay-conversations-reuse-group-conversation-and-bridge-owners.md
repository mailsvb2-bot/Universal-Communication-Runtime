# ADR-0073: Phase 35 Overlay Conversations reuse Group, Conversation and Bridge owners

Status: Accepted

## Context

The Canon defines Overlay as cross-network logical groups: one logical Conversation may span Native App, Telegram, VK, MAX and Web while external platforms remain endpoints. UCR already has provider-independent Conversation, canonical Group aggregates, `GroupBridgeMapping`, Bridge registrations/capabilities/data permissions, and provider-specific Phase-32/33/34 adapters.

Creating a separate Overlay conversation table, provider-group graph, identity matcher, retry queue or message fan-out state machine would duplicate canonical owners and violate the prohibition on a second communication brain.

## Decision

Phase 35 keeps `GroupRecord.bridge_mappings` as the single durable external-group binding owner. Mapping lifecycle becomes explicit `GroupChangeKind::AddBridgeMapping` / `RemoveBridgeMapping`, preserving EventId deduplication, optimistic Group revision, authorization, offline Group replication and deterministic fingerprints.

Adding a mapping requires the exact scoped Bridge registration to be Active even when the generic `GroupStore` API is called directly. Removing stale mappings remains possible after registration disable/revoke/removal.

SQLite v28 adds a uniqueness index over the existing mapping table plus a restart-safe additive sidecar for offline replication of mapping changes. It does not add an Overlay aggregate table. Memory provides the same uniqueness and reverse-resolution behavior.

`ucr-overlay` is a stateless facade. Inbound resolution returns the already-existing canonical Group/Conversation and never creates Identity or Message state. Outbound projection reports endpoint readiness/degradation but invokes no provider. Actual external side effects remain in `BridgeRuntime`.

## Rejected alternatives

- A new `overlay_conversations` durable table owning copied Conversation state.
- Treating provider group/chat IDs as canonical Identity or Conversation IDs.
- Matching users or groups by names, phone numbers, display names or provider-ID similarity.
- Letting one external endpoint alias multiple canonical Groups.
- Allowing mapping creation before Bridge registration and “fixing it later”.
- Hiding inactive/unsupported endpoints by silently dropping them from projection.
- Sending provider messages directly from Overlay instead of Phase-31 BridgeRuntime.

## Consequences

Overlay remains restart-safe and cross-network while canonical authority stays singular. Existing Phase-18 Groups with bridge metadata remain valid. Providers can participate only through capabilities/data permissions they truly advertise; Phase 35 does not fabricate Group/media/call support for text-only adapters.

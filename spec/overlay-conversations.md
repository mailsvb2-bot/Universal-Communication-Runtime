# Phase 35 — Overlay Conversations

Status: **Prepared/reference**.

Phase 35 implements the Canon release-1.3 cross-network logical-group model. One canonical UCR Group keeps one provider-independent Conversation while explicit external platform group/chat endpoints are attached through the existing `GroupBridgeMapping` and Phase-31 Bridge registration owners.

## Single-owner rule

Overlay is a projection and resolution layer, not a second communication brain. It introduces no Overlay Message store, Conversation store, Identity store, Delivery store, provider retry queue, provider polling loop, or routing authority. Canonical Group revision/history/policy remains owned by Group. Provider lifecycle/capabilities/data permissions remain owned by Bridge registrations. Provider side effects remain owned by `BridgeRuntime` and concrete bridge adapters.

A provider account/chat/group identifier is never canonical Identity evidence. Display name, provider actor ID, provider group ID, or similarity heuristics MUST NOT merge people, Groups, or Conversations.

## Endpoint binding lifecycle

An Overlay endpoint is the exact tuple `(TenantScope, IntegrationId, external_group_id)` stored in the existing canonical Group aggregate. Adding/removing one mapping is an ordinary idempotent `GroupChange` with EventId, optimistic Group revision and deterministic fingerprint.

Adding a mapping requires an existing Active Bridge registration for the exact scope + IntegrationId. This invariant is repeated by durable Group stores so callers cannot bypass the Overlay facade. Removing a mapping remains allowed after a registration becomes Disabled, Revoked, or absent, so stale endpoint state can be cleaned up safely.

Within one scope, an exact external endpoint may resolve to at most one canonical Group. SQLite v28 enforces this with a unique index over the existing `group_bridge_mappings`; Memory enforces the same invariant. Historical ambiguous state fails closed rather than selecting a Group heuristically.

## Inbound resolution

`resolve_inbound_text` consumes an already validated Bridge inbound event. It requires exact caller/event scope equality, Group-read and Bridge-event authorization, an Active exact Bridge registration, Text capability, and the `InboundEvents`, `ExternalIdentityReferences`, and `MessageContent` data permissions.

Resolution returns only the existing canonical GroupId + ConversationRef + IntegrationId. It does not create a Message, Identity, membership, Delivery fact, or external identity binding. Unknown mappings and private Groups invisible to the caller return non-disclosing absence.

## Outbound projection

`text_projection` maps one visible canonical Group Conversation to all configured external endpoints. Every configured endpoint is represented explicitly as `Ready`, `RegistrationUnavailable`, `RegistrationInactive`, `CapabilityUnavailable`, or `DataPermissionDenied`; unsupported endpoints are not silently dropped.

A Ready text endpoint requires an Active registration with Text capability plus external-identity and message-content data permissions. Projection itself performs no provider side effect. Callers must continue through Phase-31 `BridgeRuntime`, which retains canonical Message/policy/idempotency/acceptance ownership.

## Offline/restart semantics

SQLite schema v28 does not create an Overlay database. It adds only a uniqueness invariant over the existing Group mapping table and an additive offline-replication sidecar for bridge-mapping Group changes. A single monotonic offline Group-change sequence orders legacy v23 mutations and v28 mapping mutations under the existing opaque Group cursor.

Migration v27→v28 preserves existing `group_bridge_mappings` byte-for-byte, creates no inferred endpoint or Conversation relationship, and starts the new bridge-change sidecar empty. Restart must preserve exact reverse resolution.

## Privacy and diagnostics

Provider external group IDs are opaque provider metadata. Overlay debug output redacts them. Overlay does not log/copy provider message payload or external actor IDs into a new durable store. Provider-visible data remains subject to the Bridge registration permissions and provider retention policy.

## Non-claims

Phase 35 does not claim universal provider group-management APIs, provider-side membership synchronization, automatic identity matching, message fan-out orchestration, exactly-once cross-network delivery, attachment/call/reaction parity, provider webhook/HA ownership, Reference Messenger UI, or Production maturity. Concrete provider adapters still expose only their independently implemented capabilities; Overlay never upgrades Telegram/VK/MAX from Text to Group capability by declaration.

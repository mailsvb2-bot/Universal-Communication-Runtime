# ADR-0074: Phase 36 Federation is explicit local trust over Endpoint, Crypto and Sync owners

Status: Accepted

## Context

The Canon requires independent UCR nodes to communicate without treating federation as blind trust. It distinguishes Known, Authenticated, Authorized and Trusted nodes, and requires compromised-node revoke, block and credential rotation.

UCR already has canonical `EndpointKind::PersonalNode` / `OrganizationNode`, authenticated `EstablishedSession`, exact-scope Device/signing-key trust, and durable `SyncSession`. Creating a parallel Node identity graph, federation Message store, transport, or authorization engine would duplicate existing owners and violate the one-communication-model rule.

The existing Phase-15 Internet handshake intentionally binds one exact `TenantScope`. Independent federation peers may belong to different scopes, so cross-scope federation policy cannot be inferred from that same-scope transport binding.
## Decision

Phase 36 adds one local durable `FederationPeerRecord` keyed by local scope, remote scope and remote node Endpoint. The record contains only explicit local policy: local/remote endpoints, expected remote Device/key, allowed capabilities, trust state and optimistic generation.

The trust lifecycle is `Known -> Authenticated -> Authorized -> Trusted`. `Trusted` may be reduced to `Authorized`; any active state may become `Revoked` or `Blocked`. Neither terminal state can be silently reactivated. Credential rotation is a separate compare-and-swap operation and always resets the relation to `Known`.

A live admission revalidates the authenticated peer Device, current trusted signing key, local permission, durable federation state, allowed capability and the existing canonical `SyncSession`. Durable `Authenticated` records historical proof only; it never substitutes for revalidating the live session.

Cross-tenant federation is therefore an explicit local authorization relationship. A peer-supplied remote scope, Endpoint, Device, key, capability or trust claim cannot create authority.
SQLite v29 persists only this federation trust/admission policy and capability list. Migration v28→v29 creates empty federation tables and infers no peer relationship from existing Endpoint, Device, Sync, Group, Bridge or network state.

`ucr-federation` is a stateless admission facade over existing owners. It does not persist Message, Conversation, Delivery, transport routes or replicated content, and it does not make a remote node a source of truth.

## Rejected alternatives

- A new canonical `NodeId` when canonical Endpoint already models Personal/Organization nodes.
- A federation-specific Message, Conversation, Delivery or Identity store.
- Treating a successful network handshake as cross-tenant authorization.
- Letting the remote peer self-declare `Authorized` or `Trusted`.
- Preserving trust level across credential rotation.
- Reusing `PeerPeer` sync while ignoring explicit Device↔Node endpoint binding.
- Treating `Trusted` as permission bypass or unrestricted data access.
## Consequences

Phase 36 can safely express independent-node trust and cross-scope sync admission without weakening exact-scope defaults. Revocation, blocking and credential rotation are restart-safe, while live Device/key revocation invalidates later admission even when an older session object still exists.

This phase remains **Prepared**. It does not claim global discovery, NAT traversal, a managed federation directory, federated Relay, content replication policy, automatic organization membership, Personal Node product lifecycle, Organization Mode, production deployment, HA or SLA. Those remain later phases/owners.
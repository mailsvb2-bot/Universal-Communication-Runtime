# Phase 37 — Personal Node

Status: **Prepared/reference**.

Phase 37 makes the Canon Personal Node a real owner-controlled deployment boundary for a PC, NAS, mini-PC or home server. It is not a second Identity, Message, Conversation, Delivery, Sync, Relay, Bridge or communication brain. The Personal Node composes existing Endpoint, authorization, Sync, Store-and-Forward and Bridge owners and adds only node profile/lifecycle plus encrypted mailbox/cache object storage.

## Canonical identity and lifecycle

A Personal Node is identified by the existing canonical `EndpointId` with `EndpointKind::PersonalNode`. Phase 37 adds no `NodeId`, account graph, Message identity or route identity.

One exact `PersonalNodeProfile` is keyed by `TenantScope + EndpointId`. It declares a bounded service set, state, optimistic generation and explicit mailbox/cache byte ceilings. The reference lifecycle is `Active <-> Disabled`; generation advances only through compare-and-swap transitions.

Node possession is not authority. Install/read/transition/object/use operations remain guarded by exact-scope canonical permissions, and a different tenant cannot self-install or reactivate the node.
## Services reuse existing owners

`Sync` admits only an already-existing Active canonical `SyncSession` with `DeviceNode` binding to the Personal Node endpoint. The Personal Node does not own Sync checkpoints or reconciliation truth.

`Relay` admits an existing sender-side Store-and-Forward job. It performs no transport side effect and owns no Delivery transition. `NoRelay`, `LocalOnly`, `DirectOnly` and `PrivateNetworkOnly` fail closed at this admission boundary; `NoExternalBridge` does not prohibit relay.

`Bridge` admits only an existing Active canonical Bridge registration. Provider execution, provider acceptance ambiguity and provider-specific data policy remain owned by the Bridge runtime.

`EncryptedMailbox` and `Cache` are node-local opaque object services. Their durable objects contain ciphertext, declared encryption scheme, SHA-256 ciphertext integrity, creation/optional expiry metadata and no Message/Conversation/Delivery semantics.

A disabled node denies new service admission while leaving canonical Sync, Store-and-Forward and Bridge state untouched.
## Durability, ownership and portability

SQLite schema v30 stores profile/lifecycle and encrypted mailbox/cache objects. Migration from v29 creates empty Personal Node state and infers no node from Federation peers, Sync sessions, Bridge registrations, Devices, Messages or network reachability.

Object capacity is enforced transactionally per node and object kind. Equal object retries deduplicate; changed semantics under the same object ID conflict. Objects can be read, bounded-listed and explicitly deleted by an authorized owner, providing the Phase-37 user-owned data control surface without claiming a complete backup/export product.

`SYNC != BACKUP`: Phase 37 does not reinterpret Sync as backup. Encrypted backup versioning, restore conformance and documented recovery-key ownership remain separate Canon requirements.

## Privacy and non-claims

The Personal Node boundary may see only owner-assigned scope/node metadata, canonical state required for admitted services, and ciphertext selected for mailbox/cache storage. Possession of a node, endpoint or ciphertext grants no Identity, permission or federation authority.

Phase 37 does not claim automatic discovery, NAT traversal, a new generic Relay transport, provider-side Bridge execution, backup/restore, managed hosting, HA/SLA, Organization Mode, production deployment or Production maturity. Those remain separate phases or infrastructure owners.

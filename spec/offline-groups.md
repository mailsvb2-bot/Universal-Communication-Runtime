# Phase 26 — Offline Groups

Status: **Prepared/reference**.

Phase 26 adds local-first, one-hop Group reconciliation over the existing canonical Group, Message, Sync, Device, Crypto and storage owners. It does not create a second Group database, Message database, Sync state machine, routing layer, relay, or Store-and-Forward queue.

## Scope

The reference path supports Group synchronization while external Internet connectivity is unavailable, provided two peers can establish an existing authenticated UCR session and an existing active `SyncSession` with `link_kind = PeerPeer`.

A Phase-26 operation is always bound to one known canonical Group and its existing Conversation. `SyncMode::Full` permits that Group; `SyncMode::Partial` permits it only when the Group Conversation ID is present in the existing canonical `SyncSelection`.

The public capability is `ucr.group.offline_sync` with Prepared maturity.

## Trust boundary

A raw peer-supplied Principal is never authentication evidence. The Prepared reference path accepts the remote peer only as a canonical Device principal whose Principal ID exactly equals the Device ID proven by the existing trusted `EstablishedSession`.

Before every export or reconciliation operation, the runtime re-checks that the authenticated Device remains `Active` and that the exact signing-key descriptor authenticated by the session is still the independently resolved active trusted key for that Device and Identity. Revocation or key rotation therefore invalidates an already-open offline-sync session.

No Person→Device, AI→Device, Bot→Device or Organization→Device relationship is inferred.## Group changes

A locally committed canonical `GroupChange` may receive source-local replication evidence only after the canonical Group transition succeeds. The evidence contains the exact actor, change and resulting `group_generation`.

Inbound one-hop changes are canonicalized and then re-enter the existing Group transition owner. Revision, role, ownership, membership tombstone, crypto-state and Event-ID conflict rules are therefore not reimplemented by Offline Groups.

A new inbound change must advance exactly to the next local replication generation. A retry of an already-applied change may reach the existing Event-ID/fingerprint duplicate check. A stale record with different semantics remains a conflict.

Group membership is security-sensitive. The runtime accepts a remote change only when the record actor is the exact authenticated Device principal. The intended local recipient must remain an active Group member with history access.

## Group messages

Offline Group messages reuse the existing canonical `MessageEnvelope` and Message store. Replication requires a durable `DeliveryState::Persisted` Message, a signature, exact Group Conversation binding, exact source Principal provenance in `origin.principal_id`, and a non-future `group_generation`.

The runtime additionally requires `message.author_device.device_id` to equal the Device authenticated by the trusted session and re-verifies the Message signature through the current trusted-key resolver. Revoked Device/key state therefore fails closed even after reconnect or delayed delivery.

Historical author membership is evaluated at the declared Group generation. A removal tombstone may therefore prove that a delayed Message was authored while membership was still active, but a Message at or after the removal generation is denied.

Current recipient membership and current history policy are also enforced before persistence.## Enumeration, cursors and delayed sync

Local replication evidence is enumerated in bounded pages of at most 256 items. The source-issued cursor is opaque to callers and is cryptographically bound to exact Tenant/Namespace + Group + stream kind. Cross-Group or cross-stream cursor reuse fails closed.

The cursor sequence is a store-private source enumeration position only. It is not canonical Message ordering, Group revision authority, global time, or recipient acknowledgement.

Durable pause/resume remains owned by the existing `SyncSession` / `SyncCheckpoint` model. Offline Group cursors do not create a second durable sync state machine.

## One-hop boundary

Only records authored/acted by the exact local `source` are exported. Records reconciled from another peer are applied to canonical Group/Message state but intentionally do **not** receive local export sidecars.

This means A→B reconciliation does not make B a forwarding peer for A's record. Intermediary transport, durable forwarding queues, expiry/retry while the recipient is absent, and multi-hop propagation belong to Phase 27 Store-and-Forward or later routing phases.

## SQLite v23

SQLite schema v23 adds only replication sidecars over existing owners. `offline_group_changes` references committed Group changes and stores the complete canonical mutation semantics required for restart-safe source enumeration. `offline_group_messages` references the existing canonical Message row and stores only Group/source/generation enumeration metadata.

Migration v22→v23 creates both sidecars empty. It never invents replication generation, source authorship, or replay evidence for historical v22 Groups/Messages.

## Non-claims

Phase 26 itself does not claim discovery, mesh routing, intermediary relay, Store-and-Forward, exactly-once delivery, group E2EE/MLS, automatic conflict repair, SFU, conferencing, or production listener lifecycle. Phase 27 Store-and-Forward and Phase 28 signed-Group-Message Mesh are separate later layers and do not widen this one-hop contract.
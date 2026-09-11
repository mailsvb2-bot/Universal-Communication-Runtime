# Phase 28 Mesh

## Scope

Phase 28 adds Prepared bounded multi-hop propagation for **signed Group Messages only**. It extends Phase 26 one-hop Offline Groups without creating a second Message body, Group membership authority, Delivery state machine, durable topology graph, Relay, discovery service, or NAT traversal layer. Canonical Message, Group, Sync, Device and trusted-key owners remain authoritative.

The capability is `ucr.group.mesh_sync`. Group changes are deliberately not forwarded: Phase-18 Group changes do not carry an author-Device signature suitable for trustworthy third-party propagation.

## Trust and forwarding path

Each operation reuses an active `PeerPeer` SyncSession selected for the exact Group Conversation and an established cryptographic peer session. The immediate peer Device and active signing-key state are revalidated before export/reconcile. The original Message signature is reverified through the existing trusted-key resolver at every receiving hop.

A Mesh replica carries a bounded `forward_path` of Device IDs. The first entry must be the original `message.author_device.device_id`, the authenticated exporting peer must be the current path tail, entries are unique, and at most 8 Devices are allowed. The recipient is appended atomically when the Message is accepted. A recipient already in the path is rejected, preventing simple forwarding loops.

The path is routing metadata only. It grants no authorization, changes no authorship, proves no Delivery state, and must not be treated as Identity/social-graph evidence. It is visible only to participating peers that receive the replica; the reference implementation does not publish a topology directory.

## Persistence and restart

The canonical Message remains in the existing Message store. SQLite v25 adds only `mesh_group_message_hops`, keyed to the existing Phase-26 `offline_group_messages` sidecar. A v24→v25 migration creates an empty hop table and invents no Mesh history. Memory and SQLite use the same source-sequence pagination semantics and bound one scan page to `max_items + 1` source records.

A Mesh-received signed Message is inserted through the existing canonical Message owner and becomes eligible for later Mesh export with the same Message ID, content, author Device and signature. Duplicate canonical Message retries are idempotent; conflicting reuse fails closed. The stored forwarding path is not replaced by an alternative duplicate path.

## Membership and history

Both the immediate source and intended recipient must be active Group members with history-read authority. Historical author membership is checked at the record's Group generation, while current immediate-peer Device/key trust is checked at operation time. Group history policy remains the canonical visibility owner.

## Public contract and nonclaims

`proto/ucr/v1/mesh.proto` exposes only bounded Mesh cursor/page/replica data and defines no service. Existing Sync/Crypto/Transport surfaces carry the authenticated peer connection.

Phase 28 does not claim arbitrary direct-chat mesh, GroupChange forwarding, topology discovery, mDNS/Wi-Fi Direct/BLE control, Relay/TURN, NAT traversal, global routing, simultaneous multipath delivery, exactly-once delivery, recipient Delivered/Read evidence, anonymous forwarding, production listener lifecycle, or an infrastructure Relay trust boundary. Those require separate owners and release evidence.

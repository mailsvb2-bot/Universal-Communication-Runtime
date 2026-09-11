# ADR-0066: Phase 28 Mesh reuses Group, Message, Sync, Device and trust owners

## Status
Accepted

## Context
Phase 26 intentionally stops at one-hop Offline Groups, while the roadmap assigns Mesh to Phase 28. Extending propagation must not turn every peer into a new Message/Delivery authority or silently introduce Relay/discovery infrastructure.

## Decision
Phase 28 forwards only canonical **signed Group Messages**. The original Message ID/body/author/signature remain unchanged. Every hop reuses active PeerPeer Sync admission, current Device/signing-key trust and canonical Group membership/history checks. A bounded loop-free Device path (maximum 8) is routing metadata only; the authenticated exporter must equal the path tail and the receiver is appended atomically.

SQLite v25 persists only path hops referencing the existing Phase-26 offline Group Message sidecar. Migration from v24 creates no inferred Mesh paths. No second Message store, Delivery state machine, durable topology graph, Relay identity, discovery service, or exactly-once claim is introduced.

Group changes are not forwarded because their current canonical form lacks an author-Device signature that makes third-party propagation independently verifiable.

## Consequences
Multi-hop signed Group Message propagation can continue A→B→C while preserving original authorship and restart-safe loop state. Participating peers may observe up to eight Device IDs in the traversed path; this is an explicit bounded metadata cost and never Identity/social-graph evidence.

Relay/NAT traversal, discovery, arbitrary direct-message mesh, simultaneous multipath and production networking remain separate later work.

## Rejected alternatives
- Re-sign forwarded Messages as the intermediate Device: rejected because it destroys original canonical authorship.
- Forward unsigned Group changes: rejected because downstream peers cannot independently verify the original actor Device.
- Persist a global topology/routing graph: rejected as a second routing brain and unnecessary for bounded explicit peer propagation.
- Treat a hop as Delivered/Read evidence: rejected because forwarding possession is not recipient/device/user evidence.
- Introduce a Relay/TURN service under the Mesh phase: rejected because Relay is a separate trust boundary and needs its own metadata/security evidence.

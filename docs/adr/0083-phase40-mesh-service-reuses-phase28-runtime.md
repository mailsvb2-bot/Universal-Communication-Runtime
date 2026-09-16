# ADR 0083: Phase 40 MeshService reuses the Phase-28 runtime

## Status
Accepted for the Prepared Phase-40 Reference Messenger proof.

## Decision
The public `MeshService` is a thin gRPC binding over the existing Phase-28 `MeshGroupsRuntime`. That existing Phase-28 `MeshGroupsRuntime` remains the canonical Mesh owner; Phase 40 does not create a second P2P replication engine.

The binding accepts a canonical `SyncSession` ID and resolves peer identity plus an already-authenticated cryptographic peer session through host-owned ephemeral connection plumbing. Peer identity/session material is never accepted from the public request and is never persisted by the binding.

Before invoking Mesh, the service applies normal Service Principal authentication, quota, exact-scope `ucr.sync.read` or `ucr.sync.write` permission enforcement and operation audit. The Mesh runtime then independently revalidates Sync, Device, Group membership, signature and forwarding-path authority.

## Rejected alternatives
- Exposing peer addresses, topology graphs, Relay/NAT controls or transport selection through the public API.
- Letting the SDK maintain peer trust, Mesh cursors, retry loops or durable forwarding state.
- Duplicating Phase-28 export/reconciliation logic in the gRPC layer.

## Consequences
P2P becomes reachable through the public SDK and Reference Messenger without weakening the no-second-brain rule. Recovery and concrete platform accessibility evidence remain separate Phase-40 work.

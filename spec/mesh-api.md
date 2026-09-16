# Phase 40 Public Mesh API

`MeshService` is a narrow public-consumer binding over the existing Phase-28 `MeshGroupsRuntime`. It exists so the Reference Messenger can prove P2P/Mesh behavior through the same versioned public UCR contract used by every other external consumer.

The public surface contains only two bounded operations: `ExportGroupMessages` and `ReconcileGroupMessage`. Both are scoped by a canonical `TenantScope` and an existing canonical `SyncSession` identifier. Export also names one canonical Group and an opaque Mesh cursor; reconciliation carries one already-signed canonical Mesh Group Message replica.

The caller never supplies peer identity, local Device identity, transport address, topology, route, Relay, NAT traversal configuration, retry policy or cryptographic session material. The UCR host resolves an already-authenticated live peer session by the supplied canonical Sync session ID. That process-local resolver is connection plumbing only and is not a durable trust owner.

`MeshGroupsRuntime` revalidates canonical Sync state, Group membership, Device lifecycle, trusted signing keys, original Message signatures and bounded forwarding paths. Service Principal admission adds quota, `ucr.sync.read`/`ucr.sync.write` permission checks and operation audit before the Mesh runtime is invoked.

The API does not expose discovery, topology, NAT traversal, Relay, route selection or retry. It also does not claim that Mesh replication itself is Message delivery/read evidence.

use ucr_model::{
    GroupId, MeshCursor, MeshGroupMessagePage, MeshGroupMessageReplica, ScopedPrincipal,
    TenantScope,
};

use crate::{DurableRecordStatus, DurableStoreError, OfflineGroupStore};

/// Durable routing-metadata sidecar for bounded signed Group Message Mesh propagation.
///
/// Implementations reuse the canonical Group/Message/Sync owners and MUST NOT create a second
/// Message body, membership authority, Delivery state machine, Relay identity, or topology graph.
pub trait MeshGroupStore: OfflineGroupStore {
    /// Enumerates a bounded page of signed Group Messages that this exact Device may forward to
    /// another active Group member without revisiting a Device already in the stored path.
    ///
    /// # Errors
    /// Rejects cross-scope membership/cursor misuse, malformed bounds, corrupt provenance, or
    /// storage failures.
    fn mesh_group_message_page(
        &self,
        source: &ScopedPrincipal,
        recipient: &ScopedPrincipal,
        scope: &TenantScope,
        group_id: &GroupId,
        cursor: Option<&MeshCursor>,
        max_items: usize,
    ) -> Result<MeshGroupMessagePage, DurableStoreError>;

    /// Persists one already-authenticated and signature-verified multi-hop Group Message through
    /// the canonical Message owner and records only bounded non-authoritative forwarding metadata.
    /// The receiving Device is appended atomically to the path.
    ///
    /// # Errors
    /// Rejects loops, hop-budget exhaustion, inactive/history-invalid membership, semantic Message
    /// conflicts, or storage failures.
    fn reconcile_mesh_group_message(
        &self,
        recipient: &ScopedPrincipal,
        record: &MeshGroupMessageReplica,
    ) -> Result<DurableRecordStatus, DurableStoreError>;
}

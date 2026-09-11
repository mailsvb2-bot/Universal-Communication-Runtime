use core::fmt;

use crate::{DeviceId, GroupId, OfflineGroupMessageReplica, TenantScope};

#[derive(Clone, PartialEq, Eq)]
pub struct MeshCursor {
    pub token: Vec<u8>,
}

impl fmt::Debug for MeshCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeshCursor")
            .field("token", &"<opaque>")
            .field("token_len", &self.token.len())
            .finish()
    }
}

/// One signed Group Message plus the bounded Device path that has already carried it.
///
/// `forward_path` is routing metadata only. It never replaces Message authorship, Device trust,
/// Group membership, Sync authority, or Delivery evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshGroupMessageReplica {
    pub record: OfflineGroupMessageReplica,
    pub forward_path: Vec<DeviceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshGroupMessagePage {
    pub scope: TenantScope,
    pub group_id: GroupId,
    pub records: Vec<MeshGroupMessageReplica>,
    pub next_cursor: Option<MeshCursor>,
}

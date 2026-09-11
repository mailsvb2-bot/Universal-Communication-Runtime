use core::fmt;

use crate::{GroupChange, GroupId, MessageEnvelope, ScopedPrincipal, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineGroupStreamKind {
    Changes,
    Messages,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OfflineGroupCursor {
    pub token: Vec<u8>,
}

impl fmt::Debug for OfflineGroupCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineGroupCursor")
            .field("token", &"<opaque>")
            .field("token_len", &self.token.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineGroupChangeReplica {
    pub actor: ScopedPrincipal,
    pub group_generation: u64,
    pub change: GroupChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineGroupMessageReplica {
    pub author: ScopedPrincipal,
    pub group_id: GroupId,
    pub group_generation: u64,
    pub message: MessageEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineGroupChangePage {
    pub scope: TenantScope,
    pub group_id: GroupId,
    pub records: Vec<OfflineGroupChangeReplica>,
    pub next_cursor: Option<OfflineGroupCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineGroupMessagePage {
    pub scope: TenantScope,
    pub group_id: GroupId,
    pub records: Vec<OfflineGroupMessageReplica>,
    pub next_cursor: Option<OfflineGroupCursor>,
}

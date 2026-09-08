use core::fmt;

use crate::{
    ConversationRef, DeliveryPolicy, EventId, GroupId, IntegrationId, OpaqueId, PrincipalRef,
    TenantScope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum GroupRole {
    Owner = 1,
    Admin = 2,
    Member = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum GroupPermission {
    SendMessage = 1,
    ReadHistory = 2,
    ManageMembers = 3,
    ManageRoles = 4,
    ManageGroup = 5,
    TransferOwnership = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMemberState {
    Active,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupOwnership {
    PersonOwned(PrincipalRef),
    OrganizationOwned(PrincipalRef),
    SharedAdmin,
    OwnerlessFederated,
    Temporary {
        owner: Option<PrincipalRef>,
        expires_at_unix_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupHistoryPolicy {
    NoHistory,
    FromJoin,
    LastNMessages(u32),
    FromTimestamp(i64),
    FullHistory,
    CustomPolicy(String),
}

#[derive(Clone, PartialEq, Eq)]
pub struct GroupCryptoState {
    pub capability_id: Option<String>,
    pub epoch: u64,
    pub state_ref: Option<OpaqueId>,
}

impl fmt::Debug for GroupCryptoState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupCryptoState")
            .field("capability_id", &self.capability_id)
            .field("epoch", &self.epoch)
            .field("has_state_ref", &self.state_ref.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicGroupJoinPolicy {
    Open,
    ApprovalRequired,
    InviteOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicGroupDiscovery {
    Unlisted,
    Discoverable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicGroupPolicy {
    pub join_policy: PublicGroupJoinPolicy,
    pub discovery: PublicGroupDiscovery,
    pub indexed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaState {
    Idle,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GroupBridgeMapping {
    pub integration_id: IntegrationId,
    pub external_group_id: Vec<u8>,
}

impl fmt::Debug for GroupBridgeMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupBridgeMapping")
            .field("integration_id", &self.integration_id)
            .field("external_group_id", &"<opaque>")
            .field("external_group_id_len", &self.external_group_id.len())
            .finish()
    }
}

/// Canonical durable Group aggregate.
///
/// `conversation` is the existing provider-independent Conversation identity. Group-specific
/// membership/ownership/policy state lives here rather than being copied into Conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub scope: TenantScope,
    pub group_id: GroupId,
    pub conversation: ConversationRef,
    pub ownership: GroupOwnership,
    pub history_policy: GroupHistoryPolicy,
    pub delivery_policy: DeliveryPolicy,
    pub crypto_state: GroupCryptoState,
    pub public_policy: Option<PublicGroupPolicy>,
    pub media_state: GroupMediaState,
    pub bridge_mappings: Vec<GroupBridgeMapping>,
    pub replication_generation: u64,
    pub revision: u64,
}

/// Durable membership row. Removed members remain as tombstones so stale membership cannot
/// silently regain authority after retries/restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembership {
    pub scope: TenantScope,
    pub group_id: GroupId,
    pub member: PrincipalRef,
    pub role: GroupRole,
    pub permissions: Vec<GroupPermission>,
    pub state: GroupMemberState,
    pub joined_revision: u64,
    pub removed_revision: Option<u64>,
    pub history_floor_logical_order: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupChangeKind {
    AddMember {
        member: PrincipalRef,
        role: GroupRole,
    },
    RemoveMember {
        member: PrincipalRef,
    },
    ChangeRole {
        member: PrincipalRef,
        role: GroupRole,
    },
    TransferOwnership {
        new_owner: PrincipalRef,
    },
    SetHistoryPolicy {
        policy: GroupHistoryPolicy,
    },
    SetPublicPolicy {
        policy: PublicGroupPolicy,
    },
    SetDeliveryPolicy {
        policy: DeliveryPolicy,
    },
}

/// One idempotent security-sensitive Group mutation.
///
/// `event_id` is the exact-scope unique fact identifier. A committed Group change reserves that
/// identity against unrelated generic Event append; any future same-fact Event projection must use
/// an explicit reconciliation path rather than silently reusing the identifier.
/// This structure never stores localized human-readable system text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupChange {
    pub event_id: EventId,
    pub scope: TenantScope,
    pub group_id: GroupId,
    pub expected_revision: u64,
    pub kind: GroupChangeKind,
    /// Required for membership/role/ownership changes when a standardized group-crypto state is
    /// configured. The opaque state itself is owned by that crypto provider, not by Group logic.
    pub next_crypto_state: Option<GroupCryptoState>,
}

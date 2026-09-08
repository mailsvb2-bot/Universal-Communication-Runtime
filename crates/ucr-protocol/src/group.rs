use sha2::{Digest, Sha256};
use ucr_model::{
    ConversationKind, DeliveryPolicy, GroupBridgeMapping, GroupChange, GroupChangeKind,
    GroupCryptoState, GroupHistoryPolicy, GroupMemberState, GroupMembership, GroupOwnership,
    GroupPermission, GroupRecord, GroupRole, PrincipalKind, PrincipalRef, PublicGroupPolicy,
    TenantScope,
};

use crate::validate_namespaced_identifier;

pub const GROUP_MLS_CAPABILITY: &str = "ucr.group.mls";
pub const MAX_GROUP_MEMBERS: usize = 4096;
pub const MAX_GROUP_MEMBER_LIST: usize = 4096;
pub const MAX_GROUP_BRIDGE_MAPPINGS: usize = 32;
pub const MAX_EXTERNAL_GROUP_ID_LEN: usize = 4096;
pub const MAX_GROUP_HISTORY_MESSAGES: u32 = 10_000;
pub const GROUP_CHANGE_FINGERPRINT_V1_DOMAIN: &[u8] = b"UCR-GROUP-CHANGE-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupError {
    InvalidKind,
    InvalidPublicPolicy,
    InvalidOwnership,
    InvalidHistoryPolicy,
    InvalidCryptoState,
    InvalidBridgeMapping,
    DuplicateBridgeMapping,
    InvalidMembership,
    DuplicateMembership,
    TooManyMembers,
    ScopeMismatch,
    GroupMismatch,
    RevisionMismatch,
    PermissionDenied,
    MemberAlreadyActive,
    MemberNotActive,
    InvalidRoleTransition,
    OwnershipTransferNotSupported,
    WouldOrphanGroup,
    InvalidHistoryFloor,
    InvalidListLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTransition {
    pub group: GroupRecord,
    pub memberships: Vec<GroupMembership>,
}

#[must_use]
pub fn group_permissions_for_role(role: GroupRole) -> Vec<GroupPermission> {
    match role {
        GroupRole::Owner => vec![
            GroupPermission::SendMessage,
            GroupPermission::ReadHistory,
            GroupPermission::ManageMembers,
            GroupPermission::ManageRoles,
            GroupPermission::ManageGroup,
            GroupPermission::TransferOwnership,
        ],
        GroupRole::Admin => vec![
            GroupPermission::SendMessage,
            GroupPermission::ReadHistory,
            GroupPermission::ManageMembers,
            GroupPermission::ManageGroup,
        ],
        GroupRole::Member => vec![GroupPermission::SendMessage, GroupPermission::ReadHistory],
    }
}

#[must_use]
pub const fn is_group_conversation_kind(kind: ConversationKind) -> bool {
    matches!(
        kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    )
}

/// Validates and canonicalizes one Group aggregate.
///
/// # Errors
/// Returns an explicit Group error for invalid kind, ownership, policy, crypto, or bridge state.
pub fn canonical_group_record(group: &GroupRecord) -> Result<GroupRecord, GroupError> {
    if !is_group_conversation_kind(group.conversation.kind) {
        return Err(GroupError::InvalidKind);
    }
    validate_ownership(&group.ownership)?;
    validate_history_policy(&group.history_policy)?;
    validate_crypto_state(&group.crypto_state)?;
    match group.conversation.kind {
        ConversationKind::PrivateGroup if group.public_policy.is_some() => {
            return Err(GroupError::InvalidPublicPolicy);
        }
        ConversationKind::PublicGroup if group.public_policy.is_none() => {
            return Err(GroupError::InvalidPublicPolicy);
        }
        _ => {}
    }
    if group.bridge_mappings.len() > MAX_GROUP_BRIDGE_MAPPINGS {
        return Err(GroupError::InvalidBridgeMapping);
    }
    let mut canonical = group.clone();
    canonical.bridge_mappings.sort_by(|left, right| {
        left.integration_id
            .cmp(&right.integration_id)
            .then_with(|| left.external_group_id.cmp(&right.external_group_id))
    });
    for mapping in &canonical.bridge_mappings {
        validate_bridge_mapping(mapping)?;
    }
    if canonical
        .bridge_mappings
        .windows(2)
        .any(|pair| pair[0].integration_id == pair[1].integration_id)
    {
        return Err(GroupError::DuplicateBridgeMapping);
    }
    Ok(canonical)
}

/// Validates one membership against its owning Group revision and scope.
///
/// # Errors
/// Returns an explicit Group error for scope/group mismatch, invalid role permissions, or invalid lifecycle revision.
pub fn canonical_group_membership(
    group: &GroupRecord,
    membership: &GroupMembership,
) -> Result<GroupMembership, GroupError> {
    if membership.scope != group.scope {
        return Err(GroupError::ScopeMismatch);
    }
    if membership.group_id != group.group_id {
        return Err(GroupError::GroupMismatch);
    }
    if membership.permissions != group_permissions_for_role(membership.role) {
        return Err(GroupError::InvalidMembership);
    }
    if membership.joined_revision > group.revision {
        return Err(GroupError::InvalidMembership);
    }
    match membership.state {
        GroupMemberState::Active if membership.removed_revision.is_some() => {
            return Err(GroupError::InvalidMembership);
        }
        GroupMemberState::Removed => {
            let removed = membership
                .removed_revision
                .ok_or(GroupError::InvalidMembership)?;
            if removed < membership.joined_revision || removed > group.revision {
                return Err(GroupError::InvalidMembership);
            }
        }
        GroupMemberState::Active => {}
    }
    Ok(membership.clone())
}

/// Canonicalizes initial Group state and derives the creator membership.
///
/// # Errors
/// Returns an explicit Group error for invalid ownership, scope, or non-zero initial revision/generation.
pub fn canonical_group_creation(
    group: &GroupRecord,
    creator_scope: &TenantScope,
    creator: &PrincipalRef,
) -> Result<(GroupRecord, GroupMembership), GroupError> {
    if creator_scope != &group.scope {
        return Err(GroupError::ScopeMismatch);
    }
    let group = canonical_group_record(group)?;
    if group.revision != 0 || group.replication_generation != 0 {
        return Err(GroupError::RevisionMismatch);
    }
    let role = match &group.ownership {
        GroupOwnership::PersonOwned(owner) => {
            if owner != creator || creator.kind != PrincipalKind::Person {
                return Err(GroupError::InvalidOwnership);
            }
            GroupRole::Owner
        }
        GroupOwnership::OrganizationOwned(owner) => {
            if owner != creator || creator.kind != PrincipalKind::Organization {
                return Err(GroupError::InvalidOwnership);
            }
            GroupRole::Owner
        }
        GroupOwnership::SharedAdmin | GroupOwnership::OwnerlessFederated => GroupRole::Admin,
        GroupOwnership::Temporary { owner, .. } => {
            if let Some(owner) = owner {
                if owner != creator {
                    return Err(GroupError::InvalidOwnership);
                }
                GroupRole::Owner
            } else {
                GroupRole::Admin
            }
        }
    };
    let membership = GroupMembership {
        scope: group.scope.clone(),
        group_id: group.group_id.clone(),
        member: creator.clone(),
        role,
        permissions: group_permissions_for_role(role),
        state: GroupMemberState::Active,
        joined_revision: 0,
        removed_revision: None,
        history_floor_logical_order: 0,
    };
    Ok((group, membership))
}

/// Canonicalizes, bounds, sorts, and deduplicates the Group membership set.
///
/// # Errors
/// Returns an explicit Group error for invalid, duplicate, or over-capacity membership state.
pub fn canonical_group_memberships(
    group: &GroupRecord,
    memberships: &[GroupMembership],
) -> Result<Vec<GroupMembership>, GroupError> {
    if memberships.len() > MAX_GROUP_MEMBERS {
        return Err(GroupError::TooManyMembers);
    }
    let mut canonical = memberships
        .iter()
        .map(|membership| canonical_group_membership(group, membership))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort_by(|left, right| {
        left.member
            .principal_id
            .cmp(&right.member.principal_id)
            .then_with(|| {
                principal_kind_code(left.member.kind).cmp(&principal_kind_code(right.member.kind))
            })
    });
    if canonical
        .windows(2)
        .any(|pair| pair[0].member == pair[1].member)
    {
        return Err(GroupError::DuplicateMembership);
    }
    Ok(canonical)
}

/// Returns the current active role for one exact Group actor.
///
/// This is intentionally narrower than change authorization: idempotent retries may remain valid
/// after the original transition changed the actor's role (for example ownership transfer), but a
/// removed actor must not receive duplicate/conflict existence evidence.
///
/// # Errors
/// Returns an explicit Group error for invalid aggregate/membership state, cross-scope actors, or
/// an actor without an active exact-PrincipalRef membership.
pub fn active_group_actor_role(
    group: &GroupRecord,
    memberships: &[GroupMembership],
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
) -> Result<GroupRole, GroupError> {
    let group = canonical_group_record(group)?;
    let memberships = canonical_group_memberships(&group, memberships)?;
    if actor_scope != &group.scope {
        return Err(GroupError::ScopeMismatch);
    }
    let actor_index =
        active_member_index(&memberships, actor).ok_or(GroupError::PermissionDenied)?;
    Ok(memberships[actor_index].role)
}

/// Applies one optimistic-concurrency Group mutation through the canonical transition owner.
///
/// # Errors
/// Returns an explicit Group error for stale revision, unauthorized role, invalid policy/crypto
/// transition, membership conflict, or an ownership change that would orphan the Group.
pub fn apply_group_change(
    group: &GroupRecord,
    memberships: &[GroupMembership],
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
    change: &GroupChange,
    add_history_floor_logical_order: Option<u64>,
) -> Result<GroupTransition, GroupError> {
    let mut group = canonical_group_record(group)?;
    let mut memberships = canonical_group_memberships(&group, memberships)?;
    validate_change_binding(&group, actor_scope, change)?;
    let actor_index =
        active_member_index(&memberships, actor).ok_or(GroupError::PermissionDenied)?;
    let actor_role = memberships[actor_index].role;
    let next_revision = group
        .revision
        .checked_add(1)
        .ok_or(GroupError::RevisionMismatch)?;
    let next_generation = group
        .replication_generation
        .checked_add(1)
        .ok_or(GroupError::RevisionMismatch)?;
    apply_change_crypto(&mut group, change)?;
    let context = GroupChangeContext {
        actor,
        actor_index,
        actor_role,
        next_revision,
        history_floor: add_history_floor_logical_order,
    };
    apply_change_kind(&mut group, &mut memberships, change, &context)?;
    group.revision = next_revision;
    group.replication_generation = next_generation;
    let memberships = canonical_group_memberships(&group, &memberships)?;
    require_group_admin_continuity(&memberships)?;
    Ok(GroupTransition { group, memberships })
}

fn validate_change_binding(
    group: &GroupRecord,
    actor_scope: &TenantScope,
    change: &GroupChange,
) -> Result<(), GroupError> {
    if actor_scope != &group.scope || change.scope != group.scope {
        return Err(GroupError::ScopeMismatch);
    }
    if change.group_id != group.group_id {
        return Err(GroupError::GroupMismatch);
    }
    if change.expected_revision != group.revision {
        return Err(GroupError::RevisionMismatch);
    }
    Ok(())
}

fn apply_change_crypto(group: &mut GroupRecord, change: &GroupChange) -> Result<(), GroupError> {
    let security_sensitive = matches!(
        change.kind,
        GroupChangeKind::AddMember { .. }
            | GroupChangeKind::RemoveMember { .. }
            | GroupChangeKind::ChangeRole { .. }
            | GroupChangeKind::TransferOwnership { .. }
    );
    if security_sensitive {
        advance_crypto_state(group, change.next_crypto_state.as_ref())
    } else if change.next_crypto_state.is_some() {
        Err(GroupError::InvalidCryptoState)
    } else {
        Ok(())
    }
}

struct GroupChangeContext<'a> {
    actor: &'a PrincipalRef,
    actor_index: usize,
    actor_role: GroupRole,
    next_revision: u64,
    history_floor: Option<u64>,
}

fn apply_change_kind(
    group: &mut GroupRecord,
    memberships: &mut Vec<GroupMembership>,
    change: &GroupChange,
    context: &GroupChangeContext<'_>,
) -> Result<(), GroupError> {
    match &change.kind {
        GroupChangeKind::AddMember { member, role } => apply_add_member(
            group,
            memberships,
            context.actor_role,
            member,
            *role,
            context.next_revision,
            context.history_floor,
        ),
        GroupChangeKind::RemoveMember { member } => apply_remove_member(
            memberships,
            context.actor,
            context.actor_role,
            member,
            context.next_revision,
        ),
        GroupChangeKind::ChangeRole { member, role } => {
            apply_role_change(memberships, context.actor_role, member, *role)
        }
        GroupChangeKind::TransferOwnership { new_owner } => apply_ownership_transfer(
            group,
            memberships,
            context.actor,
            context.actor_index,
            context.actor_role,
            new_owner,
        ),
        GroupChangeKind::SetHistoryPolicy { policy } => {
            apply_history_policy(group, context.actor_role, policy)
        }
        GroupChangeKind::SetPublicPolicy { policy } => {
            apply_public_policy(group, context.actor_role, policy)
        }
        GroupChangeKind::SetDeliveryPolicy { policy } => {
            require_manage_group(context.actor_role)?;
            group.delivery_policy = *policy;
            Ok(())
        }
    }
}

fn apply_add_member(
    group: &GroupRecord,
    memberships: &mut Vec<GroupMembership>,
    actor_role: GroupRole,
    member: &PrincipalRef,
    role: GroupRole,
    next_revision: u64,
    history_floor: Option<u64>,
) -> Result<(), GroupError> {
    require_manage_members(actor_role)?;
    if role == GroupRole::Owner || (role == GroupRole::Admin && actor_role != GroupRole::Owner) {
        return Err(GroupError::InvalidRoleTransition);
    }
    let history_floor = history_floor.ok_or(GroupError::InvalidHistoryFloor)?;
    if let Some(index) = member_index(memberships, member) {
        if memberships[index].state == GroupMemberState::Active {
            return Err(GroupError::MemberAlreadyActive);
        }
        memberships[index].role = role;
        memberships[index].permissions = group_permissions_for_role(role);
        memberships[index].state = GroupMemberState::Active;
        memberships[index].joined_revision = next_revision;
        memberships[index].removed_revision = None;
        memberships[index].history_floor_logical_order = history_floor;
        return Ok(());
    }
    if memberships.len() >= MAX_GROUP_MEMBERS {
        return Err(GroupError::TooManyMembers);
    }
    memberships.push(GroupMembership {
        scope: group.scope.clone(),
        group_id: group.group_id.clone(),
        member: member.clone(),
        role,
        permissions: group_permissions_for_role(role),
        state: GroupMemberState::Active,
        joined_revision: next_revision,
        removed_revision: None,
        history_floor_logical_order: history_floor,
    });
    Ok(())
}

fn apply_remove_member(
    memberships: &mut [GroupMembership],
    actor: &PrincipalRef,
    actor_role: GroupRole,
    member: &PrincipalRef,
    next_revision: u64,
) -> Result<(), GroupError> {
    let target = member_index(memberships, member).ok_or(GroupError::MemberNotActive)?;
    if memberships[target].state != GroupMemberState::Active {
        return Err(GroupError::MemberNotActive);
    }
    if memberships[target].role == GroupRole::Owner {
        return Err(GroupError::WouldOrphanGroup);
    }
    if member != actor {
        require_manage_members(actor_role)?;
        if memberships[target].role == GroupRole::Admin && actor_role != GroupRole::Owner {
            return Err(GroupError::PermissionDenied);
        }
    }
    memberships[target].state = GroupMemberState::Removed;
    memberships[target].removed_revision = Some(next_revision);
    Ok(())
}

fn apply_role_change(
    memberships: &mut [GroupMembership],
    actor_role: GroupRole,
    member: &PrincipalRef,
    role: GroupRole,
) -> Result<(), GroupError> {
    if actor_role != GroupRole::Owner || role == GroupRole::Owner {
        return Err(GroupError::InvalidRoleTransition);
    }
    let target = active_member_index(memberships, member).ok_or(GroupError::MemberNotActive)?;
    if memberships[target].role == GroupRole::Owner {
        return Err(GroupError::InvalidRoleTransition);
    }
    memberships[target].role = role;
    memberships[target].permissions = group_permissions_for_role(role);
    Ok(())
}

fn apply_ownership_transfer(
    group: &mut GroupRecord,
    memberships: &mut [GroupMembership],
    actor: &PrincipalRef,
    actor_index: usize,
    actor_role: GroupRole,
    new_owner: &PrincipalRef,
) -> Result<(), GroupError> {
    if actor_role != GroupRole::Owner {
        return Err(GroupError::PermissionDenied);
    }
    let target = active_member_index(memberships, new_owner).ok_or(GroupError::MemberNotActive)?;
    if new_owner == actor {
        return Err(GroupError::InvalidRoleTransition);
    }
    update_ownership(&mut group.ownership, new_owner)?;
    memberships[actor_index].role = GroupRole::Admin;
    memberships[actor_index].permissions = group_permissions_for_role(GroupRole::Admin);
    memberships[target].role = GroupRole::Owner;
    memberships[target].permissions = group_permissions_for_role(GroupRole::Owner);
    Ok(())
}

fn update_ownership(
    ownership: &mut GroupOwnership,
    new_owner: &PrincipalRef,
) -> Result<(), GroupError> {
    match ownership {
        GroupOwnership::PersonOwned(owner) => {
            if new_owner.kind != PrincipalKind::Person {
                return Err(GroupError::InvalidOwnership);
            }
            *owner = new_owner.clone();
        }
        GroupOwnership::OrganizationOwned(owner) => {
            if new_owner.kind != PrincipalKind::Organization {
                return Err(GroupError::InvalidOwnership);
            }
            *owner = new_owner.clone();
        }
        GroupOwnership::Temporary { owner, .. } => *owner = Some(new_owner.clone()),
        GroupOwnership::SharedAdmin | GroupOwnership::OwnerlessFederated => {
            return Err(GroupError::OwnershipTransferNotSupported);
        }
    }
    Ok(())
}

fn apply_history_policy(
    group: &mut GroupRecord,
    actor_role: GroupRole,
    policy: &GroupHistoryPolicy,
) -> Result<(), GroupError> {
    require_manage_group(actor_role)?;
    validate_history_policy(policy)?;
    group.history_policy = policy.clone();
    Ok(())
}

fn apply_public_policy(
    group: &mut GroupRecord,
    actor_role: GroupRole,
    policy: &PublicGroupPolicy,
) -> Result<(), GroupError> {
    require_manage_group(actor_role)?;
    if group.conversation.kind != ConversationKind::PublicGroup {
        return Err(GroupError::InvalidPublicPolicy);
    }
    group.public_policy = Some(policy.clone());
    Ok(())
}

fn require_group_admin_continuity(memberships: &[GroupMembership]) -> Result<(), GroupError> {
    if memberships.iter().any(|membership| {
        membership.state == GroupMemberState::Active
            && matches!(membership.role, GroupRole::Owner | GroupRole::Admin)
    }) {
        Ok(())
    } else {
        Err(GroupError::WouldOrphanGroup)
    }
}

/// Validates a bounded Group membership-list request size.
///
/// # Errors
/// Returns `InvalidListLimit` for zero or above-limit requests.
pub fn validate_group_member_list_limit(max_items: usize) -> Result<(), GroupError> {
    if max_items == 0 || max_items > MAX_GROUP_MEMBER_LIST {
        Err(GroupError::InvalidListLimit)
    } else {
        Ok(())
    }
}

/// Produces the versioned deterministic fingerprint for one Group change.
///
/// # Errors
/// Returns an explicit Group error if one encoded Group policy component is invalid.
pub fn group_change_fingerprint(change: &GroupChange) -> Result<[u8; 32], GroupError> {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, change.event_id.as_opaque().as_wire_bytes());
    push_scope(&mut bytes, &change.scope);
    push_bytes(&mut bytes, change.group_id.as_opaque().as_wire_bytes());
    bytes.extend_from_slice(&change.expected_revision.to_be_bytes());
    match &change.kind {
        GroupChangeKind::AddMember { member, role } => {
            bytes.push(1);
            push_principal(&mut bytes, member);
            bytes.push(*role as u8);
        }
        GroupChangeKind::RemoveMember { member } => {
            bytes.push(2);
            push_principal(&mut bytes, member);
        }
        GroupChangeKind::ChangeRole { member, role } => {
            bytes.push(3);
            push_principal(&mut bytes, member);
            bytes.push(*role as u8);
        }
        GroupChangeKind::TransferOwnership { new_owner } => {
            bytes.push(4);
            push_principal(&mut bytes, new_owner);
        }
        GroupChangeKind::SetHistoryPolicy { policy } => {
            bytes.push(5);
            push_history_policy(&mut bytes, policy);
        }
        GroupChangeKind::SetPublicPolicy { policy } => {
            bytes.push(6);
            push_public_policy(&mut bytes, policy);
        }
        GroupChangeKind::SetDeliveryPolicy { policy } => {
            bytes.push(7);
            bytes.push(delivery_policy_code(*policy));
        }
    }
    match &change.next_crypto_state {
        Some(state) => {
            bytes.push(1);
            push_crypto_state(&mut bytes, state);
        }
        None => bytes.push(0),
    }
    let mut hasher = Sha256::new();
    hasher.update(GROUP_CHANGE_FINGERPRINT_V1_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

#[must_use]
pub fn group_change_event_type(change: &GroupChange) -> &'static str {
    match change.kind {
        GroupChangeKind::AddMember { .. } => "ucr.group.member_added",
        GroupChangeKind::RemoveMember { .. } => "ucr.group.member_removed",
        GroupChangeKind::ChangeRole { .. } => "ucr.group.role_changed",
        GroupChangeKind::TransferOwnership { .. } => "ucr.group.ownership_transferred",
        GroupChangeKind::SetHistoryPolicy { .. } => "ucr.group.history_policy_changed",
        GroupChangeKind::SetPublicPolicy { .. } => "ucr.group.public_policy_changed",
        GroupChangeKind::SetDeliveryPolicy { .. } => "ucr.group.delivery_policy_changed",
    }
}

fn validate_bridge_mapping(mapping: &GroupBridgeMapping) -> Result<(), GroupError> {
    if mapping.external_group_id.is_empty()
        || mapping.external_group_id.len() > MAX_EXTERNAL_GROUP_ID_LEN
    {
        return Err(GroupError::InvalidBridgeMapping);
    }
    Ok(())
}

fn validate_ownership(ownership: &GroupOwnership) -> Result<(), GroupError> {
    match ownership {
        GroupOwnership::PersonOwned(owner) if owner.kind != PrincipalKind::Person => {
            Err(GroupError::InvalidOwnership)
        }
        GroupOwnership::OrganizationOwned(owner) if owner.kind != PrincipalKind::Organization => {
            Err(GroupError::InvalidOwnership)
        }
        GroupOwnership::Temporary {
            expires_at_unix_ms, ..
        } if *expires_at_unix_ms <= 0 => Err(GroupError::InvalidOwnership),
        _ => Ok(()),
    }
}

fn validate_history_policy(policy: &GroupHistoryPolicy) -> Result<(), GroupError> {
    match policy {
        GroupHistoryPolicy::LastNMessages(count)
            if *count == 0 || *count > MAX_GROUP_HISTORY_MESSAGES =>
        {
            Err(GroupError::InvalidHistoryPolicy)
        }
        GroupHistoryPolicy::CustomPolicy(identifier) => {
            validate_namespaced_identifier(identifier).map_err(|_| GroupError::InvalidHistoryPolicy)
        }
        _ => Ok(()),
    }
}

fn validate_crypto_state(state: &GroupCryptoState) -> Result<(), GroupError> {
    match (&state.capability_id, state.epoch, &state.state_ref) {
        (None, 0, None) => Ok(()),
        (Some(capability), epoch, Some(_)) if capability == GROUP_MLS_CAPABILITY && epoch > 0 => {
            Ok(())
        }
        _ => Err(GroupError::InvalidCryptoState),
    }
}

fn advance_crypto_state(
    group: &mut GroupRecord,
    replacement: Option<&GroupCryptoState>,
) -> Result<(), GroupError> {
    match (&group.crypto_state.capability_id, replacement) {
        (None, None) => Ok(()),
        (None, Some(_)) | (Some(_), None) => Err(GroupError::InvalidCryptoState),
        (Some(current_capability), Some(next)) => {
            validate_crypto_state(next)?;
            let expected_epoch = group
                .crypto_state
                .epoch
                .checked_add(1)
                .ok_or(GroupError::InvalidCryptoState)?;
            if next.capability_id.as_deref() != Some(current_capability.as_str())
                || next.epoch != expected_epoch
                || next.state_ref == group.crypto_state.state_ref
            {
                return Err(GroupError::InvalidCryptoState);
            }
            group.crypto_state = next.clone();
            Ok(())
        }
    }
}

fn member_index(memberships: &[GroupMembership], principal: &PrincipalRef) -> Option<usize> {
    memberships
        .iter()
        .position(|membership| membership.member == *principal)
}

fn active_member_index(memberships: &[GroupMembership], principal: &PrincipalRef) -> Option<usize> {
    memberships.iter().position(|membership| {
        membership.member == *principal && membership.state == GroupMemberState::Active
    })
}

fn require_manage_members(role: GroupRole) -> Result<(), GroupError> {
    if matches!(role, GroupRole::Owner | GroupRole::Admin) {
        Ok(())
    } else {
        Err(GroupError::PermissionDenied)
    }
}

fn require_manage_group(role: GroupRole) -> Result<(), GroupError> {
    require_manage_members(role)
}

fn push_scope(bytes: &mut Vec<u8>, scope: &TenantScope) {
    push_bytes(bytes, scope.tenant_id.as_opaque().as_wire_bytes());
    if let Some(namespace) = &scope.namespace_id {
        bytes.push(1);
        push_bytes(bytes, namespace.as_opaque().as_wire_bytes());
    } else {
        bytes.push(0);
    }
}

fn push_principal(bytes: &mut Vec<u8>, principal: &PrincipalRef) {
    push_bytes(bytes, principal.principal_id.as_opaque().as_wire_bytes());
    bytes.push(principal_kind_code(principal.kind));
}

fn push_crypto_state(bytes: &mut Vec<u8>, state: &GroupCryptoState) {
    if let Some(capability) = &state.capability_id {
        bytes.push(1);
        push_bytes(bytes, capability.as_bytes());
    } else {
        bytes.push(0);
    }
    bytes.extend_from_slice(&state.epoch.to_be_bytes());
    if let Some(state_ref) = &state.state_ref {
        bytes.push(1);
        push_bytes(bytes, state_ref.as_wire_bytes());
    } else {
        bytes.push(0);
    }
}

fn push_history_policy(bytes: &mut Vec<u8>, policy: &GroupHistoryPolicy) {
    match policy {
        GroupHistoryPolicy::NoHistory => bytes.push(1),
        GroupHistoryPolicy::FromJoin => bytes.push(2),
        GroupHistoryPolicy::LastNMessages(count) => {
            bytes.push(3);
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        GroupHistoryPolicy::FromTimestamp(timestamp) => {
            bytes.push(4);
            bytes.extend_from_slice(&timestamp.to_be_bytes());
        }
        GroupHistoryPolicy::FullHistory => bytes.push(5),
        GroupHistoryPolicy::CustomPolicy(identifier) => {
            bytes.push(6);
            push_bytes(bytes, identifier.as_bytes());
        }
    }
}

fn push_public_policy(bytes: &mut Vec<u8>, policy: &PublicGroupPolicy) {
    bytes.push(match policy.join_policy {
        ucr_model::PublicGroupJoinPolicy::Open => 1,
        ucr_model::PublicGroupJoinPolicy::ApprovalRequired => 2,
        ucr_model::PublicGroupJoinPolicy::InviteOnly => 3,
    });
    bytes.push(match policy.discovery {
        ucr_model::PublicGroupDiscovery::Unlisted => 1,
        ucr_model::PublicGroupDiscovery::Discoverable => 2,
    });
    bytes.push(u8::from(policy.indexed));
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

const fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Person => 1,
        PrincipalKind::Device => 2,
        PrincipalKind::ServiceAccount => 3,
        PrincipalKind::AiAgent => 4,
        PrincipalKind::Bot => 5,
        PrincipalKind::Organization => 6,
        PrincipalKind::Automation => 7,
        PrincipalKind::ExternalPlatform => 8,
    }
}

const fn delivery_policy_code(policy: DeliveryPolicy) -> u8 {
    match policy {
        DeliveryPolicy::BestEffort => 1,
        DeliveryPolicy::Durable => 2,
        DeliveryPolicy::Urgent => 3,
        DeliveryPolicy::Expiring => 4,
        DeliveryPolicy::LocalOnly => 5,
        DeliveryPolicy::DirectOnly => 6,
        DeliveryPolicy::NoRelay => 7,
        DeliveryPolicy::NoExternalBridge => 8,
        DeliveryPolicy::PrivateNetworkOnly => 9,
    }
}

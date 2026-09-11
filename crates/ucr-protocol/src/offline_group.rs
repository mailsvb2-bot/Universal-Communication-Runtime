use sha2::{Digest, Sha256};
use ucr_model::{
    ConversationKind, DeliveryState, GroupId, OfflineGroupChangeReplica, OfflineGroupCursor,
    OfflineGroupMessageReplica, OfflineGroupStreamKind, TenantScope,
};

use crate::{canonical_message, group_change_fingerprint};

pub const OFFLINE_GROUPS_CAPABILITY: &str = "ucr.group.offline_sync";
pub const MAX_OFFLINE_GROUP_PAGE_ITEMS: usize = 256;
pub const OFFLINE_GROUP_CURSOR_LEN: usize = 24;
const CURSOR_DOMAIN: &[u8] = b"UCR-OFFLINE-GROUP-CURSOR-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineGroupError {
    InvalidPageSize,
    InvalidCursor,
    ScopeMismatch,
    GroupMismatch,
    InvalidGeneration,
    InvalidMessage,
    MissingSignature,
}

#[must_use]
pub const fn phase26_offline_group_capabilities() -> [&'static str; 1] {
    [OFFLINE_GROUPS_CAPABILITY]
}

/// Validates one bounded page request.
///
/// # Errors
/// Returns `InvalidPageSize` for zero or above-limit requests.
pub fn validate_offline_group_page_size(max_items: usize) -> Result<(), OfflineGroupError> {
    if max_items == 0 || max_items > MAX_OFFLINE_GROUP_PAGE_ITEMS {
        Err(OfflineGroupError::InvalidPageSize)
    } else {
        Ok(())
    }
}

/// Canonicalizes a new Group-change replication record.
///
/// # Errors
/// Rejects scope/group/generation mismatch. The canonical Group owner still performs the
/// security-sensitive role/revision/crypto transition when the record is applied.
pub fn canonical_offline_group_change_replica(
    record: &OfflineGroupChangeReplica,
) -> Result<OfflineGroupChangeReplica, OfflineGroupError> {
    if record.actor.scope != record.change.scope {
        return Err(OfflineGroupError::ScopeMismatch);
    }
    if record.group_generation == 0
        || record.group_generation != record.change.expected_revision.saturating_add(1)
    {
        return Err(OfflineGroupError::InvalidGeneration);
    }
    group_change_fingerprint(&record.change).map_err(|_| OfflineGroupError::GroupMismatch)?;
    Ok(record.clone())
}

/// Canonicalizes one Message replication record without weakening Message validation.
///
/// # Errors
/// Rejects scope/group/provenance mismatch, unsupported author principal kinds, or malformed Messages.
pub fn canonical_offline_group_message_replica(
    record: &OfflineGroupMessageReplica,
) -> Result<OfflineGroupMessageReplica, OfflineGroupError> {
    let message =
        canonical_message(&record.message).map_err(|_| OfflineGroupError::InvalidMessage)?;
    if record.author.scope != message.scope {
        return Err(OfflineGroupError::ScopeMismatch);
    }
    if !matches!(
        message.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return Err(OfflineGroupError::GroupMismatch);
    }
    if message.origin.principal_id.as_ref() != Some(&record.author.principal.principal_id) {
        return Err(OfflineGroupError::InvalidMessage);
    }
    if message.delivery_state != DeliveryState::Persisted {
        return Err(OfflineGroupError::InvalidMessage);
    }
    if message.signature.is_none() {
        return Err(OfflineGroupError::MissingSignature);
    }
    Ok(OfflineGroupMessageReplica {
        author: record.author.clone(),
        group_id: record.group_id.clone(),
        group_generation: record.group_generation,
        message,
    })
}

/// Produces an opaque, stream- and Group-bound source cursor.
#[must_use]
pub fn offline_group_cursor(
    scope: &TenantScope,
    group_id: &GroupId,
    stream: OfflineGroupStreamKind,
    source_sequence: u64,
) -> OfflineGroupCursor {
    let binding = cursor_binding(scope, group_id, stream);
    let mut token = Vec::with_capacity(OFFLINE_GROUP_CURSOR_LEN);
    token.extend_from_slice(&binding[..16]);
    token.extend_from_slice(&source_sequence.to_be_bytes());
    OfflineGroupCursor { token }
}

/// Decodes one cursor only for the exact source Group stream that issued it.
///
/// # Errors
/// Returns `InvalidCursor` for malformed or cross-Group/cross-stream reuse.
pub fn offline_group_cursor_sequence(
    scope: &TenantScope,
    group_id: &GroupId,
    stream: OfflineGroupStreamKind,
    cursor: &OfflineGroupCursor,
) -> Result<u64, OfflineGroupError> {
    if cursor.token.len() != OFFLINE_GROUP_CURSOR_LEN {
        return Err(OfflineGroupError::InvalidCursor);
    }
    let binding = cursor_binding(scope, group_id, stream);
    if cursor.token[..16] != binding[..16] {
        return Err(OfflineGroupError::InvalidCursor);
    }
    let mut sequence = [0_u8; 8];
    sequence.copy_from_slice(&cursor.token[16..]);
    Ok(u64::from_be_bytes(sequence))
}

fn cursor_binding(
    scope: &TenantScope,
    group_id: &GroupId,
    stream: OfflineGroupStreamKind,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CURSOR_DOMAIN);
    hasher.update(scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hasher.update([1]);
            hasher.update(namespace.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(group_id.as_opaque().as_wire_bytes());
    hasher.update([match stream {
        OfflineGroupStreamKind::Changes => 1,
        OfflineGroupStreamKind::Messages => 2,
    }]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{NamespaceId, OpaqueId, TenantId};

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-offline").expect("id")),
            namespace_id: Some(NamespaceId::from_opaque(
                OpaqueId::new("ns-offline").expect("id"),
            )),
        }
    }

    #[test]
    fn cursor_is_bound_to_group_and_stream() {
        let scope = scope();
        let group = GroupId::from_opaque(OpaqueId::new("group-a").expect("id"));
        let other = GroupId::from_opaque(OpaqueId::new("group-b").expect("id"));
        let cursor = offline_group_cursor(&scope, &group, OfflineGroupStreamKind::Messages, 42);
        assert_eq!(
            offline_group_cursor_sequence(
                &scope,
                &group,
                OfflineGroupStreamKind::Messages,
                &cursor
            ),
            Ok(42)
        );
        assert_eq!(
            offline_group_cursor_sequence(
                &scope,
                &other,
                OfflineGroupStreamKind::Messages,
                &cursor
            ),
            Err(OfflineGroupError::InvalidCursor)
        );
        assert_eq!(
            offline_group_cursor_sequence(&scope, &group, OfflineGroupStreamKind::Changes, &cursor),
            Err(OfflineGroupError::InvalidCursor)
        );
    }

    #[test]
    fn page_size_is_bounded() {
        assert_eq!(validate_offline_group_page_size(1), Ok(()));
        assert_eq!(validate_offline_group_page_size(256), Ok(()));
        assert_eq!(
            validate_offline_group_page_size(0),
            Err(OfflineGroupError::InvalidPageSize)
        );
        assert_eq!(
            validate_offline_group_page_size(257),
            Err(OfflineGroupError::InvalidPageSize)
        );
    }
}

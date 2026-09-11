use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use ucr_model::{
    DeviceId, GroupId, MeshCursor, MeshGroupMessageReplica, PrincipalKind, TenantScope,
};

use crate::canonical_offline_group_message_replica;

pub const MESH_GROUPS_CAPABILITY: &str = "ucr.group.mesh_sync";
pub const MAX_MESH_GROUP_PAGE_ITEMS: usize = 256;
pub const MAX_MESH_PATH_DEVICES: usize = 8;
pub const MESH_CURSOR_LEN: usize = 24;
const CURSOR_DOMAIN: &[u8] = b"UCR-MESH-GROUP-CURSOR-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshError {
    InvalidPageSize,
    InvalidCursor,
    InvalidReplica,
    NonDeviceAuthor,
    EmptyPath,
    PathTooLong,
    DuplicateDevice,
    AuthorPathMismatch,
    SourcePathMismatch,
    RecipientLoop,
}

#[must_use]
pub const fn phase28_mesh_capabilities() -> [&'static str; 1] {
    [MESH_GROUPS_CAPABILITY]
}

/// Validates one bounded Mesh page request.
///
/// # Errors
/// Returns `InvalidPageSize` for zero or above-limit requests.
pub const fn validate_mesh_group_page_size(max_items: usize) -> Result<(), MeshError> {
    if max_items == 0 || max_items > MAX_MESH_GROUP_PAGE_ITEMS {
        Err(MeshError::InvalidPageSize)
    } else {
        Ok(())
    }
}

/// Canonicalizes a signed Group Message plus its already-traversed Device path.
///
/// The path is non-authoritative routing metadata. The canonical Message signature and Group
/// membership remain independently validated by their existing owners.
///
/// # Errors
/// Rejects malformed Message replicas, non-Device authors, empty/oversized/looped paths, or a path
/// whose first Device is not the Message author Device.
pub fn canonical_mesh_group_message_replica(
    replica: &MeshGroupMessageReplica,
) -> Result<MeshGroupMessageReplica, MeshError> {
    let record = canonical_offline_group_message_replica(&replica.record)
        .map_err(|_| MeshError::InvalidReplica)?;
    if record.author.principal.kind != PrincipalKind::Device {
        return Err(MeshError::NonDeviceAuthor);
    }
    if record
        .author
        .principal
        .principal_id
        .as_opaque()
        .as_wire_bytes()
        != record
            .message
            .author_device
            .device_id
            .as_opaque()
            .as_wire_bytes()
    {
        return Err(MeshError::AuthorPathMismatch);
    }
    if replica.forward_path.is_empty() {
        return Err(MeshError::EmptyPath);
    }
    if replica.forward_path.len() > MAX_MESH_PATH_DEVICES {
        return Err(MeshError::PathTooLong);
    }
    if replica.forward_path.first() != Some(&record.message.author_device.device_id) {
        return Err(MeshError::AuthorPathMismatch);
    }
    let mut seen = BTreeSet::new();
    for device in &replica.forward_path {
        if !seen.insert(device.as_opaque().as_str()) {
            return Err(MeshError::DuplicateDevice);
        }
    }
    Ok(MeshGroupMessageReplica {
        record,
        forward_path: replica.forward_path.clone(),
    })
}

/// Checks that the authenticated exporting peer is exactly the current end of the path.
///
/// # Errors
/// Returns `SourcePathMismatch` when another Device tries to re-export someone else's path state.
pub fn validate_mesh_source(
    replica: &MeshGroupMessageReplica,
    source_device_id: &DeviceId,
) -> Result<(), MeshError> {
    let canonical = canonical_mesh_group_message_replica(replica)?;
    if canonical.forward_path.last() == Some(source_device_id) {
        Ok(())
    } else {
        Err(MeshError::SourcePathMismatch)
    }
}

/// Extends one canonical path with the receiving Device.
///
/// # Errors
/// Rejects loops or the finite hop ceiling before mutation.
pub fn append_mesh_recipient(
    replica: &MeshGroupMessageReplica,
    recipient_device_id: &DeviceId,
) -> Result<MeshGroupMessageReplica, MeshError> {
    let mut canonical = canonical_mesh_group_message_replica(replica)?;
    if canonical.forward_path.contains(recipient_device_id) {
        return Err(MeshError::RecipientLoop);
    }
    if canonical.forward_path.len() >= MAX_MESH_PATH_DEVICES {
        return Err(MeshError::PathTooLong);
    }
    canonical.forward_path.push(recipient_device_id.clone());
    Ok(canonical)
}

/// Produces an opaque scope/Group-bound cursor over the Mesh export sequence.
#[must_use]
pub fn mesh_group_cursor(
    scope: &TenantScope,
    group_id: &GroupId,
    source_sequence: u64,
) -> MeshCursor {
    let binding = cursor_binding(scope, group_id);
    let mut token = Vec::with_capacity(MESH_CURSOR_LEN);
    token.extend_from_slice(&binding[..16]);
    token.extend_from_slice(&source_sequence.to_be_bytes());
    MeshCursor { token }
}

/// Decodes one cursor only for the exact scope and Group that issued it.
///
/// # Errors
/// Returns `InvalidCursor` for malformed or cross-scope/Group reuse.
pub fn mesh_group_cursor_sequence(
    scope: &TenantScope,
    group_id: &GroupId,
    cursor: &MeshCursor,
) -> Result<u64, MeshError> {
    if cursor.token.len() != MESH_CURSOR_LEN {
        return Err(MeshError::InvalidCursor);
    }
    let binding = cursor_binding(scope, group_id);
    if cursor.token[..16] != binding[..16] {
        return Err(MeshError::InvalidCursor);
    }
    let mut sequence = [0_u8; 8];
    sequence.copy_from_slice(&cursor.token[16..]);
    Ok(u64::from_be_bytes(sequence))
}

fn cursor_binding(scope: &TenantScope, group_id: &GroupId) -> [u8; 32] {
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
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("mesh-tenant")),
            namespace_id: None,
        }
    }

    fn device(value: &str) -> DeviceId {
        DeviceId::from_opaque(oid(value))
    }

    fn replica() -> MeshGroupMessageReplica {
        let author_device = device("device-a");
        MeshGroupMessageReplica {
            record: OfflineGroupMessageReplica {
                author: ScopedPrincipal {
                    scope: scope(),
                    principal: PrincipalRef {
                        principal_id: PrincipalId::from_opaque(oid("device-a")),
                        kind: PrincipalKind::Device,
                    },
                },
                group_id: GroupId::from_opaque(oid("group-a")),
                group_generation: 1,
                message: MessageEnvelope {
                    message_id: MessageId::from_opaque(oid("message-a")),
                    scope: scope(),
                    conversation: ConversationRef {
                        conversation_id: ConversationId::from_opaque(oid("conversation-a")),
                        kind: ConversationKind::PrivateGroup,
                    },
                    author: ActorRef {
                        actor_id: ActorId::from_opaque(oid("actor-a")),
                        kind: ActorKind::Person,
                        on_behalf_of: None,
                    },
                    author_device: DeviceRef {
                        device_id: author_device.clone(),
                        identity_id: IdentityId::from_opaque(oid("identity-a")),
                    },
                    created_at_unix_ms: 1,
                    logical_order: 1,
                    content: b"hello".to_vec(),
                    attachment_ids: vec![],
                    reply_to: None,
                    relations: vec![],
                    crypto_metadata: None,
                    delivery_policy: DeliveryPolicy::Durable,
                    delivery_state: DeliveryState::Persisted,
                    origin: OriginRef {
                        principal_id: Some(PrincipalId::from_opaque(oid("device-a"))),
                        endpoint_id: None,
                        integration_id: None,
                    },
                    correlation: CorrelationContext {
                        correlation_id: oid("corr"),
                        causation_id: None,
                        idempotency_key: None,
                    },
                    extensions: vec![],
                    external_mappings: vec![],
                    signature: Some(MessageSignature {
                        key_id: KeyId::from_opaque(oid("key-a")),
                        algorithm_id: "ed25519".into(),
                        algorithm_version: 1,
                        signature: vec![7; 64],
                    }),
                },
            },
            forward_path: vec![author_device],
        }
    }

    #[test]
    fn mesh_path_is_bounded_loop_free_and_author_bound() {
        let first = replica();
        assert!(canonical_mesh_group_message_replica(&first).is_ok());
        let second = append_mesh_recipient(&first, &device("device-b")).expect("append");
        assert_eq!(second.forward_path.len(), 2);
        assert_eq!(
            append_mesh_recipient(&second, &device("device-a")),
            Err(MeshError::RecipientLoop)
        );
        assert_eq!(
            validate_mesh_source(&second, &device("device-a")),
            Err(MeshError::SourcePathMismatch)
        );
    }

    #[test]
    fn mesh_cursor_is_scope_and_group_bound() {
        let group = GroupId::from_opaque(oid("group-a"));
        let other = GroupId::from_opaque(oid("group-b"));
        let cursor = mesh_group_cursor(&scope(), &group, 9);
        assert_eq!(mesh_group_cursor_sequence(&scope(), &group, &cursor), Ok(9));
        assert_eq!(
            mesh_group_cursor_sequence(&scope(), &other, &cursor),
            Err(MeshError::InvalidCursor)
        );
    }
}

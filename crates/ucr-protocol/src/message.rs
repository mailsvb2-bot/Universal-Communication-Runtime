use std::collections::BTreeSet;

use ucr_model::{
    ConversationKind, ConversationRecord, ExternalMessageMapping, MessageEnvelope,
    MessageRelationKind, MessageSignature,
};

use crate::{
    ALGORITHM_VERSION, DEFAULT_MAX_PAYLOAD_LEN, SIGNATURE_ALGORITHM_ID, SIGNATURE_LEN,
    validate_origin_ref,
};

pub const MESSAGE_ATTACHMENT_LIMIT: usize = 128;
pub const MESSAGE_RELATION_LIMIT: usize = 128;
pub const EXTERNAL_MESSAGE_MAPPING_LIMIT: usize = 64;
pub const EXTERNAL_MESSAGE_ID_LIMIT: usize = 2_048;
pub const MESSAGE_CRYPTO_METADATA_LIMIT: usize = 16 * 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationError {
    SelfParent,
    MissingHierarchicalParent,
    UnexpectedParent,
    InvalidParentKind,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    ContentTooLarge,
    TooManyAttachments,
    DuplicateAttachment,
    TooManyRelations,
    DuplicateRelation,
    SelfRelation,
    ReplyProjectionMismatch,
    EmptyMessage,
    CryptoMetadataTooLarge,
    TooManyExternalMappings,
    EmptyExternalMessageId,
    ExternalMessageIdTooLarge,
    DuplicateExternalMapping,
    EmptyOrigin,
    InvalidSignature,
}

/// Validates provider-independent Conversation structure.
///
/// # Errors
/// Rejects self-parenting and Topic/Thread records without a parent.
pub fn validate_conversation(record: &ConversationRecord) -> Result<(), ConversationError> {
    if record.parent_conversation_id.as_ref() == Some(&record.conversation.conversation_id) {
        return Err(ConversationError::SelfParent);
    }
    let hierarchical = matches!(
        record.conversation.kind,
        ConversationKind::Topic | ConversationKind::Thread
    );
    if hierarchical && record.parent_conversation_id.is_none() {
        return Err(ConversationError::MissingHierarchicalParent);
    }
    if !hierarchical && record.parent_conversation_id.is_some() {
        return Err(ConversationError::UnexpectedParent);
    }
    Ok(())
}

/// Validates the kind relationship after the parent Conversation is loaded.
///
/// # Errors
/// A Topic must attach to a root Conversation; a Thread must attach to a Topic.
pub const fn validate_conversation_parent_kind(
    child: ConversationKind,
    parent: ConversationKind,
) -> Result<(), ConversationError> {
    match child {
        ConversationKind::Topic => {
            if matches!(parent, ConversationKind::Topic | ConversationKind::Thread) {
                Err(ConversationError::InvalidParentKind)
            } else {
                Ok(())
            }
        }
        ConversationKind::Thread => {
            if matches!(parent, ConversationKind::Topic) {
                Ok(())
            } else {
                Err(ConversationError::InvalidParentKind)
            }
        }
        _ => Err(ConversationError::UnexpectedParent),
    }
}

/// Validates the canonical Message envelope before durable persistence.
///
/// # Errors
/// Rejects oversized/ambiguous bodies, malformed relationships, provenance,
/// external mappings, crypto metadata, or signatures.
pub fn validate_message(message: &MessageEnvelope) -> Result<(), MessageError> {
    let content_len =
        u32::try_from(message.content.len()).map_err(|_| MessageError::ContentTooLarge)?;
    if content_len > DEFAULT_MAX_PAYLOAD_LEN {
        return Err(MessageError::ContentTooLarge);
    }
    if message.attachment_ids.len() > MESSAGE_ATTACHMENT_LIMIT {
        return Err(MessageError::TooManyAttachments);
    }
    let mut attachments = BTreeSet::new();
    for attachment in &message.attachment_ids {
        if !attachments.insert(attachment.as_opaque().as_str()) {
            return Err(MessageError::DuplicateAttachment);
        }
    }
    if message.relations.len() > MESSAGE_RELATION_LIMIT {
        return Err(MessageError::TooManyRelations);
    }
    let mut relations = BTreeSet::new();
    let mut reply_relation = None;
    for relation in &message.relations {
        if relation.target_message_id == message.message_id {
            return Err(MessageError::SelfRelation);
        }
        let key = (
            relation.kind as u8,
            relation.target_message_id.as_opaque().as_str(),
        );
        if !relations.insert(key) {
            return Err(MessageError::DuplicateRelation);
        }
        if relation.kind == MessageRelationKind::Reply
            && reply_relation
                .replace(&relation.target_message_id)
                .is_some()
        {
            return Err(MessageError::DuplicateRelation);
        }
    }
    match (&message.reply_to, reply_relation) {
        (Some(projected), Some(related)) if projected == related => {}
        (None, None) => {}
        _ => return Err(MessageError::ReplyProjectionMismatch),
    }
    if message.content.is_empty()
        && message.attachment_ids.is_empty()
        && message.relations.is_empty()
    {
        return Err(MessageError::EmptyMessage);
    }
    if let Some(metadata) = &message.crypto_metadata
        && metadata.opaque_metadata.len() > MESSAGE_CRYPTO_METADATA_LIMIT
    {
        return Err(MessageError::CryptoMetadataTooLarge);
    }
    if message.external_mappings.len() > EXTERNAL_MESSAGE_MAPPING_LIMIT {
        return Err(MessageError::TooManyExternalMappings);
    }
    validate_external_mappings(&message.external_mappings)?;
    validate_origin_ref(&message.origin).map_err(|_| MessageError::EmptyOrigin)?;
    if let Some(signature) = &message.signature {
        validate_message_signature(signature)?;
    }
    Ok(())
}

/// Returns the deterministic semantic representation used by durable stores.
///
/// Relation and external-mapping order is not semantic; attachment order is.
///
/// # Errors
/// Returns the same fail-closed errors as [`validate_message`].
pub fn canonical_message(message: &MessageEnvelope) -> Result<MessageEnvelope, MessageError> {
    validate_message(message)?;
    let mut canonical = message.clone();
    canonical.relations.sort_by(|left, right| {
        relation_rank(left.kind)
            .cmp(&relation_rank(right.kind))
            .then_with(|| {
                left.target_message_id
                    .as_opaque()
                    .as_str()
                    .cmp(right.target_message_id.as_opaque().as_str())
            })
    });
    canonical.external_mappings.sort_by(|left, right| {
        left.integration_id
            .as_opaque()
            .as_str()
            .cmp(right.integration_id.as_opaque().as_str())
    });
    Ok(canonical)
}

const fn relation_rank(kind: MessageRelationKind) -> u8 {
    match kind {
        MessageRelationKind::Reply => 1,
        MessageRelationKind::Quote => 2,
        MessageRelationKind::Edit => 3,
        MessageRelationKind::Reaction => 4,
        MessageRelationKind::ThreadParent => 5,
        MessageRelationKind::Forward => 6,
        MessageRelationKind::Reference => 7,
    }
}

fn validate_external_mappings(mappings: &[ExternalMessageMapping]) -> Result<(), MessageError> {
    let mut integrations = BTreeSet::new();
    for mapping in mappings {
        if mapping.external_message_id.is_empty() {
            return Err(MessageError::EmptyExternalMessageId);
        }
        if mapping.external_message_id.len() > EXTERNAL_MESSAGE_ID_LIMIT {
            return Err(MessageError::ExternalMessageIdTooLarge);
        }
        if !integrations.insert(mapping.integration_id.as_opaque().as_str()) {
            return Err(MessageError::DuplicateExternalMapping);
        }
    }
    Ok(())
}

fn validate_message_signature(signature: &MessageSignature) -> Result<(), MessageError> {
    if signature.algorithm_id != SIGNATURE_ALGORITHM_ID
        || signature.algorithm_version != ALGORITHM_VERSION
        || signature.signature.len() != SIGNATURE_LEN
    {
        return Err(MessageError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::*;

    use super::*;
    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn message() -> MessageEnvelope {
        let reply = MessageId::from_opaque(oid("message-parent"));
        MessageEnvelope {
            message_id: MessageId::from_opaque(oid("message-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: None,
            },
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation-a")),
                kind: ConversationKind::Direct,
            },
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"hello".to_vec(),
            attachment_ids: vec![AttachmentId::from_opaque(oid("attachment-a"))],
            reply_to: Some(reply.clone()),
            relations: vec![MessageRelation {
                kind: MessageRelationKind::Reply,
                target_message_id: reply,
            }],
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(PrincipalId::from_opaque(oid("principal-a"))),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: None,
                idempotency_key: Some("message-idempotency-a".into()),
            },
            external_mappings: Vec::new(),
            signature: None,
        }
    }
    #[test]
    fn canonical_message_is_accepted() {
        assert_eq!(validate_message(&message()), Ok(()));
    }

    #[test]
    fn reply_projection_must_match_relation() {
        let mut value = message();
        value.reply_to = Some(MessageId::from_opaque(oid("different-parent")));
        assert_eq!(
            validate_message(&value),
            Err(MessageError::ReplyProjectionMismatch)
        );
    }

    #[test]
    fn self_relation_and_empty_message_fail_closed() {
        let mut value = message();
        value.relations[0].target_message_id = value.message_id.clone();
        assert_eq!(validate_message(&value), Err(MessageError::SelfRelation));

        let mut empty = message();
        empty.content.clear();
        empty.attachment_ids.clear();
        empty.relations.clear();
        empty.reply_to = None;
        assert_eq!(validate_message(&empty), Err(MessageError::EmptyMessage));
    }
    #[test]
    fn topic_and_thread_require_parent_and_cannot_self_parent() {
        let topic_id = ConversationId::from_opaque(oid("topic-a"));
        let mut topic = ConversationRecord {
            scope: message().scope,
            conversation: ConversationRef {
                conversation_id: topic_id.clone(),
                kind: ConversationKind::Topic,
            },
            parent_conversation_id: None,
        };
        assert_eq!(
            validate_conversation(&topic),
            Err(ConversationError::MissingHierarchicalParent)
        );
        topic.parent_conversation_id = Some(topic_id);
        assert_eq!(
            validate_conversation(&topic),
            Err(ConversationError::SelfParent)
        );

        assert_eq!(
            validate_conversation_parent_kind(ConversationKind::Topic, ConversationKind::Direct),
            Ok(())
        );
        assert_eq!(
            validate_conversation_parent_kind(ConversationKind::Thread, ConversationKind::Topic),
            Ok(())
        );
        assert_eq!(
            validate_conversation_parent_kind(ConversationKind::Thread, ConversationKind::Direct),
            Err(ConversationError::InvalidParentKind)
        );
        let root_with_parent = ConversationRecord {
            scope: message().scope,
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("root-a")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: Some(ConversationId::from_opaque(oid("other-root"))),
        };
        assert_eq!(
            validate_conversation(&root_with_parent),
            Err(ConversationError::UnexpectedParent)
        );
    }
}

use sha2::{Digest, Sha256};
use ucr_model::{
    ActorKind, ConversationKind, DeliveryPolicy, MessageEnvelope, MessageRelationKind, OpaqueId,
};

use crate::{MessageError, canonical_message};

pub const MESSAGE_SIGNING_BINDING_V1_DOMAIN: &[u8] = b"UCR-MESSAGE-SIGNING-BINDING-V1\0";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageSigningBinding([u8; 32]);

impl core::fmt::Debug for MessageSigningBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("MessageSigningBinding")
            .field(&"<sha256>")
            .finish()
    }
}

impl MessageSigningBinding {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Produces the versioned canonical authored-Message binding used for signatures.
///
/// Delivery state, provider external mappings, and signature metadata are intentionally
/// excluded because they are runtime/provider/result material rather than authored content.
///
/// # Errors
/// Returns the same validation failures as [`canonical_message`].
pub fn message_signing_binding(
    message: &MessageEnvelope,
) -> Result<MessageSigningBinding, MessageError> {
    let canonical = canonical_message(message)?;
    let mut hash = Sha256::new();
    hash.update(MESSAGE_SIGNING_BINDING_V1_DOMAIN);
    hash_id(&mut hash, canonical.message_id.as_opaque());
    hash_scope(&mut hash, &canonical.scope);
    hash_id(
        &mut hash,
        canonical.conversation.conversation_id.as_opaque(),
    );
    hash.update([conversation_kind_code(canonical.conversation.kind)]);
    hash_id(&mut hash, canonical.author.actor_id.as_opaque());
    hash.update([actor_kind_code(canonical.author.kind)]);
    hash_optional_id(
        &mut hash,
        canonical
            .author
            .on_behalf_of
            .as_ref()
            .map(ucr_model::PrincipalId::as_opaque),
    );
    hash_id(&mut hash, canonical.author_device.device_id.as_opaque());
    hash_id(&mut hash, canonical.author_device.identity_id.as_opaque());
    hash.update(canonical.created_at_unix_ms.to_be_bytes());
    hash.update(canonical.logical_order.to_be_bytes());
    hash_bytes(&mut hash, &canonical.content);
    hash.update((canonical.attachment_ids.len() as u64).to_be_bytes());
    for attachment in &canonical.attachment_ids {
        hash_id(&mut hash, attachment.as_opaque());
    }
    hash_optional_id(
        &mut hash,
        canonical
            .reply_to
            .as_ref()
            .map(ucr_model::MessageId::as_opaque),
    );
    hash.update((canonical.relations.len() as u64).to_be_bytes());
    for relation in &canonical.relations {
        hash.update([relation_kind_code(relation.kind)]);
        hash_id(&mut hash, relation.target_message_id.as_opaque());
    }
    match &canonical.crypto_metadata {
        None => hash.update([0]),
        Some(metadata) => {
            hash.update([1]);
            hash.update((metadata.suite as u32).to_be_bytes());
            hash_optional_id(
                &mut hash,
                metadata.key_id.as_ref().map(ucr_model::KeyId::as_opaque),
            );
            hash_bytes(&mut hash, &metadata.opaque_metadata);
        }
    }
    hash.update([delivery_policy_code(canonical.delivery_policy)]);
    hash_optional_id(
        &mut hash,
        canonical
            .origin
            .principal_id
            .as_ref()
            .map(ucr_model::PrincipalId::as_opaque),
    );
    hash_optional_id(
        &mut hash,
        canonical
            .origin
            .endpoint_id
            .as_ref()
            .map(ucr_model::EndpointId::as_opaque),
    );
    hash_optional_id(
        &mut hash,
        canonical
            .origin
            .integration_id
            .as_ref()
            .map(ucr_model::IntegrationId::as_opaque),
    );
    hash_id(&mut hash, &canonical.correlation.correlation_id);
    hash_optional_id(&mut hash, canonical.correlation.causation_id.as_ref());
    hash_optional_string(&mut hash, canonical.correlation.idempotency_key.as_deref());
    hash.update((canonical.extensions.len() as u64).to_be_bytes());
    for extension in &canonical.extensions {
        hash_bytes(&mut hash, extension.name.as_bytes());
        hash.update([u8::from(extension.critical)]);
        hash_bytes(&mut hash, &extension.payload);
    }
    Ok(MessageSigningBinding(hash.finalize().into()))
}

fn hash_scope(hash: &mut Sha256, scope: &ucr_model::TenantScope) {
    hash_id(hash, scope.tenant_id.as_opaque());
    hash_optional_id(
        hash,
        scope
            .namespace_id
            .as_ref()
            .map(ucr_model::NamespaceId::as_opaque),
    );
}

fn hash_id(hash: &mut Sha256, id: &OpaqueId) {
    hash_bytes(hash, id.as_wire_bytes());
}

fn hash_optional_id(hash: &mut Sha256, id: Option<&OpaqueId>) {
    match id {
        None => hash.update([0]),
        Some(id) => {
            hash.update([1]);
            hash_id(hash, id);
        }
    }
}

fn hash_optional_string(hash: &mut Sha256, value: Option<&str>) {
    match value {
        None => hash.update([0]),
        Some(value) => {
            hash.update([1]);
            hash_bytes(hash, value.as_bytes());
        }
    }
}

fn hash_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

const fn actor_kind_code(kind: ActorKind) -> u8 {
    match kind {
        ActorKind::Person => 1,
        ActorKind::AiAgent => 2,
        ActorKind::Bot => 3,
        ActorKind::Organization => 4,
        ActorKind::System => 5,
    }
}

const fn conversation_kind_code(kind: ConversationKind) -> u8 {
    match kind {
        ConversationKind::Direct => 1,
        ConversationKind::PrivateGroup => 2,
        ConversationKind::PublicGroup => 3,
        ConversationKind::Broadcast => 4,
        ConversationKind::Community => 5,
        ConversationKind::Room => 6,
        ConversationKind::Topic => 7,
        ConversationKind::Thread => 8,
        ConversationKind::System => 9,
    }
}

const fn relation_kind_code(kind: MessageRelationKind) -> u8 {
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
                namespace_id: Some(NamespaceId::from_opaque(oid("namespace-a"))),
            },
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation-a")),
                kind: ConversationKind::Direct,
            },
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::Person,
                on_behalf_of: Some(PrincipalId::from_opaque(oid("principal-delegator"))),
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            created_at_unix_ms: 1_700_000_000_123,
            logical_order: 42,
            content: b"hello signed world".to_vec(),
            attachment_ids: vec![AttachmentId::from_opaque(oid("attachment-a"))],
            reply_to: Some(reply.clone()),
            relations: vec![
                MessageRelation {
                    kind: MessageRelationKind::Quote,
                    target_message_id: MessageId::from_opaque(oid("message-quoted")),
                },
                MessageRelation {
                    kind: MessageRelationKind::Reply,
                    target_message_id: reply,
                },
            ],
            crypto_metadata: Some(MessageCryptoMetadata {
                suite: CryptoSuite::UcrV1,
                key_id: Some(KeyId::from_opaque(oid("content-key-a"))),
                opaque_metadata: b"content-crypto-metadata".to_vec(),
            }),
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(PrincipalId::from_opaque(oid("principal-a"))),
                endpoint_id: Some(EndpointId::from_opaque(oid("endpoint-a"))),
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: Some(oid("causation-a")),
                idempotency_key: Some("message-idempotency-a".to_owned()),
            },
            extensions: vec![
                ProtocolExtension {
                    name: "vendor.example.z".to_owned(),
                    critical: false,
                    payload: b"z".to_vec(),
                },
                ProtocolExtension {
                    name: "ucr.example.a".to_owned(),
                    critical: true,
                    payload: b"a".to_vec(),
                },
            ],
            external_mappings: Vec::new(),
            signature: None,
        }
    }

    #[test]
    fn signing_binding_has_stable_golden_vector() {
        let binding = message_signing_binding(&message()).expect("binding");
        assert_eq!(
            *binding.as_bytes(),
            [
                0xd7, 0x13, 0x67, 0x10, 0x71, 0x72, 0x32, 0x2c, 0xa4, 0x08, 0x61, 0x0f, 0x8a, 0x1d,
                0xe9, 0xb0, 0x0f, 0xff, 0x44, 0x38, 0x3f, 0x33, 0xee, 0x56, 0xe4, 0x31, 0x6f, 0xd5,
                0x04, 0x3d, 0x09, 0xd2,
            ]
        );
    }

    #[test]
    fn authored_fields_change_binding_but_runtime_provider_fields_do_not() {
        let base = message();
        let base_binding = message_signing_binding(&base).expect("base binding");

        let mut changed_content = base.clone();
        changed_content.content.push(b'!');
        assert_ne!(
            base_binding,
            message_signing_binding(&changed_content).expect("content binding")
        );

        let mut changed_device = base.clone();
        changed_device.author_device.device_id = DeviceId::from_opaque(oid("device-b"));
        assert_ne!(
            base_binding,
            message_signing_binding(&changed_device).expect("device binding")
        );

        let mut runtime_only = base.clone();
        runtime_only.delivery_state = DeliveryState::Persisted;
        runtime_only.external_mappings.push(ExternalMessageMapping {
            integration_id: IntegrationId::from_opaque(oid("integration-a")),
            external_message_id: b"provider-message-a".to_vec(),
        });
        runtime_only.signature = Some(MessageSignature {
            key_id: KeyId::from_opaque(oid("signing-key-a")),
            algorithm_id: crate::SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: crate::ALGORITHM_VERSION,
            signature: vec![7_u8; crate::SIGNATURE_LEN],
        });
        assert_eq!(
            base_binding,
            message_signing_binding(&runtime_only).expect("runtime-only binding")
        );
    }

    #[test]
    fn nonsemantic_collection_order_does_not_change_binding() {
        let base = message();
        let base_binding = message_signing_binding(&base).expect("base binding");
        let mut reordered = base;
        reordered.relations.reverse();
        reordered.extensions.reverse();
        assert_eq!(
            base_binding,
            message_signing_binding(&reordered).expect("reordered binding")
        );
    }

    #[test]
    fn signing_binding_debug_redacts_digest() {
        let binding = MessageSigningBinding::from_bytes([0xAB; 32]);
        let debug = format!("{binding:?}");
        assert!(debug.contains("<sha256>"));
        assert!(!debug.contains("171"));
    }
}

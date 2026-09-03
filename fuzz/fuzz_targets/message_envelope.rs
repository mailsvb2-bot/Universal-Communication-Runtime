#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::*;
use ucr_protocol::{canonical_message, message_signing_binding, validate_message};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static fuzz id")
}

fn delivery_policy(value: u8) -> DeliveryPolicy {
    match value % 9 {
        0 => DeliveryPolicy::BestEffort,
        1 => DeliveryPolicy::Durable,
        2 => DeliveryPolicy::Urgent,
        3 => DeliveryPolicy::Expiring,
        4 => DeliveryPolicy::LocalOnly,
        5 => DeliveryPolicy::DirectOnly,
        6 => DeliveryPolicy::NoRelay,
        7 => DeliveryPolicy::NoExternalBridge,
        _ => DeliveryPolicy::PrivateNetworkOnly,
    }
}

fn delivery_state(value: u8) -> DeliveryState {
    match value % 11 {
        0 => DeliveryState::Created,
        1 => DeliveryState::Persisted,
        2 => DeliveryState::Encrypted,
        3 => DeliveryState::Queued,
        4 => DeliveryState::RoutePlanned,
        5 => DeliveryState::InFlight,
        6 => DeliveryState::Acknowledged,
        7 => DeliveryState::Delivered,
        8 => DeliveryState::Read,
        9 => DeliveryState::Failed,
        _ => DeliveryState::Expired,
    }
}

fuzz_target!(|data: &[u8]| {
    let flags = data.first().copied().unwrap_or(0);
    let parent = MessageId::from_opaque(oid("fuzz-parent"));
    let message_id = MessageId::from_opaque(oid("fuzz-message"));
    let mut relations = Vec::new();
    let mut reply_to = None;
    if flags & 1 != 0 {
        let target = if flags & 4 != 0 {
            message_id.clone()
        } else {
            parent.clone()
        };
        relations.push(MessageRelation {
            kind: MessageRelationKind::Reply,
            target_message_id: target,
        });
        reply_to = Some(if flags & 2 != 0 {
            MessageId::from_opaque(oid("fuzz-other"))
        } else {
            parent
        });
    }

    let mut attachment_ids = Vec::new();
    if flags & 8 != 0 {
        attachment_ids.push(AttachmentId::from_opaque(oid("fuzz-attachment")));
        if flags & 16 != 0 {
            attachment_ids.push(AttachmentId::from_opaque(oid("fuzz-attachment")));
        }
    }
    let content = data
        .get(4..)
        .unwrap_or_default()
        .iter()
        .take(2_048)
        .copied()
        .collect();
    let crypto_metadata = (flags & 32 != 0).then(|| MessageCryptoMetadata {
        suite: CryptoSuite::UcrV1,
        key_id: Some(KeyId::from_opaque(oid("fuzz-content-key"))),
        opaque_metadata: data.iter().skip(1).take(256).copied().collect(),
    });
    let mut extensions = Vec::new();
    if flags & 64 != 0 {
        extensions.push(ProtocolExtension {
            name: "ucr.fuzz.alpha".to_owned(),
            critical: false,
            payload: data.iter().skip(2).take(128).copied().collect(),
        });
        if flags & 128 != 0 {
            extensions.push(ProtocolExtension {
                name: "ucr.fuzz.alpha".to_owned(),
                critical: false,
                payload: Vec::new(),
            });
        }
    }

    let mut external_mappings = Vec::new();
    if data.get(1).copied().unwrap_or(0) & 1 != 0 {
        external_mappings.push(ExternalMessageMapping {
            integration_id: IntegrationId::from_opaque(oid("fuzz-integration")),
            external_message_id: data.iter().skip(3).take(128).copied().collect(),
        });
    }
    let origin = if data.get(2).copied().unwrap_or(0) & 1 == 0 {
        OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("fuzz-principal"))),
            endpoint_id: None,
            integration_id: None,
        }
    } else {
        OriginRef {
            principal_id: None,
            endpoint_id: None,
            integration_id: None,
        }
    };

    let message = MessageEnvelope {
        message_id,
        scope: TenantScope {
            tenant_id: TenantId::from_opaque(oid("fuzz-tenant")),
            namespace_id: Some(NamespaceId::from_opaque(oid("fuzz-namespace"))),
        },
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("fuzz-conversation")),
            kind: ConversationKind::Direct,
        },
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("fuzz-actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("fuzz-device")),
            identity_id: IdentityId::from_opaque(oid("fuzz-identity")),
        },
        created_at_unix_ms: i64::from(data.get(1).copied().unwrap_or(0)),
        logical_order: u64::from(data.get(2).copied().unwrap_or(0)),
        content,
        attachment_ids,
        reply_to,
        relations,
        crypto_metadata,
        delivery_policy: delivery_policy(data.get(1).copied().unwrap_or(0)),
        delivery_state: delivery_state(data.get(2).copied().unwrap_or(0)),
        origin,
        correlation: CorrelationContext {
            correlation_id: oid("fuzz-correlation"),
            causation_id: None,
            idempotency_key: None,
        },
        extensions,
        external_mappings,
        signature: None,
    };

    let validated = validate_message(&message);
    let canonical = canonical_message(&message);
    assert_eq!(validated.is_ok(), canonical.is_ok());
    if let Ok(canonical) = canonical {
        assert_eq!(canonical_message(&canonical), Ok(canonical.clone()));
        assert!(message_signing_binding(&canonical).is_ok());
    }
});

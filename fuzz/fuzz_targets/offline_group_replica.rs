#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, SIGNATURE_ALGORITHM_ID, canonical_offline_group_change_replica,
    canonical_offline_group_message_replica, offline_group_cursor, offline_group_cursor_sequence,
    validate_offline_group_page_size,
};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static fuzz id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("fuzz-offline-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("fuzz-offline-namespace"))),
    }
}

fn device_principal() -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("fuzz-offline-device")),
        kind: PrincipalKind::Device,
    }
}
fn signed_shape_message(data: &[u8], generation: u64) -> MessageEnvelope {
    let principal = device_principal();
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid("fuzz-offline-message")),
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("fuzz-offline-conversation")),
            kind: ConversationKind::PrivateGroup,
        },
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("fuzz-offline-actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("fuzz-offline-device")),
            identity_id: IdentityId::from_opaque(oid("fuzz-offline-identity")),
        },
        created_at_unix_ms: i64::try_from(generation).unwrap_or(i64::MAX),
        logical_order: generation,
        content: data.iter().take(2048).copied().collect(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Persisted,
        origin: OriginRef {
            principal_id: Some(principal.principal_id),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("fuzz-offline-correlation"),
            causation_id: None,
            idempotency_key: None,
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: Some(MessageSignature {
            key_id: KeyId::from_opaque(oid("fuzz-offline-key")),
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            signature: vec![data.first().copied().unwrap_or_default(); 64],
        }),
    }
}

fuzz_target!(|data: &[u8]| {
    let expected_revision = u64::from(data.first().copied().unwrap_or_default());
    let generation = u64::from(data.get(1).copied().unwrap_or_default());
    let scope = scope();
    let group_id = GroupId::from_opaque(oid("fuzz-offline-group"));
    let actor = ScopedPrincipal {
        scope: scope.clone(),
        principal: device_principal(),
    };
    let change = GroupChange {
        event_id: EventId::from_opaque(oid("fuzz-offline-change")),
        scope: scope.clone(),
        group_id: group_id.clone(),
        expected_revision,
        kind: GroupChangeKind::SetHistoryPolicy {
            policy: GroupHistoryPolicy::FullHistory,
        },
        next_crypto_state: None,
    };
    let change_record = OfflineGroupChangeReplica {
        actor: actor.clone(),
        group_generation: generation,
        change,
    };
    let change_result = canonical_offline_group_change_replica(&change_record);
    assert_eq!(
        change_result.is_ok(),
        generation != 0 && generation == expected_revision.saturating_add(1)
    );

    let message_record = OfflineGroupMessageReplica {
        author: actor,
        group_id: group_id.clone(),
        group_generation: generation,
        message: signed_shape_message(data, generation),
    };
    let _ = canonical_offline_group_message_replica(&message_record);

    let sequence = u64::from(data.get(2).copied().unwrap_or_default());
    let cursor = offline_group_cursor(
        &scope,
        &group_id,
        OfflineGroupStreamKind::Messages,
        sequence,
    );
    assert_eq!(
        offline_group_cursor_sequence(&scope, &group_id, OfflineGroupStreamKind::Messages, &cursor,),
        Ok(sequence)
    );
    assert!(
        offline_group_cursor_sequence(&scope, &group_id, OfflineGroupStreamKind::Changes, &cursor,)
            .is_err()
    );

    let requested = usize::from(data.get(3).copied().unwrap_or_default());
    let _ = validate_offline_group_page_size(requested);
});

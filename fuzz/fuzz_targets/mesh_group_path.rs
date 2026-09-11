#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::*;
use ucr_protocol::{
    append_mesh_recipient, canonical_mesh_group_message_replica, mesh_group_cursor,
    mesh_group_cursor_sequence, validate_mesh_group_page_size, validate_mesh_source,
};

fn oid(prefix: &str, value: u8) -> OpaqueId {
    OpaqueId::new(format!("{prefix}-{value:02x}")).expect("bounded fuzz id")
}

fn device(value: u8) -> DeviceId {
    DeviceId::from_opaque(oid("mesh-device", value))
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(
            OpaqueId::new("mesh-fuzz-tenant").expect("static tenant id"),
        ),
        namespace_id: None,
    }
}

fn replica(seed: u8, path_values: &[u8]) -> MeshGroupMessageReplica {
    let author = path_values.first().copied().unwrap_or(seed);
    let author_device = device(author);
    MeshGroupMessageReplica {
        record: OfflineGroupMessageReplica {
            author: ScopedPrincipal {
                scope: scope(),
                principal: PrincipalRef {
                    principal_id: PrincipalId::from_opaque(author_device.as_opaque().clone()),
                    kind: PrincipalKind::Device,
                },
            },
            group_id: GroupId::from_opaque(oid("mesh-group", seed)),
            group_generation: 1,
            message: MessageEnvelope {
                message_id: MessageId::from_opaque(oid("mesh-message", seed)),
                scope: scope(),
                conversation: ConversationRef {
                    conversation_id: ConversationId::from_opaque(oid("mesh-conversation", seed)),
                    kind: ConversationKind::PrivateGroup,
                },
                author: ActorRef {
                    actor_id: ActorId::from_opaque(oid("mesh-actor", seed)),
                    kind: ActorKind::Person,
                    on_behalf_of: None,
                },
                author_device: DeviceRef {
                    device_id: author_device,
                    identity_id: IdentityId::from_opaque(oid("mesh-identity", author)),
                },
                created_at_unix_ms: 1,
                logical_order: 1,
                content: vec![seed],
                attachment_ids: vec![],
                reply_to: None,
                relations: vec![],
                crypto_metadata: None,
                delivery_policy: DeliveryPolicy::Durable,
                delivery_state: DeliveryState::Persisted,
                origin: OriginRef {
                    principal_id: Some(PrincipalId::from_opaque(
                        device(author).as_opaque().clone(),
                    )),
                    endpoint_id: None,
                    integration_id: None,
                },
                correlation: CorrelationContext {
                    correlation_id: oid("mesh-correlation", seed),
                    causation_id: None,
                    idempotency_key: None,
                },
                extensions: vec![],
                external_mappings: vec![],
                signature: Some(MessageSignature {
                    key_id: KeyId::from_opaque(oid("mesh-key", author)),
                    algorithm_id: "ed25519".to_owned(),
                    algorithm_version: 1,
                    signature: vec![seed; 64],
                }),
            },
        },
        forward_path: path_values.iter().copied().map(device).collect(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let seed = data[0];
    let take = usize::from(data.get(1).copied().unwrap_or(0) % 12);
    let path_values = data.iter().copied().skip(2).take(take).collect::<Vec<_>>();
    let candidate = replica(seed, &path_values);
    let _ = canonical_mesh_group_message_replica(&candidate);
    if let Some(last) = candidate.forward_path.last() {
        let _ = validate_mesh_source(&candidate, last);
    }
    let recipient = device(data.get(14).copied().unwrap_or(seed.wrapping_add(1)));
    let _ = append_mesh_recipient(&candidate, &recipient);
    let _ = validate_mesh_group_page_size(usize::from(data.get(15).copied().unwrap_or(1)) + 1);
    let group = &candidate.record.group_id;
    let cursor = mesh_group_cursor(&scope(), group, u64::from(seed));
    let _ = mesh_group_cursor_sequence(&scope(), group, &cursor);
});

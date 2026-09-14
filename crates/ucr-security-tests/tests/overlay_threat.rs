use ucr_core::{AuthorizationEvaluator, BridgeRegistrationStore, DurableStoreError, GroupStore};
use ucr_model::{
    AuthorizationRequest, BridgeCapability, BridgeDataPermission, BridgeInboundEvent,
    BridgeProviderManifest, BridgeRegistration, BridgeRegistrationState, ConversationId,
    ConversationKind, ConversationRecord, ConversationRef, DeliveryPolicy, EventId,
    GroupBridgeMapping, GroupChange, GroupChangeKind, GroupCryptoState, GroupHistoryPolicy,
    GroupId, GroupMediaState, GroupOwnership, GroupRecord, IntegrationId, NamespaceId, OpaqueId,
    PrincipalId, PrincipalKind, PrincipalRef, ProtocolVersion, ScopedPrincipal, TenantId,
    TenantScope,
};
use ucr_overlay::{OverlayError, OverlayRuntime};
use ucr_protocol::{BRIDGE_SDK_VERSION, CanonicalError};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}
fn scope(namespace: &str) -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("overlay-threat-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid(namespace))),
    }
}
fn actor(name: &str, namespace: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(namespace),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(name)),
            kind: PrincipalKind::Person,
        },
    }
}
fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("overlay-threat-integration"))
}
fn registration() -> BridgeRegistration {
    BridgeRegistration {
        scope: scope("overlay-threat-ns"),
        integration_id: integration(),
        manifest: BridgeProviderManifest {
            provider_id: "vendor.overlay.threat".to_owned(),
            sdk_min: BRIDGE_SDK_VERSION,
            sdk_max: BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities: vec![BridgeCapability::Text],
            permissions: vec![
                BridgeDataPermission::MessageContent,
                BridgeDataPermission::ExternalIdentityReferences,
                BridgeDataPermission::InboundEvents,
            ],
            extensions: vec![],
        },
        state: BridgeRegistrationState::Active,
        generation: 1,
    }
}
fn group(name: &str, owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
    let conversation = ConversationRef {
        conversation_id: ConversationId::from_opaque(oid(&format!("overlay-threat-conv-{name}"))),
        kind: ConversationKind::PrivateGroup,
    };
    (
        ConversationRecord {
            scope: owner.scope.clone(),
            conversation: conversation.clone(),
            parent_conversation_id: None,
        },
        GroupRecord {
            scope: owner.scope.clone(),
            group_id: GroupId::from_opaque(oid(&format!("overlay-threat-group-{name}"))),
            conversation,
            ownership: GroupOwnership::PersonOwned(owner.principal.clone()),
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: vec![],
            replication_generation: 0,
            revision: 0,
        },
    )
}
fn inbound(scope: TenantScope) -> BridgeInboundEvent {
    BridgeInboundEvent {
        scope,
        integration_id: integration(),
        external_event_id: b"malicious-event".to_vec(),
        external_conversation_id: b"provider-room".to_vec(),
        external_actor_id: Some(b"provider-actor".to_vec()),
        capability: BridgeCapability::Text,
        payload: b"provider-controlled-text".to_vec(),
        occurred_at_unix_ms: 1_700_000_000_000,
    }
}

#[test]
fn compromised_overlay_boundary_cannot_alias_groups_or_choose_scope() {
    let store = MemoryLocalStore::default();
    let owner = actor("overlay-threat-owner", "overlay-threat-ns");
    let outsider = actor("overlay-threat-outsider", "overlay-threat-ns");
    store
        .install_bridge_registration(&registration())
        .expect("registration");
    let (conversation_a, group_a) = group("a", &owner);
    let (conversation_b, group_b) = group("b", &owner);
    store
        .create_group(&conversation_a, &group_a, &owner)
        .expect("group a");
    store
        .create_group(&conversation_b, &group_b, &owner)
        .expect("group b");
    let runtime = OverlayRuntime::new(&AllowAll, &store);
    runtime
        .bind_endpoint(
            &owner,
            EventId::from_opaque(oid("overlay-threat-bind-a")),
            group_a.group_id.clone(),
            0,
            GroupBridgeMapping {
                integration_id: integration(),
                external_group_id: b"provider-room".to_vec(),
            },
        )
        .expect("bind a");

    assert!(matches!(
        runtime.resolve_inbound_text(&owner, &inbound(scope("other-ns"))),
        Err(OverlayError::ScopeMismatch)
    ));
    assert!(
        runtime
            .resolve_inbound_text(&outsider, &inbound(scope("overlay-threat-ns")))
            .expect("non-disclosing resolution")
            .is_none()
    );
    let collision = GroupChange {
        event_id: EventId::from_opaque(oid("overlay-threat-bind-b")),
        scope: owner.scope.clone(),
        group_id: group_b.group_id,
        expected_revision: 0,
        kind: GroupChangeKind::AddBridgeMapping {
            mapping: GroupBridgeMapping {
                integration_id: integration(),
                external_group_id: b"provider-room".to_vec(),
            },
        },
        next_crypto_state: None,
    };
    assert_eq!(
        store.apply_group_change(&owner, &collision),
        Err(DurableStoreError::Conflict)
    );
}

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
use ucr_overlay::{OverlayEndpointState, OverlayError, OverlayRuntime};
use ucr_protocol::{BRIDGE_SDK_VERSION, CanonicalError};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Default, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-overlay")),
        namespace_id: Some(NamespaceId::from_opaque(oid("ns-overlay"))),
    }
}

fn actor(name: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(name)),
            kind: PrincipalKind::Person,
        },
    }
}

fn integration(name: &str) -> IntegrationId {
    IntegrationId::from_opaque(oid(name))
}

fn registration(id: IntegrationId) -> BridgeRegistration {
    BridgeRegistration {
        scope: scope(),
        integration_id: id,
        manifest: BridgeProviderManifest {
            provider_id: "vendor.test.overlay".to_owned(),
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

fn group_fixture(name: &str, owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
    let conversation = ConversationRef {
        conversation_id: ConversationId::from_opaque(oid(&format!("conv-{name}"))),
        kind: ConversationKind::PrivateGroup,
    };
    (
        ConversationRecord {
            scope: scope(),
            conversation: conversation.clone(),
            parent_conversation_id: None,
        },
        GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid(&format!("group-{name}"))),
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

fn inbound(id: &IntegrationId, external_group_id: &[u8]) -> BridgeInboundEvent {
    BridgeInboundEvent {
        scope: scope(),
        integration_id: id.clone(),
        external_event_id: b"event-1".to_vec(),
        external_conversation_id: external_group_id.to_vec(),
        external_actor_id: Some(b"provider-user-7".to_vec()),
        capability: BridgeCapability::Text,
        payload: b"hello overlay".to_vec(),
        occurred_at_unix_ms: 1_700_000_000_123,
    }
}

#[test]
fn bind_projects_and_resolves_one_logical_group_without_copying_conversation() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-a");
    let (conversation, group) = group_fixture("a", &owner);
    store
        .create_group(&conversation, &group, &owner)
        .expect("create group");
    let integration_id = integration("integration-a");
    store
        .install_bridge_registration(&registration(integration_id.clone()))
        .expect("registration");
    let runtime = OverlayRuntime::new(&AllowAll, &store);
    let mapping = GroupBridgeMapping {
        integration_id: integration_id.clone(),
        external_group_id: b"chat:-10042".to_vec(),
    };
    runtime
        .bind_endpoint(
            &owner,
            EventId::from_opaque(oid("bind-a")),
            group.group_id.clone(),
            0,
            mapping.clone(),
        )
        .expect("bind");

    let projection = runtime
        .text_projection(&owner, &scope(), &conversation.conversation.conversation_id)
        .expect("projection")
        .expect("visible group");
    assert_eq!(projection.group_id, group.group_id);
    assert_eq!(projection.conversation, conversation.conversation);
    assert_eq!(projection.endpoints.len(), 1);
    assert_eq!(projection.endpoints[0].state, OverlayEndpointState::Ready);
    assert_eq!(
        projection.endpoints[0].external_group_id,
        mapping.external_group_id
    );

    let resolution = runtime
        .resolve_inbound_text(&owner, &inbound(&integration_id, b"chat:-10042"))
        .expect("resolution")
        .expect("mapped");
    assert_eq!(resolution.group_id, group.group_id);
    assert_eq!(resolution.conversation, conversation.conversation);
}

#[test]
fn inactive_registration_is_explicit_degradation_but_mapping_can_be_removed() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-b");
    let (conversation, group) = group_fixture("b", &owner);
    store
        .create_group(&conversation, &group, &owner)
        .expect("create group");
    let integration_id = integration("integration-b");
    store
        .install_bridge_registration(&registration(integration_id.clone()))
        .expect("registration");
    let runtime = OverlayRuntime::new(&AllowAll, &store);
    runtime
        .bind_endpoint(
            &owner,
            EventId::from_opaque(oid("bind-b")),
            group.group_id.clone(),
            0,
            GroupBridgeMapping {
                integration_id: integration_id.clone(),
                external_group_id: b"room-b".to_vec(),
            },
        )
        .expect("bind");
    store
        .transition_bridge_registration(
            &scope(),
            &integration_id,
            1,
            BridgeRegistrationState::Disabled,
        )
        .expect("disable");

    let projection = runtime
        .text_projection(&owner, &scope(), &conversation.conversation.conversation_id)
        .expect("projection")
        .expect("visible");
    assert_eq!(
        projection.endpoints[0].state,
        OverlayEndpointState::RegistrationInactive
    );
    assert!(matches!(
        runtime.resolve_inbound_text(&owner, &inbound(&integration_id, b"room-b")),
        Err(OverlayError::RegistrationInactive)
    ));
    runtime
        .unbind_endpoint(
            &owner,
            EventId::from_opaque(oid("unbind-b")),
            group.group_id,
            1,
            integration_id,
            b"room-b".to_vec(),
        )
        .expect("cleanup stale mapping");
}

#[test]
fn private_overlay_is_non_disclosing_to_non_member() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-c");
    let outsider = actor("outsider-c");
    let (conversation, group) = group_fixture("c", &owner);
    let integration_id = integration("integration-c");
    store
        .install_bridge_registration(&registration(integration_id.clone()))
        .expect("registration");
    let mut initial = group.clone();
    initial.bridge_mappings.push(GroupBridgeMapping {
        integration_id: integration_id.clone(),
        external_group_id: b"room-c".to_vec(),
    });
    store
        .create_group(&conversation, &initial, &owner)
        .expect("create group");
    let runtime = OverlayRuntime::new(&AllowAll, &store);

    assert!(
        runtime
            .text_projection(
                &outsider,
                &scope(),
                &conversation.conversation.conversation_id
            )
            .expect("projection")
            .is_none()
    );
    assert!(
        runtime
            .resolve_inbound_text(&outsider, &inbound(&integration_id, b"room-c"))
            .expect("resolution")
            .is_none()
    );
}

#[test]
fn one_external_endpoint_cannot_be_bound_to_two_canonical_groups() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-d");
    let integration_id = integration("integration-d");
    store
        .install_bridge_registration(&registration(integration_id.clone()))
        .expect("registration");
    let runtime = OverlayRuntime::new(&AllowAll, &store);
    let (conversation_a, group_a) = group_fixture("d-a", &owner);
    let (conversation_b, group_b) = group_fixture("d-b", &owner);
    store
        .create_group(&conversation_a, &group_a, &owner)
        .expect("group a");
    store
        .create_group(&conversation_b, &group_b, &owner)
        .expect("group b");
    let external = b"same-provider-room".to_vec();
    runtime
        .bind_endpoint(
            &owner,
            EventId::from_opaque(oid("bind-d-a")),
            group_a.group_id,
            0,
            GroupBridgeMapping {
                integration_id: integration_id.clone(),
                external_group_id: external.clone(),
            },
        )
        .expect("bind a");
    let error = runtime
        .bind_endpoint(
            &owner,
            EventId::from_opaque(oid("bind-d-b")),
            group_b.group_id,
            0,
            GroupBridgeMapping {
                integration_id,
                external_group_id: external,
            },
        )
        .expect_err("collision must fail");
    assert!(matches!(
        error,
        OverlayError::Store(DurableStoreError::Conflict)
    ));
}

#[test]
fn direct_group_store_cannot_add_mapping_without_active_registration() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-e");
    let (conversation, group) = group_fixture("e", &owner);
    store
        .create_group(&conversation, &group, &owner)
        .expect("group");
    let change = GroupChange {
        event_id: EventId::from_opaque(oid("bind-e")),
        scope: scope(),
        group_id: group.group_id,
        expected_revision: 0,
        kind: GroupChangeKind::AddBridgeMapping {
            mapping: GroupBridgeMapping {
                integration_id: integration("missing-registration"),
                external_group_id: b"room-e".to_vec(),
            },
        },
        next_crypto_state: None,
    };
    assert_eq!(
        store.apply_group_change(&owner, &change),
        Err(DurableStoreError::Conflict)
    );
}

#[test]
fn initial_group_mapping_cannot_bypass_active_registration_requirement() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-initial-bypass");
    let (conversation, mut group) = group_fixture("initial-bypass", &owner);
    group.bridge_mappings.push(GroupBridgeMapping {
        integration_id: integration("missing-initial-registration"),
        external_group_id: b"room-initial-bypass".to_vec(),
    });
    assert_eq!(
        store.create_group(&conversation, &group, &owner),
        Err(DurableStoreError::Conflict)
    );
}

#[test]
fn endpoint_debug_redacts_provider_conversation_id() {
    let endpoint = ucr_overlay::OverlayEndpoint {
        integration_id: integration("debug-integration"),
        external_group_id: b"secret-provider-room".to_vec(),
        provider_id: Some("vendor.test.overlay".to_owned()),
        state: OverlayEndpointState::Ready,
    };
    let rendered = format!("{endpoint:?}");
    assert!(rendered.contains("<opaque>"));
    assert!(!rendered.contains("secret-provider-room"));
}

#[test]
fn inbound_resolution_requires_all_consumed_data_permissions() {
    let store = MemoryLocalStore::default();
    let owner = actor("owner-f");
    let (conversation, mut group) = group_fixture("f", &owner);
    let integration_id = integration("integration-f");
    let mut limited = registration(integration_id.clone());
    limited.manifest.permissions = vec![BridgeDataPermission::InboundEvents];
    store
        .install_bridge_registration(&limited)
        .expect("registration");
    group.bridge_mappings.push(GroupBridgeMapping {
        integration_id: integration_id.clone(),
        external_group_id: b"room-f".to_vec(),
    });
    store
        .create_group(&conversation, &group, &owner)
        .expect("create group");
    let runtime = OverlayRuntime::new(&AllowAll, &store);
    assert!(matches!(
        runtime.resolve_inbound_text(&owner, &inbound(&integration_id, b"room-f")),
        Err(OverlayError::DataPermissionDenied)
    ));
}

use ucr_core::{
    BridgeRegistrationStore, CommunicationIntentStore, ConversationStore, DeviceLifecycleStore,
    IdentityStore, MessageStore, PermissionGrantStore, StoreForwardStore,
};
use ucr_model::*;
use ucr_organization_mode::{OrganizationModeError, OrganizationModeRuntime};
use ucr_protocol::*;
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("organization-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("organization-private"))),
    }
}

fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("organization-admin")),
            kind: PrincipalKind::Person,
        },
    }
}
fn organization() -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("organization-owner")),
        kind: PrincipalKind::Organization,
    }
}

fn endpoint() -> EndpointId {
    EndpointId::from_opaque(oid("organization-node"))
}

fn grant(store: &MemoryLocalStore, permission: &str) {
    store
        .grant_permission(&PermissionGrant {
            grantee: actor(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(scope()),
        })
        .expect("grant");
}

fn grant_runtime_permissions(store: &MemoryLocalStore) {
    for permission in [
        ORGANIZATION_MANAGE_PERMISSION,
        ORGANIZATION_READ_PERMISSION,
        ORGANIZATION_DISCOVERY_READ_PERMISSION,
        ORGANIZATION_IDENTITY_MANAGE_PERMISSION,
        ORGANIZATION_DEVICE_MANAGE_PERMISSION,
        ORGANIZATION_RELAY_USE_PERMISSION,
        ORGANIZATION_SFU_USE_PERMISSION,
        ORGANIZATION_BRIDGE_USE_PERMISSION,
        IDENTITY_READ_PERMISSION,
        DEVICE_READ_PERMISSION,
        BRIDGE_REGISTRATION_READ_PERMISSION,
    ] {
        grant(store, permission);
    }
}

fn profile() -> OrganizationModeProfile {
    OrganizationModeProfile {
        scope: scope(),
        organization: organization(),
        endpoint_id: endpoint(),
        endpoint_kind: EndpointKind::OrganizationNode,
        services: vec![
            OrganizationService::PrivateDiscovery,
            OrganizationService::PrivateRelay,
            OrganizationService::PrivateSfu,
            OrganizationService::PrivateBridge,
            OrganizationService::ManagedIdentities,
            OrganizationService::ManagedDevices,
        ],
        state: OrganizationModeState::Active,
        generation: 1,
    }
}
fn managed_identity(id: &str, ownership: IdentityOwnership) -> IdentityRecord {
    IdentityRecord {
        scope: scope(),
        identity_id: IdentityId::from_opaque(oid(id)),
        ownership,
        evidence: IdentityEvidence::OrganizationVerified,
        expires_at_unix_ms: None,
    }
}

fn identity_binding(identity_id: IdentityId) -> OrganizationManagedIdentityBinding {
    OrganizationManagedIdentityBinding {
        scope: scope(),
        organization: organization(),
        identity_id,
    }
}

fn managed_device(
    id: &str,
    identity_id: IdentityId,
    state: DeviceLifecycleState,
) -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid(id)),
        identity_id,
        state,
    }
}

fn device_binding(device_id: DeviceId) -> OrganizationManagedDeviceBinding {
    OrganizationManagedDeviceBinding {
        scope: scope(),
        organization: organization(),
        device_id,
    }
}
fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("organization-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}

fn message(id: &str, policy: DeliveryPolicy) -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid(id)),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("organization-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("organization-author-device")),
            identity_id: IdentityId::from_opaque(oid("organization-author-identity")),
        },
        created_at_unix_ms: 1_000,
        logical_order: 1,
        content: b"message".to_vec(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: policy,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("organization-origin"))),
            endpoint_id: Some(endpoint()),
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid(id),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    }
}

fn intent(id: &str) -> CommunicationIntent {
    CommunicationIntent {
        intent_id: IntentId::from_opaque(oid(id)),
        scope: scope(),
        target_identity_id: IdentityId::from_opaque(oid("organization-target")),
        payload: b"intent".to_vec(),
        constraints: IntentConstraints {
            allowed_transport_capabilities: Vec::new(),
            forbidden_transport_capabilities: Vec::new(),
            privacy_profile: None,
            region_constraint: None,
            max_cost_microunits: None,
            priority_class: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
        extensions: Vec::new(),
    }
}

fn store_forward_job(id: &str, message_id: MessageId, intent_id: IntentId) -> StoreForwardJob {
    StoreForwardJob {
        store_forward_id: StoreForwardId::from_opaque(oid(id)),
        scope: scope(),
        intent_id,
        message_id,
        encrypted_envelope: b"opaque-organization-envelope".to_vec(),
        policy: StoreForwardPolicy {
            max_delivery_attempts: 3,
            base_retry_delay_ms: 100,
            max_retry_delay_ms: 1_000,
            lease_duration_ms: 5_000,
            expires_at_unix_ms: None,
        },
        attempts_used: 0,
        next_attempt_at_unix_ms: 1_000,
        last_delivery_id: None,
    }
}

fn seed_store_forward(
    store: &MemoryLocalStore,
    id: &str,
    policy: DeliveryPolicy,
) -> StoreForwardJob {
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    let message = message(&format!("message-{id}"), policy);
    store.persist_message(&message).expect("message");
    let intent = intent(&format!("intent-{id}"));
    store.persist_communication_intent(&intent).expect("intent");
    let job = store_forward_job(&format!("job-{id}"), message.message_id, intent.intent_id);
    store
        .persist_store_forward_job(&job)
        .expect("store-forward job");
    job
}
fn bridge_registration(state: BridgeRegistrationState) -> BridgeRegistration {
    BridgeRegistration {
        scope: scope(),
        integration_id: IntegrationId::from_opaque(oid("organization-bridge")),
        manifest: BridgeProviderManifest {
            provider_id: "vendor.organization.reference".to_owned(),
            sdk_min: BRIDGE_SDK_VERSION,
            sdk_max: BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities: vec![BridgeCapability::Text],
            permissions: vec![BridgeDataPermission::MessageContent],
            extensions: Vec::new(),
        },
        state,
        generation: 1,
    }
}

fn install_profile(
    store: &MemoryLocalStore,
) -> OrganizationModeRuntime<'_, MemoryLocalStore, MemoryLocalStore> {
    grant_runtime_permissions(store);
    let runtime = OrganizationModeRuntime::new(store, store);
    runtime
        .install_profile(&actor(), &profile())
        .expect("profile");
    runtime
}
#[test]
fn managed_identity_device_and_private_directory_reuse_canonical_owners() {
    let store = MemoryLocalStore::default();
    let runtime = OrganizationModeRuntime::new(&store, &store);
    assert!(matches!(
        runtime.install_profile(&actor(), &profile()),
        Err(OrganizationModeError::Authorization(_))
    ));

    grant_runtime_permissions(&store);
    runtime
        .install_profile(&actor(), &profile())
        .expect("profile");
    let identity = managed_identity("managed-a", IdentityOwnership::OrganizationManaged);
    store.persist_identity(&identity).expect("identity");
    let binding = identity_binding(identity.identity_id.clone());
    runtime
        .bind_managed_identity(&actor(), &binding)
        .expect("bind identity");
    assert_eq!(
        runtime
            .private_directory(&actor(), &scope(), &organization(), 16)
            .expect("directory"),
        vec![identity.clone()]
    );

    let device = managed_device(
        "device-a",
        identity.identity_id.clone(),
        DeviceLifecycleState::Active,
    );
    store.register_device(&scope(), &device).expect("device");
    runtime
        .bind_managed_device(&actor(), &device_binding(device.device_id.clone()))
        .expect("bind device");
    assert_eq!(
        runtime
            .managed_devices(&actor(), &scope(), &organization(), 16)
            .expect("devices"),
        vec![device]
    );
}
#[test]
fn unmanaged_identity_and_ineligible_device_fail_closed() {
    let store = MemoryLocalStore::default();
    let runtime = install_profile(&store);

    let user_owned = managed_identity("user-owned", IdentityOwnership::UserManaged);
    store.persist_identity(&user_owned).expect("identity");
    assert!(matches!(
        runtime.bind_managed_identity(&actor(), &identity_binding(user_owned.identity_id.clone())),
        Err(OrganizationModeError::IdentityNotOrganizationManaged)
    ));

    let managed = managed_identity("managed-b", IdentityOwnership::OrganizationManaged);
    store.persist_identity(&managed).expect("managed identity");
    runtime
        .bind_managed_identity(&actor(), &identity_binding(managed.identity_id.clone()))
        .expect("managed identity binding");
    let revoked = managed_device(
        "revoked-device",
        managed.identity_id.clone(),
        DeviceLifecycleState::Revoked,
    );
    store
        .register_device(&scope(), &revoked)
        .expect("revoked device record");
    assert!(matches!(
        runtime.bind_managed_device(&actor(), &device_binding(revoked.device_id)),
        Err(OrganizationModeError::DeviceNotEligible)
    ));
}
#[test]
fn relay_sfu_bridge_and_disable_reuse_existing_runtime_boundaries() {
    let store = MemoryLocalStore::default();
    let runtime = install_profile(&store);

    let relay = seed_store_forward(&store, "relay", DeliveryPolicy::Durable);
    assert_eq!(
        runtime
            .admit_relay(&actor(), &scope(), &organization(), &relay.store_forward_id)
            .expect("relay")
            .store_forward_id,
        relay.store_forward_id
    );
    let denied = seed_store_forward(&store, "no-relay", DeliveryPolicy::NoRelay);
    assert!(matches!(
        runtime.admit_relay(
            &actor(),
            &scope(),
            &organization(),
            &denied.store_forward_id
        ),
        Err(OrganizationModeError::RelayPolicyDenied)
    ));

    assert_eq!(
        runtime
            .admit_sfu(&actor(), &scope(), &organization())
            .expect("sfu")
            .endpoint_id,
        endpoint()
    );
    let bridge = bridge_registration(BridgeRegistrationState::Active);
    store.install_bridge_registration(&bridge).expect("bridge");
    assert_eq!(
        runtime
            .admit_bridge(&actor(), &scope(), &organization(), &bridge.integration_id)
            .expect("bridge admission"),
        bridge
    );
    runtime
        .transition_profile(
            &actor(),
            &scope(),
            &organization(),
            1,
            OrganizationModeState::Disabled,
        )
        .expect("disable");
    assert!(matches!(
        runtime.admit_sfu(&actor(), &scope(), &organization()),
        Err(OrganizationModeError::ModeDisabled)
    ));
    assert_eq!(
        store
            .store_forward_job(&scope(), &relay.store_forward_id)
            .expect("canonical relay state")
            .expect("relay still exists")
            .store_forward_id,
        relay.store_forward_id,
        "Organization Mode disable must not rewrite canonical Store-and-Forward state"
    );
}

#[test]
fn cross_namespace_actor_cannot_manage_organization_mode() {
    let store = MemoryLocalStore::default();
    grant_runtime_permissions(&store);
    let runtime = OrganizationModeRuntime::new(&store, &store);
    let foreign = ScopedPrincipal {
        scope: TenantScope {
            tenant_id: scope().tenant_id,
            namespace_id: Some(NamespaceId::from_opaque(oid("other-private"))),
        },
        principal: actor().principal,
    };
    assert!(matches!(
        runtime.install_profile(&foreign, &profile()),
        Err(OrganizationModeError::Authorization(_))
    ));
    assert!(
        ucr_core::OrganizationModeStore::organization_mode_profile(
            &store,
            &scope(),
            &organization(),
        )
        .expect("durable state")
        .is_none()
    );
}

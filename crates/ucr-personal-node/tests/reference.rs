use sha2::{Digest, Sha256};
use ucr_core::{
    BridgeRegistrationStore, CommunicationIntentStore, ConversationStore, MessageStore,
    PermissionGrantStore, StoreForwardStore, SyncStore,
};
use ucr_model::*;
use ucr_personal_node::{PersonalNodeError, PersonalNodeRuntime};
use ucr_protocol::{
    PERSONAL_NODE_MANAGE_PERMISSION, PERSONAL_NODE_OBJECT_READ_PERMISSION,
    PERSONAL_NODE_OBJECT_WRITE_PERMISSION, PERSONAL_NODE_READ_PERMISSION,
    PERSONAL_NODE_USE_PERMISSION, SYNC_READ_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("personal-node-tenant")),
        namespace_id: None,
    }
}

fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("personal-node-owner")),
            kind: PrincipalKind::Person,
        },
    }
}
fn endpoint() -> EndpointId {
    EndpointId::from_opaque(oid("personal-node-endpoint"))
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
        PERSONAL_NODE_MANAGE_PERMISSION,
        PERSONAL_NODE_READ_PERMISSION,
        PERSONAL_NODE_OBJECT_READ_PERMISSION,
        PERSONAL_NODE_OBJECT_WRITE_PERMISSION,
        PERSONAL_NODE_USE_PERMISSION,
        SYNC_READ_PERMISSION,
        ucr_protocol::BRIDGE_REGISTRATION_READ_PERMISSION,
    ] {
        grant(store, permission);
    }
}
fn profile() -> PersonalNodeProfile {
    PersonalNodeProfile {
        scope: scope(),
        endpoint_id: endpoint(),
        endpoint_kind: EndpointKind::PersonalNode,
        services: vec![
            PersonalNodeService::Sync,
            PersonalNodeService::EncryptedMailbox,
            PersonalNodeService::Relay,
            PersonalNodeService::Cache,
            PersonalNodeService::Bridge,
        ],
        state: PersonalNodeState::Active,
        generation: 1,
        mailbox_capacity_bytes: 4096,
        cache_capacity_bytes: 4096,
    }
}

fn object(id: &str, kind: PersonalNodeObjectKind, bytes: &[u8]) -> PersonalNodeObject {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    PersonalNodeObject {
        scope: scope(),
        endpoint_id: endpoint(),
        object_id: PersonalNodeObjectId::from_opaque(oid(id)),
        kind,
        encryption_scheme: "ucr.aead.v1".to_owned(),
        ciphertext: bytes.to_vec(),
        ciphertext_sha256: digest,
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: Some(10_000),
    }
}

fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("pn-conversation")),
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
            actor_id: ActorId::from_opaque(oid("pn-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("pn-device")),
            identity_id: IdentityId::from_opaque(oid("pn-author-identity")),
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
            principal_id: Some(PrincipalId::from_opaque(oid("pn-origin"))),
            endpoint_id: None,
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
        target_identity_id: IdentityId::from_opaque(oid("pn-target")),
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
        encrypted_envelope: b"opaque-encrypted-envelope".to_vec(),
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

fn bridge_registration() -> BridgeRegistration {
    BridgeRegistration {
        scope: scope(),
        integration_id: IntegrationId::from_opaque(oid("pn-bridge")),
        manifest: BridgeProviderManifest {
            provider_id: "vendor.personal-node.reference".to_owned(),
            sdk_min: ucr_protocol::BRIDGE_SDK_VERSION,
            sdk_max: ucr_protocol::BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities: vec![BridgeCapability::Text],
            permissions: vec![BridgeDataPermission::MessageContent],
            extensions: Vec::new(),
        },
        state: BridgeRegistrationState::Active,
        generation: 1,
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

#[test]
fn permissions_objects_and_disable_are_fail_closed() {
    let store = MemoryLocalStore::default();
    let runtime = PersonalNodeRuntime::new(&store, &store);
    assert!(matches!(
        runtime.install_profile(&actor(), &profile()),
        Err(PersonalNodeError::Authorization(_))
    ));

    grant_runtime_permissions(&store);
    assert_eq!(
        runtime
            .install_profile(&actor(), &profile())
            .expect("install"),
        ucr_core::DurableRecordStatus::Persisted
    );
    let mailbox = object(
        "mailbox-1",
        PersonalNodeObjectKind::Mailbox,
        b"ciphertext-mailbox",
    );
    runtime.put_object(&actor(), &mailbox).expect("put mailbox");
    assert_eq!(
        runtime
            .object(&actor(), &scope(), &endpoint(), &mailbox.object_id)
            .expect("read"),
        Some(mailbox.clone())
    );
    assert_eq!(
        runtime
            .remove_object(&actor(), &scope(), &endpoint(), &mailbox.object_id)
            .expect("remove"),
        ucr_core::DurableRecordStatus::Persisted
    );
    assert!(
        runtime
            .object(&actor(), &scope(), &endpoint(), &mailbox.object_id)
            .expect("read removed")
            .is_none()
    );
    runtime
        .transition_profile(
            &actor(),
            &scope(),
            &endpoint(),
            1,
            PersonalNodeState::Disabled,
        )
        .expect("disable");
    assert!(matches!(
        runtime.put_object(
            &actor(),
            &object(
                "mailbox-disabled",
                PersonalNodeObjectKind::Mailbox,
                b"ciphertext"
            )
        ),
        Err(PersonalNodeError::NodeDisabled)
    ));
}

#[test]
fn sync_relay_and_bridge_admission_reuse_canonical_owners() {
    let store = MemoryLocalStore::default();
    grant_runtime_permissions(&store);
    let runtime = PersonalNodeRuntime::new(&store, &store);
    runtime
        .install_profile(&actor(), &profile())
        .expect("profile");

    let sync_id = SessionId::from_opaque(oid("pn-sync"));
    let sync = SyncSession {
        session_id: sync_id.clone(),
        scope: scope(),
        source_endpoint_id: EndpointId::from_opaque(oid("pn-device-endpoint")),
        target_endpoint_id: endpoint(),
        link_kind: SyncLinkKind::DeviceNode,
        selection: SyncSelection {
            mode: SyncMode::Full,
            conversation_ids: Vec::new(),
        },
        state: SyncState::Prepared,
    };
    store.create_sync_session(&sync).expect("sync prepared");
    store
        .transition_sync(&scope(), &sync_id, SyncState::Prepared, SyncState::Active)
        .expect("sync active");
    assert_eq!(
        runtime
            .admit_sync(&actor(), &scope(), &endpoint(), &sync_id)
            .expect("sync admission")
            .session_id,
        sync_id
    );

    let relay_job = seed_store_forward(&store, "relay", DeliveryPolicy::Durable);
    assert_eq!(
        runtime
            .admit_relay(&actor(), &scope(), &endpoint(), &relay_job.store_forward_id,)
            .expect("relay admission")
            .store_forward_id,
        relay_job.store_forward_id
    );
    let denied_job = seed_store_forward(&store, "no-relay", DeliveryPolicy::NoRelay);
    assert!(matches!(
        runtime.admit_relay(
            &actor(),
            &scope(),
            &endpoint(),
            &denied_job.store_forward_id,
        ),
        Err(PersonalNodeError::RelayPolicyDenied)
    ));

    let registration = bridge_registration();
    store
        .install_bridge_registration(&registration)
        .expect("bridge registration");
    assert_eq!(
        runtime
            .admit_bridge(
                &actor(),
                &scope(),
                &endpoint(),
                &registration.integration_id,
            )
            .expect("bridge admission"),
        registration
    );
}

#[test]
fn cross_scope_actor_cannot_manage_personal_node() {
    let store = MemoryLocalStore::default();
    grant_runtime_permissions(&store);
    let runtime = PersonalNodeRuntime::new(&store, &store);
    let foreign = ScopedPrincipal {
        scope: TenantScope {
            tenant_id: TenantId::from_opaque(oid("foreign-tenant")),
            namespace_id: None,
        },
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("foreign-actor")),
            kind: PrincipalKind::Person,
        },
    };
    assert!(matches!(
        runtime.install_profile(&foreign, &profile()),
        Err(PersonalNodeError::Authorization(_))
    ));
    assert!(
        ucr_core::PersonalNodeStore::personal_node_profile(&store, &scope(), &endpoint())
            .expect("read durable state")
            .is_none()
    );
}

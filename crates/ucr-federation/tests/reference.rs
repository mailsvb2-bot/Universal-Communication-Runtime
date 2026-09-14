use ucr_core::{
    DeviceLifecycleStore, DurableRecordStatus, FederationPeerStore, PermissionGrantStore,
    SyncStore, TrustedSigningKeyStore,
};
use ucr_crypto::{
    AgreementKeyPair, EstablishedSession, SessionHandshakeInput, SessionRole, SigningKeyMaterial,
    TranscriptBinding, TrustedSessionHandshakeInput, begin_session,
    begin_session_with_trusted_peer,
};
use ucr_federation::{FederationError, FederationRuntime, FederationSyncAdmission};
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, FEDERATION_PEER_MANAGE_PERMISSION, FEDERATION_PEER_READ_PERMISSION,
    FEDERATION_SYNC_PERMISSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, SYNC_READ_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn local_scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("federation-local-tenant")),
        namespace_id: None,
    }
}

fn remote_scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("federation-remote-tenant")),
        namespace_id: None,
    }
}
fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: local_scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("federation-admin")),
            kind: PrincipalKind::Person,
        },
    }
}

fn grant(store: &MemoryLocalStore, subject: &ScopedPrincipal, permission: &str) {
    store
        .grant_permission(&PermissionGrant {
            grantee: subject.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(local_scope()),
        })
        .expect("grant permission");
}

fn grant_federation_permissions(store: &MemoryLocalStore, subject: &ScopedPrincipal) {
    for permission in [
        FEDERATION_PEER_MANAGE_PERMISSION,
        FEDERATION_PEER_READ_PERMISSION,
        FEDERATION_SYNC_PERMISSION,
        SYNC_READ_PERMISSION,
    ] {
        grant(store, subject, permission);
    }
}

fn device(id: &str, identity: &str) -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid(id)),
        identity_id: IdentityId::from_opaque(oid(identity)),
        state: DeviceLifecycleState::Active,
    }
}
fn provision_remote_credential(
    store: &MemoryLocalStore,
    device: &DeviceDescriptor,
    key_id: &str,
) -> (SigningKeyMaterial, PublicKeyDescriptor) {
    store
        .register_device(&remote_scope(), device)
        .expect("register remote device");
    let signer = SigningKeyMaterial::generate().expect("remote signing key");
    let descriptor = PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid(key_id)),
        device_id: device.device_id.clone(),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: signer.verifying_key().0.to_vec(),
    };
    store
        .provision_trusted_signing_key(&remote_scope(), &descriptor)
        .expect("trust remote signing key");
    (signer, descriptor)
}

fn trusted_session(
    store: &MemoryLocalStore,
    signer: &SigningKeyMaterial,
    descriptor: &PublicKeyDescriptor,
    binding_byte: u8,
) -> EstablishedSession {
    let local_signer = SigningKeyMaterial::generate().expect("local signer");
    let local_agreement = AgreementKeyPair::generate().expect("local agreement");
    let remote_agreement = AgreementKeyPair::generate().expect("remote agreement");
    let local_public = local_agreement.public_key();
    let remote_public = remote_agreement.public_key();
    let binding = TranscriptBinding::from_bytes([binding_byte; 32]);
    let local_pending = begin_session_with_trusted_peer(
        local_agreement,
        &TrustedSessionHandshakeInput {
            scope: remote_scope(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: remote_public,
            initiator_public: local_public,
            responder_public: remote_public,
            peer_signing_descriptor: descriptor.clone(),
            peer_signature: signer.sign_transcript(&binding),
            binding,
        },
        store,
        store,
    )
    .expect("trusted local pending");
    let remote_pending = begin_session(
        remote_agreement,
        SessionHandshakeInput {
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Responder,
            peer_agreement: local_public,
            initiator_public: local_public,
            responder_public: remote_public,
            trusted_peer_verifying_key: local_signer.verifying_key(),
            peer_signature: local_signer.sign_transcript(&binding),
            binding,
        },
        store,
    )
    .expect("remote pending");
    let remote_tag = remote_pending.local_confirmation_tag().expect("remote tag");
    local_pending.confirm_peer(remote_tag).expect("session")
}
fn peer_record(device: &DeviceDescriptor, key: &PublicKeyDescriptor) -> FederationPeerRecord {
    FederationPeerRecord {
        local_scope: local_scope(),
        remote_scope: remote_scope(),
        local_endpoint_id: EndpointId::from_opaque(oid("local-node")),
        remote_endpoint_id: EndpointId::from_opaque(oid("remote-node")),
        remote_endpoint_kind: EndpointKind::OrganizationNode,
        expected_device_id: device.device_id.clone(),
        expected_signing_key_id: key.key_id.clone(),
        allowed_capabilities: vec!["ucr.sync".to_owned()],
        state: FederationTrustState::Known,
        generation: 1,
    }
}

fn sync_admission<'a>(
    peer: &'a FederationPeerRecord,
    sync_session_id: &'a SessionId,
    required_capability: &'a str,
    session: &'a EstablishedSession,
) -> FederationSyncAdmission<'a> {
    FederationSyncAdmission {
        local_scope: &peer.local_scope,
        remote_scope: &peer.remote_scope,
        remote_endpoint_id: &peer.remote_endpoint_id,
        sync_session_id,
        required_capability,
        session,
    }
}

fn active_sync(store: &MemoryLocalStore, target: EndpointId) -> SessionId {
    let session_id = SessionId::from_opaque(oid("federation-sync"));
    let sync = SyncSession {
        session_id: session_id.clone(),
        scope: local_scope(),
        source_endpoint_id: EndpointId::from_opaque(oid("local-node")),
        target_endpoint_id: target,
        link_kind: SyncLinkKind::DeviceNode,
        selection: SyncSelection {
            mode: SyncMode::Full,
            conversation_ids: Vec::new(),
        },
        state: SyncState::Prepared,
    };
    store.create_sync_session(&sync).expect("create sync");
    store
        .transition_sync(
            &local_scope(),
            &session_id,
            SyncState::Prepared,
            SyncState::Active,
        )
        .expect("activate sync");
    session_id
}
fn authenticate_and_authorize(
    runtime: &FederationRuntime<'_, MemoryLocalStore, MemoryLocalStore>,
    actor: &ScopedPrincipal,
    peer: &FederationPeerRecord,
    session: &EstablishedSession,
) {
    runtime
        .authenticate_peer(
            actor,
            &peer.local_scope,
            &peer.remote_scope,
            &peer.remote_endpoint_id,
            session,
        )
        .expect("authenticate");
    runtime
        .transition_peer(
            actor,
            &peer.local_scope,
            &peer.remote_scope,
            &peer.remote_endpoint_id,
            2,
            FederationTrustState::Authorized,
        )
        .expect("authorize");
}

#[test]
fn known_peer_requires_authentication_and_explicit_authorization_before_sync() {
    let store = MemoryLocalStore::default();
    let actor = actor();
    grant_federation_permissions(&store, &actor);
    let remote_device = device("remote-device", "remote-identity");
    let (signer, key) = provision_remote_credential(&store, &remote_device, "remote-key");
    let session = trusted_session(&store, &signer, &key, 36);
    let peer = peer_record(&remote_device, &key);
    let runtime = FederationRuntime::new(&store, &store);
    assert_eq!(
        runtime.install_peer(&actor, &peer).expect("install"),
        DurableRecordStatus::Persisted
    );
    let sync_id = active_sync(&store, peer.remote_endpoint_id.clone());

    assert!(matches!(
        runtime.admit_sync(
            &actor,
            &sync_admission(&peer, &sync_id, "ucr.sync", &session)
        ),
        Err(FederationError::StateDenied)
    ));
    assert_eq!(
        runtime
            .authenticate_peer(
                &actor,
                &local_scope(),
                &remote_scope(),
                &peer.remote_endpoint_id,
                &session,
            )
            .expect("authenticate"),
        DurableRecordStatus::Persisted
    );
    let authenticated = runtime
        .peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
        )
        .expect("read")
        .expect("peer");
    assert_eq!(authenticated.state, FederationTrustState::Authenticated);
    assert!(matches!(
        runtime.admit_sync(
            &actor,
            &sync_admission(&peer, &sync_id, "ucr.sync", &session)
        ),
        Err(FederationError::StateDenied)
    ));
    assert_eq!(
        runtime
            .transition_peer(
                &actor,
                &local_scope(),
                &remote_scope(),
                &peer.remote_endpoint_id,
                authenticated.generation,
                FederationTrustState::Authorized,
            )
            .expect("authorize peer"),
        DurableRecordStatus::Persisted
    );
    let admitted = runtime
        .admit_sync(
            &actor,
            &sync_admission(&peer, &sync_id, "ucr.sync", &session),
        )
        .expect("admit sync");
    assert_eq!(admitted.state, FederationTrustState::Authorized);
}
#[test]
fn capability_and_sync_endpoint_binding_fail_closed() {
    let store = MemoryLocalStore::default();
    let actor = actor();
    grant_federation_permissions(&store, &actor);
    let remote_device = device("remote-device-b", "remote-identity-b");
    let (signer, key) = provision_remote_credential(&store, &remote_device, "remote-key-b");
    let session = trusted_session(&store, &signer, &key, 37);
    let mut peer = peer_record(&remote_device, &key);
    peer.remote_endpoint_id = EndpointId::from_opaque(oid("remote-node-b"));
    let runtime = FederationRuntime::new(&store, &store);
    runtime.install_peer(&actor, &peer).expect("install");
    authenticate_and_authorize(&runtime, &actor, &peer, &session);
    let wrong_sync = active_sync(&store, EndpointId::from_opaque(oid("other-node")));
    assert!(matches!(
        runtime.admit_sync(
            &actor,
            &sync_admission(&peer, &wrong_sync, "ucr.sync", &session)
        ),
        Err(FederationError::SyncBindingMismatch)
    ));
    assert!(matches!(
        runtime.admit_sync(
            &actor,
            &sync_admission(&peer, &wrong_sync, "ucr.message.text", &session)
        ),
        Err(FederationError::CapabilityDenied)
    ));
}

#[test]
fn revoked_remote_device_invalidates_an_existing_authorized_session() {
    let store = MemoryLocalStore::default();
    let actor = actor();
    grant_federation_permissions(&store, &actor);
    let remote_device = device("remote-device-c", "remote-identity-c");
    let (signer, key) = provision_remote_credential(&store, &remote_device, "remote-key-c");
    let session = trusted_session(&store, &signer, &key, 38);
    let mut peer = peer_record(&remote_device, &key);
    peer.remote_endpoint_id = EndpointId::from_opaque(oid("remote-node-c"));
    let runtime = FederationRuntime::new(&store, &store);
    runtime.install_peer(&actor, &peer).expect("install");
    authenticate_and_authorize(&runtime, &actor, &peer, &session);
    let sync_id = active_sync(&store, peer.remote_endpoint_id.clone());
    runtime
        .admit_sync(
            &actor,
            &sync_admission(&peer, &sync_id, "ucr.sync", &session),
        )
        .expect("initial admission");
    store
        .revoke_device(
            &remote_scope(),
            &remote_device.device_id,
            &remote_device.identity_id,
        )
        .expect("revoke remote device");
    assert!(matches!(
        runtime.admit_sync(
            &actor,
            &sync_admission(&peer, &sync_id, "ucr.sync", &session)
        ),
        Err(FederationError::PeerDeviceInactive)
    ));
}
#[test]
fn blocked_peer_can_rotate_credentials_but_returns_to_known() {
    let store = MemoryLocalStore::default();
    let actor = actor();
    grant_federation_permissions(&store, &actor);
    let old_device = device("remote-device-old", "remote-identity-old");
    let (old_signer, old_key) = provision_remote_credential(&store, &old_device, "remote-key-old");
    let old_session = trusted_session(&store, &old_signer, &old_key, 39);
    let mut peer = peer_record(&old_device, &old_key);
    peer.remote_endpoint_id = EndpointId::from_opaque(oid("remote-node-rotate"));
    let runtime = FederationRuntime::new(&store, &store);
    runtime.install_peer(&actor, &peer).expect("install");
    authenticate_and_authorize(&runtime, &actor, &peer, &old_session);
    runtime
        .transition_peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
            3,
            FederationTrustState::Trusted,
        )
        .expect("trust");
    runtime
        .transition_peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
            4,
            FederationTrustState::Blocked,
        )
        .expect("block");
    let blocked = runtime
        .peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
        )
        .expect("read")
        .expect("blocked peer");
    assert_eq!(blocked.state, FederationTrustState::Blocked);

    let new_device = device("remote-device-new", "remote-identity-new");
    let (new_signer, new_key) = provision_remote_credential(&store, &new_device, "remote-key-new");
    let new_session = trusted_session(&store, &new_signer, &new_key, 40);
    let mut replacement = blocked.clone();
    replacement.expected_device_id = new_device.device_id.clone();
    replacement.expected_signing_key_id = new_key.key_id.clone();
    replacement.state = FederationTrustState::Known;
    replacement.generation += 1;
    assert_eq!(
        runtime
            .rotate_peer_credential(&actor, &blocked, &replacement)
            .expect("rotate credential"),
        DurableRecordStatus::Persisted
    );
    let rotated = runtime
        .peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
        )
        .expect("read rotated")
        .expect("rotated peer");
    assert_eq!(rotated.state, FederationTrustState::Known);
    assert!(matches!(
        runtime.authenticate_peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
            &old_session,
        ),
        Err(FederationError::PeerDeviceMismatch)
    ));
    assert_eq!(
        runtime
            .authenticate_peer(
                &actor,
                &local_scope(),
                &remote_scope(),
                &peer.remote_endpoint_id,
                &new_session,
            )
            .expect("authenticate new credential"),
        DurableRecordStatus::Persisted
    );
    let authenticated = runtime
        .peer(
            &actor,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
        )
        .expect("read authenticated")
        .expect("authenticated peer");
    assert_eq!(authenticated.state, FederationTrustState::Authenticated);
}

#[test]
fn cross_tenant_actor_cannot_mutate_local_federation_policy() {
    let store = MemoryLocalStore::default();
    let remote_actor = ScopedPrincipal {
        scope: remote_scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("remote-admin")),
            kind: PrincipalKind::Person,
        },
    };
    let dummy_device = device("dummy-device", "dummy-identity");
    let dummy_key = PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid("dummy-key")),
        device_id: dummy_device.device_id.clone(),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: vec![7; 32],
    };
    let peer = peer_record(&dummy_device, &dummy_key);
    let runtime = FederationRuntime::new(&store, &store);
    assert!(matches!(
        runtime.install_peer(&remote_actor, &peer),
        Err(FederationError::Authorization(_))
    ));
    assert!(
        store
            .federation_peer(&local_scope(), &remote_scope(), &peer.remote_endpoint_id)
            .expect("read durable state")
            .is_none()
    );
}

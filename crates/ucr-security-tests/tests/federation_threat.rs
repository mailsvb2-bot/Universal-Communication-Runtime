use ucr_core::{
    DeviceLifecycleStore, FederationPeerStore, PermissionGrantStore, SyncStore,
    TrustedSigningKeyStore,
};
use ucr_crypto::{
    AgreementKeyPair, EstablishedSession, SessionHandshakeInput, SessionRole, SigningKeyMaterial,
    TranscriptBinding, TrustedSessionHandshakeInput, begin_session,
    begin_session_with_trusted_peer,
};
use ucr_federation::{FederationError, FederationRuntime, FederationSyncAdmission};
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, FEDERATION_PEER_MANAGE_PERMISSION, FEDERATION_SYNC_PERMISSION,
    KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, SYNC_READ_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}

fn local_scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("federation-threat-local")),
        namespace_id: None,
    }
}

fn remote_scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("federation-threat-remote")),
        namespace_id: None,
    }
}
fn principal(scope: TenantScope, name: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope,
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(name)),
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
        .expect("grant");
}

fn remote_device() -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid("federation-threat-device")),
        identity_id: IdentityId::from_opaque(oid("federation-threat-identity")),
        state: DeviceLifecycleState::Active,
    }
}
fn provision_remote_credential(
    store: &MemoryLocalStore,
    device: &DeviceDescriptor,
) -> (SigningKeyMaterial, PublicKeyDescriptor) {
    store
        .register_device(&remote_scope(), device)
        .expect("register remote device");
    let signer = SigningKeyMaterial::generate().expect("remote signer");
    let descriptor = PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid("federation-threat-key")),
        device_id: device.device_id.clone(),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: signer.verifying_key().0.to_vec(),
    };
    store
        .provision_trusted_signing_key(&remote_scope(), &descriptor)
        .expect("trust remote key");
    (signer, descriptor)
}

fn trusted_session(
    store: &MemoryLocalStore,
    signer: &SigningKeyMaterial,
    descriptor: &PublicKeyDescriptor,
) -> EstablishedSession {
    let local_signer = SigningKeyMaterial::generate().expect("local signer");
    let local_agreement = AgreementKeyPair::generate().expect("local agreement");
    let remote_agreement = AgreementKeyPair::generate().expect("remote agreement");
    let local_public = local_agreement.public_key();
    let remote_public = remote_agreement.public_key();
    let binding = TranscriptBinding::from_bytes([36_u8; 32]);
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
    .expect("trusted pending");
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
    let tag = remote_pending.local_confirmation_tag().expect("tag");
    local_pending.confirm_peer(tag).expect("session")
}

fn peer(device: &DeviceDescriptor, key: &PublicKeyDescriptor) -> FederationPeerRecord {
    FederationPeerRecord {
        local_scope: local_scope(),
        remote_scope: remote_scope(),
        local_endpoint_id: EndpointId::from_opaque(oid("federation-threat-local-node")),
        remote_endpoint_id: EndpointId::from_opaque(oid("federation-threat-remote-node")),
        remote_endpoint_kind: EndpointKind::OrganizationNode,
        expected_device_id: device.device_id.clone(),
        expected_signing_key_id: key.key_id.clone(),
        allowed_capabilities: vec!["ucr.sync".to_owned()],
        state: FederationTrustState::Known,
        generation: 1,
    }
}
fn active_sync(store: &MemoryLocalStore, peer: &FederationPeerRecord) -> SessionId {
    let id = SessionId::from_opaque(oid("federation-threat-sync"));
    store
        .create_sync_session(&SyncSession {
            session_id: id.clone(),
            scope: local_scope(),
            source_endpoint_id: peer.local_endpoint_id.clone(),
            target_endpoint_id: peer.remote_endpoint_id.clone(),
            link_kind: SyncLinkKind::DeviceNode,
            selection: SyncSelection {
                mode: SyncMode::Full,
                conversation_ids: Vec::new(),
            },
            state: SyncState::Prepared,
        })
        .expect("create sync");
    store
        .transition_sync(&local_scope(), &id, SyncState::Prepared, SyncState::Active)
        .expect("activate sync");
    id
}

#[test]
fn compromised_federated_node_cannot_self_authorize_or_survive_revocation() {
    let store = MemoryLocalStore::default();
    let admin = principal(local_scope(), "federation-threat-admin");
    let attacker = principal(remote_scope(), "federation-threat-attacker");
    for permission in [
        FEDERATION_PEER_MANAGE_PERMISSION,
        FEDERATION_SYNC_PERMISSION,
        SYNC_READ_PERMISSION,
    ] {
        grant(&store, &admin, permission);
    }
    let remote_device = remote_device();
    let (signer, key) = provision_remote_credential(&store, &remote_device);
    let session = trusted_session(&store, &signer, &key);
    let peer = peer(&remote_device, &key);
    let runtime = FederationRuntime::new(&store, &store);

    assert!(matches!(
        runtime.install_peer(&attacker, &peer),
        Err(FederationError::Authorization(_))
    ));
    assert!(
        store
            .federation_peer(&local_scope(), &remote_scope(), &peer.remote_endpoint_id)
            .expect("lookup")
            .is_none()
    );

    runtime.install_peer(&admin, &peer).expect("install peer");
    runtime
        .authenticate_peer(
            &admin,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
            &session,
        )
        .expect("authenticate");
    runtime
        .transition_peer(
            &admin,
            &local_scope(),
            &remote_scope(),
            &peer.remote_endpoint_id,
            2,
            FederationTrustState::Authorized,
        )
        .expect("authorize");
    let sync_id = active_sync(&store, &peer);
    runtime
        .admit_sync(
            &admin,
            &FederationSyncAdmission {
                local_scope: &peer.local_scope,
                remote_scope: &peer.remote_scope,
                remote_endpoint_id: &peer.remote_endpoint_id,
                sync_session_id: &sync_id,
                required_capability: "ucr.sync",
                session: &session,
            },
        )
        .expect("admitted before revocation");

    store
        .revoke_device(
            &remote_scope(),
            &remote_device.device_id,
            &remote_device.identity_id,
        )
        .expect("revoke remote device");

    assert!(matches!(
        runtime.admit_sync(
            &admin,
            &FederationSyncAdmission {
                local_scope: &peer.local_scope,
                remote_scope: &peer.remote_scope,
                remote_endpoint_id: &peer.remote_endpoint_id,
                sync_session_id: &sync_id,
                required_capability: "ucr.sync",
                session: &session
            }
        ),
        Err(FederationError::PeerDeviceInactive)
    ));
}

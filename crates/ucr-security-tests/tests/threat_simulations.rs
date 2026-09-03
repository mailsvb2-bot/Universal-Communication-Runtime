use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use ucr_core::{
    AuthorizedDurableRuntime, AuthorizedMutationError, DeviceLifecycleStore, PermissionGrantStore,
    TrustedSigningKeyStore,
};
use ucr_crypto::{
    AgreementKeyPair, ReplayError, ReplayProtector, SessionError, SessionRole, SignatureError,
    SigningKeyMaterial, TranscriptBinding, TrustedKeyResolutionError, TrustedMessageSignatureError,
    TrustedSessionError, TrustedSessionHandshakeInput, begin_session_with_trusted_peer,
    verify_message_signature_with_trust,
};
use ucr_model::{
    ActorId, ActorKind, ActorRef, ConversationId, ConversationKind, ConversationRef,
    CorrelationContext, CryptoSuite, DeliveryPolicy, DeliveryState, DeviceDescriptor, DeviceId,
    DeviceLifecycleState, DeviceRef, IdentityId, KeyId, KeyPurpose, MessageEnvelope, MessageId,
    MessageSignature, NamespaceId, OpaqueId, OriginRef, PermissionGrant, PermissionScope,
    PrincipalId, PrincipalKind, PrincipalRef, PublicKeyDescriptor, ScopedPrincipal, TenantId,
    TenantScope,
};
use ucr_protocol::{
    ALGORITHM_VERSION, CanonicalErrorCode, DEVICE_READ_PERMISSION, DEVICE_REGISTER_PERMISSION,
    KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, message_signing_binding,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_storage_sqlite::SqliteLocalStore;

static DB_SEQUENCE: AtomicU64 = AtomicU64::new(120_000);

struct TestDb(PathBuf);

impl TestDb {
    fn new(label: &str) -> Self {
        let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ucr-threat-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn scope(tenant: &str, namespace: Option<&str>) -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid(tenant)),
        namespace_id: namespace.map(|value| NamespaceId::from_opaque(oid(value))),
    }
}

fn subject(scope: &TenantScope, id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(id)),
            kind: PrincipalKind::Person,
        },
    }
}

fn grant(subject: &ScopedPrincipal, permission: &str, resource: &TenantScope) -> PermissionGrant {
    PermissionGrant {
        grantee: subject.clone(),
        permission: permission.to_owned(),
        scope: PermissionScope::Exact(resource.clone()),
    }
}

fn device(id: &str, identity: &str) -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid(id)),
        identity_id: IdentityId::from_opaque(oid(identity)),
        state: DeviceLifecycleState::Active,
    }
}

fn signing_descriptor(
    signer: &SigningKeyMaterial,
    key_id: &str,
    device_id: &DeviceId,
) -> PublicKeyDescriptor {
    PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid(key_id)),
        device_id: device_id.clone(),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: signer.verifying_key().0.to_vec(),
    }
}

fn register_trusted_signer(
    store: &MemoryLocalStore,
    scope: &TenantScope,
    identity: &str,
    signer: &SigningKeyMaterial,
    key_id: &str,
    device_id: &str,
) -> PublicKeyDescriptor {
    let descriptor = signing_descriptor(signer, key_id, &DeviceId::from_opaque(oid(device_id)));
    store
        .register_device(scope, &device(device_id, identity))
        .expect("register trusted device");
    store
        .provision_trusted_signing_key(scope, &descriptor)
        .expect("provision trusted signing key");
    descriptor
}

fn signed_message(
    signer: &SigningKeyMaterial,
    descriptor: &PublicKeyDescriptor,
    scope: &TenantScope,
    identity: &str,
) -> MessageEnvelope {
    let mut message = MessageEnvelope {
        message_id: MessageId::from_opaque(oid("threat-message")),
        scope: scope.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("threat-conversation")),
            kind: ConversationKind::Direct,
        },
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("threat-actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: descriptor.device_id.clone(),
            identity_id: IdentityId::from_opaque(oid(identity)),
        },
        created_at_unix_ms: 1,
        logical_order: 1,
        content: b"threat simulation".to_vec(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("threat-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("threat-correlation"),
            causation_id: None,
            idempotency_key: None,
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    };
    let binding = message_signing_binding(&message).expect("canonical message binding");
    message.signature = Some(MessageSignature {
        key_id: descriptor.key_id.clone(),
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        signature: signer.sign_message_binding(&binding).0.to_vec(),
    });
    message
}

fn trusted_handshake_input(
    scope: &TenantScope,
    descriptor: PublicKeyDescriptor,
    signer: &SigningKeyMaterial,
    binding_byte: u8,
) -> (AgreementKeyPair, TrustedSessionHandshakeInput) {
    let local = AgreementKeyPair::generate().expect("local agreement key");
    let peer = AgreementKeyPair::generate().expect("peer agreement key");
    let binding = TranscriptBinding::from_bytes([binding_byte; 32]);
    let input = TrustedSessionHandshakeInput {
        scope: scope.clone(),
        suite: CryptoSuite::UcrV1,
        role: SessionRole::Initiator,
        peer_agreement: peer.public_key(),
        initiator_public: local.public_key(),
        responder_public: peer.public_key(),
        peer_signing_descriptor: descriptor,
        peer_signature: signer.sign_transcript(&binding),
        binding,
    };
    (local, input)
}

#[test]
fn replay_simulation_survives_process_restart_and_rejects_duplicate_binding() {
    let db = TestDb::new("replay");
    let signer = SigningKeyMaterial::generate().expect("signer");
    let peer = signer.verifying_key();
    let binding = TranscriptBinding::from_bytes([41_u8; 32]);
    {
        let store = SqliteLocalStore::open(db.path()).expect("open replay store");
        assert_eq!(store.record_once(&peer, &binding), Ok(()));
    }
    let reopened = SqliteLocalStore::open(db.path()).expect("reopen replay store");
    assert_eq!(
        reopened.record_once(&peer, &binding),
        Err(ReplayError::Replayed)
    );
    assert_eq!(
        reopened.record_once(&peer, &TranscriptBinding::from_bytes([42_u8; 32])),
        Ok(())
    );
}

#[test]
fn mitm_simulation_cannot_replace_trusted_peer_signature_or_poison_replay_state() {
    let store = MemoryLocalStore::default();
    let tenant = scope("tenant-mitm", None);
    let trusted_signer = SigningKeyMaterial::generate().expect("trusted signer");
    let attacker = SigningKeyMaterial::generate().expect("attacker signer");
    let descriptor = register_trusted_signer(
        &store,
        &tenant,
        "identity-mitm",
        &trusted_signer,
        "mitm-key",
        "mitm-device",
    );
    let (local, input) = trusted_handshake_input(&tenant, descriptor.clone(), &attacker, 51);
    assert_eq!(
        begin_session_with_trusted_peer(local, &input, &store, &store)
            .expect_err("MITM signature must fail"),
        TrustedSessionError::Session(SessionError::Signature(SignatureError::InvalidSignature))
    );

    let (legit_local, legit_input) =
        trusted_handshake_input(&tenant, descriptor, &trusted_signer, 51);
    assert!(
        begin_session_with_trusted_peer(legit_local, &legit_input, &store, &store).is_ok(),
        "failed MITM attempt must not consume replay state"
    );
}

#[test]
fn forged_identity_simulation_fails_even_with_valid_device_private_key() {
    let store = MemoryLocalStore::default();
    let tenant = scope("tenant-forged-identity", None);
    let signer = SigningKeyMaterial::generate().expect("signer");
    let descriptor = register_trusted_signer(
        &store,
        &tenant,
        "identity-legitimate",
        &signer,
        "identity-key",
        "identity-device",
    );
    let forged = signed_message(&signer, &descriptor, &tenant, "identity-forged");
    assert_eq!(
        verify_message_signature_with_trust(&forged, &store),
        Err(TrustedMessageSignatureError::Trust(
            TrustedKeyResolutionError::NotTrusted
        ))
    );
}

#[test]
fn malicious_tenant_simulation_cannot_cross_scope_or_mutate_storage() {
    let store = MemoryLocalStore::default();
    let scope_a = scope("tenant-a", Some("namespace-a"));
    let scope_b = scope("tenant-b", Some("namespace-b"));
    let admin = subject(&scope_a, "tenant-a-admin");
    store
        .grant_permission(&grant(&admin, DEVICE_REGISTER_PERMISSION, &scope_a))
        .expect("bootstrap exact permission");
    let target = device("tenant-b-device", "tenant-b-identity");
    let runtime = AuthorizedDurableRuntime::new(&store, &store);
    let error = runtime
        .register_device(&admin, &scope_b, &target)
        .expect_err("cross-tenant register must fail");
    assert!(matches!(
        error,
        AuthorizedMutationError::Authorization(ref failure)
            if failure.code == CanonicalErrorCode::PermissionDenied
    ));
    assert_eq!(store.device(&scope_b, &target.device_id), Ok(None));
}

#[test]
fn malicious_service_account_simulation_cannot_bypass_admission_proof() {
    let store = MemoryLocalStore::default();
    let tenant = scope("tenant-service-attacker", None);
    let service = ScopedPrincipal {
        scope: tenant.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("malicious-service")),
            kind: PrincipalKind::ServiceAccount,
        },
    };
    store
        .grant_permission(&grant(&service, DEVICE_REGISTER_PERMISSION, &tenant))
        .expect("bootstrap persisted permission fixture");
    let target = device("service-target-device", "service-target-identity");
    let runtime = AuthorizedDurableRuntime::new(&store, &store);
    let error = runtime
        .register_device(&service, &tenant, &target)
        .expect_err("service account without admission proof must fail");
    assert!(matches!(
        error,
        AuthorizedMutationError::Authorization(ref failure)
            if failure.code == CanonicalErrorCode::PermissionDenied
    ));
    assert_eq!(store.device(&tenant, &target.device_id), Ok(None));
}

#[test]
fn malicious_peer_simulation_cannot_self_provision_claimed_key() {
    let store = MemoryLocalStore::default();
    let tenant = scope("tenant-malicious-peer", None);
    let signer = SigningKeyMaterial::generate().expect("trusted signer");
    let descriptor = register_trusted_signer(
        &store,
        &tenant,
        "identity-peer",
        &signer,
        "peer-key",
        "peer-device",
    );
    let mut false_claim = descriptor.clone();
    false_claim.public_key[0] ^= 1;
    let (local, input) = trusted_handshake_input(&tenant, false_claim, &signer, 61);
    assert_eq!(
        begin_session_with_trusted_peer(local, &input, &store, &store)
            .expect_err("peer claim must not become trust"),
        TrustedSessionError::Trust(TrustedKeyResolutionError::NotTrusted)
    );

    let (legit_local, legit_input) = trusted_handshake_input(&tenant, descriptor, &signer, 61);
    assert!(
        begin_session_with_trusted_peer(legit_local, &legit_input, &store, &store).is_ok(),
        "rejected peer claim must not poison replay/trust state"
    );
}

#[test]
fn invalid_permission_simulation_denies_mutation_before_storage() {
    let store = MemoryLocalStore::default();
    let tenant = scope("tenant-permission", Some("namespace-permission"));
    let reader = subject(&tenant, "read-only-principal");
    store
        .grant_permission(&grant(&reader, DEVICE_READ_PERMISSION, &tenant))
        .expect("bootstrap read-only permission");
    let target = device("write-denied-device", "write-denied-identity");
    let runtime = AuthorizedDurableRuntime::new(&store, &store);
    let error = runtime
        .register_device(&reader, &tenant, &target)
        .expect_err("read permission cannot authorize register");
    assert!(matches!(
        error,
        AuthorizedMutationError::Authorization(ref failure)
            if failure.code == CanonicalErrorCode::PermissionDenied
    ));
    assert_eq!(store.device(&tenant, &target.device_id), Ok(None));
}

#[test]
fn revoked_device_simulation_denies_existing_signature_and_future_key_access() {
    let store = MemoryLocalStore::default();
    let tenant = scope("tenant-revoked", None);
    let signer = SigningKeyMaterial::generate().expect("signer");
    let descriptor = register_trusted_signer(
        &store,
        &tenant,
        "identity-revoked",
        &signer,
        "revoked-key",
        "revoked-device",
    );
    let message = signed_message(&signer, &descriptor, &tenant, "identity-revoked");
    assert_eq!(
        verify_message_signature_with_trust(&message, &store),
        Ok(())
    );

    store
        .revoke_device(
            &tenant,
            &descriptor.device_id,
            &IdentityId::from_opaque(oid("identity-revoked")),
        )
        .expect("revoke device");
    assert_eq!(
        verify_message_signature_with_trust(&message, &store),
        Err(TrustedMessageSignatureError::Trust(
            TrustedKeyResolutionError::NotTrusted
        ))
    );
    let replacement = signing_descriptor(
        &SigningKeyMaterial::generate().expect("replacement signer"),
        "replacement-key",
        &descriptor.device_id,
    );
    assert_eq!(
        store.provision_trusted_signing_key(&tenant, &replacement),
        Err(ucr_core::DurableStoreError::PermissionDenied)
    );
}

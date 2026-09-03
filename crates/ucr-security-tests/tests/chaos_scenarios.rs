use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    thread,
};

use ucr_core::{
    AntiEntropyStore, AuthorizedDurableRuntime, AuthorizedMutationError, CommandAcceptanceStore,
    DeviceLifecycleStore, DurableStoreError, EventAppendStatus, EventJournalStore,
    PermissionGrantStore, ServiceAuditStore, ServiceCredentialStore, ServicePrincipalRequestGate,
    ServiceQuotaClock, ServiceQuotaClockError, ServiceQuotaStore, SyncStore,
    TrustedSigningKeyStore, issue_service_credential,
};
use ucr_crypto::{
    MessageSignatureVerificationError, SigningKeyMaterial, TrustedKeyResolutionError,
    TrustedMessageSignatureError, TrustedSigningKeyResolver, verify_message_signature_with_trust,
};
use ucr_model::{
    ActorId, ActorKind, ActorRef, CommandEnvelope, CommandId, ConversationId, ConversationKind,
    ConversationRef, CorrelationContext, DeliveryPolicy, DeliveryState, DeviceDescriptor, DeviceId,
    DeviceLifecycleState, DeviceRef, EndpointId, EventEnvelope, EventId, EventReplicaState,
    IdentityId, KeyId, KeyPurpose, MessageEnvelope, MessageId, MessageSignature, NamespaceId,
    OpaqueId, OriginRef, PermissionGrant, PermissionScope, PrincipalId, PrincipalKind,
    PrincipalRef, ProtocolVersion, PublicKeyDescriptor, ScopedPrincipal, ServiceAuditOutcome,
    ServiceQuotaPolicy, SessionId, SyncLinkKind, SyncMode, SyncSelection, SyncSession, SyncState,
    TenantId, TenantScope,
};
use ucr_protocol::{
    ALGORITHM_VERSION, CONVERSATION_READ_PERMISSION, CanonicalError, CanonicalErrorCode,
    CommandReceiptStatus, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, VersionNegotiationError,
    VersionPolicy, VersionRange, message_signing_binding, negotiate_version,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_storage_sqlite::SqliteLocalStore;

static DB_SEQUENCE: AtomicU64 = AtomicU64::new(180_000);

struct TestDb(PathBuf);

impl TestDb {
    fn new(label: &str) -> Self {
        let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ucr-chaos-{label}-{}-{sequence}.sqlite3",
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

#[derive(Debug)]
struct TestClock(AtomicI64);

impl TestClock {
    fn new(now_unix_ms: i64) -> Self {
        Self(AtomicI64::new(now_unix_ms))
    }

    fn set(&self, now_unix_ms: i64) {
        self.0.store(now_unix_ms, Ordering::Release);
    }
}

impl ServiceQuotaClock for TestClock {
    fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
        Ok(self.0.load(Ordering::Acquire))
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

fn command(id: &str, idempotency_key: &str, payload: &[u8]) -> CommandEnvelope {
    CommandEnvelope {
        command_id: CommandId::from_opaque(oid(id)),
        scope: scope("tenant-chaos-command", Some("namespace-chaos-command")),
        command_type: "ucr.message.send".to_owned(),
        payload: payload.to_vec(),
        correlation: CorrelationContext {
            correlation_id: oid(&format!("correlation-{id}")),
            causation_id: None,
            idempotency_key: Some(idempotency_key.to_owned()),
        },
        schema_version: ProtocolVersion::new(1, 0),
        extensions: Vec::new(),
    }
}

fn service_subject(resource: &TenantScope) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: resource.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("service-chaos-clock")),
            kind: PrincipalKind::ServiceAccount,
        },
    }
}

fn exact_grant(
    subject: &ScopedPrincipal,
    permission: &str,
    resource: &TenantScope,
) -> PermissionGrant {
    PermissionGrant {
        grantee: subject.clone(),
        permission: permission.to_owned(),
        scope: PermissionScope::Exact(resource.clone()),
    }
}

fn sync_session() -> SyncSession {
    SyncSession {
        session_id: SessionId::from_opaque(oid("chaos-partition-sync")),
        scope: scope("tenant-chaos-partition", None),
        source_endpoint_id: EndpointId::from_opaque(oid("chaos-source")),
        target_endpoint_id: EndpointId::from_opaque(oid("chaos-target")),
        link_kind: SyncLinkKind::DeviceDevice,
        selection: SyncSelection {
            mode: SyncMode::Full,
            conversation_ids: Vec::new(),
        },
        state: SyncState::Prepared,
    }
}

fn activate_sync(store: &MemoryLocalStore, session: &SyncSession) {
    store
        .create_sync_session(session)
        .expect("create sync session");
    store
        .transition_sync(
            &session.scope,
            &session.session_id,
            SyncState::Prepared,
            SyncState::Active,
        )
        .expect("activate sync session");
}

fn event(session: &SyncSession, id: &str, payload: &[u8]) -> EventEnvelope {
    EventEnvelope {
        event_id: EventId::from_opaque(oid(id)),
        scope: session.scope.clone(),
        event_type: "ucr.chaos.event".to_owned(),
        payload: payload.to_vec(),
        actor: ActorRef {
            actor_id: ActorId::from_opaque(oid("chaos-actor")),
            kind: ActorKind::System,
            on_behalf_of: None,
        },
        source_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("chaos-device")),
            identity_id: IdentityId::from_opaque(oid("chaos-identity")),
        },
        wall_time_unix_ms: 1,
        logical_order: 1,
        correlation: CorrelationContext {
            correlation_id: oid(&format!("chaos-correlation-{id}")),
            causation_id: None,
            idempotency_key: None,
        },
        schema_version: ProtocolVersion::new(1, 0),
        integrity_metadata: Vec::new(),
        extensions: Vec::new(),
    }
}

fn active_device() -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid("chaos-revoked-device")),
        identity_id: IdentityId::from_opaque(oid("chaos-revoked-identity")),
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

fn signed_message(
    signer: &SigningKeyMaterial,
    descriptor: &PublicKeyDescriptor,
    resource: &TenantScope,
) -> MessageEnvelope {
    let mut message = MessageEnvelope {
        message_id: MessageId::from_opaque(oid("chaos-corrupt-message")),
        scope: resource.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("chaos-corrupt-conversation")),
            kind: ConversationKind::Direct,
        },
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("chaos-message-actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: descriptor.device_id.clone(),
            identity_id: IdentityId::from_opaque(oid("chaos-message-identity")),
        },
        created_at_unix_ms: 1,
        logical_order: 1,
        content: b"authenticated chaos payload".to_vec(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("chaos-message-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("chaos-message-correlation"),
            causation_id: None,
            idempotency_key: None,
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    };
    let binding = message_signing_binding(&message).expect("message signing binding");
    message.signature = Some(MessageSignature {
        key_id: descriptor.key_id.clone(),
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        signature: signer.sign_message_binding(&binding).0.to_vec(),
    });
    message
}

#[test]
fn app_restart_chaos_preserves_command_deduplication() {
    let db = TestDb::new("restart-command");
    let original = command("chaos-command-a", "chaos-retry", b"payload");
    {
        let store = SqliteLocalStore::open(db.path()).expect("open command store");
        let receipt = store.accept_command(&original).expect("accept command");
        assert_eq!(receipt.status, CommandReceiptStatus::Accepted);
    }

    let retry = command("chaos-command-b", "chaos-retry", b"payload");
    let reopened = SqliteLocalStore::open(db.path()).expect("reopen command store");
    let receipt = reopened.accept_command(&retry).expect("deduplicate retry");
    assert_eq!(receipt.status, CommandReceiptStatus::Duplicate);
    assert_eq!(receipt.original_command_id, Some(original.command_id));
}

#[test]
fn duplicate_ingress_chaos_has_one_canonical_acceptance() {
    let db = TestDb::new("duplicate-race");
    drop(SqliteLocalStore::open(db.path()).expect("initialize store"));
    let barrier = Arc::new(Barrier::new(3));
    let spawn = |id: &'static str| {
        let path = db.path().to_owned();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let store = SqliteLocalStore::open(path).expect("open concurrent store");
            let value = command(id, "chaos-duplicate-key", b"same-payload");
            barrier.wait();
            store.accept_command(&value)
        })
    };
    let first = spawn("chaos-duplicate-a");
    let second = spawn("chaos-duplicate-b");
    barrier.wait();
    let receipts = [
        first
            .join()
            .expect("first duplicate thread")
            .expect("first receipt"),
        second
            .join()
            .expect("second duplicate thread")
            .expect("second receipt"),
    ];
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.status == CommandReceiptStatus::Accepted)
            .count(),
        1
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.status == CommandReceiptStatus::Duplicate)
            .count(),
        1
    );
}

#[test]
fn clock_rollback_chaos_fails_closed_and_is_audited() {
    let store = MemoryLocalStore::default();
    let resource = scope("tenant-chaos-clock", Some("namespace-chaos-clock"));
    let service = service_subject(&resource);
    let (credential, secret) = issue_service_credential(&service).expect("issue credential");
    store
        .provision_service_credential(&credential)
        .expect("provision credential");
    store
        .grant_permission(&exact_grant(
            &service,
            CONVERSATION_READ_PERMISSION,
            &resource,
        ))
        .expect("grant read permission");
    store
        .set_service_quota_policy(&ServiceQuotaPolicy {
            subject: service,
            max_requests: 4,
            window_ms: 1_000,
        })
        .expect("set quota policy");
    let clock = TestClock::new(10_000);
    let missing = ConversationId::from_opaque(oid("chaos-clock-conversation"));

    let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
    let first = gate
        .authenticate_request(
            &resource,
            &credential.credential_id,
            &secret,
            CONVERSATION_READ_PERMISSION,
            &resource,
        )
        .expect("authenticate initial request");
    let runtime = AuthorizedDurableRuntime::new(&first, &store);
    assert_eq!(
        runtime.conversation(first.subject(), &resource, &missing),
        Ok(None)
    );

    clock.set(9_999);
    let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
    let rollback = gate
        .authenticate_request(
            &resource,
            &credential.credential_id,
            &secret,
            CONVERSATION_READ_PERMISSION,
            &resource,
        )
        .expect("authentication precedes quota clock check");
    let runtime = AuthorizedDurableRuntime::new(&rollback, &store);
    assert_eq!(
        runtime.conversation(rollback.subject(), &resource, &missing),
        Err(AuthorizedMutationError::Authorization(CanonicalError::new(
            CanonicalErrorCode::TemporarilyUnavailable,
        )))
    );
    let audit = store
        .service_audit_records(&resource, 8)
        .expect("read chaos audit");
    assert_eq!(
        audit.last().map(|record| record.outcome),
        Some(ServiceAuditOutcome::QuotaUnavailable)
    );
}

#[test]
fn local_partition_merge_chaos_recovers_missing_and_refuses_damaged_state() {
    let source = MemoryLocalStore::default();
    let target = MemoryLocalStore::default();
    let sync = sync_session();
    activate_sync(&source, &sync);
    activate_sync(&target, &sync);

    let matching = event(&sync, "chaos-event-matching", b"same");
    let damaged_source = event(&sync, "chaos-event-damaged", b"source");
    let missing = event(&sync, "chaos-event-missing", b"missing");
    for value in [&matching, &damaged_source, &missing] {
        source.append_event(value).expect("append source event");
    }
    target
        .append_event(&matching)
        .expect("append matching target event");
    target
        .append_event(&event(&sync, "chaos-event-damaged", b"different-target"))
        .expect("append damaged target event");

    let page = source
        .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 8)
        .expect("source anti-entropy page");
    let states = target
        .classify_event_summaries(&sync.scope, &sync.session_id, &page.summaries)
        .expect("classify partition merge");
    assert_eq!(states[0].state, EventReplicaState::Matching);
    assert_eq!(states[1].state, EventReplicaState::Damaged);
    assert_eq!(states[2].state, EventReplicaState::Missing);
    assert_eq!(
        target.reconcile_event(&sync.scope, &sync.session_id, &matching),
        Ok(EventAppendStatus::Duplicate)
    );
    assert_eq!(
        target.reconcile_event(&sync.scope, &sync.session_id, &damaged_source),
        Err(DurableStoreError::Conflict)
    );
    assert_eq!(
        target.reconcile_event(&sync.scope, &sync.session_id, &missing),
        Ok(EventAppendStatus::Appended)
    );

    let after = target
        .classify_event_summaries(&sync.scope, &sync.session_id, &page.summaries)
        .expect("classify after merge");
    assert_eq!(after[0].state, EventReplicaState::Matching);
    assert_eq!(after[1].state, EventReplicaState::Damaged);
    assert_eq!(after[2].state, EventReplicaState::Matching);
}

#[test]
fn old_client_chaos_cannot_force_policy_downgrade() {
    let local = VersionRange::new(ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 4))
        .expect("local version range");
    let old_client = VersionRange::new(ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 0))
        .expect("old client range");
    assert_eq!(
        negotiate_version(
            local,
            old_client,
            VersionPolicy {
                minimum: ProtocolVersion::new(2, 1),
            },
        ),
        Err(VersionNegotiationError::BelowLocalMinimum)
    );
    let compatible = VersionRange::new(ProtocolVersion::new(2, 1), ProtocolVersion::new(2, 1))
        .expect("compatible client range");
    assert_eq!(
        negotiate_version(
            local,
            compatible,
            VersionPolicy {
                minimum: ProtocolVersion::new(2, 1),
            },
        ),
        Ok(ProtocolVersion::new(2, 1))
    );
}

#[test]
fn authenticated_message_corruption_chaos_fails_closed() {
    let store = MemoryLocalStore::default();
    let resource = scope("tenant-chaos-corruption", None);
    let signer = SigningKeyMaterial::generate().expect("generate signer");
    let device = DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid("chaos-message-device")),
        identity_id: IdentityId::from_opaque(oid("chaos-message-identity")),
        state: DeviceLifecycleState::Active,
    };
    let descriptor = signing_descriptor(&signer, "chaos-message-key", &device.device_id);
    store
        .register_device(&resource, &device)
        .expect("register device");
    store
        .provision_trusted_signing_key(&resource, &descriptor)
        .expect("provision signing key");
    let message = signed_message(&signer, &descriptor, &resource);
    assert_eq!(
        verify_message_signature_with_trust(&message, &store),
        Ok(())
    );

    let mut corrupted = message;
    corrupted.content.push(b'!');
    assert_eq!(
        verify_message_signature_with_trust(&corrupted, &store),
        Err(TrustedMessageSignatureError::Verification(
            MessageSignatureVerificationError::InvalidSignature,
        ))
    );
}

#[test]
fn revoked_device_restart_chaos_never_resurrects_trust() {
    let db = TestDb::new("revoked-restart");
    let resource = scope("tenant-chaos-revoked", None);
    let device = active_device();
    let signer = SigningKeyMaterial::generate().expect("generate signer");
    let descriptor = signing_descriptor(&signer, "chaos-revoked-key", &device.device_id);
    {
        let store = SqliteLocalStore::open(db.path()).expect("open revoked store");
        store
            .register_device(&resource, &device)
            .expect("register device");
        store
            .provision_trusted_signing_key(&resource, &descriptor)
            .expect("provision trusted key");
    }
    {
        let store = SqliteLocalStore::open(db.path()).expect("reopen before revoke");
        store
            .revoke_device(&resource, &device.device_id, &device.identity_id)
            .expect("revoke device");
    }
    let reopened = SqliteLocalStore::open(db.path()).expect("reopen after revoke");
    assert_eq!(
        reopened.resolve_active_signing_key(
            &resource,
            &device.device_id,
            Some(&device.identity_id),
            &descriptor.key_id,
        ),
        Err(TrustedKeyResolutionError::NotTrusted)
    );
    let replacement = signing_descriptor(
        &SigningKeyMaterial::generate().expect("replacement signer"),
        "chaos-replacement-key",
        &device.device_id,
    );
    assert_eq!(
        reopened.provision_trusted_signing_key(&resource, &replacement),
        Err(DurableStoreError::PermissionDenied)
    );
    assert_eq!(
        reopened.register_device(&resource, &device),
        Err(DurableStoreError::Conflict)
    );
}

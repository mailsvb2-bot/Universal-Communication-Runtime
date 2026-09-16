use std::{collections::HashMap, sync::Arc};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, transport::Server};
use ucr_api_grpc::{
    AuthenticatedMeshPeerSession, GrpcMeshService, MeshPeerSessionResolver,
    attach_service_credential, mesh_service_server, pb,
};
use ucr_core::{
    DeviceLifecycleStore, DurableRecordStatus, GroupStore, PermissionGrantStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaStore, SyncStore,
    SystemServiceQuotaClock, TrustedSigningKeyStore, issue_service_credential,
};
use ucr_crypto::{
    AgreementKeyPair, EstablishedSession, SessionHandshakeInput, SessionRole, SigningKeyMaterial,
    TranscriptBinding, TrustedSessionHandshakeInput, begin_session,
    begin_session_with_trusted_peer,
};
use ucr_mesh::MeshGroupsRuntime;
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, SYNC_READ_PERMISSION,
    SYNC_WRITE_PERMISSION, message_signing_binding,
};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("phase40-mesh-tenant")),
        namespace_id: None,
    }
}

fn device_subject(id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(id)),
            kind: PrincipalKind::Device,
        },
    }
}

fn service_subject(id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(id)),
            kind: PrincipalKind::ServiceAccount,
        },
    }
}

fn device_descriptor(id: &str) -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid(id)),
        identity_id: IdentityId::from_opaque(oid(&format!("identity-{id}"))),
        state: DeviceLifecycleState::Active,
    }
}
fn trusted_peer_session(
    store: &MemoryLocalStore,
    peer: &DeviceDescriptor,
    signer: &SigningKeyMaterial,
    key_id: &str,
    binding_byte: u8,
) -> Arc<EstablishedSession> {
    let descriptor = PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid(key_id)),
        device_id: peer.device_id.clone(),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: signer.verifying_key().0.to_vec(),
    };
    store
        .provision_trusted_signing_key(&scope(), &descriptor)
        .expect("peer trust");
    let local_signer = SigningKeyMaterial::generate().expect("local signer");
    let local_agreement = AgreementKeyPair::generate().expect("local agreement");
    let peer_agreement = AgreementKeyPair::generate().expect("peer agreement");
    let local_public = local_agreement.public_key();
    let peer_public = peer_agreement.public_key();
    let binding = TranscriptBinding::from_bytes([binding_byte; 32]);
    let local_pending = begin_session_with_trusted_peer(
        local_agreement,
        &TrustedSessionHandshakeInput {
            scope: scope(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: peer_public,
            initiator_public: local_public,
            responder_public: peer_public,
            peer_signing_descriptor: descriptor,
            peer_signature: signer.sign_transcript(&binding),
            binding,
        },
        store,
        store,
    )
    .expect("trusted local pending");
    let peer_pending = begin_session(
        peer_agreement,
        SessionHandshakeInput {
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Responder,
            peer_agreement: local_public,
            initiator_public: local_public,
            responder_public: peer_public,
            trusted_peer_verifying_key: local_signer.verifying_key(),
            peer_signature: local_signer.sign_transcript(&binding),
            binding,
        },
        store,
    )
    .expect("peer pending");
    Arc::new(
        local_pending
            .confirm_peer(peer_pending.local_confirmation_tag().expect("peer tag"))
            .expect("established"),
    )
}

fn active_sync(
    store: &MemoryLocalStore,
    id: &str,
    conversation_id: &ConversationId,
    source_suffix: &str,
    target_suffix: &str,
) -> SyncSession {
    let session = SyncSession {
        session_id: SessionId::from_opaque(oid(id)),
        scope: scope(),
        source_endpoint_id: EndpointId::from_opaque(oid(source_suffix)),
        target_endpoint_id: EndpointId::from_opaque(oid(target_suffix)),
        link_kind: SyncLinkKind::PeerPeer,
        selection: SyncSelection {
            mode: SyncMode::Partial,
            conversation_ids: vec![conversation_id.clone()],
        },
        state: SyncState::Prepared,
    };
    store.create_sync_session(&session).expect("sync create");
    store
        .transition_sync(
            &scope(),
            &session.session_id,
            SyncState::Prepared,
            SyncState::Active,
        )
        .expect("sync active");
    session
}

fn group_with_members(
    store: &MemoryLocalStore,
    owner: &ScopedPrincipal,
    members: [&ScopedPrincipal; 2],
) -> GroupRecord {
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("phase40-mesh-conversation")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("phase40-mesh-group")),
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::Temporary {
            owner: Some(owner.principal.clone()),
            expires_at_unix_ms: 9_999_999_999_999,
        },
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
    };
    store
        .create_group(&conversation, &group, owner)
        .expect("group");
    for (index, member) in members.into_iter().enumerate() {
        store
            .apply_group_change(
                owner,
                &GroupChange {
                    event_id: EventId::from_opaque(oid(if index == 0 {
                        "phase40-mesh-add-a"
                    } else {
                        "phase40-mesh-add-c"
                    })),
                    scope: scope(),
                    group_id: group.group_id.clone(),
                    expected_revision: index as u64,
                    kind: GroupChangeKind::AddMember {
                        member: member.principal.clone(),
                        role: GroupRole::Member,
                    },
                    next_crypto_state: None,
                },
            )
            .expect("add member");
    }
    group
}

struct Fixture {
    store: Arc<MemoryLocalStore>,
    a: ScopedPrincipal,
    b: ScopedPrincipal,
    c: ScopedPrincipal,
    a_device: DeviceDescriptor,
    a_signer: SigningKeyMaterial,
    group: GroupRecord,
    sync_a: SyncSession,
    sync_c: SyncSession,
    sync_b: SyncSession,
    session_a: Arc<EstablishedSession>,
    session_c: Arc<EstablishedSession>,
    session_b: Arc<EstablishedSession>,
}

fn fixture() -> Fixture {
    let store = Arc::new(MemoryLocalStore::default());
    let a = device_subject("phase40-mesh-a");
    let b = device_subject("phase40-mesh-b");
    let c = device_subject("phase40-mesh-c");
    let a_device = device_descriptor("phase40-mesh-a");
    let b_device = device_descriptor("phase40-mesh-b");
    let c_device = device_descriptor("phase40-mesh-c");
    for descriptor in [&a_device, &b_device, &c_device] {
        store
            .register_device(&scope(), descriptor)
            .expect("register device");
    }
    let a_signer = SigningKeyMaterial::generate().expect("a signer");
    let b_signer = SigningKeyMaterial::generate().expect("b signer");
    let c_signer = SigningKeyMaterial::generate().expect("c signer");
    let session_a = trusted_peer_session(
        store.as_ref(),
        &a_device,
        &a_signer,
        "phase40-mesh-a-key",
        40,
    );
    let session_c = trusted_peer_session(
        store.as_ref(),
        &c_device,
        &c_signer,
        "phase40-mesh-c-key",
        41,
    );
    let session_b = trusted_peer_session(
        store.as_ref(),
        &b_device,
        &b_signer,
        "phase40-mesh-b-key",
        42,
    );
    let group = group_with_members(store.as_ref(), &b, [&a, &c]);
    let sync_a = active_sync(
        store.as_ref(),
        "phase40-mesh-sync-a",
        &group.conversation.conversation_id,
        "phase40-mesh-b-endpoint",
        "phase40-mesh-a-endpoint",
    );
    let sync_c = active_sync(
        store.as_ref(),
        "phase40-mesh-sync-c",
        &group.conversation.conversation_id,
        "phase40-mesh-b-endpoint-2",
        "phase40-mesh-c-endpoint",
    );
    let sync_b = active_sync(
        store.as_ref(),
        "phase40-mesh-sync-b",
        &group.conversation.conversation_id,
        "phase40-mesh-c-endpoint-2",
        "phase40-mesh-b-endpoint-2",
    );
    Fixture {
        store,
        a,
        b,
        c,
        a_device,
        a_signer,
        group,
        sync_a,
        sync_c,
        sync_b,
        session_a,
        session_c,
        session_b,
    }
}
fn signed_a_message(f: &Fixture) -> MeshGroupMessageReplica {
    let mut message = MessageEnvelope {
        message_id: MessageId::from_opaque(oid("phase40-mesh-message")),
        scope: scope(),
        conversation: f.group.conversation.clone(),
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("phase40-mesh-actor-a")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: f.a_device.device_id.clone(),
            identity_id: f.a_device.identity_id.clone(),
        },
        created_at_unix_ms: 1,
        logical_order: 1,
        content: b"phase40 mesh hello".to_vec(),
        attachment_ids: vec![],
        reply_to: None,
        relations: vec![],
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Persisted,
        origin: OriginRef {
            principal_id: Some(f.a.principal.principal_id.clone()),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("phase40-mesh-correlation"),
            causation_id: None,
            idempotency_key: Some("phase40-mesh-idempotency".into()),
        },
        extensions: vec![],
        external_mappings: vec![],
        signature: None,
    };
    let binding = message_signing_binding(&message).expect("message binding");
    message.signature = Some(MessageSignature {
        key_id: KeyId::from_opaque(oid("phase40-mesh-a-key")),
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        signature: f.a_signer.sign_message_binding(&binding).0.to_vec(),
    });
    MeshGroupMessageReplica {
        record: OfflineGroupMessageReplica {
            author: f.a.clone(),
            group_id: f.group.group_id.clone(),
            group_generation: 2,
            message,
        },
        forward_path: vec![f.a_device.device_id.clone()],
    }
}
#[derive(Default)]
struct StaticMeshResolver {
    sessions: HashMap<String, AuthenticatedMeshPeerSession>,
}

impl MeshPeerSessionResolver for StaticMeshResolver {
    fn resolve(
        &self,
        _scope: &TenantScope,
        sync_session_id: &SessionId,
    ) -> Option<AuthenticatedMeshPeerSession> {
        self.sessions
            .get(sync_session_id.as_opaque().as_str())
            .cloned()
    }
}

fn seed_service(
    store: &MemoryLocalStore,
    id: &str,
    permissions: &[&str],
) -> (ServiceCredentialId, ServiceCredentialSecret) {
    let subject = service_subject(id);
    let (record, secret) = issue_service_credential(&subject).expect("issue credential");
    store
        .provision_service_credential(&record)
        .expect("credential");
    for permission in permissions {
        store
            .grant_permission(&PermissionGrant {
                grantee: subject.clone(),
                permission: (*permission).to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("permission");
    }
    store
        .set_service_quota_policy(&ServiceQuotaPolicy {
            subject,
            max_requests: 64,
            window_ms: 60_000,
        })
        .expect("quota");
    (record.credential_id, secret)
}

fn pb_id(value: &str) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    }
}

fn wire_scope() -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb_id("phase40-mesh-tenant")),
        namespace_id: None,
    }
}

async fn grpc_client_and_server(
    fixture: &Fixture,
) -> (
    pb::mesh_service_client::MeshServiceClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let resolver = StaticMeshResolver {
        sessions: HashMap::from([
            (
                fixture.sync_a.session_id.as_opaque().as_str().to_owned(),
                AuthenticatedMeshPeerSession::new(
                    fixture.b.clone(),
                    fixture.a.clone(),
                    Arc::clone(&fixture.session_a),
                ),
            ),
            (
                fixture.sync_c.session_id.as_opaque().as_str().to_owned(),
                AuthenticatedMeshPeerSession::new(
                    fixture.b.clone(),
                    fixture.c.clone(),
                    Arc::clone(&fixture.session_c),
                ),
            ),
            (
                fixture.sync_b.session_id.as_opaque().as_str().to_owned(),
                AuthenticatedMeshPeerSession::new(
                    fixture.c.clone(),
                    fixture.b.clone(),
                    Arc::clone(&fixture.session_b),
                ),
            ),
        ]),
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC listener");
    let address = listener.local_addr().expect("gRPC listener address");
    let incoming = TcpListenerStream::new(listener);
    let store = Arc::clone(&fixture.store);
    let service = GrpcMeshService::new(
        Arc::new(SystemServiceQuotaClock),
        Arc::clone(&store),
        store,
        Arc::new(resolver),
    );
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(mesh_service_server(service))
            .serve_with_incoming(incoming)
            .await
    });
    let client = pb::mesh_service_client::MeshServiceClient::connect(format!("http://{address}"))
        .await
        .expect("connect mesh client");
    (client, server)
}
#[tokio::test(flavor = "multi_thread")]
async fn public_mesh_export_and_reconcile_use_authenticated_phase28_runtime() {
    let fixture = fixture();
    let record = signed_a_message(&fixture);
    let runtime = MeshGroupsRuntime::new(fixture.store.as_ref());
    assert_eq!(
        runtime.reconcile_message(
            &fixture.b,
            &fixture.a,
            &fixture.sync_a.session_id,
            &record,
            fixture.session_a.as_ref(),
        ),
        Ok(DurableRecordStatus::Persisted)
    );
    let (credential_id, secret) = seed_service(
        fixture.store.as_ref(),
        "phase40-mesh-service",
        &[SYNC_READ_PERMISSION, SYNC_WRITE_PERMISSION],
    );
    let (denied_id, denied_secret) = seed_service(
        fixture.store.as_ref(),
        "phase40-mesh-denied",
        &[SYNC_READ_PERMISSION],
    );
    let (mut client, server) = grpc_client_and_server(&fixture).await;

    let mut export = Request::new(pb::MeshExportGroupMessagesRequest {
        scope: Some(wire_scope()),
        sync_session_id: Some(pb_id("phase40-mesh-sync-c")),
        group_id: Some(pb_id("phase40-mesh-group")),
        cursor: None,
        max_items: 8,
    });
    attach_service_credential(&mut export, &credential_id, &secret);
    let page = match client
        .export_group_messages(export)
        .await
        .expect("mesh export transport")
        .into_inner()
        .result
        .expect("mesh export result")
    {
        pb::mesh_export_group_messages_response::Result::Page(page) => page,
        pb::mesh_export_group_messages_response::Result::Error(error) => {
            panic!("mesh export failed: {:?}", error.code)
        }
    };
    assert_eq!(page.records.len(), 1);
    let wire_record = page.records[0].clone();

    let mut reconcile = Request::new(pb::MeshReconcileGroupMessageRequest {
        scope: Some(wire_scope()),
        sync_session_id: Some(pb_id("phase40-mesh-sync-b")),
        record: Some(wire_record.clone()),
    });
    attach_service_credential(&mut reconcile, &credential_id, &secret);
    let response = client
        .reconcile_group_message(reconcile)
        .await
        .expect("mesh reconcile transport")
        .into_inner();
    assert!(matches!(
        response.result.expect("mesh reconcile result"),
        pb::mesh_reconcile_group_message_response::Result::Acknowledgement(_)
    ));

    let mut denied = Request::new(pb::MeshReconcileGroupMessageRequest {
        scope: Some(wire_scope()),
        sync_session_id: Some(pb_id("phase40-mesh-sync-b")),
        record: Some(wire_record),
    });
    attach_service_credential(&mut denied, &denied_id, &denied_secret);
    let denied = client
        .reconcile_group_message(denied)
        .await
        .expect("denied mesh reconcile transport")
        .into_inner();
    let error = match denied.result.expect("denied mesh result") {
        pb::mesh_reconcile_group_message_response::Result::Error(error) => error,
        pb::mesh_reconcile_group_message_response::Result::Acknowledgement(_) => {
            panic!("write-denied mesh reconcile unexpectedly succeeded")
        }
    };
    assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
    server.abort();
}

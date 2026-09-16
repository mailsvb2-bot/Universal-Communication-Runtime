use std::{
    collections::{HashMap, HashSet},
    net::TcpListener as StdTcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, transport::Server};
use ucr_api_grpc::{
    GrpcLocalTransportService, attach_service_credential, local_transport_service_server, pb,
};
use ucr_core::{
    PermissionGrantStore, ServiceAuditStore, ServiceCredentialSecret, ServiceCredentialStore,
    ServiceQuotaStore, SystemServiceQuotaClock, issue_service_credential,
};
use ucr_crypto::{
    ReplayError, ReplayProtector, SigningKeyMaterial, TranscriptBinding, TrustedKeyResolutionError,
    TrustedSigningKeyResolver, VerifyingKeyBytes,
};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, CryptoSuite, DeviceId, EndpointId, HandshakeNonce,
    IdentityId, KeyId, KeyPurpose, NamespaceId, OpaqueId, PermissionGrant, PermissionScope,
    PrincipalId, PrincipalKind, PrincipalRef, PublicKeyDescriptor, ScopedPrincipal,
    ServiceAuditOperationRef, ServiceAuditOutcome, ServiceQuotaPolicy, TenantId, TenantScope,
};
use ucr_protocol::{
    ALGORITHM_VERSION, CapabilityRequirement, CryptoPolicy, KEY_FORMAT_VERSION,
    LOCAL_TRANSPORT_USE_PERMISSION, NegotiationPolicy, PeerHello, ProtocolVersion,
    SERVICE_AUDIT_LOCAL_TRANSPORT_TRANSMIT_OPERATION_KIND, SIGNATURE_ALGORITHM_ID, VersionPolicy,
    VersionRange,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_transport_internet::{
    InternetPeerExpectation, InternetPeerExpectationError, InternetPeerExpectationResolver,
    LOCAL_TCP_CAPABILITY, LOCAL_TCP_SCHEME, LocalAcceptStatus, LocalEnvelopeSink, LocalSinkError,
    LocalTransportIdentity, LocalTransportPolicy, LocalTransportProvider, LocalTransportServer,
};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-phase40-local")),
        namespace_id: Some(NamespaceId::from_opaque(oid("namespace-phase40-local"))),
    }
}

fn subject(principal_id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(principal_id)),
            kind: PrincipalKind::ServiceAccount,
        },
    }
}

fn pb_id(value: &str) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    }
}

fn wire_scope() -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb_id("tenant-phase40-local")),
        namespace_id: Some(pb_id("namespace-phase40-local")),
    }
}

fn seed_with_permissions(
    store: &MemoryLocalStore,
    subject: ScopedPrincipal,
    permissions: &[&str],
) -> (ucr_model::ServiceCredentialId, ServiceCredentialSecret) {
    let (record, secret) = issue_service_credential(&subject).expect("issue credential");
    store
        .provision_service_credential(&record)
        .expect("persist credential");
    for permission in permissions {
        store
            .grant_permission(&PermissionGrant {
                grantee: subject.clone(),
                permission: (*permission).to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant permission");
    }
    store
        .set_service_quota_policy(&ServiceQuotaPolicy {
            subject,
            max_requests: 64,
            window_ms: 60_000,
        })
        .expect("install quota");
    (record.credential_id, secret)
}

#[derive(Debug)]
struct StaticTrust {
    by_key: HashMap<(String, String), PublicKeyDescriptor>,
}

impl TrustedSigningKeyResolver for StaticTrust {
    fn resolve_active_signing_key(
        &self,
        _scope: &TenantScope,
        device_id: &DeviceId,
        _identity_id: Option<&IdentityId>,
        key_id: &KeyId,
    ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError> {
        self.by_key
            .get(&(
                device_id.as_opaque().as_str().to_owned(),
                key_id.as_opaque().as_str().to_owned(),
            ))
            .cloned()
            .ok_or(TrustedKeyResolutionError::NotTrusted)
    }
}

#[derive(Debug, Default)]
struct MemoryReplay(Mutex<HashSet<([u8; 32], [u8; 32])>>);

impl ReplayProtector for MemoryReplay {
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError> {
        let mut seen = self.0.lock().map_err(|_| ReplayError::Internal)?;
        if !seen.insert((peer_verifying_key.0, *binding.as_bytes())) {
            return Err(ReplayError::Replayed);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StaticExpectation {
    by_endpoint: HashMap<String, InternetPeerExpectation>,
}

impl InternetPeerExpectationResolver for StaticExpectation {
    fn expected_peer(
        &self,
        _scope: &TenantScope,
        endpoint_id: &EndpointId,
    ) -> Result<InternetPeerExpectation, InternetPeerExpectationError> {
        self.by_endpoint
            .get(endpoint_id.as_opaque().as_str())
            .cloned()
            .ok_or(InternetPeerExpectationError::NotFound)
    }
}

#[derive(Debug, Default)]
struct CaptureSink {
    accepted: Mutex<Vec<Vec<u8>>>,
    calls: AtomicU64,
}

impl LocalEnvelopeSink for CaptureSink {
    fn accept_once(
        &self,
        _scope: &TenantScope,
        _source_endpoint_id: &EndpointId,
        _attempt_id: &OpaqueId,
        encrypted_envelope: &[u8],
    ) -> Result<LocalAcceptStatus, LocalSinkError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.accepted
            .lock()
            .map_err(|_| LocalSinkError::Internal)?
            .push(encrypted_envelope.to_vec());
        Ok(LocalAcceptStatus::Accepted)
    }
}

struct PairFixture {
    client_identity: Arc<LocalTransportIdentity>,
    server_identity: Arc<LocalTransportIdentity>,
    server_endpoint: EndpointId,
}

fn descriptor(key_id: &str, device_id: &str, signing: &SigningKeyMaterial) -> PublicKeyDescriptor {
    PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid(key_id)),
        device_id: DeviceId::from_opaque(oid(device_id)),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: signing.verifying_key().0.to_vec(),
    }
}

fn hello() -> PeerHello {
    PeerHello {
        supported_versions: vec![
            VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                .expect("version"),
        ],
        supported_crypto_suites: vec![CryptoSuite::UcrV1],
        nonce: HandshakeNonce::new([1; 32]),
        capabilities: vec![CapabilityDescriptor {
            id: LOCAL_TCP_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }],
        extensions: Vec::new(),
    }
}

fn negotiation_policy() -> NegotiationPolicy {
    NegotiationPolicy {
        version: VersionPolicy {
            minimum: ProtocolVersion::new(1, 0),
        },
        crypto: CryptoPolicy {
            preferred_suites: vec![CryptoSuite::UcrV1],
        },
        required_capabilities: vec![CapabilityRequirement {
            id: LOCAL_TCP_CAPABILITY.to_owned(),
            minimum: CapabilityMaturity::Prepared,
            allow_deprecated: false,
        }],
    }
}

fn fixture() -> PairFixture {
    let client_signing = Arc::new(SigningKeyMaterial::generate().expect("client signing"));
    let server_signing = Arc::new(SigningKeyMaterial::generate().expect("server signing"));
    let client_descriptor = descriptor(
        "phase40-local-key-client",
        "phase40-local-device-client",
        client_signing.as_ref(),
    );
    let server_descriptor = descriptor(
        "phase40-local-key-server",
        "phase40-local-device-server",
        server_signing.as_ref(),
    );
    let client_endpoint = EndpointId::from_opaque(oid("phase40-local-endpoint-client"));
    let server_endpoint = EndpointId::from_opaque(oid("phase40-local-endpoint-server"));
    let trust = Arc::new(StaticTrust {
        by_key: HashMap::from([
            (
                (
                    "phase40-local-device-client".to_owned(),
                    "phase40-local-key-client".to_owned(),
                ),
                client_descriptor.clone(),
            ),
            (
                (
                    "phase40-local-device-server".to_owned(),
                    "phase40-local-key-server".to_owned(),
                ),
                server_descriptor.clone(),
            ),
        ]),
    });
    let expectations = Arc::new(StaticExpectation {
        by_endpoint: HashMap::from([
            (
                "phase40-local-endpoint-client".to_owned(),
                InternetPeerExpectation {
                    device_id: client_descriptor.device_id.clone(),
                    signing_key_id: Some(client_descriptor.key_id.clone()),
                },
            ),
            (
                "phase40-local-endpoint-server".to_owned(),
                InternetPeerExpectation {
                    device_id: server_descriptor.device_id.clone(),
                    signing_key_id: Some(server_descriptor.key_id.clone()),
                },
            ),
        ]),
    });
    let client_identity = Arc::new(LocalTransportIdentity {
        scope: scope(),
        endpoint_id: client_endpoint,
        hello_template: hello(),
        negotiation_policy: negotiation_policy(),
        signing_descriptor: client_descriptor,
        signing_key: client_signing,
        trusted_keys: trust.clone(),
        replay: Arc::new(MemoryReplay::default()),
        peer_expectations: expectations.clone(),
    });
    let server_identity = Arc::new(LocalTransportIdentity {
        scope: scope(),
        endpoint_id: server_endpoint.clone(),
        hello_template: hello(),
        negotiation_policy: negotiation_policy(),
        signing_descriptor: server_descriptor,
        signing_key: server_signing,
        trusted_keys: trust,
        replay: Arc::new(MemoryReplay::default()),
        peer_expectations: expectations,
    });
    PairFixture {
        client_identity,
        server_identity,
        server_endpoint,
    }
}

fn fast_policy() -> LocalTransportPolicy {
    LocalTransportPolicy {
        connect_timeout: Duration::from_secs(1),
        io_timeout: Duration::from_secs(2),
        max_attempts: 2,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        max_envelope_len: 16 * 1024 * 1024,
        chunk_plaintext_len: 64 * 1024,
    }
}

async fn grpc_client_and_server(
    store: Arc<MemoryLocalStore>,
    provider: Arc<LocalTransportProvider>,
) -> (
    pb::local_transport_service_client::LocalTransportServiceClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC listener");
    let address = listener.local_addr().expect("gRPC listener address");
    let incoming = TcpListenerStream::new(listener);
    let service = GrpcLocalTransportService::new(
        Arc::new(SystemServiceQuotaClock),
        Arc::clone(&store),
        store,
        provider,
    );
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(local_transport_service_server(service))
            .serve_with_incoming(incoming)
            .await
    });
    let client = pb::local_transport_service_client::LocalTransportServiceClient::connect(format!(
        "http://{address}"
    ))
    .await
    .expect("connect gRPC client");
    (client, server)
}

fn request_body(address: String) -> pb::LocalTransportTransmitRequest {
    pb::LocalTransportTransmitRequest {
        scope: Some(wire_scope()),
        route: Some(pb::LocalTransportRoute {
            destination_endpoint_id: Some(pb_id("phase40-local-endpoint-server")),
            address: Some(pb::EndpointAddress {
                scheme: LOCAL_TCP_SCHEME.to_owned(),
                value: address.into_bytes(),
            }),
        }),
        encrypted_envelope: b"opaque-phase40-local-envelope".to_vec(),
    }
}

type TestLocalClient =
    pb::local_transport_service_client::LocalTransportServiceClient<tonic::transport::Channel>;

async fn assert_permission_denied(
    client: &mut TestLocalClient,
    provider: &LocalTransportProvider,
    address: String,
    credential_id: &ucr_model::ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) {
    let mut request = Request::new(request_body(address));
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .transmit(request)
        .await
        .expect("permission denial transport")
        .into_inner();
    let failure = match response.result.expect("permission denial result") {
        pb::local_transport_transmit_response::Result::Failure(failure) => failure,
        pb::local_transport_transmit_response::Result::Accepted(_) => {
            panic!("permission denial unexpectedly reached provider")
        }
    };
    assert_eq!(
        failure.error.expect("permission error").code,
        pb::ErrorCode::PermissionDenied as i32
    );
    assert_eq!(
        failure.disposition,
        pb::LocalTransportFailureDisposition::NotAccepted as i32
    );
    assert_eq!(provider.metrics().connection_attempts, 1);
}

async fn assert_public_route_rejected(
    client: &mut TestLocalClient,
    provider: &LocalTransportProvider,
    credential_id: &ucr_model::ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) {
    let mut request = Request::new(request_body("8.8.8.8:443".to_owned()));
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .transmit(request)
        .await
        .expect("public route rejection transport")
        .into_inner();
    let failure = match response.result.expect("public route result") {
        pb::local_transport_transmit_response::Result::Failure(failure) => failure,
        pb::local_transport_transmit_response::Result::Accepted(_) => {
            panic!("public Internet route accepted as local")
        }
    };
    assert_eq!(
        failure.error.expect("policy error").code,
        pb::ErrorCode::PolicyDenied as i32
    );
    assert_eq!(
        failure.disposition,
        pb::LocalTransportFailureDisposition::NotAccepted as i32
    );
    assert_eq!(provider.metrics().connection_attempts, 1);
}

fn assert_local_transport_audit(store: &MemoryLocalStore, endpoint: &EndpointId) {
    let operation = ServiceAuditOperationRef {
        operation_kind: SERVICE_AUDIT_LOCAL_TRANSPORT_TRANSMIT_OPERATION_KIND.to_owned(),
        operation_id: endpoint.as_opaque().clone(),
    };
    let audits = store
        .service_audit_records_for_operation(&scope(), &operation, 8)
        .expect("local transport audit");
    assert_eq!(audits.len(), 3);
    assert!(audits.iter().any(|record| {
        record.permission == LOCAL_TRANSPORT_USE_PERMISSION
            && record.outcome == ServiceAuditOutcome::Authorized
    }));
    assert!(audits.iter().any(|record| {
        record.permission == LOCAL_TRANSPORT_USE_PERMISSION
            && record.outcome == ServiceAuditOutcome::PermissionDenied
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn public_local_transport_reaches_real_authenticated_peer_and_fails_closed() {
    let fixture = fixture();
    let peer_endpoint = fixture.server_endpoint.clone();
    let sink = Arc::new(CaptureSink::default());
    let peer_server =
        LocalTransportServer::new(fixture.server_identity, fast_policy(), sink.clone())
            .expect("peer local server");
    let peer_listener = StdTcpListener::bind("127.0.0.1:0").expect("peer listener");
    let peer_address = peer_listener.local_addr().expect("peer address");
    let peer_thread = thread::spawn(move || peer_server.accept_once(&peer_listener));

    let provider = Arc::new(
        LocalTransportProvider::new(fixture.client_identity, fast_policy())
            .expect("local provider"),
    );
    let store = Arc::new(MemoryLocalStore::default());
    let (credential_id, secret) = seed_with_permissions(
        store.as_ref(),
        subject("service-phase40-local-authorized"),
        &[LOCAL_TRANSPORT_USE_PERMISSION],
    );
    let (denied_credential_id, denied_secret) =
        seed_with_permissions(store.as_ref(), subject("service-phase40-local-denied"), &[]);
    let (mut client, grpc_server) =
        grpc_client_and_server(Arc::clone(&store), Arc::clone(&provider)).await;

    let mut request = Request::new(request_body(peer_address.to_string()));
    attach_service_credential(&mut request, &credential_id, &secret);
    let response = client
        .transmit(request)
        .await
        .expect("local transmit transport")
        .into_inner();
    assert!(matches!(
        response.result.expect("local transmit result"),
        pb::local_transport_transmit_response::Result::Accepted(_)
    ));
    assert_eq!(peer_thread.join().expect("peer thread"), Ok(()));
    assert_eq!(sink.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        sink.accepted.lock().expect("captured payload").as_slice(),
        &[b"opaque-phase40-local-envelope".to_vec()]
    );
    assert_eq!(provider.metrics().connection_attempts, 1);

    assert_permission_denied(
        &mut client,
        provider.as_ref(),
        peer_address.to_string(),
        &denied_credential_id,
        &denied_secret,
    )
    .await;
    assert_public_route_rejected(&mut client, provider.as_ref(), &credential_id, &secret).await;
    assert_local_transport_audit(store.as_ref(), &peer_endpoint);
    grpc_server.abort();
}

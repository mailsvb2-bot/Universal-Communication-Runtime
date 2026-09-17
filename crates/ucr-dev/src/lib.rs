#![forbid(unsafe_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, transport::Server};
use ucr_api_grpc::{
    GrpcCallService, GrpcDeviceService, GrpcEventService, GrpcGroupService, GrpcIntegrationService,
    GrpcStoreForwardService, GrpcSyncService, attach_service_credential, call_service_server,
    device_service_server, event_service_server, group_service_server, integration_service_server,
    pb, store_forward_service_server, sync_service_server,
};
use ucr_core::{
    CanonicalTransportError, ClassifiedTransportFailure, DeviceLifecycleStore, IdentityStore,
    PermissionGrantStore, RouteCandidate, ServiceCredentialSecret, ServiceCredentialStore,
    ServiceQuotaStore, StorageProvider, SystemEventDeliveryClock, SystemServiceQuotaClock,
    TransportHealth, TransportProvider, issue_service_credential,
};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, DeviceDescriptor, DeviceId, DeviceLifecycleState,
    IdentityEvidence, IdentityId, IdentityOwnership, IdentityRecord, NamespaceId, OpaqueId,
    PermissionGrant, PermissionScope, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal,
    ServiceCredentialId, ServiceQuotaPolicy, TenantId, TenantScope,
};
use ucr_protocol::RUNTIME_PERMISSION_IDS;
use ucr_storage_memory::MemoryLocalStore;

pub const DEFAULT_DEV_BIND: &str = "127.0.0.1:50051";
pub const DEV_TRANSPORT_CAPABILITY: &str = "ucr.transport.test.dev";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestFault {
    None,
    Delay,
    Drop,
    Duplicate,
    Reorder,
    Disconnect,
    Corrupt,
    Throttle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxScenario {
    Message,
    Delivery,
    Group,
    Call,
    Retry,
    Failure,
    Offline,
    Reconnect,
    BridgeDegradation,
}

impl SandboxScenario {
    #[must_use]
    pub const fn all() -> [Self; 9] {
        [
            Self::Message,
            Self::Delivery,
            Self::Group,
            Self::Call,
            Self::Retry,
            Self::Failure,
            Self::Offline,
            Self::Reconnect,
            Self::BridgeDegradation,
        ]
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Delivery => "delivery",
            Self::Group => "group",
            Self::Call => "call",
            Self::Retry => "retry",
            Self::Failure => "failure",
            Self::Offline => "offline",
            Self::Reconnect => "reconnect",
            Self::BridgeDegradation => "bridge-degradation",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all()
            .into_iter()
            .find(|scenario| scenario.name() == value)
    }
}

#[derive(Debug)]
struct TestTransportState {
    fault: TestFault,
    connected: bool,
    events: Vec<String>,
}

#[derive(Debug)]
pub struct TestTransport {
    state: Mutex<TestTransportState>,
}

impl Default for TestTransport {
    fn default() -> Self {
        Self {
            state: Mutex::new(TestTransportState {
                fault: TestFault::None,
                connected: true,
                events: vec!["test_transport.ready".to_owned()],
            }),
        }
    }
}

impl TestTransport {
    /// Changes only dev fault-injection state; no canonical communication state is mutated.
    ///
    /// # Errors
    /// Returns an error if the dev transport state lock is unavailable.
    pub fn set_fault(&self, fault: TestFault) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "test transport lock poisoned")?;
        state.fault = fault;
        if fault == TestFault::Disconnect {
            state.connected = false;
        }
        state.events.push(format!("test_transport.fault.{fault:?}"));
        Ok(())
    }

    /// Restores the dev transport after an explicit disconnect simulation.
    ///
    /// # Errors
    /// Returns an error if the dev transport state lock is unavailable.
    pub fn reconnect(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "test transport lock poisoned")?;
        state.connected = true;
        state.fault = TestFault::None;
        state.events.push("test_transport.reconnected".to_owned());
        Ok(())
    }

    /// Returns redaction-safe dev transport events.
    ///
    /// # Errors
    /// Returns an error if the dev transport state lock is unavailable.
    pub fn events(&self) -> Result<Vec<String>, String> {
        self.state
            .lock()
            .map(|state| state.events.clone())
            .map_err(|_| "test transport lock poisoned".to_owned())
    }
}

impl TransportProvider for TestTransport {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: DEV_TRANSPORT_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Experimental,
            extensions: Vec::new(),
        }]
    }

    fn health(&self) -> TransportHealth {
        self.state
            .lock()
            .map_or(TransportHealth::Unavailable, |state| {
                if state.connected {
                    if matches!(state.fault, TestFault::Throttle | TestFault::Delay) {
                        TransportHealth::Degraded
                    } else {
                        TransportHealth::Healthy
                    }
                } else {
                    TransportHealth::Unavailable
                }
            })
    }

    fn transmit(
        &self,
        scope: &TenantScope,
        route: &RouteCandidate,
        encrypted_envelope: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        self.transmit_classified(scope, route, encrypted_envelope)
            .map_err(|failure| failure.error)
    }

    fn transmit_classified(
        &self,
        _scope: &TenantScope,
        _route: &RouteCandidate,
        encrypted_envelope: &[u8],
    ) -> Result<(), ClassifiedTransportFailure> {
        let (fault, connected) = self
            .state
            .lock()
            .map(|state| (state.fault, state.connected))
            .map_err(|_| {
                ClassifiedTransportFailure::acceptance_unknown(CanonicalTransportError::Internal)
            })?;
        if !connected {
            return Err(ClassifiedTransportFailure::not_accepted(
                CanonicalTransportError::Unavailable,
            ));
        }
        if encrypted_envelope.is_empty() {
            return Err(ClassifiedTransportFailure::not_accepted(
                CanonicalTransportError::Rejected,
            ));
        }
        match fault {
            TestFault::None | TestFault::Duplicate | TestFault::Reorder => Ok(()),
            TestFault::Delay => {
                std::thread::sleep(Duration::from_millis(5));
                Ok(())
            }
            TestFault::Throttle => {
                std::thread::sleep(Duration::from_millis(2));
                Ok(())
            }
            TestFault::Drop => Err(ClassifiedTransportFailure::not_accepted(
                CanonicalTransportError::Timeout,
            )),
            TestFault::Disconnect => Err(ClassifiedTransportFailure::not_accepted(
                CanonicalTransportError::Unavailable,
            )),
            TestFault::Corrupt => Err(ClassifiedTransportFailure::not_accepted(
                CanonicalTransportError::MalformedResponse,
            )),
        }
    }
}

#[derive(Debug)]
pub struct DevEnvironment {
    store: Arc<MemoryLocalStore>,
    transport: Arc<TestTransport>,
    scope: TenantScope,
    local_identity_id: IdentityId,
    local_device_id: DeviceId,
    mock_peer_identity_id: IdentityId,
    mock_peer_device_id: DeviceId,
    credential_id: ServiceCredentialId,
    credential_secret: ServiceCredentialSecret,
    debug_events: Mutex<Vec<String>>,
}

impl DevEnvironment {
    /// Creates one isolated, authenticated dev environment using canonical in-memory owners.
    ///
    /// # Errors
    /// Returns an error when canonical seed state, credentials, grants or quota cannot be created.
    pub fn new() -> Result<Self, String> {
        let store = Arc::new(MemoryLocalStore::default());
        let scope = dev_scope();
        let local_identity_id = identity_id("dev-local-identity");
        let local_device_id = device_id("dev-local-device");
        let mock_peer_identity_id = identity_id("dev-mock-peer-identity");
        let mock_peer_device_id = device_id("dev-mock-peer-device");

        seed_identity_and_device(&store, &scope, &local_identity_id, &local_device_id)?;
        seed_identity_and_device(&store, &scope, &mock_peer_identity_id, &mock_peer_device_id)?;

        let subject = ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("dev-service-principal")),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        let (record, credential_secret) = issue_service_credential(&subject)
            .map_err(|error| format!("credential issue: {error:?}"))?;
        store
            .provision_service_credential(&record)
            .map_err(|error| format!("credential persist: {error:?}"))?;
        for permission in RUNTIME_PERMISSION_IDS {
            store
                .grant_permission(&PermissionGrant {
                    grantee: subject.clone(),
                    permission: (*permission).to_owned(),
                    scope: PermissionScope::Exact(scope.clone()),
                })
                .map_err(|error| format!("permission grant {permission}: {error:?}"))?;
        }
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject,
                max_requests: 10_000,
                window_ms: 60_000,
            })
            .map_err(|error| format!("quota seed: {error:?}"))?;

        Ok(Self {
            store,
            transport: Arc::new(TestTransport::default()),
            scope,
            local_identity_id,
            local_device_id,
            mock_peer_identity_id,
            mock_peer_device_id,
            credential_id: record.credential_id,
            credential_secret,
            debug_events: Mutex::new(vec![
                "dev.identity.ready".to_owned(),
                "dev.node.ready".to_owned(),
                "dev.storage.ready".to_owned(),
                "dev.mock_peer.ready".to_owned(),
                "dev.local_api.prepared".to_owned(),
            ]),
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }

    #[must_use]
    pub const fn credential_id(&self) -> &ServiceCredentialId {
        &self.credential_id
    }

    #[must_use]
    pub const fn credential_secret(&self) -> &ServiceCredentialSecret {
        &self.credential_secret
    }

    #[must_use]
    pub fn credential_secret_hex(&self) -> String {
        hex(self.credential_secret.as_bytes())
    }

    #[must_use]
    pub const fn local_identity_id(&self) -> &IdentityId {
        &self.local_identity_id
    }

    #[must_use]
    pub const fn local_device_id(&self) -> &DeviceId {
        &self.local_device_id
    }

    #[must_use]
    pub const fn mock_peer_identity_id(&self) -> &IdentityId {
        &self.mock_peer_identity_id
    }

    #[must_use]
    pub const fn mock_peer_device_id(&self) -> &DeviceId {
        &self.mock_peer_device_id
    }

    #[must_use]
    pub fn transport(&self) -> Arc<TestTransport> {
        Arc::clone(&self.transport)
    }

    /// Records one sandbox scenario and configures only the dev `TestTransport` when applicable.
    ///
    /// # Errors
    /// Returns an error only when the local dev event/fault state cannot be updated.
    pub fn simulate(&self, scenario: SandboxScenario) -> Result<(), String> {
        let fault = match scenario {
            SandboxScenario::Message => TestFault::None,
            SandboxScenario::Delivery => TestFault::Duplicate,
            SandboxScenario::Group => TestFault::Reorder,
            SandboxScenario::Call => TestFault::Throttle,
            SandboxScenario::Retry => TestFault::Drop,
            SandboxScenario::Failure => TestFault::Corrupt,
            SandboxScenario::Offline => TestFault::Disconnect,
            SandboxScenario::Reconnect => {
                self.transport.reconnect()?;
                TestFault::None
            }
            SandboxScenario::BridgeDegradation => TestFault::Delay,
        };
        if scenario != SandboxScenario::Reconnect {
            self.transport.set_fault(fault)?;
        }
        self.debug_events
            .lock()
            .map_err(|_| "debug event lock poisoned".to_owned())?
            .push(format!("sandbox.{}", scenario.name()));
        Ok(())
    }

    /// Returns dev diagnostics without exposing canonical payload material.
    ///
    /// # Errors
    /// Returns an error when storage or dev event state is unavailable.
    pub fn diagnostics(&self) -> Result<DevDiagnostics, String> {
        let storage_health = self
            .store
            .health()
            .map_err(|error| format!("storage health: {error:?}"))?;
        let debug_event_count = self
            .debug_events
            .lock()
            .map_err(|_| "debug event lock poisoned".to_owned())?
            .len();
        Ok(DevDiagnostics {
            storage_health: format!("{storage_health:?}"),
            transport_health: format!("{:?}", self.transport.health()),
            debug_event_count,
        })
    }

    /// Returns redaction-safe dev-mode diagnostic events.
    ///
    /// # Errors
    /// Returns an error if the diagnostic event lock is unavailable.
    pub fn debug_events(&self) -> Result<Vec<String>, String> {
        self.debug_events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| "debug event lock poisoned".to_owned())
    }

    /// Starts the public loopback gRPC dev API on the requested loopback address.
    ///
    /// # Errors
    /// Non-loopback binds and listener/server failures fail closed.
    pub async fn serve(self: Arc<Self>, bind: SocketAddr) -> Result<(), String> {
        if !bind.ip().is_loopback() {
            return Err("ucr dev may bind only to loopback addresses".to_owned());
        }
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|error| format!("bind dev API: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("resolve dev API address: {error}"))?;
        println!("UCR_DEV_READY endpoint=http://{address}");
        println!(
            "UCR_DEV_TENANT={}",
            wire_text(self.scope.tenant_id.as_opaque())
        );
        println!(
            "UCR_DEV_CREDENTIAL_ID={}",
            wire_text(self.credential_id.as_opaque())
        );
        println!(
            "UCR_DEV_CREDENTIAL_SECRET_HEX={}",
            self.credential_secret_hex()
        );
        println!("UCR_DEV_MODE=development-only auth=enabled storage=memory loopback=true");

        let incoming = TcpListenerStream::new(listener);
        let clock = Arc::new(SystemServiceQuotaClock);
        let event_clock = Arc::new(SystemEventDeliveryClock);
        let store = Arc::clone(&self.store);
        let authorization = Arc::clone(&self.store);

        Server::builder()
            .add_service(integration_service_server(GrpcIntegrationService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(group_service_server(GrpcGroupService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(device_service_server(GrpcDeviceService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(sync_service_server(GrpcSyncService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(call_service_server(GrpcCallService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(event_service_server(GrpcEventService::new(
                Arc::clone(&clock),
                event_clock,
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(store_forward_service_server(GrpcStoreForwardService::new(
                clock,
                authorization,
                store,
            )))
            .serve_with_incoming(incoming)
            .await
            .map_err(|error| format!("dev API server: {error}"))
    }

    /// Exercises seeded owners, every sandbox scenario and authenticated public Integration API.
    ///
    /// # Errors
    /// Any missing seed, sandbox fault, authentication/authorization or public API failure fails.
    pub async fn self_check(self: &Arc<Self>) -> Result<(), String> {
        require_seeded(self)?;
        verify_test_transport_faults(self)?;
        for scenario in SandboxScenario::all() {
            self.simulate(scenario)?;
        }
        self.transport.reconnect()?;
        verify_public_api(self).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevDiagnostics {
    pub storage_health: String,
    pub transport_health: String,
    pub debug_event_count: usize,
}

fn seed_identity_and_device(
    store: &MemoryLocalStore,
    scope: &TenantScope,
    identity_id: &IdentityId,
    device_id: &DeviceId,
) -> Result<(), String> {
    store
        .persist_identity(&IdentityRecord {
            scope: scope.clone(),
            identity_id: identity_id.clone(),
            ownership: IdentityOwnership::UcrNative,
            evidence: IdentityEvidence::SelfAsserted,
            expires_at_unix_ms: None,
        })
        .map_err(|error| format!("identity seed: {error:?}"))?;
    store
        .register_device(
            scope,
            &DeviceDescriptor {
                device_id: device_id.clone(),
                identity_id: identity_id.clone(),
                state: DeviceLifecycleState::Active,
            },
        )
        .map_err(|error| format!("device seed: {error:?}"))
}

fn require_seeded(env: &DevEnvironment) -> Result<(), String> {
    let local_identity = env
        .store
        .identity(&env.scope, &env.local_identity_id)
        .map_err(|error| format!("local identity lookup: {error:?}"))?;
    let peer_identity = env
        .store
        .identity(&env.scope, &env.mock_peer_identity_id)
        .map_err(|error| format!("peer identity lookup: {error:?}"))?;
    let local_device = env
        .store
        .device(&env.scope, &env.local_device_id)
        .map_err(|error| format!("local device lookup: {error:?}"))?;
    let peer_device = env
        .store
        .device(&env.scope, &env.mock_peer_device_id)
        .map_err(|error| format!("peer device lookup: {error:?}"))?;
    if local_identity.is_none()
        || peer_identity.is_none()
        || local_device.is_none()
        || peer_device.is_none()
    {
        return Err("dev seed state incomplete".to_owned());
    }
    Ok(())
}

fn verify_test_transport_faults(env: &DevEnvironment) -> Result<(), String> {
    let route = RouteCandidate {
        endpoint_id: ucr_model::EndpointId::from_opaque(opaque("dev-test-endpoint")),
        transport_capability: DEV_TRANSPORT_CAPABILITY.to_owned(),
        address: ucr_model::EndpointAddress {
            scheme: "ucr.test".to_owned(),
            value: b"mock-peer".to_vec(),
        },
    };
    for fault in [
        TestFault::Delay,
        TestFault::Drop,
        TestFault::Duplicate,
        TestFault::Reorder,
        TestFault::Disconnect,
        TestFault::Corrupt,
        TestFault::Throttle,
    ] {
        env.transport.set_fault(fault)?;
        let _ = env
            .transport
            .transmit_classified(&env.scope, &route, b"encrypted-dev-envelope");
        if fault == TestFault::Disconnect {
            env.transport.reconnect()?;
        }
    }
    env.transport.set_fault(TestFault::None)
}

async fn verify_public_api(env: &Arc<DevEnvironment>) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("self-check bind: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("self-check address: {error}"))?;
    let incoming = TcpListenerStream::new(listener);
    let clock = Arc::new(SystemServiceQuotaClock);
    let store = Arc::clone(&env.store);
    let authorization = Arc::clone(&env.store);
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(integration_service_server(GrpcIntegrationService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(group_service_server(GrpcGroupService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(call_service_server(GrpcCallService::new(
                clock,
                authorization,
                store,
            )))
            .serve_with_incoming(incoming)
            .await
    });
    let endpoint = format!("http://{address}");
    verify_integration_round_trip(&endpoint, env).await?;
    verify_group_round_trip(&endpoint, env).await?;
    verify_call_round_trip(&endpoint, env).await?;
    server.abort();
    Ok(())
}

async fn verify_integration_round_trip(endpoint: &str, env: &DevEnvironment) -> Result<(), String> {
    let mut client =
        pb::integration_service_client::IntegrationServiceClient::connect(endpoint.to_owned())
            .await
            .map_err(|error| format!("self-check IntegrationService connect: {error}"))?;
    let mut create_identity = Request::new(pb::IntegrationCreateIdentityRequest {
        identity: Some(pb::IdentityRecord {
            scope: Some(pb_scope(&env.scope)),
            identity_id: Some(pb_id("dev-public-api-check")),
            ownership: pb::IdentityOwnership::UcrNative as i32,
            evidence: pb::IdentityEvidence::SelfAsserted as i32,
            expires_at_unix_ms: None,
        }),
    });
    attach_dev_credential(&mut create_identity, env);
    let identity = client
        .create_identity(create_identity)
        .await
        .map_err(|error| format!("self-check CreateIdentity: {error}"))?
        .into_inner();
    require_result(
        matches!(
            identity.result,
            Some(pb::integration_create_identity_response::Result::Identity(
                _
            ))
        ),
        "CreateIdentity",
    )?;

    let mut create_conversation = Request::new(pb::IntegrationCreateConversationRequest {
        conversation: Some(pb_conversation(
            &env.scope,
            "dev-conversation",
            pb::ConversationKind::Direct,
        )),
    });
    attach_dev_credential(&mut create_conversation, env);
    let conversation = client
        .create_conversation(create_conversation)
        .await
        .map_err(|error| format!("self-check CreateConversation: {error}"))?
        .into_inner();
    require_result(
        matches!(
            conversation.result,
            Some(pb::integration_create_conversation_response::Result::Conversation(_))
        ),
        "CreateConversation",
    )?;

    let mut send = Request::new(pb::IntegrationSendMessageRequest {
        message: Some(pb_message(&env.scope)),
    });
    attach_dev_credential(&mut send, env);
    let response = client
        .send_message(send)
        .await
        .map_err(|error| format!("self-check SendMessage: {error}"))?
        .into_inner();
    require_result(
        matches!(
            response.result,
            Some(pb::integration_send_message_response::Result::Acknowledgement(_))
        ),
        "SendMessage",
    )
}

async fn verify_group_round_trip(endpoint: &str, env: &DevEnvironment) -> Result<(), String> {
    let mut client = pb::group_service_client::GroupServiceClient::connect(endpoint.to_owned())
        .await
        .map_err(|error| format!("self-check GroupService connect: {error}"))?;
    let mut request = Request::new(pb::GroupCreateRequest {
        conversation: Some(pb_conversation(
            &env.scope,
            "dev-group-conversation",
            pb::ConversationKind::PrivateGroup,
        )),
        group: Some(pb_group(&env.scope)),
    });
    attach_dev_credential(&mut request, env);
    let response = client
        .create_group(request)
        .await
        .map_err(|error| format!("self-check CreateGroup: {error}"))?
        .into_inner();
    require_result(
        matches!(
            response.result,
            Some(pb::group_create_response::Result::Group(_))
        ),
        "CreateGroup",
    )
}

async fn verify_call_round_trip(endpoint: &str, env: &DevEnvironment) -> Result<(), String> {
    let mut client = pb::call_service_client::CallServiceClient::connect(endpoint.to_owned())
        .await
        .map_err(|error| format!("self-check CallService connect: {error}"))?;
    let mut request = Request::new(pb::CallStartRequest {
        session: Some(pb_call(&env.scope)),
    });
    attach_dev_credential(&mut request, env);
    let response = client
        .start_call(request)
        .await
        .map_err(|error| format!("self-check StartCall: {error}"))?
        .into_inner();
    require_result(
        matches!(
            response.result,
            Some(pb::call_start_response::Result::Call(_))
        ),
        "StartCall",
    )
}

fn attach_dev_credential<T>(request: &mut Request<T>, env: &DevEnvironment) {
    attach_service_credential(request, &env.credential_id, &env.credential_secret);
}

fn require_result(condition: bool, operation: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!(
            "authenticated public {operation} self-check failed"
        ))
    }
}

fn pb_conversation(
    scope: &TenantScope,
    conversation_id: &str,
    kind: pb::ConversationKind,
) -> pb::ConversationRecord {
    pb::ConversationRecord {
        scope: Some(pb_scope(scope)),
        conversation: Some(pb::ConversationRef {
            conversation_id: Some(pb_id(conversation_id)),
            kind: kind as i32,
        }),
        parent_conversation_id: None,
    }
}

fn pb_message(scope: &TenantScope) -> pb::MessageEnvelope {
    pb::MessageEnvelope {
        message_id: Some(pb_id("dev-message")),
        scope: Some(pb_scope(scope)),
        conversation: Some(pb::ConversationRef {
            conversation_id: Some(pb_id("dev-conversation")),
            kind: pb::ConversationKind::Direct as i32,
        }),
        author: Some(pb::ActorRef {
            actor_id: Some(pb_id("dev-local-person")),
            kind: pb::ActorKind::Person as i32,
            on_behalf_of: None,
        }),
        author_device: Some(pb::DeviceRef {
            device_id: Some(pb_id("dev-local-device")),
            identity_id: Some(pb_id("dev-local-identity")),
        }),
        logical_order: 1,
        content: b"hello from ucr dev".to_vec(),
        delivery_policy: pb::DeliveryPolicy::Durable as i32,
        correlation: Some(pb::Correlation {
            correlation_id: Some(pb_id("dev-message-correlation")),
            causation_id: None,
            idempotency_key: Some("dev-message-key".to_owned()),
        }),
        extensions: Vec::new(),
        origin: Some(pb::OriginRef {
            principal_id: Some(pb_id("dev-service-principal")),
            endpoint_id: None,
            integration_id: None,
        }),
        created_at_unix_ms: 1_700_000_000_000,
        attachment_ids: Vec::new(),
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_state: pb::DeliveryState::Created as i32,
        external_mappings: Vec::new(),
        signature: None,
        reply_to: None,
    }
}

fn pb_group(scope: &TenantScope) -> pb::GroupRecord {
    pb::GroupRecord {
        scope: Some(pb_scope(scope)),
        group_id: Some(pb_id("dev-group")),
        conversation: Some(pb::ConversationRef {
            conversation_id: Some(pb_id("dev-group-conversation")),
            kind: pb::ConversationKind::PrivateGroup as i32,
        }),
        ownership: Some(pb::GroupOwnership {
            kind: pb::GroupOwnershipKind::SharedAdmin as i32,
            owner: None,
            expires_at_unix_ms: None,
        }),
        history_policy: Some(pb::GroupHistoryPolicy {
            kind: pb::GroupHistoryPolicyKind::FullHistory as i32,
            last_n_messages: None,
            from_timestamp_unix_ms: None,
            custom_policy: None,
        }),
        delivery_policy: pb::DeliveryPolicy::Durable as i32,
        crypto_state: Some(pb::GroupCryptoState {
            capability_id: None,
            epoch: 0,
            state_ref: None,
        }),
        public_policy: None,
        media_state: pb::GroupMediaState::Idle as i32,
        bridge_mappings: Vec::new(),
        replication_generation: 0,
        revision: 0,
    }
}

fn pb_call(scope: &TenantScope) -> pb::CallSession {
    let service = pb::PrincipalRef {
        principal_id: Some(pb_id("dev-service-principal")),
        kind: pb::PrincipalKind::ServiceAccount as i32,
    };
    pb::CallSession {
        scope: Some(pb_scope(scope)),
        call_id: Some(pb_id("dev-call")),
        conversation: Some(pb::ConversationRef {
            conversation_id: Some(pb_id("dev-conversation")),
            kind: pb::ConversationKind::Direct as i32,
        }),
        initiated_by: Some(service.clone()),
        participants: vec![
            pb::CallParticipant {
                principal: Some(service),
                state: pb::CallParticipantState::Accepted as i32,
                joined_revision: 0,
                left_revision: None,
            },
            pb::CallParticipant {
                principal: Some(pb::PrincipalRef {
                    principal_id: Some(pb_id("dev-mock-peer-person")),
                    kind: pb::PrincipalKind::Person as i32,
                }),
                state: pb::CallParticipantState::Invited as i32,
                joined_revision: 0,
                left_revision: None,
            },
        ],
        signalling_state: pb::CallSignallingState::Inviting as i32,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
        reconnecting_participant: None,
    }
}

fn pb_scope(scope: &TenantScope) -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb::OpaqueId {
            value: scope.tenant_id.as_opaque().as_wire_bytes().to_vec(),
        }),
        namespace_id: scope
            .namespace_id
            .as_ref()
            .map(|namespace_id| pb::OpaqueId {
                value: namespace_id.as_opaque().as_wire_bytes().to_vec(),
            }),
    }
}

fn pb_id(value: &str) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    }
}

fn dev_scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(opaque("dev-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(opaque("dev-namespace"))),
    }
}

fn identity_id(value: &str) -> IdentityId {
    IdentityId::from_opaque(opaque(value))
}

fn device_id(value: &str) -> DeviceId {
    DeviceId::from_opaque(opaque(value))
}

fn opaque(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static dev IDs are canonical")
}

fn wire_text(value: &OpaqueId) -> String {
    String::from_utf8(value.as_wire_bytes().to_vec()).expect("canonical OpaqueId is UTF-8")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_protocol::IDENTITY_CREATE_PERMISSION;

    #[tokio::test]
    async fn dev_mode_provides_auth_on_public_api_and_all_required_sandbox_scenarios() {
        let env = Arc::new(DevEnvironment::new().expect("create dev environment"));
        env.self_check().await.expect("dev self-check");
        let diagnostics = env.diagnostics().expect("diagnostics");
        assert_eq!(diagnostics.storage_health, "Healthy");
        assert_eq!(diagnostics.transport_health, "Healthy");
        for scenario in SandboxScenario::all() {
            assert!(
                env.debug_events()
                    .expect("debug events")
                    .contains(&format!("sandbox.{}", scenario.name()))
            );
        }
        let grants = env
            .store
            .permission_grants_for(&ScopedPrincipal {
                scope: env.scope.clone(),
                principal: PrincipalRef {
                    principal_id: PrincipalId::from_opaque(opaque("dev-service-principal")),
                    kind: PrincipalKind::ServiceAccount,
                },
            })
            .expect("grants");
        assert!(
            grants
                .iter()
                .any(|grant| grant.permission == IDENTITY_CREATE_PERMISSION)
        );
    }

    #[test]
    fn sandbox_names_cover_the_canon_dev_mode_matrix() {
        let names = SandboxScenario::all().map(SandboxScenario::name);
        assert_eq!(
            names,
            [
                "message",
                "delivery",
                "group",
                "call",
                "retry",
                "failure",
                "offline",
                "reconnect",
                "bridge-degradation",
            ]
        );
    }
}

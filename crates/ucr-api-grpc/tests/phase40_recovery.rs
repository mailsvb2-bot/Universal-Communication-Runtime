use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, transport::Server};
use ucr_api_grpc::{GrpcRecoveryService, attach_service_credential, pb, recovery_service_server};
use ucr_core::{
    DeviceLifecycleStore, DeviceReverificationVerificationError, DeviceReverificationVerifier,
    PermissionGrantStore, RecoveryAuthorityVerificationError, RecoveryAuthorityVerifier,
    ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaStore, SystemServiceQuotaClock,
    issue_service_credential,
};
use ucr_model::*;
use ucr_protocol::{
    RECOVERY_ACTIVATE_PERMISSION, RECOVERY_PLAN_INSTALL_PERMISSION, RECOVERY_PLAN_READ_PERMISSION,
    RECOVERY_STAGE_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;
fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("phase40-recovery-tenant")),
        namespace_id: None,
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

fn pb_id(value: &str) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    }
}
fn wire_scope() -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb_id("phase40-recovery-tenant")),
        namespace_id: None,
    }
}

fn wire_plan() -> pb::RecoveryPlan {
    pb::RecoveryPlan {
        plan_id: Some(pb_id("phase40-recovery-plan")),
        scope: Some(wire_scope()),
        identity_id: Some(pb_id("phase40-recovery-identity")),
        authorities: vec![pb::RecoveryAuthority {
            method: pb::RecoveryMethod::RecoveryKey as i32,
            device_id: None,
            principal_id: None,
        }],
        historical_message_access: pb::HistoricalMessageAccess::None as i32,
        recovered_device_state: pb::DeviceLifecycleState::ReverificationRequired as i32,
        trust_model: pb::RecoveryTrustModel::UserControlled as i32,
    }
}
#[derive(Debug, Default)]
struct ToggleRecoveryVerifier {
    allowed: AtomicBool,
    calls: AtomicUsize,
}

impl ToggleRecoveryVerifier {
    fn allow(&self) {
        self.allowed.store(true, Ordering::Release);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl RecoveryAuthorityVerifier for ToggleRecoveryVerifier {
    fn verify_authority(
        &self,
        _plan: &RecoveryPlan,
        _request: &RecoveryRequest,
    ) -> Result<(), RecoveryAuthorityVerificationError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.allowed
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(RecoveryAuthorityVerificationError::Denied)
    }
}
#[derive(Debug, Default)]
struct ToggleReverificationVerifier {
    allowed: AtomicBool,
    calls: AtomicUsize,
}

impl ToggleReverificationVerifier {
    fn allow(&self) {
        self.allowed.store(true, Ordering::Release);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl DeviceReverificationVerifier for ToggleReverificationVerifier {
    fn verify_reverification(
        &self,
        _device: &DeviceDescriptor,
    ) -> Result<(), DeviceReverificationVerificationError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.allowed
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(DeviceReverificationVerificationError::Denied)
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
async fn recovery_client_and_server(
    store: Arc<MemoryLocalStore>,
    recovery_verifier: Arc<ToggleRecoveryVerifier>,
    reverification_verifier: Arc<ToggleReverificationVerifier>,
) -> (
    pb::recovery_service_client::RecoveryServiceClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gRPC listener");
    let address = listener.local_addr().expect("gRPC listener address");
    let incoming = TcpListenerStream::new(listener);
    let service = GrpcRecoveryService::new(
        Arc::new(SystemServiceQuotaClock),
        Arc::clone(&store),
        store,
        recovery_verifier,
        reverification_verifier,
    );
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(recovery_service_server(service))
            .serve_with_incoming(incoming)
            .await
    });
    let client =
        pb::recovery_service_client::RecoveryServiceClient::connect(format!("http://{address}"))
            .await
            .expect("connect recovery client");
    (client, server)
}

fn recovery_request() -> pb::RecoveryRequest {
    pb::RecoveryRequest {
        plan_id: Some(pb_id("phase40-recovery-plan")),
        scope: Some(wire_scope()),
        identity_id: Some(pb_id("phase40-recovery-identity")),
        authority: Some(pb::RecoveryAuthority {
            method: pb::RecoveryMethod::RecoveryKey as i32,
            device_id: None,
            principal_id: None,
        }),
        target_device_id: Some(pb_id("phase40-recovered-device")),
    }
}
type RecoveryClient = pb::recovery_service_client::RecoveryServiceClient<tonic::transport::Channel>;

async fn install_and_read_plan(
    client: &mut RecoveryClient,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) {
    let mut install = Request::new(pb::RecoveryInstallPlanRequest {
        plan: Some(wire_plan()),
    });
    attach_service_credential(&mut install, credential_id, secret);
    let installed = client
        .install_plan(install)
        .await
        .expect("install recovery plan transport")
        .into_inner();
    assert!(matches!(
        installed.result.expect("install result"),
        pb::recovery_plan_mutation_response::Result::Acknowledgement(_)
    ));

    let mut read = Request::new(pb::RecoveryGetActivePlanRequest {
        scope: Some(wire_scope()),
        identity_id: Some(pb_id("phase40-recovery-identity")),
    });
    attach_service_credential(&mut read, credential_id, secret);
    let active = client
        .get_active_plan(read)
        .await
        .expect("read recovery plan transport")
        .into_inner();
    assert!(matches!(
        active.result.expect("active plan result"),
        pb::recovery_get_active_plan_response::Result::Plan(_)
    ));
}

async fn assert_channel_permission_denial(
    client: &mut RecoveryClient,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
    verifier: &ToggleRecoveryVerifier,
) {
    let before = verifier.calls();
    let mut request = Request::new(pb::RecoveryStageDeviceRequest {
        recovery: Some(recovery_request()),
    });
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .stage_recovered_device(request)
        .await
        .expect("stage permission denial transport")
        .into_inner();
    let error = match response.result.expect("denied stage result") {
        pb::recovery_device_response::Result::Error(error) => error,
        pb::recovery_device_response::Result::Device(_) => {
            panic!("stage without channel permission unexpectedly succeeded")
        }
    };
    assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
    assert_eq!(verifier.calls(), before);
}

async fn assert_recovery_authority_denial(
    client: &mut RecoveryClient,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
    verifier: &ToggleRecoveryVerifier,
    store: &MemoryLocalStore,
) {
    let before = verifier.calls();
    let mut request = Request::new(pb::RecoveryStageDeviceRequest {
        recovery: Some(recovery_request()),
    });
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .stage_recovered_device(request)
        .await
        .expect("recovery proof denial transport")
        .into_inner();
    let error = match response.result.expect("proof-denied stage result") {
        pb::recovery_device_response::Result::Error(error) => error,
        pb::recovery_device_response::Result::Device(_) => {
            panic!("PermissionGrant replaced recovery authority")
        }
    };
    assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
    assert_eq!(verifier.calls(), before + 1);
    assert_eq!(
        store.device(
            &scope(),
            &DeviceId::from_opaque(oid("phase40-recovered-device"))
        ),
        Ok(None)
    );
}

async fn stage_verified_device(
    client: &mut RecoveryClient,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) {
    let mut request = Request::new(pb::RecoveryStageDeviceRequest {
        recovery: Some(recovery_request()),
    });
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .stage_recovered_device(request)
        .await
        .expect("stage recovered device transport")
        .into_inner();
    let device = match response.result.expect("staged result") {
        pb::recovery_device_response::Result::Device(device) => device,
        pb::recovery_device_response::Result::Error(error) => {
            panic!("verified recovery failed: {:?}", error.code)
        }
    };
    assert_eq!(
        device.state,
        pb::DeviceLifecycleState::ReverificationRequired as i32
    );
}

async fn assert_reverification_denial(
    client: &mut RecoveryClient,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
    verifier: &ToggleReverificationVerifier,
) {
    let before = verifier.calls();
    let mut request = Request::new(pb::RecoveryActivateDeviceRequest {
        scope: Some(wire_scope()),
        device_id: Some(pb_id("phase40-recovered-device")),
        identity_id: Some(pb_id("phase40-recovery-identity")),
    });
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .activate_recovered_device(request)
        .await
        .expect("reverification denial transport")
        .into_inner();
    let error = match response.result.expect("denied activation result") {
        pb::recovery_device_response::Result::Error(error) => error,
        pb::recovery_device_response::Result::Device(_) => {
            panic!("staged recovered device activated without re-verification")
        }
    };
    assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
    assert_eq!(verifier.calls(), before + 1);
}

async fn activate_verified_device(
    client: &mut RecoveryClient,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
    store: &MemoryLocalStore,
) {
    let mut request = Request::new(pb::RecoveryActivateDeviceRequest {
        scope: Some(wire_scope()),
        device_id: Some(pb_id("phase40-recovered-device")),
        identity_id: Some(pb_id("phase40-recovery-identity")),
    });
    attach_service_credential(&mut request, credential_id, secret);
    let response = client
        .activate_recovered_device(request)
        .await
        .expect("activate recovered device transport")
        .into_inner();
    let device = match response.result.expect("activated result") {
        pb::recovery_device_response::Result::Device(device) => device,
        pb::recovery_device_response::Result::Error(error) => {
            panic!("verified activation failed: {:?}", error.code)
        }
    };
    assert_eq!(device.state, pb::DeviceLifecycleState::Active as i32);
    assert_eq!(
        store.device(
            &scope(),
            &DeviceId::from_opaque(oid("phase40-recovered-device"))
        ),
        Ok(Some(DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid("phase40-recovered-device")),
            identity_id: IdentityId::from_opaque(oid("phase40-recovery-identity")),
            state: DeviceLifecycleState::Active,
        }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn public_recovery_requires_channel_permission_authority_and_reverification() {
    let store = Arc::new(MemoryLocalStore::default());
    let recovery_verifier = Arc::new(ToggleRecoveryVerifier::default());
    let reverification_verifier = Arc::new(ToggleReverificationVerifier::default());
    let (credential_id, secret) = seed_service(
        store.as_ref(),
        "phase40-recovery-service",
        &[
            RECOVERY_PLAN_INSTALL_PERMISSION,
            RECOVERY_PLAN_READ_PERMISSION,
            RECOVERY_STAGE_PERMISSION,
            RECOVERY_ACTIVATE_PERMISSION,
        ],
    );
    let (denied_id, denied_secret) = seed_service(
        store.as_ref(),
        "phase40-recovery-denied",
        &[RECOVERY_PLAN_READ_PERMISSION],
    );
    let (mut client, server) = recovery_client_and_server(
        Arc::clone(&store),
        Arc::clone(&recovery_verifier),
        Arc::clone(&reverification_verifier),
    )
    .await;

    install_and_read_plan(&mut client, &credential_id, &secret).await;
    assert_channel_permission_denial(
        &mut client,
        &denied_id,
        &denied_secret,
        recovery_verifier.as_ref(),
    )
    .await;
    assert_recovery_authority_denial(
        &mut client,
        &credential_id,
        &secret,
        recovery_verifier.as_ref(),
        store.as_ref(),
    )
    .await;
    recovery_verifier.allow();
    stage_verified_device(&mut client, &credential_id, &secret).await;
    assert_reverification_denial(
        &mut client,
        &credential_id,
        &secret,
        reverification_verifier.as_ref(),
    )
    .await;
    reverification_verifier.allow();
    activate_verified_device(&mut client, &credential_id, &secret, store.as_ref()).await;
    server.abort();
}

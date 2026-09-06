#![forbid(unsafe_code)]

use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status, metadata::MetadataMap};
use ucr_core::{
    AuthorizationEvaluator, CommandAcceptanceStore, IntegrationIngress, ServiceAuditStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_model::{
    CommandEnvelope, CommandId, CorrelationContext, NamespaceId, OpaqueId, ProtocolExtension,
    ProtocolVersion, ServiceCredentialId, TenantId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, CommandReceipt, CommandReceiptStatus,
    MAX_COMMAND_PAYLOAD_LEN, MAX_EXTENSION_PAYLOAD_LEN, MAX_IDEMPOTENCY_KEY_LEN,
    MAX_NAMESPACED_IDENTIFIER_LEN, MAX_PROTOCOL_EXTENSIONS, error_envelope_from_canonical,
};

/// Generated Rust mapping of the versioned public `ucr.v1` protobuf/gRPC contract.
#[allow(clippy::all, clippy::pedantic)]
pub mod pb {
    tonic::include_proto!("ucr.v1");
}

pub const SERVICE_CREDENTIAL_ID_METADATA_KEY: &str = "ucr-service-credential-id-bin";
pub const SERVICE_CREDENTIAL_SECRET_METADATA_KEY: &str = "ucr-service-credential-secret-bin";
pub const GRPC_DIAGNOSTIC_DOMAIN: &str = "ucr.grpc.binding";
const PROTOBUF_TAG_MAX_BYTES: usize = 1;
const PROTOBUF_U32_MAX_BYTES: usize = 5;
const PROTOBUF_LEN_PREFIX_MAX_BYTES: usize = 5;
const PROTOBUF_BOOL_MAX_BYTES: usize = 1;
const OPAQUE_ID_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + OpaqueId::MAX_LEN;
const OPAQUE_ID_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + OPAQUE_ID_WIRE_MAX_BYTES;
const TENANT_SCOPE_WIRE_MAX_BYTES: usize = 2 * OPAQUE_ID_FIELD_WIRE_MAX_BYTES;
const TENANT_SCOPE_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + TENANT_SCOPE_WIRE_MAX_BYTES;
const NAMESPACED_STRING_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_NAMESPACED_IDENTIFIER_LEN;
const COMMAND_PAYLOAD_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_COMMAND_PAYLOAD_LEN;
const IDEMPOTENCY_KEY_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_IDEMPOTENCY_KEY_LEN;
const CORRELATION_WIRE_MAX_BYTES: usize =
    2 * OPAQUE_ID_FIELD_WIRE_MAX_BYTES + IDEMPOTENCY_KEY_FIELD_WIRE_MAX_BYTES;
const CORRELATION_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + CORRELATION_WIRE_MAX_BYTES;
const PROTOCOL_VERSION_WIRE_MAX_BYTES: usize =
    2 * (PROTOBUF_TAG_MAX_BYTES + PROTOBUF_U32_MAX_BYTES);
const PROTOCOL_VERSION_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + PROTOCOL_VERSION_WIRE_MAX_BYTES;
const EXTENSION_WIRE_MAX_BYTES: usize = NAMESPACED_STRING_FIELD_WIRE_MAX_BYTES
    + PROTOBUF_TAG_MAX_BYTES
    + PROTOBUF_BOOL_MAX_BYTES
    + PROTOBUF_TAG_MAX_BYTES
    + PROTOBUF_LEN_PREFIX_MAX_BYTES
    + MAX_EXTENSION_PAYLOAD_LEN;
const EXTENSION_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + EXTENSION_WIRE_MAX_BYTES;
const COMMAND_ENVELOPE_WIRE_MAX_BYTES: usize = OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + TENANT_SCOPE_FIELD_WIRE_MAX_BYTES
    + NAMESPACED_STRING_FIELD_WIRE_MAX_BYTES
    + COMMAND_PAYLOAD_FIELD_WIRE_MAX_BYTES
    + CORRELATION_FIELD_WIRE_MAX_BYTES
    + PROTOCOL_VERSION_FIELD_WIRE_MAX_BYTES
    + MAX_PROTOCOL_EXTENSIONS * EXTENSION_FIELD_WIRE_MAX_BYTES;
/// Finite receive budget for the complete `IntegrationCommandRequest`, derived only from
/// canonical field limits plus protobuf tag/varint upper bounds.
pub const GRPC_MAX_DECODING_MESSAGE_SIZE: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + COMMAND_ENVELOPE_WIRE_MAX_BYTES;
const _: () = assert!(GRPC_MAX_DECODING_MESSAGE_SIZE > MAX_COMMAND_PAYLOAD_LEN);

/// Thin Phase-13 gRPC adapter over the canonical Integration ingress.
pub struct GrpcIntegrationService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
}

impl<C, A, S> GrpcIntegrationService<C, A, S> {
    #[must_use]
    pub const fn new(clock: Arc<C>, authorization: Arc<A>, store: Arc<S>) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }
}

impl<C, A, S> Clone for GrpcIntegrationService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcIntegrationService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcIntegrationService")
            .finish_non_exhaustive()
    }
}

/// Builds the generated gRPC server with a bounded request budget compatible with the
/// canonical command payload limit. TLS/listener policy belongs to the deployment layer.
#[must_use]
pub fn integration_service_server<C, A, S>(
    service: GrpcIntegrationService<C, A, S>,
) -> pb::integration_service_server::IntegrationServiceServer<GrpcIntegrationService<C, A, S>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + CommandAcceptanceStore
        + 'static,
{
    pb::integration_service_server::IntegrationServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
}

/// Adds the binding-specific Service Principal credential to one outgoing gRPC request.
/// The secret is binary metadata, marked sensitive, and never enters the protobuf body.
pub fn attach_service_credential<T>(
    request: &mut Request<T>,
    credential_id: &ServiceCredentialId,
    secret: &ServiceCredentialSecret,
) {
    let mut credential_id_value =
        tonic::metadata::BinaryMetadataValue::from_bytes(credential_id.as_opaque().as_wire_bytes());
    credential_id_value.set_sensitive(true);
    request
        .metadata_mut()
        .insert_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY, credential_id_value);

    let mut secret_value = tonic::metadata::BinaryMetadataValue::from_bytes(secret.as_bytes());
    secret_value.set_sensitive(true);
    request
        .metadata_mut()
        .insert_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY, secret_value);
}

#[tonic::async_trait]
impl<C, A, S> pb::integration_service_server::IntegrationService for GrpcIntegrationService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + CommandAcceptanceStore
        + 'static,
{
    async fn submit_command(
        &self,
        request: Request<pb::IntegrationCommandRequest>,
    ) -> Result<Response<pb::IntegrationCommandResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let command = body
            .command
            .ok_or_else(invalid_argument)
            .and_then(decode_command);

        let result = match (credentials, command) {
            (Ok((credential_id, secret)), Ok(command)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .submit_command(&command.scope, &credential_id, &secret, &command)
                    .map(pb_command_receipt)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationCommandResponse {
            result: Some(match result {
                Ok(receipt) => pb::integration_command_response::Result::Receipt(receipt),
                Err(error) => pb::integration_command_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn create_identity(
        &self,
        _request: Request<pb::IntegrationCreateIdentityRequest>,
    ) -> Result<Response<pb::IntegrationCreateIdentityResponse>, Status> {
        Err(Status::unimplemented(
            "CreateIdentity gRPC binding is not implemented",
        ))
    }

    async fn link_identity(
        &self,
        _request: Request<pb::IntegrationLinkIdentityRequest>,
    ) -> Result<Response<pb::IntegrationLinkIdentityResponse>, Status> {
        Err(Status::unimplemented(
            "LinkIdentity gRPC binding is not implemented",
        ))
    }

    async fn get_identity(
        &self,
        _request: Request<pb::IntegrationGetIdentityRequest>,
    ) -> Result<Response<pb::IntegrationGetIdentityResponse>, Status> {
        Err(Status::unimplemented(
            "GetIdentity gRPC binding is not implemented",
        ))
    }

    async fn resolve_identity_binding(
        &self,
        _request: Request<pb::IntegrationResolveIdentityBindingRequest>,
    ) -> Result<Response<pb::IntegrationResolveIdentityBindingResponse>, Status> {
        Err(Status::unimplemented(
            "ResolveIdentityBinding gRPC binding is not implemented",
        ))
    }

    async fn create_conversation(
        &self,
        _request: Request<pb::IntegrationCreateConversationRequest>,
    ) -> Result<Response<pb::IntegrationCreateConversationResponse>, Status> {
        Err(Status::unimplemented(
            "CreateConversation gRPC binding is not implemented",
        ))
    }

    async fn get_conversation(
        &self,
        _request: Request<pb::IntegrationGetConversationRequest>,
    ) -> Result<Response<pb::IntegrationGetConversationResponse>, Status> {
        Err(Status::unimplemented(
            "GetConversation gRPC binding is not implemented",
        ))
    }

    async fn send_message(
        &self,
        _request: Request<pb::IntegrationSendMessageRequest>,
    ) -> Result<Response<pb::IntegrationSendMessageResponse>, Status> {
        Err(Status::unimplemented(
            "SendMessage gRPC binding is not implemented",
        ))
    }

    async fn get_message(
        &self,
        _request: Request<pb::IntegrationGetMessageRequest>,
    ) -> Result<Response<pb::IntegrationGetMessageResponse>, Status> {
        Err(Status::unimplemented(
            "GetMessage gRPC binding is not implemented",
        ))
    }

    async fn create_communication_intent(
        &self,
        _request: Request<pb::IntegrationCreateCommunicationIntentRequest>,
    ) -> Result<Response<pb::IntegrationCreateCommunicationIntentResponse>, Status> {
        Err(Status::unimplemented(
            "CreateCommunicationIntent gRPC binding is not implemented",
        ))
    }

    async fn get_communication_intent(
        &self,
        _request: Request<pb::IntegrationGetCommunicationIntentRequest>,
    ) -> Result<Response<pb::IntegrationGetCommunicationIntentResponse>, Status> {
        Err(Status::unimplemented(
            "GetCommunicationIntent gRPC binding is not implemented",
        ))
    }
}

fn invalid_argument() -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidArgument)
}

fn unauthenticated() -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Unauthenticated)
}

fn decode_credentials(
    metadata: &MetadataMap,
) -> Result<(ServiceCredentialId, ServiceCredentialSecret), CanonicalError> {
    let credential_id = metadata
        .get_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY)
        .ok_or_else(unauthenticated)?
        .to_bytes()
        .map_err(|_| unauthenticated())?;
    let credential_id = OpaqueId::from_wire_bytes(credential_id.as_ref())
        .map(ServiceCredentialId::from_opaque)
        .map_err(|_| unauthenticated())?;

    let secret = metadata
        .get_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY)
        .ok_or_else(unauthenticated)?
        .to_bytes()
        .map_err(|_| unauthenticated())?;
    let secret: [u8; 32] = secret.as_ref().try_into().map_err(|_| unauthenticated())?;
    Ok((credential_id, ServiceCredentialSecret::from_bytes(secret)))
}

fn decode_command(value: pb::CommandEnvelope) -> Result<CommandEnvelope, CanonicalError> {
    Ok(CommandEnvelope {
        command_id: CommandId::from_opaque(decode_opaque(value.command_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        command_type: value.command_type,
        payload: value.payload,
        correlation: decode_correlation(value.correlation.ok_or_else(invalid_argument)?)?,
        schema_version: decode_protocol_version(value.schema_version.ok_or_else(invalid_argument)?),
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
    })
}

fn decode_scope(value: pb::TenantScope) -> Result<TenantScope, CanonicalError> {
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(decode_opaque(value.tenant_id)?),
        namespace_id: value
            .namespace_id
            .map(|value| decode_opaque(Some(value)).map(NamespaceId::from_opaque))
            .transpose()?,
    })
}

fn decode_correlation(value: pb::Correlation) -> Result<CorrelationContext, CanonicalError> {
    Ok(CorrelationContext {
        correlation_id: decode_opaque(value.correlation_id)?,
        causation_id: value
            .causation_id
            .map(|value| decode_opaque(Some(value)))
            .transpose()?,
        idempotency_key: value.idempotency_key,
    })
}

fn decode_protocol_version(value: pb::ProtocolVersion) -> ProtocolVersion {
    ProtocolVersion::new(value.major, value.minor)
}

fn decode_extension(value: pb::Extension) -> ProtocolExtension {
    ProtocolExtension {
        name: value.name,
        critical: value.critical,
        payload: value.payload,
    }
}

fn decode_opaque(value: Option<pb::OpaqueId>) -> Result<OpaqueId, CanonicalError> {
    let value = value.ok_or_else(invalid_argument)?;
    OpaqueId::from_wire_bytes(&value.value).map_err(CanonicalError::from)
}

fn pb_opaque(value: &OpaqueId) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_wire_bytes().to_vec(),
    }
}

fn pb_protocol_version(value: ProtocolVersion) -> pb::ProtocolVersion {
    pb::ProtocolVersion {
        major: value.major,
        minor: value.minor,
    }
}

fn pb_extension(value: ProtocolExtension) -> pb::Extension {
    pb::Extension {
        name: value.name,
        critical: value.critical,
        payload: value.payload,
    }
}

fn pb_command_receipt(value: CommandReceipt) -> pb::CommandReceipt {
    let status = match value.status {
        CommandReceiptStatus::Accepted => pb::CommandReceiptStatus::Accepted,
        CommandReceiptStatus::Duplicate => pb::CommandReceiptStatus::Duplicate,
    };
    pb::CommandReceipt {
        command_id: Some(pb_opaque(value.command_id.as_opaque())),
        status: status as i32,
        original_command_id: value
            .original_command_id
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
        schema_version: Some(pb_protocol_version(value.schema_version)),
        extensions: value.extensions.into_iter().map(pb_extension).collect(),
    }
}

fn pb_error(error: CanonicalError) -> pb::ErrorEnvelope {
    let envelope = error_envelope_from_canonical(error, GRPC_DIAGNOSTIC_DOMAIN);
    pb::ErrorEnvelope {
        code: envelope.code,
        retryable: envelope.retryable,
        retry_after_ms: envelope.retry_after_ms,
        diagnostic_domain: envelope.diagnostic_domain,
        extensions: envelope.extensions.into_iter().map(pb_extension).collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Code, Request, transport::Server};
    use ucr_core::{
        PermissionGrantStore, ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaStore,
        SystemServiceQuotaClock, issue_service_credential,
    };
    use ucr_model::{
        NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId, PrincipalKind,
        PrincipalRef, ScopedPrincipal, ServiceQuotaPolicy, TenantId, TenantScope,
    };
    use ucr_protocol::{
        COMMAND_ACCEPT_PERMISSION, MAX_COMMAND_PAYLOAD_LEN, MAX_EXTENSION_PAYLOAD_LEN,
        MAX_IDEMPOTENCY_KEY_LEN, MAX_NAMESPACED_IDENTIFIER_LEN, MAX_PROTOCOL_EXTENSIONS,
    };
    use ucr_storage_memory::MemoryLocalStore;

    use super::{
        GRPC_MAX_DECODING_MESSAGE_SIZE, GrpcIntegrationService, SERVICE_CREDENTIAL_ID_METADATA_KEY,
        SERVICE_CREDENTIAL_SECRET_METADATA_KEY, attach_service_credential, decode_command,
        integration_service_server, pb,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid opaque id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-grpc")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-grpc"))),
        }
    }

    fn subject() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("service-grpc")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn pb_id(value: &str) -> pb::OpaqueId {
        pb::OpaqueId {
            value: value.as_bytes().to_vec(),
        }
    }

    fn command(id: &str, key: &str, payload: &[u8]) -> pb::CommandEnvelope {
        pb::CommandEnvelope {
            command_id: Some(pb_id(id)),
            scope: Some(pb::TenantScope {
                tenant_id: Some(pb_id("tenant-grpc")),
                namespace_id: Some(pb_id("namespace-grpc")),
            }),
            command_type: "ucr.message.send".to_owned(),
            payload: payload.to_vec(),
            correlation: Some(pb::Correlation {
                correlation_id: Some(pb_id("correlation-grpc")),
                causation_id: None,
                idempotency_key: Some(key.to_owned()),
            }),
            schema_version: Some(pb::ProtocolVersion { major: 1, minor: 0 }),
            extensions: Vec::new(),
        }
    }

    fn seed(store: &MemoryLocalStore) -> (ucr_model::ServiceCredentialId, ServiceCredentialSecret) {
        let subject = subject();
        let (record, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&record)
            .expect("persist credential");
        store
            .grant_permission(&PermissionGrant {
                grantee: subject.clone(),
                permission: COMMAND_ACCEPT_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant command permission");
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject,
                max_requests: 16,
                window_ms: 60_000,
            })
            .expect("install quota");
        (record.credential_id, secret)
    }

    async fn client_and_server(
        store: Arc<MemoryLocalStore>,
    ) -> (
        pb::integration_service_client::IntegrationServiceClient<tonic::transport::Channel>,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let address = listener.local_addr().expect("listener address");
        let incoming = TcpListenerStream::new(listener);
        let service = GrpcIntegrationService::new(
            Arc::new(SystemServiceQuotaClock),
            Arc::clone(&store),
            store,
        );
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(integration_service_server(service))
                .serve_with_incoming(incoming)
                .await
        });
        let client = pb::integration_service_client::IntegrationServiceClient::connect(format!(
            "http://{address}"
        ))
        .await
        .expect("connect loopback client");
        (client, server)
    }

    #[test]
    fn credential_metadata_is_binary_exact_and_secret_is_sensitive() {
        let credential_id = ucr_model::ServiceCredentialId::from_opaque(
            OpaqueId::new("credential-é").expect("utf8 credential id"),
        );
        let secret = ServiceCredentialSecret::from_bytes([0xa5; 32]);
        let mut request = Request::new(());
        attach_service_credential(&mut request, &credential_id, &secret);

        let id = request
            .metadata()
            .get_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY)
            .expect("credential id metadata");
        assert_eq!(
            id.to_bytes().expect("decode credential id").as_ref(),
            credential_id.as_opaque().as_wire_bytes()
        );
        assert!(id.is_sensitive());

        let secret_value = request
            .metadata()
            .get_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY)
            .expect("credential secret metadata");
        assert_eq!(
            secret_value.to_bytes().expect("decode secret").as_ref(),
            secret.as_bytes()
        );
        assert!(secret_value.is_sensitive());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn permission_denial_over_grpc_cannot_bypass_core_or_create_ghost_acceptance() {
        let store = Arc::new(MemoryLocalStore::default());
        let subject = subject();
        let (record, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&record)
            .expect("persist credential");
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: subject.clone(),
                max_requests: 16,
                window_ms: 60_000,
            })
            .expect("install quota");
        let credential_id = record.credential_id;
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let wire = command(
            "command-grpc-denied",
            "grpc-denied-key",
            b"permission boundary",
        );

        let mut denied = Request::new(pb::IntegrationCommandRequest {
            command: Some(wire.clone()),
        });
        attach_service_credential(&mut denied, &credential_id, &secret);
        let response = client
            .submit_command(denied)
            .await
            .expect("permission denial is canonical application response")
            .into_inner();
        let error = match response.result.expect("denied response result") {
            pb::integration_command_response::Result::Error(error) => error,
            pb::integration_command_response::Result::Receipt(_) => panic!("permission bypassed"),
        };
        assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);

        store
            .grant_permission(&PermissionGrant {
                grantee: subject,
                permission: COMMAND_ACCEPT_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant command permission");
        let mut retry = Request::new(pb::IntegrationCommandRequest {
            command: Some(wire),
        });
        attach_service_credential(&mut retry, &credential_id, &secret);
        let response = client
            .submit_command(retry)
            .await
            .expect("authorized retry succeeds")
            .into_inner();
        let receipt = match response.result.expect("authorized retry result") {
            pb::integration_command_response::Result::Receipt(receipt) => receipt,
            pb::integration_command_response::Result::Error(error) => {
                panic!("authorized retry failed: {}", error.code)
            }
        };
        assert_eq!(receipt.status, pb::CommandReceiptStatus::Accepted as i32);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_command_round_trips_over_real_grpc_and_deduplicates() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed(&store);
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let wire_command = command("command-grpc", "grpc-key", b"hello over grpc");

        let mut first = Request::new(pb::IntegrationCommandRequest {
            command: Some(wire_command.clone()),
        });
        attach_service_credential(&mut first, &credential_id, &secret);
        let first = client
            .submit_command(first)
            .await
            .expect("gRPC submit succeeds")
            .into_inner();
        let receipt = match first.result.expect("response result") {
            pb::integration_command_response::Result::Receipt(receipt) => receipt,
            pb::integration_command_response::Result::Error(error) => {
                panic!("unexpected canonical error: {}", error.code)
            }
        };
        assert_eq!(receipt.status, pb::CommandReceiptStatus::Accepted as i32);

        let mut duplicate = Request::new(pb::IntegrationCommandRequest {
            command: Some(wire_command),
        });
        attach_service_credential(&mut duplicate, &credential_id, &secret);
        let duplicate = client
            .submit_command(duplicate)
            .await
            .expect("duplicate gRPC submit succeeds")
            .into_inner();
        let receipt = match duplicate.result.expect("duplicate response result") {
            pb::integration_command_response::Result::Receipt(receipt) => receipt,
            pb::integration_command_response::Result::Error(error) => {
                panic!("unexpected duplicate error: {}", error.code)
            }
        };
        assert_eq!(receipt.status, pb::CommandReceiptStatus::Duplicate as i32);
        server.abort();
    }

    #[test]
    fn grpc_decode_budget_contains_maximum_canonical_command_wire_size() {
        use prost::Message as _;
        use ucr_protocol::canonical_command;

        fn opaque_bytes(fill: u8) -> pb::OpaqueId {
            pb::OpaqueId {
                value: vec![fill; OpaqueId::MAX_LEN],
            }
        }

        fn max_namespaced(prefix: &str, suffix: usize) -> String {
            let stem = format!("{prefix}{suffix}-");
            assert!(stem.len() <= MAX_NAMESPACED_IDENTIFIER_LEN);
            format!(
                "{stem}{}",
                "a".repeat(MAX_NAMESPACED_IDENTIFIER_LEN - stem.len())
            )
        }

        let extensions = (0..MAX_PROTOCOL_EXTENSIONS)
            .map(|index| pb::Extension {
                name: max_namespaced("vendor.grpc_budget.", index),
                critical: true,
                payload: vec![0x42; MAX_EXTENSION_PAYLOAD_LEN],
            })
            .collect::<Vec<_>>();
        let wire = pb::CommandEnvelope {
            command_id: Some(opaque_bytes(b'c')),
            scope: Some(pb::TenantScope {
                tenant_id: Some(opaque_bytes(b't')),
                namespace_id: Some(opaque_bytes(b'n')),
            }),
            command_type: max_namespaced("vendor.command.", 0),
            payload: vec![0x5a; MAX_COMMAND_PAYLOAD_LEN],
            correlation: Some(pb::Correlation {
                correlation_id: Some(opaque_bytes(b'r')),
                causation_id: Some(opaque_bytes(b'a')),
                idempotency_key: Some("i".repeat(MAX_IDEMPOTENCY_KEY_LEN)),
            }),
            schema_version: Some(pb::ProtocolVersion {
                major: u32::MAX,
                minor: u32::MAX,
            }),
            extensions,
        };

        let canonical = decode_command(wire.clone()).expect("maximum command remains canonical");
        canonical_command(&canonical).expect("maximum command validates in protocol owner");
        let request = pb::IntegrationCommandRequest {
            command: Some(wire),
        };
        assert!(request.encoded_len() <= GRPC_MAX_DECODING_MESSAGE_SIZE);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn grpc_binding_does_not_reintroduce_tonic_four_mib_default() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed(&store);
        let (mut client, server) = client_and_server(store).await;
        let payload = vec![0x5a; 5 * 1024 * 1024];
        let mut request = Request::new(pb::IntegrationCommandRequest {
            command: Some(command(
                "command-grpc-five-mib",
                "grpc-five-mib-key",
                &payload,
            )),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .submit_command(request)
            .await
            .expect("canonical payload above Tonic default must pass")
            .into_inner();
        let receipt = match response.result.expect("large command response") {
            pb::integration_command_response::Result::Receipt(receipt) => receipt,
            pb::integration_command_response::Result::Error(error) => {
                panic!("large canonical command rejected: {}", error.code)
            }
        };
        assert_eq!(receipt.status, pb::CommandReceiptStatus::Accepted as i32);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bad_credentials_and_malformed_body_return_canonical_errors_without_ghost_acceptance() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed(&store);
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;

        let mut wrong_secret = Request::new(pb::IntegrationCommandRequest {
            command: Some(command("command-bad-secret", "bad-secret-key", b"payload")),
        });
        attach_service_credential(
            &mut wrong_secret,
            &credential_id,
            &ServiceCredentialSecret::from_bytes([0x11; 32]),
        );
        let response = client
            .submit_command(wrong_secret)
            .await
            .expect("canonical auth error is an application response")
            .into_inner();
        let error = match response.result.expect("auth error result") {
            pb::integration_command_response::Result::Error(error) => error,
            pb::integration_command_response::Result::Receipt(_) => panic!("bad secret accepted"),
        };
        assert_eq!(error.code, pb::ErrorCode::Unauthenticated as i32);

        let mut retry = Request::new(pb::IntegrationCommandRequest {
            command: Some(command("command-bad-secret", "bad-secret-key", b"payload")),
        });
        attach_service_credential(&mut retry, &credential_id, &secret);
        let retry = client
            .submit_command(retry)
            .await
            .expect("correct retry after bad secret")
            .into_inner();
        let receipt = match retry.result.expect("retry result") {
            pb::integration_command_response::Result::Receipt(receipt) => receipt,
            pb::integration_command_response::Result::Error(error) => {
                panic!("correct retry failed: {}", error.code)
            }
        };
        assert_eq!(receipt.status, pb::CommandReceiptStatus::Accepted as i32);

        let mut malformed = Request::new(pb::IntegrationCommandRequest { command: None });
        attach_service_credential(&mut malformed, &credential_id, &secret);
        let response = client
            .submit_command(malformed)
            .await
            .expect("canonical malformed error is an application response")
            .into_inner();
        let error = match response.result.expect("malformed error result") {
            pb::integration_command_response::Result::Error(error) => error,
            pb::integration_command_response::Result::Receipt(_) => {
                panic!("malformed body accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::InvalidArgument as i32);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unbound_rpc_is_explicitly_unimplemented_and_does_not_mutate_core() {
        let store = Arc::new(MemoryLocalStore::default());
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let error = client
            .create_identity(Request::new(pb::IntegrationCreateIdentityRequest {
                identity: None,
            }))
            .await
            .expect_err("unbound RPC must be explicit");
        assert_eq!(error.code(), Code::Unimplemented);
        server.abort();
    }
}

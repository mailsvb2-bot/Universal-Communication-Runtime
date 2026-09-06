#![forbid(unsafe_code)]

use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status, metadata::MetadataMap};
use ucr_core::{
    AuthorizationEvaluator, CommandAcceptanceStore, ExternalIdentityBindingLookup,
    ExternalIdentityBindingStore, IdentityStore, IntegrationIngress, ServiceAuditStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_model::{
    CommandEnvelope, CommandId, CorrelationContext, ExternalIdentityBinding, IdentityEvidence,
    IdentityId, IdentityOwnership, IdentityRecord, IntegrationId, NamespaceId, OpaqueId,
    ProtocolExtension, ProtocolVersion, ServiceCredentialId, TenantId, TenantScope,
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
        + IdentityStore
        + ExternalIdentityBindingStore
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
        + IdentityStore
        + ExternalIdentityBindingStore
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
        request: Request<pb::IntegrationCreateIdentityRequest>,
    ) -> Result<Response<pb::IntegrationCreateIdentityResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let identity = body
            .identity
            .ok_or_else(invalid_argument)
            .and_then(decode_identity_record);

        let result = match (credentials, identity) {
            (Ok((credential_id, secret)), Ok(identity)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .create_identity(&identity.scope, &credential_id, &secret, &identity)
                    .map(|identity| pb_identity_record(&identity))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationCreateIdentityResponse {
            result: Some(match result {
                Ok(identity) => {
                    pb::integration_create_identity_response::Result::Identity(identity)
                }
                Err(error) => {
                    pb::integration_create_identity_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn link_identity(
        &self,
        request: Request<pb::IntegrationLinkIdentityRequest>,
    ) -> Result<Response<pb::IntegrationLinkIdentityResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let binding = body
            .binding
            .ok_or_else(invalid_argument)
            .and_then(decode_external_identity_binding);

        let result = match (credentials, binding) {
            (Ok((credential_id, secret)), Ok(binding)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .link_identity(&binding.scope, &credential_id, &secret, &binding)
                    .map(pb_external_identity_binding)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationLinkIdentityResponse {
            result: Some(match result {
                Ok(binding) => pb::integration_link_identity_response::Result::Binding(binding),
                Err(error) => {
                    pb::integration_link_identity_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<pb::IntegrationGetIdentityRequest>,
    ) -> Result<Response<pb::IntegrationGetIdentityResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let lookup = decode_identity_lookup(body);

        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, identity_id))) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .get_identity(&scope, &credential_id, &secret, &scope, &identity_id)
                    .map(|identity| pb_identity_record(&identity))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationGetIdentityResponse {
            result: Some(match result {
                Ok(identity) => pb::integration_get_identity_response::Result::Identity(identity),
                Err(error) => pb::integration_get_identity_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn resolve_identity_binding(
        &self,
        request: Request<pb::IntegrationResolveIdentityBindingRequest>,
    ) -> Result<Response<pb::IntegrationResolveIdentityBindingResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let lookup = decode_external_identity_binding_lookup(body);

        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, integration_id, namespace, entity_id))) => {
                let lookup = ExternalIdentityBindingLookup::new(
                    &scope,
                    &integration_id,
                    &namespace,
                    &entity_id,
                );
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .resolve_identity_binding(&scope, &credential_id, &secret, lookup)
                    .map(pb_external_identity_binding)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(
            pb::IntegrationResolveIdentityBindingResponse {
                result: Some(match result {
                    Ok(binding) => {
                        pb::integration_resolve_identity_binding_response::Result::Binding(binding)
                    }
                    Err(error) => pb::integration_resolve_identity_binding_response::Result::Error(
                        pb_error(error),
                    ),
                }),
            },
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

fn decode_identity_record(value: pb::IdentityRecord) -> Result<IdentityRecord, CanonicalError> {
    Ok(IdentityRecord {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        identity_id: IdentityId::from_opaque(decode_opaque(value.identity_id)?),
        ownership: decode_identity_ownership(value.ownership)?,
        evidence: decode_identity_evidence(value.evidence)?,
        expires_at_unix_ms: value.expires_at_unix_ms,
    })
}

fn decode_identity_ownership(value: i32) -> Result<IdentityOwnership, CanonicalError> {
    match pb::IdentityOwnership::try_from(value).map_err(|_| invalid_argument())? {
        pb::IdentityOwnership::Unspecified => Err(invalid_argument()),
        pb::IdentityOwnership::UcrNative => Ok(IdentityOwnership::UcrNative),
        pb::IdentityOwnership::UserManaged => Ok(IdentityOwnership::UserManaged),
        pb::IdentityOwnership::PlatformManaged => Ok(IdentityOwnership::PlatformManaged),
        pb::IdentityOwnership::OrganizationManaged => Ok(IdentityOwnership::OrganizationManaged),
        pb::IdentityOwnership::Federated => Ok(IdentityOwnership::Federated),
        pb::IdentityOwnership::Temporary => Ok(IdentityOwnership::Temporary),
    }
}

fn decode_identity_evidence(value: i32) -> Result<IdentityEvidence, CanonicalError> {
    match pb::IdentityEvidence::try_from(value).map_err(|_| invalid_argument())? {
        pb::IdentityEvidence::Unspecified => Err(invalid_argument()),
        pb::IdentityEvidence::Unverified => Ok(IdentityEvidence::Unverified),
        pb::IdentityEvidence::SelfAsserted => Ok(IdentityEvidence::SelfAsserted),
        pb::IdentityEvidence::DeviceVerified => Ok(IdentityEvidence::DeviceVerified),
        pb::IdentityEvidence::ContactVerified => Ok(IdentityEvidence::ContactVerified),
        pb::IdentityEvidence::OrganizationVerified => Ok(IdentityEvidence::OrganizationVerified),
        pb::IdentityEvidence::ExternalProviderVerified => {
            Ok(IdentityEvidence::ExternalProviderVerified)
        }
    }
}

fn decode_external_identity_binding(
    value: pb::ExternalIdentityBinding,
) -> Result<ExternalIdentityBinding, CanonicalError> {
    Ok(ExternalIdentityBinding {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        integration_id: IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
        external_namespace: value.external_namespace,
        external_entity_id: value.external_entity_id,
        identity_id: IdentityId::from_opaque(decode_opaque(value.identity_id)?),
    })
}

fn decode_identity_lookup(
    value: pb::IntegrationGetIdentityRequest,
) -> Result<(TenantScope, IdentityId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        IdentityId::from_opaque(decode_opaque(value.identity_id)?),
    ))
}

fn decode_external_identity_binding_lookup(
    value: pb::IntegrationResolveIdentityBindingRequest,
) -> Result<(TenantScope, IntegrationId, String, Vec<u8>), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
        value.external_namespace,
        value.external_entity_id,
    ))
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

fn pb_identity_record(value: &IdentityRecord) -> pb::IdentityRecord {
    pb::IdentityRecord {
        scope: Some(pb_scope(&value.scope)),
        identity_id: Some(pb_opaque(value.identity_id.as_opaque())),
        ownership: match value.ownership {
            IdentityOwnership::UcrNative => pb::IdentityOwnership::UcrNative,
            IdentityOwnership::UserManaged => pb::IdentityOwnership::UserManaged,
            IdentityOwnership::PlatformManaged => pb::IdentityOwnership::PlatformManaged,
            IdentityOwnership::OrganizationManaged => pb::IdentityOwnership::OrganizationManaged,
            IdentityOwnership::Federated => pb::IdentityOwnership::Federated,
            IdentityOwnership::Temporary => pb::IdentityOwnership::Temporary,
        } as i32,
        evidence: match value.evidence {
            IdentityEvidence::Unverified => pb::IdentityEvidence::Unverified,
            IdentityEvidence::SelfAsserted => pb::IdentityEvidence::SelfAsserted,
            IdentityEvidence::DeviceVerified => pb::IdentityEvidence::DeviceVerified,
            IdentityEvidence::ContactVerified => pb::IdentityEvidence::ContactVerified,
            IdentityEvidence::OrganizationVerified => pb::IdentityEvidence::OrganizationVerified,
            IdentityEvidence::ExternalProviderVerified => {
                pb::IdentityEvidence::ExternalProviderVerified
            }
        } as i32,
        expires_at_unix_ms: value.expires_at_unix_ms,
    }
}

fn pb_external_identity_binding(value: ExternalIdentityBinding) -> pb::ExternalIdentityBinding {
    pb::ExternalIdentityBinding {
        scope: Some(pb_scope(&value.scope)),
        integration_id: Some(pb_opaque(value.integration_id.as_opaque())),
        external_namespace: value.external_namespace,
        external_entity_id: value.external_entity_id,
        identity_id: Some(pb_opaque(value.identity_id.as_opaque())),
    }
}

fn pb_scope(value: &TenantScope) -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb_opaque(value.tenant_id.as_opaque())),
        namespace_id: value
            .namespace_id
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
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
        IdentityStore, PermissionGrantStore, ServiceCredentialSecret, ServiceCredentialStore,
        ServiceQuotaStore, SystemServiceQuotaClock, issue_service_credential,
    };
    use ucr_model::{
        IdentityId, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalKind, PrincipalRef, ScopedPrincipal, ServiceQuotaPolicy, TenantId, TenantScope,
    };
    use ucr_protocol::{
        COMMAND_ACCEPT_PERMISSION, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
        EXTERNAL_IDENTITY_BINDING_READ_PERMISSION, IDENTITY_CREATE_PERMISSION,
        IDENTITY_READ_PERMISSION, MAX_COMMAND_PAYLOAD_LEN, MAX_EXTENSION_PAYLOAD_LEN,
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

    fn wire_scope() -> pb::TenantScope {
        pb::TenantScope {
            tenant_id: Some(pb_id("tenant-grpc")),
            namespace_id: Some(pb_id("namespace-grpc")),
        }
    }

    fn identity(
        id: &str,
        ownership: pb::IdentityOwnership,
        evidence: pb::IdentityEvidence,
    ) -> pb::IdentityRecord {
        pb::IdentityRecord {
            scope: Some(wire_scope()),
            identity_id: Some(pb_id(id)),
            ownership: ownership as i32,
            evidence: evidence as i32,
            expires_at_unix_ms: None,
        }
    }

    fn binding(identity_id: &str, external_entity_id: Vec<u8>) -> pb::ExternalIdentityBinding {
        pb::ExternalIdentityBinding {
            scope: Some(wire_scope()),
            integration_id: Some(pb_id("integration-grpc")),
            external_namespace: "vendor.example.customer".to_owned(),
            external_entity_id,
            identity_id: Some(pb_id(identity_id)),
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

    fn seed_with_permissions(
        store: &MemoryLocalStore,
        permissions: &[&str],
    ) -> (ucr_model::ServiceCredentialId, ServiceCredentialSecret) {
        let subject = subject();
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

    fn seed(store: &MemoryLocalStore) -> (ucr_model::ServiceCredentialId, ServiceCredentialSecret) {
        seed_with_permissions(store, &[COMMAND_ACCEPT_PERMISSION])
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
    async fn identity_create_retry_get_and_semantic_conflict_round_trip_over_grpc() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[IDENTITY_CREATE_PERMISSION, IDENTITY_READ_PERMISSION],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let wire = identity(
            "identity-grpc",
            pb::IdentityOwnership::UserManaged,
            pb::IdentityEvidence::SelfAsserted,
        );

        for attempt in 0..2 {
            let mut request = Request::new(pb::IntegrationCreateIdentityRequest {
                identity: Some(wire.clone()),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .create_identity(request)
                .await
                .expect("create/retry is canonical application response")
                .into_inner();
            let created = match response.result.expect("identity result") {
                pb::integration_create_identity_response::Result::Identity(identity) => identity,
                pb::integration_create_identity_response::Result::Error(error) => {
                    panic!("identity attempt {attempt} failed: {}", error.code)
                }
            };
            assert_eq!(created, wire);
        }

        let mut changed = wire.clone();
        changed.ownership = pb::IdentityOwnership::PlatformManaged as i32;
        let mut request = Request::new(pb::IntegrationCreateIdentityRequest {
            identity: Some(changed),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .create_identity(request)
            .await
            .expect("semantic conflict is application response")
            .into_inner();
        let error = match response.result.expect("conflict result") {
            pb::integration_create_identity_response::Result::Error(error) => error,
            pb::integration_create_identity_response::Result::Identity(_) => {
                panic!("identity semantic rewrite was accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::Conflict as i32);

        let mut request = Request::new(pb::IntegrationGetIdentityRequest {
            scope: Some(wire_scope()),
            identity_id: Some(pb_id("identity-grpc")),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .get_identity(request)
            .await
            .expect("authorized get succeeds")
            .into_inner();
        let fetched = match response.result.expect("get result") {
            pb::integration_get_identity_response::Result::Identity(identity) => identity,
            pb::integration_get_identity_response::Result::Error(error) => {
                panic!("get failed: {}", error.code)
            }
        };
        assert_eq!(fetched, wire);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identity_link_retry_resolve_preserves_opaque_external_entity_bytes() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                IDENTITY_CREATE_PERMISSION,
                EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
                EXTERNAL_IDENTITY_BINDING_READ_PERMISSION,
            ],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let target = identity(
            "identity-grpc-binding",
            pb::IdentityOwnership::Federated,
            pb::IdentityEvidence::ExternalProviderVerified,
        );
        let mut create = Request::new(pb::IntegrationCreateIdentityRequest {
            identity: Some(target),
        });
        attach_service_credential(&mut create, &credential_id, &secret);
        let response = client
            .create_identity(create)
            .await
            .expect("target identity creation")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_create_identity_response::Result::Identity(
                _
            ))
        ));

        let opaque_entity = vec![0x00, 0xff, 0x80, 0x58, 0x01];
        let wire = binding("identity-grpc-binding", opaque_entity.clone());
        for attempt in 0..2 {
            let mut request = Request::new(pb::IntegrationLinkIdentityRequest {
                binding: Some(wire.clone()),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .link_identity(request)
                .await
                .expect("link/retry is application response")
                .into_inner();
            let linked = match response.result.expect("link result") {
                pb::integration_link_identity_response::Result::Binding(binding) => binding,
                pb::integration_link_identity_response::Result::Error(error) => {
                    panic!("link attempt {attempt} failed: {}", error.code)
                }
            };
            assert_eq!(linked.external_entity_id, opaque_entity);
        }

        let mut resolve = Request::new(pb::IntegrationResolveIdentityBindingRequest {
            scope: Some(wire_scope()),
            integration_id: Some(pb_id("integration-grpc")),
            external_namespace: "vendor.example.customer".to_owned(),
            external_entity_id: opaque_entity.clone(),
        });
        attach_service_credential(&mut resolve, &credential_id, &secret);
        let response = client
            .resolve_identity_binding(resolve)
            .await
            .expect("resolve succeeds")
            .into_inner();
        let resolved = match response.result.expect("resolve result") {
            pb::integration_resolve_identity_binding_response::Result::Binding(binding) => binding,
            pb::integration_resolve_identity_binding_response::Result::Error(error) => {
                panic!("resolve failed: {}", error.code)
            }
        };
        assert_eq!(resolved.external_entity_id, opaque_entity);
        assert_eq!(resolved, wire);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identity_permission_denial_and_bad_secret_never_create_ghost_identity() {
        let store = Arc::new(MemoryLocalStore::default());
        let subject = subject();
        let (record, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&record)
            .expect("persist credential");
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: subject.clone(),
                max_requests: 64,
                window_ms: 60_000,
            })
            .expect("install quota");
        let credential_id = record.credential_id;
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;

        let denied_id = "identity-grpc-denied";
        let denied_wire = identity(
            denied_id,
            pb::IdentityOwnership::UcrNative,
            pb::IdentityEvidence::Unverified,
        );
        let mut denied = Request::new(pb::IntegrationCreateIdentityRequest {
            identity: Some(denied_wire.clone()),
        });
        attach_service_credential(&mut denied, &credential_id, &secret);
        let response = client
            .create_identity(denied)
            .await
            .expect("permission denial is application response")
            .into_inner();
        let error = match response.result.expect("denied result") {
            pb::integration_create_identity_response::Result::Error(error) => error,
            pb::integration_create_identity_response::Result::Identity(_) => {
                panic!("denial bypassed")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        assert!(
            store
                .identity(&scope(), &IdentityId::from_opaque(oid(denied_id)))
                .expect("read durable owner")
                .is_none()
        );

        store
            .grant_permission(&PermissionGrant {
                grantee: subject,
                permission: IDENTITY_CREATE_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant identity create");

        let bad_secret_id = "identity-grpc-bad-secret";
        let bad_secret_wire = identity(
            bad_secret_id,
            pb::IdentityOwnership::UserManaged,
            pb::IdentityEvidence::SelfAsserted,
        );
        let mut bad_secret = Request::new(pb::IntegrationCreateIdentityRequest {
            identity: Some(bad_secret_wire.clone()),
        });
        attach_service_credential(
            &mut bad_secret,
            &credential_id,
            &ServiceCredentialSecret::from_bytes([0x31; 32]),
        );
        let response = client
            .create_identity(bad_secret)
            .await
            .expect("bad secret is application response")
            .into_inner();
        let error = match response.result.expect("bad-secret result") {
            pb::integration_create_identity_response::Result::Error(error) => error,
            pb::integration_create_identity_response::Result::Identity(_) => {
                panic!("bad secret accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::Unauthenticated as i32);
        assert!(
            store
                .identity(&scope(), &IdentityId::from_opaque(oid(bad_secret_id)))
                .expect("read durable owner")
                .is_none()
        );

        for wire in [denied_wire, bad_secret_wire] {
            let mut retry = Request::new(pb::IntegrationCreateIdentityRequest {
                identity: Some(wire.clone()),
            });
            attach_service_credential(&mut retry, &credential_id, &secret);
            let response = client
                .create_identity(retry)
                .await
                .expect("correct retry succeeds")
                .into_inner();
            assert!(matches!(
                response.result,
                Some(pb::integration_create_identity_response::Result::Identity(identity)) if identity == wire
            ));
        }
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identity_reads_hide_existence_until_authorized_and_authorized_absence_is_not_found() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(&store, &[IDENTITY_CREATE_PERMISSION]);
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let existing_id = "identity-grpc-private";
        let mut create = Request::new(pb::IntegrationCreateIdentityRequest {
            identity: Some(identity(
                existing_id,
                pb::IdentityOwnership::UserManaged,
                pb::IdentityEvidence::ContactVerified,
            )),
        });
        attach_service_credential(&mut create, &credential_id, &secret);
        let response = client
            .create_identity(create)
            .await
            .expect("create existing identity")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_create_identity_response::Result::Identity(
                _
            ))
        ));

        for id in [existing_id, "identity-grpc-missing"] {
            let mut lookup = Request::new(pb::IntegrationGetIdentityRequest {
                scope: Some(wire_scope()),
                identity_id: Some(pb_id(id)),
            });
            attach_service_credential(&mut lookup, &credential_id, &secret);
            let response = client
                .get_identity(lookup)
                .await
                .expect("unauthorized lookup is application response")
                .into_inner();
            let error = match response.result.expect("lookup result") {
                pb::integration_get_identity_response::Result::Error(error) => error,
                pb::integration_get_identity_response::Result::Identity(_) => {
                    panic!("unauthorized lookup disclosed existence")
                }
            };
            assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        }

        store
            .grant_permission(&PermissionGrant {
                grantee: subject(),
                permission: IDENTITY_READ_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant identity read");
        let mut missing = Request::new(pb::IntegrationGetIdentityRequest {
            scope: Some(wire_scope()),
            identity_id: Some(pb_id("identity-grpc-missing")),
        });
        attach_service_credential(&mut missing, &credential_id, &secret);
        let response = client
            .get_identity(missing)
            .await
            .expect("authorized missing lookup is application response")
            .into_inner();
        let error = match response.result.expect("missing result") {
            pb::integration_get_identity_response::Result::Error(error) => error,
            pb::integration_get_identity_response::Result::Identity(_) => {
                panic!("missing identity fabricated")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::NotFound as i32);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_identity_enum_values_are_invalid_argument_without_ghost_and_valid_retry_succeeds()
     {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(&store, &[IDENTITY_CREATE_PERMISSION]);
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let id = "identity-grpc-malformed";

        let mut unspecified = identity(
            id,
            pb::IdentityOwnership::Unspecified,
            pb::IdentityEvidence::SelfAsserted,
        );
        let mut unknown = identity(
            id,
            pb::IdentityOwnership::UserManaged,
            pb::IdentityEvidence::SelfAsserted,
        );
        unknown.evidence = 9_999;
        for malformed in [&mut unspecified, &mut unknown] {
            let mut request = Request::new(pb::IntegrationCreateIdentityRequest {
                identity: Some((*malformed).clone()),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .create_identity(request)
                .await
                .expect("malformed enum is application response")
                .into_inner();
            let error = match response.result.expect("malformed result") {
                pb::integration_create_identity_response::Result::Error(error) => error,
                pb::integration_create_identity_response::Result::Identity(_) => {
                    panic!("malformed identity accepted")
                }
            };
            assert_eq!(error.code, pb::ErrorCode::InvalidArgument as i32);
            assert!(
                store
                    .identity(&scope(), &IdentityId::from_opaque(oid(id)))
                    .expect("read durable owner")
                    .is_none()
            );
        }

        let valid = identity(
            id,
            pb::IdentityOwnership::UserManaged,
            pb::IdentityEvidence::SelfAsserted,
        );
        let mut retry = Request::new(pb::IntegrationCreateIdentityRequest {
            identity: Some(valid.clone()),
        });
        attach_service_credential(&mut retry, &credential_id, &secret);
        let response = client
            .create_identity(retry)
            .await
            .expect("valid retry succeeds")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_create_identity_response::Result::Identity(identity)) if identity == valid
        ));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unbound_rpc_is_explicitly_unimplemented_and_does_not_mutate_core() {
        let store = Arc::new(MemoryLocalStore::default());
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let error = client
            .create_conversation(Request::new(pb::IntegrationCreateConversationRequest {
                conversation: None,
            }))
            .await
            .expect_err("unbound RPC must be explicit");
        assert_eq!(error.code(), Code::Unimplemented);
        server.abort();
    }
}

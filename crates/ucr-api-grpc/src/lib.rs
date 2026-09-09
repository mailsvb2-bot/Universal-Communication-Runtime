#![forbid(unsafe_code)]

use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status, metadata::MetadataMap};
use ucr_core::{
    AuthorizationEvaluator, CallStore, CommandAcceptanceStore, CommunicationIntentStore,
    ConversationStore, EventApiIngress, EventAppendStatus, EventCursorRejection,
    EventDeliveryClock, EventSubscriptionStore, ExternalIdentityBindingLookup,
    ExternalIdentityBindingStore, IdentityStore, IntegrationIngress, MessageStore,
    ServiceAuditStore, ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaClock,
    ServiceQuotaStore,
};
use ucr_model::{
    ActorId, ActorKind, AttachmentId, CallId, CallParticipant, CallParticipantState,
    CallParticipantUpdateKind, CallReconnectPhase, CallSession, CallSignal, CallSignalKind,
    CallSignallingState, CallTerminationReason, CommandEnvelope, CommandId, CommunicationIntent,
    ConversationId, ConversationKind, ConversationRecord, ConversationRef, CorrelationContext,
    CryptoSuite, DeliveryPolicy, DeliveryState, DeviceId, DeviceRef, EndpointId,
    EventConsumerCursor, EventDeadLetter, EventDeliveryBatch, EventDeliveryFailureKind,
    EventEnvelope, EventPollResult, EventSubscription, EventSubscriptionId, EventSubscriptionMode,
    EventSubscriptionStart, ExternalIdentityBinding, ExternalMessageMapping, IdentityEvidence,
    IdentityId, IdentityOwnership, IdentityRecord, IntegrationId, IntentConstraints, IntentId,
    KeyId, MessageCryptoMetadata, MessageEnvelope, MessageId, MessageRelation, MessageRelationKind,
    MessageSignature, NamespaceId, OpaqueId, OriginRef, PrincipalId, PrincipalKind, PrincipalRef,
    ProtocolExtension, ProtocolVersion, ServiceCredentialId, TenantId, TenantScope,
};
use ucr_protocol::{
    AcknowledgementEnvelope, CanonicalError, CanonicalErrorCode, CommandReceipt,
    CommandReceiptStatus, EXTERNAL_MESSAGE_ID_LIMIT, EXTERNAL_MESSAGE_MAPPING_LIMIT,
    MAX_COMMAND_PAYLOAD_LEN, MAX_EVENT_BATCH_ITEMS, MAX_EVENT_DELIVERY_BATCH_BYTES,
    MAX_EVENT_DELIVERY_SIZE, MAX_EVENT_INTEGRITY_METADATA_LEN, MAX_EVENT_PAYLOAD_LEN,
    MAX_EXTENSION_PAYLOAD_LEN, MAX_IDEMPOTENCY_KEY_LEN, MAX_INTENT_POLICY_VALUE_LEN,
    MAX_INTENT_TRANSPORT_CONSTRAINTS, MAX_NAMESPACED_IDENTIFIER_LEN, MAX_PROTOCOL_EXTENSIONS,
    MESSAGE_ATTACHMENT_LIMIT, MESSAGE_CRYPTO_METADATA_LIMIT, MESSAGE_RELATION_LIMIT,
    SIGNATURE_ALGORITHM_ID, SIGNATURE_LEN, acknowledgement_for, error_envelope_from_canonical,
};

/// Generated Rust mapping of the versioned public `ucr.v1` protobuf/gRPC contract.
#[allow(clippy::all, clippy::pedantic)]
pub mod pb {
    tonic::include_proto!("ucr.v1");
}

pub const SERVICE_CREDENTIAL_ID_METADATA_KEY: &str = "ucr-service-credential-id-bin";
pub const SERVICE_CREDENTIAL_SECRET_METADATA_KEY: &str = "ucr-service-credential-secret-bin";
pub const GRPC_DIAGNOSTIC_DOMAIN: &str = "ucr.grpc.binding";
const PROTOBUF_TAG_MAX_BYTES: usize = 2;
const PROTOBUF_U32_MAX_BYTES: usize = 5;
const PROTOBUF_U64_MAX_BYTES: usize = 10;
const PROTOBUF_I64_MAX_BYTES: usize = 10;
const PROTOBUF_ENUM_MAX_BYTES: usize = 1;
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
const POLICY_STRING_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_INTENT_POLICY_VALUE_LEN;
const COMMAND_PAYLOAD_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_COMMAND_PAYLOAD_LEN;
const IDEMPOTENCY_KEY_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_IDEMPOTENCY_KEY_LEN;
const ENUM_FIELD_WIRE_MAX_BYTES: usize = PROTOBUF_TAG_MAX_BYTES + PROTOBUF_ENUM_MAX_BYTES;
const U32_FIELD_WIRE_MAX_BYTES: usize = PROTOBUF_TAG_MAX_BYTES + PROTOBUF_U32_MAX_BYTES;
const U64_FIELD_WIRE_MAX_BYTES: usize = PROTOBUF_TAG_MAX_BYTES + PROTOBUF_U64_MAX_BYTES;
const I64_FIELD_WIRE_MAX_BYTES: usize = PROTOBUF_TAG_MAX_BYTES + PROTOBUF_I64_MAX_BYTES;
const CORRELATION_WIRE_MAX_BYTES: usize =
    2 * OPAQUE_ID_FIELD_WIRE_MAX_BYTES + IDEMPOTENCY_KEY_FIELD_WIRE_MAX_BYTES;
const CORRELATION_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + CORRELATION_WIRE_MAX_BYTES;
const PROTOCOL_VERSION_WIRE_MAX_BYTES: usize = 2 * U32_FIELD_WIRE_MAX_BYTES;
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
const INTEGRATION_COMMAND_REQUEST_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + COMMAND_ENVELOPE_WIRE_MAX_BYTES;

const EVENT_PAYLOAD_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_EVENT_PAYLOAD_LEN;
const EVENT_INTEGRITY_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MAX_EVENT_INTEGRITY_METADATA_LEN;

const CONVERSATION_REF_WIRE_MAX_BYTES: usize =
    OPAQUE_ID_FIELD_WIRE_MAX_BYTES + ENUM_FIELD_WIRE_MAX_BYTES;
const CONVERSATION_REF_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + CONVERSATION_REF_WIRE_MAX_BYTES;
const ACTOR_REF_WIRE_MAX_BYTES: usize =
    2 * OPAQUE_ID_FIELD_WIRE_MAX_BYTES + ENUM_FIELD_WIRE_MAX_BYTES;
const ACTOR_REF_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + ACTOR_REF_WIRE_MAX_BYTES;
const DEVICE_REF_WIRE_MAX_BYTES: usize = 2 * OPAQUE_ID_FIELD_WIRE_MAX_BYTES;
const DEVICE_REF_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + DEVICE_REF_WIRE_MAX_BYTES;
const EVENT_ENVELOPE_WIRE_MAX_BYTES: usize = OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + TENANT_SCOPE_FIELD_WIRE_MAX_BYTES
    + NAMESPACED_STRING_FIELD_WIRE_MAX_BYTES
    + EVENT_PAYLOAD_FIELD_WIRE_MAX_BYTES
    + U64_FIELD_WIRE_MAX_BYTES
    + CORRELATION_FIELD_WIRE_MAX_BYTES
    + PROTOCOL_VERSION_FIELD_WIRE_MAX_BYTES
    + EVENT_INTEGRITY_FIELD_WIRE_MAX_BYTES
    + MAX_PROTOCOL_EXTENSIONS * EXTENSION_FIELD_WIRE_MAX_BYTES
    + ACTOR_REF_FIELD_WIRE_MAX_BYTES
    + DEVICE_REF_FIELD_WIRE_MAX_BYTES
    + I64_FIELD_WIRE_MAX_BYTES;
const EVENT_PUBLISH_REQUEST_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + EVENT_ENVELOPE_WIRE_MAX_BYTES;
const EVENT_ENVELOPE_WIRE_OVERHEAD_MAX_BYTES: usize =
    EVENT_ENVELOPE_WIRE_MAX_BYTES - MAX_EVENT_DELIVERY_SIZE;
const EVENT_CURSOR_WIRE_MAX_BYTES: usize = PROTOBUF_TAG_MAX_BYTES
    + PROTOBUF_LEN_PREFIX_MAX_BYTES
    + ucr_protocol::MAX_EVENT_CONSUMER_CURSOR_LEN;
const EVENT_CURSOR_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + EVENT_CURSOR_WIRE_MAX_BYTES;
const EVENT_BATCH_EVENT_FIELD_OVERHEAD_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES;
const EVENT_DELIVERY_BATCH_WIRE_MAX_BYTES: usize = OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + TENANT_SCOPE_FIELD_WIRE_MAX_BYTES
    + MAX_EVENT_DELIVERY_BATCH_BYTES
    + MAX_EVENT_BATCH_ITEMS
        * (EVENT_ENVELOPE_WIRE_OVERHEAD_MAX_BYTES + EVENT_BATCH_EVENT_FIELD_OVERHEAD_MAX_BYTES)
    + EVENT_CURSOR_FIELD_WIRE_MAX_BYTES
    + U32_FIELD_WIRE_MAX_BYTES;
const EVENT_POLL_RESPONSE_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + EVENT_DELIVERY_BATCH_WIRE_MAX_BYTES;
const ORIGIN_REF_WIRE_MAX_BYTES: usize = 3 * OPAQUE_ID_FIELD_WIRE_MAX_BYTES;
const ORIGIN_REF_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + ORIGIN_REF_WIRE_MAX_BYTES;
const MESSAGE_RELATION_WIRE_MAX_BYTES: usize =
    ENUM_FIELD_WIRE_MAX_BYTES + OPAQUE_ID_FIELD_WIRE_MAX_BYTES;
const MESSAGE_RELATION_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MESSAGE_RELATION_WIRE_MAX_BYTES;
const EXTERNAL_MESSAGE_ID_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + EXTERNAL_MESSAGE_ID_LIMIT;
const EXTERNAL_MESSAGE_MAPPING_WIRE_MAX_BYTES: usize =
    OPAQUE_ID_FIELD_WIRE_MAX_BYTES + EXTERNAL_MESSAGE_ID_FIELD_WIRE_MAX_BYTES;
const EXTERNAL_MESSAGE_MAPPING_FIELD_WIRE_MAX_BYTES: usize = PROTOBUF_TAG_MAX_BYTES
    + PROTOBUF_LEN_PREFIX_MAX_BYTES
    + EXTERNAL_MESSAGE_MAPPING_WIRE_MAX_BYTES;
const MESSAGE_CRYPTO_METADATA_FIELD_BYTES_MAX: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MESSAGE_CRYPTO_METADATA_LIMIT;
const MESSAGE_CRYPTO_METADATA_WIRE_MAX_BYTES: usize = ENUM_FIELD_WIRE_MAX_BYTES
    + OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + MESSAGE_CRYPTO_METADATA_FIELD_BYTES_MAX;
const MESSAGE_CRYPTO_METADATA_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MESSAGE_CRYPTO_METADATA_WIRE_MAX_BYTES;
const SIGNATURE_ALGORITHM_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + SIGNATURE_ALGORITHM_ID.len();
const SIGNATURE_BYTES_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + SIGNATURE_LEN;
const MESSAGE_SIGNATURE_WIRE_MAX_BYTES: usize = OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + SIGNATURE_ALGORITHM_FIELD_WIRE_MAX_BYTES
    + U32_FIELD_WIRE_MAX_BYTES
    + SIGNATURE_BYTES_FIELD_WIRE_MAX_BYTES;
const MESSAGE_SIGNATURE_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MESSAGE_SIGNATURE_WIRE_MAX_BYTES;
const MESSAGE_ENVELOPE_WIRE_MAX_BYTES: usize = OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + TENANT_SCOPE_FIELD_WIRE_MAX_BYTES
    + CONVERSATION_REF_FIELD_WIRE_MAX_BYTES
    + ACTOR_REF_FIELD_WIRE_MAX_BYTES
    + DEVICE_REF_FIELD_WIRE_MAX_BYTES
    + U64_FIELD_WIRE_MAX_BYTES
    + COMMAND_PAYLOAD_FIELD_WIRE_MAX_BYTES
    + ENUM_FIELD_WIRE_MAX_BYTES
    + CORRELATION_FIELD_WIRE_MAX_BYTES
    + MAX_PROTOCOL_EXTENSIONS * EXTENSION_FIELD_WIRE_MAX_BYTES
    + ORIGIN_REF_FIELD_WIRE_MAX_BYTES
    + I64_FIELD_WIRE_MAX_BYTES
    + MESSAGE_ATTACHMENT_LIMIT * OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + MESSAGE_RELATION_LIMIT * MESSAGE_RELATION_FIELD_WIRE_MAX_BYTES
    + MESSAGE_CRYPTO_METADATA_FIELD_WIRE_MAX_BYTES
    + ENUM_FIELD_WIRE_MAX_BYTES
    + EXTERNAL_MESSAGE_MAPPING_LIMIT * EXTERNAL_MESSAGE_MAPPING_FIELD_WIRE_MAX_BYTES
    + MESSAGE_SIGNATURE_FIELD_WIRE_MAX_BYTES
    + OPAQUE_ID_FIELD_WIRE_MAX_BYTES;
const INTEGRATION_MESSAGE_REQUEST_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + MESSAGE_ENVELOPE_WIRE_MAX_BYTES;

const INTENT_CONSTRAINTS_WIRE_MAX_BYTES: usize = MAX_INTENT_TRANSPORT_CONSTRAINTS
    * NAMESPACED_STRING_FIELD_WIRE_MAX_BYTES
    + 2 * POLICY_STRING_FIELD_WIRE_MAX_BYTES
    + U64_FIELD_WIRE_MAX_BYTES
    + U32_FIELD_WIRE_MAX_BYTES;
const INTENT_CONSTRAINTS_FIELD_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + INTENT_CONSTRAINTS_WIRE_MAX_BYTES;
const COMMUNICATION_INTENT_WIRE_MAX_BYTES: usize = OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + TENANT_SCOPE_FIELD_WIRE_MAX_BYTES
    + OPAQUE_ID_FIELD_WIRE_MAX_BYTES
    + COMMAND_PAYLOAD_FIELD_WIRE_MAX_BYTES
    + INTENT_CONSTRAINTS_FIELD_WIRE_MAX_BYTES
    + CORRELATION_FIELD_WIRE_MAX_BYTES
    + MAX_PROTOCOL_EXTENSIONS * EXTENSION_FIELD_WIRE_MAX_BYTES;
const INTEGRATION_INTENT_REQUEST_WIRE_MAX_BYTES: usize =
    PROTOBUF_TAG_MAX_BYTES + PROTOBUF_LEN_PREFIX_MAX_BYTES + COMMUNICATION_INTENT_WIRE_MAX_BYTES;

const fn max4(left: usize, middle: usize, right: usize, fourth: usize) -> usize {
    let first_pair = if left > middle { left } else { middle };
    let second_pair = if right > fourth { right } else { fourth };
    if first_pair > second_pair {
        first_pair
    } else {
        second_pair
    }
}

/// Finite receive budget for every canonical Phase-13 Integration and Phase-14 Event request.
///
/// The payload-bearing maxima are Command, Message, Communication Intent, and Event.
/// Each upper bound is derived from canonical field/count limits plus protobuf tag/varint bounds;
/// smaller Identity, binding, Conversation, subscription, cursor, and lookup requests fit beneath
/// the same ceiling.
pub const GRPC_MAX_DECODING_MESSAGE_SIZE: usize = max4(
    INTEGRATION_COMMAND_REQUEST_WIRE_MAX_BYTES,
    INTEGRATION_MESSAGE_REQUEST_WIRE_MAX_BYTES,
    INTEGRATION_INTENT_REQUEST_WIRE_MAX_BYTES,
    EVENT_PUBLISH_REQUEST_WIRE_MAX_BYTES,
);
const _: () = assert!(GRPC_MAX_DECODING_MESSAGE_SIZE >= INTEGRATION_COMMAND_REQUEST_WIRE_MAX_BYTES);
const _: () = assert!(GRPC_MAX_DECODING_MESSAGE_SIZE >= INTEGRATION_MESSAGE_REQUEST_WIRE_MAX_BYTES);
const _: () = assert!(GRPC_MAX_DECODING_MESSAGE_SIZE >= INTEGRATION_INTENT_REQUEST_WIRE_MAX_BYTES);
const _: () = assert!(GRPC_MAX_DECODING_MESSAGE_SIZE >= EVENT_PUBLISH_REQUEST_WIRE_MAX_BYTES);

/// Finite send budget for public responses. The Phase-14 Event poll batch is the largest
/// response shape because aggregate semantic Event bytes are bounded independently of item count.
pub const GRPC_MAX_ENCODING_MESSAGE_SIZE: usize = EVENT_POLL_RESPONSE_WIRE_MAX_BYTES;
const _: () = assert!(GRPC_MAX_ENCODING_MESSAGE_SIZE >= MESSAGE_ENVELOPE_WIRE_MAX_BYTES);
const _: () = assert!(GRPC_MAX_ENCODING_MESSAGE_SIZE >= COMMUNICATION_INTENT_WIRE_MAX_BYTES);

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

/// Builds the generated gRPC server with a bounded request budget compatible with every
/// canonical Phase-13 Integration request. TLS/listener policy belongs to the deployment layer.
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
        + ConversationStore
        + MessageStore
        + CommunicationIntentStore
        + 'static,
{
    pb::integration_service_server::IntegrationServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
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
        + ConversationStore
        + MessageStore
        + CommunicationIntentStore
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
        request: Request<pb::IntegrationCreateConversationRequest>,
    ) -> Result<Response<pb::IntegrationCreateConversationResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let conversation = body
            .conversation
            .ok_or_else(invalid_argument)
            .and_then(decode_conversation_record);

        let result = match (credentials, conversation) {
            (Ok((credential_id, secret)), Ok(conversation)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .create_conversation(
                        &conversation.scope,
                        &credential_id,
                        &secret,
                        &conversation,
                    )
                    .map(|conversation| pb_conversation_record(&conversation))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationCreateConversationResponse {
            result: Some(match result {
                Ok(conversation) => {
                    pb::integration_create_conversation_response::Result::Conversation(conversation)
                }
                Err(error) => {
                    pb::integration_create_conversation_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn get_conversation(
        &self,
        request: Request<pb::IntegrationGetConversationRequest>,
    ) -> Result<Response<pb::IntegrationGetConversationResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_conversation_lookup(request.into_inner());

        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, conversation_id))) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .get_conversation(&scope, &credential_id, &secret, &scope, &conversation_id)
                    .map(|conversation| pb_conversation_record(&conversation))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationGetConversationResponse {
            result: Some(match result {
                Ok(conversation) => {
                    pb::integration_get_conversation_response::Result::Conversation(conversation)
                }
                Err(error) => {
                    pb::integration_get_conversation_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn send_message(
        &self,
        request: Request<pb::IntegrationSendMessageRequest>,
    ) -> Result<Response<pb::IntegrationSendMessageResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let message = body
            .message
            .ok_or_else(invalid_argument)
            .and_then(decode_message_envelope);

        let result = match (credentials, message) {
            (Ok((credential_id, secret)), Ok(message)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .send_message(&message.scope, &credential_id, &secret, &message)
                    .map(pb_acknowledgement)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationSendMessageResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::integration_send_message_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::integration_send_message_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_message(
        &self,
        request: Request<pb::IntegrationGetMessageRequest>,
    ) -> Result<Response<pb::IntegrationGetMessageResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_message_lookup(request.into_inner());

        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, message_id))) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .get_message(&scope, &credential_id, &secret, &scope, &message_id)
                    .map(|message| pb_message_envelope(&message))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::IntegrationGetMessageResponse {
            result: Some(match result {
                Ok(message) => pb::integration_get_message_response::Result::Message(message),
                Err(error) => pb::integration_get_message_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn create_communication_intent(
        &self,
        request: Request<pb::IntegrationCreateCommunicationIntentRequest>,
    ) -> Result<Response<pb::IntegrationCreateCommunicationIntentResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let intent = body
            .intent
            .ok_or_else(invalid_argument)
            .and_then(decode_communication_intent);

        let result = match (credentials, intent) {
            (Ok((credential_id, secret)), Ok(intent)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .create_communication_intent(&intent.scope, &credential_id, &secret, &intent)
                    .map(pb_acknowledgement)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(
            pb::IntegrationCreateCommunicationIntentResponse {
                result: Some(match result {
                    Ok(acknowledgement) => {
                        pb::integration_create_communication_intent_response::Result::Acknowledgement(
                            acknowledgement,
                        )
                    }
                    Err(error) => {
                        pb::integration_create_communication_intent_response::Result::Error(
                            pb_error(error),
                        )
                    }
                }),
            },
        ))
    }

    async fn get_communication_intent(
        &self,
        request: Request<pb::IntegrationGetCommunicationIntentRequest>,
    ) -> Result<Response<pb::IntegrationGetCommunicationIntentResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_communication_intent_lookup(request.into_inner());

        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, intent_id))) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .get_communication_intent(&scope, &credential_id, &secret, &scope, &intent_id)
                    .map(|intent| pb_communication_intent(&intent))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(
            pb::IntegrationGetCommunicationIntentResponse {
                result: Some(match result {
                    Ok(intent) => {
                        pb::integration_get_communication_intent_response::Result::Intent(intent)
                    }
                    Err(error) => pb::integration_get_communication_intent_response::Result::Error(
                        pb_error(error),
                    ),
                }),
            },
        ))
    }
}

/// Thin Phase-19 gRPC binding over the existing `ServicePrincipal` request gate and `CallStore` owner.
pub struct GrpcCallService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
}

impl<C, A, S> GrpcCallService<C, A, S> {
    #[must_use]
    pub const fn new(clock: Arc<C>, authorization: Arc<A>, store: Arc<S>) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }
}

impl<C, A, S> Clone for GrpcCallService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcCallService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcCallService")
            .finish_non_exhaustive()
    }
}

/// Builds the generated Phase-19 Call signalling gRPC server. The shared request budget is larger
/// than the bounded Call contract. Listener/TLS/media transport remain outside this binding.
#[must_use]
pub fn call_service_server<C, A, S>(
    service: GrpcCallService<C, A, S>,
) -> pb::call_service_server::CallServiceServer<GrpcCallService<C, A, S>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + CallStore + 'static,
{
    pb::call_service_server::CallServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S> pb::call_service_server::CallService for GrpcCallService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + CallStore + 'static,
{
    async fn start_call(
        &self,
        request: Request<pb::CallStartRequest>,
    ) -> Result<Response<pb::CallStartResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let session = request
            .into_inner()
            .session
            .ok_or_else(invalid_argument)
            .and_then(decode_call_session);
        let result = match (credentials, session) {
            (Ok((credential_id, secret)), Ok(session)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .start_call(&session.scope, &credential_id, &secret, &session)
                    .map(|call| pb_call_session(&call))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::CallStartResponse {
            result: Some(match result {
                Ok(call) => pb::call_start_response::Result::Call(call),
                Err(error) => pb::call_start_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_call(
        &self,
        request: Request<pb::CallGetRequest>,
    ) -> Result<Response<pb::CallGetResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_call_lookup(request.into_inner());
        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, call_id))) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .get_call(&scope, &credential_id, &secret, &scope, &call_id)
                    .map(|call| pb_call_session(&call))
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::CallGetResponse {
            result: Some(match result {
                Ok(call) => pb::call_get_response::Result::Call(call),
                Err(error) => pb::call_get_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn signal_call(
        &self,
        request: Request<pb::CallSignalRequest>,
    ) -> Result<Response<pb::CallSignalResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let signal = request
            .into_inner()
            .signal
            .ok_or_else(invalid_argument)
            .and_then(decode_call_signal);
        let result = match (credentials, signal) {
            (Ok((credential_id, secret)), Ok(signal)) => {
                IntegrationIngress::new(&*self.clock, &*self.authorization, &*self.store)
                    .signal_call(&signal.scope, &credential_id, &secret, &signal)
                    .map(pb_acknowledgement)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::CallSignalResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::call_signal_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::call_signal_response::Result::Error(pb_error(error)),
            }),
        }))
    }
}

/// Thin Phase-14 gRPC adapter over the canonical Event API ingress.
pub struct GrpcEventService<Q, E, A, S> {
    quota_clock: Arc<Q>,
    event_clock: Arc<E>,
    authorization: Arc<A>,
    store: Arc<S>,
}

impl<Q, E, A, S> GrpcEventService<Q, E, A, S> {
    #[must_use]
    pub const fn new(
        quota_clock: Arc<Q>,
        event_clock: Arc<E>,
        authorization: Arc<A>,
        store: Arc<S>,
    ) -> Self {
        Self {
            quota_clock,
            event_clock,
            authorization,
            store,
        }
    }
}

impl<Q, E, A, S> Clone for GrpcEventService<Q, E, A, S> {
    fn clone(&self) -> Self {
        Self {
            quota_clock: Arc::clone(&self.quota_clock),
            event_clock: Arc::clone(&self.event_clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
        }
    }
}

impl<Q, E, A, S> fmt::Debug for GrpcEventService<Q, E, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcEventService")
            .finish_non_exhaustive()
    }
}

/// Builds the generated Phase-14 Event gRPC server with the shared canonical request budget.
/// TLS/listener/Internet policy remains a deployment/Phase-15 concern.
#[must_use]
pub fn event_service_server<Q, E, A, S>(
    service: GrpcEventService<Q, E, A, S>,
) -> pb::event_service_server::EventServiceServer<GrpcEventService<Q, E, A, S>>
where
    Q: ServiceQuotaClock + 'static,
    E: EventDeliveryClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + EventSubscriptionStore
        + 'static,
{
    pb::event_service_server::EventServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<Q, E, A, S> pb::event_service_server::EventService for GrpcEventService<Q, E, A, S>
where
    Q: ServiceQuotaClock + 'static,
    E: EventDeliveryClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + EventSubscriptionStore
        + 'static,
{
    async fn publish_event(
        &self,
        request: Request<pb::EventPublishRequest>,
    ) -> Result<Response<pb::EventPublishResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let event = request
            .into_inner()
            .event
            .ok_or_else(invalid_argument)
            .and_then(decode_event_envelope);
        let result = match (credentials, event) {
            (Ok((credential_id, secret)), Ok(event)) => EventApiIngress::new(
                &*self.quota_clock,
                &*self.event_clock,
                &*self.authorization,
                &*self.store,
            )
            .publish_event(&event.scope, &credential_id, &secret, &event)
            .map(|status| pb_event_publish_receipt(&event, status)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventPublishResponse {
            result: Some(match result {
                Ok(receipt) => pb::event_publish_response::Result::Receipt(receipt),
                Err(error) => pb::event_publish_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn create_subscription(
        &self,
        request: Request<pb::EventCreateSubscriptionRequest>,
    ) -> Result<Response<pb::EventCreateSubscriptionResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let subscription = request
            .into_inner()
            .subscription
            .ok_or_else(invalid_argument)
            .and_then(decode_event_subscription);
        let result = match (credentials, subscription) {
            (Ok((credential_id, secret)), Ok(subscription)) => EventApiIngress::new(
                &*self.quota_clock,
                &*self.event_clock,
                &*self.authorization,
                &*self.store,
            )
            .create_subscription(&subscription.scope, &credential_id, &secret, &subscription)
            .map(|value| pb_event_subscription(&value)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventCreateSubscriptionResponse {
            result: Some(match result {
                Ok(subscription) => {
                    pb::event_create_subscription_response::Result::Subscription(subscription)
                }
                Err(error) => {
                    pb::event_create_subscription_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn get_subscription(
        &self,
        request: Request<pb::EventGetSubscriptionRequest>,
    ) -> Result<Response<pb::EventGetSubscriptionResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_event_subscription_lookup(request.into_inner());
        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, subscription_id))) => EventApiIngress::new(
                &*self.quota_clock,
                &*self.event_clock,
                &*self.authorization,
                &*self.store,
            )
            .get_subscription(&scope, &credential_id, &secret, &scope, &subscription_id)
            .map(|value| pb_event_subscription(&value)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventGetSubscriptionResponse {
            result: Some(match result {
                Ok(subscription) => {
                    pb::event_get_subscription_response::Result::Subscription(subscription)
                }
                Err(error) => pb::event_get_subscription_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn poll_events(
        &self,
        request: Request<pb::EventPollRequest>,
    ) -> Result<Response<pb::EventPollResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let poll = decode_event_poll(request.into_inner());
        let result = match (credentials, poll) {
            (Ok((credential_id, secret)), Ok((scope, subscription_id, max_items))) => {
                EventApiIngress::new(
                    &*self.quota_clock,
                    &*self.event_clock,
                    &*self.authorization,
                    &*self.store,
                )
                .poll_events(
                    &scope,
                    &credential_id,
                    &secret,
                    &scope,
                    &subscription_id,
                    max_items,
                )
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventPollResponse {
            result: Some(match result {
                Ok(EventPollResult::Empty) => {
                    pb::event_poll_response::Result::Empty(pb::EventPollEmpty {})
                }
                Ok(EventPollResult::RetryAfter { retry_after_ms }) => {
                    pb::event_poll_response::Result::RetryAfter(pb::EventPollRetryAfter {
                        retry_after_ms,
                    })
                }
                Ok(EventPollResult::Batch(batch)) => {
                    pb::event_poll_response::Result::Batch(pb_event_delivery_batch(&batch))
                }
                Err(error) => pb::event_poll_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn acknowledge_events(
        &self,
        request: Request<pb::EventAcknowledgeRequest>,
    ) -> Result<Response<pb::EventAcknowledgeResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let acknowledgement = decode_event_acknowledgement(request.into_inner());
        let result = match (credentials, acknowledgement) {
            (Ok((credential_id, secret)), Ok((scope, subscription_id, cursor))) => {
                EventApiIngress::new(
                    &*self.quota_clock,
                    &*self.event_clock,
                    &*self.authorization,
                    &*self.store,
                )
                .acknowledge_events(
                    &scope,
                    &credential_id,
                    &secret,
                    &scope,
                    &subscription_id,
                    &cursor,
                )
                .map(|_| {
                    pb_acknowledgement(acknowledgement_for(subscription_id.as_opaque().clone()))
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventAcknowledgeResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::event_acknowledge_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::event_acknowledge_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn reject_events(
        &self,
        request: Request<pb::EventRejectRequest>,
    ) -> Result<Response<pb::EventRejectResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let rejection = decode_event_rejection(request.into_inner());
        let result = match (credentials, rejection) {
            (Ok((credential_id, secret)), Ok((scope, subscription_id, cursor, failure_kind))) => {
                EventApiIngress::new(
                    &*self.quota_clock,
                    &*self.event_clock,
                    &*self.authorization,
                    &*self.store,
                )
                .reject_events(
                    &scope,
                    &credential_id,
                    &secret,
                    EventCursorRejection {
                        scope: &scope,
                        subscription_id: &subscription_id,
                        cursor: &cursor,
                        failure_kind,
                    },
                )
                .map(|_| {
                    pb_acknowledgement(acknowledgement_for(subscription_id.as_opaque().clone()))
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventRejectResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::event_reject_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::event_reject_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn replay_subscription(
        &self,
        request: Request<pb::EventReplayRequest>,
    ) -> Result<Response<pb::EventReplayResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let replay = decode_event_replay(request.into_inner());
        let result = match (credentials, replay) {
            (Ok((credential_id, secret)), Ok((scope, subscription_id, replay_id))) => {
                EventApiIngress::new(
                    &*self.quota_clock,
                    &*self.event_clock,
                    &*self.authorization,
                    &*self.store,
                )
                .replay_subscription(
                    &scope,
                    &credential_id,
                    &secret,
                    &scope,
                    &subscription_id,
                    &replay_id,
                )
                .map(|_| {
                    pb_acknowledgement(acknowledgement_for(subscription_id.as_opaque().clone()))
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventReplayResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::event_replay_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::event_replay_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn list_dead_letters(
        &self,
        request: Request<pb::EventListDeadLettersRequest>,
    ) -> Result<Response<pb::EventListDeadLettersResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_event_dead_letter_lookup(request.into_inner());
        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, subscription_id, max_items))) => {
                EventApiIngress::new(
                    &*self.quota_clock,
                    &*self.event_clock,
                    &*self.authorization,
                    &*self.store,
                )
                .list_dead_letters(
                    &scope,
                    &credential_id,
                    &secret,
                    &scope,
                    &subscription_id,
                    max_items,
                )
                .map(|dead_letters| pb::EventDeadLetterList {
                    dead_letters: dead_letters.iter().map(pb_event_dead_letter).collect(),
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::EventListDeadLettersResponse {
            result: Some(match result {
                Ok(dead_letters) => {
                    pb::event_list_dead_letters_response::Result::DeadLetters(dead_letters)
                }
                Err(error) => pb::event_list_dead_letters_response::Result::Error(pb_error(error)),
            }),
        }))
    }
}

fn decode_event_envelope(value: pb::EventEnvelope) -> Result<EventEnvelope, CanonicalError> {
    Ok(EventEnvelope {
        event_id: ucr_model::EventId::from_opaque(decode_opaque(value.event_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        event_type: value.event_type,
        payload: value.payload,
        actor: decode_actor_ref(value.actor.ok_or_else(invalid_argument)?)?,
        source_device: decode_device_ref(value.source_device.ok_or_else(invalid_argument)?)?,
        wall_time_unix_ms: value.wall_time_unix_ms,
        logical_order: value.logical_order,
        correlation: decode_correlation(value.correlation.ok_or_else(invalid_argument)?)?,
        schema_version: decode_protocol_version(value.schema_version.ok_or_else(invalid_argument)?),
        integrity_metadata: value.integrity_metadata,
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
    })
}

fn decode_event_subscription(
    value: pb::EventSubscription,
) -> Result<EventSubscription, CanonicalError> {
    Ok(EventSubscription {
        subscription_id: EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        mode: decode_event_subscription_mode(value.mode)?,
        webhook_uri: value.webhook_uri,
        event_types: value.event_types,
        max_in_flight: value.max_in_flight,
        max_attempts: value.max_attempts,
        start: decode_event_subscription_start(value.start)?,
    })
}

fn decode_event_subscription_mode(value: i32) -> Result<EventSubscriptionMode, CanonicalError> {
    match pb::EventSubscriptionMode::try_from(value).map_err(|_| invalid_argument())? {
        pb::EventSubscriptionMode::Unspecified => Err(invalid_argument()),
        pb::EventSubscriptionMode::DurableStream => Ok(EventSubscriptionMode::DurableStream),
        pb::EventSubscriptionMode::Webhook => Ok(EventSubscriptionMode::Webhook),
    }
}

fn decode_event_subscription_start(value: i32) -> Result<EventSubscriptionStart, CanonicalError> {
    match pb::EventSubscriptionStart::try_from(value).map_err(|_| invalid_argument())? {
        pb::EventSubscriptionStart::Unspecified => Err(invalid_argument()),
        pb::EventSubscriptionStart::Beginning => Ok(EventSubscriptionStart::Beginning),
        pb::EventSubscriptionStart::Latest => Ok(EventSubscriptionStart::Latest),
    }
}

fn decode_event_failure_kind(value: i32) -> Result<EventDeliveryFailureKind, CanonicalError> {
    match pb::EventDeliveryFailureKind::try_from(value).map_err(|_| invalid_argument())? {
        pb::EventDeliveryFailureKind::Unspecified => Err(invalid_argument()),
        pb::EventDeliveryFailureKind::Retryable => Ok(EventDeliveryFailureKind::Retryable),
        pb::EventDeliveryFailureKind::Permanent => Ok(EventDeliveryFailureKind::Permanent),
    }
}

fn decode_event_subscription_lookup(
    value: pb::EventGetSubscriptionRequest,
) -> Result<(TenantScope, EventSubscriptionId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
    ))
}

fn decode_event_poll(
    value: pb::EventPollRequest,
) -> Result<(TenantScope, EventSubscriptionId, usize), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
        usize::try_from(value.max_items).map_err(|_| invalid_argument())?,
    ))
}

fn decode_event_cursor(value: pb::EventConsumerCursor) -> EventConsumerCursor {
    EventConsumerCursor { token: value.token }
}

fn decode_event_acknowledgement(
    value: pb::EventAcknowledgeRequest,
) -> Result<(TenantScope, EventSubscriptionId, EventConsumerCursor), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
        decode_event_cursor(value.cursor.ok_or_else(invalid_argument)?),
    ))
}

fn decode_event_rejection(
    value: pb::EventRejectRequest,
) -> Result<
    (
        TenantScope,
        EventSubscriptionId,
        EventConsumerCursor,
        EventDeliveryFailureKind,
    ),
    CanonicalError,
> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
        decode_event_cursor(value.cursor.ok_or_else(invalid_argument)?),
        decode_event_failure_kind(value.failure_kind)?,
    ))
}

fn decode_event_replay(
    value: pb::EventReplayRequest,
) -> Result<(TenantScope, EventSubscriptionId, OpaqueId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
        decode_opaque(value.replay_id)?,
    ))
}

fn decode_event_dead_letter_lookup(
    value: pb::EventListDeadLettersRequest,
) -> Result<(TenantScope, EventSubscriptionId, usize), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        EventSubscriptionId::from_opaque(decode_opaque(value.subscription_id)?),
        usize::try_from(value.max_items).map_err(|_| invalid_argument())?,
    ))
}

fn pb_event_envelope(value: &EventEnvelope) -> pb::EventEnvelope {
    pb::EventEnvelope {
        event_id: Some(pb_opaque(value.event_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        event_type: value.event_type.clone(),
        payload: value.payload.clone(),
        logical_order: value.logical_order,
        correlation: Some(pb_correlation(&value.correlation)),
        schema_version: Some(pb_protocol_version(value.schema_version)),
        integrity_metadata: value.integrity_metadata.clone(),
        extensions: value.extensions.iter().cloned().map(pb_extension).collect(),
        actor: Some(pb_actor_ref(&value.actor)),
        source_device: Some(pb_device_ref(&value.source_device)),
        wall_time_unix_ms: value.wall_time_unix_ms,
    }
}

fn pb_event_subscription_mode(value: EventSubscriptionMode) -> i32 {
    match value {
        EventSubscriptionMode::DurableStream => pb::EventSubscriptionMode::DurableStream as i32,
        EventSubscriptionMode::Webhook => pb::EventSubscriptionMode::Webhook as i32,
    }
}

fn pb_event_subscription_start(value: EventSubscriptionStart) -> i32 {
    match value {
        EventSubscriptionStart::Beginning => pb::EventSubscriptionStart::Beginning as i32,
        EventSubscriptionStart::Latest => pb::EventSubscriptionStart::Latest as i32,
    }
}

fn pb_event_failure_kind(value: EventDeliveryFailureKind) -> i32 {
    match value {
        EventDeliveryFailureKind::Retryable => pb::EventDeliveryFailureKind::Retryable as i32,
        EventDeliveryFailureKind::Permanent => pb::EventDeliveryFailureKind::Permanent as i32,
    }
}

fn pb_event_subscription(value: &EventSubscription) -> pb::EventSubscription {
    pb::EventSubscription {
        subscription_id: Some(pb_opaque(value.subscription_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        mode: pb_event_subscription_mode(value.mode),
        webhook_uri: value.webhook_uri.clone(),
        event_types: value.event_types.clone(),
        max_in_flight: value.max_in_flight,
        max_attempts: value.max_attempts,
        start: pb_event_subscription_start(value.start),
    }
}

fn pb_event_delivery_batch(value: &EventDeliveryBatch) -> pb::EventDeliveryBatch {
    pb::EventDeliveryBatch {
        subscription_id: Some(pb_opaque(value.subscription_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        events: value.events.iter().map(pb_event_envelope).collect(),
        cursor: Some(pb::EventConsumerCursor {
            token: value.cursor.token.clone(),
        }),
        attempt: value.attempt,
    }
}

fn pb_event_dead_letter(value: &EventDeadLetter) -> pb::EventDeadLetter {
    pb::EventDeadLetter {
        subscription_id: Some(pb_opaque(value.subscription_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        event: Some(pb_event_envelope(&value.event)),
        attempts: value.attempts,
        failure_kind: pb_event_failure_kind(value.failure_kind),
    }
}

fn pb_event_publish_receipt(
    event: &EventEnvelope,
    status: EventAppendStatus,
) -> pb::EventPublishReceipt {
    let result = match status {
        EventAppendStatus::Appended => pb::EventAppendResult::Appended,
        EventAppendStatus::Duplicate => pb::EventAppendResult::Duplicate,
    };
    pb::EventPublishReceipt {
        event_id: Some(pb_opaque(event.event_id.as_opaque())),
        result: result as i32,
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

fn decode_principal_ref(value: pb::PrincipalRef) -> Result<PrincipalRef, CanonicalError> {
    Ok(PrincipalRef {
        principal_id: PrincipalId::from_opaque(decode_opaque(value.principal_id)?),
        kind: match pb::PrincipalKind::try_from(value.kind).map_err(|_| invalid_argument())? {
            pb::PrincipalKind::Unspecified => return Err(invalid_argument()),
            pb::PrincipalKind::Person => PrincipalKind::Person,
            pb::PrincipalKind::Device => PrincipalKind::Device,
            pb::PrincipalKind::ServiceAccount => PrincipalKind::ServiceAccount,
            pb::PrincipalKind::AiAgent => PrincipalKind::AiAgent,
            pb::PrincipalKind::Bot => PrincipalKind::Bot,
            pb::PrincipalKind::Organization => PrincipalKind::Organization,
            pb::PrincipalKind::Automation => PrincipalKind::Automation,
            pb::PrincipalKind::ExternalPlatform => PrincipalKind::ExternalPlatform,
        },
    })
}

fn decode_call_session(value: pb::CallSession) -> Result<CallSession, CanonicalError> {
    Ok(CallSession {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        call_id: CallId::from_opaque(decode_opaque(value.call_id)?),
        conversation: decode_conversation_ref(value.conversation.ok_or_else(invalid_argument)?)?,
        initiated_by: decode_principal_ref(value.initiated_by.ok_or_else(invalid_argument)?)?,
        participants: value
            .participants
            .into_iter()
            .map(decode_call_participant)
            .collect::<Result<Vec<_>, _>>()?,
        signalling_state: decode_call_signalling_state(value.signalling_state)?,
        media_negotiation_ref: value
            .media_negotiation_ref
            .map(|value| decode_opaque(Some(value)))
            .transpose()?,
        media_negotiation_generation: value.media_negotiation_generation,
        replication_generation: value.replication_generation,
        revision: value.revision,
        termination_reason: value
            .termination_reason
            .map(decode_call_termination_reason)
            .transpose()?,
    })
}

fn decode_call_participant(value: pb::CallParticipant) -> Result<CallParticipant, CanonicalError> {
    Ok(CallParticipant {
        principal: decode_principal_ref(value.principal.ok_or_else(invalid_argument)?)?,
        state: match pb::CallParticipantState::try_from(value.state)
            .map_err(|_| invalid_argument())?
        {
            pb::CallParticipantState::Unspecified => return Err(invalid_argument()),
            pb::CallParticipantState::Invited => CallParticipantState::Invited,
            pb::CallParticipantState::Ringing => CallParticipantState::Ringing,
            pb::CallParticipantState::Accepted => CallParticipantState::Accepted,
            pb::CallParticipantState::Rejected => CallParticipantState::Rejected,
            pb::CallParticipantState::Busy => CallParticipantState::Busy,
            pb::CallParticipantState::Left => CallParticipantState::Left,
        },
        joined_revision: value.joined_revision,
        left_revision: value.left_revision,
    })
}

fn decode_call_signalling_state(value: i32) -> Result<CallSignallingState, CanonicalError> {
    match pb::CallSignallingState::try_from(value).map_err(|_| invalid_argument())? {
        pb::CallSignallingState::Unspecified => Err(invalid_argument()),
        pb::CallSignallingState::Inviting => Ok(CallSignallingState::Inviting),
        pb::CallSignallingState::Ringing => Ok(CallSignallingState::Ringing),
        pb::CallSignallingState::Active => Ok(CallSignallingState::Active),
        pb::CallSignallingState::Reconnecting => Ok(CallSignallingState::Reconnecting),
        pb::CallSignallingState::Terminated => Ok(CallSignallingState::Terminated),
    }
}

fn decode_call_termination_reason(value: i32) -> Result<CallTerminationReason, CanonicalError> {
    match pb::CallTerminationReason::try_from(value).map_err(|_| invalid_argument())? {
        pb::CallTerminationReason::Unspecified => Err(invalid_argument()),
        pb::CallTerminationReason::Rejected => Ok(CallTerminationReason::Rejected),
        pb::CallTerminationReason::Busy => Ok(CallTerminationReason::Busy),
        pb::CallTerminationReason::Cancelled => Ok(CallTerminationReason::Cancelled),
        pb::CallTerminationReason::TimedOut => Ok(CallTerminationReason::TimedOut),
        pb::CallTerminationReason::Completed => Ok(CallTerminationReason::Completed),
        pb::CallTerminationReason::Failed => Ok(CallTerminationReason::Failed),
    }
}

fn decode_call_lookup(value: pb::CallGetRequest) -> Result<(TenantScope, CallId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        CallId::from_opaque(decode_opaque(value.call_id)?),
    ))
}

fn decode_call_signal(value: pb::CallSignal) -> Result<CallSignal, CanonicalError> {
    let kind = value.kind.ok_or_else(invalid_argument)?;
    Ok(CallSignal {
        event_id: ucr_model::EventId::from_opaque(decode_opaque(value.event_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        call_id: CallId::from_opaque(decode_opaque(value.call_id)?),
        expected_revision: value.expected_revision,
        kind: match kind {
            pb::call_signal::Kind::Ringing(_) => CallSignalKind::Ringing,
            pb::call_signal::Kind::Accept(_) => CallSignalKind::Accept,
            pb::call_signal::Kind::Reject(_) => CallSignalKind::Reject,
            pb::call_signal::Kind::Busy(_) => CallSignalKind::Busy,
            pb::call_signal::Kind::Cancel(_) => CallSignalKind::Cancel,
            pb::call_signal::Kind::Timeout(_) => CallSignalKind::Timeout,
            pb::call_signal::Kind::Reconnect(value) => CallSignalKind::Reconnect {
                phase: match pb::CallReconnectPhase::try_from(value.phase)
                    .map_err(|_| invalid_argument())?
                {
                    pb::CallReconnectPhase::Unspecified => return Err(invalid_argument()),
                    pb::CallReconnectPhase::Started => CallReconnectPhase::Started,
                    pb::CallReconnectPhase::Restored => CallReconnectPhase::Restored,
                },
            },
            pb::call_signal::Kind::ParticipantUpdate(value) => CallSignalKind::ParticipantUpdate {
                participant: decode_principal_ref(value.participant.ok_or_else(invalid_argument)?)?,
                kind: match pb::CallParticipantUpdateKind::try_from(value.kind)
                    .map_err(|_| invalid_argument())?
                {
                    pb::CallParticipantUpdateKind::Unspecified => return Err(invalid_argument()),
                    pb::CallParticipantUpdateKind::Add => CallParticipantUpdateKind::Add,
                    pb::CallParticipantUpdateKind::Remove => CallParticipantUpdateKind::Remove,
                },
            },
            pb::call_signal::Kind::MediaRenegotiation(value) => {
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: decode_opaque(value.negotiation_ref)?,
                }
            }
            pb::call_signal::Kind::Terminate(value) => CallSignalKind::Terminate {
                reason: decode_call_termination_reason(value.reason)?,
            },
        },
    })
}

fn decode_conversation_record(
    value: pb::ConversationRecord,
) -> Result<ConversationRecord, CanonicalError> {
    Ok(ConversationRecord {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        conversation: decode_conversation_ref(value.conversation.ok_or_else(invalid_argument)?)?,
        parent_conversation_id: value
            .parent_conversation_id
            .map(|value| decode_opaque(Some(value)).map(ConversationId::from_opaque))
            .transpose()?,
    })
}

fn decode_conversation_ref(value: pb::ConversationRef) -> Result<ConversationRef, CanonicalError> {
    Ok(ConversationRef {
        conversation_id: ConversationId::from_opaque(decode_opaque(value.conversation_id)?),
        kind: decode_conversation_kind(value.kind)?,
    })
}

fn decode_conversation_kind(value: i32) -> Result<ConversationKind, CanonicalError> {
    match pb::ConversationKind::try_from(value).map_err(|_| invalid_argument())? {
        pb::ConversationKind::Unspecified => Err(invalid_argument()),
        pb::ConversationKind::Direct => Ok(ConversationKind::Direct),
        pb::ConversationKind::PrivateGroup => Ok(ConversationKind::PrivateGroup),
        pb::ConversationKind::PublicGroup => Ok(ConversationKind::PublicGroup),
        pb::ConversationKind::Broadcast => Ok(ConversationKind::Broadcast),
        pb::ConversationKind::Community => Ok(ConversationKind::Community),
        pb::ConversationKind::Room => Ok(ConversationKind::Room),
        pb::ConversationKind::Topic => Ok(ConversationKind::Topic),
        pb::ConversationKind::Thread => Ok(ConversationKind::Thread),
        pb::ConversationKind::System => Ok(ConversationKind::System),
    }
}

fn decode_actor_ref(value: pb::ActorRef) -> Result<ucr_model::ActorRef, CanonicalError> {
    Ok(ucr_model::ActorRef {
        actor_id: ActorId::from_opaque(decode_opaque(value.actor_id)?),
        kind: decode_actor_kind(value.kind)?,
        on_behalf_of: value
            .on_behalf_of
            .map(|value| decode_opaque(Some(value)).map(PrincipalId::from_opaque))
            .transpose()?,
    })
}

fn decode_actor_kind(value: i32) -> Result<ActorKind, CanonicalError> {
    match pb::ActorKind::try_from(value).map_err(|_| invalid_argument())? {
        pb::ActorKind::Unspecified => Err(invalid_argument()),
        pb::ActorKind::Person => Ok(ActorKind::Person),
        pb::ActorKind::AiAgent => Ok(ActorKind::AiAgent),
        pb::ActorKind::Bot => Ok(ActorKind::Bot),
        pb::ActorKind::Organization => Ok(ActorKind::Organization),
        pb::ActorKind::System => Ok(ActorKind::System),
    }
}

fn decode_device_ref(value: pb::DeviceRef) -> Result<DeviceRef, CanonicalError> {
    Ok(DeviceRef {
        device_id: DeviceId::from_opaque(decode_opaque(value.device_id)?),
        identity_id: IdentityId::from_opaque(decode_opaque(value.identity_id)?),
    })
}

fn decode_origin_ref(value: pb::OriginRef) -> Result<OriginRef, CanonicalError> {
    Ok(OriginRef {
        principal_id: value
            .principal_id
            .map(|value| decode_opaque(Some(value)).map(PrincipalId::from_opaque))
            .transpose()?,
        endpoint_id: value
            .endpoint_id
            .map(|value| decode_opaque(Some(value)).map(EndpointId::from_opaque))
            .transpose()?,
        integration_id: value
            .integration_id
            .map(|value| decode_opaque(Some(value)).map(IntegrationId::from_opaque))
            .transpose()?,
    })
}

fn decode_delivery_policy(value: i32) -> Result<DeliveryPolicy, CanonicalError> {
    match pb::DeliveryPolicy::try_from(value).map_err(|_| invalid_argument())? {
        pb::DeliveryPolicy::Unspecified => Err(invalid_argument()),
        pb::DeliveryPolicy::BestEffort => Ok(DeliveryPolicy::BestEffort),
        pb::DeliveryPolicy::Durable => Ok(DeliveryPolicy::Durable),
        pb::DeliveryPolicy::Urgent => Ok(DeliveryPolicy::Urgent),
        pb::DeliveryPolicy::Expiring => Ok(DeliveryPolicy::Expiring),
        pb::DeliveryPolicy::LocalOnly => Ok(DeliveryPolicy::LocalOnly),
        pb::DeliveryPolicy::DirectOnly => Ok(DeliveryPolicy::DirectOnly),
        pb::DeliveryPolicy::NoRelay => Ok(DeliveryPolicy::NoRelay),
        pb::DeliveryPolicy::NoExternalBridge => Ok(DeliveryPolicy::NoExternalBridge),
        pb::DeliveryPolicy::PrivateNetworkOnly => Ok(DeliveryPolicy::PrivateNetworkOnly),
    }
}

fn decode_delivery_state(value: i32) -> Result<DeliveryState, CanonicalError> {
    match pb::DeliveryState::try_from(value).map_err(|_| invalid_argument())? {
        pb::DeliveryState::Unspecified => Err(invalid_argument()),
        pb::DeliveryState::Created => Ok(DeliveryState::Created),
        pb::DeliveryState::Persisted => Ok(DeliveryState::Persisted),
        pb::DeliveryState::Encrypted => Ok(DeliveryState::Encrypted),
        pb::DeliveryState::Queued => Ok(DeliveryState::Queued),
        pb::DeliveryState::RoutePlanned => Ok(DeliveryState::RoutePlanned),
        pb::DeliveryState::InFlight => Ok(DeliveryState::InFlight),
        pb::DeliveryState::Acknowledged => Ok(DeliveryState::Acknowledged),
        pb::DeliveryState::Delivered => Ok(DeliveryState::Delivered),
        pb::DeliveryState::Read => Ok(DeliveryState::Read),
        pb::DeliveryState::Failed => Ok(DeliveryState::Failed),
        pb::DeliveryState::Expired => Ok(DeliveryState::Expired),
    }
}

fn decode_message_relation(value: pb::MessageRelation) -> Result<MessageRelation, CanonicalError> {
    Ok(MessageRelation {
        kind: decode_message_relation_kind(value.kind)?,
        target_message_id: MessageId::from_opaque(decode_opaque(value.target_message_id)?),
    })
}

fn decode_message_relation_kind(value: i32) -> Result<MessageRelationKind, CanonicalError> {
    match pb::MessageRelationKind::try_from(value).map_err(|_| invalid_argument())? {
        pb::MessageRelationKind::Unspecified => Err(invalid_argument()),
        pb::MessageRelationKind::Reply => Ok(MessageRelationKind::Reply),
        pb::MessageRelationKind::Quote => Ok(MessageRelationKind::Quote),
        pb::MessageRelationKind::Edit => Ok(MessageRelationKind::Edit),
        pb::MessageRelationKind::Reaction => Ok(MessageRelationKind::Reaction),
        pb::MessageRelationKind::ThreadParent => Ok(MessageRelationKind::ThreadParent),
        pb::MessageRelationKind::Forward => Ok(MessageRelationKind::Forward),
        pb::MessageRelationKind::Reference => Ok(MessageRelationKind::Reference),
    }
}

fn decode_external_message_mapping(
    value: pb::ExternalMessageMapping,
) -> Result<ExternalMessageMapping, CanonicalError> {
    Ok(ExternalMessageMapping {
        integration_id: IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
        external_message_id: value.external_message_id,
    })
}

fn decode_crypto_suite(value: i32) -> Result<CryptoSuite, CanonicalError> {
    match pb::CryptoSuite::try_from(value).map_err(|_| invalid_argument())? {
        pb::CryptoSuite::Unspecified => Err(invalid_argument()),
        pb::CryptoSuite::UcrV1 => Ok(CryptoSuite::UcrV1),
    }
}

fn decode_message_crypto_metadata(
    value: pb::MessageCryptoMetadata,
) -> Result<MessageCryptoMetadata, CanonicalError> {
    Ok(MessageCryptoMetadata {
        suite: decode_crypto_suite(value.suite)?,
        key_id: value
            .key_id
            .map(|value| decode_opaque(Some(value)).map(KeyId::from_opaque))
            .transpose()?,
        opaque_metadata: value.opaque_metadata,
    })
}

fn decode_message_signature(
    value: pb::MessageSignature,
) -> Result<MessageSignature, CanonicalError> {
    Ok(MessageSignature {
        key_id: KeyId::from_opaque(decode_opaque(value.key_id)?),
        algorithm_id: value.algorithm_id,
        algorithm_version: value.algorithm_version,
        signature: value.signature,
    })
}

fn decode_message_envelope(value: pb::MessageEnvelope) -> Result<MessageEnvelope, CanonicalError> {
    Ok(MessageEnvelope {
        message_id: MessageId::from_opaque(decode_opaque(value.message_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        conversation: decode_conversation_ref(value.conversation.ok_or_else(invalid_argument)?)?,
        author: decode_actor_ref(value.author.ok_or_else(invalid_argument)?)?,
        author_device: decode_device_ref(value.author_device.ok_or_else(invalid_argument)?)?,
        created_at_unix_ms: value.created_at_unix_ms,
        logical_order: value.logical_order,
        content: value.content,
        attachment_ids: value
            .attachment_ids
            .into_iter()
            .map(|value| decode_opaque(Some(value)).map(AttachmentId::from_opaque))
            .collect::<Result<_, _>>()?,
        reply_to: value
            .reply_to
            .map(|value| decode_opaque(Some(value)).map(MessageId::from_opaque))
            .transpose()?,
        relations: value
            .relations
            .into_iter()
            .map(decode_message_relation)
            .collect::<Result<_, _>>()?,
        crypto_metadata: value
            .crypto_metadata
            .map(decode_message_crypto_metadata)
            .transpose()?,
        delivery_policy: decode_delivery_policy(value.delivery_policy)?,
        delivery_state: decode_delivery_state(value.delivery_state)?,
        origin: decode_origin_ref(value.origin.ok_or_else(invalid_argument)?)?,
        correlation: decode_correlation(value.correlation.ok_or_else(invalid_argument)?)?,
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
        external_mappings: value
            .external_mappings
            .into_iter()
            .map(decode_external_message_mapping)
            .collect::<Result<_, _>>()?,
        signature: value.signature.map(decode_message_signature).transpose()?,
    })
}

fn decode_intent_constraints(value: pb::IntentConstraints) -> IntentConstraints {
    IntentConstraints {
        allowed_transport_capabilities: value.allowed_transport_capabilities,
        forbidden_transport_capabilities: value.forbidden_transport_capabilities,
        privacy_profile: value.privacy_profile,
        region_constraint: value.region_constraint,
        max_cost_microunits: value.max_cost_microunits,
        priority_class: value.priority_class,
    }
}

fn decode_communication_intent(
    value: pb::CommunicationIntent,
) -> Result<CommunicationIntent, CanonicalError> {
    Ok(CommunicationIntent {
        intent_id: IntentId::from_opaque(decode_opaque(value.intent_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        target_identity_id: IdentityId::from_opaque(decode_opaque(value.target_identity_id)?),
        payload: value.payload,
        constraints: decode_intent_constraints(value.constraints.ok_or_else(invalid_argument)?),
        correlation: decode_correlation(value.correlation.ok_or_else(invalid_argument)?)?,
        extensions: value.extensions.into_iter().map(decode_extension).collect(),
    })
}

fn decode_conversation_lookup(
    value: pb::IntegrationGetConversationRequest,
) -> Result<(TenantScope, ConversationId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        ConversationId::from_opaque(decode_opaque(value.conversation_id)?),
    ))
}

fn decode_message_lookup(
    value: pb::IntegrationGetMessageRequest,
) -> Result<(TenantScope, MessageId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        MessageId::from_opaque(decode_opaque(value.message_id)?),
    ))
}

fn decode_communication_intent_lookup(
    value: pb::IntegrationGetCommunicationIntentRequest,
) -> Result<(TenantScope, IntentId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        IntentId::from_opaque(decode_opaque(value.intent_id)?),
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

fn pb_principal_ref(value: &PrincipalRef) -> pb::PrincipalRef {
    pb::PrincipalRef {
        principal_id: Some(pb_opaque(value.principal_id.as_opaque())),
        kind: (match value.kind {
            PrincipalKind::Person => pb::PrincipalKind::Person,
            PrincipalKind::Device => pb::PrincipalKind::Device,
            PrincipalKind::ServiceAccount => pb::PrincipalKind::ServiceAccount,
            PrincipalKind::AiAgent => pb::PrincipalKind::AiAgent,
            PrincipalKind::Bot => pb::PrincipalKind::Bot,
            PrincipalKind::Organization => pb::PrincipalKind::Organization,
            PrincipalKind::Automation => pb::PrincipalKind::Automation,
            PrincipalKind::ExternalPlatform => pb::PrincipalKind::ExternalPlatform,
        }) as i32,
    }
}

fn pb_call_session(value: &CallSession) -> pb::CallSession {
    pb::CallSession {
        scope: Some(pb_scope(&value.scope)),
        call_id: Some(pb_opaque(value.call_id.as_opaque())),
        conversation: Some(pb_conversation_ref(&value.conversation)),
        initiated_by: Some(pb_principal_ref(&value.initiated_by)),
        participants: value
            .participants
            .iter()
            .map(|participant| pb::CallParticipant {
                principal: Some(pb_principal_ref(&participant.principal)),
                state: (match participant.state {
                    CallParticipantState::Invited => pb::CallParticipantState::Invited,
                    CallParticipantState::Ringing => pb::CallParticipantState::Ringing,
                    CallParticipantState::Accepted => pb::CallParticipantState::Accepted,
                    CallParticipantState::Rejected => pb::CallParticipantState::Rejected,
                    CallParticipantState::Busy => pb::CallParticipantState::Busy,
                    CallParticipantState::Left => pb::CallParticipantState::Left,
                }) as i32,
                joined_revision: participant.joined_revision,
                left_revision: participant.left_revision,
            })
            .collect(),
        signalling_state: (match value.signalling_state {
            CallSignallingState::Inviting => pb::CallSignallingState::Inviting,
            CallSignallingState::Ringing => pb::CallSignallingState::Ringing,
            CallSignallingState::Active => pb::CallSignallingState::Active,
            CallSignallingState::Reconnecting => pb::CallSignallingState::Reconnecting,
            CallSignallingState::Terminated => pb::CallSignallingState::Terminated,
        }) as i32,
        media_negotiation_ref: value.media_negotiation_ref.as_ref().map(pb_opaque),
        media_negotiation_generation: value.media_negotiation_generation,
        replication_generation: value.replication_generation,
        revision: value.revision,
        termination_reason: value.termination_reason.map(|reason| {
            (match reason {
                CallTerminationReason::Rejected => pb::CallTerminationReason::Rejected,
                CallTerminationReason::Busy => pb::CallTerminationReason::Busy,
                CallTerminationReason::Cancelled => pb::CallTerminationReason::Cancelled,
                CallTerminationReason::TimedOut => pb::CallTerminationReason::TimedOut,
                CallTerminationReason::Completed => pb::CallTerminationReason::Completed,
                CallTerminationReason::Failed => pb::CallTerminationReason::Failed,
            }) as i32
        }),
    }
}

fn pb_conversation_kind(value: ConversationKind) -> i32 {
    (match value {
        ConversationKind::Direct => pb::ConversationKind::Direct,
        ConversationKind::PrivateGroup => pb::ConversationKind::PrivateGroup,
        ConversationKind::PublicGroup => pb::ConversationKind::PublicGroup,
        ConversationKind::Broadcast => pb::ConversationKind::Broadcast,
        ConversationKind::Community => pb::ConversationKind::Community,
        ConversationKind::Room => pb::ConversationKind::Room,
        ConversationKind::Topic => pb::ConversationKind::Topic,
        ConversationKind::Thread => pb::ConversationKind::Thread,
        ConversationKind::System => pb::ConversationKind::System,
    }) as i32
}

fn pb_conversation_ref(value: &ConversationRef) -> pb::ConversationRef {
    pb::ConversationRef {
        conversation_id: Some(pb_opaque(value.conversation_id.as_opaque())),
        kind: pb_conversation_kind(value.kind),
    }
}

fn pb_conversation_record(value: &ConversationRecord) -> pb::ConversationRecord {
    pb::ConversationRecord {
        scope: Some(pb_scope(&value.scope)),
        conversation: Some(pb_conversation_ref(&value.conversation)),
        parent_conversation_id: value
            .parent_conversation_id
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
    }
}

fn pb_actor_kind(value: ActorKind) -> i32 {
    (match value {
        ActorKind::Person => pb::ActorKind::Person,
        ActorKind::AiAgent => pb::ActorKind::AiAgent,
        ActorKind::Bot => pb::ActorKind::Bot,
        ActorKind::Organization => pb::ActorKind::Organization,
        ActorKind::System => pb::ActorKind::System,
    }) as i32
}

fn pb_actor_ref(value: &ucr_model::ActorRef) -> pb::ActorRef {
    pb::ActorRef {
        actor_id: Some(pb_opaque(value.actor_id.as_opaque())),
        kind: pb_actor_kind(value.kind),
        on_behalf_of: value
            .on_behalf_of
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
    }
}

fn pb_device_ref(value: &DeviceRef) -> pb::DeviceRef {
    pb::DeviceRef {
        device_id: Some(pb_opaque(value.device_id.as_opaque())),
        identity_id: Some(pb_opaque(value.identity_id.as_opaque())),
    }
}

fn pb_origin_ref(value: &OriginRef) -> pb::OriginRef {
    pb::OriginRef {
        principal_id: value
            .principal_id
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
        endpoint_id: value
            .endpoint_id
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
        integration_id: value
            .integration_id
            .as_ref()
            .map(|id| pb_opaque(id.as_opaque())),
    }
}

fn pb_delivery_policy(value: DeliveryPolicy) -> i32 {
    (match value {
        DeliveryPolicy::BestEffort => pb::DeliveryPolicy::BestEffort,
        DeliveryPolicy::Durable => pb::DeliveryPolicy::Durable,
        DeliveryPolicy::Urgent => pb::DeliveryPolicy::Urgent,
        DeliveryPolicy::Expiring => pb::DeliveryPolicy::Expiring,
        DeliveryPolicy::LocalOnly => pb::DeliveryPolicy::LocalOnly,
        DeliveryPolicy::DirectOnly => pb::DeliveryPolicy::DirectOnly,
        DeliveryPolicy::NoRelay => pb::DeliveryPolicy::NoRelay,
        DeliveryPolicy::NoExternalBridge => pb::DeliveryPolicy::NoExternalBridge,
        DeliveryPolicy::PrivateNetworkOnly => pb::DeliveryPolicy::PrivateNetworkOnly,
    }) as i32
}

fn pb_delivery_state(value: DeliveryState) -> i32 {
    (match value {
        DeliveryState::Created => pb::DeliveryState::Created,
        DeliveryState::Persisted => pb::DeliveryState::Persisted,
        DeliveryState::Encrypted => pb::DeliveryState::Encrypted,
        DeliveryState::Queued => pb::DeliveryState::Queued,
        DeliveryState::RoutePlanned => pb::DeliveryState::RoutePlanned,
        DeliveryState::InFlight => pb::DeliveryState::InFlight,
        DeliveryState::Acknowledged => pb::DeliveryState::Acknowledged,
        DeliveryState::Delivered => pb::DeliveryState::Delivered,
        DeliveryState::Read => pb::DeliveryState::Read,
        DeliveryState::Failed => pb::DeliveryState::Failed,
        DeliveryState::Expired => pb::DeliveryState::Expired,
    }) as i32
}

fn pb_message_relation_kind(value: MessageRelationKind) -> i32 {
    (match value {
        MessageRelationKind::Reply => pb::MessageRelationKind::Reply,
        MessageRelationKind::Quote => pb::MessageRelationKind::Quote,
        MessageRelationKind::Edit => pb::MessageRelationKind::Edit,
        MessageRelationKind::Reaction => pb::MessageRelationKind::Reaction,
        MessageRelationKind::ThreadParent => pb::MessageRelationKind::ThreadParent,
        MessageRelationKind::Forward => pb::MessageRelationKind::Forward,
        MessageRelationKind::Reference => pb::MessageRelationKind::Reference,
    }) as i32
}

fn pb_message_relation(value: &MessageRelation) -> pb::MessageRelation {
    pb::MessageRelation {
        kind: pb_message_relation_kind(value.kind),
        target_message_id: Some(pb_opaque(value.target_message_id.as_opaque())),
    }
}

fn pb_external_message_mapping(value: &ExternalMessageMapping) -> pb::ExternalMessageMapping {
    pb::ExternalMessageMapping {
        integration_id: Some(pb_opaque(value.integration_id.as_opaque())),
        external_message_id: value.external_message_id.clone(),
    }
}

fn pb_crypto_suite(value: CryptoSuite) -> i32 {
    (match value {
        CryptoSuite::UcrV1 => pb::CryptoSuite::UcrV1,
    }) as i32
}

fn pb_message_crypto_metadata(value: &MessageCryptoMetadata) -> pb::MessageCryptoMetadata {
    pb::MessageCryptoMetadata {
        suite: pb_crypto_suite(value.suite),
        key_id: value.key_id.as_ref().map(|id| pb_opaque(id.as_opaque())),
        opaque_metadata: value.opaque_metadata.clone(),
    }
}

fn pb_message_signature(value: &MessageSignature) -> pb::MessageSignature {
    pb::MessageSignature {
        key_id: Some(pb_opaque(value.key_id.as_opaque())),
        algorithm_id: value.algorithm_id.clone(),
        algorithm_version: value.algorithm_version,
        signature: value.signature.clone(),
    }
}

fn pb_correlation(value: &CorrelationContext) -> pb::Correlation {
    pb::Correlation {
        correlation_id: Some(pb_opaque(&value.correlation_id)),
        causation_id: value.causation_id.as_ref().map(pb_opaque),
        idempotency_key: value.idempotency_key.clone(),
    }
}

fn pb_message_envelope(value: &MessageEnvelope) -> pb::MessageEnvelope {
    pb::MessageEnvelope {
        message_id: Some(pb_opaque(value.message_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        conversation: Some(pb_conversation_ref(&value.conversation)),
        author: Some(pb_actor_ref(&value.author)),
        author_device: Some(pb_device_ref(&value.author_device)),
        logical_order: value.logical_order,
        content: value.content.clone(),
        delivery_policy: pb_delivery_policy(value.delivery_policy),
        correlation: Some(pb_correlation(&value.correlation)),
        extensions: value.extensions.iter().cloned().map(pb_extension).collect(),
        origin: Some(pb_origin_ref(&value.origin)),
        created_at_unix_ms: value.created_at_unix_ms,
        attachment_ids: value
            .attachment_ids
            .iter()
            .map(|id| pb_opaque(id.as_opaque()))
            .collect(),
        relations: value.relations.iter().map(pb_message_relation).collect(),
        crypto_metadata: value
            .crypto_metadata
            .as_ref()
            .map(pb_message_crypto_metadata),
        delivery_state: pb_delivery_state(value.delivery_state),
        external_mappings: value
            .external_mappings
            .iter()
            .map(pb_external_message_mapping)
            .collect(),
        signature: value.signature.as_ref().map(pb_message_signature),
        reply_to: value.reply_to.as_ref().map(|id| pb_opaque(id.as_opaque())),
    }
}

fn pb_intent_constraints(value: &IntentConstraints) -> pb::IntentConstraints {
    pb::IntentConstraints {
        allowed_transport_capabilities: value.allowed_transport_capabilities.clone(),
        forbidden_transport_capabilities: value.forbidden_transport_capabilities.clone(),
        privacy_profile: value.privacy_profile.clone(),
        region_constraint: value.region_constraint.clone(),
        max_cost_microunits: value.max_cost_microunits,
        priority_class: value.priority_class,
    }
}

fn pb_communication_intent(value: &CommunicationIntent) -> pb::CommunicationIntent {
    pb::CommunicationIntent {
        intent_id: Some(pb_opaque(value.intent_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        target_identity_id: Some(pb_opaque(value.target_identity_id.as_opaque())),
        payload: value.payload.clone(),
        constraints: Some(pb_intent_constraints(&value.constraints)),
        correlation: Some(pb_correlation(&value.correlation)),
        extensions: value.extensions.iter().cloned().map(pb_extension).collect(),
    }
}

fn pb_acknowledgement(value: AcknowledgementEnvelope) -> pb::AcknowledgementEnvelope {
    pb::AcknowledgementEnvelope {
        acknowledged_id: Some(pb_opaque(&value.acknowledged_id)),
        schema_version: Some(pb_protocol_version(value.schema_version)),
        extensions: value.extensions.into_iter().map(pb_extension).collect(),
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
    use tonic::{Request, transport::Server};
    use ucr_core::{
        CommunicationIntentStore, ConversationStore, IdentityStore, MessageStore,
        PermissionGrantStore, ServiceCredentialSecret, ServiceCredentialStore, ServiceQuotaStore,
        SystemEventDeliveryClock, SystemServiceQuotaClock, issue_service_credential,
    };
    use ucr_model::{
        IdentityId, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalKind, PrincipalRef, ScopedPrincipal, ServiceQuotaPolicy, TenantId, TenantScope,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, CALL_OBSERVE_PERMISSION, CALL_SIGNAL_PERMISSION, CALL_START_PERMISSION,
        COMMAND_ACCEPT_PERMISSION, COMMUNICATION_INTENT_READ_PERMISSION,
        COMMUNICATION_INTENT_WRITE_PERMISSION, CONVERSATION_READ_PERMISSION,
        CONVERSATION_WRITE_PERMISSION, DEFAULT_MAX_PAYLOAD_LEN, EVENT_APPEND_PERMISSION,
        EVENT_CONSUME_PERMISSION, EVENT_DEAD_LETTER_READ_PERMISSION, EVENT_REPLAY_PERMISSION,
        EVENT_SUBSCRIBE_PERMISSION, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
        EXTERNAL_IDENTITY_BINDING_READ_PERMISSION, EXTERNAL_MESSAGE_ID_LIMIT,
        EXTERNAL_MESSAGE_MAPPING_LIMIT, IDENTITY_CREATE_PERMISSION, IDENTITY_READ_PERMISSION,
        MAX_COMMAND_PAYLOAD_LEN, MAX_EVENT_INTEGRITY_METADATA_LEN, MAX_EVENT_PAYLOAD_LEN,
        MAX_EXTENSION_PAYLOAD_LEN, MAX_IDEMPOTENCY_KEY_LEN, MAX_INTENT_POLICY_VALUE_LEN,
        MAX_INTENT_TRANSPORT_CONSTRAINTS, MAX_NAMESPACED_IDENTIFIER_LEN, MAX_PROTOCOL_EXTENSIONS,
        MESSAGE_ATTACHMENT_LIMIT, MESSAGE_CRYPTO_METADATA_LIMIT, MESSAGE_READ_PERMISSION,
        MESSAGE_RELATION_LIMIT, MESSAGE_WRITE_PERMISSION, SIGNATURE_ALGORITHM_ID, SIGNATURE_LEN,
        validate_communication_intent, validate_event, validate_message,
    };
    use ucr_storage_memory::MemoryLocalStore;

    use super::{
        GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, GrpcCallService,
        GrpcEventService, GrpcIntegrationService, SERVICE_CREDENTIAL_ID_METADATA_KEY,
        SERVICE_CREDENTIAL_SECRET_METADATA_KEY, attach_service_credential, call_service_server,
        decode_command, decode_communication_intent, decode_conversation_record,
        decode_event_envelope, decode_message_envelope, event_service_server,
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

    fn budget_pb_id(prefix: &str, index: usize) -> pb::OpaqueId {
        let stem = format!("{prefix}-{index}-");
        assert!(stem.len() <= OpaqueId::MAX_LEN);
        pb::OpaqueId {
            value: format!("{stem}{}", "x".repeat(OpaqueId::MAX_LEN - stem.len())).into_bytes(),
        }
    }

    fn budget_namespaced(prefix: &str, index: usize) -> String {
        let stem = format!("{prefix}.{index}.");
        assert!(stem.len() <= MAX_NAMESPACED_IDENTIFIER_LEN);
        format!(
            "{stem}{}",
            "a".repeat(MAX_NAMESPACED_IDENTIFIER_LEN - stem.len())
        )
    }

    fn budget_extensions(prefix: &str) -> Vec<pb::Extension> {
        (0..MAX_PROTOCOL_EXTENSIONS)
            .map(|index| pb::Extension {
                name: budget_namespaced(prefix, index),
                critical: false,
                payload: vec![0x42; MAX_EXTENSION_PAYLOAD_LEN],
            })
            .collect()
    }

    fn budget_correlation(prefix: &str) -> pb::Correlation {
        pb::Correlation {
            correlation_id: Some(budget_pb_id(prefix, 0)),
            causation_id: Some(budget_pb_id(prefix, 1)),
            idempotency_key: Some("i".repeat(MAX_IDEMPOTENCY_KEY_LEN)),
        }
    }

    fn maximum_message_for_decode_budget() -> pb::MessageEnvelope {
        pb::MessageEnvelope {
            message_id: Some(budget_pb_id("message", 0)),
            scope: Some(pb::TenantScope {
                tenant_id: Some(budget_pb_id("tenant", 0)),
                namespace_id: Some(budget_pb_id("namespace", 0)),
            }),
            conversation: Some(pb::ConversationRef {
                conversation_id: Some(budget_pb_id("conversation", 0)),
                kind: pb::ConversationKind::Direct as i32,
            }),
            author: Some(pb::ActorRef {
                actor_id: Some(budget_pb_id("actor", 0)),
                kind: pb::ActorKind::Person as i32,
                on_behalf_of: Some(budget_pb_id("delegator", 0)),
            }),
            author_device: Some(pb::DeviceRef {
                device_id: Some(budget_pb_id("device", 0)),
                identity_id: Some(budget_pb_id("author-identity", 0)),
            }),
            logical_order: u64::MAX,
            content: vec![0x5a; DEFAULT_MAX_PAYLOAD_LEN as usize],
            delivery_policy: pb::DeliveryPolicy::Durable as i32,
            correlation: Some(budget_correlation("message-correlation")),
            extensions: budget_extensions("vendor.grpc_message_budget"),
            origin: Some(pb::OriginRef {
                principal_id: Some(budget_pb_id("principal", 0)),
                endpoint_id: Some(budget_pb_id("endpoint", 0)),
                integration_id: Some(budget_pb_id("origin-integration", 0)),
            }),
            created_at_unix_ms: i64::MIN,
            attachment_ids: (0..MESSAGE_ATTACHMENT_LIMIT)
                .map(|index| budget_pb_id("attachment", index))
                .collect(),
            relations: (0..MESSAGE_RELATION_LIMIT)
                .map(|index| pb::MessageRelation {
                    kind: pb::MessageRelationKind::Reference as i32,
                    target_message_id: Some(budget_pb_id("relation-target", index)),
                })
                .collect(),
            crypto_metadata: Some(pb::MessageCryptoMetadata {
                suite: pb::CryptoSuite::UcrV1 as i32,
                key_id: Some(budget_pb_id("crypto-key", 0)),
                opaque_metadata: vec![0x6b; MESSAGE_CRYPTO_METADATA_LIMIT],
            }),
            delivery_state: pb::DeliveryState::Created as i32,
            external_mappings: (0..EXTERNAL_MESSAGE_MAPPING_LIMIT)
                .map(|index| pb::ExternalMessageMapping {
                    integration_id: Some(budget_pb_id("mapping-integration", index)),
                    external_message_id: vec![0x80; EXTERNAL_MESSAGE_ID_LIMIT],
                })
                .collect(),
            signature: Some(pb::MessageSignature {
                key_id: Some(budget_pb_id("signature-key", 0)),
                algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                algorithm_version: ALGORITHM_VERSION,
                signature: vec![0x7a; SIGNATURE_LEN],
            }),
            reply_to: None,
        }
    }

    fn maximum_intent_for_decode_budget() -> pb::CommunicationIntent {
        pb::CommunicationIntent {
            intent_id: Some(budget_pb_id("intent", 0)),
            scope: Some(pb::TenantScope {
                tenant_id: Some(budget_pb_id("tenant", 0)),
                namespace_id: Some(budget_pb_id("namespace", 0)),
            }),
            target_identity_id: Some(budget_pb_id("target-identity", 0)),
            payload: vec![0x5a; DEFAULT_MAX_PAYLOAD_LEN as usize],
            constraints: Some(pb::IntentConstraints {
                allowed_transport_capabilities: (0..MAX_INTENT_TRANSPORT_CONSTRAINTS)
                    .map(|index| budget_namespaced("ucr.transport.grpc_budget", index))
                    .collect(),
                forbidden_transport_capabilities: Vec::new(),
                privacy_profile: Some("p".repeat(MAX_INTENT_POLICY_VALUE_LEN)),
                region_constraint: Some("r".repeat(MAX_INTENT_POLICY_VALUE_LEN)),
                max_cost_microunits: Some(u64::MAX),
                priority_class: Some(u32::MAX),
            }),
            correlation: Some(budget_correlation("intent-correlation")),
            extensions: budget_extensions("vendor.grpc_intent_budget"),
        }
    }

    fn maximum_event_for_decode_budget() -> pb::EventEnvelope {
        pb::EventEnvelope {
            event_id: Some(budget_pb_id("event", 0)),
            scope: Some(pb::TenantScope {
                tenant_id: Some(budget_pb_id("tenant", 0)),
                namespace_id: Some(budget_pb_id("namespace", 0)),
            }),
            event_type: budget_namespaced("vendor.grpc_event_budget", 0),
            payload: vec![0x5a; MAX_EVENT_PAYLOAD_LEN],
            logical_order: u64::MAX,
            correlation: Some(budget_correlation("event-correlation")),
            schema_version: Some(pb::ProtocolVersion {
                major: u32::MAX,
                minor: u32::MAX,
            }),
            integrity_metadata: vec![0x6b; MAX_EVENT_INTEGRITY_METADATA_LEN],
            extensions: budget_extensions("vendor.grpc_event_extension_budget"),
            actor: Some(pb::ActorRef {
                actor_id: Some(budget_pb_id("event-actor", 0)),
                kind: pb::ActorKind::System as i32,
                on_behalf_of: Some(budget_pb_id("event-delegator", 0)),
            }),
            source_device: Some(pb::DeviceRef {
                device_id: Some(budget_pb_id("event-device", 0)),
                identity_id: Some(budget_pb_id("event-identity", 0)),
            }),
            wall_time_unix_ms: i64::MIN,
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

    fn conversation(id: &str, kind: pb::ConversationKind) -> pb::ConversationRecord {
        pb::ConversationRecord {
            scope: Some(wire_scope()),
            conversation: Some(pb::ConversationRef {
                conversation_id: Some(pb_id(id)),
                kind: kind as i32,
            }),
            parent_conversation_id: None,
        }
    }

    fn call_session(id: &str, conversation_id: &str) -> pb::CallSession {
        pb::CallSession {
            scope: Some(wire_scope()),
            call_id: Some(pb_id(id)),
            conversation: Some(pb::ConversationRef {
                conversation_id: Some(pb_id(conversation_id)),
                kind: pb::ConversationKind::Direct as i32,
            }),
            initiated_by: Some(pb::PrincipalRef {
                principal_id: Some(pb_id("service-grpc")),
                kind: pb::PrincipalKind::ServiceAccount as i32,
            }),
            participants: vec![
                pb::CallParticipant {
                    principal: Some(pb::PrincipalRef {
                        principal_id: Some(pb_id("service-grpc")),
                        kind: pb::PrincipalKind::ServiceAccount as i32,
                    }),
                    state: pb::CallParticipantState::Accepted as i32,
                    joined_revision: 0,
                    left_revision: None,
                },
                pb::CallParticipant {
                    principal: Some(pb::PrincipalRef {
                        principal_id: Some(pb_id("remote-person")),
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
        }
    }

    fn cancel_call_signal(id: &str, call_id: &str) -> pb::CallSignal {
        pb::CallSignal {
            event_id: Some(pb_id(id)),
            scope: Some(wire_scope()),
            call_id: Some(pb_id(call_id)),
            expected_revision: 0,
            kind: Some(pb::call_signal::Kind::Cancel(pb::CallEmptySignal {})),
        }
    }

    fn message(
        id: &str,
        conversation_id: &str,
        content: &[u8],
        external_message_id: Vec<u8>,
    ) -> pb::MessageEnvelope {
        pb::MessageEnvelope {
            message_id: Some(pb_id(id)),
            scope: Some(wire_scope()),
            conversation: Some(pb::ConversationRef {
                conversation_id: Some(pb_id(conversation_id)),
                kind: pb::ConversationKind::Direct as i32,
            }),
            author: Some(pb::ActorRef {
                actor_id: Some(pb_id("actor-grpc")),
                kind: pb::ActorKind::Person as i32,
                on_behalf_of: None,
            }),
            author_device: Some(pb::DeviceRef {
                device_id: Some(pb_id("device-grpc")),
                identity_id: Some(pb_id("identity-grpc-author")),
            }),
            logical_order: 7,
            content: content.to_vec(),
            delivery_policy: pb::DeliveryPolicy::Durable as i32,
            correlation: Some(pb::Correlation {
                correlation_id: Some(pb_id("correlation-message-grpc")),
                causation_id: None,
                idempotency_key: Some(format!("message-key-{id}")),
            }),
            extensions: vec![pb::Extension {
                name: "vendor.example.message".to_owned(),
                critical: false,
                payload: vec![0, 255, 128, 77],
            }],
            origin: Some(pb::OriginRef {
                principal_id: Some(pb_id("service-grpc")),
                endpoint_id: None,
                integration_id: Some(pb_id("integration-grpc")),
            }),
            created_at_unix_ms: 1_700_000_000_123,
            attachment_ids: Vec::new(),
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_state: pb::DeliveryState::Created as i32,
            external_mappings: vec![pb::ExternalMessageMapping {
                integration_id: Some(pb_id("integration-grpc")),
                external_message_id,
            }],
            signature: None,
            reply_to: None,
        }
    }

    fn intent(id: &str, payload: &[u8]) -> pb::CommunicationIntent {
        pb::CommunicationIntent {
            intent_id: Some(pb_id(id)),
            scope: Some(wire_scope()),
            target_identity_id: Some(pb_id("identity-grpc-target")),
            payload: payload.to_vec(),
            constraints: Some(pb::IntentConstraints {
                allowed_transport_capabilities: vec!["ucr.transport.direct".to_owned()],
                forbidden_transport_capabilities: vec!["ucr.transport.relay".to_owned()],
                privacy_profile: Some("ucr.privacy.private".to_owned()),
                region_constraint: Some("ee".to_owned()),
                max_cost_microunits: Some(42),
                priority_class: Some(2),
            }),
            correlation: Some(pb::Correlation {
                correlation_id: Some(pb_id("correlation-intent-grpc")),
                causation_id: Some(pb_id("cause-intent-grpc")),
                idempotency_key: Some(format!("intent-key-{id}")),
            }),
            extensions: vec![pb::Extension {
                name: "vendor.example.intent".to_owned(),
                critical: false,
                payload: vec![0, 255, 128, 73],
            }],
        }
    }

    fn event(id: &str, payload: &[u8]) -> pb::EventEnvelope {
        pb::EventEnvelope {
            event_id: Some(pb_id(id)),
            scope: Some(wire_scope()),
            event_type: "ucr.message.created".to_owned(),
            payload: payload.to_vec(),
            logical_order: 11,
            correlation: Some(pb::Correlation {
                correlation_id: Some(pb_id(&format!("correlation-{id}"))),
                causation_id: None,
                idempotency_key: None,
            }),
            schema_version: Some(pb::ProtocolVersion { major: 1, minor: 0 }),
            integrity_metadata: vec![0x91, 0x92],
            extensions: vec![pb::Extension {
                name: "vendor.example.event".to_owned(),
                critical: false,
                payload: vec![0, 255, 128, 69],
            }],
            actor: Some(pb::ActorRef {
                actor_id: Some(pb_id("actor-event-grpc")),
                kind: pb::ActorKind::System as i32,
                on_behalf_of: None,
            }),
            source_device: Some(pb::DeviceRef {
                device_id: Some(pb_id("device-event-grpc")),
                identity_id: Some(pb_id("identity-event-grpc")),
            }),
            wall_time_unix_ms: 1_700_000_000_456,
        }
    }

    fn subscription(id: &str, max_attempts: u32) -> pb::EventSubscription {
        pb::EventSubscription {
            subscription_id: Some(pb_id(id)),
            scope: Some(wire_scope()),
            mode: pb::EventSubscriptionMode::DurableStream as i32,
            webhook_uri: None,
            event_types: vec!["ucr.message.created".to_owned()],
            max_in_flight: 1,
            max_attempts,
            start: pb::EventSubscriptionStart::Beginning as i32,
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

    fn seed_subject_with_permissions(
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
        .expect("connect loopback client")
        .max_decoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE);
        (client, server)
    }

    async fn call_client_and_server(
        store: Arc<MemoryLocalStore>,
    ) -> (
        pb::call_service_client::CallServiceClient<tonic::transport::Channel>,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Call loopback listener");
        let address = listener.local_addr().expect("Call listener address");
        let incoming = TcpListenerStream::new(listener);
        let service =
            GrpcCallService::new(Arc::new(SystemServiceQuotaClock), Arc::clone(&store), store);
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(call_service_server(service))
                .serve_with_incoming(incoming)
                .await
        });
        let client =
            pb::call_service_client::CallServiceClient::connect(format!("http://{address}"))
                .await
                .expect("connect Call loopback client")
                .max_decoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE);
        (client, server)
    }

    async fn event_client_and_server(
        store: Arc<MemoryLocalStore>,
    ) -> (
        pb::event_service_client::EventServiceClient<tonic::transport::Channel>,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Event loopback listener");
        let address = listener.local_addr().expect("Event listener address");
        let incoming = TcpListenerStream::new(listener);
        let service = GrpcEventService::new(
            Arc::new(SystemServiceQuotaClock),
            Arc::new(SystemEventDeliveryClock),
            Arc::clone(&store),
            store,
        );
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(event_service_server(service))
                .serve_with_incoming(incoming)
                .await
        });
        let client =
            pb::event_service_client::EventServiceClient::connect(format!("http://{address}"))
                .await
                .expect("connect Event loopback client")
                .max_decoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE);
        (client, server)
    }

    type TestCallClient = pb::call_service_client::CallServiceClient<tonic::transport::Channel>;

    fn assert_canonical_start_participant_order(started: &pb::CallSession) {
        assert_eq!(started.participants.len(), 2);
        let participant_id = |index: usize| {
            started.participants[index]
                .principal
                .as_ref()
                .and_then(|principal| principal.principal_id.as_ref())
                .map(|id| id.value.as_slice())
        };
        assert_eq!(participant_id(0), Some(b"remote-person".as_slice()));
        assert_eq!(participant_id(1), Some(b"service-grpc".as_slice()));
    }

    async fn start_cancel_get_call(
        client: &mut TestCallClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        call_id: &str,
    ) {
        let mut start = Request::new(pb::CallStartRequest {
            session: Some(call_session(call_id, "call-conversation-grpc")),
        });
        attach_service_credential(&mut start, credential_id, secret);
        let response = client
            .start_call(start)
            .await
            .expect("start call application response")
            .into_inner();
        let started = match response.result.expect("start result") {
            pb::call_start_response::Result::Call(call) => call,
            pb::call_start_response::Result::Error(error) => {
                panic!("start call failed: {}", error.code)
            }
        };
        assert_eq!(
            started.signalling_state,
            pb::CallSignallingState::Inviting as i32
        );
        assert_eq!(started.revision, 0);
        assert_canonical_start_participant_order(&started);

        let cancel = cancel_call_signal("call-cancel-grpc", call_id);
        for expected_duplicate in [false, true] {
            let mut request = Request::new(pb::CallSignalRequest {
                signal: Some(cancel.clone()),
            });
            attach_service_credential(&mut request, credential_id, secret);
            let response = client
                .signal_call(request)
                .await
                .expect("signal application response")
                .into_inner();
            let acknowledgement = match response.result.expect("signal result") {
                pb::call_signal_response::Result::Acknowledgement(value) => value,
                pb::call_signal_response::Result::Error(error) => {
                    panic!(
                        "signal failed duplicate={expected_duplicate}: {}",
                        error.code
                    )
                }
            };
            assert_eq!(
                acknowledgement
                    .acknowledged_id
                    .expect("acknowledged id")
                    .value,
                b"call-cancel-grpc"
            );
        }

        let mut retry_start = Request::new(pb::CallStartRequest {
            session: Some(call_session(call_id, "call-conversation-grpc")),
        });
        attach_service_credential(&mut retry_start, credential_id, secret);
        let response = client
            .start_call(retry_start)
            .await
            .expect("retry StartCall application response")
            .into_inner();
        let accepted_origin = match response.result.expect("retry StartCall result") {
            pb::call_start_response::Result::Call(call) => call,
            pb::call_start_response::Result::Error(error) => {
                panic!(
                    "retry StartCall after lifecycle progress failed: {}",
                    error.code
                )
            }
        };
        assert_eq!(
            accepted_origin.signalling_state,
            pb::CallSignallingState::Inviting as i32
        );
        assert_eq!(accepted_origin.revision, 0);

        let mut lookup = Request::new(pb::CallGetRequest {
            scope: Some(wire_scope()),
            call_id: Some(pb_id(call_id)),
        });
        attach_service_credential(&mut lookup, credential_id, secret);
        let response = client
            .get_call(lookup)
            .await
            .expect("get call response")
            .into_inner();
        let ended = match response.result.expect("get result") {
            pb::call_get_response::Result::Call(call) => call,
            pb::call_get_response::Result::Error(error) => {
                panic!("get call failed: {}", error.code)
            }
        };
        assert_eq!(
            ended.signalling_state,
            pb::CallSignallingState::Terminated as i32
        );
        assert_eq!(
            ended.termination_reason,
            Some(pb::CallTerminationReason::Cancelled as i32)
        );
        assert_eq!(ended.revision, 1);
    }

    async fn assert_call_non_disclosure(
        store: &MemoryLocalStore,
        client: &mut TestCallClient,
        credential_id: &ucr_model::ServiceCredentialId,
        call_id: &str,
    ) {
        let attacker = ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("service-grpc-attacker")),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        let (attacker_id, attacker_secret) =
            seed_subject_with_permissions(store, attacker, &[CALL_OBSERVE_PERMISSION]);
        let mut attacker_lookup = Request::new(pb::CallGetRequest {
            scope: Some(wire_scope()),
            call_id: Some(pb_id(call_id)),
        });
        attach_service_credential(&mut attacker_lookup, &attacker_id, &attacker_secret);
        let response = client
            .get_call(attacker_lookup)
            .await
            .expect("non-participant response")
            .into_inner();
        let error = match response.result.expect("non-participant result") {
            pb::call_get_response::Result::Error(error) => error,
            pb::call_get_response::Result::Call(_) => {
                panic!("non-participant disclosed call existence")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::NotFound as i32);

        let mut bad_secret = Request::new(pb::CallGetRequest {
            scope: Some(wire_scope()),
            call_id: Some(pb_id(call_id)),
        });
        attach_service_credential(
            &mut bad_secret,
            credential_id,
            &ServiceCredentialSecret::from_bytes([0x44; 32]),
        );
        let response = client
            .get_call(bad_secret)
            .await
            .expect("bad credential response")
            .into_inner();
        let error = match response.result.expect("bad credential result") {
            pb::call_get_response::Result::Error(error) => error,
            pb::call_get_response::Result::Call(_) => panic!("bad credential disclosed call"),
        };
        assert_eq!(error.code, pb::ErrorCode::Unauthenticated as i32);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn call_start_cancel_duplicate_get_and_non_disclosure_round_trip_over_grpc() {
        let store = Arc::new(MemoryLocalStore::default());
        let permissions = [
            CALL_START_PERMISSION,
            CALL_OBSERVE_PERMISSION,
            CALL_SIGNAL_PERMISSION,
        ];
        let (credential_id, secret) = seed_with_permissions(&store, &permissions);
        let conversation = conversation("call-conversation-grpc", pb::ConversationKind::Direct);
        store
            .persist_conversation(
                &decode_conversation_record(conversation).expect("decode conversation"),
            )
            .expect("persist conversation");
        let (mut client, server) = call_client_and_server(Arc::clone(&store)).await;
        let call_id = "call-session-grpc";
        start_cancel_get_call(&mut client, &credential_id, &secret, call_id).await;
        assert_call_non_disclosure(&store, &mut client, &credential_id, call_id).await;
        server.abort();
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

    #[test]
    fn grpc_decode_budget_contains_maximum_canonical_message_wire_size() {
        use prost::Message as _;

        let mut request = pb::IntegrationSendMessageRequest {
            message: Some(maximum_message_for_decode_budget()),
        };
        let encoded_len = request.encoded_len();
        let decoded = decode_message_envelope(request.message.take().expect("maximum message"))
            .expect("maximum message decodes");
        validate_message(&decoded).expect("maximum message remains canonical");
        assert!(encoded_len <= GRPC_MAX_DECODING_MESSAGE_SIZE);
    }

    #[test]
    fn grpc_decode_budget_contains_maximum_canonical_intent_wire_size() {
        use prost::Message as _;

        let mut request = pb::IntegrationCreateCommunicationIntentRequest {
            intent: Some(maximum_intent_for_decode_budget()),
        };
        let encoded_len = request.encoded_len();
        let decoded = decode_communication_intent(request.intent.take().expect("maximum intent"))
            .expect("maximum intent decodes");
        validate_communication_intent(&decoded).expect("maximum intent remains canonical");
        assert!(encoded_len <= GRPC_MAX_DECODING_MESSAGE_SIZE);
    }

    #[test]
    fn grpc_decode_budget_contains_maximum_canonical_event_wire_size() {
        use prost::Message as _;

        let mut request = pb::EventPublishRequest {
            event: Some(maximum_event_for_decode_budget()),
        };
        let encoded_len = request.encoded_len();
        let decoded = decode_event_envelope(request.event.take().expect("maximum event"))
            .expect("maximum event decodes");
        validate_event(&decoded).expect("maximum event remains canonical");
        assert!(encoded_len <= GRPC_MAX_DECODING_MESSAGE_SIZE);
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
    async fn conversation_create_retry_get_conflict_and_non_disclosure_round_trip_over_grpc() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[CONVERSATION_WRITE_PERMISSION, CONVERSATION_READ_PERMISSION],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let created = conversation("conversation-grpc", pb::ConversationKind::Direct);

        for _ in 0..2 {
            let mut request = Request::new(pb::IntegrationCreateConversationRequest {
                conversation: Some(created.clone()),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .create_conversation(request)
                .await
                .expect("conversation create is application response")
                .into_inner();
            assert!(matches!(
                response.result,
                Some(pb::integration_create_conversation_response::Result::Conversation(value))
                    if value == created
            ));
        }

        let mut lookup = Request::new(pb::IntegrationGetConversationRequest {
            scope: Some(wire_scope()),
            conversation_id: Some(pb_id("conversation-grpc")),
        });
        attach_service_credential(&mut lookup, &credential_id, &secret);
        let response = client
            .get_conversation(lookup)
            .await
            .expect("conversation get")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_get_conversation_response::Result::Conversation(value))
                if value == created
        ));

        let changed = conversation("conversation-grpc", pb::ConversationKind::Broadcast);
        let mut conflict = Request::new(pb::IntegrationCreateConversationRequest {
            conversation: Some(changed),
        });
        attach_service_credential(&mut conflict, &credential_id, &secret);
        let response = client
            .create_conversation(conflict)
            .await
            .expect("conversation conflict is application response")
            .into_inner();
        let error = match response.result.expect("conflict result") {
            pb::integration_create_conversation_response::Result::Error(error) => error,
            pb::integration_create_conversation_response::Result::Conversation(_) => {
                panic!("conflicting conversation accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::Conflict as i32);
        server.abort();

        let hidden_store = Arc::new(MemoryLocalStore::default());
        let (hidden_credential, hidden_secret) =
            seed_with_permissions(&hidden_store, &[CONVERSATION_WRITE_PERMISSION]);
        let record = ucr_model::ConversationRecord {
            scope: scope(),
            conversation: ucr_model::ConversationRef {
                conversation_id: ucr_model::ConversationId::from_opaque(oid("conversation-hidden")),
                kind: ucr_model::ConversationKind::Direct,
            },
            parent_conversation_id: None,
        };
        hidden_store
            .persist_conversation(&record)
            .expect("seed hidden conversation");
        let (mut hidden_client, hidden_server) = client_and_server(Arc::clone(&hidden_store)).await;
        for id in ["conversation-hidden", "conversation-absent"] {
            let mut request = Request::new(pb::IntegrationGetConversationRequest {
                scope: Some(wire_scope()),
                conversation_id: Some(pb_id(id)),
            });
            attach_service_credential(&mut request, &hidden_credential, &hidden_secret);
            let response = hidden_client
                .get_conversation(request)
                .await
                .expect("unauthorized lookup is application response")
                .into_inner();
            let error = match response.result.expect("lookup result") {
                pb::integration_get_conversation_response::Result::Error(error) => error,
                pb::integration_get_conversation_response::Result::Conversation(_) => {
                    panic!("unauthorized lookup disclosed existence")
                }
            };
            assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        }
        hidden_server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn message_send_retry_get_preserves_opaque_mapping_and_service_principal_provenance() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                CONVERSATION_WRITE_PERMISSION,
                MESSAGE_WRITE_PERMISSION,
                MESSAGE_READ_PERMISSION,
            ],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;

        let mut create_conversation = Request::new(pb::IntegrationCreateConversationRequest {
            conversation: Some(conversation(
                "conversation-message-grpc",
                pb::ConversationKind::Direct,
            )),
        });
        attach_service_credential(&mut create_conversation, &credential_id, &secret);
        client
            .create_conversation(create_conversation)
            .await
            .expect("create conversation for message");

        let opaque_external = vec![0, 255, 128, 77, 1];
        let sent = message(
            "message-grpc",
            "conversation-message-grpc",
            b"hello over grpc",
            opaque_external.clone(),
        );
        for _ in 0..2 {
            let mut request = Request::new(pb::IntegrationSendMessageRequest {
                message: Some(sent.clone()),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .send_message(request)
                .await
                .expect("message send is application response")
                .into_inner();
            let acknowledgement = match response.result.expect("send result") {
                pb::integration_send_message_response::Result::Acknowledgement(value) => value,
                pb::integration_send_message_response::Result::Error(error) => {
                    panic!("message send failed: {error:?}")
                }
            };
            assert_eq!(acknowledgement.acknowledged_id, Some(pb_id("message-grpc")));
        }

        let mut lookup = Request::new(pb::IntegrationGetMessageRequest {
            scope: Some(wire_scope()),
            message_id: Some(pb_id("message-grpc")),
        });
        attach_service_credential(&mut lookup, &credential_id, &secret);
        let response = client
            .get_message(lookup)
            .await
            .expect("message get")
            .into_inner();
        let persisted = match response.result.expect("message result") {
            pb::integration_get_message_response::Result::Message(value) => value,
            pb::integration_get_message_response::Result::Error(error) => {
                panic!("message lookup failed: {error:?}")
            }
        };
        assert_eq!(persisted.content, b"hello over grpc");
        assert_eq!(
            persisted.external_mappings[0].external_message_id,
            opaque_external
        );
        assert_eq!(
            persisted.origin.expect("origin").principal_id,
            Some(pb_id("service-grpc"))
        );
        assert_eq!(
            persisted.delivery_state,
            pb::DeliveryState::Persisted as i32
        );

        let changed = message(
            "message-grpc",
            "conversation-message-grpc",
            b"different payload",
            vec![9],
        );
        let mut conflict = Request::new(pb::IntegrationSendMessageRequest {
            message: Some(changed),
        });
        attach_service_credential(&mut conflict, &credential_id, &secret);
        let response = client
            .send_message(conflict)
            .await
            .expect("message conflict response")
            .into_inner();
        let error = match response.result.expect("conflict result") {
            pb::integration_send_message_response::Result::Error(error) => error,
            pb::integration_send_message_response::Result::Acknowledgement(_) => {
                panic!("conflicting message accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::Conflict as i32);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn message_provenance_denial_creates_no_ghost_and_valid_retry_succeeds() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[CONVERSATION_WRITE_PERMISSION, MESSAGE_WRITE_PERMISSION],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let mut create_conversation = Request::new(pb::IntegrationCreateConversationRequest {
            conversation: Some(conversation(
                "conversation-provenance-grpc",
                pb::ConversationKind::Direct,
            )),
        });
        attach_service_credential(&mut create_conversation, &credential_id, &secret);
        client
            .create_conversation(create_conversation)
            .await
            .expect("create conversation");

        let mut denied = message(
            "message-provenance-grpc",
            "conversation-provenance-grpc",
            b"provenance",
            vec![1, 2, 3],
        );
        denied.origin.as_mut().expect("origin").principal_id = Some(pb_id("other-service"));
        let mut request = Request::new(pb::IntegrationSendMessageRequest {
            message: Some(denied),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .send_message(request)
            .await
            .expect("provenance denial response")
            .into_inner();
        let error = match response.result.expect("denial result") {
            pb::integration_send_message_response::Result::Error(error) => error,
            pb::integration_send_message_response::Result::Acknowledgement(_) => {
                panic!("provenance mismatch accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        assert!(
            store
                .message(
                    &scope(),
                    &ucr_model::MessageId::from_opaque(oid("message-provenance-grpc"))
                )
                .expect("read message owner")
                .is_none()
        );

        let mut valid = Request::new(pb::IntegrationSendMessageRequest {
            message: Some(message(
                "message-provenance-grpc",
                "conversation-provenance-grpc",
                b"provenance",
                vec![1, 2, 3],
            )),
        });
        attach_service_credential(&mut valid, &credential_id, &secret);
        let response = client
            .send_message(valid)
            .await
            .expect("valid retry")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_send_message_response::Result::Acknowledgement(_))
        ));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn message_reads_hide_existence_until_authorized_and_then_return_not_found() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[CONVERSATION_WRITE_PERMISSION, MESSAGE_WRITE_PERMISSION],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;

        let mut create_conversation = Request::new(pb::IntegrationCreateConversationRequest {
            conversation: Some(conversation(
                "conversation-read-hide-grpc",
                pb::ConversationKind::Direct,
            )),
        });
        attach_service_credential(&mut create_conversation, &credential_id, &secret);
        client
            .create_conversation(create_conversation)
            .await
            .expect("create conversation");
        let mut send = Request::new(pb::IntegrationSendMessageRequest {
            message: Some(message(
                "message-read-hide-grpc",
                "conversation-read-hide-grpc",
                b"hidden",
                vec![7, 8, 9],
            )),
        });
        attach_service_credential(&mut send, &credential_id, &secret);
        client
            .send_message(send)
            .await
            .expect("seed hidden message");

        for id in ["message-read-hide-grpc", "message-read-absent-grpc"] {
            let mut request = Request::new(pb::IntegrationGetMessageRequest {
                scope: Some(wire_scope()),
                message_id: Some(pb_id(id)),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .get_message(request)
                .await
                .expect("unauthorized read is application response")
                .into_inner();
            let error = match response.result.expect("read result") {
                pb::integration_get_message_response::Result::Error(error) => error,
                pb::integration_get_message_response::Result::Message(_) => {
                    panic!("unauthorized message read disclosed existence")
                }
            };
            assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        }

        store
            .grant_permission(&PermissionGrant {
                grantee: subject(),
                permission: MESSAGE_READ_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant message read");
        let mut missing = Request::new(pb::IntegrationGetMessageRequest {
            scope: Some(wire_scope()),
            message_id: Some(pb_id("message-read-absent-grpc")),
        });
        attach_service_credential(&mut missing, &credential_id, &secret);
        let response = client
            .get_message(missing)
            .await
            .expect("authorized missing read")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_get_message_response::Result::Error(error))
                if error.code == pb::ErrorCode::NotFound as i32
        ));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn communication_intent_create_retry_get_and_conflict_round_trip_over_grpc() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                COMMUNICATION_INTENT_WRITE_PERMISSION,
                COMMUNICATION_INTENT_READ_PERMISSION,
            ],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let created = intent("intent-grpc", &[0, 255, 128, 73, 1]);

        for _ in 0..2 {
            let mut request = Request::new(pb::IntegrationCreateCommunicationIntentRequest {
                intent: Some(created.clone()),
            });
            attach_service_credential(&mut request, &credential_id, &secret);
            let response = client
                .create_communication_intent(request)
                .await
                .expect("intent create")
                .into_inner();
            let acknowledgement = match response.result.expect("intent result") {
                pb::integration_create_communication_intent_response::Result::Acknowledgement(
                    value,
                ) => value,
                pb::integration_create_communication_intent_response::Result::Error(error) => {
                    panic!("intent create failed: {error:?}")
                }
            };
            assert_eq!(acknowledgement.acknowledged_id, Some(pb_id("intent-grpc")));
        }

        let mut lookup = Request::new(pb::IntegrationGetCommunicationIntentRequest {
            scope: Some(wire_scope()),
            intent_id: Some(pb_id("intent-grpc")),
        });
        attach_service_credential(&mut lookup, &credential_id, &secret);
        let response = client
            .get_communication_intent(lookup)
            .await
            .expect("intent get")
            .into_inner();
        let persisted = match response.result.expect("get result") {
            pb::integration_get_communication_intent_response::Result::Intent(value) => value,
            pb::integration_get_communication_intent_response::Result::Error(error) => {
                panic!("intent lookup failed: {error:?}")
            }
        };
        assert_eq!(persisted.payload, vec![0, 255, 128, 73, 1]);
        assert_eq!(persisted.constraints, created.constraints);
        assert_eq!(persisted.correlation, created.correlation);
        assert_eq!(persisted.extensions, created.extensions);

        let mut changed = created.clone();
        changed.payload = b"changed".to_vec();
        let mut conflict = Request::new(pb::IntegrationCreateCommunicationIntentRequest {
            intent: Some(changed),
        });
        attach_service_credential(&mut conflict, &credential_id, &secret);
        let response = client
            .create_communication_intent(conflict)
            .await
            .expect("intent conflict response")
            .into_inner();
        let error = match response.result.expect("conflict result") {
            pb::integration_create_communication_intent_response::Result::Error(error) => error,
            pb::integration_create_communication_intent_response::Result::Acknowledgement(_) => {
                panic!("conflicting intent accepted")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::Conflict as i32);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn communication_intent_reads_hide_existence_until_authorized() {
        let hidden_store = Arc::new(MemoryLocalStore::default());
        let (hidden_credential, hidden_secret) =
            seed_with_permissions(&hidden_store, &[COMMUNICATION_INTENT_WRITE_PERMISSION]);
        let (mut hidden_client, hidden_server) = client_and_server(Arc::clone(&hidden_store)).await;
        let mut create = Request::new(pb::IntegrationCreateCommunicationIntentRequest {
            intent: Some(intent("intent-hidden", b"hidden")),
        });
        attach_service_credential(&mut create, &hidden_credential, &hidden_secret);
        hidden_client
            .create_communication_intent(create)
            .await
            .expect("seed hidden intent");
        for id in ["intent-hidden", "intent-absent"] {
            let mut request = Request::new(pb::IntegrationGetCommunicationIntentRequest {
                scope: Some(wire_scope()),
                intent_id: Some(pb_id(id)),
            });
            attach_service_credential(&mut request, &hidden_credential, &hidden_secret);
            let response = hidden_client
                .get_communication_intent(request)
                .await
                .expect("unauthorized lookup")
                .into_inner();
            let error = match response.result.expect("lookup result") {
                pb::integration_get_communication_intent_response::Result::Error(error) => error,
                pb::integration_get_communication_intent_response::Result::Intent(_) => {
                    panic!("unauthorized intent lookup disclosed existence")
                }
            };
            assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        }
        hidden_server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_message_enum_is_invalid_argument_without_ghost_state() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(&store, &[MESSAGE_WRITE_PERMISSION]);
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;
        let mut malformed = message(
            "message-malformed-grpc",
            "conversation-malformed-message-grpc",
            b"bad enum",
            vec![1],
        );
        malformed.delivery_policy = 9_999;
        let mut request = Request::new(pb::IntegrationSendMessageRequest {
            message: Some(malformed),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .send_message(request)
            .await
            .expect("malformed message response")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_send_message_response::Result::Error(error))
                if error.code == pb::ErrorCode::InvalidArgument as i32
        ));
        assert!(
            store
                .message(
                    &scope(),
                    &ucr_model::MessageId::from_opaque(oid("message-malformed-grpc"))
                )
                .expect("message owner")
                .is_none()
        );
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_remaining_rpc_shapes_are_invalid_argument_without_ghost_state() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                CONVERSATION_WRITE_PERMISSION,
                MESSAGE_WRITE_PERMISSION,
                COMMUNICATION_INTENT_WRITE_PERMISSION,
            ],
        );
        let (mut client, server) = client_and_server(Arc::clone(&store)).await;

        let mut bad_conversation = conversation(
            "conversation-malformed-grpc",
            pb::ConversationKind::Unspecified,
        );
        bad_conversation
            .conversation
            .as_mut()
            .expect("conversation")
            .kind = 9_999;
        let mut request = Request::new(pb::IntegrationCreateConversationRequest {
            conversation: Some(bad_conversation),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .create_conversation(request)
            .await
            .expect("malformed conversation response")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_create_conversation_response::Result::Error(error))
                if error.code == pb::ErrorCode::InvalidArgument as i32
        ));
        assert!(
            store
                .conversation(
                    &scope(),
                    &ucr_model::ConversationId::from_opaque(oid("conversation-malformed-grpc"))
                )
                .expect("conversation owner")
                .is_none()
        );

        let mut malformed_intent = intent("intent-malformed-grpc", b"bad");
        malformed_intent.constraints = None;
        let mut request = Request::new(pb::IntegrationCreateCommunicationIntentRequest {
            intent: Some(malformed_intent),
        });
        attach_service_credential(&mut request, &credential_id, &secret);
        let response = client
            .create_communication_intent(request)
            .await
            .expect("malformed intent response")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::integration_create_communication_intent_response::Result::Error(error))
                if error.code == pb::ErrorCode::InvalidArgument as i32
        ));
        assert!(
            store
                .communication_intent(
                    &scope(),
                    &ucr_model::IntentId::from_opaque(oid("intent-malformed-grpc"))
                )
                .expect("intent owner")
                .is_none()
        );
        server.abort();
    }
    type EventGrpcClient = pb::event_service_client::EventServiceClient<tonic::transport::Channel>;

    async fn grpc_create_event_subscription(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        value: pb::EventSubscription,
    ) {
        let mut request = Request::new(pb::EventCreateSubscriptionRequest {
            subscription: Some(value),
        });
        attach_service_credential(&mut request, credential_id, secret);
        let response = client
            .create_subscription(request)
            .await
            .expect("create Event subscription transport")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::event_create_subscription_response::Result::Subscription(_))
        ));
    }

    async fn grpc_publish_event(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        value: pb::EventEnvelope,
    ) -> pb::EventPublishReceipt {
        let mut request = Request::new(pb::EventPublishRequest { event: Some(value) });
        attach_service_credential(&mut request, credential_id, secret);
        let response = client
            .publish_event(request)
            .await
            .expect("publish Event transport")
            .into_inner();
        match response.result.expect("publish Event result") {
            pb::event_publish_response::Result::Receipt(receipt) => receipt,
            pb::event_publish_response::Result::Error(error) => {
                panic!("unexpected Event publish error: {}", error.code)
            }
        }
    }

    async fn grpc_poll_event_subscription(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        subscription_id: &str,
    ) -> pb::EventPollResponse {
        let mut request = Request::new(pb::EventPollRequest {
            scope: Some(wire_scope()),
            subscription_id: Some(pb_id(subscription_id)),
            max_items: 1,
        });
        attach_service_credential(&mut request, credential_id, secret);
        client
            .poll_events(request)
            .await
            .expect("poll Event subscription transport")
            .into_inner()
    }

    fn require_event_batch(response: pb::EventPollResponse) -> pb::EventDeliveryBatch {
        match response.result.expect("Event poll result") {
            pb::event_poll_response::Result::Batch(batch) => batch,
            other => panic!("expected Event batch, got {other:?}"),
        }
    }

    async fn grpc_ack_event_batch(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        subscription_id: &str,
        cursor: pb::EventConsumerCursor,
    ) {
        let mut request = Request::new(pb::EventAcknowledgeRequest {
            scope: Some(wire_scope()),
            subscription_id: Some(pb_id(subscription_id)),
            cursor: Some(cursor),
        });
        attach_service_credential(&mut request, credential_id, secret);
        assert!(matches!(
            client
                .acknowledge_events(request)
                .await
                .expect("Event ack transport")
                .into_inner()
                .result,
            Some(pb::event_acknowledge_response::Result::Acknowledgement(_))
        ));
    }

    async fn grpc_reject_event_batch_permanently(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        subscription_id: &str,
        cursor: Option<pb::EventConsumerCursor>,
    ) {
        let mut request = Request::new(pb::EventRejectRequest {
            scope: Some(wire_scope()),
            subscription_id: Some(pb_id(subscription_id)),
            cursor,
            failure_kind: pb::EventDeliveryFailureKind::Permanent as i32,
        });
        attach_service_credential(&mut request, credential_id, secret);
        client
            .reject_events(request)
            .await
            .expect("permanent Event reject transport");
    }

    async fn grpc_event_dead_letters(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        subscription_id: &str,
    ) -> pb::EventDeadLetterList {
        let mut request = Request::new(pb::EventListDeadLettersRequest {
            scope: Some(wire_scope()),
            subscription_id: Some(pb_id(subscription_id)),
            max_items: 8,
        });
        attach_service_credential(&mut request, credential_id, secret);
        match client
            .list_dead_letters(request)
            .await
            .expect("Event DLQ list transport")
            .into_inner()
            .result
            .expect("Event DLQ list result")
        {
            pb::event_list_dead_letters_response::Result::DeadLetters(list) => list,
            pb::event_list_dead_letters_response::Result::Error(error) => {
                panic!("unexpected Event DLQ list error: {}", error.code)
            }
        }
    }

    async fn grpc_replay_event_subscription(
        client: &mut EventGrpcClient,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        subscription_id: &str,
        replay_id: &str,
    ) {
        let mut request = Request::new(pb::EventReplayRequest {
            scope: Some(wire_scope()),
            subscription_id: Some(pb_id(subscription_id)),
            replay_id: Some(pb_id(replay_id)),
        });
        attach_service_credential(&mut request, credential_id, secret);
        client
            .replay_subscription(request)
            .await
            .expect("Event replay transport");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_publish_poll_backpressure_ack_and_duplicate_round_trip_over_grpc() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                EVENT_APPEND_PERMISSION,
                EVENT_SUBSCRIBE_PERMISSION,
                EVENT_CONSUME_PERMISSION,
            ],
        );
        let (mut client, server) = event_client_and_server(store).await;
        grpc_create_event_subscription(
            &mut client,
            &credential_id,
            &secret,
            subscription("subscription-grpc", 3),
        )
        .await;

        let wire_event = event("event-grpc", b"event-payload");
        for expected in [
            pb::EventAppendResult::Appended,
            pb::EventAppendResult::Duplicate,
        ] {
            let receipt =
                grpc_publish_event(&mut client, &credential_id, &secret, wire_event.clone()).await;
            assert_eq!(receipt.result, expected as i32);
        }

        let first_batch = require_event_batch(
            grpc_poll_event_subscription(&mut client, &credential_id, &secret, "subscription-grpc")
                .await,
        );
        assert_eq!(first_batch.events.len(), 1);
        assert_eq!(first_batch.events[0].payload, b"event-payload");
        let first_cursor = first_batch.cursor.clone().expect("first cursor");
        let repeated_batch = require_event_batch(
            grpc_poll_event_subscription(&mut client, &credential_id, &secret, "subscription-grpc")
                .await,
        );
        assert_eq!(repeated_batch.cursor.as_ref(), Some(&first_cursor));
        assert_eq!(repeated_batch.attempt, first_batch.attempt);
        grpc_ack_event_batch(
            &mut client,
            &credential_id,
            &secret,
            "subscription-grpc",
            first_cursor,
        )
        .await;
        assert!(matches!(
            grpc_poll_event_subscription(
                &mut client,
                &credential_id,
                &secret,
                "subscription-grpc",
            )
            .await
            .result,
            Some(pb::event_poll_response::Result::Empty(_))
        ));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_permanent_reject_dead_letter_and_replay_round_trip_over_grpc() {
        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                EVENT_APPEND_PERMISSION,
                EVENT_SUBSCRIBE_PERMISSION,
                EVENT_CONSUME_PERMISSION,
                EVENT_REPLAY_PERMISSION,
                EVENT_DEAD_LETTER_READ_PERMISSION,
            ],
        );
        let (mut client, server) = event_client_and_server(store).await;
        grpc_create_event_subscription(
            &mut client,
            &credential_id,
            &secret,
            subscription("subscription-dlq-grpc", 4),
        )
        .await;
        grpc_publish_event(
            &mut client,
            &credential_id,
            &secret,
            event("event-dlq-grpc", b"dlq-payload"),
        )
        .await;
        let batch = require_event_batch(
            grpc_poll_event_subscription(
                &mut client,
                &credential_id,
                &secret,
                "subscription-dlq-grpc",
            )
            .await,
        );
        grpc_reject_event_batch_permanently(
            &mut client,
            &credential_id,
            &secret,
            "subscription-dlq-grpc",
            batch.cursor,
        )
        .await;
        let dead_letters = grpc_event_dead_letters(
            &mut client,
            &credential_id,
            &secret,
            "subscription-dlq-grpc",
        )
        .await;
        assert_eq!(dead_letters.dead_letters.len(), 1);
        assert_eq!(
            dead_letters.dead_letters[0].failure_kind,
            pb::EventDeliveryFailureKind::Permanent as i32
        );
        grpc_replay_event_subscription(
            &mut client,
            &credential_id,
            &secret,
            "subscription-dlq-grpc",
            "replay-dlq-grpc",
        )
        .await;
        let replayed_batch = require_event_batch(
            grpc_poll_event_subscription(
                &mut client,
                &credential_id,
                &secret,
                "subscription-dlq-grpc",
            )
            .await,
        );
        assert_eq!(replayed_batch.events.len(), 1);
        assert_eq!(replayed_batch.events[0].payload, b"dlq-payload");
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_permission_denial_hides_subscription_and_large_event_exceeds_tonic_default() {
        let hidden_store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) =
            seed_with_permissions(&hidden_store, &[EVENT_APPEND_PERMISSION]);
        let (mut hidden_client, hidden_server) = event_client_and_server(hidden_store).await;
        let mut hidden = Request::new(pb::EventGetSubscriptionRequest {
            scope: Some(wire_scope()),
            subscription_id: Some(pb_id("hidden-subscription")),
        });
        attach_service_credential(&mut hidden, &credential_id, &secret);
        let hidden = hidden_client
            .get_subscription(hidden)
            .await
            .expect("permission denial remains canonical response")
            .into_inner();
        let error = match hidden.result.expect("hidden result") {
            pb::event_get_subscription_response::Result::Error(error) => error,
            pb::event_get_subscription_response::Result::Subscription(_) => {
                panic!("unauthorized caller disclosed subscription")
            }
        };
        assert_eq!(error.code, pb::ErrorCode::PermissionDenied as i32);
        hidden_server.abort();

        let store = Arc::new(MemoryLocalStore::default());
        let (credential_id, secret) = seed_with_permissions(
            &store,
            &[
                EVENT_APPEND_PERMISSION,
                EVENT_SUBSCRIBE_PERMISSION,
                EVENT_CONSUME_PERMISSION,
            ],
        );
        let (mut client, server) = event_client_and_server(store).await;
        grpc_create_event_subscription(
            &mut client,
            &credential_id,
            &secret,
            subscription("subscription-five-mib", 2),
        )
        .await;
        let large_payload = vec![0x5a; 5 * 1024 * 1024];
        let mut publish = Request::new(pb::EventPublishRequest {
            event: Some(event("event-five-mib", &large_payload)),
        });
        attach_service_credential(&mut publish, &credential_id, &secret);
        let response = client
            .publish_event(publish)
            .await
            .expect("Event above Tonic default must pass")
            .into_inner();
        assert!(matches!(
            response.result,
            Some(pb::event_publish_response::Result::Receipt(_))
        ));
        let batch = require_event_batch(
            grpc_poll_event_subscription(
                &mut client,
                &credential_id,
                &secret,
                "subscription-five-mib",
            )
            .await,
        );
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].payload.len(), large_payload.len());
        assert_eq!(batch.events[0].payload, large_payload);
        server.abort();
    }
}

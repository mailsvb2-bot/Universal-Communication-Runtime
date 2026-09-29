use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_core::{
    AttachmentStore, AuthorizationEvaluator, DurableStoreError, ServiceAuditStore,
    ServiceCredentialStore, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_crypto::{MachineTokenPolicy, MachineTokenPublicKeySet};
use ucr_model::{
    AttachmentChunk, AttachmentContentId, AttachmentDescriptor, AttachmentId, ScopedPrincipal,
    TenantScope,
};
use ucr_protocol::{
    ATTACHMENT_CONTENT_HASH_LEN, ATTACHMENT_READ_PERMISSION, ATTACHMENT_WRITE_PERMISSION,
    AttachmentProtocolError, CanonicalError, CanonicalErrorCode, acknowledgement_for,
    validate_attachment_descriptor, verify_attachment_chunk, verify_complete_attachment,
};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_opaque, decode_scope,
    invalid_argument,
    machine_api_auth::{
        MachineApiAuthentication, MachineBearerConfig, admit_machine_api,
        decode_machine_api_authentication,
    },
    pb, pb_acknowledgement, pb_error, pb_opaque, pb_scope,
};

pub struct GrpcAttachmentService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    machine_bearer: Option<Arc<MachineBearerConfig>>,
}

impl<C, A, S> GrpcAttachmentService<C, A, S> {
    #[must_use]
    pub const fn new(clock: Arc<C>, authorization: Arc<A>, store: Arc<S>) -> Self {
        Self {
            clock,
            authorization,
            store,
            machine_bearer: None,
        }
    }

    #[must_use]
    pub fn with_machine_bearer_auth(
        mut self,
        verification_keys: Arc<MachineTokenPublicKeySet>,
        policy: MachineTokenPolicy,
    ) -> Self {
        self.machine_bearer = Some(Arc::new(MachineBearerConfig::static_keys(
            verification_keys,
            policy,
        )));
        self
    }

    #[must_use]
    pub fn with_machine_bearer_auth_provider(
        mut self,
        provider: Arc<dyn super::MachineTokenVerificationKeyProvider>,
        policy: MachineTokenPolicy,
    ) -> Self {
        self.machine_bearer = Some(Arc::new(MachineBearerConfig::provider(provider, policy)));
        self
    }
}

impl<C, A, S> Clone for GrpcAttachmentService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            machine_bearer: self.machine_bearer.as_ref().map(Arc::clone),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcAttachmentService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcAttachmentService")
            .finish_non_exhaustive()
    }
}

impl<C, A, S> GrpcAttachmentService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    fn admit(
        &self,
        scope: &TenantScope,
        authentication: MachineApiAuthentication,
        permission: &str,
    ) -> Result<ScopedPrincipal, CanonicalError> {
        admit_machine_api(
            &*self.clock,
            &*self.authorization,
            &*self.store,
            self.machine_bearer.as_deref(),
            scope,
            authentication,
            permission,
        )
    }
}

#[must_use]
pub fn attachment_service_server<C, A, S>(
    service: GrpcAttachmentService<C, A, S>,
) -> pb::attachment_service_server::AttachmentServiceServer<GrpcAttachmentService<C, A, S>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + AttachmentStore
        + 'static,
{
    pb::attachment_service_server::AttachmentServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S> pb::attachment_service_server::AttachmentService for GrpcAttachmentService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + AttachmentStore
        + 'static,
{
    async fn register_attachment(
        &self,
        request: Request<pb::AttachmentRegisterRequest>,
    ) -> Result<Response<pb::AttachmentRegisterResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded = body
            .attachment
            .ok_or_else(invalid_argument)
            .and_then(decode_attachment_descriptor);
        let result = match (authentication, decoded) {
            (Ok(authentication), Ok(attachment)) => self
                .admit(&attachment.scope, authentication, ATTACHMENT_WRITE_PERMISSION)
                .and_then(|_| {
                    self.store
                        .persist_attachment_descriptor(&attachment)
                        .map_err(map_store_error)?;
                    self.store
                        .attachment_descriptor(&attachment.scope, &attachment.attachment_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::AttachmentRegisterResponse {
            result: Some(match result {
                Ok(attachment) => {
                    pb::attachment_register_response::Result::Attachment(pb_attachment_descriptor(
                        &attachment,
                    ))
                }
                Err(error) => pb::attachment_register_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_attachment(
        &self,
        request: Request<pb::AttachmentGetRequest>,
    ) -> Result<Response<pb::AttachmentGetResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded = decode_attachment_lookup(body.scope, body.attachment_id);
        let result = match (authentication, decoded) {
            (Ok(authentication), Ok((scope, attachment_id))) => self
                .admit(&scope, authentication, ATTACHMENT_READ_PERMISSION)
                .and_then(|_| {
                    self.store
                        .attachment_descriptor(&scope, &attachment_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::AttachmentGetResponse {
            result: Some(match result {
                Ok(attachment) => {
                    pb::attachment_get_response::Result::Attachment(pb_attachment_descriptor(
                        &attachment,
                    ))
                }
                Err(error) => pb::attachment_get_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn put_chunk(
        &self,
        request: Request<pb::AttachmentPutChunkRequest>,
    ) -> Result<Response<pb::AttachmentPutChunkResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let scope = body
            .scope
            .ok_or_else(invalid_argument)
            .and_then(decode_scope);
        let chunk = body.chunk.ok_or_else(invalid_argument).and_then(decode_attachment_chunk);
        let result = match (authentication, scope, chunk) {
            (Ok(authentication), Ok(scope), Ok(chunk)) => self
                .admit(&scope, authentication, ATTACHMENT_WRITE_PERMISSION)
                .and_then(|_| {
                    let descriptor = self
                        .store
                        .attachment_descriptor(&scope, &chunk.attachment_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
                    verify_attachment_chunk(&descriptor, &chunk).map_err(map_attachment_error)?;
                    self.store
                        .persist_attachment_chunk(&scope, &chunk)
                        .map_err(map_store_error)?;
                    Ok(acknowledgement_for(
                        chunk.attachment_id.as_opaque().clone(),
                    ))
                }),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::AttachmentPutChunkResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::attachment_put_chunk_response::Result::Acknowledgement(
                        pb_acknowledgement(acknowledgement),
                    )
                }
                Err(error) => pb::attachment_put_chunk_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_chunk(
        &self,
        request: Request<pb::AttachmentGetChunkRequest>,
    ) -> Result<Response<pb::AttachmentGetChunkResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded = decode_attachment_lookup(body.scope, body.attachment_id);
        let result = match (authentication, decoded) {
            (Ok(authentication), Ok((scope, attachment_id))) => self
                .admit(&scope, authentication, ATTACHMENT_READ_PERMISSION)
                .and_then(|_| {
                    self.store
                        .attachment_chunk(&scope, &attachment_id, body.index)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::AttachmentGetChunkResponse {
            result: Some(match result {
                Ok(chunk) => {
                    pb::attachment_get_chunk_response::Result::Chunk(pb_attachment_chunk(&chunk))
                }
                Err(error) => pb::attachment_get_chunk_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn verify_attachment(
        &self,
        request: Request<pb::AttachmentVerifyRequest>,
    ) -> Result<Response<pb::AttachmentVerifyResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded = decode_attachment_lookup(body.scope, body.attachment_id);
        let result = match (authentication, decoded) {
            (Ok(authentication), Ok((scope, attachment_id))) => self
                .admit(&scope, authentication, ATTACHMENT_READ_PERMISSION)
                .and_then(|_| {
                    self.verify_complete_from_store(&scope, &attachment_id)?;
                    Ok(attachment_id)
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::AttachmentVerifyResponse {
            result: Some(match result {
                Ok(attachment_id) => pb::attachment_verify_response::Result::Acknowledgement(
                    pb_acknowledgement(acknowledgement_for(
                        attachment_id.as_opaque().clone(),
                    )),
                ),
                Err(error) => pb::attachment_verify_response::Result::Error(pb_error(error)),
            }),
        }))
    }
}

impl<C, A, S> GrpcAttachmentService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + AttachmentStore,
{
    fn verify_complete_from_store(
        &self,
        scope: &TenantScope,
        attachment_id: &AttachmentId,
    ) -> Result<(), CanonicalError> {
        let descriptor = self
            .store
            .attachment_descriptor(scope, attachment_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;

        let mut next_index = 0_u32;
        let mut store_error = None;
        let chunks = std::iter::from_fn(|| {
            if next_index >= descriptor.chunk_count || store_error.is_some() {
                return None;
            }
            let index = next_index;
            match self.store.attachment_chunk(scope, attachment_id, index) {
                Ok(Some(chunk)) => {
                    next_index += 1;
                    Some(chunk)
                }
                Ok(None) => None,
                Err(error) => {
                    store_error = Some(error);
                    None
                }
            }
        });
        let verification = verify_complete_attachment(&descriptor, chunks);
        if let Some(error) = store_error {
            return Err(map_store_error(error));
        }
        verification.map_err(map_attachment_error)
    }
}

fn decode_attachment_lookup(
    scope: Option<pb::TenantScope>,
    attachment_id: Option<pb::OpaqueId>,
) -> Result<(TenantScope, AttachmentId), CanonicalError> {
    Ok((
        decode_scope(scope.ok_or_else(invalid_argument)?)?,
        AttachmentId::from_opaque(decode_opaque(attachment_id)?),
    ))
}

fn decode_attachment_descriptor(
    value: pb::AttachmentDescriptor,
) -> Result<AttachmentDescriptor, CanonicalError> {
    let content_id = value.content_id.ok_or_else(invalid_argument)?;
    let sha256: [u8; ATTACHMENT_CONTENT_HASH_LEN] = content_id
        .sha256
        .try_into()
        .map_err(|_| invalid_argument())?;
    let descriptor = AttachmentDescriptor {
        attachment_id: AttachmentId::from_opaque(decode_opaque(value.attachment_id)?),
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        content_id: AttachmentContentId { sha256 },
        size_bytes: value.size_bytes,
        chunk_size_bytes: value.chunk_size_bytes,
        chunk_count: value.chunk_count,
        media_type: value.media_type,
        file_name: value.file_name,
    };
    validate_attachment_descriptor(&descriptor).map_err(map_attachment_error)?;
    Ok(descriptor)
}

fn decode_attachment_chunk(value: pb::AttachmentChunk) -> Result<AttachmentChunk, CanonicalError> {
    let sha256: [u8; ATTACHMENT_CONTENT_HASH_LEN] =
        value.sha256.try_into().map_err(|_| invalid_argument())?;
    Ok(AttachmentChunk {
        attachment_id: AttachmentId::from_opaque(decode_opaque(value.attachment_id)?),
        index: value.index,
        offset_bytes: value.offset_bytes,
        bytes: value.payload,
        sha256,
    })
}

fn pb_attachment_descriptor(value: &AttachmentDescriptor) -> pb::AttachmentDescriptor {
    pb::AttachmentDescriptor {
        attachment_id: Some(pb_opaque(value.attachment_id.as_opaque())),
        scope: Some(pb_scope(&value.scope)),
        content_id: Some(pb::AttachmentContentId {
            sha256: value.content_id.sha256.to_vec(),
        }),
        size_bytes: value.size_bytes,
        chunk_size_bytes: value.chunk_size_bytes,
        chunk_count: value.chunk_count,
        media_type: value.media_type.clone(),
        file_name: value.file_name.clone(),
    }
}

fn pb_attachment_chunk(value: &AttachmentChunk) -> pb::AttachmentChunk {
    pb::AttachmentChunk {
        attachment_id: Some(pb_opaque(value.attachment_id.as_opaque())),
        index: value.index,
        offset_bytes: value.offset_bytes,
        payload: value.bytes.clone(),
        sha256: value.sha256.to_vec(),
    }
}

fn map_attachment_error(error: AttachmentProtocolError) -> CanonicalError {
    let code = match error {
        AttachmentProtocolError::ChunkIntegrityMismatch
        | AttachmentProtocolError::ContentIntegrityMismatch => CanonicalErrorCode::IntegrityFailure,
        AttachmentProtocolError::MissingOrDuplicateChunk => CanonicalErrorCode::Conflict,
        AttachmentProtocolError::AttachmentTooLarge
        | AttachmentProtocolError::InvalidChunkSize
        | AttachmentProtocolError::InvalidChunkCount
        | AttachmentProtocolError::InvalidMediaType
        | AttachmentProtocolError::InvalidFileName
        | AttachmentProtocolError::WrongAttachment
        | AttachmentProtocolError::InvalidChunkIndex
        | AttachmentProtocolError::InvalidChunkOffset
        | AttachmentProtocolError::InvalidChunkLength => CanonicalErrorCode::InvalidArgument,
    };
    CanonicalError::new(code)
}

fn map_store_error(error: DurableStoreError) -> CanonicalError {
    let code = match error {
        DurableStoreError::InvalidRecord => CanonicalErrorCode::InvalidArgument,
        DurableStoreError::Conflict => CanonicalErrorCode::Conflict,
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::Corrupt => CanonicalErrorCode::IntegrityFailure,
        DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

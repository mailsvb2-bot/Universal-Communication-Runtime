use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, DurableStoreError, ServiceAuditStore, ServiceCredentialSecret,
    ServiceCredentialStore, ServicePrincipalRequestGate, ServiceQuotaClock, ServiceQuotaStore,
    UniversalConferenceStore, generate_opaque_id,
};
use ucr_model::{
    AuthorizationRequest, ConferenceScheduleMetadata, GroupId, IntegrationId, ScopedPrincipal,
    TenantScope, UniversalConferenceLifecycle, UniversalConferenceMode, UniversalConferenceProfile,
};
use ucr_protocol::{
    CONFERENCE_CREATE_PERMISSION, CONFERENCE_READ_PERMISSION, CanonicalError, CanonicalErrorCode,
};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_opaque, decode_scope, invalid_argument, pb, pb_error, pb_opaque, pb_scope,
};

const MAX_EXTERNAL_CONFERENCE_ID_BYTES: usize = 512;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_TIMEZONE_BYTES: usize = 128;
const MAX_JOIN_WINDOW_SECONDS: u32 = 31_536_000;

pub struct GrpcUniversalConferenceService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
}

impl<C, A, S> GrpcUniversalConferenceService<C, A, S> {
    #[must_use]
    pub const fn new(clock: Arc<C>, authorization: Arc<A>, store: Arc<S>) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }
}

impl<C, A, S> Clone for GrpcUniversalConferenceService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcUniversalConferenceService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcUniversalConferenceService")
            .finish_non_exhaustive()
    }
}

impl<C, A, S> GrpcUniversalConferenceService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    fn admit(
        &self,
        scope: &TenantScope,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        permission: &str,
    ) -> Result<ScopedPrincipal, CanonicalError> {
        let gate =
            ServicePrincipalRequestGate::new(&*self.clock, &*self.authorization, &*self.store);
        let admission =
            gate.authenticate_request(scope, credential_id, secret, permission, scope)?;
        let actor = admission.subject().clone();
        admission.authorize(&AuthorizationRequest {
            subject: actor.clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        })?;
        Ok(actor)
    }
}

#[must_use]
pub fn universal_conference_service_server<C, A, S>(
    service: GrpcUniversalConferenceService<C, A, S>,
) -> pb::universal_conference_service_server::UniversalConferenceServiceServer<
    GrpcUniversalConferenceService<C, A, S>,
>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + UniversalConferenceStore
        + 'static,
{
    pb::universal_conference_service_server::UniversalConferenceServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S> pb::universal_conference_service_server::UniversalConferenceService
    for GrpcUniversalConferenceService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + UniversalConferenceStore
        + 'static,
{
    async fn create_conference(
        &self,
        request: Request<pb::UniversalCreateConferenceRequest>,
    ) -> Result<Response<pb::UniversalCreateConferenceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_create(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit(
                    &input.scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_CREATE_PERMISSION,
                )
                .and_then(|_| create_or_resolve(&*self.store, input)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::UniversalCreateConferenceResponse {
            result: Some(match result {
                Ok(conference) => {
                    pb::universal_create_conference_response::Result::Conference(
                        pb_conference(&conference),
                    )
                }
                Err(error) => {
                    pb::universal_create_conference_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn resolve_conference(
        &self,
        request: Request<pb::UniversalResolveConferenceRequest>,
    ) -> Result<Response<pb::UniversalResolveConferenceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_resolve(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, integration_id, external_id))) => self
                .admit(
                    &scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_READ_PERMISSION,
                )
                .and_then(|_| {
                    self.store
                        .universal_conference_profile_for_external(
                            &scope,
                            &integration_id,
                            &external_id,
                        )
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::UniversalResolveConferenceResponse {
            result: Some(match result {
                Ok(conference) => {
                    pb::universal_resolve_conference_response::Result::Conference(
                        pb_conference(&conference),
                    )
                }
                Err(error) => {
                    pb::universal_resolve_conference_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn transition_conference(
        &self,
        _request: Request<pb::UniversalConferenceLifecycleRequest>,
    ) -> Result<Response<pb::UniversalConferenceLifecycleResponse>, Status> {
        Ok(Response::new(pb::UniversalConferenceLifecycleResponse {
            result: Some(
                pb::universal_conference_lifecycle_response::Result::Error(unsupported()),
            ),
        }))
    }

    async fn set_entry_open(
        &self,
        _request: Request<pb::UniversalSetEntryOpenRequest>,
    ) -> Result<Response<pb::UniversalSetEntryOpenResponse>, Status> {
        Ok(Response::new(pb::UniversalSetEntryOpenResponse {
            result: Some(pb::universal_set_entry_open_response::Result::Error(
                unsupported(),
            )),
        }))
    }

    async fn ensure_participant(
        &self,
        _request: Request<pb::UniversalEnsureParticipantRequest>,
    ) -> Result<Response<pb::UniversalEnsureParticipantResponse>, Status> {
        Ok(Response::new(pb::UniversalEnsureParticipantResponse {
            result: Some(pb::universal_ensure_participant_response::Result::Error(
                unsupported(),
            )),
        }))
    }

    async fn update_participant(
        &self,
        _request: Request<pb::UniversalUpdateParticipantRequest>,
    ) -> Result<Response<pb::UniversalUpdateParticipantResponse>, Status> {
        Ok(Response::new(pb::UniversalUpdateParticipantResponse {
            result: Some(pb::universal_update_participant_response::Result::Error(
                unsupported(),
            )),
        }))
    }

    async fn remove_participant(
        &self,
        _request: Request<pb::UniversalRemoveParticipantRequest>,
    ) -> Result<Response<pb::UniversalRemoveParticipantResponse>, Status> {
        Ok(Response::new(pb::UniversalRemoveParticipantResponse {
            result: Some(pb::universal_remove_participant_response::Result::Error(
                unsupported(),
            )),
        }))
    }

    async fn list_participants(
        &self,
        _request: Request<pb::UniversalListParticipantsRequest>,
    ) -> Result<Response<pb::UniversalListParticipantsResponse>, Status> {
        Ok(Response::new(pb::UniversalListParticipantsResponse {
            result: Some(pb::universal_list_participants_response::Result::Error(
                unsupported(),
            )),
        }))
    }

    async fn issue_join_grant(
        &self,
        _request: Request<pb::UniversalIssueJoinGrantRequest>,
    ) -> Result<Response<pb::UniversalIssueJoinGrantResponse>, Status> {
        Ok(Response::new(pb::UniversalIssueJoinGrantResponse {
            result: Some(pb::universal_issue_join_grant_response::Result::Error(
                unsupported(),
            )),
        }))
    }

    async fn revoke_join_grant(
        &self,
        _request: Request<pb::UniversalRevokeJoinGrantRequest>,
    ) -> Result<Response<pb::UniversalRevokeJoinGrantResponse>, Status> {
        Ok(Response::new(pb::UniversalRevokeJoinGrantResponse {
            result: Some(pb::universal_revoke_join_grant_response::Result::Error(
                unsupported(),
            )),
        }))
    }
}

struct CreateInput {
    scope: TenantScope,
    integration_id: IntegrationId,
    external_conference_id: Vec<u8>,
    idempotency_key: String,
    mode: UniversalConferenceMode,
    schedule: ConferenceScheduleMetadata,
}

fn decode_create(value: pb::UniversalCreateConferenceRequest) -> Result<CreateInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_external_id(&value.external_conference_id)?;
    validate_idempotency_key(&value.idempotency_key)?;
    let mode = decode_mode(value.mode)?;
    let schedule = decode_schedule(value.schedule.ok_or_else(invalid_argument)?)?;
    Ok(CreateInput {
        scope,
        integration_id,
        external_conference_id: value.external_conference_id,
        idempotency_key: value.idempotency_key,
        mode,
        schedule,
    })
}

fn decode_resolve(
    value: pb::UniversalResolveConferenceRequest,
) -> Result<(TenantScope, IntegrationId, Vec<u8>), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_external_id(&value.external_conference_id)?;
    Ok((scope, integration_id, value.external_conference_id))
}

fn decode_mode(value: i32) -> Result<UniversalConferenceMode, CanonicalError> {
    match pb::UniversalConferenceMode::try_from(value).map_err(|_| invalid_argument())? {
        pb::UniversalConferenceMode::Unspecified => Err(invalid_argument()),
        pb::UniversalConferenceMode::Meeting => Ok(UniversalConferenceMode::Meeting),
        pb::UniversalConferenceMode::Webinar => Ok(UniversalConferenceMode::Webinar),
        pb::UniversalConferenceMode::Broadcast => Ok(UniversalConferenceMode::Broadcast),
        pb::UniversalConferenceMode::AudioRoom => Ok(UniversalConferenceMode::AudioRoom),
    }
}

fn decode_schedule(
    value: pb::ConferenceScheduleMetadata,
) -> Result<ConferenceScheduleMetadata, CanonicalError> {
    if value
        .planned_end_unix_ms
        .is_some_and(|end| end < value.starts_at_unix_ms)
        || value.join_before_seconds > MAX_JOIN_WINDOW_SECONDS
        || value.join_after_seconds > MAX_JOIN_WINDOW_SECONDS
        || value
            .timezone
            .as_ref()
            .is_some_and(|timezone| timezone.is_empty() || timezone.len() > MAX_TIMEZONE_BYTES)
    {
        return Err(invalid_argument());
    }
    Ok(ConferenceScheduleMetadata {
        starts_at_unix_ms: value.starts_at_unix_ms,
        planned_end_unix_ms: value.planned_end_unix_ms,
        join_before_seconds: value.join_before_seconds,
        join_after_seconds: value.join_after_seconds,
        timezone: value.timezone,
    })
}

fn create_or_resolve<S: UniversalConferenceStore>(
    store: &S,
    input: CreateInput,
) -> Result<UniversalConferenceProfile, CanonicalError> {
    if let Some(existing) = store
        .universal_conference_profile_for_external(
            &input.scope,
            &input.integration_id,
            &input.external_conference_id,
        )
        .map_err(map_store_error)?
    {
        if existing.integration_id == input.integration_id
            && existing.external_conference_id == input.external_conference_id
            && existing.create_idempotency_key == input.idempotency_key
            && existing.mode == input.mode
            && existing.schedule == input.schedule
        {
            return Ok(existing);
        }
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }

    let conference_id = GroupId::from_opaque(
        generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let profile = UniversalConferenceProfile {
        scope: input.scope,
        conference_id,
        integration_id: input.integration_id,
        external_conference_id: input.external_conference_id,
        create_idempotency_key: input.idempotency_key,
        mode: input.mode,
        lifecycle: UniversalConferenceLifecycle::Scheduled,
        schedule: input.schedule,
        entry_open: false,
        revision: 1,
    };
    store
        .persist_universal_conference_profile(&profile)
        .map_err(map_store_error)?;
    Ok(profile)
}

fn pb_conference(value: &UniversalConferenceProfile) -> pb::UniversalConferenceDescriptor {
    pb::UniversalConferenceDescriptor {
        scope: Some(pb_scope(&value.scope)),
        conference_id: Some(pb_opaque(value.conference_id.as_opaque())),
        integration_id: Some(pb_opaque(value.integration_id.as_opaque())),
        external_conference_id: value.external_conference_id.clone(),
        mode: (match value.mode {
            UniversalConferenceMode::Meeting => pb::UniversalConferenceMode::Meeting,
            UniversalConferenceMode::Webinar => pb::UniversalConferenceMode::Webinar,
            UniversalConferenceMode::Broadcast => pb::UniversalConferenceMode::Broadcast,
            UniversalConferenceMode::AudioRoom => pb::UniversalConferenceMode::AudioRoom,
        }) as i32,
        lifecycle: (match value.lifecycle {
            UniversalConferenceLifecycle::Scheduled => {
                pb::UniversalConferenceLifecycle::Scheduled
            }
            UniversalConferenceLifecycle::Waiting => pb::UniversalConferenceLifecycle::Waiting,
            UniversalConferenceLifecycle::Live => pb::UniversalConferenceLifecycle::Live,
            UniversalConferenceLifecycle::Ending => pb::UniversalConferenceLifecycle::Ending,
            UniversalConferenceLifecycle::Ended => pb::UniversalConferenceLifecycle::Ended,
        }) as i32,
        schedule: Some(pb::ConferenceScheduleMetadata {
            starts_at_unix_ms: value.schedule.starts_at_unix_ms,
            planned_end_unix_ms: value.schedule.planned_end_unix_ms,
            join_before_seconds: value.schedule.join_before_seconds,
            join_after_seconds: value.schedule.join_after_seconds,
            timezone: value.schedule.timezone.clone(),
        }),
        entry_open: value.entry_open,
        revision: value.revision,
    }
}

fn validate_external_id(value: &[u8]) -> Result<(), CanonicalError> {
    if value.is_empty() || value.len() > MAX_EXTERNAL_CONFERENCE_ID_BYTES {
        Err(invalid_argument())
    } else {
        Ok(())
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), CanonicalError> {
    if value.is_empty()
        || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || value.chars().any(char::is_control)
    {
        Err(invalid_argument())
    } else {
        Ok(())
    }
}

fn unsupported() -> pb::ErrorEnvelope {
    pb_error(CanonicalError::new(CanonicalErrorCode::CapabilityMismatch))
}

fn map_store_error(error: DurableStoreError) -> CanonicalError {
    let code = match error {
        DurableStoreError::InvalidRecord => CanonicalErrorCode::InvalidArgument,
        DurableStoreError::Conflict => CanonicalErrorCode::Conflict,
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

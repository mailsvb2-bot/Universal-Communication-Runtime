use std::{fmt, sync::Arc};

use prost::Message;
use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, CommandAcceptanceStore, DurableStoreError,
    ExternalIdentityBindingStore, GroupCallLookupStore, IdentityDeviceLookupStore, IdentityStore,
    PrincipalIdentityBindingStore, PrincipalIdentityLookupStore, ServiceAuditStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServicePrincipalRequestGate,
    ServiceQuotaClock, ServiceQuotaStore, UniversalConferenceStore, generate_opaque_id,
};
use ucr_model::{
    AuthorizationRequest, CallParticipantState, CallSignallingState, CommandEnvelope, CommandId,
    ConferenceParticipantRole, ConferenceScheduleMetadata, CorrelationContext,
    DeviceLifecycleState, ExternalIdentityBinding, GroupId, IdentityEvidence, IdentityId,
    IdentityOwnership, IdentityRecord, IntegrationId, OpaqueId, PrincipalId,
    PrincipalIdentityBinding, PrincipalKind, PrincipalRef, ProtocolVersion, ScopedPrincipal,
    SessionId, TenantScope, UniversalConferenceLifecycle, UniversalConferenceMode,
    UniversalConferenceParticipantProfile, UniversalConferenceProfile,
};
use ucr_protocol::{
    CONFERENCE_CREATE_PERMISSION, CONFERENCE_JOIN_ISSUE_PERMISSION, CONFERENCE_MANAGE_PERMISSION,
    CONFERENCE_PARTICIPANT_ENSURE_PERMISSION, CONFERENCE_PARTICIPANT_MANAGE_PERMISSION,
    CONFERENCE_READ_PERMISSION, CanonicalError, CanonicalErrorCode, CommandReceiptStatus,
    acknowledgement_for,
};
use ucr_realtime::{
    JoinGrantUsePolicy as RealtimeJoinGrantUsePolicy, JoinTokenError, JoinTokenIssuer,
};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_credentials,
    decode_opaque, decode_scope, invalid_argument, pb, pb_acknowledgement, pb_error, pb_opaque,
    pb_scope,
};

const MAX_EXTERNAL_CONFERENCE_ID_BYTES: usize = 512;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_TIMEZONE_BYTES: usize = 128;
const MAX_JOIN_WINDOW_SECONDS: u32 = 31_536_000;

pub struct GrpcUniversalConferenceService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    join_issuer: Option<Arc<JoinTokenIssuer>>,
}

impl<C, A, S> GrpcUniversalConferenceService<C, A, S> {
    #[must_use]
    pub const fn new(clock: Arc<C>, authorization: Arc<A>, store: Arc<S>) -> Self {
        Self {
            clock,
            authorization,
            store,
            join_issuer: None,
        }
    }

    #[must_use]
    pub const fn with_join_issuer(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        join_issuer: Arc<JoinTokenIssuer>,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            join_issuer: Some(join_issuer),
        }
    }
}

impl<C, A, S> Clone for GrpcUniversalConferenceService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            join_issuer: self.join_issuer.as_ref().map(Arc::clone),
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
        + CommandAcceptanceStore
        + IdentityStore
        + ExternalIdentityBindingStore
        + PrincipalIdentityBindingStore
        + PrincipalIdentityLookupStore
        + IdentityDeviceLookupStore
        + GroupCallLookupStore
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
        + CommandAcceptanceStore
        + IdentityStore
        + ExternalIdentityBindingStore
        + PrincipalIdentityBindingStore
        + PrincipalIdentityLookupStore
        + IdentityDeviceLookupStore
        + GroupCallLookupStore
        + 'static,
{
    async fn create_conference(
        &self,
        request: Request<pb::UniversalCreateConferenceRequest>,
    ) -> Result<Response<pb::UniversalCreateConferenceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let command_payload = body.encode_to_vec();
        let decoded = decode_create(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit(
                    &input.scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_CREATE_PERMISSION,
                )
                .and_then(|_| create_or_resolve(&*self.store, input, command_payload)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };

        Ok(Response::new(pb::UniversalCreateConferenceResponse {
            result: Some(match result {
                Ok(conference) => pb::universal_create_conference_response::Result::Conference(
                    pb_conference(&conference),
                ),
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
                .admit(&scope, &credential_id, &secret, CONFERENCE_READ_PERMISSION)
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
                Ok(conference) => pb::universal_resolve_conference_response::Result::Conference(
                    pb_conference(&conference),
                ),
                Err(error) => {
                    pb::universal_resolve_conference_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn transition_conference(
        &self,
        request: Request<pb::UniversalConferenceLifecycleRequest>,
    ) -> Result<Response<pb::UniversalConferenceLifecycleResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_lifecycle_request(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, conference_id, target, idempotency_key))) => {
                self.admit(
                    &scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_MANAGE_PERMISSION,
                )
                .and_then(|_| {
                    accept_mutation(
                        &*self.store,
                        &scope,
                        "ucr.conference.lifecycle.v1",
                        &idempotency_key,
                        payload,
                    )?;
                    let current = self
                        .store
                        .universal_conference_profile(&scope, &conference_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
                    if current.lifecycle == target {
                        return Ok(current);
                    }
                    self.store
                        .transition_universal_conference(
                            &scope,
                            &conference_id,
                            current.revision,
                            target,
                            current.entry_open,
                        )
                        .map_err(map_store_error)
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalConferenceLifecycleResponse {
            result: Some(match result {
                Ok(conference) => pb::universal_conference_lifecycle_response::Result::Conference(
                    pb_conference(&conference),
                ),
                Err(error) => {
                    pb::universal_conference_lifecycle_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn set_entry_open(
        &self,
        request: Request<pb::UniversalSetEntryOpenRequest>,
    ) -> Result<Response<pb::UniversalSetEntryOpenResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_entry_request(body);
        let result = match (credentials, decoded) {
            (
                Ok((credential_id, secret)),
                Ok((scope, conference_id, entry_open, idempotency_key)),
            ) => self
                .admit(
                    &scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_MANAGE_PERMISSION,
                )
                .and_then(|_| {
                    accept_mutation(
                        &*self.store,
                        &scope,
                        "ucr.conference.entry.v1",
                        &idempotency_key,
                        payload,
                    )?;
                    let current = self
                        .store
                        .universal_conference_profile(&scope, &conference_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
                    if current.entry_open == entry_open {
                        return Ok(current);
                    }
                    self.store
                        .transition_universal_conference(
                            &scope,
                            &conference_id,
                            current.revision,
                            current.lifecycle,
                            entry_open,
                        )
                        .map_err(map_store_error)
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalSetEntryOpenResponse {
            result: Some(match result {
                Ok(conference) => pb::universal_set_entry_open_response::Result::Conference(
                    pb_conference(&conference),
                ),
                Err(error) => pb::universal_set_entry_open_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn ensure_participant(
        &self,
        request: Request<pb::UniversalEnsureParticipantRequest>,
    ) -> Result<Response<pb::UniversalEnsureParticipantResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_ensure_participant(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit(
                    &input.scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_PARTICIPANT_ENSURE_PERMISSION,
                )
                .and_then(|_| ensure_participant(&*self.store, input, payload)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalEnsureParticipantResponse {
            result: Some(match result {
                Ok(participant) => pb::universal_ensure_participant_response::Result::Participant(
                    pb_participant(&participant),
                ),
                Err(error) => {
                    pb::universal_ensure_participant_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn update_participant(
        &self,
        request: Request<pb::UniversalUpdateParticipantRequest>,
    ) -> Result<Response<pb::UniversalUpdateParticipantResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_update_participant(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit(
                    &input.scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_PARTICIPANT_MANAGE_PERMISSION,
                )
                .and_then(|_| update_participant(&*self.store, input, payload)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalUpdateParticipantResponse {
            result: Some(match result {
                Ok(participant) => pb::universal_update_participant_response::Result::Participant(
                    pb_participant(&participant),
                ),
                Err(error) => {
                    pb::universal_update_participant_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn remove_participant(
        &self,
        request: Request<pb::UniversalRemoveParticipantRequest>,
    ) -> Result<Response<pb::UniversalRemoveParticipantResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_remove_participant(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit(
                    &input.scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_PARTICIPANT_MANAGE_PERMISSION,
                )
                .and_then(|_| remove_participant(&*self.store, input, payload)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalRemoveParticipantResponse {
            result: Some(match result {
                Ok(command_id) => {
                    pb::universal_remove_participant_response::Result::Acknowledgement(
                        pb_acknowledgement(acknowledgement_for(command_id.as_opaque().clone())),
                    )
                }
                Err(error) => {
                    pb::universal_remove_participant_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn list_participants(
        &self,
        request: Request<pb::UniversalListParticipantsRequest>,
    ) -> Result<Response<pb::UniversalListParticipantsResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_list_participants(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, conference_id, max_items))) => self
                .admit(&scope, &credential_id, &secret, CONFERENCE_READ_PERMISSION)
                .and_then(|_| list_participants(&*self.store, &scope, &conference_id, max_items)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalListParticipantsResponse {
            result: Some(match result {
                Ok(participants) => pb::universal_list_participants_response::Result::Participants(
                    pb::UniversalParticipantList {
                        participants: participants.iter().map(pb_participant).collect(),
                    },
                ),
                Err(error) => {
                    pb::universal_list_participants_response::Result::Error(pb_error(error))
                }
            }),
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

struct EnsureParticipantInput {
    scope: TenantScope,
    conference_id: GroupId,
    integration_id: IntegrationId,
    external_user_id: Vec<u8>,
    role: ConferenceParticipantRole,
    idempotency_key: String,
}

struct UpdateParticipantInput {
    scope: TenantScope,
    conference_id: GroupId,
    participant: PrincipalRef,
    role: Option<ConferenceParticipantRole>,
    audio_muted: Option<bool>,
    camera_allowed: Option<bool>,
    publish_audio_allowed: Option<bool>,
    publish_video_allowed: Option<bool>,
    idempotency_key: String,
}

struct RemoveParticipantInput {
    scope: TenantScope,
    conference_id: GroupId,
    participant: PrincipalRef,
    idempotency_key: String,
}

struct CreateInput {
    scope: TenantScope,
    integration_id: IntegrationId,
    external_conference_id: Vec<u8>,
    idempotency_key: String,
    mode: UniversalConferenceMode,
    schedule: ConferenceScheduleMetadata,
}

fn decode_create(
    value: pb::UniversalCreateConferenceRequest,
) -> Result<CreateInput, CanonicalError> {
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

fn decode_ensure_participant(
    value: pb::UniversalEnsureParticipantRequest,
) -> Result<EnsureParticipantInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    if value.external_user_id.is_empty() || value.external_user_id.len() > 512 {
        return Err(invalid_argument());
    }
    validate_idempotency_key(&value.idempotency_key)?;
    let role = decode_participant_role(value.role)?;
    Ok(EnsureParticipantInput {
        scope,
        conference_id,
        integration_id,
        external_user_id: value.external_user_id,
        role,
        idempotency_key: value.idempotency_key,
    })
}

fn decode_participant_role(value: i32) -> Result<ConferenceParticipantRole, CanonicalError> {
    match pb::ConferenceParticipantRole::try_from(value).map_err(|_| invalid_argument())? {
        pb::ConferenceParticipantRole::Unspecified => Err(invalid_argument()),
        pb::ConferenceParticipantRole::Owner => Ok(ConferenceParticipantRole::Owner),
        pb::ConferenceParticipantRole::Host => Ok(ConferenceParticipantRole::Host),
        pb::ConferenceParticipantRole::Moderator => Ok(ConferenceParticipantRole::Moderator),
        pb::ConferenceParticipantRole::Speaker => Ok(ConferenceParticipantRole::Speaker),
        pb::ConferenceParticipantRole::Attendee => Ok(ConferenceParticipantRole::Attendee),
    }
}

fn participant_ref(value: Option<pb::OpaqueId>) -> Result<PrincipalRef, CanonicalError> {
    Ok(PrincipalRef {
        principal_id: PrincipalId::from_opaque(decode_opaque(value)?),
        kind: PrincipalKind::Person,
    })
}

fn decode_update_participant(
    value: pb::UniversalUpdateParticipantRequest,
) -> Result<UpdateParticipantInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let participant = participant_ref(value.participant_id)?;
    validate_idempotency_key(&value.idempotency_key)?;
    let role = value.role.map(decode_participant_role).transpose()?;
    Ok(UpdateParticipantInput {
        scope,
        conference_id,
        participant,
        role,
        audio_muted: value.audio_muted,
        camera_allowed: value.camera_allowed,
        publish_audio_allowed: value.publish_audio_allowed,
        publish_video_allowed: value.publish_video_allowed,
        idempotency_key: value.idempotency_key,
    })
}

fn decode_remove_participant(
    value: pb::UniversalRemoveParticipantRequest,
) -> Result<RemoveParticipantInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let participant = participant_ref(value.participant_id)?;
    validate_idempotency_key(&value.idempotency_key)?;
    Ok(RemoveParticipantInput {
        scope,
        conference_id,
        participant,
        idempotency_key: value.idempotency_key,
    })
}

fn decode_list_participants(
    value: pb::UniversalListParticipantsRequest,
) -> Result<(TenantScope, GroupId, usize), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let max_items = if value.max_items == 0 {
        256
    } else {
        usize::try_from(value.max_items).map_err(|_| invalid_argument())?
    };
    if max_items > 1024 {
        return Err(invalid_argument());
    }
    Ok((scope, conference_id, max_items))
}

fn decode_lifecycle_request(
    value: pb::UniversalConferenceLifecycleRequest,
) -> Result<(TenantScope, GroupId, UniversalConferenceLifecycle, String), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    validate_idempotency_key(&value.idempotency_key)?;
    let target = match pb::UniversalConferenceLifecycle::try_from(value.target)
        .map_err(|_| invalid_argument())?
    {
        pb::UniversalConferenceLifecycle::Unspecified => return Err(invalid_argument()),
        pb::UniversalConferenceLifecycle::Scheduled => UniversalConferenceLifecycle::Scheduled,
        pb::UniversalConferenceLifecycle::Waiting => UniversalConferenceLifecycle::Waiting,
        pb::UniversalConferenceLifecycle::Live => UniversalConferenceLifecycle::Live,
        pb::UniversalConferenceLifecycle::Ending => UniversalConferenceLifecycle::Ending,
        pb::UniversalConferenceLifecycle::Ended => UniversalConferenceLifecycle::Ended,
    };
    Ok((scope, conference_id, target, value.idempotency_key))
}

fn decode_entry_request(
    value: pb::UniversalSetEntryOpenRequest,
) -> Result<(TenantScope, GroupId, bool, String), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    validate_idempotency_key(&value.idempotency_key)?;
    Ok((
        scope,
        conference_id,
        value.entry_open,
        value.idempotency_key,
    ))
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

const EXTERNAL_PARTICIPANT_NAMESPACE: &str = "ucr.conference.participant.v1";

fn ensure_participant<S>(
    store: &S,
    input: EnsureParticipantInput,
    payload: Vec<u8>,
) -> Result<UniversalConferenceParticipantProfile, CanonicalError>
where
    S: UniversalConferenceStore
        + CommandAcceptanceStore
        + IdentityStore
        + ExternalIdentityBindingStore
        + PrincipalIdentityBindingStore
        + PrincipalIdentityLookupStore,
{
    let conference = store
        .universal_conference_profile(&input.scope, &input.conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    if conference.integration_id != input.integration_id
        || conference.lifecycle == UniversalConferenceLifecycle::Ended
    {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }

    let stable_command_id = accept_mutation_id(
        store,
        &input.scope,
        "ucr.conference.participant.ensure.v1",
        &input.idempotency_key,
        payload,
    )?;

    let binding = match store
        .external_identity_binding(
            &input.scope,
            &input.integration_id,
            EXTERNAL_PARTICIPANT_NAMESPACE,
            &input.external_user_id,
        )
        .map_err(map_store_error)?
    {
        Some(binding) => binding,
        None => {
            let identity_id = IdentityId::from_opaque(derived_id("identity", &stable_command_id)?);
            let identity = IdentityRecord {
                scope: input.scope.clone(),
                identity_id: identity_id.clone(),
                ownership: IdentityOwnership::PlatformManaged,
                evidence: IdentityEvidence::Unverified,
                expires_at_unix_ms: None,
            };
            store.persist_identity(&identity).map_err(map_store_error)?;
            let binding = ExternalIdentityBinding {
                scope: input.scope.clone(),
                integration_id: input.integration_id.clone(),
                external_namespace: EXTERNAL_PARTICIPANT_NAMESPACE.to_owned(),
                external_entity_id: input.external_user_id.clone(),
                identity_id,
            };
            match store.persist_external_identity_binding(&binding) {
                Ok(_) => binding,
                Err(DurableStoreError::Conflict) => store
                    .external_identity_binding(
                        &input.scope,
                        &input.integration_id,
                        EXTERNAL_PARTICIPANT_NAMESPACE,
                        &input.external_user_id,
                    )
                    .map_err(map_store_error)?
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Conflict))?,
                Err(error) => return Err(map_store_error(error)),
            }
        }
    };

    if store
        .identity(&input.scope, &binding.identity_id)
        .map_err(map_store_error)?
        .is_none()
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Internal));
    }

    let bindings = store
        .principal_identity_bindings_for_identity(&input.scope, &binding.identity_id, 16)
        .map_err(map_store_error)?;
    let mut person_principals = bindings
        .into_iter()
        .filter(|candidate| candidate.principal.kind == PrincipalKind::Person);
    let participant = match (person_principals.next(), person_principals.next()) {
        (Some(existing), None) => existing.principal,
        (Some(_), Some(_)) => return Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
        (None, _) => {
            let principal = PrincipalRef {
                principal_id: PrincipalId::from_opaque(derived_id(
                    "principal",
                    &stable_command_id,
                )?),
                kind: PrincipalKind::Person,
            };
            let principal_binding = PrincipalIdentityBinding {
                scope: input.scope.clone(),
                principal: principal.clone(),
                identity_id: binding.identity_id.clone(),
            };
            store
                .persist_principal_identity_binding(&principal_binding)
                .map_err(map_store_error)?;
            principal
        }
    };

    let (audio_muted, camera_allowed, publish_audio_allowed, publish_video_allowed) =
        participant_defaults(conference.mode, input.role);
    let desired = UniversalConferenceParticipantProfile {
        scope: input.scope.clone(),
        conference_id: input.conference_id.clone(),
        integration_id: input.integration_id,
        external_user_id: input.external_user_id,
        participant: participant.clone(),
        role: input.role,
        audio_muted,
        camera_allowed,
        publish_audio_allowed,
        publish_video_allowed,
        active: true,
        revision: 1,
    };

    match store
        .universal_conference_participant(&input.scope, &input.conference_id, &participant)
        .map_err(map_store_error)?
    {
        None => {
            store
                .persist_universal_conference_participant(&desired)
                .map_err(map_store_error)?;
            Ok(desired)
        }
        Some(current)
            if current.integration_id == desired.integration_id
                && current.external_user_id == desired.external_user_id
                && current.role == desired.role
                && current.audio_muted == desired.audio_muted
                && current.camera_allowed == desired.camera_allowed
                && current.publish_audio_allowed == desired.publish_audio_allowed
                && current.publish_video_allowed == desired.publish_video_allowed
                && current.active =>
        {
            Ok(current)
        }
        Some(current)
            if current.integration_id == desired.integration_id
                && current.external_user_id == desired.external_user_id =>
        {
            store
                .update_universal_conference_participant(
                    &input.scope,
                    &input.conference_id,
                    &participant,
                    current.revision,
                    desired.role,
                    desired.audio_muted,
                    desired.camera_allowed,
                    desired.publish_audio_allowed,
                    desired.publish_video_allowed,
                    true,
                )
                .map_err(map_store_error)
        }
        Some(_) => Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
    }
}

fn update_participant<S>(
    store: &S,
    input: UpdateParticipantInput,
    payload: Vec<u8>,
) -> Result<UniversalConferenceParticipantProfile, CanonicalError>
where
    S: UniversalConferenceStore + CommandAcceptanceStore,
{
    let conference = store
        .universal_conference_profile(&input.scope, &input.conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    if conference.lifecycle == UniversalConferenceLifecycle::Ended {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    let current = store
        .universal_conference_participant(&input.scope, &input.conference_id, &input.participant)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;

    accept_mutation(
        store,
        &input.scope,
        "ucr.conference.participant.update.v1",
        &input.idempotency_key,
        payload,
    )?;

    let role = input.role.unwrap_or(current.role);
    let (required_muted, camera_ceiling, audio_publish_ceiling, video_publish_ceiling) =
        participant_defaults(conference.mode, role);

    if input.audio_muted == Some(false) && required_muted
        || input.camera_allowed == Some(true) && !camera_ceiling
        || input.publish_audio_allowed == Some(true) && !audio_publish_ceiling
        || input.publish_video_allowed == Some(true) && !video_publish_ceiling
    {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }

    let audio_muted = input.audio_muted.unwrap_or(current.audio_muted) || required_muted;
    let camera_allowed = input.camera_allowed.unwrap_or(current.camera_allowed) && camera_ceiling;
    let publish_audio_allowed = input
        .publish_audio_allowed
        .unwrap_or(current.publish_audio_allowed)
        && audio_publish_ceiling;
    let publish_video_allowed = input
        .publish_video_allowed
        .unwrap_or(current.publish_video_allowed)
        && video_publish_ceiling;

    if publish_video_allowed && !camera_allowed {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }

    if current.role == role
        && current.audio_muted == audio_muted
        && current.camera_allowed == camera_allowed
        && current.publish_audio_allowed == publish_audio_allowed
        && current.publish_video_allowed == publish_video_allowed
        && current.active
    {
        return Ok(current);
    }

    store
        .update_universal_conference_participant(
            &input.scope,
            &input.conference_id,
            &input.participant,
            current.revision,
            role,
            audio_muted,
            camera_allowed,
            publish_audio_allowed,
            publish_video_allowed,
            true,
        )
        .map_err(map_store_error)
}

fn remove_participant<S>(
    store: &S,
    input: RemoveParticipantInput,
    payload: Vec<u8>,
) -> Result<CommandId, CanonicalError>
where
    S: UniversalConferenceStore + CommandAcceptanceStore,
{
    let conference = store
        .universal_conference_profile(&input.scope, &input.conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    if conference.lifecycle == UniversalConferenceLifecycle::Ended {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    let current = store
        .universal_conference_participant(&input.scope, &input.conference_id, &input.participant)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;

    let command_id = accept_mutation_id(
        store,
        &input.scope,
        "ucr.conference.participant.remove.v1",
        &input.idempotency_key,
        payload,
    )?;

    if current.active {
        store
            .update_universal_conference_participant(
                &input.scope,
                &input.conference_id,
                &input.participant,
                current.revision,
                current.role,
                true,
                false,
                false,
                false,
                false,
            )
            .map_err(map_store_error)?;
    }
    Ok(command_id)
}

fn list_participants<S: UniversalConferenceStore>(
    store: &S,
    scope: &TenantScope,
    conference_id: &GroupId,
    max_items: usize,
) -> Result<Vec<UniversalConferenceParticipantProfile>, CanonicalError> {
    store
        .universal_conference_profile(scope, conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    store
        .universal_conference_participants(scope, conference_id, max_items)
        .map_err(map_store_error)
}

fn derived_id(prefix: &str, command_id: &CommandId) -> Result<OpaqueId, CanonicalError> {
    OpaqueId::new(format!("{prefix}-{}", command_id.as_opaque().as_str()))
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

const fn participant_defaults(
    mode: UniversalConferenceMode,
    role: ConferenceParticipantRole,
) -> (bool, bool, bool, bool) {
    match role {
        ConferenceParticipantRole::Owner
        | ConferenceParticipantRole::Host
        | ConferenceParticipantRole::Moderator
        | ConferenceParticipantRole::Speaker => (
            false,
            !matches!(mode, UniversalConferenceMode::AudioRoom),
            true,
            !matches!(mode, UniversalConferenceMode::AudioRoom),
        ),
        ConferenceParticipantRole::Attendee => match mode {
            UniversalConferenceMode::Meeting => (false, true, true, true),
            UniversalConferenceMode::Webinar | UniversalConferenceMode::Broadcast => {
                (true, false, false, false)
            }
            UniversalConferenceMode::AudioRoom => (true, false, false, false),
        },
    }
}

fn pb_participant(
    value: &UniversalConferenceParticipantProfile,
) -> pb::UniversalConferenceParticipant {
    pb::UniversalConferenceParticipant {
        participant_id: Some(pb_opaque(value.participant.principal_id.as_opaque())),
        external_user_id: value.external_user_id.clone(),
        role: (match value.role {
            ConferenceParticipantRole::Owner => pb::ConferenceParticipantRole::Owner,
            ConferenceParticipantRole::Host => pb::ConferenceParticipantRole::Host,
            ConferenceParticipantRole::Moderator => pb::ConferenceParticipantRole::Moderator,
            ConferenceParticipantRole::Speaker => pb::ConferenceParticipantRole::Speaker,
            ConferenceParticipantRole::Attendee => pb::ConferenceParticipantRole::Attendee,
        }) as i32,
        audio_muted: value.audio_muted,
        camera_allowed: value.camera_allowed,
        publish_audio_allowed: value.publish_audio_allowed,
        publish_video_allowed: value.publish_video_allowed,
        active: value.active,
    }
}

fn accept_mutation_id<S: CommandAcceptanceStore>(
    store: &S,
    scope: &TenantScope,
    command_type: &str,
    idempotency_key: &str,
    payload: Vec<u8>,
) -> Result<CommandId, CanonicalError> {
    validate_idempotency_key(idempotency_key)?;
    let command_id = CommandId::from_opaque(
        generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let command = CommandEnvelope {
        command_id: command_id.clone(),
        scope: scope.clone(),
        command_type: command_type.to_owned(),
        payload,
        correlation: CorrelationContext {
            correlation_id: command_id.as_opaque().clone(),
            causation_id: None,
            idempotency_key: Some(idempotency_key.to_owned()),
        },
        schema_version: ProtocolVersion::new(1, 0),
        extensions: Vec::new(),
    };
    let receipt = store.accept_command(&command).map_err(map_store_error)?;
    match receipt.status {
        CommandReceiptStatus::Accepted => Ok(receipt.command_id),
        CommandReceiptStatus::Duplicate => receipt
            .original_command_id
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal)),
    }
}

fn accept_mutation<S: CommandAcceptanceStore>(
    store: &S,
    scope: &TenantScope,
    command_type: &str,
    idempotency_key: &str,
    payload: Vec<u8>,
) -> Result<(), CanonicalError> {
    accept_mutation_id(store, scope, command_type, idempotency_key, payload).map(|_| ())
}

fn create_or_resolve<S: UniversalConferenceStore + CommandAcceptanceStore>(
    store: &S,
    input: CreateInput,
    command_payload: Vec<u8>,
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

    let incoming_command_id = CommandId::from_opaque(
        generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let command = CommandEnvelope {
        command_id: incoming_command_id.clone(),
        scope: input.scope.clone(),
        command_type: "ucr.conference.create.v1".to_owned(),
        payload: command_payload,
        correlation: CorrelationContext {
            correlation_id: incoming_command_id.as_opaque().clone(),
            causation_id: None,
            idempotency_key: Some(input.idempotency_key.clone()),
        },
        schema_version: ProtocolVersion::new(1, 0),
        extensions: Vec::new(),
    };
    let receipt = store.accept_command(&command).map_err(map_store_error)?;
    let stable_command_id = match receipt.status {
        CommandReceiptStatus::Accepted => receipt.command_id,
        CommandReceiptStatus::Duplicate => receipt
            .original_command_id
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?,
    };
    let conference_id = GroupId::from_opaque(stable_command_id.as_opaque().clone());
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
            UniversalConferenceLifecycle::Scheduled => pb::UniversalConferenceLifecycle::Scheduled,
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

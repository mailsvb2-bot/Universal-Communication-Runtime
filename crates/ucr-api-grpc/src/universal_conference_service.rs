use std::{fmt, sync::Arc};

use prost::Message;
use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, CallStore, CommandAcceptanceStore, DeviceLifecycleStore,
    DurableStoreError, EventJournalStore, ExternalIdentityBindingStore, GroupCallLookupStore,
    GroupStore, IdentityDeviceLookupStore, IdentityStore,
    PrincipalIdentityBindingStore, PrincipalIdentityLookupStore, ServiceAuditStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServicePrincipalRequestGate,
    ServiceQuotaClock, ServiceQuotaStore, UniversalConferenceStore, generate_opaque_id,
};
use ucr_group_mls::{GroupMlsAtomicStore, GroupMlsStoreError, MlsDeviceAdmission};
use ucr_model::{
    AuthorizationRequest, CallId, CallParticipant, CallParticipantState,
    CallParticipantUpdateKind, CallSession, CallSignal, CallSignalKind, CallSignallingState,
    CommandEnvelope, CommandId, ConferenceParticipantRole,
    ConferenceScheduleMetadata, ConversationId, ConversationKind, ConversationRecord,
    ConversationRef, CorrelationContext, DeliveryPolicy, DeviceDescriptor, DeviceId,
    DeviceLifecycleState, EventId, ExternalIdentityBinding, GroupChange, GroupChangeKind,
    GroupCryptoState, GroupHistoryPolicy, GroupId, GroupMediaState, GroupOwnership, GroupRecord,
    GroupRole, IdentityEvidence, IdentityId, IdentityOwnership, IdentityRecord, IntegrationId,
    OpaqueId, PrincipalId, PrincipalIdentityBinding, PrincipalKind, PrincipalRef, ProtocolVersion,
    ScopedPrincipal, SessionId, TenantScope, UniversalConferenceLifecycle,
    UniversalConferenceMode, UniversalConferenceParticipantProfile, UniversalConferenceProfile,
};
use ucr_protocol::{
    CONFERENCE_ATTENDANCE_READ_PERMISSION, CONFERENCE_CREATE_PERMISSION,
    CONFERENCE_JOIN_ISSUE_PERMISSION, CONFERENCE_MANAGE_PERMISSION,
    CONFERENCE_PARTICIPANT_ENSURE_PERMISSION, CONFERENCE_PARTICIPANT_MANAGE_PERMISSION,
    CONFERENCE_READ_PERMISSION, DEVICE_REGISTER_PERMISSION, CanonicalError, CanonicalErrorCode,
    CapabilityMaturity, CommandReceiptStatus, GROUP_MLS_CAPABILITY, MAX_CALL_PARTICIPANTS,
    acknowledgement_for, canonical_capabilities,
    phase20_audio_capabilities, phase21_video_capabilities, phase22_media_e2ee_capabilities,
    phase29_sfu_capabilities, phase30_conference_capabilities,
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

    fn admit_integration(
        &self,
        scope: &TenantScope,
        credential_id: &ucr_model::ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        integration_id: &IntegrationId,
        permission: &str,
    ) -> Result<ScopedPrincipal, CanonicalError> {
        let actor = self.admit(scope, credential_id, secret, permission)?;
        if actor.principal.kind != PrincipalKind::ServiceAccount
            || actor.principal.principal_id.as_opaque() != integration_id.as_opaque()
        {
            return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
        }
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
        + DeviceLifecycleStore
        + GroupStore
        + GroupMlsAtomicStore
        + CallStore
        + GroupCallLookupStore
        + EventJournalStore
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
        + DeviceLifecycleStore
        + GroupStore
        + GroupMlsAtomicStore
        + CallStore
        + GroupCallLookupStore
        + EventJournalStore
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
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
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
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
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
                Ok(conference) => pb::universal_resolve_conference_response::Result::Conference(
                    pb_conference(&conference),
                ),
                Err(error) => {
                    pb::universal_resolve_conference_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn get_conference(
        &self,
        request: Request<pb::UniversalGetConferenceRequest>,
    ) -> Result<Response<pb::UniversalGetConferenceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_get_conference(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, conference_id, integration_id))) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
                    CONFERENCE_READ_PERMISSION,
                )
                .and_then(|_| {
                    conference_for_integration(
                        &*self.store,
                        &scope,
                        &conference_id,
                        &integration_id,
                    )
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalGetConferenceResponse {
            result: Some(match result {
                Ok(conference) => pb::universal_get_conference_response::Result::Conference(
                    pb_conference(&conference),
                ),
                Err(error) => pb::universal_get_conference_response::Result::Error(pb_error(error)),
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
            (
                Ok((credential_id, secret)),
                Ok((scope, conference_id, integration_id, target, idempotency_key)),
            ) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
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
                    let current = conference_for_integration(
                        &*self.store,
                        &scope,
                        &conference_id,
                        &integration_id,
                    )?;
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
                }),
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
                Ok((scope, conference_id, integration_id, entry_open, idempotency_key)),
            ) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
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
                    let current = conference_for_integration(
                        &*self.store,
                        &scope,
                        &conference_id,
                        &integration_id,
                    )?;
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
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
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

    async fn ensure_participant_device(
        &self,
        request: Request<pb::UniversalEnsureParticipantDeviceRequest>,
    ) -> Result<Response<pb::UniversalEnsureParticipantDeviceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_ensure_participant_device(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
                    DEVICE_REGISTER_PERMISSION,
                )
                .and_then(|_| ensure_participant_device(&*self.store, &input, payload)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalEnsureParticipantDeviceResponse {
            result: Some(match result {
                Ok(device) => {
                    pb::universal_ensure_participant_device_response::Result::Device(device)
                }
                Err(error) => {
                    pb::universal_ensure_participant_device_response::Result::Error(pb_error(error))
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
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
                    CONFERENCE_PARTICIPANT_MANAGE_PERMISSION,
                )
                .and_then(|_| update_participant(&*self.store, &input, payload)),
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
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
                    CONFERENCE_PARTICIPANT_MANAGE_PERMISSION,
                )
                .and_then(|_| remove_participant(&*self.store, &input, payload)),
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
            (
                Ok((credential_id, secret)),
                Ok((scope, conference_id, integration_id, max_items)),
            ) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
                    CONFERENCE_READ_PERMISSION,
                )
                .and_then(|_| {
                    list_participants(
                        &*self.store,
                        &scope,
                        &conference_id,
                        &integration_id,
                        max_items,
                    )
                }),
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

    async fn prepare_conference_runtime(
        &self,
        request: Request<pb::UniversalPrepareConferenceRuntimeRequest>,
    ) -> Result<Response<pb::UniversalPrepareConferenceRuntimeResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let body = request.into_inner();
        let payload = body.encode_to_vec();
        let decoded = decode_prepare_conference_runtime(body);
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
                    CONFERENCE_MANAGE_PERMISSION,
                )
                .and_then(|_| prepare_conference_runtime(&*self.store, &input, payload)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(
            pb::UniversalPrepareConferenceRuntimeResponse {
                result: Some(match result {
                    Ok(runtime) => {
                        pb::universal_prepare_conference_runtime_response::Result::Runtime(runtime)
                    }
                    Err(error) => {
                        pb::universal_prepare_conference_runtime_response::Result::Error(pb_error(
                            error,
                        ))
                    }
                }),
            },
        ))
    }

    async fn issue_join_grant(
        &self,
        request: Request<pb::UniversalIssueJoinGrantRequest>,
    ) -> Result<Response<pb::UniversalIssueJoinGrantResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_issue_join_grant(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok(input)) => self
                .admit_integration(
                    &input.scope,
                    &credential_id,
                    &secret,
                    &input.integration_id,
                    CONFERENCE_JOIN_ISSUE_PERMISSION,
                )
                .and_then(|_| {
                    let issuer = self.join_issuer.as_deref().ok_or_else(|| {
                        CanonicalError::new(CanonicalErrorCode::CapabilityMismatch)
                    })?;
                    let now_unix_ms = self.clock.now_unix_ms().map_err(|_| {
                        CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
                    })?;
                    issue_join_grant(&*self.store, issuer, input, now_unix_ms)
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalIssueJoinGrantResponse {
            result: Some(match result {
                Ok(grant) => pb::universal_issue_join_grant_response::Result::Grant(grant),
                Err(error) => {
                    pb::universal_issue_join_grant_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn revoke_join_grant(
        &self,
        request: Request<pb::UniversalRevokeJoinGrantRequest>,
    ) -> Result<Response<pb::UniversalRevokeJoinGrantResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_revoke_join_grant(request.into_inner());
        let result = match (credentials, decoded) {
            (
                Ok((credential_id, secret)),
                Ok((scope, conference_id, integration_id, session_id)),
            ) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
                    CONFERENCE_JOIN_ISSUE_PERMISSION,
                )
                .and_then(|_| {
                    let issuer = self.join_issuer.as_deref().ok_or_else(|| {
                        CanonicalError::new(CanonicalErrorCode::CapabilityMismatch)
                    })?;
                    revoke_join_grant(
                        &*self.store,
                        issuer,
                        &scope,
                        &conference_id,
                        &integration_id,
                        &session_id,
                    )?;
                    Ok(session_id)
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalRevokeJoinGrantResponse {
            result: Some(match result {
                Ok(session_id) => {
                    pb::universal_revoke_join_grant_response::Result::Acknowledgement(
                        pb_acknowledgement(acknowledgement_for(session_id.as_opaque().clone())),
                    )
                }
                Err(error) => {
                    pb::universal_revoke_join_grant_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn get_participant_attendance(
        &self,
        request: Request<pb::UniversalGetParticipantAttendanceRequest>,
    ) -> Result<Response<pb::UniversalGetParticipantAttendanceResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_participant_attendance(request.into_inner());
        let result = match (credentials, decoded) {
            (
                Ok((credential_id, secret)),
                Ok((scope, conference_id, integration_id, external_user_id)),
            ) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
                    CONFERENCE_ATTENDANCE_READ_PERMISSION,
                )
                .and_then(|_| {
                    let now_unix_ms = self.clock.now_unix_ms().map_err(|_| {
                        CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
                    })?;
                    participant_attendance(
                        &*self.store,
                        &scope,
                        &conference_id,
                        &integration_id,
                        &external_user_id,
                        now_unix_ms,
                    )
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(
            pb::UniversalGetParticipantAttendanceResponse {
                result: Some(match result {
                    Ok(attendance) => {
                        pb::universal_get_participant_attendance_response::Result::Attendance(
                            attendance,
                        )
                    }
                    Err(error) => pb::universal_get_participant_attendance_response::Result::Error(
                        pb_error(error),
                    ),
                }),
            },
        ))
    }

    async fn get_capabilities(
        &self,
        request: Request<pb::UniversalGetCapabilitiesRequest>,
    ) -> Result<Response<pb::UniversalGetCapabilitiesResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let decoded = decode_capabilities_request(request.into_inner());
        let result = match (credentials, decoded) {
            (Ok((credential_id, secret)), Ok((scope, integration_id))) => self
                .admit_integration(
                    &scope,
                    &credential_id,
                    &secret,
                    &integration_id,
                    CONFERENCE_READ_PERMISSION,
                )
                .and_then(|_| universal_capabilities()),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::UniversalGetCapabilitiesResponse {
            result: Some(match result {
                Ok(capabilities) => {
                    pb::universal_get_capabilities_response::Result::Capabilities(capabilities)
                }
                Err(error) => {
                    pb::universal_get_capabilities_response::Result::Error(pb_error(error))
                }
            }),
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

struct EnsureParticipantDeviceInput {
    scope: TenantScope,
    conference_id: GroupId,
    integration_id: IntegrationId,
    external_user_id: Vec<u8>,
    idempotency_key: String,
}

struct UpdateParticipantInput {
    scope: TenantScope,
    conference_id: GroupId,
    integration_id: IntegrationId,
    external_user_id: Vec<u8>,
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
    integration_id: IntegrationId,
    external_user_id: Vec<u8>,
    idempotency_key: String,
}

struct PrepareConferenceRuntimeInput {
    scope: TenantScope,
    conference_id: GroupId,
    integration_id: IntegrationId,
    idempotency_key: String,
}

struct IssueJoinGrantInput {
    scope: TenantScope,
    conference_id: GroupId,
    integration_id: IntegrationId,
    external_user_id: Vec<u8>,
    ttl_seconds: u32,
    use_policy: RealtimeJoinGrantUsePolicy,
    not_before_unix_ms: Option<i64>,
    not_after_unix_ms: Option<i64>,
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
    validate_external_user_id(&value.external_user_id)?;
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

fn decode_ensure_participant_device(
    value: pb::UniversalEnsureParticipantDeviceRequest,
) -> Result<EnsureParticipantDeviceInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_external_user_id(&value.external_user_id)?;
    validate_idempotency_key(&value.idempotency_key)?;
    Ok(EnsureParticipantDeviceInput {
        scope,
        conference_id,
        integration_id,
        external_user_id: value.external_user_id,
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

fn decode_update_participant(
    value: pb::UniversalUpdateParticipantRequest,
) -> Result<UpdateParticipantInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_external_user_id(&value.external_user_id)?;
    validate_idempotency_key(&value.idempotency_key)?;
    let role = value.role.map(decode_participant_role).transpose()?;
    Ok(UpdateParticipantInput {
        scope,
        conference_id,
        integration_id,
        external_user_id: value.external_user_id,
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
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_external_user_id(&value.external_user_id)?;
    validate_idempotency_key(&value.idempotency_key)?;
    Ok(RemoveParticipantInput {
        scope,
        conference_id,
        integration_id,
        external_user_id: value.external_user_id,
        idempotency_key: value.idempotency_key,
    })
}

fn decode_list_participants(
    value: pb::UniversalListParticipantsRequest,
) -> Result<(TenantScope, GroupId, IntegrationId, usize), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    let max_items = if value.max_items == 0 {
        256
    } else {
        usize::try_from(value.max_items).map_err(|_| invalid_argument())?
    };
    if max_items > 1024 {
        return Err(invalid_argument());
    }
    Ok((scope, conference_id, integration_id, max_items))
}

fn decode_prepare_conference_runtime(
    value: pb::UniversalPrepareConferenceRuntimeRequest,
) -> Result<PrepareConferenceRuntimeInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_idempotency_key(&value.idempotency_key)?;
    Ok(PrepareConferenceRuntimeInput {
        scope,
        conference_id,
        integration_id,
        idempotency_key: value.idempotency_key,
    })
}

fn decode_issue_join_grant(
    value: pb::UniversalIssueJoinGrantRequest,
) -> Result<IssueJoinGrantInput, CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_external_user_id(&value.external_user_id)?;
    let use_policy =
        match pb::JoinGrantUsePolicy::try_from(value.use_policy).map_err(|_| invalid_argument())? {
            pb::JoinGrantUsePolicy::Unspecified => return Err(invalid_argument()),
            pb::JoinGrantUsePolicy::SingleUse => RealtimeJoinGrantUsePolicy::SingleUse,
            pb::JoinGrantUsePolicy::Reusable => RealtimeJoinGrantUsePolicy::Reusable,
        };
    Ok(IssueJoinGrantInput {
        scope,
        conference_id,
        integration_id,
        external_user_id: value.external_user_id,
        ttl_seconds: value.ttl_seconds,
        use_policy,
        not_before_unix_ms: value.not_before_unix_ms,
        not_after_unix_ms: value.not_after_unix_ms,
    })
}

fn decode_revoke_join_grant(
    value: pb::UniversalRevokeJoinGrantRequest,
) -> Result<(TenantScope, GroupId, IntegrationId, SessionId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        GroupId::from_opaque(decode_opaque(value.conference_id)?),
        IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
        SessionId::from_opaque(decode_opaque(value.session_id)?),
    ))
}

fn decode_participant_attendance(
    value: pb::UniversalGetParticipantAttendanceRequest,
) -> Result<(TenantScope, GroupId, IntegrationId, Vec<u8>), CanonicalError> {
    validate_external_user_id(&value.external_user_id)?;
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        GroupId::from_opaque(decode_opaque(value.conference_id)?),
        IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
        value.external_user_id,
    ))
}

fn decode_capabilities_request(
    value: pb::UniversalGetCapabilitiesRequest,
) -> Result<(TenantScope, IntegrationId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
    ))
}

fn decode_lifecycle_request(
    value: pb::UniversalConferenceLifecycleRequest,
) -> Result<
    (
        TenantScope,
        GroupId,
        IntegrationId,
        UniversalConferenceLifecycle,
        String,
    ),
    CanonicalError,
> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
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
    Ok((
        scope,
        conference_id,
        integration_id,
        target,
        value.idempotency_key,
    ))
}

fn decode_entry_request(
    value: pb::UniversalSetEntryOpenRequest,
) -> Result<(TenantScope, GroupId, IntegrationId, bool, String), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let conference_id = GroupId::from_opaque(decode_opaque(value.conference_id)?);
    let integration_id = IntegrationId::from_opaque(decode_opaque(value.integration_id)?);
    validate_idempotency_key(&value.idempotency_key)?;
    Ok((
        scope,
        conference_id,
        integration_id,
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

fn decode_get_conference(
    value: pb::UniversalGetConferenceRequest,
) -> Result<(TenantScope, GroupId, IntegrationId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        GroupId::from_opaque(decode_opaque(value.conference_id)?),
        IntegrationId::from_opaque(decode_opaque(value.integration_id)?),
    ))
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

fn resolve_external_participant_identity<S>(
    store: &S,
    input: &EnsureParticipantInput,
    stable_command_id: &CommandId,
) -> Result<ExternalIdentityBinding, CanonicalError>
where
    S: IdentityStore + ExternalIdentityBindingStore,
{
    if let Some(binding) = store
        .external_identity_binding(
            &input.scope,
            &input.integration_id,
            EXTERNAL_PARTICIPANT_NAMESPACE,
            &input.external_user_id,
        )
        .map_err(map_store_error)?
    {
        return Ok(binding);
    }

    let identity_id = IdentityId::from_opaque(derived_id("identity", stable_command_id)?);
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
        Ok(_) => Ok(binding),
        Err(DurableStoreError::Conflict) => store
            .external_identity_binding(
                &input.scope,
                &input.integration_id,
                EXTERNAL_PARTICIPANT_NAMESPACE,
                &input.external_user_id,
            )
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Conflict)),
        Err(error) => Err(map_store_error(error)),
    }
}

fn resolve_person_principal<S>(
    store: &S,
    scope: &TenantScope,
    identity_id: &IdentityId,
    stable_command_id: &CommandId,
) -> Result<PrincipalRef, CanonicalError>
where
    S: IdentityStore + PrincipalIdentityBindingStore + PrincipalIdentityLookupStore,
{
    if store
        .identity(scope, identity_id)
        .map_err(map_store_error)?
        .is_none()
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Internal));
    }
    let bindings = store
        .principal_identity_bindings_for_identity(scope, identity_id, 16)
        .map_err(map_store_error)?;
    if bindings.len() == 16 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let mut person_principals = bindings
        .into_iter()
        .filter(|candidate| candidate.principal.kind == PrincipalKind::Person);
    match (person_principals.next(), person_principals.next()) {
        (Some(existing), None) => Ok(existing.principal),
        (Some(_), Some(_)) => Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
        (None, _) => {
            let principal = PrincipalRef {
                principal_id: PrincipalId::from_opaque(derived_id("principal", stable_command_id)?),
                kind: PrincipalKind::Person,
            };
            store
                .persist_principal_identity_binding(&PrincipalIdentityBinding {
                    scope: scope.clone(),
                    principal: principal.clone(),
                    identity_id: identity_id.clone(),
                })
                .map_err(map_store_error)?;
            Ok(principal)
        }
    }
}

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

    let binding = resolve_external_participant_identity(store, &input, &stable_command_id)?;
    let participant = resolve_person_principal(
        store,
        &input.scope,
        &binding.identity_id,
        &stable_command_id,
    )?;

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

fn ensure_participant_device<S>(
    store: &S,
    input: &EnsureParticipantDeviceInput,
    payload: Vec<u8>,
) -> Result<pb::UniversalParticipantDeviceStatus, CanonicalError>
where
    S: UniversalConferenceStore
        + CommandAcceptanceStore
        + PrincipalIdentityBindingStore
        + IdentityDeviceLookupStore
        + DeviceLifecycleStore,
{
    let conference = conference_for_integration(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
    )?;
    if conference.lifecycle == UniversalConferenceLifecycle::Ended {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    let participant = participant_for_external(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
        &input.external_user_id,
    )?;
    if !participant.active {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    let binding = store
        .principal_identity_binding(&input.scope, &participant.participant)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;

    let stable_command_id = accept_mutation_id(
        store,
        &input.scope,
        "ucr.conference.participant.device.ensure.v1",
        &input.idempotency_key,
        payload,
    )?;
    let devices = store
        .devices_for_identity(&input.scope, &binding.identity_id, 64)
        .map_err(map_store_error)?;
    if devices.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let active = devices
        .iter()
        .filter(|device| device.state == DeviceLifecycleState::Active)
        .collect::<Vec<_>>();
    match active.as_slice() {
        [_] => Ok(participant_device_status(&input.external_user_id)),
        [_, ..] => Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
        [] if !devices.is_empty() => Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied)),
        [] => {
            let device_id = DeviceId::from_opaque(derived_id("device", &stable_command_id)?);
            store
                .register_device(
                    &input.scope,
                    &DeviceDescriptor {
                        device_id,
                        identity_id: binding.identity_id,
                        state: DeviceLifecycleState::Active,
                    },
                )
                .map_err(map_store_error)?;
            Ok(participant_device_status(&input.external_user_id))
        }
    }
}

fn participant_device_status(external_user_id: &[u8]) -> pb::UniversalParticipantDeviceStatus {
    pb::UniversalParticipantDeviceStatus {
        external_user_id: external_user_id.to_vec(),
        active: true,
    }
}

fn update_participant<S>(
    store: &S,
    input: &UpdateParticipantInput,
    payload: Vec<u8>,
) -> Result<UniversalConferenceParticipantProfile, CanonicalError>
where
    S: UniversalConferenceStore + CommandAcceptanceStore,
{
    let conference = conference_for_integration(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
    )?;
    if conference.lifecycle == UniversalConferenceLifecycle::Ended {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    let current = participant_for_external(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
        &input.external_user_id,
    )?;

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
            &current.participant,
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
    input: &RemoveParticipantInput,
    payload: Vec<u8>,
) -> Result<CommandId, CanonicalError>
where
    S: UniversalConferenceStore + CommandAcceptanceStore,
{
    let conference = conference_for_integration(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
    )?;
    if conference.lifecycle == UniversalConferenceLifecycle::Ended {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    let current = participant_for_external(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
        &input.external_user_id,
    )?;

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
                &current.participant,
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

fn conference_for_integration<S: UniversalConferenceStore>(
    store: &S,
    scope: &TenantScope,
    conference_id: &GroupId,
    integration_id: &IntegrationId,
) -> Result<UniversalConferenceProfile, CanonicalError> {
    let conference = store
        .universal_conference_profile(scope, conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    if conference.integration_id != *integration_id {
        return Err(CanonicalError::new(CanonicalErrorCode::NotFound));
    }
    Ok(conference)
}

fn participant_for_external<S: UniversalConferenceStore>(
    store: &S,
    scope: &TenantScope,
    conference_id: &GroupId,
    integration_id: &IntegrationId,
    external_user_id: &[u8],
) -> Result<UniversalConferenceParticipantProfile, CanonicalError> {
    store
        .universal_conference_participant_for_external(
            scope,
            conference_id,
            integration_id,
            external_user_id,
        )
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
}

fn list_participants<S: UniversalConferenceStore>(
    store: &S,
    scope: &TenantScope,
    conference_id: &GroupId,
    integration_id: &IntegrationId,
    max_items: usize,
) -> Result<Vec<UniversalConferenceParticipantProfile>, CanonicalError> {
    conference_for_integration(store, scope, conference_id, integration_id)?;
    store
        .universal_conference_participants(scope, conference_id, max_items)
        .map_err(map_store_error)
}

#[derive(Debug, Clone)]
struct RuntimeReadyParticipant {
    profile: UniversalConferenceParticipantProfile,
    device_id: DeviceId,
}

fn prepare_conference_runtime<S>(
    store: &S,
    input: &PrepareConferenceRuntimeInput,
    payload: Vec<u8>,
) -> Result<pb::UniversalConferenceRuntimeStatus, CanonicalError>
where
    S: UniversalConferenceStore
        + CommandAcceptanceStore
        + PrincipalIdentityBindingStore
        + IdentityDeviceLookupStore
        + DeviceLifecycleStore
        + GroupStore
        + GroupMlsAtomicStore
        + CallStore
        + GroupCallLookupStore,
{
    let conference = conference_for_integration(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
    )?;
    if conference.lifecycle == UniversalConferenceLifecycle::Ended {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }

    let participants = store
        .universal_conference_participants(&input.scope, &input.conference_id, 1024)
        .map_err(map_store_error)?;
    if participants.len() == 1024 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let active = participants
        .into_iter()
        .filter(|participant| participant.active)
        .collect::<Vec<_>>();
    let owners = active
        .iter()
        .filter(|participant| participant.role == ConferenceParticipantRole::Owner)
        .cloned()
        .collect::<Vec<_>>();
    let [owner] = owners.as_slice() else {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    };
    if owner.participant.kind != PrincipalKind::Person {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }

    let mut ready = Vec::new();
    for participant in active {
        if let Some(device_id) =
            optional_single_active_device(store, &input.scope, &participant.participant)?
        {
            ready.push(RuntimeReadyParticipant {
                profile: participant,
                device_id,
            });
        }
    }
    ready.sort_by(|left, right| {
        left.profile
            .participant
            .principal_id
            .as_opaque()
            .as_wire_bytes()
            .cmp(
                right
                    .profile
                    .participant
                    .principal_id
                    .as_opaque()
                    .as_wire_bytes(),
            )
    });
    let owner_ready = ready
        .iter()
        .find(|participant| participant.profile.participant == owner.participant)
        .cloned()
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PolicyDenied))?;
    let owner_actor = ScopedPrincipal {
        scope: input.scope.clone(),
        principal: owner_ready.profile.participant.clone(),
    };
    let stable_command_id = accept_mutation_id(
        store,
        &input.scope,
        "ucr.conference.runtime.prepare.v1",
        &input.idempotency_key,
        payload,
    )?;

    let group = ensure_runtime_group(
        store,
        input,
        &stable_command_id,
        &owner_actor,
        &owner_ready.device_id,
    )?;
    reconcile_runtime_group_members(
        store,
        &owner_actor,
        &owner_ready.device_id,
        &group,
        &ready,
    )?;
    let call_ready = reconcile_runtime_call(
        store,
        input,
        &stable_command_id,
        &owner_actor,
        &ready,
    )?;
    let admitted_participant_count = u32::try_from(ready.len())
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::ResourceExhausted))?;
    Ok(pb::UniversalConferenceRuntimeStatus {
        group_ready: true,
        call_ready,
        admitted_participant_count,
    })
}

fn optional_single_active_device<S>(
    store: &S,
    scope: &TenantScope,
    participant: &PrincipalRef,
) -> Result<Option<DeviceId>, CanonicalError>
where
    S: PrincipalIdentityBindingStore + IdentityDeviceLookupStore,
{
    let binding = store
        .principal_identity_binding(scope, participant)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let devices = store
        .devices_for_identity(scope, &binding.identity_id, 64)
        .map_err(map_store_error)?;
    if devices.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let mut active = devices
        .into_iter()
        .filter(|device| device.state == DeviceLifecycleState::Active);
    match (active.next(), active.next()) {
        (None, _) => Ok(None),
        (Some(device), None) => Ok(Some(device.device_id)),
        (Some(_), Some(_)) => Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
    }
}

fn ensure_runtime_group<S>(
    store: &S,
    input: &PrepareConferenceRuntimeInput,
    stable_command_id: &CommandId,
    owner: &ScopedPrincipal,
    owner_device_id: &DeviceId,
) -> Result<GroupRecord, CanonicalError>
where
    S: GroupStore + GroupMlsAtomicStore,
{
    if let Some(group) = store
        .group(&input.scope, &input.conference_id)
        .map_err(map_store_error)?
    {
        validate_runtime_group(&group, owner)?;
        return Ok(group);
    }

    let conversation = ConversationRecord {
        scope: input.scope.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(derived_id(
                "conversation",
                stable_command_id,
            )?),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = GroupRecord {
        scope: input.scope.clone(),
        group_id: input.conference_id.clone(),
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::PersonOwned(owner.principal.clone()),
        history_policy: GroupHistoryPolicy::NoHistory,
        delivery_policy: DeliveryPolicy::NoExternalBridge,
        crypto_state: GroupCryptoState {
            capability_id: None,
            epoch: 0,
            state_ref: None,
        },
        public_policy: None,
        media_state: GroupMediaState::Idle,
        bridge_mappings: Vec::new(),
        replication_generation: 0,
        revision: 0,
    };
    let key_package = store
        .create_mls_device_key_package(&input.scope, owner_device_id)
        .map_err(map_group_mls_error)?;
    let (_, created) = store
        .create_mls_backed_group(
            &conversation,
            &group,
            owner,
            owner_device_id,
            &key_package,
        )
        .map_err(map_group_mls_error)?;
    validate_runtime_group(&created, owner)?;
    Ok(created)
}

fn validate_runtime_group(
    group: &GroupRecord,
    owner: &ScopedPrincipal,
) -> Result<(), CanonicalError> {
    if group.scope != owner.scope
        || group.ownership != GroupOwnership::PersonOwned(owner.principal.clone())
        || group.conversation.kind != ConversationKind::PrivateGroup
        || group.crypto_state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY)
        || group.crypto_state.state_ref.is_none()
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }
    Ok(())
}

fn reconcile_runtime_group_members<S>(
    store: &S,
    owner: &ScopedPrincipal,
    owner_device_id: &DeviceId,
    initial_group: &GroupRecord,
    ready: &[RuntimeReadyParticipant],
) -> Result<(), CanonicalError>
where
    S: GroupStore + GroupMlsAtomicStore,
{
    validate_runtime_group(initial_group, owner)?;
    for participant in ready {
        if participant.profile.participant == owner.principal {
            continue;
        }
        if store
            .group_membership(
                &owner.scope,
                &initial_group.group_id,
                &participant.profile.participant,
            )
            .map_err(map_store_error)?
            .is_some_and(|membership| membership.state == ucr_model::GroupMemberState::Active)
        {
            continue;
        }
        let group = store
            .group(&owner.scope, &initial_group.group_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
        let key_package = store
            .create_mls_device_key_package(&owner.scope, &participant.device_id)
            .map_err(map_group_mls_error)?;
        let change = GroupChange {
            event_id: runtime_event_id(
                "gm",
                group.revision,
                &participant.profile.participant,
            )?,
            scope: owner.scope.clone(),
            group_id: group.group_id.clone(),
            expected_revision: group.revision,
            kind: GroupChangeKind::AddMember {
                member: participant.profile.participant.clone(),
                role: runtime_group_role(participant.profile.role),
            },
            next_crypto_state: None,
        };
        store
            .apply_mls_backed_group_change(
                owner,
                owner_device_id,
                &change,
                &[MlsDeviceAdmission {
                    device_id: participant.device_id.clone(),
                    key_package: key_package.bytes,
                }],
            )
            .map_err(map_group_mls_error)?;
    }
    Ok(())
}

const fn runtime_group_role(role: ConferenceParticipantRole) -> GroupRole {
    match role {
        ConferenceParticipantRole::Owner => GroupRole::Owner,
        ConferenceParticipantRole::Host | ConferenceParticipantRole::Moderator => GroupRole::Admin,
        ConferenceParticipantRole::Speaker | ConferenceParticipantRole::Attendee => {
            GroupRole::Member
        }
    }
}

fn reconcile_runtime_call<S>(
    store: &S,
    input: &PrepareConferenceRuntimeInput,
    stable_command_id: &CommandId,
    owner: &ScopedPrincipal,
    ready: &[RuntimeReadyParticipant],
) -> Result<bool, CanonicalError>
where
    S: GroupStore + CallStore + GroupCallLookupStore,
{
    let calls = store
        .calls_for_group(&input.scope, &input.conference_id, 64)
        .map_err(map_store_error)?;
    if calls.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let mut live_calls = calls
        .into_iter()
        .filter(|call| call.signalling_state != CallSignallingState::Terminated)
        .collect::<Vec<_>>();
    if live_calls.len() > 1 {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }
    if let Some(call) = live_calls.pop() {
        return reconcile_existing_runtime_call(store, owner, call, ready);
    }
    if ready.len() < 2 {
        return Ok(false);
    }
    let group = store
        .group(&input.scope, &input.conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let mut participants = Vec::with_capacity(ready.len());
    participants.push(CallParticipant {
        principal: owner.principal.clone(),
        state: CallParticipantState::Accepted,
        joined_revision: 0,
        left_revision: None,
    });
    participants.extend(
        ready
            .iter()
            .filter(|participant| participant.profile.participant != owner.principal)
            .map(|participant| CallParticipant {
                principal: participant.profile.participant.clone(),
                state: CallParticipantState::Invited,
                joined_revision: 0,
                left_revision: None,
            }),
    );
    let call = CallSession {
        scope: input.scope.clone(),
        call_id: CallId::from_opaque(derived_id("call", stable_command_id)?),
        conversation: group.conversation,
        initiated_by: owner.principal.clone(),
        participants,
        signalling_state: CallSignallingState::Inviting,
        reconnecting_participant: None,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
    };
    store.create_call(owner, &call).map_err(map_store_error)?;
    Ok(true)
}

fn reconcile_existing_runtime_call<S>(
    store: &S,
    owner: &ScopedPrincipal,
    mut call: CallSession,
    ready: &[RuntimeReadyParticipant],
) -> Result<bool, CanonicalError>
where
    S: CallStore,
{
    if call.initiated_by != owner.principal
        || !call.participants.iter().any(|participant| {
            participant.principal == owner.principal
                && participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        })
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }
    for participant in ready {
        if participant.profile.participant == owner.principal
            || call.participants.iter().any(|candidate| {
                candidate.principal == participant.profile.participant
                    && matches!(
                        candidate.state,
                        CallParticipantState::Invited
                            | CallParticipantState::Ringing
                            | CallParticipantState::Accepted
                    )
                    && candidate.left_revision.is_none()
            })
        {
            continue;
        }
        let signal = CallSignal {
            event_id: runtime_event_id(
                "ca",
                call.revision,
                &participant.profile.participant,
            )?,
            scope: owner.scope.clone(),
            call_id: call.call_id.clone(),
            expected_revision: call.revision,
            kind: CallSignalKind::ParticipantUpdate {
                participant: participant.profile.participant.clone(),
                kind: CallParticipantUpdateKind::Add,
            },
        };
        store
            .apply_call_signal(owner, &signal)
            .map_err(map_store_error)?;
        call = store
            .call(&owner.scope, &call.call_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    }
    Ok(true)
}

fn runtime_event_id(
    prefix: &str,
    revision: u64,
    participant: &PrincipalRef,
) -> Result<EventId, CanonicalError> {
    OpaqueId::new(format!(
        "{prefix}-{revision}-{}",
        participant.principal_id.as_opaque().as_str()
    ))
    .map(EventId::from_opaque)
    .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn map_group_mls_error(error: GroupMlsStoreError) -> CanonicalError {
    match error {
        GroupMlsStoreError::Durable(error) => map_store_error(error),
        GroupMlsStoreError::ActorDeviceMismatch | GroupMlsStoreError::TargetDeviceMismatch => {
            CanonicalError::new(CanonicalErrorCode::PolicyDenied)
        }
        GroupMlsStoreError::InvalidBootstrap | GroupMlsStoreError::InvalidChangeMaterial => {
            CanonicalError::new(CanonicalErrorCode::Conflict)
        }
        GroupMlsStoreError::Mls(_) => CanonicalError::new(CanonicalErrorCode::Internal),
    }
}

fn conference_join_window(
    conference: &UniversalConferenceProfile,
    now_unix_ms: i64,
) -> Result<(i64, Option<i64>), CanonicalError> {
    let join_before_ms = i64::from(conference.schedule.join_before_seconds)
        .checked_mul(1000)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let opens_at = conference
        .schedule
        .starts_at_unix_ms
        .checked_sub(join_before_ms)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let closes_at = conference
        .schedule
        .planned_end_unix_ms
        .map(|planned_end| {
            let join_after_ms = i64::from(conference.schedule.join_after_seconds)
                .checked_mul(1000)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
            planned_end
                .checked_add(join_after_ms)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))
        })
        .transpose()?;
    if now_unix_ms < opens_at || closes_at.is_some_and(|close| now_unix_ms >= close) {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    Ok((opens_at, closes_at))
}

fn resolve_join_participant<S>(
    store: &S,
    input: &IssueJoinGrantInput,
) -> Result<UniversalConferenceParticipantProfile, CanonicalError>
where
    S: UniversalConferenceStore,
{
    let participant = participant_for_external(
        store,
        &input.scope,
        &input.conference_id,
        &input.integration_id,
        &input.external_user_id,
    )?;
    if !participant.active {
        return Err(CanonicalError::new(CanonicalErrorCode::NotFound));
    }
    Ok(participant)
}

fn resolve_join_device<S>(
    store: &S,
    scope: &TenantScope,
    participant: &PrincipalRef,
) -> Result<DeviceId, CanonicalError>
where
    S: PrincipalIdentityBindingStore + IdentityDeviceLookupStore,
{
    let identity_binding = store
        .principal_identity_binding(scope, participant)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    let devices = store
        .devices_for_identity(scope, &identity_binding.identity_id, 64)
        .map_err(map_store_error)?;
    if devices.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let mut active_devices = devices
        .into_iter()
        .filter(|device| device.state == DeviceLifecycleState::Active);
    match (active_devices.next(), active_devices.next()) {
        (Some(device), None) => Ok(device.device_id),
        (None, _) => Err(CanonicalError::new(CanonicalErrorCode::NotFound)),
        (Some(_), Some(_)) => Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
    }
}

fn resolve_join_call<S>(
    store: &S,
    scope: &TenantScope,
    conference_id: &GroupId,
    participant: &PrincipalRef,
) -> Result<CallId, CanonicalError>
where
    S: GroupCallLookupStore,
{
    let calls = store
        .calls_for_group(scope, conference_id, 64)
        .map_err(map_store_error)?;
    if calls.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let active_calls = calls
        .into_iter()
        .filter(|call| call.signalling_state != CallSignallingState::Terminated)
        .collect::<Vec<_>>();
    if active_calls.is_empty() {
        return Err(CanonicalError::new(CanonicalErrorCode::CapabilityMismatch));
    }
    let mut eligible = active_calls.into_iter().filter(|call| {
        call.participants.iter().any(|candidate| {
            &candidate.principal == participant
                && matches!(
                    candidate.state,
                    CallParticipantState::Invited
                        | CallParticipantState::Ringing
                        | CallParticipantState::Accepted
                )
                && candidate.left_revision.is_none()
        })
    });
    match (eligible.next(), eligible.next()) {
        (Some(call), None) => Ok(call.call_id),
        (None, _) => Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied)),
        (Some(_), Some(_)) => Err(CanonicalError::new(CanonicalErrorCode::Conflict)),
    }
}

fn issue_join_grant<S>(
    store: &S,
    issuer: &JoinTokenIssuer,
    input: IssueJoinGrantInput,
    now_unix_ms: i64,
) -> Result<pb::ConferenceJoinGrant, CanonicalError>
where
    S: UniversalConferenceStore
        + PrincipalIdentityBindingStore
        + IdentityDeviceLookupStore
        + GroupCallLookupStore,
{
    let conference = store
        .universal_conference_profile(&input.scope, &input.conference_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    if conference.integration_id != input.integration_id
        || !conference.entry_open
        || !matches!(
            conference.lifecycle,
            UniversalConferenceLifecycle::Waiting | UniversalConferenceLifecycle::Live
        )
    {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }

    let (opens_at, closes_at) = conference_join_window(&conference, now_unix_ms)?;
    let participant = resolve_join_participant(store, &input)?;
    let device_id = resolve_join_device(store, &input.scope, &participant.participant)?;
    let call_id = resolve_join_call(
        store,
        &input.scope,
        &input.conference_id,
        &participant.participant,
    )?;

    let ttl_ms = i64::from(input.ttl_seconds)
        .checked_mul(1000)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidArgument))?;
    let default_expiry = now_unix_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidArgument))?;
    let requested_expiry = input.not_after_unix_ms.unwrap_or(default_expiry);
    if input
        .not_before_unix_ms
        .is_some_and(|not_before| not_before < opens_at)
        || closes_at.is_some_and(|close| requested_expiry > close)
    {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }

    issuer
        .issue_with_policy(
            input.scope,
            call_id,
            participant.participant,
            Some(device_id),
            input.ttl_seconds,
            input.use_policy,
            input.not_before_unix_ms,
            input.not_after_unix_ms,
            now_unix_ms,
        )
        .map(|grant| pb::ConferenceJoinGrant {
            session_id: Some(pb_opaque(grant.claims.session_id.as_opaque())),
            join_url: grant.join_url,
            expires_at_unix_ms: grant.claims.expires_at_unix_ms,
        })
        .map_err(map_join_token_error)
}

fn revoke_join_grant<S>(
    store: &S,
    issuer: &JoinTokenIssuer,
    scope: &TenantScope,
    conference_id: &GroupId,
    integration_id: &IntegrationId,
    session_id: &SessionId,
) -> Result<(), CanonicalError>
where
    S: UniversalConferenceStore + GroupCallLookupStore,
{
    conference_for_integration(store, scope, conference_id, integration_id)?;
    let claims = issuer
        .grant_claims(scope, session_id)
        .map_err(map_join_token_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    let calls = store
        .calls_for_group(scope, conference_id, 64)
        .map_err(map_store_error)?;
    if calls.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    if !calls.iter().any(|call| call.call_id == claims.call_id) {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    issuer
        .revoke(scope, session_id)
        .map(|_| ())
        .map_err(map_join_token_error)
}

fn universal_capabilities() -> Result<pb::UniversalConferenceCapabilities, CanonicalError> {
    let mut capabilities = phase20_audio_capabilities();
    capabilities.extend(phase21_video_capabilities());
    capabilities.extend(phase22_media_e2ee_capabilities());
    capabilities.extend(phase29_sfu_capabilities());
    capabilities.extend(phase30_conference_capabilities());
    let capabilities = canonical_capabilities(&capabilities)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
    Ok(pb::UniversalConferenceCapabilities {
        capabilities: capabilities.iter().map(pb_capability).collect(),
        max_participants: u32::try_from(MAX_CALL_PARTICIPANTS)
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
        browser_realtime_gateway: false,
        production_webrtc: false,
        turn: false,
        recording: false,
        horizontal_sfu: false,
    })
}

fn pb_capability(value: &ucr_model::CapabilityDescriptor) -> pb::Capability {
    pb::Capability {
        id: value.id.clone(),
        maturity: (match value.maturity {
            CapabilityMaturity::Experimental => pb::CapabilityMaturity::Experimental,
            CapabilityMaturity::Prepared => pb::CapabilityMaturity::Prepared,
            CapabilityMaturity::Beta => pb::CapabilityMaturity::Beta,
            CapabilityMaturity::Production => pb::CapabilityMaturity::Production,
            CapabilityMaturity::Deprecated => pb::CapabilityMaturity::Deprecated,
            CapabilityMaturity::Disabled => pb::CapabilityMaturity::Disabled,
        }) as i32,
        extensions: value
            .extensions
            .iter()
            .map(|extension| pb::Extension {
                name: extension.name.clone(),
                critical: extension.critical,
                payload: extension.payload.clone(),
            })
            .collect(),
    }
}

const ATTENDANCE_EVENT_TYPES: [&str; 4] = [
    "ucr.conference.attendance.joined.v1",
    "ucr.conference.attendance.left.v1",
    "ucr.conference.attendance.reconnected.v1",
    "ucr.conference.attendance.media_ready.v1",
];
const MAX_ATTENDANCE_PROJECTION_EVENTS: usize = 16_384;

#[derive(Debug)]
struct AttendanceSessionProjection {
    session_id: SessionId,
    joined_at_unix_ms: i64,
    left_at_unix_ms: Option<i64>,
}

#[derive(Debug, Default)]
struct AttendanceProjectionState {
    sessions: Vec<AttendanceSessionProjection>,
    first_join_at_unix_ms: Option<i64>,
    last_leave_at_unix_ms: Option<i64>,
    first_media_ready_at_unix_ms: Option<i64>,
    join_count: u32,
    reconnect_count: u32,
    media_ready_count: u32,
}

#[derive(Debug)]
struct AttendanceObservation {
    session_id: SessionId,
    kind: pb::ConferenceAttendanceKind,
    occurred_at_unix_ms: i64,
}

fn participant_attendance<S>(
    store: &S,
    scope: &TenantScope,
    conference_id: &GroupId,
    integration_id: &IntegrationId,
    external_user_id: &[u8],
    now_unix_ms: i64,
) -> Result<pb::UniversalParticipantAttendance, CanonicalError>
where
    S: UniversalConferenceStore + GroupCallLookupStore + EventJournalStore,
{
    if now_unix_ms < 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::TemporarilyUnavailable,
        ));
    }
    conference_for_integration(store, scope, conference_id, integration_id)?;
    let participant = participant_for_external(
        store,
        scope,
        conference_id,
        integration_id,
        external_user_id,
    )?;
    let calls = store
        .calls_for_group(scope, conference_id, 64)
        .map_err(map_store_error)?;
    if calls.len() == 64 {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }
    let call_ids = calls
        .into_iter()
        .map(|call| call.call_id)
        .collect::<Vec<_>>();
    if call_ids.is_empty() {
        return Ok(empty_attendance(external_user_id));
    }
    let events = store
        .events_for_types(
            scope,
            &ATTENDANCE_EVENT_TYPES,
            MAX_ATTENDANCE_PROJECTION_EVENTS,
        )
        .map_err(map_store_error)?;
    if events.len() == MAX_ATTENDANCE_PROJECTION_EVENTS {
        return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
    }

    let mut state = AttendanceProjectionState::default();
    for event in &events {
        if let Some(observation) =
            decode_attendance_observation(event, scope, &participant.participant, &call_ids)?
        {
            apply_attendance_observation(&mut state, observation)?;
        }
    }
    finalize_attendance(external_user_id, state, now_unix_ms)
}

fn decode_attendance_observation(
    event: &ucr_model::EventEnvelope,
    scope: &TenantScope,
    participant: &PrincipalRef,
    call_ids: &[CallId],
) -> Result<Option<AttendanceObservation>, CanonicalError> {
    let attendance = pb::ConferenceAttendanceEvent::decode(event.payload.as_slice())
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let event_scope = attendance
        .scope
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))
        .and_then(|value| {
            decode_scope(value).map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
        })?;
    let call_id = CallId::from_opaque(
        decode_opaque(attendance.call_id)
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let event_participant = attendance
        .participant
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))
        .and_then(|value| {
            super::decode_principal_ref(value)
                .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
        })?;
    if event_scope != *scope || !call_ids.contains(&call_id) || event_participant != *participant {
        return Ok(None);
    }
    if attendance.occurred_at_unix_ms < 0
        || attendance.occurred_at_unix_ms != event.wall_time_unix_ms
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Internal));
    }
    let session_id = SessionId::from_opaque(
        decode_opaque(attendance.session_id)
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let kind = pb::ConferenceAttendanceKind::try_from(attendance.kind)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
    if kind != expected_attendance_kind(&event.event_type)? {
        return Err(CanonicalError::new(CanonicalErrorCode::Internal));
    }
    Ok(Some(AttendanceObservation {
        session_id,
        kind,
        occurred_at_unix_ms: attendance.occurred_at_unix_ms,
    }))
}

fn expected_attendance_kind(
    event_type: &str,
) -> Result<pb::ConferenceAttendanceKind, CanonicalError> {
    match event_type {
        "ucr.conference.attendance.joined.v1" => Ok(pb::ConferenceAttendanceKind::Joined),
        "ucr.conference.attendance.left.v1" => Ok(pb::ConferenceAttendanceKind::Left),
        "ucr.conference.attendance.reconnected.v1" => Ok(pb::ConferenceAttendanceKind::Reconnected),
        "ucr.conference.attendance.media_ready.v1" => Ok(pb::ConferenceAttendanceKind::MediaReady),
        _ => Err(CanonicalError::new(CanonicalErrorCode::Internal)),
    }
}

fn apply_attendance_observation(
    state: &mut AttendanceProjectionState,
    observation: AttendanceObservation,
) -> Result<(), CanonicalError> {
    match observation.kind {
        pb::ConferenceAttendanceKind::Joined => {
            if state
                .sessions
                .iter()
                .any(|session| session.session_id == observation.session_id)
            {
                return Err(CanonicalError::new(CanonicalErrorCode::Internal));
            }
            state.sessions.push(AttendanceSessionProjection {
                session_id: observation.session_id,
                joined_at_unix_ms: observation.occurred_at_unix_ms,
                left_at_unix_ms: None,
            });
            state.join_count = checked_increment(state.join_count)?;
            state.first_join_at_unix_ms = Some(
                state
                    .first_join_at_unix_ms
                    .map_or(observation.occurred_at_unix_ms, |current| {
                        current.min(observation.occurred_at_unix_ms)
                    }),
            );
        }
        pb::ConferenceAttendanceKind::Left => {
            let session = state
                .sessions
                .iter_mut()
                .find(|session| session.session_id == observation.session_id)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
            if session.left_at_unix_ms.is_some()
                || observation.occurred_at_unix_ms < session.joined_at_unix_ms
            {
                return Err(CanonicalError::new(CanonicalErrorCode::Internal));
            }
            session.left_at_unix_ms = Some(observation.occurred_at_unix_ms);
            state.last_leave_at_unix_ms = Some(
                state
                    .last_leave_at_unix_ms
                    .map_or(observation.occurred_at_unix_ms, |current| {
                        current.max(observation.occurred_at_unix_ms)
                    }),
            );
        }
        pb::ConferenceAttendanceKind::Reconnected => {
            require_active_attendance_session(state, &observation)?;
            state.reconnect_count = checked_increment(state.reconnect_count)?;
        }
        pb::ConferenceAttendanceKind::MediaReady => {
            require_active_attendance_session(state, &observation)?;
            state.media_ready_count = checked_increment(state.media_ready_count)?;
            state.first_media_ready_at_unix_ms = Some(
                state
                    .first_media_ready_at_unix_ms
                    .map_or(observation.occurred_at_unix_ms, |current| {
                        current.min(observation.occurred_at_unix_ms)
                    }),
            );
        }
        pb::ConferenceAttendanceKind::Unspecified => {
            return Err(CanonicalError::new(CanonicalErrorCode::Internal));
        }
    }
    Ok(())
}

fn require_active_attendance_session(
    state: &AttendanceProjectionState,
    observation: &AttendanceObservation,
) -> Result<(), CanonicalError> {
    let session = state
        .sessions
        .iter()
        .find(|session| session.session_id == observation.session_id)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    if session.left_at_unix_ms.is_some()
        || observation.occurred_at_unix_ms < session.joined_at_unix_ms
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Internal));
    }
    Ok(())
}

fn checked_increment(value: u32) -> Result<u32, CanonicalError> {
    value
        .checked_add(1)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn finalize_attendance(
    external_user_id: &[u8],
    state: AttendanceProjectionState,
    now_unix_ms: i64,
) -> Result<pb::UniversalParticipantAttendance, CanonicalError> {
    let mut total_connected_ms = 0_u64;
    let mut current_connected_ms = 0_u64;
    let mut connected = false;
    for session in state.sessions {
        let end = session.left_at_unix_ms.unwrap_or(now_unix_ms);
        if end < session.joined_at_unix_ms {
            return Err(CanonicalError::new(CanonicalErrorCode::Internal));
        }
        let duration = u64::try_from(end - session.joined_at_unix_ms)
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
        total_connected_ms = total_connected_ms
            .checked_add(duration)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
        if session.left_at_unix_ms.is_none() {
            connected = true;
            current_connected_ms = current_connected_ms
                .checked_add(duration)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
        }
    }
    Ok(pb::UniversalParticipantAttendance {
        external_user_id: external_user_id.to_vec(),
        first_join_at_unix_ms: state.first_join_at_unix_ms,
        last_leave_at_unix_ms: state.last_leave_at_unix_ms,
        first_media_ready_at_unix_ms: state.first_media_ready_at_unix_ms,
        total_connected_seconds: total_connected_ms / 1000,
        current_connected_seconds: current_connected_ms / 1000,
        join_count: state.join_count,
        reconnect_count: state.reconnect_count,
        media_ready_count: state.media_ready_count,
        connected,
    })
}

fn empty_attendance(external_user_id: &[u8]) -> pb::UniversalParticipantAttendance {
    pb::UniversalParticipantAttendance {
        external_user_id: external_user_id.to_vec(),
        first_join_at_unix_ms: None,
        last_leave_at_unix_ms: None,
        first_media_ready_at_unix_ms: None,
        total_connected_seconds: 0,
        current_connected_seconds: 0,
        join_count: 0,
        reconnect_count: 0,
        media_ready_count: 0,
        connected: false,
    }
}

const fn map_join_token_error(error: JoinTokenError) -> CanonicalError {
    let code = match error {
        JoinTokenError::InvalidBaseUrl
        | JoinTokenError::InvalidTtl
        | JoinTokenError::InvalidWindow => CanonicalErrorCode::InvalidArgument,
        JoinTokenError::Malformed
        | JoinTokenError::InvalidSignature
        | JoinTokenError::NotYetValid
        | JoinTokenError::Expired
        | JoinTokenError::UnknownGrant
        | JoinTokenError::Revoked
        | JoinTokenError::AlreadyUsed => CanonicalErrorCode::Unauthenticated,
        JoinTokenError::CapacityExceeded => CanonicalErrorCode::ResourceExhausted,
        JoinTokenError::StateUnavailable => CanonicalErrorCode::TemporarilyUnavailable,
        JoinTokenError::ClockOverflow
        | JoinTokenError::RandomUnavailable
        | JoinTokenError::Internal => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
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
            UniversalConferenceMode::Webinar
            | UniversalConferenceMode::Broadcast
            | UniversalConferenceMode::AudioRoom => (true, false, false, false),
        },
    }
}

fn pb_participant(
    value: &UniversalConferenceParticipantProfile,
) -> pb::UniversalConferenceParticipant {
    pb::UniversalConferenceParticipant {
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

fn validate_external_user_id(value: &[u8]) -> Result<(), CanonicalError> {
    if value.is_empty() || value.len() > 512 {
        return Err(invalid_argument());
    }
    Ok(())
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

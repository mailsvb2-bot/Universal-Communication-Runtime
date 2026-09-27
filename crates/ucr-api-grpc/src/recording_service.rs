use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, CallStore, ConferenceJoinGrantStore, DeviceLifecycleStore,
    DurableRecordStatus, DurableStoreError, PrincipalIdentityBindingStore, RecordingStore,
    ServiceAuditStore, ServiceCredentialStore, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_crypto::{MachineTokenPolicy, MachineTokenPublicKeySet};
use ucr_model::{
    CallParticipantState, CallSignallingState, PrincipalRef, RecordingConsent,
    RecordingConsentState, RecordingId, RecordingPolicy, RecordingSession, RecordingState,
    ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    CONFERENCE_RECORDING_MANAGE_PERMISSION, CanonicalError, CanonicalErrorCode,
    MAX_RECORDING_CONSENTS,
};
use ucr_realtime::JoinTokenIssuer;

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_opaque,
    decode_principal_ref, decode_scope,
    machine_api_auth::{
        MachineApiAuthentication, MachineBearerConfig, admit_machine_api,
        decode_machine_api_authentication,
    },
    pb, pb_acknowledgement, pb_error, pb_opaque, pb_principal_ref, pb_scope,
    realtime_service::{authenticate_realtime_bearer_claims, decode_bearer_token},
};
use ucr_protocol::acknowledgement_for;

pub struct GrpcRecordingService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    join_issuer: Arc<JoinTokenIssuer>,
    machine_bearer: Option<Arc<MachineBearerConfig>>,
    recording_available: bool,
}

impl<C, A, S> GrpcRecordingService<C, A, S> {
    #[must_use]
    pub fn new(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        join_issuer: Arc<JoinTokenIssuer>,
        recording_available: bool,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            join_issuer,
            machine_bearer: None,
            recording_available,
        }
    }

    #[must_use]
    pub fn with_machine_bearer_auth(
        mut self,
        verification_keys: Arc<MachineTokenPublicKeySet>,
        policy: MachineTokenPolicy,
    ) -> Self {
        self.machine_bearer = Some(Arc::new(MachineBearerConfig {
            verification_keys,
            policy,
        }));
        self
    }
}

impl<C, A, S> Clone for GrpcRecordingService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            join_issuer: Arc::clone(&self.join_issuer),
            machine_bearer: self.machine_bearer.as_ref().map(Arc::clone),
            recording_available: self.recording_available,
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcRecordingService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcRecordingService")
            .field("recording_available", &self.recording_available)
            .finish_non_exhaustive()
    }
}

impl<C, A, S> GrpcRecordingService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    fn require_available(&self) -> Result<(), CanonicalError> {
        if self.recording_available {
            Ok(())
        } else {
            Err(CanonicalError::new(CanonicalErrorCode::CapabilityMismatch))
        }
    }

    fn admit_management(
        &self,
        scope: &TenantScope,
        authentication: MachineApiAuthentication,
    ) -> Result<ScopedPrincipal, CanonicalError> {
        self.require_available()?;
        admit_machine_api(
            &*self.clock,
            &*self.authorization,
            &*self.store,
            self.machine_bearer.as_deref(),
            scope,
            authentication,
            CONFERENCE_RECORDING_MANAGE_PERMISSION,
        )
    }

    fn now(&self) -> Result<i64, CanonicalError> {
        self.clock
            .now_unix_ms()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))
    }
}

#[must_use]
pub fn recording_service_server<C, A, S>(
    service: GrpcRecordingService<C, A, S>,
) -> pb::recording_service_server::RecordingServiceServer<GrpcRecordingService<C, A, S>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + RecordingStore
        + CallStore
        + ConferenceJoinGrantStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + 'static,
{
    pb::recording_service_server::RecordingServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S> pb::recording_service_server::RecordingService for GrpcRecordingService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + RecordingStore
        + CallStore
        + ConferenceJoinGrantStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + 'static,
{
    async fn request_recording(
        &self,
        request: Request<pb::RecordingRequest>,
    ) -> Result<Response<pb::RecordingRequestResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let decoded = decode_recording_request(request.into_inner());
        let result = match (authentication, decoded) {
            (Ok(authentication), Ok((scope, recording_id, call_id, policy))) => {
                self.request_recording_inner(
                    authentication,
                    &scope,
                    &recording_id,
                    call_id,
                    policy,
                )
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RecordingRequestResponse {
            result: Some(match result {
                Ok(recording) => {
                    pb::recording_request_response::Result::Recording(pb_recording(&recording))
                }
                Err(error) => pb::recording_request_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_recording(
        &self,
        request: Request<pb::RecordingGetRequest>,
    ) -> Result<Response<pb::RecordingGetResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded = decode_recording_lookup(body.scope, body.recording_id);
        let result = match (authentication, decoded) {
            (Ok(authentication), Ok((scope, recording_id))) => {
                self.admit_management(&scope, authentication).and_then(|_| {
                    self.store
                        .recording(scope, recording_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RecordingGetResponse {
            result: Some(match result {
                Ok(recording) => {
                    pb::recording_get_response::Result::Recording(pb_recording(&recording))
                }
                Err(error) => pb::recording_get_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn set_recording_consent(
        &self,
        request: Request<pb::RecordingSetConsentRequest>,
    ) -> Result<Response<pb::RecordingSetConsentResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let body = request.into_inner();
        let decoded = decode_consent_request(body);
        let result = match (token, decoded) {
            (Ok(token), Ok((scope, recording_id, participant, state, expected_revision))) => {
                self.require_available().and_then(|()| {
                    let claims = authenticate_realtime_bearer_claims(
                        &*self.store,
                        &self.join_issuer,
                        &token,
                        self.now()?,
                    )?;
                    if claims.scope != scope || claims.participant != participant {
                        return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
                    }
                    let recording = self
                        .store
                        .recording(scope, recording_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
                    if claims.call_id != recording.call_id {
                        return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
                    }
                    let scoped = ScopedPrincipal {
                        scope: scope.clone(),
                        principal: participant.clone(),
                    };
                    let call = self
                        .store
                        .call_for_participant(&scoped, &scope, &recording.call_id)
                        .map_err(map_store_error)?
                        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PermissionDenied))?;
                    let accepted = call.participants.iter().any(|item| {
                        item.principal == participant
                            && item.state == CallParticipantState::Accepted
                            && item.left_revision.is_none()
                    });
                    if !accepted {
                        return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
                    }
                    self.store
                        .set_recording_consent(
                            &scope,
                            &recording_id,
                            expected_revision,
                            &participant,
                            state,
                            self.now()?,
                        )
                        .map_err(map_store_error)
                })
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RecordingSetConsentResponse {
            result: Some(match result {
                Ok(recording) => {
                    pb::recording_set_consent_response::Result::Recording(pb_recording(&recording))
                }
                Err(error) => pb::recording_set_consent_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn start_recording(
        &self,
        request: Request<pb::RecordingStartRequest>,
    ) -> Result<Response<pb::RecordingStartResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded =
            decode_recording_mutation(body.scope, body.recording_id, body.expected_revision);
        let result =
            self.management_transition(authentication, decoded, RecordingStore::start_recording);
        Ok(Response::new(pb::RecordingStartResponse {
            result: Some(match result {
                Ok(recording) => {
                    pb::recording_start_response::Result::Recording(pb_recording(&recording))
                }
                Err(error) => pb::recording_start_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn stop_recording(
        &self,
        request: Request<pb::RecordingStopRequest>,
    ) -> Result<Response<pb::RecordingStopResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded =
            decode_recording_mutation(body.scope, body.recording_id, body.expected_revision);
        let result =
            self.management_transition(authentication, decoded, RecordingStore::stop_recording);
        Ok(Response::new(pb::RecordingStopResponse {
            result: Some(match result {
                Ok(recording) => {
                    pb::recording_stop_response::Result::Recording(pb_recording(&recording))
                }
                Err(error) => pb::recording_stop_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn delete_recording(
        &self,
        request: Request<pb::RecordingDeleteRequest>,
    ) -> Result<Response<pb::RecordingDeleteResponse>, Status> {
        let authentication = decode_machine_api_authentication(request.metadata());
        let body = request.into_inner();
        let decoded =
            decode_recording_mutation(body.scope, body.recording_id, body.expected_revision);
        let recording_id = decoded.as_ref().ok().map(|(_, id, _)| id.clone());
        let result =
            self.management_transition(authentication, decoded, RecordingStore::delete_recording);
        Ok(Response::new(pb::RecordingDeleteResponse {
            result: Some(match result {
                Ok(_) => pb::recording_delete_response::Result::Acknowledgement(
                    pb_acknowledgement(acknowledgement_for(
                        recording_id
                            .expect("successful recording delete has decoded id")
                            .as_opaque()
                            .clone(),
                    )),
                ),
                Err(error) => pb::recording_delete_response::Result::Error(pb_error(error)),
            }),
        }))
    }
}

impl<C, A, S> GrpcRecordingService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + RecordingStore + CallStore,
{
    fn request_recording_inner(
        &self,
        authentication: MachineApiAuthentication,
        scope: &TenantScope,
        recording_id: &RecordingId,
        call_id: ucr_model::CallId,
        policy: RecordingPolicy,
    ) -> Result<RecordingSession, CanonicalError> {
        let actor = self.admit_management(scope, authentication)?;
        if let Some(existing) = self
            .store
            .recording(scope, recording_id)
            .map_err(map_store_error)?
        {
            if recording_request_matches(&existing, &call_id, &policy, &actor.principal) {
                return Ok(existing);
            }
            return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
        }

        let call = self
            .store
            .call(scope, &call_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
        if call.signalling_state == CallSignallingState::Terminated {
            return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
        }

        let participants = call
            .participants
            .iter()
            .filter(|participant| {
                participant.state == CallParticipantState::Accepted
                    && participant.left_revision.is_none()
            })
            .map(|participant| RecordingConsent {
                participant: participant.principal.clone(),
                state: RecordingConsentState::Pending,
                decided_at_unix_ms: 0,
            })
            .collect::<Vec<_>>();
        if participants.is_empty() || participants.len() > MAX_RECORDING_CONSENTS {
            return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
        }

        let now = self.now()?;
        let retention_ms = i64::try_from(policy.retention_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidArgument))?;
        let expires_at_unix_ms = now
            .checked_add(retention_ms)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidArgument))?;
        let recording = RecordingSession {
            scope: scope.clone(),
            recording_id: recording_id.clone(),
            call_id,
            requested_by: actor.principal,
            state: if policy.require_all_participant_consent {
                RecordingState::WaitingForConsent
            } else {
                RecordingState::Ready
            },
            policy,
            consents: participants,
            requested_at_unix_ms: now,
            started_at_unix_ms: None,
            stopped_at_unix_ms: None,
            expires_at_unix_ms,
            revision: 1,
        };

        match self.store.persist_recording(&recording) {
            Ok(DurableRecordStatus::Persisted | DurableRecordStatus::Duplicate) => self
                .store
                .recording(scope, recording_id)
                .map_err(map_store_error)?
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal)),
            Err(DurableStoreError::Conflict) => {
                let winner = self
                    .store
                    .recording(scope, recording_id)
                    .map_err(map_store_error)?
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Conflict))?;
                if recording_request_matches(
                    &winner,
                    &recording.call_id,
                    &recording.policy,
                    &recording.requested_by,
                ) {
                    Ok(winner)
                } else {
                    Err(CanonicalError::new(CanonicalErrorCode::Conflict))
                }
            }
            Err(error) => Err(map_store_error(error)),
        }
    }
}

impl<C, A, S> GrpcRecordingService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + RecordingStore,
{
    fn management_transition<F>(
        &self,
        authentication: Result<MachineApiAuthentication, CanonicalError>,
        decoded: Result<(TenantScope, RecordingId, u64), CanonicalError>,
        transition: F,
    ) -> Result<RecordingSession, CanonicalError>
    where
        F: FnOnce(
            &S,
            &TenantScope,
            &RecordingId,
            u64,
            i64,
        ) -> Result<RecordingSession, DurableStoreError>,
    {
        match (authentication, decoded) {
            (Ok(authentication), Ok((scope, recording_id, expected_revision))) => {
                self.admit_management(scope, authentication)?;
                transition(
                    &*self.store,
                    &scope,
                    &recording_id,
                    expected_revision,
                    self.now()?,
                )
                .map_err(map_store_error)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

fn recording_request_matches(
    existing: &RecordingSession,
    call_id: &ucr_model::CallId,
    policy: &RecordingPolicy,
    requested_by: &PrincipalRef,
) -> bool {
    existing.call_id == *call_id
        && existing.policy == *policy
        && existing.requested_by == *requested_by
}

fn decode_recording_request(
    value: pb::RecordingRequest,
) -> Result<(TenantScope, RecordingId, ucr_model::CallId, RecordingPolicy), CanonicalError> {
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let recording_id = RecordingId::from_opaque(decode_opaque(value.recording_id)?);
    let call_id = ucr_model::CallId::from_opaque(decode_opaque(value.call_id)?);
    let policy = value.policy.ok_or_else(invalid_argument)?;
    Ok((
        scope,
        recording_id,
        call_id,
        RecordingPolicy {
            require_all_participant_consent: policy.require_all_participant_consent,
            notify_all_participants: policy.notify_all_participants,
            retention_seconds: policy.retention_seconds,
            policy_reference: policy.policy_reference,
        },
    ))
}

fn decode_recording_lookup(
    scope: Option<pb::TenantScope>,
    recording_id: Option<pb::OpaqueId>,
) -> Result<(TenantScope, RecordingId), CanonicalError> {
    Ok((
        decode_scope(scope.ok_or_else(invalid_argument)?)?,
        RecordingId::from_opaque(decode_opaque(recording_id)?),
    ))
}

fn decode_recording_mutation(
    scope: Option<pb::TenantScope>,
    recording_id: Option<pb::OpaqueId>,
    expected_revision: u64,
) -> Result<(TenantScope, RecordingId, u64), CanonicalError> {
    if expected_revision == 0 {
        return Err(invalid_argument());
    }
    let (scope, recording_id) = decode_recording_lookup(scope, recording_id)?;
    Ok((scope, recording_id, expected_revision))
}

fn decode_consent_request(
    value: pb::RecordingSetConsentRequest,
) -> Result<
    (
        TenantScope,
        RecordingId,
        PrincipalRef,
        RecordingConsentState,
        u64,
    ),
    CanonicalError,
> {
    if value.expected_revision == 0 {
        return Err(invalid_argument());
    }
    let scope = decode_scope(value.scope.ok_or_else(invalid_argument)?)?;
    let recording_id = RecordingId::from_opaque(decode_opaque(value.recording_id)?);
    let consent = value.consent.ok_or_else(invalid_argument)?;
    let participant = decode_principal_ref(consent.participant.ok_or_else(invalid_argument)?)?;
    let state =
        match pb::RecordingConsentState::try_from(consent.state).map_err(|_| invalid_argument())? {
            pb::RecordingConsentState::Granted => RecordingConsentState::Granted,
            pb::RecordingConsentState::Denied => RecordingConsentState::Denied,
            pb::RecordingConsentState::Revoked => RecordingConsentState::Revoked,
            pb::RecordingConsentState::Pending | pb::RecordingConsentState::Unspecified => {
                return Err(invalid_argument());
            }
        };
    Ok((
        scope,
        recording_id,
        participant,
        state,
        value.expected_revision,
    ))
}

fn pb_recording(value: &RecordingSession) -> pb::RecordingSession {
    pb::RecordingSession {
        scope: Some(pb_scope(&value.scope)),
        recording_id: Some(pb_opaque(value.recording_id.as_opaque())),
        call_id: Some(pb_opaque(value.call_id.as_opaque())),
        requested_by: Some(pb_principal_ref(&value.requested_by)),
        policy: Some(pb::RecordingPolicy {
            require_all_participant_consent: value.policy.require_all_participant_consent,
            notify_all_participants: value.policy.notify_all_participants,
            retention_seconds: value.policy.retention_seconds,
            policy_reference: value.policy.policy_reference.clone(),
        }),
        state: match value.state {
            RecordingState::WaitingForConsent => pb::RecordingState::WaitingForConsent as i32,
            RecordingState::Ready => pb::RecordingState::Ready as i32,
            RecordingState::Active => pb::RecordingState::Active as i32,
            RecordingState::Stopped => pb::RecordingState::Stopped as i32,
            RecordingState::Expired => pb::RecordingState::Expired as i32,
            RecordingState::Deleted => pb::RecordingState::Deleted as i32,
        },
        consents: value.consents.iter().map(pb_consent).collect(),
        requested_at_unix_ms: value.requested_at_unix_ms,
        started_at_unix_ms: value.started_at_unix_ms,
        stopped_at_unix_ms: value.stopped_at_unix_ms,
        expires_at_unix_ms: value.expires_at_unix_ms,
        revision: value.revision,
    }
}

fn pb_consent(value: &RecordingConsent) -> pb::RecordingConsent {
    pb::RecordingConsent {
        participant: Some(pb_principal_ref(&value.participant)),
        state: match value.state {
            RecordingConsentState::Pending => pb::RecordingConsentState::Pending as i32,
            RecordingConsentState::Granted => pb::RecordingConsentState::Granted as i32,
            RecordingConsentState::Denied => pb::RecordingConsentState::Denied as i32,
            RecordingConsentState::Revoked => pb::RecordingConsentState::Revoked as i32,
        },
        decided_at_unix_ms: value.decided_at_unix_ms,
    }
}

fn invalid_argument() -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidArgument)
}

const fn map_store_error(error: DurableStoreError) -> CanonicalError {
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

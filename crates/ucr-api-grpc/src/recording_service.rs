use std::{fmt, sync::Arc};

use prost::Message;
use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, CallStore, CommandAcceptanceStore, ConferenceJoinGrantStore,
    DeviceLifecycleStore, DurableRecordStatus, DurableStoreError, EventJournalStore,
    PrincipalIdentityBindingStore, RecordingStore, ServiceAuditStore, ServiceCredentialStore,
    ServiceQuotaClock, ServiceQuotaStore, generate_opaque_id,
};
use ucr_crypto::{MachineTokenPolicy, MachineTokenPublicKeySet};
use ucr_model::{
    ActorId, ActorKind, ActorRef, CallParticipantState, CallSignallingState, CommandId,
    CorrelationContext, DeviceId, DeviceRef, EventEnvelope, EventId, IdentityId, OpaqueId,
    PrincipalId, PrincipalRef, ProtocolVersion, RecordingConsent, RecordingConsentState,
    RecordingId, RecordingPolicy, RecordingSession, RecordingState, ScopedPrincipal, TenantScope,
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
    mutation_idempotency::accept_mutation_receipt,
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
        + CommandAcceptanceStore
        + EventJournalStore
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
        + CommandAcceptanceStore
        + EventJournalStore
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
                self.request_recording_inner(authentication, &scope, &recording_id, call_id, policy)
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
                        .recording(&scope, &recording_id)
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
                        .recording(&scope, &recording_id)
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
                    let now_unix_ms = self.now()?;
                    let event = if recording.state == RecordingState::Active
                        && state != RecordingConsentState::Granted
                    {
                        Some(recording_lifecycle_event(
                            &recording,
                            RecordingState::Stopped,
                            fresh_event_id()?,
                            None,
                            None,
                            now_unix_ms,
                        )?)
                    } else {
                        None
                    };
                    self.store
                        .set_recording_consent_with_event(
                            &scope,
                            &recording_id,
                            expected_revision,
                            &participant,
                            state,
                            now_unix_ms,
                            event.as_ref(),
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
        let payload = body.encode_to_vec();
        let decoded = decode_recording_mutation(
            body.scope,
            body.recording_id,
            body.expected_revision,
            body.idempotency_key,
        );
        let result = self.management_lifecycle_transition(
            authentication,
            decoded,
            payload,
            RecordingLifecycleMutation::Start,
        );
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
        let payload = body.encode_to_vec();
        let decoded = decode_recording_mutation(
            body.scope,
            body.recording_id,
            body.expected_revision,
            body.idempotency_key,
        );
        let result = self.management_lifecycle_transition(
            authentication,
            decoded,
            payload,
            RecordingLifecycleMutation::Stop,
        );
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
        let payload = body.encode_to_vec();
        let decoded = decode_recording_mutation(
            body.scope,
            body.recording_id,
            body.expected_revision,
            body.idempotency_key,
        );
        let acknowledgement_id = decoded.as_ref().ok().map(|(_, id, _, _)| id.clone());
        let result = self.management_lifecycle_transition(
            authentication,
            decoded,
            payload,
            RecordingLifecycleMutation::Delete,
        );
        Ok(Response::new(pb::RecordingDeleteResponse {
            result: Some(match result {
                Ok(_) => pb::recording_delete_response::Result::Acknowledgement(
                    pb_acknowledgement(acknowledgement_for(
                        acknowledgement_id
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordingLifecycleMutation {
    Start,
    Stop,
    Delete,
}

impl RecordingLifecycleMutation {
    const fn command_type(self) -> &'static str {
        match self {
            Self::Start => "ucr.recording.start.v1",
            Self::Stop => "ucr.recording.stop.v1",
            Self::Delete => "ucr.recording.delete.v1",
        }
    }

    const fn target_state(self) -> RecordingState {
        match self {
            Self::Start => RecordingState::Active,
            Self::Stop => RecordingState::Stopped,
            Self::Delete => RecordingState::Deleted,
        }
    }
}

impl<C, A, S> GrpcRecordingService<C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + CommandAcceptanceStore
        + EventJournalStore
        + RecordingStore,
{
    fn management_lifecycle_transition(
        &self,
        authentication: Result<MachineApiAuthentication, CanonicalError>,
        decoded: Result<(TenantScope, RecordingId, u64, Option<String>), CanonicalError>,
        payload: Vec<u8>,
        mutation: RecordingLifecycleMutation,
    ) -> Result<RecordingSession, CanonicalError> {
        let (authentication, (scope, recording_id, expected_revision, idempotency_key)) =
            match (authentication, decoded) {
                (Ok(authentication), Ok(decoded)) => (authentication, decoded),
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
        self.admit_management(&scope, authentication)?;

        let accepted = if let Some(key) = idempotency_key.as_deref() {
            Some(accept_mutation_receipt(
                &*self.store,
                &scope,
                mutation.command_type(),
                key,
                payload,
            )?)
        } else {
            None
        };

        let event_id = if let Some(accepted) = accepted.as_ref() {
            recording_event_id(&accepted.command_id)?
        } else {
            fresh_event_id()?
        };

        if let Some(accepted) = accepted.as_ref().filter(|accepted| accepted.duplicate)
            && let Some(existing_event) = self
                .store
                .event(&scope, &event_id)
                .map_err(map_store_error)?
        {
            validate_applied_recording_event(
                &existing_event,
                &scope,
                &recording_id,
                mutation,
                &accepted.command_id,
                idempotency_key
                    .as_deref()
                    .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?,
            )?;
            return self
                .store
                .recording(&scope, &recording_id)
                .map_err(map_store_error)?
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal));
        }

        let current = self
            .store
            .recording(&scope, &recording_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;

        if current.revision != expected_revision {
            return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
        }
        if mutation == RecordingLifecycleMutation::Delete
            && current.state == RecordingState::Deleted
        {
            return Ok(current);
        }

        let now_unix_ms = self.now()?;
        let event = recording_lifecycle_event(
            &current,
            mutation.target_state(),
            event_id,
            accepted.as_ref().map(|value| &value.command_id),
            idempotency_key.as_deref(),
            now_unix_ms,
        )?;

        match mutation {
            RecordingLifecycleMutation::Start => self.store.start_recording_with_event(
                &scope,
                &recording_id,
                expected_revision,
                now_unix_ms,
                &event,
            ),
            RecordingLifecycleMutation::Stop => self.store.stop_recording_with_event(
                &scope,
                &recording_id,
                expected_revision,
                now_unix_ms,
                &event,
            ),
            RecordingLifecycleMutation::Delete => self.store.delete_recording_with_event(
                &scope,
                &recording_id,
                expected_revision,
                now_unix_ms,
                &event,
            ),
        }
        .map_err(map_store_error)
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
    idempotency_key: Option<String>,
) -> Result<(TenantScope, RecordingId, u64, Option<String>), CanonicalError> {
    if expected_revision == 0 {
        return Err(invalid_argument());
    }
    let (scope, recording_id) = decode_recording_lookup(scope, recording_id)?;
    if idempotency_key.as_ref().is_some_and(|value| value.is_empty()) {
        return Err(invalid_argument());
    }
    Ok((scope, recording_id, expected_revision, idempotency_key))
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

const fn pb_recording_state(value: RecordingState) -> pb::RecordingState {
    match value {
        RecordingState::WaitingForConsent => pb::RecordingState::WaitingForConsent,
        RecordingState::Ready => pb::RecordingState::Ready,
        RecordingState::Active => pb::RecordingState::Active,
        RecordingState::Stopped => pb::RecordingState::Stopped,
        RecordingState::Expired => pb::RecordingState::Expired,
        RecordingState::Deleted => pb::RecordingState::Deleted,
    }
}

const fn recording_lifecycle_event_type(state: RecordingState) -> Option<&'static str> {
    match state {
        RecordingState::Active => Some("ucr.recording.started"),
        RecordingState::Stopped => Some("ucr.recording.stopped"),
        RecordingState::Expired => Some("ucr.recording.expired"),
        RecordingState::Deleted => Some("ucr.recording.deleted"),
        RecordingState::WaitingForConsent | RecordingState::Ready => None,
    }
}

fn validate_applied_recording_event(
    event: &EventEnvelope,
    scope: &TenantScope,
    recording_id: &RecordingId,
    mutation: RecordingLifecycleMutation,
    command_id: &CommandId,
    idempotency_key: &str,
) -> Result<(), CanonicalError> {
    let expected_type = recording_lifecycle_event_type(mutation.target_state())
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    if event.scope != *scope
        || event.event_type != expected_type
        || event.correlation.causation_id.as_ref() != Some(command_id.as_opaque())
        || event.correlation.idempotency_key.as_deref() != Some(idempotency_key)
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }
    let payload = pb::RecordingLifecycleEvent::decode(event.payload.as_slice())
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Conflict))?;
    let payload_recording_id = decode_opaque(payload.recording_id)
        .map(RecordingId::from_opaque)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Conflict))?;
    let payload_state = pb::RecordingState::try_from(payload.current)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Conflict))?;
    if payload_recording_id != *recording_id
        || payload_state != pb_recording_state(mutation.target_state())
        || payload.revision != event.logical_order
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
    }
    Ok(())
}

fn recording_event_id(command_id: &CommandId) -> Result<EventId, CanonicalError> {
    OpaqueId::new(format!(
        "recording-event-{}",
        command_id.as_opaque().as_str()
    ))
    .map(EventId::from_opaque)
    .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn fresh_event_id() -> Result<EventId, CanonicalError> {
    generate_opaque_id()
        .map(EventId::from_opaque)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn fresh_actor_id() -> Result<ActorId, CanonicalError> {
    generate_opaque_id()
        .map(ActorId::from_opaque)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn fresh_device_id() -> Result<DeviceId, CanonicalError> {
    generate_opaque_id()
        .map(DeviceId::from_opaque)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn fresh_identity_id() -> Result<IdentityId, CanonicalError> {
    generate_opaque_id()
        .map(IdentityId::from_opaque)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn recording_lifecycle_event(
    current: &RecordingSession,
    target: RecordingState,
    event_id: EventId,
    command_id: Option<&CommandId>,
    idempotency_key: Option<&str>,
    occurred_at_unix_ms: i64,
) -> Result<EventEnvelope, CanonicalError> {
    let event_type = recording_lifecycle_event_type(target)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let revision = current
        .revision
        .checked_add(1)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let payload = pb::RecordingLifecycleEvent {
        scope: Some(pb_scope(&current.scope)),
        recording_id: Some(pb_opaque(current.recording_id.as_opaque())),
        call_id: Some(pb_opaque(current.call_id.as_opaque())),
        previous: pb_recording_state(current.state) as i32,
        current: pb_recording_state(target) as i32,
        revision,
        occurred_at_unix_ms,
    }
    .encode_to_vec();
    let correlation_id = command_id
        .map(|value| value.as_opaque().clone())
        .unwrap_or_else(|| event_id.as_opaque().clone());
    Ok(EventEnvelope {
        event_id,
        scope: current.scope.clone(),
        event_type: event_type.to_owned(),
        payload,
        actor: ActorRef {
            actor_id: fresh_actor_id()?,
            kind: ActorKind::System,
            on_behalf_of: Some(PrincipalId::from_opaque(
                current.requested_by.principal_id.as_opaque().clone(),
            )),
        },
        source_device: DeviceRef {
            device_id: fresh_device_id()?,
            identity_id: fresh_identity_id()?,
        },
        wall_time_unix_ms: occurred_at_unix_ms,
        logical_order: revision,
        correlation: CorrelationContext {
            correlation_id,
            causation_id: command_id.map(|value| value.as_opaque().clone()),
            idempotency_key: idempotency_key.map(str::to_owned),
        },
        schema_version: ProtocolVersion::new(1, 0),
        integrity_metadata: Vec::new(),
        extensions: Vec::new(),
    })
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
        state: pb_recording_state(value.state) as i32,
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

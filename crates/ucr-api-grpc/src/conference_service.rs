use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_conference::{
    ConferenceError, ConferenceRuntime, ConferenceRuntimeState, PreparedConferenceCapabilities,
};
use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, DurableStoreError, GroupStore,
    PrincipalIdentityBindingStore, ServiceAuditStore, ServiceCredentialSecret,
    ServiceCredentialStore, ServicePrincipalRequestGate, ServiceQuotaClock, ServiceQuotaStore,
};
use ucr_crypto::TrustedSigningKeyResolver;
use ucr_media_e2ee::PreparedGroupMediaE2eeCapabilities;
use ucr_model::{
    AuthorizationRequest, CallId, CallParticipantState, ConferenceMediaSubscription,
    ConferenceSnapshot, ConferenceStart, ConferenceSubscriptionSet, ConferenceTopology, DeviceId,
    DeviceLifecycleState, GroupId, MediaKind, PrincipalKind, PrincipalRef, ScopedPrincipal,
    TenantScope,
};
use ucr_protocol::{
    CALL_OBSERVE_PERMISSION, CALL_SIGNAL_PERMISSION, CALL_START_PERMISSION,
    CONFERENCE_JOIN_ISSUE_PERMISSION, CONFERENCE_SUBSCRIBE_PERMISSION, CanonicalError,
    CanonicalErrorCode, ConferenceProtocolError, acknowledgement_for,
};
use ucr_realtime::{JoinTokenError, JoinTokenIssuer};
use ucr_sfu::PreparedSfuCapabilities;

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_call_signal,
    decode_credentials, decode_opaque, decode_principal_ref, decode_scope, invalid_argument, pb,
    pb_acknowledgement, pb_call_session, pb_error, pb_opaque,
};

/// Stable public Conference facade over the canonical Call/Group/MLS/SFU owners.
pub struct GrpcConferenceService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    state: Arc<ConferenceRuntimeState>,
    join_issuer: Option<Arc<JoinTokenIssuer>>,
}

impl<C, A, S> GrpcConferenceService<C, A, S> {
    #[must_use]
    pub fn new(clock: Arc<C>, authorization: Arc<A>, store: Arc<S>) -> Self {
        Self {
            clock,
            authorization,
            store,
            state: Arc::new(ConferenceRuntimeState::new()),
            join_issuer: None,
        }
    }

    #[must_use]
    pub fn with_join_issuer(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        join_issuer: Arc<JoinTokenIssuer>,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            state: Arc::new(ConferenceRuntimeState::new()),
            join_issuer: Some(join_issuer),
        }
    }

    #[must_use]
    pub const fn with_state(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        state: Arc<ConferenceRuntimeState>,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            state,
            join_issuer: None,
        }
    }

    #[must_use]
    pub const fn with_state_and_join_issuer(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        state: Arc<ConferenceRuntimeState>,
        join_issuer: Arc<JoinTokenIssuer>,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            state,
            join_issuer: Some(join_issuer),
        }
    }
}

impl<C, A, S> Clone for GrpcConferenceService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            state: Arc::clone(&self.state),
            join_issuer: self.join_issuer.as_ref().map(Arc::clone),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcConferenceService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcConferenceService")
            .finish_non_exhaustive()
    }
}

impl<C, A, S> GrpcConferenceService<C, A, S>
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
pub fn conference_service_server<C, A, S>(
    service: GrpcConferenceService<C, A, S>,
) -> pb::conference_service_server::ConferenceServiceServer<GrpcConferenceService<C, A, S>>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + 'static,
{
    pb::conference_service_server::ConferenceServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S> pb::conference_service_server::ConferenceService for GrpcConferenceService<C, A, S>
where
    C: ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + 'static,
{
    async fn start_conference(
        &self,
        request: Request<pb::ConferenceStartRequest>,
    ) -> Result<Response<pb::ConferenceStartResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let start = request
            .into_inner()
            .conference
            .ok_or_else(invalid_argument)
            .and_then(decode_conference_start);
        let result = match (credentials, start) {
            (Ok((credential_id, secret)), Ok(start)) => self
                .admit(&start.scope, &credential_id, &secret, CALL_START_PERMISSION)
                .and_then(|actor| {
                    conference_runtime(self)
                        .start(&actor, &start)
                        .map(|(_, snapshot)| pb_conference_snapshot(&snapshot))
                        .map_err(|error| map_conference_error(&error))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::ConferenceStartResponse {
            result: Some(match result {
                Ok(conference) => pb::conference_start_response::Result::Conference(conference),
                Err(error) => pb::conference_start_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn get_conference(
        &self,
        request: Request<pb::ConferenceGetRequest>,
    ) -> Result<Response<pb::ConferenceGetResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let lookup = decode_conference_lookup(request.into_inner());
        let result = match (credentials, lookup) {
            (Ok((credential_id, secret)), Ok((scope, call_id))) => self
                .admit(&scope, &credential_id, &secret, CALL_OBSERVE_PERMISSION)
                .and_then(|actor| {
                    conference_runtime(self)
                        .snapshot(&actor, &scope, &call_id)
                        .map(|snapshot| pb_conference_snapshot(&snapshot))
                        .map_err(|error| map_conference_error(&error))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::ConferenceGetResponse {
            result: Some(match result {
                Ok(conference) => pb::conference_get_response::Result::Conference(conference),
                Err(error) => pb::conference_get_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn signal_conference(
        &self,
        request: Request<pb::ConferenceSignalRequest>,
    ) -> Result<Response<pb::ConferenceSignalResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let signal = request
            .into_inner()
            .signal
            .ok_or_else(invalid_argument)
            .and_then(decode_call_signal);
        let result = match (credentials, signal) {
            (Ok((credential_id, secret)), Ok(signal)) => self
                .admit(
                    &signal.scope,
                    &credential_id,
                    &secret,
                    CALL_SIGNAL_PERMISSION,
                )
                .and_then(|actor| {
                    conference_runtime(self)
                        .signal(&actor, &signal)
                        .map(|_| {
                            pb_acknowledgement(acknowledgement_for(
                                signal.event_id.as_opaque().clone(),
                            ))
                        })
                        .map_err(|error| map_conference_error(&error))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::ConferenceSignalResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::conference_signal_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::conference_signal_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn set_subscriptions(
        &self,
        request: Request<pb::ConferenceSetSubscriptionsRequest>,
    ) -> Result<Response<pb::ConferenceSetSubscriptionsResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let set = request
            .into_inner()
            .subscriptions
            .ok_or_else(invalid_argument)
            .and_then(decode_subscription_set);
        let result = match (credentials, set) {
            (Ok((credential_id, secret)), Ok(set)) => self
                .admit(
                    &set.scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_SUBSCRIBE_PERMISSION,
                )
                .and_then(|actor| {
                    conference_runtime(self)
                        .set_subscriptions(&actor, &set)
                        .map(|_| {
                            pb_acknowledgement(acknowledgement_for(set.call_id.as_opaque().clone()))
                        })
                        .map_err(|error| map_conference_error(&error))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::ConferenceSetSubscriptionsResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::conference_set_subscriptions_response::Result::Acknowledgement(
                        acknowledgement,
                    )
                }
                Err(error) => {
                    pb::conference_set_subscriptions_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn issue_join_url(
        &self,
        request: Request<pb::ConferenceJoinUrlRequest>,
    ) -> Result<Response<pb::ConferenceJoinUrlResponse>, Status> {
        let credentials = decode_credentials(request.metadata());
        let join = decode_join_request(request.into_inner());
        let result = match (credentials, join) {
            (
                Ok((credential_id, secret)),
                Ok((scope, call_id, participant, device_id, ttl_seconds)),
            ) => self
                .admit(
                    &scope,
                    &credential_id,
                    &secret,
                    CONFERENCE_JOIN_ISSUE_PERMISSION,
                )
                .and_then(|actor| {
                    let snapshot = conference_runtime(self)
                        .snapshot(&actor, &scope, &call_id)
                        .map_err(|error| map_conference_error(&error))?;
                    let eligible = snapshot.call.participants.iter().any(|candidate| {
                        candidate.principal == participant
                            && candidate.left_revision.is_none()
                            && matches!(
                                candidate.state,
                                CallParticipantState::Invited
                                    | CallParticipantState::Ringing
                                    | CallParticipantState::Accepted
                            )
                    });
                    if !eligible {
                        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
                    }
                    validate_join_device(&*self.store, &scope, &participant, &device_id)?;
                    let issuer = self.join_issuer.as_deref().ok_or_else(|| {
                        CanonicalError::new(CanonicalErrorCode::CapabilityMismatch)
                    })?;
                    let now_unix_ms = self.clock.now_unix_ms().map_err(|_| {
                        CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
                    })?;
                    issuer
                        .issue(
                            scope,
                            call_id,
                            participant,
                            Some(device_id),
                            ttl_seconds,
                            now_unix_ms,
                        )
                        .map(|grant| pb::ConferenceJoinGrant {
                            session_id: Some(pb_opaque(grant.claims.session_id.as_opaque())),
                            join_url: grant.join_url,
                            expires_at_unix_ms: grant.claims.expires_at_unix_ms,
                        })
                        .map_err(map_join_token_error)
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::ConferenceJoinUrlResponse {
            result: Some(match result {
                Ok(grant) => pb::conference_join_url_response::Result::Grant(grant),
                Err(error) => pb::conference_join_url_response::Result::Error(pb_error(error)),
            }),
        }))
    }
}

fn conference_runtime<C, A, S>(
    service: &GrpcConferenceService<C, A, S>,
) -> ConferenceRuntime<
    '_,
    A,
    S,
    PreparedGroupMediaE2eeCapabilities,
    PreparedSfuCapabilities,
    PreparedConferenceCapabilities,
>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
{
    static GROUP_MEDIA: PreparedGroupMediaE2eeCapabilities = PreparedGroupMediaE2eeCapabilities;
    static SFU: PreparedSfuCapabilities = PreparedSfuCapabilities;
    static CONFERENCE: PreparedConferenceCapabilities = PreparedConferenceCapabilities;
    ConferenceRuntime::with_state(
        &*service.authorization,
        &*service.store,
        &GROUP_MEDIA,
        &SFU,
        &CONFERENCE,
        Arc::clone(&service.state),
    )
}

fn decode_conference_start(value: pb::ConferenceStart) -> Result<ConferenceStart, CanonicalError> {
    Ok(ConferenceStart {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        call_id: CallId::from_opaque(decode_opaque(value.call_id)?),
        group_id: GroupId::from_opaque(decode_opaque(value.group_id)?),
        invitees: value
            .invitees
            .into_iter()
            .map(decode_principal_ref)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn decode_conference_lookup(
    value: pb::ConferenceGetRequest,
) -> Result<(TenantScope, CallId), CanonicalError> {
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        CallId::from_opaque(decode_opaque(value.call_id)?),
    ))
}

fn decode_subscription_set(
    value: pb::ConferenceSubscriptionSet,
) -> Result<ConferenceSubscriptionSet, CanonicalError> {
    Ok(ConferenceSubscriptionSet {
        scope: decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        call_id: CallId::from_opaque(decode_opaque(value.call_id)?),
        subscriptions: value
            .subscriptions
            .into_iter()
            .map(|subscription| {
                Ok(ConferenceMediaSubscription {
                    source: decode_principal_ref(
                        subscription.source.ok_or_else(invalid_argument)?,
                    )?,
                    media_kind: decode_media_kind(subscription.media_kind)?,
                })
            })
            .collect::<Result<Vec<_>, CanonicalError>>()?,
    })
}

fn decode_media_kind(value: i32) -> Result<MediaKind, CanonicalError> {
    match pb::MediaKind::try_from(value).map_err(|_| invalid_argument())? {
        pb::MediaKind::Unspecified => Err(invalid_argument()),
        pb::MediaKind::Audio => Ok(MediaKind::Audio),
        pb::MediaKind::Video => Ok(MediaKind::Video),
    }
}

fn decode_join_request(
    value: pb::ConferenceJoinUrlRequest,
) -> Result<(TenantScope, CallId, PrincipalRef, DeviceId, u32), CanonicalError> {
    if value.ttl_seconds == 0 {
        return Err(invalid_argument());
    }
    Ok((
        decode_scope(value.scope.ok_or_else(invalid_argument)?)?,
        CallId::from_opaque(decode_opaque(value.call_id)?),
        decode_principal_ref(value.participant.ok_or_else(invalid_argument)?)?,
        DeviceId::from_opaque(decode_opaque(value.device_id)?),
        value.ttl_seconds,
    ))
}

fn pb_conference_snapshot(value: &ConferenceSnapshot) -> pb::ConferenceSnapshot {
    pb::ConferenceSnapshot {
        call: Some(pb_call_session(&value.call)),
        group_id: Some(pb_opaque(value.group_id.as_opaque())),
        topology: (match value.topology {
            ConferenceTopology::Sfu => pb::ConferenceTopology::Sfu,
        }) as i32,
        group_crypto_epoch: value.group_crypto_epoch,
        group_crypto_state_ref: Some(pb_opaque(&value.group_crypto_state_ref)),
    }
}

fn validate_join_device<S>(
    store: &S,
    scope: &TenantScope,
    participant: &PrincipalRef,
    device_id: &DeviceId,
) -> Result<(), CanonicalError>
where
    S: DeviceLifecycleStore + PrincipalIdentityBindingStore,
{
    let device = store
        .device(scope, device_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))?;
    if device.state != DeviceLifecycleState::Active {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    if participant.kind == PrincipalKind::Device {
        if participant.principal_id.as_opaque() != device_id.as_opaque() {
            return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
        }
        return Ok(());
    }
    let binding = store
        .principal_identity_binding(scope, participant)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PolicyDenied))?;
    if binding.identity_id != device.identity_id {
        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
    }
    Ok(())
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

pub(crate) fn map_conference_error(error: &ConferenceError) -> CanonicalError {
    match error {
        ConferenceError::Protocol(error) => map_conference_protocol_error(*error),
        ConferenceError::Authorization(error) => *error,
        ConferenceError::Store(error) => map_store_error(*error),
        ConferenceError::CapabilityUnavailable | ConferenceError::GroupCryptoUnavailable => {
            CanonicalError::new(CanonicalErrorCode::CapabilityMismatch)
        }
        ConferenceError::GroupUnavailable
        | ConferenceError::MembershipUnavailable
        | ConferenceError::CallUnavailable
        | ConferenceError::SourceUnavailable => CanonicalError::new(CanonicalErrorCode::NotFound),
        ConferenceError::GroupMismatch
        | ConferenceError::NotConference
        | ConferenceError::SubscriberNotAccepted => {
            CanonicalError::new(CanonicalErrorCode::PolicyDenied)
        }
        ConferenceError::SubscriptionStateUnavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
        ConferenceError::SubscriptionCapacityExceeded => {
            CanonicalError::new(CanonicalErrorCode::ResourceExhausted)
        }
        ConferenceError::Sfu(_) => CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable),
    }
}

fn map_conference_protocol_error(error: ConferenceProtocolError) -> CanonicalError {
    match error {
        ConferenceProtocolError::TooManyInvitees
        | ConferenceProtocolError::TooManySubscriptions => {
            CanonicalError::new(CanonicalErrorCode::ResourceExhausted)
        }
        ConferenceProtocolError::ScopeMismatch
        | ConferenceProtocolError::EmptyInvitees
        | ConferenceProtocolError::DuplicateInvitee
        | ConferenceProtocolError::InitiatorIncluded
        | ConferenceProtocolError::NotGroupCall
        | ConferenceProtocolError::WrongTopology
        | ConferenceProtocolError::GroupMismatch
        | ConferenceProtocolError::MissingMlsState
        | ConferenceProtocolError::DuplicateSubscription
        | ConferenceProtocolError::SelfSubscription => {
            CanonicalError::new(CanonicalErrorCode::InvalidArgument)
        }
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

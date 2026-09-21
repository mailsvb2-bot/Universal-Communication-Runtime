use std::{fmt, pin::Pin, sync::Arc};

use prost::Message as _;
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, metadata::MetadataMap};
use ucr_conference::{
    ConferenceError, ConferenceRuntime, ConferenceRuntimeState, PreparedConferenceCapabilities,
};
use ucr_core::{
    AuthorizationEvaluator, CallStore, ConferenceJoinGrantStore, DeviceLifecycleStore,
    DurableStoreError, EventJournalStore, GroupStore, PrincipalIdentityBindingStore,
    UniversalConferenceStore,
};
use ucr_crypto::TrustedSigningKeyResolver;
use ucr_media_e2ee::PreparedGroupMediaE2eeCapabilities;
use ucr_model::{
    ActorId, ActorKind, ActorRef, CallId, CallParticipantState, CallSignal, CallSignalKind,
    ConferenceJoinGrantRecord, ConferenceJoinGrantUsePolicy, ConferenceMediaSubscription,
    ConferenceParticipantRole, ConferenceSubscriptionSet, CorrelationContext, CryptoSuite,
    DeviceId, DeviceLifecycleState,
    DeviceRef, EncryptedGroupMediaFrame, EventEnvelope, EventId, GroupId, GroupMediaFrameHeader,
    GroupMediaSourceSignature, IceServerConfig, KeyId, MediaKind, OpaqueId, PrincipalKind,
    ScopedPrincipal, SessionId, SfuForwardEnvelope, TenantScope, UniversalConferenceLifecycle,
    VideoSourceKind, WebRtcIceCandidate, WebRtcSdpType, WebRtcSessionDescription,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, GROUP_MEDIA_FRAME_HEADER_V1, GROUP_MEDIA_FRAME_HEADER_V2,
    RUNTIME_ENVELOPE_SCHEMA_V1, acknowledgement_for, canonical_event,
};
use ucr_realtime::{
    AttendanceTransition, AttendanceTransitionKind, JoinTokenError, JoinTokenIssuer,
    RealtimeRegistryError, RealtimeSessionClaims, RealtimeSessionRegistry,
};
use ucr_sfu::{PreparedSfuCapabilities, SfuForwardSink};
use ucr_webrtc::{
    PreparedWebRtcProvider, WebRtcProvider, WebRtcProviderError, WebRtcSessionConfigFactory,
};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_opaque,
    decode_principal_ref, decode_scope, invalid_argument, pb, pb_acknowledgement, pb_crypto_suite,
    pb_error, pb_opaque, pb_principal_ref, pb_scope,
};

pub const REALTIME_AUTHORIZATION_METADATA_KEY: &str = "authorization";
const REALTIME_BEARER_PREFIX: &str = "Bearer ";
const REALTIME_HEARTBEAT_INTERVAL_MS: u64 = 15_000;

#[derive(Clone)]
pub struct RealtimeWebRtcDependencies {
    provider: Arc<dyn WebRtcProvider>,
    config: Arc<WebRtcSessionConfigFactory>,
}

impl RealtimeWebRtcDependencies {
    #[must_use]
    pub fn new(provider: Arc<dyn WebRtcProvider>, config: Arc<WebRtcSessionConfigFactory>) -> Self {
        Self { provider, config }
    }

    #[must_use]
    pub fn prepared() -> Self {
        Self::new(
            Arc::new(PreparedWebRtcProvider),
            Arc::new(WebRtcSessionConfigFactory::default()),
        )
    }
}

impl fmt::Debug for RealtimeWebRtcDependencies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealtimeWebRtcDependencies")
            .field("provider", &self.provider)
            .field("config", &self.config)
            .finish()
    }
}

pub struct GrpcRealtimeService<C, A, S> {
    clock: Arc<C>,
    authorization: Arc<A>,
    store: Arc<S>,
    join_issuer: Arc<JoinTokenIssuer>,
    registry: Arc<RealtimeSessionRegistry>,
    conference_state: Arc<ConferenceRuntimeState>,
    webrtc_provider: Arc<dyn WebRtcProvider>,
    webrtc_config: Arc<WebRtcSessionConfigFactory>,
}

impl<C, A, S> GrpcRealtimeService<C, A, S> {
    #[must_use]
    pub fn new(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        join_issuer: Arc<JoinTokenIssuer>,
        registry: Arc<RealtimeSessionRegistry>,
        conference_state: Arc<ConferenceRuntimeState>,
    ) -> Self {
        Self::with_webrtc(
            clock,
            authorization,
            store,
            join_issuer,
            registry,
            conference_state,
            RealtimeWebRtcDependencies::prepared(),
        )
    }

    #[must_use]
    pub fn with_webrtc(
        clock: Arc<C>,
        authorization: Arc<A>,
        store: Arc<S>,
        join_issuer: Arc<JoinTokenIssuer>,
        registry: Arc<RealtimeSessionRegistry>,
        conference_state: Arc<ConferenceRuntimeState>,
        webrtc: RealtimeWebRtcDependencies,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            join_issuer,
            registry,
            conference_state,
            webrtc_provider: webrtc.provider,
            webrtc_config: webrtc.config,
        }
    }
}

impl<C, A, S> Clone for GrpcRealtimeService<C, A, S> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            join_issuer: Arc::clone(&self.join_issuer),
            registry: Arc::clone(&self.registry),
            conference_state: Arc::clone(&self.conference_state),
            webrtc_provider: Arc::clone(&self.webrtc_provider),
            webrtc_config: Arc::clone(&self.webrtc_config),
        }
    }
}

impl<C, A, S> fmt::Debug for GrpcRealtimeService<C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcRealtimeService")
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn realtime_service_server<C, A, S>(
    service: GrpcRealtimeService<C, A, S>,
) -> pb::realtime_service_server::RealtimeServiceServer<GrpcRealtimeService<C, A, S>>
where
    C: ucr_core::ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + EventJournalStore
        + UniversalConferenceStore
        + ConferenceJoinGrantStore
        + 'static,
{
    pb::realtime_service_server::RealtimeServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C, A, S> pb::realtime_service_server::RealtimeService for GrpcRealtimeService<C, A, S>
where
    C: ucr_core::ServiceQuotaClock + 'static,
    A: AuthorizationEvaluator + 'static,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + EventJournalStore
        + UniversalConferenceStore
        + ConferenceJoinGrantStore
        + 'static,
{
    type SubscribeMediaStream =
        Pin<Box<dyn Stream<Item = Result<pb::RealtimeDownlinkMedia, Status>> + Send + 'static>>;

    async fn join_realtime(
        &self,
        request: Request<pb::RealtimeJoinRequest>,
    ) -> Result<Response<pb::RealtimeJoinResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let request = decode_realtime_lookup(request.into_inner());
        let result = match (token, request) {
            (Ok(token), Ok((scope, call_id, session_id))) => self
                .authenticated_claims(&token, &scope, &call_id, &session_id)
                .and_then(|claims| {
                    let now = self.now()?;
                    let admission = self.realtime_admission_state(&claims)?;
                    if admission == pb::RealtimeAdmissionState::Closed {
                        return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
                    }
                    let reconnect = self
                        .registry
                        .contains_active_session(&claims, now)
                        .map_err(map_registry_error)?;
                    if !reconnect {
                        self.require_entry_open_for_join(&claims)?;
                    }
                    self.ensure_accepted_conference_participant_for_join(&claims)?;
                    let redeemed = self.redeemed_claims(&token, &scope, &call_id, &session_id)?;
                    if redeemed != claims {
                        return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
                    }
                    let outcome = self
                        .registry
                        .join(claims.clone(), now)
                        .map_err(map_registry_error)?;
                    if let Err(error) = self.append_attendance(&outcome.transition) {
                        let _ = self.registry.leave(&claims, now);
                        return Err(error);
                    }
                    Ok(pb_realtime_session(&claims, admission))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeJoinResponse {
            result: Some(match result {
                Ok(session) => pb::realtime_join_response::Result::Session(session),
                Err(error) => pb::realtime_join_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn heartbeat_realtime(
        &self,
        request: Request<pb::RealtimeHeartbeatRequest>,
    ) -> Result<Response<pb::RealtimeHeartbeatResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let request = request.into_inner();
        let lookup =
            decode_realtime_lookup_fields(request.scope, request.call_id, request.session_id);
        let result = match (token, lookup) {
            (Ok(token), Ok((scope, call_id, session_id))) => self
                .authenticated_claims(&token, &scope, &call_id, &session_id)
                .and_then(|claims| {
                    let now = self.now()?;
                    let sequence = self
                        .registry
                        .heartbeat(&claims, now)
                        .map_err(map_registry_error)?;
                    if request.expected_session_sequence != 0
                        && request.expected_session_sequence != sequence
                    {
                        return Err(CanonicalError::new(CanonicalErrorCode::Conflict));
                    }
                    let admission = self.realtime_admission_state(&claims)?;
                    Ok((
                        pb_acknowledgement(acknowledgement_for(
                            claims.session_id.as_opaque().clone(),
                        )),
                        admission,
                    ))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        let (result, admission_state) = match result {
            Ok((acknowledgement, admission)) => (
                pb::realtime_heartbeat_response::Result::Acknowledgement(acknowledgement),
                admission as i32,
            ),
            Err(error) => (
                pb::realtime_heartbeat_response::Result::Error(pb_error(error)),
                pb::RealtimeAdmissionState::Unspecified as i32,
            ),
        };
        Ok(Response::new(pb::RealtimeHeartbeatResponse {
            result: Some(result),
            admission_state,
        }))
    }

    async fn leave_realtime(
        &self,
        request: Request<pb::RealtimeLeaveRequest>,
    ) -> Result<Response<pb::RealtimeLeaveResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let lookup = decode_realtime_lookup(request.into_inner());
        let result = match (token, lookup) {
            (Ok(token), Ok((scope, call_id, session_id))) => self
                .authenticated_claims(&token, &scope, &call_id, &session_id)
                .and_then(|claims| {
                    let transition = self
                        .registry
                        .leave(&claims, self.now()?)
                        .map_err(map_registry_error)?;
                    self.append_attendance(&transition)?;
                    Ok(pb_acknowledgement(acknowledgement_for(
                        claims.session_id.as_opaque().clone(),
                    )))
                }),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeLeaveResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::realtime_leave_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::realtime_leave_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn set_subscriptions(
        &self,
        request: Request<pb::RealtimeSetSubscriptionsRequest>,
    ) -> Result<Response<pb::RealtimeSetSubscriptionsResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let body = request.into_inner();
        let lookup = decode_realtime_lookup_fields(body.scope, body.call_id, body.session_id);
        let subscriptions = body
            .subscriptions
            .into_iter()
            .map(decode_media_subscription)
            .collect::<Result<Vec<_>, _>>();
        let result = match (token, lookup, subscriptions) {
            (Ok(token), Ok((scope, call_id, session_id)), Ok(subscriptions)) => self
                .authenticated_claims(&token, &scope, &call_id, &session_id)
                .and_then(|claims| {
                    self.registry
                        .heartbeat(&claims, self.now()?)
                        .map_err(map_registry_error)?;
                    self.require_live_universal_conference(&claims)?;
                    let actor = actor_for(&claims);
                    let set = ConferenceSubscriptionSet {
                        scope,
                        call_id,
                        subscriptions,
                    };
                    conference_runtime(self)
                        .set_subscriptions(&actor, &set)
                        .map_err(|error| map_conference_error(&error))?;
                    Ok(pb_acknowledgement(acknowledgement_for(
                        claims.session_id.as_opaque().clone(),
                    )))
                }),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeSetSubscriptionsResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::realtime_set_subscriptions_response::Result::Acknowledgement(
                        acknowledgement,
                    )
                }
                Err(error) => {
                    pb::realtime_set_subscriptions_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn publish_media(
        &self,
        request: Request<pb::RealtimePublishMediaRequest>,
    ) -> Result<Response<pb::RealtimePublishMediaResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let body = request.into_inner();
        let lookup = decode_realtime_lookup_fields(body.scope, body.call_id, body.session_id);
        let envelope = body
            .envelope
            .ok_or_else(invalid_argument)
            .and_then(decode_sfu_forward_envelope);
        let result = match (token, lookup, envelope) {
            (Ok(token), Ok((scope, call_id, session_id)), Ok(envelope)) => self
                .authenticated_claims(&token, &scope, &call_id, &session_id)
                .and_then(|claims| {
                    let accepted_recipients =
                        self.forward_authenticated_e2ee_media(&claims, &envelope, &*self.registry)?;
                    let accepted_recipient_count = u32::try_from(accepted_recipients)
                        .map_err(|_| CanonicalError::new(CanonicalErrorCode::ResourceExhausted))?;
                    Ok(pb::RealtimePublishMediaReceipt {
                        call_id: Some(pb_opaque(claims.call_id.as_opaque())),
                        session_id: Some(pb_opaque(claims.session_id.as_opaque())),
                        accepted_recipient_count,
                    })
                }),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimePublishMediaResponse {
            result: Some(match result {
                Ok(receipt) => pb::realtime_publish_media_response::Result::Receipt(receipt),
                Err(error) => pb::realtime_publish_media_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn subscribe_media(
        &self,
        request: Request<pb::RealtimeSubscribeMediaRequest>,
    ) -> Result<Response<Self::SubscribeMediaStream>, Status> {
        let token = decode_bearer_token(request.metadata()).map_err(status_from_canonical)?;
        let (scope, call_id, session_id) =
            decode_realtime_lookup(request.into_inner()).map_err(status_from_canonical)?;
        let claims = self
            .authenticated_claims(&token, &scope, &call_id, &session_id)
            .map_err(status_from_canonical)?;
        self.require_accepted_conference_participant(&claims)
            .map_err(status_from_canonical)?;
        self.require_live_universal_conference(&claims)
            .map_err(status_from_canonical)?;
        let attachment = self
            .registry
            .attach_downlink(&claims, self.now().map_err(status_from_canonical)?)
            .map_err(map_registry_error)
            .map_err(status_from_canonical)?;
        if let Some(transition) = &attachment.transition {
            self.append_attendance(transition)
                .map_err(status_from_canonical)?;
        }
        let stream = ReceiverStream::new(attachment.receiver).map(|envelope| {
            Ok(pb::RealtimeDownlinkMedia {
                envelope: Some(pb_sfu_forward_envelope(&envelope)),
            })
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn start_web_rtc(
        &self,
        request: Request<pb::RealtimeStartWebRtcRequest>,
    ) -> Result<Response<pb::RealtimeStartWebRtcResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let lookup = decode_realtime_lookup(request.into_inner());
        let result = match (token, lookup) {
            (Ok(token), Ok((scope, call_id, session_id))) => {
                match self.authenticated_webrtc_claims(&token, &scope, &call_id, &session_id) {
                    Ok(claims) => {
                        let now_ms = self.now();
                        match now_ms.and_then(|value| {
                            u64::try_from(value.div_euclid(1_000))
                                .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
                        }) {
                            Ok(now_unix_seconds) => {
                                let expires_at_unix_seconds =
                                    u64::try_from(claims.expires_at_unix_ms.div_euclid(1_000))
                                        .map_err(|_| {
                                            CanonicalError::new(CanonicalErrorCode::Internal)
                                        });
                                match expires_at_unix_seconds.and_then(|expires_at_unix_seconds| {
                                    self.webrtc_config
                                        .session_config_until(
                                            &claims.session_id,
                                            now_unix_seconds,
                                            expires_at_unix_seconds,
                                        )
                                        .map_err(map_webrtc_provider_error)
                                }) {
                                    Ok(config) => {
                                        let ice_servers = config.ice_servers.clone();
                                        let provider = Arc::clone(&self.webrtc_provider);
                                        match tokio::task::spawn_blocking(move || {
                                            provider.create_session(&config)
                                        })
                                        .await
                                        {
                                            Ok(Ok(description)) => Ok(pb::RealtimeWebRtcOffer {
                                                description: Some(pb_webrtc_description(
                                                    &description,
                                                )),
                                                ice_servers: ice_servers
                                                    .iter()
                                                    .map(pb_webrtc_ice_server)
                                                    .collect(),
                                            }),
                                            Ok(Err(error)) => Err(map_webrtc_provider_error(error)),
                                            Err(_) => Err(CanonicalError::new(
                                                CanonicalErrorCode::Internal,
                                            )),
                                        }
                                    }
                                    Err(error) => Err(error),
                                }
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeStartWebRtcResponse {
            result: Some(match result {
                Ok(offer) => pb::realtime_start_web_rtc_response::Result::Offer(offer),
                Err(error) => pb::realtime_start_web_rtc_response::Result::Error(pb_error(error)),
            }),
        }))
    }

    async fn set_web_rtc_remote_description(
        &self,
        request: Request<pb::RealtimeSetWebRtcRemoteDescriptionRequest>,
    ) -> Result<Response<pb::RealtimeSetWebRtcRemoteDescriptionResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let body = request.into_inner();
        let lookup = decode_realtime_lookup_fields(body.scope, body.call_id, body.session_id);
        let description = body
            .description
            .ok_or_else(invalid_argument)
            .and_then(decode_webrtc_description);
        let result = match (token, lookup, description) {
            (Ok(token), Ok((scope, call_id, session_id)), Ok(description)) => {
                match self.authenticated_webrtc_claims(&token, &scope, &call_id, &session_id) {
                    Ok(claims) => {
                        let description = WebRtcSessionDescription {
                            session_id: claims.session_id.clone(),
                            sdp_type: description.0,
                            sdp: description.1,
                        };
                        let provider = Arc::clone(&self.webrtc_provider);
                        match tokio::task::spawn_blocking(move || {
                            provider.set_remote_description(&description)
                        })
                        .await
                        {
                            Ok(Ok(())) => Ok(pb_acknowledgement(acknowledgement_for(
                                claims.session_id.as_opaque().clone(),
                            ))),
                            Ok(Err(error)) => Err(map_webrtc_provider_error(error)),
                            Err(_) => Err(CanonicalError::new(CanonicalErrorCode::Internal)),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeSetWebRtcRemoteDescriptionResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::realtime_set_web_rtc_remote_description_response::Result::Acknowledgement(
                        acknowledgement,
                    )
                }
                Err(error) => {
                    pb::realtime_set_web_rtc_remote_description_response::Result::Error(pb_error(
                        error,
                    ))
                }
            }),
        }))
    }

    async fn add_web_rtc_ice_candidate(
        &self,
        request: Request<pb::RealtimeAddWebRtcIceCandidateRequest>,
    ) -> Result<Response<pb::RealtimeAddWebRtcIceCandidateResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let body = request.into_inner();
        let lookup = decode_realtime_lookup_fields(body.scope, body.call_id, body.session_id);
        let result = match (token, lookup) {
            (Ok(token), Ok((scope, call_id, session_id))) => {
                match self.authenticated_webrtc_claims(&token, &scope, &call_id, &session_id) {
                    Ok(claims) => {
                        let mline_index = body
                            .sdp_mline_index
                            .map(u16::try_from)
                            .transpose()
                            .map_err(|_| CanonicalError::new(CanonicalErrorCode::InvalidArgument));
                        match mline_index {
                            Ok(sdp_mline_index) => {
                                let candidate = WebRtcIceCandidate {
                                    session_id: claims.session_id.clone(),
                                    candidate: body.candidate,
                                    sdp_mid: body.sdp_mid,
                                    sdp_mline_index,
                                };
                                let provider = Arc::clone(&self.webrtc_provider);
                                match tokio::task::spawn_blocking(move || {
                                    provider.add_remote_candidate(&candidate)
                                })
                                .await
                                {
                                    Ok(Ok(())) => Ok(pb_acknowledgement(acknowledgement_for(
                                        claims.session_id.as_opaque().clone(),
                                    ))),
                                    Ok(Err(error)) => Err(map_webrtc_provider_error(error)),
                                    Err(_) => {
                                        Err(CanonicalError::new(CanonicalErrorCode::Internal))
                                    }
                                }
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeAddWebRtcIceCandidateResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::realtime_add_web_rtc_ice_candidate_response::Result::Acknowledgement(
                        acknowledgement,
                    )
                }
                Err(error) => {
                    pb::realtime_add_web_rtc_ice_candidate_response::Result::Error(pb_error(error))
                }
            }),
        }))
    }

    async fn close_web_rtc(
        &self,
        request: Request<pb::RealtimeCloseWebRtcRequest>,
    ) -> Result<Response<pb::RealtimeCloseWebRtcResponse>, Status> {
        let token = decode_bearer_token(request.metadata());
        let lookup = decode_realtime_lookup(request.into_inner());
        let result = match (token, lookup) {
            (Ok(token), Ok((scope, call_id, session_id))) => {
                match self.authenticated_webrtc_claims(&token, &scope, &call_id, &session_id) {
                    Ok(claims) => {
                        let provider = Arc::clone(&self.webrtc_provider);
                        let close_session_id = claims.session_id.clone();
                        match tokio::task::spawn_blocking(move || {
                            provider.close_session(&close_session_id)
                        })
                        .await
                        {
                            Ok(Ok(()) | Err(WebRtcProviderError::SessionUnavailable)) => {
                                Ok(pb_acknowledgement(acknowledgement_for(
                                    claims.session_id.as_opaque().clone(),
                                )))
                            }
                            Ok(Err(error)) => Err(map_webrtc_provider_error(error)),
                            Err(_) => Err(CanonicalError::new(CanonicalErrorCode::Internal)),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        Ok(Response::new(pb::RealtimeCloseWebRtcResponse {
            result: Some(match result {
                Ok(acknowledgement) => {
                    pb::realtime_close_web_rtc_response::Result::Acknowledgement(acknowledgement)
                }
                Err(error) => pb::realtime_close_web_rtc_response::Result::Error(pb_error(error)),
            }),
        }))
    }
}

impl<C, A, S> GrpcRealtimeService<C, A, S>
where
    C: ucr_core::ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + EventJournalStore
        + UniversalConferenceStore
        + ConferenceJoinGrantStore,
{
    /// Routes one already-encrypted endpoint media envelope through the exact canonical
    /// Conference/SFU path after revalidating long-lived session control and publish policy.
    ///
    /// This method is shared by gRPC media publication and the WebRTC E2EE `DataChannel` bridge.
    /// It never receives endpoint key material or media plaintext.
    ///
    /// # Errors
    /// Fails closed for revoked/expired sessions, invalid Device/source bindings, policy denial,
    /// malformed ciphertext, SFU validation failures or unavailable bounded routing state.
    pub fn forward_authenticated_e2ee_media(
        &self,
        claims: &RealtimeSessionClaims,
        envelope: &SfuForwardEnvelope,
        sink: &dyn SfuForwardSink,
    ) -> Result<usize, CanonicalError> {
        self.require_live_transport_claims(claims)?;
        self.registry
            .heartbeat(claims, self.now()?)
            .map_err(map_registry_error)?;
        let device_id = claims
            .device_id
            .as_ref()
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?;
        self.require_universal_publish_allowed(
            claims,
            envelope.frame.header.media_kind,
            envelope.frame.header.video_source_kind,
        )?;
        let outcome = conference_runtime(self)
            .forward(&actor_for(claims), device_id, envelope, sink)
            .map_err(|error| map_conference_error(&error))?;
        if outcome.accepted_recipients > 0
            && let Some(transition) = self
                .registry
                .mark_media_ready(claims, self.now()?)
                .map_err(map_registry_error)?
        {
            self.append_attendance(&transition)?;
        }
        Ok(outcome.accepted_recipients)
    }

    fn require_live_transport_claims(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<(), CanonicalError> {
        let now = self.now()?;
        if let Some(record) = self
            .store
            .conference_join_grant(&claims.scope, &claims.session_id)
            .map_err(map_store_error)?
        {
            require_durable_grant_matches_claims(&record, claims)?;
            if record.revoked || now >= record.expires_at_unix_ms {
                return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
            }
        } else {
            self.join_issuer
                .validate_live_claims(claims, now)
                .map_err(map_join_token_error)?;
        }
        validate_device_claim(&*self.store, claims)?;
        self.require_accepted_conference_participant(claims)?;
        self.require_live_universal_conference(claims)
    }

    fn now(&self) -> Result<i64, CanonicalError> {
        self.clock
            .now_unix_ms()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))
    }

    fn authenticated_webrtc_claims(
        &self,
        token: &str,
        scope: &TenantScope,
        call_id: &CallId,
        session_id: &SessionId,
    ) -> Result<RealtimeSessionClaims, CanonicalError> {
        let claims = self.authenticated_claims(token, scope, call_id, session_id)?;
        self.require_accepted_conference_participant(&claims)?;
        self.require_live_universal_conference(&claims)?;
        self.registry
            .heartbeat(&claims, self.now()?)
            .map_err(map_registry_error)?;
        Ok(claims)
    }

    fn redeemed_claims(
        &self,
        token: &str,
        scope: &TenantScope,
        call_id: &CallId,
        session_id: &SessionId,
    ) -> Result<RealtimeSessionClaims, CanonicalError> {
        let claims = self
            .join_issuer
            .verify_signed_claims(token, self.now()?)
            .map_err(map_join_token_error)?;
        if claims.scope != *scope || claims.call_id != *call_id || claims.session_id != *session_id
        {
            return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
        }
        if let Some(record) = self
            .store
            .conference_join_grant(scope, session_id)
            .map_err(map_store_error)?
        {
            require_durable_grant_matches_claims(&record, &claims)?;
            if record.revoked {
                return Err(map_join_token_error(JoinTokenError::Revoked));
            }
            if record.use_policy == ConferenceJoinGrantUsePolicy::SingleUse && record.redeemed {
                return Err(map_join_token_error(JoinTokenError::AlreadyUsed));
            }
            match self.store.redeem_conference_join_grant(scope, session_id) {
                Ok(_) => {}
                Err(DurableStoreError::PermissionDenied) => {
                    return Err(map_join_token_error(JoinTokenError::Revoked));
                }
                Err(DurableStoreError::Conflict) => {
                    return Err(map_join_token_error(JoinTokenError::AlreadyUsed));
                }
                Err(error) => return Err(map_store_error(error)),
            }
        } else {
            let legacy = self
                .join_issuer
                .redeem(token, self.now()?)
                .map_err(map_join_token_error)?;
            if legacy != claims {
                return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
            }
        }
        validate_device_claim(&*self.store, &claims)?;
        Ok(claims)
    }

    fn authenticated_claims(
        &self,
        token: &str,
        scope: &TenantScope,
        call_id: &CallId,
        session_id: &SessionId,
    ) -> Result<RealtimeSessionClaims, CanonicalError> {
        let claims = self
            .join_issuer
            .verify_signed_claims(token, self.now()?)
            .map_err(map_join_token_error)?;
        if claims.scope != *scope || claims.call_id != *call_id || claims.session_id != *session_id
        {
            return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
        }
        if let Some(record) = self
            .store
            .conference_join_grant(scope, session_id)
            .map_err(map_store_error)?
        {
            require_durable_grant_matches_claims(&record, &claims)?;
            if record.revoked {
                return Err(map_join_token_error(JoinTokenError::Revoked));
            }
        } else {
            let legacy = self
                .join_issuer
                .verify(token, self.now()?)
                .map_err(map_join_token_error)?;
            if legacy != claims {
                return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
            }
        }
        validate_device_claim(&*self.store, &claims)?;
        Ok(claims)
    }

    fn ensure_accepted_conference_participant_for_join(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<(), CanonicalError> {
        const MAX_JOIN_ACCEPT_ATTEMPTS: usize = 4;
        let actor = actor_for(claims);
        for _ in 0..MAX_JOIN_ACCEPT_ATTEMPTS {
            let snapshot = conference_runtime(self)
                .snapshot(&actor, &claims.scope, &claims.call_id)
                .map_err(|error| map_conference_error(&error))?;
            let participant = snapshot
                .call
                .participants
                .iter()
                .find(|participant| {
                    participant.principal == claims.participant
                        && participant.left_revision.is_none()
                })
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PolicyDenied))?;
            match participant.state {
                CallParticipantState::Accepted => {
                    return self.require_active_universal_participant(claims, &snapshot.group_id);
                }
                CallParticipantState::Invited | CallParticipantState::Ringing => {}
                CallParticipantState::Rejected
                | CallParticipantState::Busy
                | CallParticipantState::Left => {
                    return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
                }
            }
            self.require_active_universal_participant(claims, &snapshot.group_id)?;
            let event_id = EventId::from_opaque(
                OpaqueId::new(format!("rj-{}", claims.session_id.as_opaque().as_str()))
                    .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
            );
            let signal = CallSignal {
                event_id,
                scope: claims.scope.clone(),
                call_id: claims.call_id.clone(),
                expected_revision: snapshot.call.revision,
                kind: CallSignalKind::Accept,
            };
            match self.store.apply_call_signal(&actor, &signal) {
                Ok(_) | Err(DurableStoreError::Conflict) => {}
                Err(error) => return Err(map_store_error(error)),
            }
        }
        Err(CanonicalError::new(CanonicalErrorCode::Conflict))
    }

    fn require_accepted_conference_participant(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<(), CanonicalError> {
        let actor = actor_for(claims);
        let snapshot = conference_runtime(self)
            .snapshot(&actor, &claims.scope, &claims.call_id)
            .map_err(|error| map_conference_error(&error))?;
        let accepted = snapshot.call.participants.iter().any(|participant| {
            participant.principal == claims.participant
                && participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        });
        if !accepted {
            return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
        }
        self.require_active_universal_participant(claims, &snapshot.group_id)
    }

    fn require_active_universal_participant(
        &self,
        claims: &RealtimeSessionClaims,
        group_id: &GroupId,
    ) -> Result<(), CanonicalError> {
        let Some(_) = self
            .store
            .universal_conference_profile(&claims.scope, group_id)
            .map_err(map_store_error)?
        else {
            return Ok(());
        };
        let participant = self
            .store
            .universal_conference_participant(&claims.scope, group_id, &claims.participant)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PolicyDenied))?;
        if participant.active {
            Ok(())
        } else {
            Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied))
        }
    }

    fn realtime_admission_state(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<pb::RealtimeAdmissionState, CanonicalError> {
        let actor = actor_for(claims);
        let snapshot = conference_runtime(self)
            .snapshot(&actor, &claims.scope, &claims.call_id)
            .map_err(|error| map_conference_error(&error))?;
        let Some(conference) = self
            .store
            .universal_conference_profile(&claims.scope, &snapshot.group_id)
            .map_err(map_store_error)?
        else {
            return Ok(pb::RealtimeAdmissionState::Admitted);
        };
        self.require_active_universal_participant(claims, &snapshot.group_id)?;
        Ok(match conference.lifecycle {
            UniversalConferenceLifecycle::Waiting => pb::RealtimeAdmissionState::WaitingRoom,
            UniversalConferenceLifecycle::Live => pb::RealtimeAdmissionState::Admitted,
            UniversalConferenceLifecycle::Scheduled
            | UniversalConferenceLifecycle::Ending
            | UniversalConferenceLifecycle::Ended => pb::RealtimeAdmissionState::Closed,
        })
    }

    fn require_live_universal_conference(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<(), CanonicalError> {
        match self.realtime_admission_state(claims)? {
            pb::RealtimeAdmissionState::Admitted => Ok(()),
            pb::RealtimeAdmissionState::WaitingRoom => Err(
                CanonicalError::new(CanonicalErrorCode::PolicyDenied).with_retry_after(2_000),
            ),
            pb::RealtimeAdmissionState::Closed | pb::RealtimeAdmissionState::Unspecified => {
                Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied))
            }
        }
    }

    fn require_entry_open_for_join(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<(), CanonicalError> {
        let actor = actor_for(claims);
        let snapshot = conference_runtime(self)
            .snapshot(&actor, &claims.scope, &claims.call_id)
            .map_err(|error| map_conference_error(&error))?;
        let Some(conference) = self
            .store
            .universal_conference_profile(&claims.scope, &snapshot.group_id)
            .map_err(map_store_error)?
        else {
            return Ok(());
        };
        let participant = self
            .store
            .universal_conference_participant(
                &claims.scope,
                &snapshot.group_id,
                &claims.participant,
            )
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PolicyDenied))?;
        if participant.role == ConferenceParticipantRole::Attendee && !conference.entry_open {
            Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied).with_retry_after(2_000))
        } else {
            Ok(())
        }
    }

    fn require_universal_publish_allowed(
        &self,
        claims: &RealtimeSessionClaims,
        media_kind: MediaKind,
        video_source_kind: Option<VideoSourceKind>,
    ) -> Result<(), CanonicalError> {
        let actor = actor_for(claims);
        let snapshot = conference_runtime(self)
            .snapshot(&actor, &claims.scope, &claims.call_id)
            .map_err(|error| map_conference_error(&error))?;
        let Some(_) = self
            .store
            .universal_conference_profile(&claims.scope, &snapshot.group_id)
            .map_err(map_store_error)?
        else {
            return Ok(());
        };
        let participant = self
            .store
            .universal_conference_participant(
                &claims.scope,
                &snapshot.group_id,
                &claims.participant,
            )
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PolicyDenied))?;
        if !participant.active {
            return Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied));
        }
        let allowed = match (media_kind, video_source_kind) {
            (MediaKind::Audio, None) => {
                !participant.audio_muted && participant.publish_audio_allowed
            }
            (MediaKind::Video, Some(VideoSourceKind::Camera)) => {
                participant.camera_allowed && participant.publish_video_allowed
            }
            (MediaKind::Video, Some(VideoSourceKind::ScreenShare)) => {
                participant.screen_share_allowed
            }
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(CanonicalError::new(CanonicalErrorCode::PolicyDenied))
        }
    }

    fn append_attendance(&self, transition: &AttendanceTransition) -> Result<(), CanonicalError> {
        let event = attendance_event(&*self.store, transition)?;
        self.store
            .append_event(&event)
            .map(|_| ())
            .map_err(map_store_error)
    }
}

fn conference_runtime<C, A, S>(
    service: &GrpcRealtimeService<C, A, S>,
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
        Arc::clone(&service.conference_state),
    )
}

fn decode_bearer_token(metadata: &MetadataMap) -> Result<String, CanonicalError> {
    let value = metadata
        .get(REALTIME_AUTHORIZATION_METADATA_KEY)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?
        .to_str()
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?;
    let token = value
        .strip_prefix(REALTIME_BEARER_PREFIX)
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?;
    if token.is_empty() {
        return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
    }
    Ok(token.to_owned())
}

fn decode_realtime_lookup(
    value: impl Into<RealtimeLookupFields>,
) -> Result<(TenantScope, CallId, SessionId), CanonicalError> {
    let value = value.into();
    decode_realtime_lookup_fields(value.scope, value.call_id, value.session_id)
}

struct RealtimeLookupFields {
    scope: Option<pb::TenantScope>,
    call_id: Option<pb::OpaqueId>,
    session_id: Option<pb::OpaqueId>,
}

impl From<pb::RealtimeJoinRequest> for RealtimeLookupFields {
    fn from(value: pb::RealtimeJoinRequest) -> Self {
        Self {
            scope: value.scope,
            call_id: value.call_id,
            session_id: value.session_id,
        }
    }
}

impl From<pb::RealtimeLeaveRequest> for RealtimeLookupFields {
    fn from(value: pb::RealtimeLeaveRequest) -> Self {
        Self {
            scope: value.scope,
            call_id: value.call_id,
            session_id: value.session_id,
        }
    }
}

impl From<pb::RealtimeStartWebRtcRequest> for RealtimeLookupFields {
    fn from(value: pb::RealtimeStartWebRtcRequest) -> Self {
        Self {
            scope: value.scope,
            call_id: value.call_id,
            session_id: value.session_id,
        }
    }
}

impl From<pb::RealtimeCloseWebRtcRequest> for RealtimeLookupFields {
    fn from(value: pb::RealtimeCloseWebRtcRequest) -> Self {
        Self {
            scope: value.scope,
            call_id: value.call_id,
            session_id: value.session_id,
        }
    }
}

impl From<pb::RealtimeSubscribeMediaRequest> for RealtimeLookupFields {
    fn from(value: pb::RealtimeSubscribeMediaRequest) -> Self {
        Self {
            scope: value.scope,
            call_id: value.call_id,
            session_id: value.session_id,
        }
    }
}

fn decode_realtime_lookup_fields(
    scope: Option<pb::TenantScope>,
    call_id: Option<pb::OpaqueId>,
    session_id: Option<pb::OpaqueId>,
) -> Result<(TenantScope, CallId, SessionId), CanonicalError> {
    Ok((
        decode_scope(scope.ok_or_else(invalid_argument)?)?,
        CallId::from_opaque(decode_opaque(call_id)?),
        SessionId::from_opaque(decode_opaque(session_id)?),
    ))
}

fn decode_media_subscription(
    value: pb::ConferenceMediaSubscription,
) -> Result<ConferenceMediaSubscription, CanonicalError> {
    Ok(ConferenceMediaSubscription {
        source: decode_principal_ref(value.source.ok_or_else(invalid_argument)?)?,
        media_kind: decode_media_kind(value.media_kind)?,
    })
}

fn decode_media_kind(value: i32) -> Result<MediaKind, CanonicalError> {
    match pb::MediaKind::try_from(value).map_err(|_| invalid_argument())? {
        pb::MediaKind::Unspecified => Err(invalid_argument()),
        pb::MediaKind::Audio => Ok(MediaKind::Audio),
        pb::MediaKind::Video => Ok(MediaKind::Video),
    }
}

fn decode_sfu_forward_envelope(
    value: pb::SfuForwardEnvelope,
) -> Result<SfuForwardEnvelope, CanonicalError> {
    let frame = value.frame.ok_or_else(invalid_argument)?;
    let header = frame.header.ok_or_else(invalid_argument)?;
    let nonce: [u8; 24] = frame.nonce.try_into().map_err(|_| invalid_argument())?;
    let signature = frame.source_signature.ok_or_else(invalid_argument)?;
    let media_kind = decode_media_kind(header.media_kind)?;
    let header_version = decode_group_media_header_version(header.header_version)?;
    let video_source_kind =
        decode_group_media_video_source(header_version, media_kind, header.video_source_kind)?;
    Ok(SfuForwardEnvelope {
        frame: EncryptedGroupMediaFrame {
            header: GroupMediaFrameHeader {
                scope: decode_scope(header.scope.ok_or_else(invalid_argument)?)?,
                call_id: CallId::from_opaque(decode_opaque(header.call_id)?),
                group_id: GroupId::from_opaque(decode_opaque(header.group_id)?),
                stream_id: decode_opaque(header.stream_id)?,
                source: decode_principal_ref(header.source.ok_or_else(invalid_argument)?)?,
                source_device_id: DeviceId::from_opaque(decode_opaque(header.source_device_id)?),
                negotiation_ref: decode_opaque(header.negotiation_ref)?,
                negotiation_generation: header.negotiation_generation,
                crypto_epoch: header.crypto_epoch,
                crypto_state_ref: decode_opaque(header.crypto_state_ref)?,
                crypto_suite: decode_crypto_suite(header.crypto_suite)?,
                header_version,
                media_kind,
                video_source_kind,
                sequence: header.sequence,
                media_timestamp: header.media_timestamp,
                keyframe: header.keyframe,
            },
            nonce,
            ciphertext: frame.ciphertext,
            source_signature: GroupMediaSourceSignature {
                key_id: KeyId::from_opaque(decode_opaque(signature.key_id)?),
                algorithm_id: signature.algorithm_id,
                algorithm_version: signature.algorithm_version,
                signature: signature.signature,
            },
        },
    })
}

fn decode_group_media_header_version(value: u32) -> Result<u8, CanonicalError> {
    match value {
        0 | 1 => Ok(GROUP_MEDIA_FRAME_HEADER_V1),
        2 => Ok(GROUP_MEDIA_FRAME_HEADER_V2),
        _ => Err(invalid_argument()),
    }
}

fn decode_group_media_video_source(
    header_version: u8,
    media_kind: MediaKind,
    value: Option<i32>,
) -> Result<Option<VideoSourceKind>, CanonicalError> {
    match (header_version, media_kind, value) {
        (GROUP_MEDIA_FRAME_HEADER_V1 | GROUP_MEDIA_FRAME_HEADER_V2, MediaKind::Audio, None) => {
            Ok(None)
        }
        (GROUP_MEDIA_FRAME_HEADER_V1, MediaKind::Video, None) => Ok(Some(VideoSourceKind::Camera)),
        (
            GROUP_MEDIA_FRAME_HEADER_V1 | GROUP_MEDIA_FRAME_HEADER_V2,
            MediaKind::Video,
            Some(value),
        ) => match pb::VideoSourceKind::try_from(value).map_err(|_| invalid_argument())? {
            pb::VideoSourceKind::Camera => Ok(Some(VideoSourceKind::Camera)),
            pb::VideoSourceKind::ScreenShare if header_version == GROUP_MEDIA_FRAME_HEADER_V2 => {
                Ok(Some(VideoSourceKind::ScreenShare))
            }
            _ => Err(invalid_argument()),
        },
        _ => Err(invalid_argument()),
    }
}

fn decode_crypto_suite(value: i32) -> Result<CryptoSuite, CanonicalError> {
    match pb::CryptoSuite::try_from(value).map_err(|_| invalid_argument())? {
        pb::CryptoSuite::Unspecified => Err(invalid_argument()),
        pb::CryptoSuite::UcrV1 => Ok(CryptoSuite::UcrV1),
    }
}

fn pb_sfu_forward_envelope(value: &SfuForwardEnvelope) -> pb::SfuForwardEnvelope {
    pb::SfuForwardEnvelope {
        frame: Some(pb::EncryptedGroupMediaFrame {
            header: Some(pb::GroupMediaFrameHeader {
                scope: Some(pb_scope(&value.frame.header.scope)),
                call_id: Some(pb_opaque(value.frame.header.call_id.as_opaque())),
                group_id: Some(pb_opaque(value.frame.header.group_id.as_opaque())),
                stream_id: Some(pb_opaque(&value.frame.header.stream_id)),
                source: Some(pb_principal_ref(&value.frame.header.source)),
                source_device_id: Some(pb_opaque(value.frame.header.source_device_id.as_opaque())),
                negotiation_ref: Some(pb_opaque(&value.frame.header.negotiation_ref)),
                negotiation_generation: value.frame.header.negotiation_generation,
                crypto_epoch: value.frame.header.crypto_epoch,
                crypto_state_ref: Some(pb_opaque(&value.frame.header.crypto_state_ref)),
                crypto_suite: pb_crypto_suite(value.frame.header.crypto_suite),
                media_kind: (match value.frame.header.media_kind {
                    MediaKind::Audio => pb::MediaKind::Audio,
                    MediaKind::Video => pb::MediaKind::Video,
                }) as i32,
                sequence: value.frame.header.sequence,
                media_timestamp: value.frame.header.media_timestamp,
                keyframe: value.frame.header.keyframe,
                header_version: u32::from(value.frame.header.header_version),
                video_source_kind: value.frame.header.video_source_kind.map(|source| {
                    (match source {
                        VideoSourceKind::Camera => pb::VideoSourceKind::Camera,
                        VideoSourceKind::ScreenShare => pb::VideoSourceKind::ScreenShare,
                    }) as i32
                }),
            }),
            nonce: value.frame.nonce.to_vec(),
            ciphertext: value.frame.ciphertext.clone(),
            source_signature: Some(pb::GroupMediaSourceSignature {
                key_id: Some(pb_opaque(value.frame.source_signature.key_id.as_opaque())),
                algorithm_id: value.frame.source_signature.algorithm_id.clone(),
                algorithm_version: value.frame.source_signature.algorithm_version,
                signature: value.frame.source_signature.signature.clone(),
            }),
        }),
    }
}

fn pb_realtime_session(
    claims: &RealtimeSessionClaims,
    admission: pb::RealtimeAdmissionState,
) -> pb::RealtimeSession {
    pb::RealtimeSession {
        scope: Some(pb_scope(&claims.scope)),
        call_id: Some(pb_opaque(claims.call_id.as_opaque())),
        session_id: Some(pb_opaque(claims.session_id.as_opaque())),
        participant: Some(pb_principal_ref(&claims.participant)),
        device_id: claims
            .device_id
            .as_ref()
            .map(|device_id| pb_opaque(device_id.as_opaque())),
        expires_at_unix_ms: claims.expires_at_unix_ms,
        heartbeat_interval_ms: REALTIME_HEARTBEAT_INTERVAL_MS,
        admission_state: admission as i32,
    }
}

fn validate_device_claim<S>(
    store: &S,
    claims: &RealtimeSessionClaims,
) -> Result<DeviceRef, CanonicalError>
where
    S: DeviceLifecycleStore + PrincipalIdentityBindingStore,
{
    let device_id = claims
        .device_id
        .as_ref()
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?;
    let device = store
        .device(&claims.scope, device_id)
        .map_err(map_store_error)?
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?;
    if device.state != DeviceLifecycleState::Active {
        return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
    }
    if claims.participant.kind == PrincipalKind::Device {
        if claims.participant.principal_id.as_opaque() != device_id.as_opaque() {
            return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
        }
    } else {
        let binding = store
            .principal_identity_binding(&claims.scope, &claims.participant)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Unauthenticated))?;
        if binding.identity_id != device.identity_id {
            return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
        }
    }
    Ok(DeviceRef {
        device_id: device.device_id,
        identity_id: device.identity_id,
    })
}

fn attendance_event<S>(
    store: &S,
    transition: &AttendanceTransition,
) -> Result<EventEnvelope, CanonicalError>
where
    S: DeviceLifecycleStore + PrincipalIdentityBindingStore,
{
    let device = validate_device_claim(store, &transition.claims)?;
    let event_type = attendance_event_type(transition.kind);
    let payload = pb::ConferenceAttendanceEvent {
        scope: Some(pb_scope(&transition.claims.scope)),
        call_id: Some(pb_opaque(transition.claims.call_id.as_opaque())),
        session_id: Some(pb_opaque(transition.claims.session_id.as_opaque())),
        participant: Some(pb_principal_ref(&transition.claims.participant)),
        device_id: transition
            .claims
            .device_id
            .as_ref()
            .map(|device_id| pb_opaque(device_id.as_opaque())),
        kind: pb_attendance_kind(transition.kind),
        occurred_at_unix_ms: transition.occurred_at_unix_ms,
        session_sequence: transition.session_sequence,
    }
    .encode_to_vec();
    let event_id_text = format!(
        "attendance-{}-{}-{}",
        transition.claims.session_id.as_opaque().as_str(),
        attendance_kind_slug(transition.kind),
        transition.session_sequence
    );
    let event_id = OpaqueId::new(event_id_text)
        .map(EventId::from_opaque)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
    let event = EventEnvelope {
        event_id,
        scope: transition.claims.scope.clone(),
        event_type: event_type.to_owned(),
        payload,
        actor: attendance_actor(&transition.claims),
        source_device: device,
        wall_time_unix_ms: transition.occurred_at_unix_ms,
        logical_order: transition.session_sequence,
        correlation: CorrelationContext {
            correlation_id: transition.claims.session_id.as_opaque().clone(),
            causation_id: None,
            idempotency_key: Some(format!(
                "attendance:{}:{}",
                attendance_kind_slug(transition.kind),
                transition.session_sequence
            )),
        },
        schema_version: RUNTIME_ENVELOPE_SCHEMA_V1,
        integrity_metadata: Vec::new(),
        extensions: Vec::new(),
    };
    canonical_event(&event).map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))
}

fn attendance_actor(claims: &RealtimeSessionClaims) -> ActorRef {
    let (actor_id, kind, on_behalf_of) = match claims.participant.kind {
        PrincipalKind::Person => (
            ActorId::from_opaque(claims.participant.principal_id.as_opaque().clone()),
            ActorKind::Person,
            None,
        ),
        PrincipalKind::AiAgent => (
            ActorId::from_opaque(claims.participant.principal_id.as_opaque().clone()),
            ActorKind::AiAgent,
            None,
        ),
        PrincipalKind::Bot => (
            ActorId::from_opaque(claims.participant.principal_id.as_opaque().clone()),
            ActorKind::Bot,
            None,
        ),
        PrincipalKind::Organization => (
            ActorId::from_opaque(claims.participant.principal_id.as_opaque().clone()),
            ActorKind::Organization,
            None,
        ),
        PrincipalKind::Device
        | PrincipalKind::ServiceAccount
        | PrincipalKind::Automation
        | PrincipalKind::ExternalPlatform => (
            ActorId::from_opaque(claims.session_id.as_opaque().clone()),
            ActorKind::System,
            Some(claims.participant.principal_id.clone()),
        ),
    };
    ActorRef {
        actor_id,
        kind,
        on_behalf_of,
    }
}

fn actor_for(claims: &RealtimeSessionClaims) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: claims.scope.clone(),
        principal: claims.participant.clone(),
    }
}

const fn attendance_event_type(kind: AttendanceTransitionKind) -> &'static str {
    match kind {
        AttendanceTransitionKind::Joined => "ucr.conference.attendance.joined.v1",
        AttendanceTransitionKind::Left => "ucr.conference.attendance.left.v1",
        AttendanceTransitionKind::Reconnected => "ucr.conference.attendance.reconnected.v1",
        AttendanceTransitionKind::MediaReady => "ucr.conference.attendance.media_ready.v1",
    }
}

const fn attendance_kind_slug(kind: AttendanceTransitionKind) -> &'static str {
    match kind {
        AttendanceTransitionKind::Joined => "joined",
        AttendanceTransitionKind::Left => "left",
        AttendanceTransitionKind::Reconnected => "reconnected",
        AttendanceTransitionKind::MediaReady => "media-ready",
    }
}

const fn pb_attendance_kind(kind: AttendanceTransitionKind) -> i32 {
    match kind {
        AttendanceTransitionKind::Joined => pb::ConferenceAttendanceKind::Joined as i32,
        AttendanceTransitionKind::Left => pb::ConferenceAttendanceKind::Left as i32,
        AttendanceTransitionKind::Reconnected => pb::ConferenceAttendanceKind::Reconnected as i32,
        AttendanceTransitionKind::MediaReady => pb::ConferenceAttendanceKind::MediaReady as i32,
    }
}

fn require_durable_grant_matches_claims(
    record: &ConferenceJoinGrantRecord,
    claims: &RealtimeSessionClaims,
) -> Result<(), CanonicalError> {
    let use_policy_matches = matches!(
        (record.use_policy, claims.use_policy),
        (
            ConferenceJoinGrantUsePolicy::SingleUse,
            ucr_realtime::JoinGrantUsePolicy::SingleUse
        ) | (
            ConferenceJoinGrantUsePolicy::Reusable,
            ucr_realtime::JoinGrantUsePolicy::Reusable
        )
    );
    if record.scope != claims.scope
        || record.call_id != claims.call_id
        || record.participant != claims.participant
        || claims.device_id.as_ref() != Some(&record.device_id)
        || record.session_id != claims.session_id
        || record.issued_at_unix_ms != claims.issued_at_unix_ms
        || record.not_before_unix_ms != claims.not_before_unix_ms
        || record.expires_at_unix_ms != claims.expires_at_unix_ms
        || !use_policy_matches
    {
        return Err(CanonicalError::new(CanonicalErrorCode::Unauthenticated));
    }
    Ok(())
}

fn pb_webrtc_description(description: &WebRtcSessionDescription) -> pb::WebRtcDescription {
    pb::WebRtcDescription {
        sdp_type: match description.sdp_type {
            WebRtcSdpType::Offer => pb::WebRtcSdpType::Offer as i32,
            WebRtcSdpType::Answer => pb::WebRtcSdpType::Answer as i32,
        },
        sdp: description.sdp.clone(),
    }
}

fn pb_webrtc_ice_server(server: &IceServerConfig) -> pb::WebRtcIceServer {
    pb::WebRtcIceServer {
        urls: server.urls.clone(),
        username: server.username.clone(),
        credential: server.credential.clone(),
    }
}

fn decode_webrtc_description(
    description: pb::WebRtcDescription,
) -> Result<(WebRtcSdpType, String), CanonicalError> {
    let sdp_type = match pb::WebRtcSdpType::try_from(description.sdp_type) {
        Ok(pb::WebRtcSdpType::Offer) => WebRtcSdpType::Offer,
        Ok(pb::WebRtcSdpType::Answer) => WebRtcSdpType::Answer,
        Ok(pb::WebRtcSdpType::Unspecified) | Err(_) => {
            return Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument));
        }
    };
    Ok((sdp_type, description.sdp))
}

const fn map_webrtc_provider_error(error: WebRtcProviderError) -> CanonicalError {
    match error {
        WebRtcProviderError::InvalidProtocol(_) => {
            CanonicalError::new(CanonicalErrorCode::InvalidArgument)
        }
        WebRtcProviderError::SessionUnavailable => {
            CanonicalError::new(CanonicalErrorCode::NotFound)
        }
        WebRtcProviderError::Conflict => CanonicalError::new(CanonicalErrorCode::Conflict),
        WebRtcProviderError::CapacityExceeded => {
            CanonicalError::new(CanonicalErrorCode::ResourceExhausted)
        }
        WebRtcProviderError::TemporarilyUnavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
        WebRtcProviderError::Internal => CanonicalError::new(CanonicalErrorCode::Internal),
    }
}

fn map_join_token_error(error: JoinTokenError) -> CanonicalError {
    match error {
        JoinTokenError::Malformed
        | JoinTokenError::InvalidSignature
        | JoinTokenError::NotYetValid
        | JoinTokenError::Expired
        | JoinTokenError::UnknownGrant
        | JoinTokenError::Revoked
        | JoinTokenError::AlreadyUsed => CanonicalError::new(CanonicalErrorCode::Unauthenticated),
        JoinTokenError::InvalidBaseUrl
        | JoinTokenError::InvalidTtl
        | JoinTokenError::InvalidWindow => CanonicalError::new(CanonicalErrorCode::InvalidArgument),
        JoinTokenError::CapacityExceeded => {
            CanonicalError::new(CanonicalErrorCode::ResourceExhausted)
        }
        JoinTokenError::StateUnavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
        JoinTokenError::ClockOverflow
        | JoinTokenError::RandomUnavailable
        | JoinTokenError::Internal => CanonicalError::new(CanonicalErrorCode::Internal),
    }
}

const fn map_registry_error(error: RealtimeRegistryError) -> CanonicalError {
    match error {
        RealtimeRegistryError::Expired | RealtimeRegistryError::ClaimMismatch => {
            CanonicalError::new(CanonicalErrorCode::Unauthenticated)
        }
        RealtimeRegistryError::CapacityExceeded => {
            CanonicalError::new(CanonicalErrorCode::ResourceExhausted)
        }
        RealtimeRegistryError::SessionUnavailable => {
            CanonicalError::new(CanonicalErrorCode::NotFound)
        }
        RealtimeRegistryError::SequenceOverflow => {
            CanonicalError::new(CanonicalErrorCode::Internal)
        }
    }
}

fn map_conference_error(error: &ConferenceError) -> CanonicalError {
    match error {
        ConferenceError::Protocol(_) => CanonicalError::new(CanonicalErrorCode::InvalidArgument),
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

fn status_from_canonical(error: CanonicalError) -> Status {
    let code = match error.code {
        CanonicalErrorCode::Unauthenticated => tonic::Code::Unauthenticated,
        CanonicalErrorCode::PermissionDenied | CanonicalErrorCode::PolicyDenied => {
            tonic::Code::PermissionDenied
        }
        CanonicalErrorCode::NotFound => tonic::Code::NotFound,
        CanonicalErrorCode::Conflict => tonic::Code::Aborted,
        CanonicalErrorCode::RateLimited | CanonicalErrorCode::ResourceExhausted => {
            tonic::Code::ResourceExhausted
        }
        CanonicalErrorCode::TemporarilyUnavailable => tonic::Code::Unavailable,
        CanonicalErrorCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        CanonicalErrorCode::Cancelled => tonic::Code::Cancelled,
        CanonicalErrorCode::InvalidArgument | CanonicalErrorCode::MalformedFrame => {
            tonic::Code::InvalidArgument
        }
        CanonicalErrorCode::CapabilityMismatch
        | CanonicalErrorCode::DowngradeRejected
        | CanonicalErrorCode::UnsupportedCriticalExtension => tonic::Code::FailedPrecondition,
        CanonicalErrorCode::IntegrityFailure => tonic::Code::DataLoss,
        CanonicalErrorCode::UnsupportedProtocolVersion => tonic::Code::Unimplemented,
        CanonicalErrorCode::Internal => tonic::Code::Internal,
    };
    Status::new(code, "realtime request rejected")
}

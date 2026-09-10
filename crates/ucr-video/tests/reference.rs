use std::sync::atomic::{AtomicBool, Ordering};

use ucr_core::{AuthorizationEvaluator, CallStore, ConversationStore, GroupStore};
use ucr_model::{
    AuthorizationRequest, CallId, CallParticipant, CallParticipantState, CallParticipantUpdateKind,
    CallSession, CallSignal, CallSignalKind, CallSignallingState, CapabilityDescriptor,
    ConversationId, ConversationKind, ConversationRecord, ConversationRef, DeliveryPolicy, EventId,
    GroupChange, GroupChangeKind, GroupCryptoState, GroupHistoryPolicy, GroupId, GroupMediaState,
    GroupOwnership, GroupRecord, GroupRole, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef,
    ProtocolExtension, ScopedPrincipal, TenantId, TenantScope, VideoCodecConfig, VideoSourceKind,
    VideoStreamDescriptor, VideoStreamId,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, CryptoSuite, H264_VIDEO_CODEC_CAPABILITY,
    MANDATORY_VIDEO_FRAME_RATE, MANDATORY_VIDEO_HEIGHT, MANDATORY_VIDEO_WIDTH,
    NegotiationResultEnvelope, ProtocolVersion, SCREEN_SHARE_VIDEO_CAPABILITY,
    VIDEO_MEDIA_CAPABILITY, phase21_video_capabilities,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_video::{
    PreparedVideoCapabilities, ResolvedVideoNegotiation, VideoCapabilityProvider, VideoError,
    VideoNegotiationResolver, VideoRuntime, preflight_h264_parameter_sets,
};

#[derive(Debug, Clone, Copy)]
struct AllowAll;

impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ToggleAuthorization(AtomicBool);

impl AuthorizationEvaluator for ToggleAuthorization {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        }
    }
}

#[derive(Debug)]
struct ToggleCapabilities(AtomicBool);

impl VideoCapabilityProvider for ToggleCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        if self.0.load(Ordering::SeqCst) {
            phase21_video_capabilities()
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NegotiationMode {
    Valid,
    Missing,
    MissingVideo,
    MissingScreenShare,
    WrongCodec,
    CriticalCapabilityExtension,
}

#[derive(Debug, Clone)]
struct TestNegotiations {
    mode: NegotiationMode,
    participants: Vec<PrincipalRef>,
}

fn negotiations_with_mode(call: &CallSession, mode: NegotiationMode) -> TestNegotiations {
    TestNegotiations {
        mode,
        participants: accepted_participants(call),
    }
}

fn negotiations_for(call: &CallSession) -> TestNegotiations {
    negotiations_with_mode(call, NegotiationMode::Valid)
}

impl VideoNegotiationResolver for TestNegotiations {
    fn resolve_video_negotiation(
        &self,
        requested_scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedVideoNegotiation>, CanonicalError> {
        if self.mode == NegotiationMode::Missing {
            return Ok(None);
        }
        let mut capabilities = phase21_video_capabilities();
        match self.mode {
            NegotiationMode::MissingVideo => {
                capabilities.retain(|c| c.id != VIDEO_MEDIA_CAPABILITY);
            }
            NegotiationMode::MissingScreenShare => {
                capabilities.retain(|c| c.id != SCREEN_SHARE_VIDEO_CAPABILITY);
            }
            NegotiationMode::CriticalCapabilityExtension => {
                capabilities[0].extensions.push(ProtocolExtension {
                    name: "vendor.video.remote-required".to_owned(),
                    critical: true,
                    payload: b"required".to_vec(),
                });
            }
            NegotiationMode::Valid | NegotiationMode::Missing | NegotiationMode::WrongCodec => {}
        }
        let mut selected_codec = camera_codec();
        if self.mode == NegotiationMode::WrongCodec {
            selected_codec.frame_rate = 30;
        }
        Ok(Some(ResolvedVideoNegotiation {
            scope: requested_scope.clone(),
            call_id: call_id.clone(),
            negotiation_ref: negotiation_ref.clone(),
            negotiation_generation,
            result: NegotiationResultEnvelope {
                version: ProtocolVersion::new(1, 0),
                capabilities,
                extensions: Vec::new(),
                transcript_binding: Vec::new(),
                crypto_suite: CryptoSuite::UcrV1,
            },
            selected_codec,
            negotiated_participants: self.participants.clone(),
        }))
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-video")),
        namespace_id: None,
    }
}

fn subject(id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(id)),
            kind: PrincipalKind::Person,
        },
    }
}

fn camera_codec() -> VideoCodecConfig {
    VideoCodecConfig {
        codec_capability_id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
        width: MANDATORY_VIDEO_WIDTH,
        height: MANDATORY_VIDEO_HEIGHT,
        frame_rate: MANDATORY_VIDEO_FRAME_RATE,
        target_bitrate_bps: 384_000,
    }
}

fn signal(session: &CallSession, id: &str, kind: CallSignalKind) -> CallSignal {
    CallSignal {
        event_id: EventId::from_opaque(oid(id)),
        scope: session.scope.clone(),
        call_id: session.call_id.clone(),
        expected_revision: session.revision,
        kind,
    }
}

fn direct_call(
    install_media_negotiation: bool,
) -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
) {
    let store = MemoryLocalStore::default();
    let alice = subject("alice-video");
    let bob = subject("bob-video");
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation-video")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };
    let session = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("call-video")),
        conversation: conversation.conversation.clone(),
        initiated_by: alice.principal.clone(),
        participants: vec![
            CallParticipant {
                principal: alice.principal.clone(),
                state: CallParticipantState::Accepted,
                joined_revision: 0,
                left_revision: None,
            },
            CallParticipant {
                principal: bob.principal.clone(),
                state: CallParticipantState::Invited,
                joined_revision: 0,
                left_revision: None,
            },
        ],
        signalling_state: CallSignallingState::Inviting,
        reconnecting_participant: None,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
    };
    store
        .persist_conversation(&conversation)
        .expect("conversation");
    store.create_call(&alice, &session).expect("call");
    store
        .apply_call_signal(
            &bob,
            &signal(&session, "accept-video", CallSignalKind::Accept),
        )
        .expect("accept");
    let mut active = store.call(&scope(), &session.call_id).unwrap().unwrap();
    if install_media_negotiation {
        store
            .apply_call_signal(
                &alice,
                &signal(
                    &active,
                    "install-video-negotiation",
                    CallSignalKind::MediaRenegotiation {
                        negotiation_ref: oid("video-negotiation-v1"),
                    },
                ),
            )
            .expect("negotiation");
        active = store.call(&scope(), &session.call_id).unwrap().unwrap();
    }
    (store, active, alice, bob)
}

fn active_call() -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
) {
    direct_call(true)
}

fn descriptor(
    call: &CallSession,
    source: &ScopedPrincipal,
    source_kind: VideoSourceKind,
) -> VideoStreamDescriptor {
    VideoStreamDescriptor {
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        stream_id: VideoStreamId::from_opaque(oid("video-stream")),
        source: source.principal.clone(),
        source_kind,
        codec: camera_codec(),
        negotiation_ref: call
            .media_negotiation_ref
            .clone()
            .expect("video negotiation"),
        negotiation_generation: call.media_negotiation_generation,
    }
}

fn accepted_participants(call: &CallSession) -> Vec<PrincipalRef> {
    call.participants
        .iter()
        .filter(|p| p.state == CallParticipantState::Accepted && p.left_revision.is_none())
        .map(|p| p.principal.clone())
        .collect()
}

fn solid_rgb(config: &VideoCodecConfig, value: u8) -> Vec<u8> {
    vec![value; usize::try_from(config.width * config.height * 3).expect("frame size")]
}

#[allow(clippy::too_many_lines)]
fn active_group_call() -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
    GroupRecord,
) {
    let store = MemoryLocalStore::default();
    let alice = subject("alice-group-video");
    let bob = subject("bob-group-video");
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation-group-video")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("group-video")),
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::PersonOwned(alice.principal.clone()),
        history_policy: GroupHistoryPolicy::FullHistory,
        delivery_policy: DeliveryPolicy::Durable,
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
    store
        .create_group(&conversation, &group, &alice)
        .expect("group");
    store
        .apply_group_change(
            &alice,
            &GroupChange {
                event_id: EventId::from_opaque(oid("add-bob-group-video")),
                scope: scope(),
                group_id: group.group_id.clone(),
                expected_revision: 0,
                kind: GroupChangeKind::AddMember {
                    member: bob.principal.clone(),
                    role: GroupRole::Member,
                },
                next_crypto_state: None,
            },
        )
        .expect("bob group");
    let session = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("call-group-video")),
        conversation: conversation.conversation,
        initiated_by: alice.principal.clone(),
        participants: vec![
            CallParticipant {
                principal: alice.principal.clone(),
                state: CallParticipantState::Accepted,
                joined_revision: 0,
                left_revision: None,
            },
            CallParticipant {
                principal: bob.principal.clone(),
                state: CallParticipantState::Invited,
                joined_revision: 0,
                left_revision: None,
            },
        ],
        signalling_state: CallSignallingState::Inviting,
        reconnecting_participant: None,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
    };
    store.create_call(&alice, &session).expect("group call");
    store
        .apply_call_signal(
            &bob,
            &signal(&session, "bob-accept-group-video", CallSignalKind::Accept),
        )
        .expect("accept");
    let active = store.call(&scope(), &session.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &alice,
            &signal(
                &active,
                "group-video-negotiation",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("group-video-negotiation-v1"),
                },
            ),
        )
        .expect("negotiation");
    let active = store.call(&scope(), &session.call_id).unwrap().unwrap();
    (store, active, alice, bob, group)
}

#[test]
fn direct_call_encodes_and_decodes_real_h264_with_redacted_payloads() {
    let (store, call, alice, bob) = active_call();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    let mut receiver = runtime.open_receiver(&bob, &stream).expect("receiver");
    let rgb = solid_rgb(&stream.codec, 96);
    let frame = sender.encode_rgb8(&rgb).expect("encode");
    assert!(!frame.payload.is_empty());
    assert_eq!(frame.sequence, 0);
    assert_eq!(frame.media_timestamp_us, 0);
    assert!(!format!("{frame:?}").contains(&format!("{:?}", frame.payload)));
    let decoded = receiver.decode_frame(&frame).expect("decode");
    assert_eq!((decoded.width, decoded.height), (320, 240));
    assert_eq!(decoded.rgb8.len(), rgb.len());
    assert!(!format!("{decoded:?}").contains(&format!("{:?}", decoded.rgb8)));
    assert_eq!(
        receiver.decode_frame(&frame),
        Err(VideoError::DuplicateOrOutOfOrder)
    );
}

#[test]
fn screen_share_is_an_explicit_negotiated_capability_and_real_h264_source() {
    let (store, call, alice, bob) = active_call();
    let mut negotiations = negotiations_for(&call);
    negotiations.participants = accepted_participants(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::ScreenShare);
    let mut sender = runtime.open_sender(&alice, &stream).expect("screen sender");
    let mut receiver = runtime
        .open_receiver(&bob, &stream)
        .expect("screen receiver");
    let frame = sender
        .encode_rgb8(&solid_rgb(&stream.codec, 32))
        .expect("screen encode");
    assert_eq!(
        receiver
            .decode_frame(&frame)
            .expect("screen decode")
            .rgb8
            .len(),
        320 * 240 * 3
    );

    let missing = negotiations_with_mode(&call, NegotiationMode::MissingScreenShare);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &missing);
    assert_eq!(
        runtime.open_sender(&alice, &stream).map(|_| ()),
        Err(VideoError::NegotiatedCapabilityUnavailable)
    );
}

#[test]
fn active_call_without_media_negotiation_cannot_open_video() {
    let (store, call, alice, _bob) = direct_call(false);
    let stream = VideoStreamDescriptor {
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        stream_id: VideoStreamId::from_opaque(oid("fabricated-video")),
        source: alice.principal.clone(),
        source_kind: VideoSourceKind::Camera,
        codec: camera_codec(),
        negotiation_ref: oid("fabricated-negotiation"),
        negotiation_generation: call.media_negotiation_generation,
    };
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    assert_eq!(
        runtime.open_sender(&alice, &stream).map(|_| ()),
        Err(VideoError::MissingNegotiation)
    );
}

#[test]
fn negotiated_video_capability_codec_and_extensions_fail_closed() {
    let (store, call, alice, _bob) = active_call();
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    for (mode, expected) in [
        (NegotiationMode::Missing, VideoError::MissingNegotiation),
        (
            NegotiationMode::MissingVideo,
            VideoError::NegotiatedCapabilityUnavailable,
        ),
        (
            NegotiationMode::WrongCodec,
            VideoError::NegotiatedCodecMismatch,
        ),
        (
            NegotiationMode::CriticalCapabilityExtension,
            VideoError::UnsupportedNegotiationExtension,
        ),
    ] {
        let negotiations = negotiations_with_mode(&call, mode);
        let runtime =
            VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
        assert_eq!(
            runtime.open_sender(&alice, &stream).map(|_| ()),
            Err(expected)
        );
    }
}

#[test]
fn media_renegotiation_invalidates_an_open_video_sender() {
    let (store, call, alice, _bob) = active_call();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    store
        .apply_call_signal(
            &alice,
            &signal(
                &call,
                "renegotiate-video",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("video-negotiation-v2"),
                },
            ),
        )
        .expect("renegotiate");
    assert_eq!(
        sender.encode_rgb8(&solid_rgb(&stream.codec, 0)),
        Err(VideoError::NegotiationGenerationMismatch)
    );
}

#[test]
fn runtime_permission_and_capability_revocation_stop_open_video() {
    let (store, call, alice, _bob) = active_call();
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let negotiations = negotiations_for(&call);
    let authorization = ToggleAuthorization(AtomicBool::new(true));
    let runtime = VideoRuntime::new(
        &authorization,
        &store,
        &PreparedVideoCapabilities,
        &negotiations,
    );
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    authorization.0.store(false, Ordering::SeqCst);
    assert!(matches!(
        sender.encode_rgb8(&solid_rgb(&stream.codec, 0)),
        Err(VideoError::Authorization(_))
    ));

    let capabilities = ToggleCapabilities(AtomicBool::new(true));
    let runtime = VideoRuntime::new(&AllowAll, &store, &capabilities, &negotiations);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    capabilities.0.store(false, Ordering::SeqCst);
    assert_eq!(
        sender.encode_rgb8(&solid_rgb(&stream.codec, 0)),
        Err(VideoError::CapabilityUnavailable)
    );
}

#[test]
fn invalid_rgb_length_fails_before_native_encoder_use() {
    let (store, call, alice, _bob) = active_call();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    assert_eq!(
        sender.encode_rgb8(&[0; 12]),
        Err(VideoError::RgbFrameLength)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn newly_accepted_group_participant_requires_fresh_video_negotiation() {
    let (store, call, alice, _bob, group) = active_group_call();
    let stale_negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(
        &AllowAll,
        &store,
        &PreparedVideoCapabilities,
        &stale_negotiations,
    );
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    sender
        .encode_rgb8(&solid_rgb(&stream.codec, 1))
        .expect("before membership change");

    let dave = subject("dave-group-video");
    store
        .apply_group_change(
            &alice,
            &GroupChange {
                event_id: EventId::from_opaque(oid("add-dave-group-video")),
                scope: scope(),
                group_id: group.group_id,
                expected_revision: 1,
                kind: GroupChangeKind::AddMember {
                    member: dave.principal.clone(),
                    role: GroupRole::Member,
                },
                next_crypto_state: None,
            },
        )
        .expect("add dave");
    let before_invite = store.call(&scope(), &call.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &alice,
            &signal(
                &before_invite,
                "invite-dave-video",
                CallSignalKind::ParticipantUpdate {
                    participant: dave.principal.clone(),
                    kind: CallParticipantUpdateKind::Add,
                },
            ),
        )
        .expect("invite dave");
    sender
        .encode_rgb8(&solid_rgb(&stream.codec, 2))
        .expect("invite alone preserves accepted set");
    let invited = store.call(&scope(), &call.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &dave,
            &signal(&invited, "dave-accept-video", CallSignalKind::Accept),
        )
        .expect("dave accepts");
    assert_eq!(
        sender.encode_rgb8(&solid_rgb(&stream.codec, 3)),
        Err(VideoError::NegotiatedParticipantSetMismatch)
    );

    let accepted = store.call(&scope(), &call.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &alice,
            &signal(
                &accepted,
                "fresh-group-video-negotiation",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("group-video-negotiation-v2"),
                },
            ),
        )
        .expect("fresh negotiation");
    let fresh_call = store.call(&scope(), &call.call_id).unwrap().unwrap();
    let fresh_negotiations = negotiations_for(&fresh_call);
    let runtime = VideoRuntime::new(
        &AllowAll,
        &store,
        &PreparedVideoCapabilities,
        &fresh_negotiations,
    );
    let fresh_stream = descriptor(&fresh_call, &alice, VideoSourceKind::Camera);
    let mut fresh_sender = runtime
        .open_sender(&alice, &fresh_stream)
        .expect("fresh sender");
    let mut dave_receiver = runtime
        .open_receiver(&dave, &fresh_stream)
        .expect("dave receiver");
    let frame = fresh_sender
        .encode_rgb8(&solid_rgb(&fresh_stream.codec, 4))
        .expect("fresh encode");
    assert_eq!(
        dave_receiver
            .decode_frame(&frame)
            .expect("fresh decode")
            .rgb8
            .len(),
        320 * 240 * 3
    );
}

#[test]
fn invited_group_participant_cannot_receive_video_before_accepting() {
    let (store, call, alice, _bob, group) = active_group_call();
    let dave = subject("dave-invited-video");
    store
        .apply_group_change(
            &alice,
            &GroupChange {
                event_id: EventId::from_opaque(oid("add-dave-invited-video")),
                scope: scope(),
                group_id: group.group_id,
                expected_revision: 1,
                kind: GroupChangeKind::AddMember {
                    member: dave.principal.clone(),
                    role: GroupRole::Member,
                },
                next_crypto_state: None,
            },
        )
        .expect("add dave");
    store
        .apply_call_signal(
            &alice,
            &signal(
                &call,
                "invite-dave-only-video",
                CallSignalKind::ParticipantUpdate {
                    participant: dave.principal.clone(),
                    kind: CallParticipantUpdateKind::Add,
                },
            ),
        )
        .expect("invite dave");
    let current = store.call(&scope(), &call.call_id).unwrap().unwrap();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&current, &alice, VideoSourceKind::Camera);
    assert_eq!(
        runtime.open_receiver(&dave, &stream).map(|_| ()),
        Err(VideoError::SubjectNotAccepted)
    );
}

#[test]
fn duplicate_or_incomplete_negotiated_participant_set_fails_closed() {
    let (store, call, alice, _bob) = active_call();
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut duplicate = negotiations_for(&call);
    duplicate
        .participants
        .push(duplicate.participants[0].clone());
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &duplicate);
    assert_eq!(
        runtime.open_sender(&alice, &stream).map(|_| ()),
        Err(VideoError::NegotiatedParticipantsInvalid)
    );

    let mut incomplete = negotiations_for(&call);
    incomplete.participants.pop();
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &incomplete);
    assert_eq!(
        runtime.open_sender(&alice, &stream).map(|_| ()),
        Err(VideoError::NegotiatedParticipantSetMismatch)
    );
}

#[test]
fn malformed_h264_does_not_advance_receiver_sequence_state() {
    let (store, call, alice, bob) = active_call();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    let mut receiver = runtime.open_receiver(&bob, &stream).expect("receiver");
    let valid = sender
        .encode_rgb8(&solid_rgb(&stream.codec, 64))
        .expect("encode");
    let mut corrupt = valid.clone();
    corrupt.payload = vec![0, 0, 0, 1, 0xff, 0x00, 0x01];
    assert!(matches!(
        receiver.decode_frame(&corrupt),
        Err(VideoError::Codec | VideoError::NoDecodedFrame)
    ));
    assert_eq!(
        receiver.decode_frame(&valid).expect("valid retry").sequence,
        valid.sequence
    );
}

#[test]
fn rejected_parameter_only_frame_resets_decoder_and_requires_fresh_sps() {
    let (store, call, alice, bob) = active_call();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    let mut receiver = runtime.open_receiver(&bob, &stream).expect("receiver");

    let keyframe = sender
        .encode_rgb8(&solid_rgb(&stream.codec, 12))
        .expect("keyframe");
    let delta = sender
        .encode_rgb8(&solid_rgb(&stream.codec, 24))
        .expect("delta");
    assert_eq!(
        preflight_h264_parameter_sets(&delta.payload, &stream.codec, false),
        Err(VideoError::MissingValidatedParameterSet)
    );

    let units = openh264::nal_units(&keyframe.payload).collect::<Vec<_>>();
    assert!(
        units.len() >= 3,
        "reference keyframe must carry SPS/PPS plus picture data"
    );
    let mut parameter_only = keyframe.clone();
    parameter_only.payload = units[..units.len() - 1].concat();
    assert!(matches!(
        receiver.decode_frame(&parameter_only),
        Err(VideoError::Codec | VideoError::NoDecodedFrame)
    ));
    assert_eq!(
        receiver.decode_frame(&delta),
        Err(VideoError::MissingValidatedParameterSet)
    );
    assert_eq!(
        receiver
            .decode_frame(&keyframe)
            .expect("fresh SPS retry")
            .sequence,
        keyframe.sequence
    );
}

#[test]
fn mismatched_h264_sps_dimensions_fail_before_native_decode() {
    use openh264::{
        OpenH264API,
        encoder::{Encoder, EncoderConfig, Level, Profile},
        formats::{RgbSliceU8, YUVBuffer},
    };

    let (store, call, alice, bob) = active_call();
    let negotiations = negotiations_for(&call);
    let runtime = VideoRuntime::new(&AllowAll, &store, &PreparedVideoCapabilities, &negotiations);
    let stream = descriptor(&call, &alice, VideoSourceKind::Camera);
    let mut receiver = runtime.open_receiver(&bob, &stream).expect("receiver");

    let wrong_width = 640_usize;
    let wrong_height = 480_usize;
    let wrong_rgb = vec![48_u8; wrong_width * wrong_height * 3];
    let source = RgbSliceU8::new(&wrong_rgb, (wrong_width, wrong_height));
    let yuv = YUVBuffer::from_rgb8_source(source);
    let wrong_config = EncoderConfig::new()
        .profile(Profile::Baseline)
        .level(Level::Level_4_0);
    let mut encoder = Encoder::with_api_config(OpenH264API::from_source(), wrong_config)
        .expect("wrong-size encoder");
    let payload = encoder.encode(&yuv).expect("wrong-size h264").to_vec();

    let frame = ucr_model::EncodedVideoFrame {
        scope: stream.scope.clone(),
        call_id: stream.call_id.clone(),
        stream_id: stream.stream_id.clone(),
        source: stream.source.clone(),
        negotiation_ref: stream.negotiation_ref.clone(),
        negotiation_generation: stream.negotiation_generation,
        sequence: 0,
        media_timestamp_us: 0,
        keyframe: true,
        payload,
    };
    assert_eq!(
        receiver.decode_frame(&frame),
        Err(VideoError::DecodedDimensionsMismatch)
    );
}

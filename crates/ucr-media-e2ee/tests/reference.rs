use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use ucr_audio::{
    AudioNegotiationResolver, AudioRuntime, PreparedAudioCapabilities, ResolvedAudioNegotiation,
};
use ucr_core::{AuthorizationEvaluator, CallStore, ConversationStore, GroupStore};
use ucr_crypto::{
    AgreementKeyPair, AgreementPublicKey, EstablishedSession, ReplayError, ReplayProtector,
    SessionHandshakeInput, SessionRole, SigningKeyMaterial, TranscriptBinding,
    TrustedKeyResolutionError, TrustedSessionHandshakeInput, TrustedSigningKeyResolver,
    VerifyingKeyBytes, begin_session, begin_session_with_trusted_peer, bind_media_e2ee_transcript,
};
use ucr_media_e2ee::{
    MediaE2eeCapabilityProvider, MediaE2eeError, MediaE2eeNegotiationResolver, MediaE2eeRuntime,
    PreparedMediaE2eeCapabilities, ResolvedMediaE2eeNegotiation,
};
use ucr_model::{
    AudioChannelLayout, AudioCodecConfig, AudioFrameDuration, AudioStreamDescriptor, AudioStreamId,
    AuthorizationRequest, CallId, CallParticipant, CallParticipantState, CallSession, CallSignal,
    CallSignalKind, CallSignallingState, CapabilityDescriptor, ConversationId, ConversationKind,
    ConversationRecord, ConversationRef, CryptoSuite, DeliveryPolicy, DeviceId, EventId,
    GroupChange, GroupChangeKind, GroupCryptoState, GroupHistoryPolicy, GroupId, GroupMediaState,
    GroupOwnership, GroupRecord, GroupRole, KeyId, KeyPurpose, MediaE2eeContext, OpaqueId,
    PrincipalId, PrincipalKind, PrincipalRef, ProtocolExtension, ProtocolVersion,
    PublicKeyDescriptor, ScopedPrincipal, TenantId, TenantScope, VideoCodecConfig, VideoSourceKind,
    VideoStreamDescriptor, VideoStreamId,
};
use ucr_protocol::{
    ALGORITHM_VERSION, H264_VIDEO_CODEC_CAPABILITY, KEY_FORMAT_VERSION, MANDATORY_VIDEO_FRAME_RATE,
    MANDATORY_VIDEO_HEIGHT, MANDATORY_VIDEO_WIDTH, MEDIA_E2EE_CAPABILITY,
    NegotiationResultEnvelope, OPUS_AUDIO_CODEC_CAPABILITY, SIGNATURE_ALGORITHM_ID,
    phase20_audio_capabilities, phase21_video_capabilities, phase22_media_e2ee_capabilities,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_video::{
    PreparedVideoCapabilities, ResolvedVideoNegotiation, VideoNegotiationResolver, VideoRuntime,
};

#[derive(Debug, Clone, Copy)]
struct AllowAll;

impl AuthorizationEvaluator for AllowAll {
    fn authorize(
        &self,
        _request: &AuthorizationRequest,
    ) -> Result<(), ucr_protocol::CanonicalError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ToggleAuthorization(AtomicBool);

impl AuthorizationEvaluator for ToggleAuthorization {
    fn authorize(
        &self,
        _request: &AuthorizationRequest,
    ) -> Result<(), ucr_protocol::CanonicalError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ucr_protocol::CanonicalError::new(
                ucr_protocol::CanonicalErrorCode::PermissionDenied,
            ))
        }
    }
}

#[derive(Debug)]
struct ToggleCapabilities(AtomicBool);

impl MediaE2eeCapabilityProvider for ToggleCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        if self.0.load(Ordering::SeqCst) {
            phase22_media_e2ee_capabilities()
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaNegotiationMode {
    Valid,
    MissingE2ee,
    CriticalExtension,
    IncompleteParticipants,
}

#[derive(Debug, Clone)]
struct TestMediaNegotiations {
    participants: Vec<PrincipalRef>,
    mode: MediaNegotiationMode,
}

impl MediaE2eeNegotiationResolver for TestMediaNegotiations {
    fn resolve_media_e2ee_negotiation(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedMediaE2eeNegotiation>, ucr_protocol::CanonicalError> {
        let mut capabilities = phase22_media_e2ee_capabilities();
        if self.mode == MediaNegotiationMode::MissingE2ee {
            capabilities.clear();
        }
        let mut extensions = Vec::new();
        if self.mode == MediaNegotiationMode::CriticalExtension {
            extensions.push(ProtocolExtension {
                name: "vendor.media.e2ee.required".to_owned(),
                critical: true,
                payload: b"required".to_vec(),
            });
        }
        let mut participants = self.participants.clone();
        if self.mode == MediaNegotiationMode::IncompleteParticipants {
            participants.pop();
        }
        Ok(Some(ResolvedMediaE2eeNegotiation {
            scope: scope.clone(),
            call_id: call_id.clone(),
            negotiation_ref: negotiation_ref.clone(),
            negotiation_generation,
            result: NegotiationResultEnvelope {
                version: ProtocolVersion::new(1, 0),
                capabilities,
                extensions,
                transcript_binding: Vec::new(),
                crypto_suite: CryptoSuite::UcrV1,
            },
            negotiated_participants: participants,
        }))
    }
}

#[derive(Debug, Clone)]
struct TestAudioNegotiations {
    participants: Vec<PrincipalRef>,
}

impl AudioNegotiationResolver for TestAudioNegotiations {
    fn resolve_audio_negotiation(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedAudioNegotiation>, ucr_protocol::CanonicalError> {
        Ok(Some(ResolvedAudioNegotiation {
            scope: scope.clone(),
            call_id: call_id.clone(),
            negotiation_ref: negotiation_ref.clone(),
            negotiation_generation,
            result: NegotiationResultEnvelope {
                version: ProtocolVersion::new(1, 0),
                capabilities: phase20_audio_capabilities(),
                extensions: Vec::new(),
                transcript_binding: Vec::new(),
                crypto_suite: CryptoSuite::UcrV1,
            },
            selected_codec: audio_codec(),
            negotiated_participants: self.participants.clone(),
        }))
    }
}

#[derive(Debug, Clone)]
struct TestVideoNegotiations {
    participants: Vec<PrincipalRef>,
}

impl VideoNegotiationResolver for TestVideoNegotiations {
    fn resolve_video_negotiation(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedVideoNegotiation>, ucr_protocol::CanonicalError> {
        Ok(Some(ResolvedVideoNegotiation {
            scope: scope.clone(),
            call_id: call_id.clone(),
            negotiation_ref: negotiation_ref.clone(),
            negotiation_generation,
            result: NegotiationResultEnvelope {
                version: ProtocolVersion::new(1, 0),
                capabilities: phase21_video_capabilities(),
                extensions: Vec::new(),
                transcript_binding: Vec::new(),
                crypto_suite: CryptoSuite::UcrV1,
            },
            selected_codec: video_codec(),
            negotiated_participants: self.participants.clone(),
        }))
    }
}

#[derive(Debug, Default)]
struct TestReplay {
    seen: Mutex<HashSet<([u8; 32], [u8; 32])>>,
}

impl ReplayProtector for TestReplay {
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError> {
        let mut seen = self.seen.lock().map_err(|_| ReplayError::Internal)?;
        if !seen.insert((peer_verifying_key.0, *binding.as_bytes())) {
            return Err(ReplayError::Replayed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TestTrust(PublicKeyDescriptor);

impl TrustedSigningKeyResolver for TestTrust {
    fn resolve_active_signing_key(
        &self,
        _scope: &TenantScope,
        device_id: &DeviceId,
        _identity_id: Option<&ucr_model::IdentityId>,
        key_id: &KeyId,
    ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError> {
        if &self.0.device_id == device_id && &self.0.key_id == key_id {
            Ok(self.0.clone())
        } else {
            Err(TrustedKeyResolutionError::NotTrusted)
        }
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-media-e2ee")),
        namespace_id: None,
    }
}

fn principal(value: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind: PrincipalKind::Person,
        },
    }
}

fn alice_device() -> DeviceId {
    DeviceId::from_opaque(oid("device-alice-media"))
}

fn bob_device() -> DeviceId {
    DeviceId::from_opaque(oid("device-bob-media"))
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

fn active_direct_call() -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
) {
    let store = MemoryLocalStore::default();
    let alice = principal("alice-media");
    let bob = principal("bob-media");
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation-media")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };
    store
        .persist_conversation(&conversation)
        .expect("conversation");
    let initial = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("call-media")),
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
    store.create_call(&alice, &initial).expect("call");
    store
        .apply_call_signal(
            &bob,
            &signal(&initial, "accept-media", CallSignalKind::Accept),
        )
        .expect("accept");
    let active = store.call(&scope(), &initial.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &alice,
            &signal(
                &active,
                "negotiation-media",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("negotiation-media-v1"),
                },
            ),
        )
        .expect("media negotiation");
    let active = store.call(&scope(), &initial.call_id).unwrap().unwrap();
    (store, active, alice, bob)
}

fn accepted(call: &CallSession) -> Vec<PrincipalRef> {
    call.participants
        .iter()
        .filter(|participant| {
            participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        })
        .map(|participant| participant.principal.clone())
        .collect()
}

fn context(
    call: &CallSession,
    alice: &ScopedPrincipal,
    bob: &ScopedPrincipal,
    epoch: u64,
) -> MediaE2eeContext {
    MediaE2eeContext {
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        initiator: alice.principal.clone(),
        responder: bob.principal.clone(),
        initiator_device_id: alice_device(),
        responder_device_id: bob_device(),
        negotiation_ref: call.media_negotiation_ref.clone().expect("negotiation"),
        negotiation_generation: call.media_negotiation_generation,
        key_epoch: epoch,
        crypto_suite: CryptoSuite::UcrV1,
    }
}

fn signing_descriptor(
    id: &str,
    device_id: DeviceId,
    key: &SigningKeyMaterial,
) -> PublicKeyDescriptor {
    PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid(id)),
        device_id,
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: key.verifying_key().0.to_vec(),
    }
}

struct SessionPair {
    alice: EstablishedSession,
    bob: EstablishedSession,
    initiator_ephemeral: AgreementPublicKey,
    responder_ephemeral: AgreementPublicKey,
}

fn established_pair(context: &MediaE2eeContext) -> SessionPair {
    let alice_signing = SigningKeyMaterial::generate().expect("alice signing");
    let bob_signing = SigningKeyMaterial::generate().expect("bob signing");
    let alice_agreement = AgreementKeyPair::generate().expect("alice agreement");
    let bob_agreement = AgreementKeyPair::generate().expect("bob agreement");
    let initiator_ephemeral = alice_agreement.public_key();
    let responder_ephemeral = bob_agreement.public_key();
    let binding = bind_media_e2ee_transcript(context, initiator_ephemeral, responder_ephemeral)
        .expect("media binding");
    let alice_descriptor = signing_descriptor("alice-signing", alice_device(), &alice_signing);
    let bob_descriptor = signing_descriptor("bob-signing", bob_device(), &bob_signing);
    let alice_pending = begin_session_with_trusted_peer(
        alice_agreement,
        &TrustedSessionHandshakeInput {
            scope: context.scope.clone(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: responder_ephemeral,
            initiator_public: initiator_ephemeral,
            responder_public: responder_ephemeral,
            peer_signing_descriptor: bob_descriptor.clone(),
            peer_signature: bob_signing.sign_transcript(&binding),
            binding,
        },
        &TestReplay::default(),
        &TestTrust(bob_descriptor),
    )
    .expect("alice pending");
    let bob_pending = begin_session_with_trusted_peer(
        bob_agreement,
        &TrustedSessionHandshakeInput {
            scope: context.scope.clone(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Responder,
            peer_agreement: initiator_ephemeral,
            initiator_public: initiator_ephemeral,
            responder_public: responder_ephemeral,
            peer_signing_descriptor: alice_descriptor.clone(),
            peer_signature: alice_signing.sign_transcript(&binding),
            binding,
        },
        &TestReplay::default(),
        &TestTrust(alice_descriptor),
    )
    .expect("bob pending");
    let alice_tag = alice_pending.local_confirmation_tag().expect("alice tag");
    let bob_tag = bob_pending.local_confirmation_tag().expect("bob tag");
    SessionPair {
        alice: alice_pending
            .confirm_peer(bob_tag)
            .expect("alice established"),
        bob: bob_pending
            .confirm_peer(alice_tag)
            .expect("bob established"),
        initiator_ephemeral,
        responder_ephemeral,
    }
}

fn raw_established_pair(
    context: &MediaE2eeContext,
) -> (
    (EstablishedSession, AgreementPublicKey, AgreementPublicKey),
    EstablishedSession,
) {
    let alice_signing = SigningKeyMaterial::generate().expect("alice signing");
    let bob_signing = SigningKeyMaterial::generate().expect("bob signing");
    let alice_agreement = AgreementKeyPair::generate().expect("alice agreement");
    let bob_agreement = AgreementKeyPair::generate().expect("bob agreement");
    let initiator_ephemeral = alice_agreement.public_key();
    let responder_ephemeral = bob_agreement.public_key();
    let binding = bind_media_e2ee_transcript(context, initiator_ephemeral, responder_ephemeral)
        .expect("binding");
    let alice_pending = begin_session(
        alice_agreement,
        SessionHandshakeInput {
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: responder_ephemeral,
            initiator_public: initiator_ephemeral,
            responder_public: responder_ephemeral,
            trusted_peer_verifying_key: bob_signing.verifying_key(),
            peer_signature: bob_signing.sign_transcript(&binding),
            binding,
        },
        &TestReplay::default(),
    )
    .expect("alice raw pending");
    let bob_pending = begin_session(
        bob_agreement,
        SessionHandshakeInput {
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Responder,
            peer_agreement: initiator_ephemeral,
            initiator_public: initiator_ephemeral,
            responder_public: responder_ephemeral,
            trusted_peer_verifying_key: alice_signing.verifying_key(),
            peer_signature: alice_signing.sign_transcript(&binding),
            binding,
        },
        &TestReplay::default(),
    )
    .expect("bob raw pending");
    let alice_tag = alice_pending.local_confirmation_tag().expect("alice tag");
    let bob_tag = bob_pending.local_confirmation_tag().expect("bob tag");
    let alice = alice_pending
        .confirm_peer(bob_tag)
        .expect("alice raw established");
    let bob = bob_pending
        .confirm_peer(alice_tag)
        .expect("bob raw established");
    ((alice, initiator_ephemeral, responder_ephemeral), bob)
}

fn media_negotiations(call: &CallSession) -> TestMediaNegotiations {
    TestMediaNegotiations {
        participants: accepted(call),
        mode: MediaNegotiationMode::Valid,
    }
}

fn audio_codec() -> AudioCodecConfig {
    AudioCodecConfig {
        codec_capability_id: OPUS_AUDIO_CODEC_CAPABILITY.to_owned(),
        sample_rate_hz: 48_000,
        channel_layout: AudioChannelLayout::Mono,
        frame_duration: AudioFrameDuration::Ms20,
    }
}

fn audio_descriptor(
    call: &CallSession,
    source: &ScopedPrincipal,
    stream: &str,
) -> AudioStreamDescriptor {
    AudioStreamDescriptor {
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        stream_id: AudioStreamId::from_opaque(oid(stream)),
        source: source.principal.clone(),
        codec: audio_codec(),
        negotiation_ref: call.media_negotiation_ref.clone().expect("negotiation"),
        negotiation_generation: call.media_negotiation_generation,
    }
}

fn video_codec() -> VideoCodecConfig {
    VideoCodecConfig {
        codec_capability_id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
        width: MANDATORY_VIDEO_WIDTH,
        height: MANDATORY_VIDEO_HEIGHT,
        frame_rate: MANDATORY_VIDEO_FRAME_RATE,
        target_bitrate_bps: 384_000,
    }
}

fn video_descriptor(call: &CallSession, source: &ScopedPrincipal) -> VideoStreamDescriptor {
    VideoStreamDescriptor {
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        stream_id: VideoStreamId::from_opaque(oid("video-e2ee-stream")),
        source: source.principal.clone(),
        source_kind: VideoSourceKind::Camera,
        codec: video_codec(),
        negotiation_ref: call.media_negotiation_ref.clone().expect("negotiation"),
        negotiation_generation: call.media_negotiation_generation,
    }
}

#[test]
fn direct_audio_uses_real_opus_then_authenticated_media_ciphertext() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let pair = established_pair(&context);
    let media_negotiations = media_negotiations(&call);
    let e2ee = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &media_negotiations,
    );
    let mut alice_e2ee = e2ee
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("alice e2ee");
    let mut bob_e2ee = e2ee
        .open_direct_session(
            &bob,
            &bob_device(),
            &context,
            pair.bob,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("bob e2ee");

    let audio_negotiations = TestAudioNegotiations {
        participants: accepted(&call),
    };
    let audio = AudioRuntime::new(
        &AllowAll,
        &store,
        &PreparedAudioCapabilities,
        &audio_negotiations,
    );
    let descriptor = audio_descriptor(&call, &alice, "audio-e2ee-stream");
    let mut sender = audio
        .open_sender(&alice, &descriptor)
        .expect("audio sender");
    let mut receiver = audio
        .open_receiver(&bob, &descriptor)
        .expect("audio receiver");
    let pcm = vec![100_i16; 960];
    let encoded = sender.encode_pcm(&pcm).expect("opus");
    let encrypted = alice_e2ee.seal_audio(&descriptor, &encoded).expect("seal");
    assert_ne!(encrypted.ciphertext, encoded.payload);
    let debug = format!("{encrypted:?}");
    assert!(!debug.contains(&format!("{:?}", encoded.payload)));
    assert!(debug.contains("<encrypted-media>"));
    let opened = bob_e2ee.open_audio(&descriptor, &encrypted).expect("open");
    assert_eq!(opened, encoded);
    assert_eq!(
        receiver.decode_frame(&opened).expect("opus decode").len(),
        pcm.len()
    );
}

#[test]
fn direct_video_uses_real_h264_then_authenticated_media_ciphertext() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let pair = established_pair(&context);
    let media_negotiations = media_negotiations(&call);
    let e2ee = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &media_negotiations,
    );
    let mut alice_e2ee = e2ee
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("alice e2ee");
    let mut bob_e2ee = e2ee
        .open_direct_session(
            &bob,
            &bob_device(),
            &context,
            pair.bob,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("bob e2ee");

    let video_negotiations = TestVideoNegotiations {
        participants: accepted(&call),
    };
    let video = VideoRuntime::new(
        &AllowAll,
        &store,
        &PreparedVideoCapabilities,
        &video_negotiations,
    );
    let descriptor = video_descriptor(&call, &alice);
    let mut sender = video
        .open_sender(&alice, &descriptor)
        .expect("video sender");
    let mut receiver = video
        .open_receiver(&bob, &descriptor)
        .expect("video receiver");
    let rgb = vec![88_u8; 320 * 240 * 3];
    let encoded = sender.encode_rgb8(&rgb).expect("h264");
    let encrypted = alice_e2ee.seal_video(&descriptor, &encoded).expect("seal");
    let opened = bob_e2ee.open_video(&descriptor, &encrypted).expect("open");
    assert_eq!(opened, encoded);
    assert_eq!(
        receiver
            .decode_frame(&opened)
            .expect("h264 decode")
            .rgb8
            .len(),
        rgb.len()
    );
}

#[test]
fn forged_high_sequence_cannot_poison_cryptographic_replay_state() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let pair = established_pair(&context);
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let mut alice_session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("alice");
    let mut bob_session = runtime
        .open_direct_session(
            &bob,
            &bob_device(),
            &context,
            pair.bob,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("bob");
    let descriptor = audio_descriptor(&call, &alice, "replay-stream");
    let encoded = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 7,
        media_timestamp_samples: 6720,
        payload: vec![1, 2, 3, 4],
    };
    let encrypted = alice_session
        .seal_audio(&descriptor, &encoded)
        .expect("seal");
    let mut forged = encrypted.clone();
    forged.header.sequence = u64::MAX - 1;
    assert!(matches!(
        bob_session.open_audio(&descriptor, &forged),
        Err(MediaE2eeError::Crypto(_))
    ));
    assert_eq!(
        bob_session
            .open_audio(&descriptor, &encrypted)
            .expect("valid after forged"),
        encoded
    );
    assert_eq!(
        bob_session.open_audio(&descriptor, &encrypted),
        Err(MediaE2eeError::Replay)
    );
}

#[test]
fn ciphertext_nonce_and_authenticated_header_tampering_fail_closed() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let descriptor = audio_descriptor(&call, &alice, "tamper-stream");
    let encoded = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 0,
        media_timestamp_samples: 0,
        payload: vec![9, 8, 7],
    };
    // Dedicated paired sessions make each failure independent and prove no partial plaintext.
    let pair = established_pair(&context);
    let mut sender = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("sender2");
    let mut receiver = runtime
        .open_direct_session(
            &bob,
            &bob_device(),
            &context,
            pair.bob,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("receiver2");
    let encrypted = sender.seal_audio(&descriptor, &encoded).expect("seal2");
    let mut changed = encrypted.clone();
    changed.ciphertext[0] ^= 1;
    assert!(matches!(
        receiver.open_audio(&descriptor, &changed),
        Err(MediaE2eeError::Crypto(_))
    ));
    changed = encrypted.clone();
    changed.nonce[0] ^= 1;
    assert!(matches!(
        receiver.open_audio(&descriptor, &changed),
        Err(MediaE2eeError::Crypto(_))
    ));
    changed = encrypted.clone();
    changed.header.media_timestamp ^= 1;
    assert!(matches!(
        receiver.open_audio(&descriptor, &changed),
        Err(MediaE2eeError::Crypto(_))
    ));
    assert_eq!(
        receiver
            .open_audio(&descriptor, &encrypted)
            .expect("original survives"),
        encoded
    );
}

#[test]
fn raw_authenticated_crypto_session_without_trusted_device_provenance_is_rejected() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let ((raw, initiator_ephemeral, responder_ephemeral), _peer) = raw_established_pair(&context);
    assert!(raw.authenticated_peer_device_id().is_none());
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    assert_eq!(
        runtime
            .open_direct_session(
                &alice,
                &alice_device(),
                &context,
                raw,
                initiator_ephemeral,
                responder_ephemeral
            )
            .map(|_| ()),
        Err(MediaE2eeError::UnauthenticatedPeerSession)
    );
}

#[test]
fn missing_e2ee_negotiation_critical_extension_and_incomplete_participants_fail_closed() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    for (mode, expected) in [
        (
            MediaNegotiationMode::MissingE2ee,
            MediaE2eeError::NegotiatedCapabilityUnavailable,
        ),
        (
            MediaNegotiationMode::CriticalExtension,
            MediaE2eeError::UnsupportedNegotiationExtension,
        ),
        (
            MediaNegotiationMode::IncompleteParticipants,
            MediaE2eeError::NegotiatedParticipantSetMismatch,
        ),
    ] {
        let pair = established_pair(&context);
        let negotiations = TestMediaNegotiations {
            participants: accepted(&call),
            mode,
        };
        let runtime = MediaE2eeRuntime::new(
            &AllowAll,
            &store,
            &PreparedMediaE2eeCapabilities,
            &negotiations,
        );
        assert_eq!(
            runtime
                .open_direct_session(
                    &alice,
                    &alice_device(),
                    &context,
                    pair.alice,
                    pair.initiator_ephemeral,
                    pair.responder_ephemeral
                )
                .map(|_| ()),
            Err(expected)
        );
    }
}

#[test]
fn media_renegotiation_invalidates_open_e2ee_session() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let pair = established_pair(&context);
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let mut session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("session");
    store
        .apply_call_signal(
            &alice,
            &signal(
                &call,
                "renegotiate-after-e2ee",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("negotiation-media-v2"),
                },
            ),
        )
        .expect("renegotiate");
    let descriptor = audio_descriptor(&call, &alice, "stale-stream");
    let frame = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 0,
        media_timestamp_samples: 0,
        payload: vec![1],
    };
    assert_eq!(
        session.seal_audio(&descriptor, &frame),
        Err(MediaE2eeError::NegotiationGenerationMismatch)
    );
}

#[test]
fn runtime_permission_and_local_e2ee_capability_revocation_stop_media() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let descriptor = audio_descriptor(&call, &alice, "revocation-stream");
    let frame = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 0,
        media_timestamp_samples: 0,
        payload: vec![1],
    };

    let authorization = ToggleAuthorization(AtomicBool::new(true));
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &authorization,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let pair = established_pair(&context);
    let mut session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("session");
    authorization.0.store(false, Ordering::SeqCst);
    assert!(matches!(
        session.seal_audio(&descriptor, &frame),
        Err(MediaE2eeError::Authorization(_))
    ));

    let capabilities = ToggleCapabilities(AtomicBool::new(true));
    let runtime = MediaE2eeRuntime::new(&AllowAll, &store, &capabilities, &negotiations);
    let pair = established_pair(&context);
    let mut session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("session");
    capabilities.0.store(false, Ordering::SeqCst);
    assert_eq!(
        session.seal_audio(&descriptor, &frame),
        Err(MediaE2eeError::CapabilityUnavailable)
    );
}

#[test]
fn explicit_key_rotation_requires_epoch_plus_one_and_fresh_ephemerals() {
    let (store, call, alice, bob) = active_direct_call();
    let context1 = context(&call, &alice, &bob, 1);
    let pair1 = established_pair(&context1);
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let mut alice_session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context1,
            pair1.alice,
            pair1.initiator_ephemeral,
            pair1.responder_ephemeral,
        )
        .expect("alice1");
    let mut bob_session = runtime
        .open_direct_session(
            &bob,
            &bob_device(),
            &context1,
            pair1.bob,
            pair1.initiator_ephemeral,
            pair1.responder_ephemeral,
        )
        .expect("bob1");
    let descriptor = audio_descriptor(&call, &alice, "rotation-stream");
    let frame = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 0,
        media_timestamp_samples: 0,
        payload: vec![5, 4, 3],
    };
    let old_encrypted = alice_session
        .seal_audio(&descriptor, &frame)
        .expect("old seal");
    assert_eq!(
        bob_session
            .open_audio(&descriptor, &old_encrypted)
            .expect("old open"),
        frame
    );

    let context2 = context(&call, &alice, &bob, 2);
    let pair2 = established_pair(&context2);
    let pair2_i = pair2.initiator_ephemeral;
    let pair2_r = pair2.responder_ephemeral;
    alice_session
        .rotate(&context2, pair2.alice, pair2_i, pair2_r)
        .expect("alice rotate");
    bob_session
        .rotate(&context2, pair2.bob, pair2_i, pair2_r)
        .expect("bob rotate");
    assert_eq!(
        bob_session.open_audio(&descriptor, &old_encrypted),
        Err(MediaE2eeError::Protocol(
            ucr_protocol::MediaE2eeProtocolError::ContextMismatch
        ))
    );
    let new_encrypted = alice_session
        .seal_audio(&descriptor, &frame)
        .expect("sequence resets per epoch");
    assert_eq!(
        bob_session
            .open_audio(&descriptor, &new_encrypted)
            .expect("new open"),
        frame
    );

    let pair3 = established_pair(&context2);
    assert_eq!(
        alice_session.rotate(
            &context2,
            pair3.alice,
            pair3.initiator_ephemeral,
            pair3.responder_ephemeral
        ),
        Err(MediaE2eeError::EpochRotationInvalid)
    );
}

#[test]
fn outbound_stream_cursor_budget_is_bounded() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let pair = established_pair(&context);
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let mut session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("session");
    for index in 0..ucr_protocol::MAX_MEDIA_STREAMS_PER_EPOCH {
        let descriptor = audio_descriptor(&call, &alice, &format!("stream-{index}"));
        let frame = ucr_model::EncodedAudioFrame {
            scope: descriptor.scope.clone(),
            call_id: descriptor.call_id.clone(),
            stream_id: descriptor.stream_id.clone(),
            source: descriptor.source.clone(),
            negotiation_ref: descriptor.negotiation_ref.clone(),
            negotiation_generation: descriptor.negotiation_generation,
            sequence: 0,
            media_timestamp_samples: 0,
            payload: vec![1],
        };
        session
            .seal_audio(&descriptor, &frame)
            .expect("within stream budget");
    }
    let descriptor = audio_descriptor(&call, &alice, "stream-over-budget");
    let frame = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 0,
        media_timestamp_samples: 0,
        payload: vec![1],
    };
    assert_eq!(
        session.seal_audio(&descriptor, &frame),
        Err(MediaE2eeError::StreamCapacityExceeded)
    );
}

fn group_e2ee_record(alice: &ScopedPrincipal, conversation: &ConversationRecord) -> GroupRecord {
    GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("group-e2ee")),
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
    }
}

fn active_group_e2ee_call() -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
) {
    let store = MemoryLocalStore::default();
    let alice = principal("alice-group-e2ee");
    let bob = principal("bob-group-e2ee");
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("group-conversation-e2ee")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = group_e2ee_record(&alice, &conversation);
    store
        .create_group(&conversation, &group, &alice)
        .expect("group");
    store
        .apply_group_change(
            &alice,
            &GroupChange {
                event_id: EventId::from_opaque(oid("add-bob-e2ee")),
                scope: scope(),
                group_id: group.group_id,
                expected_revision: 0,
                kind: GroupChangeKind::AddMember {
                    member: bob.principal.clone(),
                    role: GroupRole::Member,
                },
                next_crypto_state: None,
            },
        )
        .expect("add bob");
    let initial = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("group-call-e2ee")),
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
    store.create_call(&alice, &initial).expect("call");
    store
        .apply_call_signal(
            &bob,
            &signal(&initial, "accept-group-e2ee", CallSignalKind::Accept),
        )
        .expect("accept");
    let active = store.call(&scope(), &initial.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &alice,
            &signal(
                &active,
                "neg-group-e2ee",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("group-e2ee-negotiation"),
                },
            ),
        )
        .expect("negotiation");
    let active = store.call(&scope(), &initial.call_id).unwrap().unwrap();
    (store, active, alice, bob)
}

#[test]
fn group_calls_fail_closed_without_standardized_group_media_crypto_owner() {
    let (store, active, alice, bob) = active_group_e2ee_call();
    let context = context(&active, &alice, &bob, 1);
    let pair = established_pair(&context);
    let negotiations = media_negotiations(&active);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    assert_eq!(
        runtime
            .open_direct_session(
                &alice,
                &alice_device(),
                &context,
                pair.alice,
                pair.initiator_ephemeral,
                pair.responder_ephemeral,
            )
            .map(|_| ()),
        Err(MediaE2eeError::GroupCryptoUnavailable)
    );
}

#[test]
fn wrong_peer_device_is_rejected_even_with_valid_trusted_session() {
    let (store, call, alice, bob) = active_direct_call();
    let original = context(&call, &alice, &bob, 1);
    let pair = established_pair(&original);
    let mut wrong = original.clone();
    wrong.responder_device_id = DeviceId::from_opaque(oid("other-bob-device"));
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    assert_eq!(
        runtime
            .open_direct_session(
                &alice,
                &alice_device(),
                &wrong,
                pair.alice,
                pair.initiator_ephemeral,
                pair.responder_ephemeral,
            )
            .map(|_| ()),
        Err(MediaE2eeError::UnauthenticatedPeerSession)
    );
}

#[test]
fn outbound_sequence_must_increase_within_one_key_epoch() {
    let (store, call, alice, bob) = active_direct_call();
    let context = context(&call, &alice, &bob, 1);
    let pair = established_pair(&context);
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let mut session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context,
            pair.alice,
            pair.initiator_ephemeral,
            pair.responder_ephemeral,
        )
        .expect("session");
    let descriptor = audio_descriptor(&call, &alice, "sequence-stream");
    let frame = ucr_model::EncodedAudioFrame {
        scope: descriptor.scope.clone(),
        call_id: descriptor.call_id.clone(),
        stream_id: descriptor.stream_id.clone(),
        source: descriptor.source.clone(),
        negotiation_ref: descriptor.negotiation_ref.clone(),
        negotiation_generation: descriptor.negotiation_generation,
        sequence: 8,
        media_timestamp_samples: 7680,
        payload: vec![1],
    };
    session.seal_audio(&descriptor, &frame).expect("first");
    assert_eq!(
        session.seal_audio(&descriptor, &frame),
        Err(MediaE2eeError::OutboundSequenceRegression)
    );
}

#[test]
fn rotation_rejects_reused_role_ephemeral_before_accepting_new_keys() {
    let (store, call, alice, bob) = active_direct_call();
    let context1 = context(&call, &alice, &bob, 1);
    let pair1 = established_pair(&context1);
    let old_i = pair1.initiator_ephemeral;
    let old_r = pair1.responder_ephemeral;
    let negotiations = media_negotiations(&call);
    let runtime = MediaE2eeRuntime::new(
        &AllowAll,
        &store,
        &PreparedMediaE2eeCapabilities,
        &negotiations,
    );
    let mut session = runtime
        .open_direct_session(
            &alice,
            &alice_device(),
            &context1,
            pair1.alice,
            old_i,
            old_r,
        )
        .expect("session");
    let context2 = context(&call, &alice, &bob, 2);
    let pair2 = established_pair(&context2);
    assert_eq!(
        session.rotate(&context2, pair2.alice, old_i, pair2.responder_ephemeral),
        Err(MediaE2eeError::EphemeralReuse)
    );
}

#[test]
fn e2ee_capability_is_prepared_and_no_plaintext_fallback_capability_exists() {
    let capabilities = phase22_media_e2ee_capabilities();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].id, MEDIA_E2EE_CAPABILITY);
    assert_eq!(
        capabilities[0].maturity,
        ucr_model::CapabilityMaturity::Prepared
    );
}

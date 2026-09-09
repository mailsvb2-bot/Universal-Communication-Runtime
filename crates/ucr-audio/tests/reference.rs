use std::sync::atomic::{AtomicBool, Ordering};

use ucr_audio::{AudioCapabilityProvider, AudioError, AudioRuntime, PreparedAudioCapabilities};
use ucr_core::{AuthorizationEvaluator, CallStore, ConversationStore, GroupStore};
use ucr_model::{
    AudioChannelLayout, AudioCodecConfig, AudioFrameDuration, AudioStreamDescriptor, AudioStreamId,
    AuthorizationRequest, CallId, CallParticipant, CallParticipantState, CallParticipantUpdateKind,
    CallSession, CallSignal, CallSignalKind, CallSignallingState, CallTerminationReason,
    CapabilityDescriptor, ConversationId, ConversationKind, ConversationRecord, ConversationRef,
    DeliveryPolicy, EventId, GroupChange, GroupChangeKind, GroupCryptoState, GroupHistoryPolicy,
    GroupId, GroupMediaState, GroupOwnership, GroupRecord, GroupRole, OpaqueId, PrincipalId,
    PrincipalKind, PrincipalRef, ProtocolExtension, ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, MANDATORY_AUDIO_SAMPLE_RATE_HZ,
    OPUS_AUDIO_CODEC_CAPABILITY, phase20_audio_capabilities,
};
use ucr_storage_memory::MemoryLocalStore;

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

impl AudioCapabilityProvider for ToggleCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        if self.0.load(Ordering::SeqCst) {
            phase20_audio_capabilities()
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CriticalCapabilities;

impl AudioCapabilityProvider for CriticalCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        let mut capabilities = phase20_audio_capabilities();
        capabilities[0].extensions.push(ProtocolExtension {
            name: "vendor.audio.required-semantics".to_owned(),
            critical: true,
            payload: Vec::new(),
        });
        capabilities
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-audio")),
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

fn signal(session: &CallSession, id: &str, kind: CallSignalKind) -> CallSignal {
    CallSignal {
        event_id: EventId::from_opaque(oid(id)),
        scope: session.scope.clone(),
        call_id: session.call_id.clone(),
        expected_revision: session.revision,
        kind,
    }
}

fn active_call() -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
) {
    let store = MemoryLocalStore::default();
    let alice = subject("alice-audio");
    let bob = subject("bob-audio");
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation-audio")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };
    let session = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("call-audio")),
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
            &signal(&session, "accept-audio", CallSignalKind::Accept),
        )
        .expect("accept");
    let active = store.call(&scope(), &session.call_id).unwrap().unwrap();
    assert_eq!(active.signalling_state, CallSignallingState::Active);
    (store, active, alice, bob)
}

#[allow(clippy::too_many_lines)]
fn active_group_call() -> (
    MemoryLocalStore,
    CallSession,
    ScopedPrincipal,
    ScopedPrincipal,
    ScopedPrincipal,
    GroupRecord,
) {
    let store = MemoryLocalStore::default();
    let alice = subject("alice-group-audio");
    let bob = subject("bob-group-audio");
    let charlie = subject("charlie-group-audio");
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation-group-audio")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("group-audio")),
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
    for (revision, id, member) in [
        (0, "add-bob-group-audio", bob.principal.clone()),
        (1, "add-charlie-group-audio", charlie.principal.clone()),
    ] {
        store
            .apply_group_change(
                &alice,
                &GroupChange {
                    event_id: EventId::from_opaque(oid(id)),
                    scope: scope(),
                    group_id: group.group_id.clone(),
                    expected_revision: revision,
                    kind: GroupChangeKind::AddMember {
                        member,
                        role: GroupRole::Member,
                    },
                    next_crypto_state: None,
                },
            )
            .expect("add group member");
    }
    let session = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("call-group-audio")),
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
            CallParticipant {
                principal: charlie.principal.clone(),
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
            &signal(&session, "bob-accept-group-audio", CallSignalKind::Accept),
        )
        .expect("bob accept");
    let after_bob = store.call(&scope(), &session.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            &charlie,
            &signal(
                &after_bob,
                "charlie-accept-group-audio",
                CallSignalKind::Accept,
            ),
        )
        .expect("charlie accept");
    let active = store.call(&scope(), &session.call_id).unwrap().unwrap();
    assert_eq!(active.signalling_state, CallSignallingState::Active);
    (store, active, alice, bob, charlie, group)
}

fn descriptor(call: &CallSession, source: &ScopedPrincipal) -> AudioStreamDescriptor {
    AudioStreamDescriptor {
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        stream_id: AudioStreamId::from_opaque(oid("audio-stream")),
        source: source.principal.clone(),
        codec: AudioCodecConfig {
            codec_capability_id: OPUS_AUDIO_CODEC_CAPABILITY.to_owned(),
            sample_rate_hz: MANDATORY_AUDIO_SAMPLE_RATE_HZ,
            channel_layout: AudioChannelLayout::Mono,
            frame_duration: AudioFrameDuration::Ms20,
        },
        negotiation_generation: call.media_negotiation_generation,
    }
}

#[test]
fn direct_call_encodes_and_decodes_real_opus_without_media_brain_duplication() {
    let (store, call, alice, bob) = active_call();
    let runtime = AudioRuntime::new(&AllowAll, &store, &PreparedAudioCapabilities);
    let descriptor = descriptor(&call, &alice);
    let mut sender = runtime.open_sender(&alice, &descriptor).expect("sender");
    let mut receiver = runtime.open_receiver(&bob, &descriptor).expect("receiver");

    let pcm = vec![0_i16; 960];
    let frame = sender.encode_pcm(&pcm).expect("encode");
    assert!(!frame.payload.is_empty());
    assert_eq!(frame.sequence, 0);
    assert_eq!(frame.media_timestamp_samples, 0);
    assert!(!format!("{frame:?}").contains(&format!("{:?}", frame.payload)));

    let decoded = receiver.decode_frame(&frame).expect("decode");
    assert_eq!(decoded.len(), pcm.len());
    assert_eq!(
        receiver.decode_frame(&frame),
        Err(AudioError::DuplicateOrOutOfOrder)
    );
}

#[test]
fn media_renegotiation_invalidates_open_audio_stream_before_next_frame() {
    let (store, call, alice, _bob) = active_call();
    let runtime = AudioRuntime::new(&AllowAll, &store, &PreparedAudioCapabilities);
    let descriptor = descriptor(&call, &alice);
    let mut sender = runtime.open_sender(&alice, &descriptor).expect("sender");

    store
        .apply_call_signal(
            &alice,
            &signal(
                &call,
                "renegotiate-audio",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("audio-negotiation-v2"),
                },
            ),
        )
        .expect("renegotiate");

    assert_eq!(
        sender.encode_pcm(&vec![0_i16; 960]),
        Err(AudioError::NegotiationGenerationMismatch)
    );
}

#[test]
fn terminated_call_revokes_open_audio_sender_before_next_frame() {
    let (store, call, alice, _bob) = active_call();
    let runtime = AudioRuntime::new(&AllowAll, &store, &PreparedAudioCapabilities);
    let descriptor = descriptor(&call, &alice);
    let mut sender = runtime.open_sender(&alice, &descriptor).expect("sender");

    store
        .apply_call_signal(
            &alice,
            &signal(
                &call,
                "terminate-audio",
                CallSignalKind::Terminate {
                    reason: CallTerminationReason::Completed,
                },
            ),
        )
        .expect("terminate");

    assert!(matches!(
        sender.encode_pcm(&vec![0_i16; 960]),
        Err(AudioError::CallUnavailable | AudioError::CallNotActive)
    ));
}

#[test]
fn group_audio_reuses_group_call_authority_and_revokes_open_sender_on_removal() {
    let (store, call, alice, _bob, charlie, group) = active_group_call();
    let runtime = AudioRuntime::new(&AllowAll, &store, &PreparedAudioCapabilities);
    let mut stream = descriptor(&call, &charlie);
    stream.stream_id = AudioStreamId::from_opaque(oid("group-audio-stream"));
    let mut sender = runtime
        .open_sender(&charlie, &stream)
        .expect("group sender");
    let mut receiver = runtime
        .open_receiver(&alice, &stream)
        .expect("group receiver");

    let frame = sender.encode_pcm(&vec![0_i16; 960]).expect("group encode");
    assert_eq!(
        receiver.decode_frame(&frame).expect("group decode").len(),
        960
    );

    store
        .apply_group_change(
            &alice,
            &GroupChange {
                event_id: EventId::from_opaque(oid("remove-charlie-group-audio")),
                scope: scope(),
                group_id: group.group_id,
                expected_revision: 2,
                kind: GroupChangeKind::RemoveMember {
                    member: charlie.principal,
                },
                next_crypto_state: None,
            },
        )
        .expect("remove source from group");

    assert!(matches!(
        sender.encode_pcm(&vec![0_i16; 960]),
        Err(AudioError::CallUnavailable
            | AudioError::SubjectNotAccepted
            | AudioError::SourceNotAccepted)
    ));
    assert!(matches!(
        receiver.decode_frame(&frame),
        Err(AudioError::CallUnavailable | AudioError::SourceNotAccepted)
    ));
}

#[test]
fn runtime_capability_revocation_stops_an_already_open_sender() {
    let (store, call, alice, _bob) = active_call();
    let capabilities = ToggleCapabilities(AtomicBool::new(true));
    let runtime = AudioRuntime::new(&AllowAll, &store, &capabilities);
    let stream = descriptor(&call, &alice);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    sender.encode_pcm(&vec![0_i16; 960]).expect("first frame");

    capabilities.0.store(false, Ordering::SeqCst);
    assert_eq!(
        sender.encode_pcm(&vec![0_i16; 960]),
        Err(AudioError::CapabilityUnavailable)
    );
}

#[test]
fn invited_group_participant_cannot_receive_active_call_audio_before_accepting() {
    let (store, call, alice, _bob, _charlie, group) = active_group_call();
    let dave = subject("dave-group-audio");
    store
        .apply_group_change(
            &alice,
            &GroupChange {
                event_id: EventId::from_opaque(oid("add-dave-group-audio")),
                scope: scope(),
                group_id: group.group_id,
                expected_revision: 2,
                kind: GroupChangeKind::AddMember {
                    member: dave.principal.clone(),
                    role: GroupRole::Member,
                },
                next_crypto_state: None,
            },
        )
        .expect("add invited listener to group");
    store
        .apply_call_signal(
            &alice,
            &signal(
                &call,
                "invite-dave-to-active-audio-call",
                CallSignalKind::ParticipantUpdate {
                    participant: dave.principal.clone(),
                    kind: CallParticipantUpdateKind::Add,
                },
            ),
        )
        .expect("invite listener to active call");
    let current = store.call(&scope(), &call.call_id).unwrap().unwrap();
    let stream = descriptor(&current, &alice);
    let runtime = AudioRuntime::new(&AllowAll, &store, &PreparedAudioCapabilities);
    assert_eq!(
        runtime.open_receiver(&dave, &stream).map(|_| ()),
        Err(AudioError::SubjectNotAccepted)
    );
}

#[test]
fn unsupported_critical_audio_capability_extension_fails_closed() {
    let (store, call, alice, _bob) = active_call();
    let stream = descriptor(&call, &alice);
    let runtime = AudioRuntime::new(&AllowAll, &store, &CriticalCapabilities);
    assert_eq!(
        runtime.open_sender(&alice, &stream).map(|_| ()),
        Err(AudioError::CapabilityUnavailable)
    );
}

#[test]
fn runtime_permission_revocation_stops_an_already_open_sender() {
    let (store, call, alice, _bob) = active_call();
    let authorization = ToggleAuthorization(AtomicBool::new(true));
    let runtime = AudioRuntime::new(&authorization, &store, &PreparedAudioCapabilities);
    let stream = descriptor(&call, &alice);
    let mut sender = runtime.open_sender(&alice, &stream).expect("sender");
    sender.encode_pcm(&vec![0_i16; 960]).expect("first frame");

    authorization.0.store(false, Ordering::SeqCst);
    assert_eq!(
        sender.encode_pcm(&vec![0_i16; 960]),
        Err(AudioError::Authorization(CanonicalError::new(
            CanonicalErrorCode::PermissionDenied
        )))
    );
}

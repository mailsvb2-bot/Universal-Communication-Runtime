use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, GroupStore, IdentityStore,
    PrincipalIdentityBindingStore, TrustedSigningKeyStore,
};
use ucr_crypto::{GroupMediaEpochSecret, SigningKeyMaterial};
use ucr_media_e2ee::{GroupMediaE2eeRuntime, PreparedGroupMediaE2eeCapabilities};
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, CanonicalError, CanonicalErrorCode, GROUP_MEDIA_FRAME_HEADER_V2,
    GROUP_MLS_CAPABILITY, KEY_FORMAT_VERSION, NegotiatedSession, SCREEN_SHARE_SEND_PERMISSION,
    SCREEN_SHARE_VIDEO_CAPABILITY, SIGNATURE_ALGORITHM_ID, VIDEO_RECEIVE_PERMISSION,
    VIDEO_SEND_PERMISSION, screen_share_v2_negotiation,
};
use ucr_sfu::{
    PreparedSfuCapabilities, SfuError, SfuForwardOutcome, SfuForwardSink, SfuForwardSinkError,
    SfuRuntime, dispatch_validated_forward_batch,
};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct DenyReceive;
impl AuthorizationEvaluator for DenyReceive {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if request.permission.ends_with(".receive") {
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
struct CountingAuthorization {
    sends: AtomicUsize,
    receives: AtomicUsize,
}

impl AuthorizationEvaluator for CountingAuthorization {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if request.permission == VIDEO_SEND_PERMISSION {
            self.sends.fetch_add(1, Ordering::Relaxed);
        }
        if request.permission == VIDEO_RECEIVE_PERMISSION {
            self.receives.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct DenyScreenShareSend;
impl AuthorizationEvaluator for DenyScreenShareSend {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if request.permission == SCREEN_SHARE_SEND_PERMISSION {
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
struct CaptureSink {
    forwarded: Mutex<Vec<(SfuForwardTarget, SfuForwardEnvelope)>>,
}
impl CaptureSink {
    fn forwarded(&self) -> Vec<(SfuForwardTarget, SfuForwardEnvelope)> {
        self.forwarded.lock().expect("sink lock").clone()
    }
}
impl SfuForwardSink for CaptureSink {
    fn forward_encrypted(
        &self,
        target: &SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        self.forwarded
            .lock()
            .expect("sink lock")
            .push((target.clone(), envelope.clone()));
        Ok(())
    }
}

#[derive(Debug)]
struct FailAfterOne {
    accepted: Mutex<usize>,
}
impl FailAfterOne {
    fn new() -> Self {
        Self {
            accepted: Mutex::new(0),
        }
    }
}
impl SfuForwardSink for FailAfterOne {
    fn forward_encrypted(
        &self,
        _target: &SfuForwardTarget,
        _envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let mut accepted = self.accepted.lock().expect("sink lock");
        if *accepted == 1 {
            return Err(SfuForwardSinkError::Backpressure);
        }
        *accepted += 1;
        Ok(())
    }
}

struct Fixture {
    store: MemoryLocalStore,
    alice: ScopedPrincipal,
    bob: ScopedPrincipal,
    charlie: ScopedPrincipal,
    alice_device: DeviceId,
    signer: SigningKeyMaterial,
    signing_key_id: KeyId,
    call: CallSession,
    group: GroupRecord,
    envelope: SfuForwardEnvelope,
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-sfu-group")),
        namespace_id: None,
    }
}
fn principal(name: &str) -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid(name)),
        kind: PrincipalKind::Person,
    }
}
fn subject(name: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: principal(name),
    }
}
fn device(name: &str) -> DeviceId {
    DeviceId::from_opaque(oid(&format!("device-{name}")))
}
fn identity(name: &str) -> IdentityId {
    IdentityId::from_opaque(oid(&format!("identity-{name}")))
}

fn install_person(store: &MemoryLocalStore, name: &str) {
    let identity_id = identity(name);
    store
        .persist_identity(&IdentityRecord {
            scope: scope(),
            identity_id: identity_id.clone(),
            ownership: IdentityOwnership::UcrNative,
            evidence: IdentityEvidence::DeviceVerified,
            expires_at_unix_ms: None,
        })
        .expect("identity");
    store
        .persist_principal_identity_binding(&PrincipalIdentityBinding {
            scope: scope(),
            principal: principal(name),
            identity_id: identity_id.clone(),
        })
        .expect("binding");
    store
        .register_device(
            &scope(),
            &DeviceDescriptor {
                device_id: device(name),
                identity_id,
                state: DeviceLifecycleState::Active,
            },
        )
        .expect("device");
}

fn crypto_state(epoch: u64) -> GroupCryptoState {
    GroupCryptoState {
        capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
        epoch,
        state_ref: Some(oid(&format!("mls-state-{epoch}"))),
    }
}

fn group_change(
    group: &GroupRecord,
    event: &str,
    revision: u64,
    kind: GroupChangeKind,
    next_epoch: u64,
) -> GroupChange {
    GroupChange {
        event_id: EventId::from_opaque(oid(event)),
        scope: scope(),
        group_id: group.group_id.clone(),
        expected_revision: revision,
        kind,
        next_crypto_state: Some(crypto_state(next_epoch)),
    }
}

fn signal(call: &CallSession, id: &str, kind: CallSignalKind) -> CallSignal {
    CallSignal {
        event_id: EventId::from_opaque(oid(id)),
        scope: call.scope.clone(),
        call_id: call.call_id.clone(),
        expected_revision: call.revision,
        kind,
    }
}

fn install_alice_signing_key(store: &MemoryLocalStore) -> (SigningKeyMaterial, KeyId) {
    let signer = SigningKeyMaterial::generate().expect("signing key");
    let key_id = KeyId::from_opaque(oid("alice-signing-key"));
    store
        .provision_trusted_signing_key(
            &scope(),
            &PublicKeyDescriptor {
                key_id: key_id.clone(),
                device_id: device("alice"),
                purpose: KeyPurpose::Signing,
                algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                algorithm_version: ALGORITHM_VERSION,
                key_format_version: KEY_FORMAT_VERSION,
                public_key: signer.verifying_key().0.to_vec(),
            },
        )
        .expect("trusted signing key");
    (signer, key_id)
}

fn install_additional_person_device(
    store: &MemoryLocalStore,
    person_name: &str,
    device_name: &str,
    key_name: &str,
) -> (DeviceId, SigningKeyMaterial, KeyId) {
    let device_id = device(device_name);
    store
        .register_device(
            &scope(),
            &DeviceDescriptor {
                device_id: device_id.clone(),
                identity_id: identity(person_name),
                state: DeviceLifecycleState::Active,
            },
        )
        .expect("additional device");
    let signer = SigningKeyMaterial::generate().expect("additional signing key");
    let key_id = KeyId::from_opaque(oid(key_name));
    store
        .provision_trusted_signing_key(
            &scope(),
            &PublicKeyDescriptor {
                key_id: key_id.clone(),
                device_id: device_id.clone(),
                purpose: KeyPurpose::Signing,
                algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                algorithm_version: ALGORITHM_VERSION,
                key_format_version: KEY_FORMAT_VERSION,
                public_key: signer.verifying_key().0.to_vec(),
            },
        )
        .expect("additional trusted signing key");
    (device_id, signer, key_id)
}

fn group_media_context(group: &GroupRecord, call: &CallSession) -> GroupMediaE2eeContext {
    GroupMediaE2eeContext {
        scope: scope(),
        call_id: call.call_id.clone(),
        group_id: group.group_id.clone(),
        negotiation_ref: call.media_negotiation_ref.clone().expect("negotiation ref"),
        negotiation_generation: call.media_negotiation_generation,
        crypto_epoch: group.crypto_state.epoch,
        crypto_state_ref: group.crypto_state.state_ref.clone().expect("state ref"),
        crypto_suite: CryptoSuite::UcrV1,
    }
}

fn build_group(
    store: &MemoryLocalStore,
    alice: &ScopedPrincipal,
    bob: &ScopedPrincipal,
    charlie: &ScopedPrincipal,
) -> (ConversationRecord, GroupRecord) {
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation-sfu-group")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let initial = GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("group-sfu")),
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::PersonOwned(alice.principal.clone()),
        history_policy: GroupHistoryPolicy::FullHistory,
        delivery_policy: DeliveryPolicy::Durable,
        crypto_state: crypto_state(0),
        public_policy: None,
        media_state: GroupMediaState::Idle,
        bridge_mappings: Vec::new(),
        replication_generation: 0,
        revision: 0,
    };
    store
        .create_group(&conversation, &initial, alice)
        .expect("group");
    store
        .apply_group_change(
            alice,
            &group_change(
                &initial,
                "add-bob",
                0,
                GroupChangeKind::AddMember {
                    member: bob.principal.clone(),
                    role: GroupRole::Member,
                },
                1,
            ),
        )
        .expect("add bob");
    let group = store.group(&scope(), &initial.group_id).unwrap().unwrap();
    store
        .apply_group_change(
            alice,
            &group_change(
                &group,
                "add-charlie",
                1,
                GroupChangeKind::AddMember {
                    member: charlie.principal.clone(),
                    role: GroupRole::Member,
                },
                2,
            ),
        )
        .expect("add charlie");
    let group = store.group(&scope(), &initial.group_id).unwrap().unwrap();
    (conversation, group)
}

fn build_call(
    store: &MemoryLocalStore,
    conversation: &ConversationRecord,
    alice: &ScopedPrincipal,
    bob: &ScopedPrincipal,
    charlie: &ScopedPrincipal,
) -> CallSession {
    let initial = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("call-sfu-group")),
        conversation: conversation.conversation.clone(),
        initiated_by: alice.principal.clone(),
        participants: [alice, bob, charlie]
            .into_iter()
            .enumerate()
            .map(|(index, participant)| CallParticipant {
                principal: participant.principal.clone(),
                state: if index == 0 {
                    CallParticipantState::Accepted
                } else {
                    CallParticipantState::Invited
                },
                joined_revision: 0,
                left_revision: None,
            })
            .collect(),
        signalling_state: CallSignallingState::Inviting,
        reconnecting_participant: None,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
    };
    store.create_call(alice, &initial).expect("call");
    for (participant, event) in [(bob, "accept-bob"), (charlie, "accept-charlie")] {
        let current = store.call(&scope(), &initial.call_id).unwrap().unwrap();
        store
            .apply_call_signal(
                participant,
                &signal(&current, event, CallSignalKind::Accept),
            )
            .expect("accept participant");
    }
    let current = store.call(&scope(), &initial.call_id).unwrap().unwrap();
    store
        .apply_call_signal(
            alice,
            &signal(
                &current,
                "media-negotiation",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("group-negotiation-v1"),
                },
            ),
        )
        .expect("negotiation");
    store.call(&scope(), &initial.call_id).unwrap().unwrap()
}

fn build_envelope(
    store: &MemoryLocalStore,
    alice: &ScopedPrincipal,
    group: &GroupRecord,
    call: &CallSession,
    signing_key_id: &KeyId,
    signer: &SigningKeyMaterial,
) -> (DeviceId, SfuForwardEnvelope) {
    let context = group_media_context(group, call);
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let runtime = GroupMediaE2eeRuntime::new(&AllowAll, store, &capabilities);
    let alice_device = device("alice");
    let mut session = runtime
        .open_session(
            alice,
            &alice_device,
            &context,
            GroupMediaEpochSecret::from_exporter_bytes([42; 32]),
        )
        .expect("group media session");
    let frame = session
        .seal_payload(
            MediaKind::Video,
            &oid("video-stream-alice"),
            1,
            90_000,
            true,
            b"opaque-video-payload",
            signing_key_id,
            signer,
        )
        .expect("seal frame");
    (alice_device, SfuForwardEnvelope { frame })
}

fn build_fixture() -> Fixture {
    let store = MemoryLocalStore::default();
    let alice = subject("alice");
    let bob = subject("bob");
    let charlie = subject("charlie");
    for name in ["alice", "bob", "charlie"] {
        install_person(&store, name);
    }
    let (signer, signing_key_id) = install_alice_signing_key(&store);
    let (conversation, group) = build_group(&store, &alice, &bob, &charlie);
    let call = build_call(&store, &conversation, &alice, &bob, &charlie);
    let (alice_device, envelope) =
        build_envelope(&store, &alice, &group, &call, &signing_key_id, &signer);
    Fixture {
        store,
        alice,
        bob,
        charlie,
        alice_device,
        signer,
        signing_key_id,
        call,
        group,
        envelope,
    }
}

#[test]
fn encrypted_group_frame_fans_out_bit_exactly_to_current_call_recipients() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    assert_eq!(
        runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            &sink
        ),
        Ok(SfuForwardOutcome {
            accepted_recipients: 2
        })
    );
    let forwarded = sink.forwarded();
    assert_eq!(forwarded.len(), 2);
    assert_eq!(forwarded[0].1, fixture.envelope);
    assert_eq!(forwarded[1].1, fixture.envelope);
    let recipients = forwarded
        .into_iter()
        .map(|(target, _)| target.recipient)
        .collect::<Vec<_>>();
    assert!(recipients.contains(&fixture.bob.principal));
    assert!(recipients.contains(&fixture.charlie.principal));
}

#[test]
fn rt0_alice_sfu_bob_decrypts_authorized_media_and_rejects_replay() {
    let fixture = build_fixture();
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let sfu_capabilities = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(
        &AllowAll,
        &fixture.store,
        &capabilities,
        &sfu_capabilities,
    );
    let sink = CaptureSink::default();
    let outsider = principal("rt0-unknown-device");

    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            std::slice::from_ref(&outsider),
            &sink,
        ),
        Err(SfuError::InvalidRecipientSet),
    );
    assert!(sink.forwarded().is_empty());

    let validated = runtime
        .validate_source_frame(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
        )
        .expect("Alice authenticates encrypted source");
    let batch = runtime
        .prepare_forward_selected_from_validated_source(
            validated,
            std::slice::from_ref(&fixture.bob.principal),
        )
        .expect("Bob authorized recipient");
    assert_eq!(batch.target_count(), 1);
    assert_eq!(
        dispatch_validated_forward_batch(&batch, &sink),
        Ok(SfuForwardOutcome {
            accepted_recipients: 1,
        }),
    );

    let forwarded = sink.forwarded();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].0.recipient, fixture.bob.principal);
    assert_eq!(
        forwarded[0].1.frame.ciphertext,
        fixture.envelope.frame.ciphertext,
        "SFU forwards encrypted bytes unchanged",
    );

    let media_runtime = GroupMediaE2eeRuntime::new(
        &AllowAll,
        &fixture.store,
        &capabilities,
    );
    let mut bob = media_runtime
        .open_session(
            &fixture.bob,
            &device("bob"),
            &group_media_context(&fixture.group, &fixture.call),
            GroupMediaEpochSecret::from_exporter_bytes([42; 32]),
        )
        .expect("Bob endpoint-only media crypto");
    assert_eq!(
        bob.open_payload(&forwarded[0].1.frame),
        Ok(b"opaque-video-payload".to_vec()),
        "only recipient decrypts sealed media after canonical SFU",
    );
    assert!(matches!(
        bob.open_payload(&forwarded[0].1.frame),
        Err(ucr_media_e2ee::GroupMediaE2eeError::Replay)
    ));
}

struct Rt0WebRtcSink<'a> {
    provider: &'a ucr_webrtc::LiveWebRtcProvider,
    bob_id: ucr_model::SessionId,
    bob: PrincipalRef,
}

impl SfuForwardSink for Rt0WebRtcSink<'_> {
    fn forward_encrypted(
        &self,
        target: &SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        if target.recipient != self.bob {
            return Err(SfuForwardSinkError::Rejected);
        }
        use ucr_webrtc::WebRtcProvider;
        self.provider
            .send_e2ee_envelope(&self.bob_id, envelope)
            .map_err(|_| SfuForwardSinkError::Unavailable)
    }
}

async fn rt0_independent_webrtc_peer(
    provider: &ucr_webrtc::LiveWebRtcProvider,
    session_id: &ucr_model::SessionId,
) -> (
    std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
    std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
) {
    use ucr_webrtc::{WebRtcProvider, WebRtcSessionConfig};
    use webrtc::{
        api::{
            APIBuilder, interceptor_registry::register_default_interceptors,
            media_engine::MediaEngine,
        },
        interceptor::registry::Registry,
        peer_connection::{
            configuration::RTCConfiguration,
            sdp::session_description::RTCSessionDescription,
        },
    };
    let mut engine = MediaEngine::default();
    engine.register_default_codecs().expect("codecs");
    let interceptors =
        register_default_interceptors(Registry::new(), &mut engine).expect("interceptors");
    let api = APIBuilder::new()
        .with_media_engine(engine)
        .with_interceptor_registry(interceptors)
        .build();
    let peer = std::sync::Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer"),
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    peer.on_data_channel(Box::new(move |channel| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.try_send(channel);
        })
    }));
    let offer = provider
        .create_session(&WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        })
        .expect("server offer");
    peer.set_remote_description(
        RTCSessionDescription::offer(offer.sdp).expect("parse offer"),
    )
    .await
    .expect("set offer");
    let answer = peer.create_answer(None).await.expect("answer");
    let mut gathered = peer.gathering_complete_promise().await;
    peer.set_local_description(answer).await.expect("set answer");
    tokio::time::timeout(std::time::Duration::from_secs(12), gathered.recv())
        .await
        .expect("ICE gathering");
    provider
        .set_remote_description(&WebRtcSessionDescription {
            session_id: session_id.clone(),
            sdp_type: WebRtcSdpType::Answer,
            sdp: peer.local_description().await.expect("local description").sdp,
        })
        .expect("answer installed");
    let channel = tokio::time::timeout(std::time::Duration::from_secs(15), rx.recv())
        .await
        .expect("DataChannel timeout")
        .expect("DataChannel");
    assert_eq!(channel.label(), ucr_webrtc::WEBRTC_E2EE_DATA_CHANNEL_LABEL);
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while channel.ready_state()
            != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("open DataChannel");
    (peer, channel)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt0_real_webrtc_alice_to_authorized_sfu_to_bob_endpoint_decrypt() {
    use std::sync::Arc;
    use ucr_webrtc::{
        LiveWebRtcProvider, WebRtcE2eeReassembler, WebRtcProvider,
        encode_webrtc_e2ee_chunks,
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = build_fixture();
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let sfu_capabilities = PreparedSfuCapabilities;
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let provider = LiveWebRtcProvider::with_e2ee_ingress(tx).expect("live provider");
    let alice_id = SessionId::from_opaque(oid("rt0-auth-alice"));
    let bob_id = SessionId::from_opaque(oid("rt0-auth-bob"));
    let (alice, alice_channel) = rt0_independent_webrtc_peer(&provider, &alice_id).await;
    let (bob, bob_channel) = rt0_independent_webrtc_peer(&provider, &bob_id).await;
    let (delivered_tx, mut delivered_rx) = tokio::sync::mpsc::channel(2);
    let reassembler = Arc::new(tokio::sync::Mutex::new(WebRtcE2eeReassembler::new()));
    bob_channel.on_message(Box::new(move |message| {
        let reassembler = Arc::clone(&reassembler);
        let tx = delivered_tx.clone();
        Box::pin(async move {
            if message.is_string {
                return;
            }
            if let Some(envelope) = reassembler
                .lock()
                .await
                .push_chunk(&message.data)
                .expect("canonical encrypted chunk")
            {
                tx.send(envelope).await.expect("capture Bob ciphertext");
            }
        })
    }));

    for chunk in encode_webrtc_e2ee_chunks(&fixture.envelope, 100)
        .expect("Alice ciphertext wire chunks")
    {
        alice_channel
            .send(&bytes::Bytes::from(chunk))
            .await
            .expect("Alice WebRTC send");
    }
    let ingress = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("UCR receives Alice")
        .expect("Alice E2EE frame");
    assert_eq!(ingress.session_id, alice_id, "Alice bound to her session");
    assert_eq!(ingress.envelope, fixture.envelope);
    let runtime = SfuRuntime::new(
        &AllowAll,
        &fixture.store,
        &capabilities,
        &sfu_capabilities,
    );
    let sink = Rt0WebRtcSink {
        provider: &provider,
        bob_id: bob_id.clone(),
        bob: fixture.bob.principal.clone(),
    };
    let outsider = principal("rt0-outsider-real-transport");
    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &ingress.envelope,
            std::slice::from_ref(&outsider),
            &sink,
        ),
        Err(SfuError::InvalidRecipientSet),
    );
    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &ingress.envelope,
            std::slice::from_ref(&fixture.bob.principal),
            &sink,
        ),
        Ok(SfuForwardOutcome {
            accepted_recipients: 1,
        }),
    );
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        delivered_rx.recv(),
    )
    .await
    .expect("Bob must receive via WebRTC")
    .expect("Bob encrypted envelope");
    assert_eq!(received, ingress.envelope, "no SFU plaintext transformation");
    assert!(delivered_rx.try_recv().is_err(), "no duplicate delivery");

    let media_runtime =
        GroupMediaE2eeRuntime::new(&AllowAll, &fixture.store, &capabilities);
    let mut bob_crypto = media_runtime
        .open_session(
            &fixture.bob,
            &device("bob"),
            &group_media_context(&fixture.group, &fixture.call),
            GroupMediaEpochSecret::from_exporter_bytes([42; 32]),
        )
        .expect("Bob endpoint E2EE keys");
    assert_eq!(
        bob_crypto.open_payload(&received.frame),
        Ok(b"opaque-video-payload".to_vec()),
    );
    assert!(matches!(
        bob_crypto.open_payload(&received.frame),
        Err(ucr_media_e2ee::GroupMediaE2eeError::Replay)
    ));
    alice.close().await.expect("close Alice");
    bob.close().await.expect("close Bob");
    assert_eq!(provider.close_session(&alice_id), Ok(()));
    assert_eq!(provider.close_session(&bob_id), Ok(()));
}

#[test]
fn validated_source_frame_is_independent_from_recipient_authorization() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&DenyReceive, &fixture.store, &e2ee, &sfu);

    let validated = runtime
        .validate_source_frame(&fixture.alice, &fixture.alice_device, &fixture.envelope)
        .expect("validated source frame");
    assert_eq!(validated.envelope(), &fixture.envelope);

    let sink = CaptureSink::default();
    assert!(matches!(
        runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            &sink,
        ),
        Err(SfuError::Authorization(error))
            if error.code == CanonicalErrorCode::PermissionDenied
    ));
    assert!(sink.forwarded().is_empty());
}

#[test]
fn validated_source_token_reuses_source_authorization_for_recipient_batch() {
    let fixture = build_fixture();
    let authorization = CountingAuthorization::default();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&authorization, &fixture.store, &e2ee, &sfu);

    let validated = runtime
        .validate_source_frame(&fixture.alice, &fixture.alice_device, &fixture.envelope)
        .expect("validated source frame");
    assert_eq!(authorization.sends.load(Ordering::Relaxed), 1);
    assert_eq!(authorization.receives.load(Ordering::Relaxed), 0);

    let batch = runtime
        .prepare_forward_selected_from_validated_source(
            validated,
            std::slice::from_ref(&fixture.bob.principal),
        )
        .expect("recipient batch from validated source");
    assert_eq!(batch.target_count(), 1);
    assert_eq!(authorization.sends.load(Ordering::Relaxed), 1);
    assert_eq!(authorization.receives.load(Ordering::Relaxed), 1);
}

#[test]
fn validated_source_frame_rejects_spoofed_device_and_tampered_ciphertext() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);

    assert!(matches!(
        runtime.validate_source_frame(&fixture.alice, &device("bob"), &fixture.envelope,),
        Err(SfuError::SourceMismatch)
    ));

    let mut tampered = fixture.envelope.clone();
    tampered.frame.ciphertext[0] ^= 0x01;
    assert!(matches!(
        runtime.validate_source_frame(&fixture.alice, &fixture.alice_device, &tampered,),
        Err(SfuError::MediaE2ee(_))
    ));
}

#[test]
fn screen_share_source_kind_is_authenticated_before_sfu_fan_out() {
    let fixture = build_fixture();
    let context = group_media_context(&fixture.group, &fixture.call);
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let media_runtime = GroupMediaE2eeRuntime::new(&AllowAll, &fixture.store, &capabilities);
    let mut session = media_runtime
        .open_session(
            &fixture.alice,
            &fixture.alice_device,
            &context,
            GroupMediaEpochSecret::from_exporter_bytes([42; 32]),
        )
        .expect("screen-share media session");
    assert_eq!(
        session.seal_payload_with_source(
            MediaKind::Video,
            Some(VideoSourceKind::ScreenShare),
            &oid("screen-share-without-proof"),
            1,
            90_000,
            true,
            b"must-not-seal",
            &fixture.signing_key_id,
            &fixture.signer,
        ),
        Err(ucr_media_e2ee::GroupMediaE2eeError::ScreenShareNegotiationRequired)
    );
    let negotiated = screen_share_v2_negotiation(&NegotiatedSession {
        version: ProtocolVersion::new(1, 0),
        crypto_suite: CryptoSuite::UcrV1,
        capabilities: vec![CapabilityDescriptor {
            id: SCREEN_SHARE_VIDEO_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }],
    })
    .expect("screen-share negotiation proof");
    let frame = session
        .seal_negotiated_screen_share(
            &negotiated,
            &oid("screen-share-alice"),
            1,
            90_000,
            true,
            b"opaque-screen-share-payload",
            &fixture.signing_key_id,
            &fixture.signer,
        )
        .expect("seal negotiated screen-share frame");
    assert_eq!(frame.header.header_version, GROUP_MEDIA_FRAME_HEADER_V2);
    assert_eq!(
        frame.header.video_source_kind,
        Some(VideoSourceKind::ScreenShare)
    );

    let envelope = SfuForwardEnvelope { frame };
    let sfu = PreparedSfuCapabilities;
    let denied_runtime = SfuRuntime::new(&DenyScreenShareSend, &fixture.store, &capabilities, &sfu);
    let denied_sink = CaptureSink::default();
    assert!(matches!(
        denied_runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &envelope,
            &denied_sink
        ),
        Err(SfuError::Authorization(error))
            if error.code == CanonicalErrorCode::PermissionDenied
    ));
    assert!(denied_sink.forwarded().is_empty());

    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &capabilities, &sfu);
    let sink = CaptureSink::default();
    assert_eq!(
        runtime.forward(&fixture.alice, &fixture.alice_device, &envelope, &sink),
        Ok(SfuForwardOutcome {
            accepted_recipients: 2
        })
    );
    assert!(
        sink.forwarded()
            .iter()
            .all(|(_, forwarded)| forwarded.frame.header.video_source_kind
                == Some(VideoSourceKind::ScreenShare))
    );

    let mut relabelled = envelope;
    relabelled.frame.header.video_source_kind = Some(VideoSourceKind::Camera);
    let tampered_sink = CaptureSink::default();
    assert!(matches!(
        runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &relabelled,
            &tampered_sink
        ),
        Err(SfuError::MediaE2ee(_))
    ));
    assert!(tampered_sink.forwarded().is_empty());
}

#[test]
fn selected_encrypted_forwarding_reaches_only_explicit_current_recipient() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            std::slice::from_ref(&fixture.bob.principal),
            &sink,
        ),
        Ok(SfuForwardOutcome {
            accepted_recipients: 1
        })
    );
    let forwarded = sink.forwarded();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].0.recipient, fixture.bob.principal);
    assert_eq!(forwarded[0].1, fixture.envelope);
}

#[test]
fn rt0_authorized_ciphertext_reaches_bob_but_outsider_and_spoofed_source_fail_closed() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    let outsider = principal("rt0-outsider");

    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            std::slice::from_ref(&outsider),
            &sink,
        ),
        Err(SfuError::InvalidRecipientSet),
    );
    assert!(
        sink.forwarded().is_empty(),
        "outsider must never receive ciphertext"
    );

    assert_eq!(
        runtime.forward_selected(
            &fixture.bob,
            &device("bob"),
            &fixture.envelope,
            std::slice::from_ref(&fixture.alice.principal),
            &sink,
        ),
        Err(SfuError::SourceMismatch),
    );
    assert!(
        sink.forwarded().is_empty(),
        "spoofed source must never fan out"
    );

    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            std::slice::from_ref(&fixture.bob.principal),
            &sink,
        ),
        Ok(SfuForwardOutcome {
            accepted_recipients: 1
        }),
    );
    let forwarded = sink.forwarded();
    assert_eq!(forwarded.len(), 1, "only Bob receives ciphertext");
    assert_eq!(forwarded[0].0.recipient, fixture.bob.principal);
    assert_eq!(
        forwarded[0].1, fixture.envelope,
        "SFU must not change ciphertext"
    );
}

#[test]
fn prepared_selected_forwarding_has_no_side_effect_until_explicit_dispatch() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();

    let batch = runtime
        .prepare_forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            std::slice::from_ref(&fixture.bob.principal),
        )
        .expect("validated forward batch");

    assert_eq!(batch.target_count(), 1);
    assert_eq!(batch.targets()[0].recipient, fixture.bob.principal);
    assert_eq!(batch.envelope(), &fixture.envelope);
    assert!(sink.forwarded().is_empty());

    assert_eq!(
        dispatch_validated_forward_batch(&batch, &sink),
        Ok(SfuForwardOutcome {
            accepted_recipients: 1
        })
    );
    let forwarded = sink.forwarded();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].0.recipient, fixture.bob.principal);
    assert_eq!(forwarded[0].1, fixture.envelope);
}

#[test]
fn selected_forwarding_rejects_nonparticipant_and_duplicate_targets_before_sink() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    let outsider = principal("outsider");
    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            std::slice::from_ref(&outsider),
            &sink,
        ),
        Err(SfuError::InvalidRecipientSet)
    );
    assert_eq!(
        runtime.forward_selected(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            &[fixture.bob.principal.clone(), fixture.bob.principal.clone()],
            &sink,
        ),
        Err(SfuError::InvalidRecipientSet)
    );
    assert!(sink.forwarded().is_empty());
}

#[test]
fn compromised_sfu_simulation_rejects_spoof_before_sink() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    assert_eq!(
        runtime.forward(&fixture.bob, &device("bob"), &fixture.envelope, &sink),
        Err(SfuError::SourceMismatch)
    );
    assert!(sink.forwarded().is_empty());

    let mut tampered = fixture.envelope.clone();
    tampered.frame.ciphertext[0] ^= 1;
    assert!(matches!(
        runtime.forward(&fixture.alice, &fixture.alice_device, &tampered, &sink),
        Err(SfuError::MediaE2ee(_))
    ));
    assert!(sink.forwarded().is_empty());
}

#[test]
fn receive_permission_preflight_happens_before_first_sink_side_effect() {
    let fixture = build_fixture();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&DenyReceive, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    assert!(matches!(
        runtime.forward(&fixture.alice, &fixture.alice_device, &fixture.envelope, &sink),
        Err(SfuError::Authorization(error)) if error.code == CanonicalErrorCode::PermissionDenied
    ));
    assert!(sink.forwarded().is_empty());
}

#[test]
fn membership_rekey_invalidates_old_epoch_before_forwarding() {
    let fixture = build_fixture();
    let remove = GroupChange {
        event_id: EventId::from_opaque(oid("remove-charlie-after-frame")),
        scope: scope(),
        group_id: fixture.group.group_id.clone(),
        expected_revision: fixture.group.revision,
        kind: GroupChangeKind::RemoveMember {
            member: fixture.charlie.principal.clone(),
        },
        next_crypto_state: Some(crypto_state(fixture.group.crypto_state.epoch + 1)),
    };
    fixture
        .store
        .apply_group_change(&fixture.alice, &remove)
        .expect("remove charlie");
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    assert!(matches!(
        runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            &sink
        ),
        Err(SfuError::MediaE2ee(_))
    ));
    assert!(sink.forwarded().is_empty());
}

#[test]
fn source_device_revocation_invalidates_already_encrypted_frame() {
    let fixture = build_fixture();
    fixture
        .store
        .revoke_device(&scope(), &fixture.alice_device, &identity("alice"))
        .expect("revoke source");
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = CaptureSink::default();
    assert!(matches!(
        runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            &sink
        ),
        Err(SfuError::MediaE2ee(_))
    ));
    assert!(sink.forwarded().is_empty());
}

#[test]
fn sfu_sink_failure_chaos_preserves_call_authority() {
    let fixture = build_fixture();
    let before = fixture
        .store
        .call(&scope(), &fixture.call.call_id)
        .unwrap()
        .unwrap();
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &e2ee, &sfu);
    let sink = FailAfterOne::new();
    assert_eq!(
        runtime.forward(
            &fixture.alice,
            &fixture.alice_device,
            &fixture.envelope,
            &sink
        ),
        Err(SfuError::Sink {
            accepted_before_failure: 1,
            error: SfuForwardSinkError::Backpressure
        })
    );
    let after = fixture
        .store
        .call(&scope(), &fixture.call.call_id)
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn test_fixture_signer_and_key_id_are_bound_to_source_device() {
    let fixture = build_fixture();
    assert_eq!(
        fixture.envelope.frame.source_signature.key_id,
        fixture.signing_key_id
    );
    assert_eq!(
        fixture.envelope.frame.header.source_device_id,
        fixture.alice_device
    );
    assert_eq!(fixture.signer.verifying_key().0.len(), 32);
}

#[test]
fn same_principal_multi_device_streams_have_independent_replay_cursors() {
    let fixture = build_fixture();
    let (alice_device_2, signer_2, key_id_2) = install_additional_person_device(
        &fixture.store,
        "alice",
        "alice-secondary",
        "alice-secondary-signing-key",
    );
    let context = group_media_context(&fixture.group, &fixture.call);
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let runtime = GroupMediaE2eeRuntime::new(&AllowAll, &fixture.store, &capabilities);
    let epoch_secret = [42; 32];
    let mut alice_primary = runtime
        .open_session(
            &fixture.alice,
            &fixture.alice_device,
            &context,
            GroupMediaEpochSecret::from_exporter_bytes(epoch_secret),
        )
        .expect("primary Alice session");
    let mut alice_secondary = runtime
        .open_session(
            &fixture.alice,
            &alice_device_2,
            &context,
            GroupMediaEpochSecret::from_exporter_bytes(epoch_secret),
        )
        .expect("secondary Alice session");
    let mut bob = runtime
        .open_session(
            &fixture.bob,
            &device("bob"),
            &context,
            GroupMediaEpochSecret::from_exporter_bytes(epoch_secret),
        )
        .expect("Bob session");
    let stream_id = oid("alice-shared-device-stream");
    let primary = alice_primary
        .seal_payload(
            MediaKind::Audio,
            &stream_id,
            1,
            48_000,
            false,
            b"primary-device",
            &fixture.signing_key_id,
            &fixture.signer,
        )
        .expect("primary frame");
    let secondary = alice_secondary
        .seal_payload(
            MediaKind::Audio,
            &stream_id,
            1,
            48_000,
            false,
            b"secondary-device",
            &key_id_2,
            &signer_2,
        )
        .expect("secondary frame");

    assert_eq!(bob.open_payload(&primary), Ok(b"primary-device".to_vec()));
    assert_eq!(
        bob.open_payload(&secondary),
        Ok(b"secondary-device".to_vec())
    );
    assert!(matches!(
        bob.open_payload(&primary),
        Err(ucr_media_e2ee::GroupMediaE2eeError::Replay)
    ));
    assert!(matches!(
        bob.open_payload(&secondary),
        Err(ucr_media_e2ee::GroupMediaE2eeError::Replay)
    ));
}

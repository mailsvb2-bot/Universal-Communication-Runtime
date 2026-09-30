#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use ucr_chat::{
    ChatClock, ChatClockError, ChatRuntime, EphemeralChatError, EphemeralChatSink, TypingUpdate,
};
use ucr_core::{
    AntiEntropyStore, AttachmentStore, AuthorizationEvaluator, CallStore, CanonicalTransportError,
    ClassifiedTransportFailure, CommunicationIntentStore, ConversationStore, DeliveryStore,
    DeviceLifecycleStore, DurableRecordStatus, EventAppendStatus, EventJournalStore, MessageStore,
    PolicyDecision, PolicyEvaluator, RouteCandidate, StorageProvider, StoreForwardStore, SyncStore,
    TransportHealth, TransportProvider, TrustedSigningKeyStore,
};
use ucr_crypto::{SigningKeyMaterial, TrustedKeyResolutionError, TrustedSigningKeyResolver};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AttachmentDescriptor, AttachmentId, AuthorizationRequest, CallId,
    CallParticipant, CallParticipantState, CallSession, CallSignal, CallSignalKind,
    CallSignallingState, CapabilityDescriptor, CapabilityMaturity, CommunicationIntent,
    ConversationId, ConversationKind, ConversationRecord, ConversationRef, CorrelationContext,
    DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryId, DeliveryPolicy,
    DeliveryState, DeviceDescriptor, DeviceId, DeviceLifecycleState, DeviceRef, EndpointAddress,
    EndpointDescriptor, EndpointId, EndpointKind, EventEnvelope, EventId, EventReplicaState,
    IdentityId, IntentConstraints, IntentId, KeyId, KeyPurpose, MediaThermalState, MessageEnvelope,
    MessageId, OpaqueId, OriginRef, PrincipalId, PrincipalKind, PrincipalRef, ProtocolVersion,
    PublicKeyDescriptor, ScopedPrincipal, SessionId, StoreForwardId, StoreForwardJob,
    StoreForwardOutcome, StoreForwardPolicy, SyncLinkKind, SyncMode, SyncSelection, SyncSession,
    SyncState, TenantId, TenantScope, TransportFailoverPolicy, TransportResourceSnapshot,
    TransportRouteTelemetry, VideoCodecConfig, VideoSourceKind, VideoStreamDescriptor,
    VideoStreamId,
};
use ucr_protocol::{
    ALGORITHM_VERSION, H264_VIDEO_CODEC_CAPABILITY, KEY_FORMAT_VERSION, MANDATORY_VIDEO_FRAME_RATE,
    MANDATORY_VIDEO_HEIGHT, MANDATORY_VIDEO_WIDTH, NegotiationResultEnvelope,
    SIGNATURE_ALGORITHM_ID, VersionPolicy, VersionRange, attachment_content_id,
    canonical_attachment_chunk, negotiate_version, phase21_video_capabilities,
};
use ucr_storage_sqlite::SqliteLocalStore;
use ucr_store_forward::{
    STORE_FORWARD_INTERNET_CAPABILITY, StoreForwardClock, StoreForwardRuntime,
};
use ucr_transport_orchestrator::{
    TransportFailoverClock, TransportOrchestrator, TransportOrchestratorError, TransportRouteOption,
};
use ucr_video::{
    PreparedVideoCapabilities, ResolvedVideoNegotiation, VideoNegotiationResolver, VideoRuntime,
};

static DB_SEQUENCE: AtomicU64 = AtomicU64::new(240_000);

struct TestDb(PathBuf);

impl TestDb {
    fn new(label: &str) -> Self {
        let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ucr-main-e2e-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

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

impl PolicyEvaluator for AllowAll {
    fn evaluate_intent(&self, _intent: &CommunicationIntent) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug, Clone, Copy)]
struct FixedClock(i64);

impl ChatClock for FixedClock {
    fn now_unix_ms(&self) -> Result<i64, ChatClockError> {
        Ok(self.0)
    }
}

impl StoreForwardClock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

impl TransportFailoverClock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

#[derive(Debug, Default)]
struct NoopChatSink;

impl EphemeralChatSink for NoopChatSink {
    fn publish_typing(
        &self,
        _subject: &ScopedPrincipal,
        _update: &TypingUpdate,
    ) -> Result<(), EphemeralChatError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ProviderOutcome {
    Accepted,
    NotAccepted,
}

#[derive(Debug)]
struct CapturingProvider {
    capability: String,
    outcome: ProviderOutcome,
    captures: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CapturingProvider {
    fn new(capability: &str, outcome: ProviderOutcome) -> Self {
        Self {
            capability: capability.to_owned(),
            outcome,
            captures: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn captured(&self) -> Vec<Vec<u8>> {
        self.captures.lock().expect("capture lock").clone()
    }
}

impl TransportProvider for CapturingProvider {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: self.capability.clone(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }]
    }

    fn health(&self) -> TransportHealth {
        TransportHealth::Healthy
    }

    fn transmit(
        &self,
        _scope: &TenantScope,
        _route: &RouteCandidate,
        encrypted_envelope: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        self.captures
            .lock()
            .expect("capture lock")
            .push(encrypted_envelope.to_vec());
        match self.outcome {
            ProviderOutcome::Accepted => Ok(()),
            ProviderOutcome::NotAccepted => Err(CanonicalTransportError::Unavailable),
        }
    }

    fn transmit_classified(
        &self,
        scope: &TenantScope,
        route: &RouteCandidate,
        encrypted_envelope: &[u8],
    ) -> Result<(), ClassifiedTransportFailure> {
        self.transmit(scope, route, encrypted_envelope)
            .map_err(ClassifiedTransportFailure::not_accepted)
    }
}

#[derive(Debug, Clone)]
struct VideoNegotiation {
    participants: Vec<PrincipalRef>,
}

impl VideoNegotiationResolver for VideoNegotiation {
    fn resolve_video_negotiation(
        &self,
        requested_scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedVideoNegotiation>, ucr_protocol::CanonicalError> {
        Ok(Some(ResolvedVideoNegotiation {
            scope: requested_scope.clone(),
            call_id: call_id.clone(),
            negotiation_ref: negotiation_ref.clone(),
            negotiation_generation,
            result: NegotiationResultEnvelope {
                version: ProtocolVersion::new(1, 0),
                capabilities: phase21_video_capabilities(),
                extensions: Vec::new(),
                transcript_binding: Vec::new(),
                crypto_suite: ucr_model::CryptoSuite::UcrV1,
            },
            selected_codec: camera_codec(),
            negotiated_participants: self.participants.clone(),
        }))
    }
}

struct Scenario {
    sender_db: TestDb,
    recipient_db: TestDb,
    intermediary_db: TestDb,
    scope: TenantScope,
    alice: ScopedPrincipal,
    bob: ScopedPrincipal,
    conversation: ConversationRecord,
}

impl Scenario {
    fn new() -> Self {
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(oid("e2e-tenant")),
            namespace_id: None,
        };
        let alice = subject(&scope, "e2e-alice");
        let bob = subject(&scope, "e2e-bob");
        let conversation = ConversationRecord {
            scope: scope.clone(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("e2e-conversation")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        };
        Self {
            sender_db: TestDb::new("sender"),
            recipient_db: TestDb::new("recipient"),
            intermediary_db: TestDb::new("intermediary"),
            scope,
            alice,
            bob,
            conversation,
        }
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid e2e id")
}

fn subject(scope: &TenantScope, id: &str) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(id)),
            kind: PrincipalKind::Person,
        },
    }
}

fn message(s: &Scenario, id: &str, order: u64, content: &[u8]) -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid(id)),
        scope: s.scope.clone(),
        conversation: s.conversation.conversation.clone(),
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("e2e-alice-actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("e2e-alice-device")),
            identity_id: IdentityId::from_opaque(oid("e2e-alice-identity")),
        },
        created_at_unix_ms: 1_000 + i64::try_from(order).expect("order"),
        logical_order: order,
        content: content.to_vec(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(s.alice.principal.principal_id.clone()),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    }
}

fn intent(s: &Scenario, id: &str, payload: &[u8]) -> CommunicationIntent {
    CommunicationIntent {
        intent_id: IntentId::from_opaque(oid(id)),
        scope: s.scope.clone(),
        target_identity_id: IdentityId::from_opaque(oid("e2e-bob-identity")),
        payload: payload.to_vec(),
        constraints: IntentConstraints {
            allowed_transport_capabilities: Vec::new(),
            forbidden_transport_capabilities: Vec::new(),
            privacy_profile: Some("private".to_owned()),
            region_constraint: None,
            max_cost_microunits: None,
            priority_class: Some(1),
        },
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
        extensions: Vec::new(),
    }
}

fn resources() -> TransportResourceSnapshot {
    TransportResourceSnapshot {
        battery_percent: 80,
        external_power: false,
        thermal_state: MediaThermalState::Nominal,
    }
}

fn route_option<'a>(
    provider: &'a dyn TransportProvider,
    capability: &str,
    endpoint: &str,
    rtt_ms: u32,
) -> TransportRouteOption<'a> {
    let endpoint_id = EndpointId::from_opaque(oid(endpoint));
    let address = EndpointAddress {
        scheme: capability.to_owned(),
        value: endpoint.as_bytes().to_vec(),
    };
    TransportRouteOption {
        provider,
        route: RouteCandidate {
            endpoint_id: endpoint_id.clone(),
            transport_capability: capability.to_owned(),
            address: address.clone(),
        },
        recipient_endpoint: EndpointDescriptor {
            endpoint_id,
            kind: EndpointKind::Device,
            identity_id: Some(IdentityId::from_opaque(oid("e2e-bob-identity"))),
            device_id: Some(DeviceId::from_opaque(oid("e2e-bob-device"))),
            capabilities: provider.capabilities(),
            addresses: vec![address],
        },
        telemetry: TransportRouteTelemetry {
            estimated_bandwidth_bps: 5_000_000,
            packet_loss_basis_points: 0,
            jitter_ms: 1,
            rtt_ms,
            cost_microunits: 0,
            energy_cost_percent: 1,
            reliability_basis_points: 10_000,
            recipient_reachable: true,
            privacy_profile: Some("private".to_owned()),
            region: Some("local".to_owned()),
        },
    }
}

fn phase_internet_chat_and_video(
    s: &Scenario,
    sender: &SqliteLocalStore,
    recipient: &SqliteLocalStore,
) -> Vec<MessageEnvelope> {
    let clock = FixedClock(1_000);
    let sink = NoopChatSink;
    let chat = ChatRuntime::new(&clock, &AllowAll, sender, &sink);
    chat.open_direct_chat(&s.alice, &s.conversation)
        .expect("step 1: open Internet chat");
    recipient
        .persist_conversation(&s.conversation)
        .expect("recipient conversation");

    let internet = CapturingProvider::new("ucr.transport.internet.tcp", ProviderOutcome::Accepted);
    let orchestrator = TransportOrchestrator::new(&AllowAll);
    let mut sent = Vec::new();
    for (index, body) in [b"hello".as_slice(), b"still-online".as_slice()]
        .into_iter()
        .enumerate()
    {
        let id = format!("e2e-online-message-{}", index + 1);
        let value = message(s, &id, u64::try_from(index + 1).expect("order"), body);
        chat.send_text(&s.alice, &value).expect("step 2: send chat");
        let route_intent = intent(s, &format!("intent-{id}"), body);
        let plan = orchestrator
            .plan(
                &route_intent,
                resources(),
                &[],
                vec![route_option(
                    &internet,
                    "ucr.transport.internet.tcp",
                    "internet-primary",
                    20,
                )],
            )
            .expect("Internet route");
        orchestrator
            .transmit_with_failover(
                &route_intent,
                &plan,
                body,
                TransportFailoverPolicy {
                    max_route_attempts: 1,
                    expires_at_unix_ms: Some(10_000),
                },
                &clock,
            )
            .expect("Internet delivery");
        recipient
            .persist_message(&value)
            .expect("recipient message");
        sent.push(value);
    }
    assert_eq!(internet.captured().len(), 2);

    start_video_call(s, sender);
    sent
}

fn start_video_call(s: &Scenario, store: &SqliteLocalStore) {
    let session = CallSession {
        scope: s.scope.clone(),
        call_id: CallId::from_opaque(oid("e2e-video-call")),
        conversation: s.conversation.conversation.clone(),
        initiated_by: s.alice.principal.clone(),
        participants: vec![
            CallParticipant {
                principal: s.alice.principal.clone(),
                state: CallParticipantState::Accepted,
                joined_revision: 0,
                left_revision: None,
            },
            CallParticipant {
                principal: s.bob.principal.clone(),
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
    store.create_call(&s.alice, &session).expect("create call");
    store
        .apply_call_signal(
            &s.bob,
            &CallSignal {
                event_id: EventId::from_opaque(oid("e2e-call-accept")),
                scope: s.scope.clone(),
                call_id: session.call_id.clone(),
                expected_revision: 0,
                kind: CallSignalKind::Accept,
            },
        )
        .expect("accept call");
    let accepted = store
        .call(&s.scope, &session.call_id)
        .expect("load call")
        .expect("call exists");
    store
        .apply_call_signal(
            &s.alice,
            &CallSignal {
                event_id: EventId::from_opaque(oid("e2e-video-negotiation")),
                scope: s.scope.clone(),
                call_id: session.call_id.clone(),
                expected_revision: accepted.revision,
                kind: CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("e2e-video-negotiation-v1"),
                },
            },
        )
        .expect("install video negotiation");
    let active = store
        .call(&s.scope, &session.call_id)
        .expect("load active call")
        .expect("active call");
    let participants = active
        .participants
        .iter()
        .filter(|participant| {
            participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        })
        .map(|participant| participant.principal.clone())
        .collect();
    let negotiation = VideoNegotiation { participants };
    let video = VideoRuntime::new(&AllowAll, store, &PreparedVideoCapabilities, &negotiation);
    let descriptor = VideoStreamDescriptor {
        scope: s.scope.clone(),
        call_id: active.call_id.clone(),
        stream_id: VideoStreamId::from_opaque(oid("e2e-video-stream")),
        source: s.alice.principal.clone(),
        source_kind: VideoSourceKind::Camera,
        codec: camera_codec(),
        negotiation_ref: active
            .media_negotiation_ref
            .clone()
            .expect("negotiation ref"),
        negotiation_generation: active.media_negotiation_generation,
    };
    let mut sender = video
        .open_sender(&s.alice, &descriptor)
        .expect("video sender");
    let mut receiver = video
        .open_receiver(&s.bob, &descriptor)
        .expect("video receiver");
    let rgb = vec![
        7_u8;
        usize::try_from(MANDATORY_VIDEO_WIDTH * MANDATORY_VIDEO_HEIGHT * 3)
            .expect("frame size")
    ];
    let encoded = sender.encode_rgb8(&rgb).expect("encode video");
    let decoded = receiver.decode_frame(&encoded).expect("decode video");
    assert_eq!(decoded.rgb8.len(), rgb.len());
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

fn phase_failover_lan_and_file(s: &Scenario, sender: &SqliteLocalStore) {
    let internet_down =
        CapturingProvider::new("ucr.transport.internet.tcp", ProviderOutcome::NotAccepted);
    let alternate_ip =
        CapturingProvider::new("ucr.transport.internet.alt", ProviderOutcome::Accepted);
    let orchestrator = TransportOrchestrator::new(&AllowAll);
    let value = intent(s, "e2e-failover-intent", b"video-session-control");
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                route_option(
                    &internet_down,
                    "ucr.transport.internet.tcp",
                    "wifi-disappeared",
                    10,
                ),
                route_option(
                    &alternate_ip,
                    "ucr.transport.internet.alt",
                    "alternate-ip",
                    30,
                ),
            ],
        )
        .expect("step 4/5: failover plan");
    let decision = orchestrator
        .transmit_with_failover(
            &value,
            &plan,
            b"encrypted-session-control",
            TransportFailoverPolicy {
                max_route_attempts: 2,
                expires_at_unix_ms: Some(10_000),
            },
            &FixedClock(2_000),
        )
        .expect("step 5: session recovers over alternate IP");
    assert_eq!(decision.attempts.len(), 2);

    let local = CapturingProvider::new("ucr.transport.local.tcp", ProviderOutcome::Accepted);
    let local_intent = intent(s, "e2e-local-intent", b"local-file-route");
    let local_plan = orchestrator
        .plan(
            &local_intent,
            resources(),
            &[],
            vec![route_option(
                &local,
                "ucr.transport.local.tcp",
                "shared-lan",
                1,
            )],
        )
        .expect("step 6/7: direct local route");
    orchestrator
        .transmit_with_failover(
            &local_intent,
            &local_plan,
            b"encrypted-file-envelope",
            TransportFailoverPolicy {
                max_route_attempts: 1,
                expires_at_unix_ms: Some(10_000),
            },
            &FixedClock(3_000),
        )
        .expect("step 8: file over local route");

    let bytes = b"abcdefgh";
    let descriptor = AttachmentDescriptor {
        attachment_id: AttachmentId::from_opaque(oid("e2e-attachment")),
        scope: s.scope.clone(),
        content_id: attachment_content_id(bytes),
        size_bytes: u64::try_from(bytes.len()).expect("attachment length"),
        chunk_size_bytes: 4,
        chunk_count: 2,
        media_type: Some("application/octet-stream".to_owned()),
        file_name: Some("e2e.bin".to_owned()),
    };
    sender
        .persist_attachment_descriptor(&descriptor)
        .expect("persist attachment descriptor");
    for (index, chunk) in [bytes[..4].to_vec(), bytes[4..].to_vec()]
        .into_iter()
        .enumerate()
    {
        sender
            .persist_attachment_chunk(
                &s.scope,
                &canonical_attachment_chunk(
                    descriptor.attachment_id.clone(),
                    u32::try_from(index).expect("chunk index"),
                    u64::try_from(index * 4).expect("chunk offset"),
                    chunk,
                ),
            )
            .expect("persist attachment chunk");
    }
    assert_eq!(local.captured(), vec![b"encrypted-file-envelope".to_vec()]);
}

fn register_bob_device(store: &SqliteLocalStore, s: &Scenario) {
    store
        .register_device(
            &s.scope,
            &DeviceDescriptor {
                device_id: DeviceId::from_opaque(oid("e2e-bob-device")),
                identity_id: IdentityId::from_opaque(oid("e2e-bob-identity")),
                state: DeviceLifecycleState::Active,
            },
        )
        .expect("register Bob device");
}
fn phase_offline_store_forward(
    s: &Scenario,
    sender: &SqliteLocalStore,
    intermediary: &SqliteLocalStore,
    recipient: &SqliteLocalStore,
) -> MessageEnvelope {
    let offline = message(s, "e2e-offline-message", 3, b"queued while offline");
    register_bob_device(sender, s);
    register_bob_device(intermediary, s);
    sender
        .persist_message(&offline)
        .expect("step 10/11: durable message");
    let sf_intent = intent(s, "e2e-store-forward-intent", &offline.content);
    sender
        .persist_communication_intent(&sf_intent)
        .expect("persist sender intent");
    let job = store_forward_job(s, &offline, &sf_intent, "e2e-sender-sf");
    let runtime = StoreForwardRuntime::new(sender, &AllowAll, &FixedClock(4_000));
    runtime.enqueue(&job).expect("enqueue offline job");
    assert_eq!(
        runtime.process_one(
            &s.scope,
            &job.store_forward_id,
            resources(),
            &[],
            Vec::new()
        ),
        Ok(StoreForwardOutcome::RescheduledNoRoute)
    );
    assert!(
        sender
            .store_forward_job(&s.scope, &job.store_forward_id)
            .expect("load durable job")
            .is_some()
    );

    intermediary
        .persist_conversation(&s.conversation)
        .expect("intermediary conversation");
    intermediary
        .persist_message(&offline)
        .expect("intermediary message");
    intermediary
        .persist_communication_intent(&sf_intent)
        .expect("intermediary intent");
    let intermediary_provider =
        CapturingProvider::new(STORE_FORWARD_INTERNET_CAPABILITY, ProviderOutcome::Accepted);
    let clock = FixedClock(4_100);
    let sender_runtime = StoreForwardRuntime::new(sender, &AllowAll, &clock);
    let pending = sender
        .store_forward_job(&s.scope, &job.store_forward_id)
        .expect("load pending")
        .expect("pending job");
    let outcome = sender_runtime
        .process_one(
            &s.scope,
            &pending.store_forward_id,
            resources(),
            &[],
            vec![route_option(
                &intermediary_provider,
                STORE_FORWARD_INTERNET_CAPABILITY,
                "intermediary",
                5,
            )],
        )
        .expect("step 12/13: intermediary accepts encrypted envelope");
    assert_eq!(outcome, StoreForwardOutcome::AcceptedByTransport);
    let captured = intermediary_provider.captured();
    assert_eq!(captured.len(), 1);

    let relay_job = StoreForwardJob {
        encrypted_envelope: captured[0].clone(),
        ..store_forward_job(s, &offline, &sf_intent, "e2e-relay-sf")
    };
    let relay_runtime = StoreForwardRuntime::new(intermediary, &AllowAll, &FixedClock(4_200));
    relay_runtime
        .enqueue(&relay_job)
        .expect("enqueue intermediary relay");
    let recipient_provider =
        CapturingProvider::new(STORE_FORWARD_INTERNET_CAPABILITY, ProviderOutcome::Accepted);
    assert_eq!(
        relay_runtime.process_one(
            &s.scope,
            &relay_job.store_forward_id,
            resources(),
            &[],
            vec![route_option(
                &recipient_provider,
                STORE_FORWARD_INTERNET_CAPABILITY,
                "recipient-online",
                5,
            )],
        ),
        Ok(StoreForwardOutcome::AcceptedByTransport)
    );
    recipient
        .persist_message(&offline)
        .expect("step 14/15 recipient message");
    mark_presented_to_user(recipient, s, &offline);
    offline
}

fn store_forward_job(
    s: &Scenario,
    value: &MessageEnvelope,
    value_intent: &CommunicationIntent,
    id: &str,
) -> StoreForwardJob {
    StoreForwardJob {
        store_forward_id: StoreForwardId::from_opaque(oid(id)),
        scope: s.scope.clone(),
        intent_id: value_intent.intent_id.clone(),
        message_id: value.message_id.clone(),
        encrypted_envelope: format!("ciphertext:{}", value.message_id.as_opaque().as_str())
            .into_bytes(),
        policy: StoreForwardPolicy {
            max_delivery_attempts: 3,
            base_retry_delay_ms: 100,
            max_retry_delay_ms: 1_000,
            lease_duration_ms: 5_000,
            expires_at_unix_ms: None,
        },
        attempts_used: 0,
        next_attempt_at_unix_ms: 4_000,
        last_delivery_id: None,
    }
}

fn mark_presented_to_user(store: &SqliteLocalStore, s: &Scenario, value: &MessageEnvelope) {
    let delivery_id = DeliveryId::from_opaque(oid("e2e-recipient-delivery"));
    let attempt = DeliveryAttempt {
        delivery_id: delivery_id.clone(),
        scope: s.scope.clone(),
        message_id: value.message_id.clone(),
        state: DeliveryState::Persisted,
    };
    let persisted = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: s.scope.clone(),
        message_id: value.message_id.clone(),
        kind: DeliveryEvidenceKind::PersistedLocal,
        logical_order: 1,
    };
    store
        .create_delivery_attempt(&attempt, &persisted)
        .expect("create recipient delivery");
    for (from, to) in [
        (DeliveryState::Persisted, DeliveryState::Encrypted),
        (DeliveryState::Encrypted, DeliveryState::Queued),
        (DeliveryState::Queued, DeliveryState::RoutePlanned),
        (DeliveryState::RoutePlanned, DeliveryState::InFlight),
    ] {
        store
            .transition_delivery(&s.scope, &delivery_id, from, to, None)
            .expect("advance recipient delivery");
    }
    let accepted = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: s.scope.clone(),
        message_id: value.message_id.clone(),
        kind: DeliveryEvidenceKind::AcceptedByTransport,
        logical_order: 2,
    };
    store
        .transition_delivery(
            &s.scope,
            &delivery_id,
            DeliveryState::InFlight,
            DeliveryState::Acknowledged,
            Some(&accepted),
        )
        .expect("acknowledge recipient delivery");
    let delivered = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: s.scope.clone(),
        message_id: value.message_id.clone(),
        kind: DeliveryEvidenceKind::PresentedToUser,
        logical_order: 3,
    };
    store
        .transition_delivery(
            &s.scope,
            &delivery_id,
            DeliveryState::Acknowledged,
            DeliveryState::Delivered,
            Some(&delivered),
        )
        .expect("step 15: presented to user");
    assert_eq!(
        store
            .delivery_attempt(&s.scope, &delivery_id)
            .expect("read delivery")
            .expect("delivery exists")
            .state,
        DeliveryState::Delivered
    );
}

fn phase_reconciliation(
    s: &Scenario,
    sender: &SqliteLocalStore,
    recipient: &SqliteLocalStore,
    sent: &[MessageEnvelope],
) {
    let sync = SyncSession {
        session_id: SessionId::from_opaque(oid("e2e-reconciliation-session")),
        scope: s.scope.clone(),
        source_endpoint_id: EndpointId::from_opaque(oid("e2e-source-endpoint")),
        target_endpoint_id: EndpointId::from_opaque(oid("e2e-target-endpoint")),
        link_kind: SyncLinkKind::DeviceDevice,
        selection: SyncSelection {
            mode: SyncMode::Full,
            conversation_ids: Vec::new(),
        },
        state: SyncState::Prepared,
    };
    for store in [sender, recipient] {
        store.create_sync_session(&sync).expect("create sync");
        store
            .transition_sync(
                &s.scope,
                &sync.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("activate sync");
    }
    let event = EventEnvelope {
        event_id: EventId::from_opaque(oid("e2e-reconcile-event")),
        scope: s.scope.clone(),
        event_type: "ucr.message.reconciled".to_owned(),
        payload: b"Internet restored".to_vec(),
        actor: ActorRef {
            actor_id: ActorId::from_opaque(oid("e2e-system")),
            kind: ActorKind::System,
            on_behalf_of: None,
        },
        source_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("e2e-alice-device")),
            identity_id: IdentityId::from_opaque(oid("e2e-alice-identity")),
        },
        wall_time_unix_ms: 5_000,
        logical_order: 99,
        correlation: CorrelationContext {
            correlation_id: oid("e2e-reconcile-correlation"),
            causation_id: None,
            idempotency_key: None,
        },
        schema_version: ProtocolVersion::new(1, 0),
        integrity_metadata: Vec::new(),
        extensions: Vec::new(),
    };
    sender.append_event(&event).expect("source event");
    let page = sender
        .anti_entropy_summary_page(&s.scope, &sync.session_id, None, 16)
        .expect("step 16/17: source summary");
    let classified = recipient
        .classify_event_summaries(&s.scope, &sync.session_id, &page.summaries)
        .expect("classify recipient state");
    assert!(
        classified
            .iter()
            .any(|state| state.event_id == event.event_id
                && state.state == EventReplicaState::Missing)
    );
    assert_eq!(
        recipient.reconcile_event(&s.scope, &sync.session_id, &event),
        Ok(EventAppendStatus::Appended)
    );
    assert_eq!(
        recipient.reconcile_event(&s.scope, &sync.session_id, &event),
        Ok(EventAppendStatus::Duplicate)
    );

    for value in sent {
        assert!(
            sender
                .message(&s.scope, &value.message_id)
                .expect("sender message")
                .is_some()
        );
        assert!(
            recipient
                .message(&s.scope, &value.message_id)
                .expect("recipient message")
                .is_some()
        );
        assert_eq!(
            recipient.persist_message(value),
            Ok(DurableRecordStatus::Duplicate),
            "step 18: reconciliation must not create user-visible duplicates"
        );
    }
}

fn phase_restart_old_client_and_revocation(s: &Scenario, sent: &[MessageEnvelope]) {
    let signer = SigningKeyMaterial::generate().expect("signer");
    let device = DeviceDescriptor {
        device_id: DeviceId::from_opaque(oid("e2e-revoked-device")),
        identity_id: IdentityId::from_opaque(oid("e2e-bob-identity")),
        state: DeviceLifecycleState::Active,
    };
    let key = PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid("e2e-revoked-key")),
        device_id: device.device_id.clone(),
        purpose: KeyPurpose::Signing,
        algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
        algorithm_version: ALGORITHM_VERSION,
        key_format_version: KEY_FORMAT_VERSION,
        public_key: signer.verifying_key().0.to_vec(),
    };
    {
        let store = SqliteLocalStore::open(s.recipient_db.path()).expect("reopen recipient");
        store
            .register_device(&s.scope, &device)
            .expect("register active device");
        store
            .provision_trusted_signing_key(&s.scope, &key)
            .expect("trust device key");
    }
    {
        let sender = SqliteLocalStore::open(s.sender_db.path()).expect("restart sender");
        for value in sent {
            assert!(
                sender
                    .message(&s.scope, &value.message_id)
                    .expect("sender message after restart")
                    .is_some()
            );
        }
        let attachment_id = AttachmentId::from_opaque(oid("e2e-attachment"));
        assert!(
            sender
                .attachment_descriptor(&s.scope, &attachment_id)
                .expect("attachment after restart")
                .is_some()
        );

        let store = SqliteLocalStore::open(s.recipient_db.path()).expect("restart recipient");
        for value in sent {
            assert!(
                store
                    .message(&s.scope, &value.message_id)
                    .expect("recipient message after restart")
                    .is_some()
            );
        }
        let delivered = DeliveryId::from_opaque(oid("e2e-recipient-delivery"));
        assert_eq!(
            store
                .delivery_attempt(&s.scope, &delivered)
                .expect("delivery after restart")
                .expect("delivery exists")
                .state,
            DeliveryState::Delivered
        );
        assert_eq!(
            negotiate_version(
                VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 2))
                    .expect("current range"),
                VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                    .expect("old client"),
                VersionPolicy {
                    minimum: ProtocolVersion::new(1, 0),
                },
            ),
            Ok(ProtocolVersion::new(1, 0))
        );
        store
            .revoke_device(&s.scope, &device.device_id, &device.identity_id)
            .expect("revoke device");
    }
    let restarted = SqliteLocalStore::open(s.recipient_db.path()).expect("restart after revoke");
    let revoked = restarted
        .device(&s.scope, &device.device_id)
        .expect("read revoked device")
        .expect("device exists");
    assert_eq!(revoked.state, DeviceLifecycleState::Revoked);
    assert!(!ucr_protocol::device_allows_protected_access(&revoked));
    assert_eq!(
        restarted.resolve_active_signing_key(
            &s.scope,
            &device.device_id,
            Some(&device.identity_id),
            &key.key_id,
        ),
        Err(TrustedKeyResolutionError::NotTrusted)
    );

    let provider =
        CapturingProvider::new(STORE_FORWARD_INTERNET_CAPABILITY, ProviderOutcome::Accepted);
    let mut revoked_route = route_option(
        &provider,
        STORE_FORWARD_INTERNET_CAPABILITY,
        "revoked-device-route",
        5,
    );
    revoked_route.recipient_endpoint.device_id = Some(device.device_id.clone());
    let protected_intent = intent(s, "e2e-post-revoke-protected-intent", b"new protected content");
    assert_eq!(
        TransportOrchestrator::new(&AllowAll)
            .plan_protected(
                &protected_intent,
                resources(),
                &[],
                vec![revoked_route],
                &restarted,
            )
            .unwrap_err(),
        TransportOrchestratorError::NoEligibleRoute
    );
    assert!(
        provider.captured().is_empty(),
        "step 22: revoked device must not receive new protected content"
    );
}

#[test]
fn canon_main_end_to_end() {
    let s = Scenario::new();
    let sender = SqliteLocalStore::open(s.sender_db.path()).expect("sender store");
    let recipient = SqliteLocalStore::open(s.recipient_db.path()).expect("recipient store");
    let intermediary =
        SqliteLocalStore::open(s.intermediary_db.path()).expect("intermediary store");

    assert_eq!(
        sender.health().expect("sender health"),
        ucr_core::StorageHealth::Healthy
    );
    let mut sent = phase_internet_chat_and_video(&s, &sender, &recipient);
    phase_failover_lan_and_file(&s, &sender);
    let offline = phase_offline_store_forward(&s, &sender, &intermediary, &recipient);
    sent.push(offline);
    phase_reconciliation(&s, &sender, &recipient, &sent);

    drop(intermediary);
    drop(recipient);
    drop(sender);
    phase_restart_old_client_and_revocation(&s, &sent);
}

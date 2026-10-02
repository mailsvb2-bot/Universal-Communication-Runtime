use std::sync::Mutex;

use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, GroupStore, IdentityStore,
    PrincipalIdentityBindingStore, TrustedSigningKeyStore,
};
use ucr_crypto::{GroupMediaEpochSecret, SigningKeyMaterial};
use ucr_media_e2ee::{GroupMediaE2eeRuntime, PreparedGroupMediaE2eeCapabilities};
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, CanonicalError, GROUP_MLS_CAPABILITY, KEY_FORMAT_VERSION,
    SIGNATURE_ALGORITHM_ID,
};
use ucr_sfu::{
    PreparedSfuCapabilities, SfuError, SfuForwardOutcome, SfuForwardSink, SfuForwardSinkError,
    SfuRuntime,
};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Clone, Copy)]
struct AllowAll;

impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CountingSink {
    accepted: Mutex<usize>,
}

impl CountingSink {
    fn accepted(&self) -> usize {
        *self.accepted.lock().expect("sink lock")
    }
}

impl SfuForwardSink for CountingSink {
    fn forward_encrypted(
        &self,
        _target: &SfuForwardTarget,
        _envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let mut accepted = self.accepted.lock().expect("sink lock");
        *accepted = accepted.saturating_add(1);
        Ok(())
    }
}

#[derive(Debug)]
struct FailAfterSink {
    accepted: Mutex<usize>,
    fail_after: usize,
}

impl FailAfterSink {
    fn new(fail_after: usize) -> Self {
        Self {
            accepted: Mutex::new(0),
            fail_after,
        }
    }
}

impl SfuForwardSink for FailAfterSink {
    fn forward_encrypted(
        &self,
        _target: &SfuForwardTarget,
        _envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let mut accepted = self.accepted.lock().expect("sink lock");
        if *accepted >= self.fail_after {
            return Err(SfuForwardSinkError::Backpressure);
        }
        *accepted += 1;
        Ok(())
    }
}

struct Publisher {
    actor: ScopedPrincipal,
    device_id: DeviceId,
    signer: SigningKeyMaterial,
    key_id: KeyId,
}

struct ScaleFixture {
    store: MemoryLocalStore,
    group: GroupRecord,
    call: CallSession,
    publishers: Vec<Publisher>,
}

fn oid(value: impl AsRef<str>) -> OpaqueId {
    OpaqueId::new(value.as_ref()).expect("test id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-sfu-scale")),
        namespace_id: None,
    }
}

fn principal(index: usize) -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid(format!("person-{index:04}"))),
        kind: PrincipalKind::Person,
    }
}

fn actor(index: usize) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: principal(index),
    }
}

fn device(index: usize) -> DeviceId {
    DeviceId::from_opaque(oid(format!("device-{index:04}")))
}

fn identity(index: usize) -> IdentityId {
    IdentityId::from_opaque(oid(format!("identity-{index:04}")))
}

fn crypto_state(epoch: u64) -> GroupCryptoState {
    GroupCryptoState {
        capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
        epoch,
        state_ref: Some(oid(format!("mls-scale-{epoch}"))),
    }
}

fn install_publisher(store: &MemoryLocalStore, index: usize) -> Publisher {
    let actor = actor(index);
    let identity_id = identity(index);
    let device_id = device(index);
    store
        .persist_identity(&IdentityRecord {
            scope: scope(),
            identity_id: identity_id.clone(),
            ownership: IdentityOwnership::UcrNative,
            evidence: IdentityEvidence::DeviceVerified,
            expires_at_unix_ms: None,
        })
        .expect("publisher identity");
    store
        .persist_principal_identity_binding(&PrincipalIdentityBinding {
            scope: scope(),
            principal: actor.principal.clone(),
            identity_id: identity_id.clone(),
        })
        .expect("publisher binding");
    store
        .register_device(
            &scope(),
            &DeviceDescriptor {
                device_id: device_id.clone(),
                identity_id,
                state: DeviceLifecycleState::Active,
            },
        )
        .expect("publisher device");
    let signer = SigningKeyMaterial::generate().expect("publisher signing key");
    let key_id = KeyId::from_opaque(oid(format!("publisher-key-{index:04}")));
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
        .expect("publisher trusted signing key");
    Publisher {
        actor,
        device_id,
        signer,
        key_id,
    }
}

fn build_scale_group(
    store: &MemoryLocalStore,
    host: &ScopedPrincipal,
    participants: usize,
) -> (ConversationRecord, GroupRecord) {
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("sfu-scale-conversation")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let initial_group = GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("sfu-scale-group")),
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::PersonOwned(host.principal.clone()),
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
        .create_group(&conversation, &initial_group, host)
        .expect("scale group");

    let mut group = initial_group;
    for index in 1..participants {
        store
            .apply_group_change(
                host,
                &GroupChange {
                    event_id: EventId::from_opaque(oid(format!("add-scale-{index:04}"))),
                    scope: scope(),
                    group_id: group.group_id.clone(),
                    expected_revision: group.revision,
                    kind: GroupChangeKind::AddMember {
                        member: principal(index),
                        role: GroupRole::Member,
                    },
                    next_crypto_state: Some(crypto_state(group.crypto_state.epoch + 1)),
                },
            )
            .expect("add scale group member");
        group = store
            .group(&scope(), &group.group_id)
            .expect("scale group read")
            .expect("scale group exists");
    }
    (conversation, group)
}

fn build_scale_call(
    store: &MemoryLocalStore,
    host: &ScopedPrincipal,
    conversation: &ConversationRecord,
    participants: usize,
) -> CallSession {
    let participants_state = (0..participants)
        .map(|index| CallParticipant {
            principal: principal(index),
            state: if index == 0 {
                CallParticipantState::Accepted
            } else {
                CallParticipantState::Invited
            },
            joined_revision: 0,
            left_revision: None,
        })
        .collect();
    let initial_call = CallSession {
        scope: scope(),
        call_id: CallId::from_opaque(oid("sfu-scale-call")),
        conversation: conversation.conversation.clone(),
        initiated_by: host.principal.clone(),
        participants: participants_state,
        signalling_state: CallSignallingState::Inviting,
        reconnecting_participant: None,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
    };
    store.create_call(host, &initial_call).expect("scale call");
    for index in 1..participants {
        let current = store
            .call(&scope(), &initial_call.call_id)
            .expect("scale call read")
            .expect("scale call exists");
        store
            .apply_call_signal(
                &actor(index),
                &CallSignal {
                    event_id: EventId::from_opaque(oid(format!("accept-scale-{index:04}"))),
                    scope: scope(),
                    call_id: initial_call.call_id.clone(),
                    expected_revision: current.revision,
                    kind: CallSignalKind::Accept,
                },
            )
            .expect("accept scale participant");
    }
    let current = store
        .call(&scope(), &initial_call.call_id)
        .expect("scale call read")
        .expect("scale call exists");
    store
        .apply_call_signal(
            host,
            &CallSignal {
                event_id: EventId::from_opaque(oid("sfu-scale-negotiation")),
                scope: scope(),
                call_id: initial_call.call_id.clone(),
                expected_revision: current.revision,
                kind: CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("sfu-scale-negotiation-ref"),
                },
            },
        )
        .expect("scale media negotiation");
    store
        .call(&scope(), &initial_call.call_id)
        .expect("scale call read")
        .expect("scale call exists")
}

fn build_scale_fixture(participants: usize, publisher_count: usize) -> ScaleFixture {
    assert!((2..=1024).contains(&participants));
    assert!((1..participants).contains(&publisher_count));
    let store = MemoryLocalStore::default();
    let host = actor(0);
    let (conversation, group) = build_scale_group(&store, &host, participants);
    let call = build_scale_call(&store, &host, &conversation, participants);
    let publishers = (0..publisher_count)
        .map(|index| install_publisher(&store, index))
        .collect();
    ScaleFixture {
        store,
        group,
        call,
        publishers,
    }
}

fn context(group: &GroupRecord, call: &CallSession) -> GroupMediaE2eeContext {
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

fn envelope(fixture: &ScaleFixture, publisher: &Publisher, sequence: u64) -> SfuForwardEnvelope {
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let media = GroupMediaE2eeRuntime::new(&AllowAll, &fixture.store, &capabilities);
    let mut session = media
        .open_session(
            &publisher.actor,
            &publisher.device_id,
            &context(&fixture.group, &fixture.call),
            GroupMediaEpochSecret::from_exporter_bytes([42; 32]),
        )
        .expect("publisher media session");
    let frame = session
        .seal_payload(
            MediaKind::Video,
            &oid(format!(
                "video-stream-{}",
                publisher.actor.principal.principal_id.as_opaque().as_str()
            )),
            sequence,
            sequence.saturating_mul(3_000),
            true,
            b"opaque-scale-video-payload",
            &publisher.key_id,
            &publisher.signer,
        )
        .expect("seal scale frame");
    SfuForwardEnvelope { frame }
}

fn assert_encrypted_fanout_scale(participants: usize, publisher_count: usize) {
    let fixture = build_scale_fixture(participants, publisher_count);
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &capabilities, &sfu);
    let sink = CountingSink::default();
    for (index, publisher) in fixture.publishers.iter().enumerate() {
        let forwarded = runtime
            .forward(
                &publisher.actor,
                &publisher.device_id,
                &envelope(&fixture, publisher, index as u64 + 1),
                &sink,
            )
            .expect("encrypted scale fanout");
        assert_eq!(
            forwarded,
            SfuForwardOutcome {
                accepted_recipients: participants - 1,
            }
        );
    }
    assert_eq!(sink.accepted(), publisher_count * (participants - 1));
}

#[test]
fn ten_participant_one_publisher_encrypted_sfu_fanout() {
    assert_encrypted_fanout_scale(10, 1);
}

#[test]
fn hundred_participant_two_publisher_encrypted_sfu_fanout() {
    assert_encrypted_fanout_scale(100, 2);
}

#[test]
fn five_hundred_participant_four_publisher_encrypted_sfu_fanout() {
    assert_encrypted_fanout_scale(500, 4);
}

#[test]
fn thousand_participant_eight_publisher_encrypted_sfu_fanout() {
    assert_encrypted_fanout_scale(1000, 8);
}

#[test]
fn thousand_participant_fanout_reports_backpressure_without_false_acceptance() {
    let fixture = build_scale_fixture(1000, 1);
    let publisher = &fixture.publishers[0];
    let capabilities = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(&AllowAll, &fixture.store, &capabilities, &sfu);
    let sink = FailAfterSink::new(128);
    assert_eq!(
        runtime.forward(
            &publisher.actor,
            &publisher.device_id,
            &envelope(&fixture, publisher, 1),
            &sink,
        ),
        Err(SfuError::Sink {
            accepted_before_failure: 128,
            error: SfuForwardSinkError::Backpressure,
        })
    );
}

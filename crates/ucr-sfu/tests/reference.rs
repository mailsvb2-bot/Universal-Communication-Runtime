use std::sync::Mutex;

use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, GroupStore, IdentityStore,
    PrincipalIdentityBindingStore, TrustedSigningKeyStore,
};
use ucr_crypto::{GroupMediaEpochSecret, SigningKeyMaterial};
use ucr_media_e2ee::{GroupMediaE2eeRuntime, PreparedGroupMediaE2eeCapabilities};
use ucr_model::*;
use ucr_protocol::{
    ALGORITHM_VERSION, CanonicalError, CanonicalErrorCode, GROUP_MLS_CAPABILITY,
    KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID,
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

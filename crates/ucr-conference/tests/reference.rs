use ucr_conference::{ConferenceError, ConferenceRuntime, PreparedConferenceCapabilities};
use ucr_core::{AuthorizationEvaluator, DurableRecordStatus, GroupStore};
use ucr_media_e2ee::PreparedGroupMediaE2eeCapabilities;
use ucr_model::*;
use ucr_protocol::{
    CALL_OBSERVE_PERMISSION, CanonicalError, CanonicalErrorCode, GROUP_MLS_CAPABILITY,
    MAX_CALL_PARTICIPANTS,
};
use ucr_sfu::PreparedSfuCapabilities;
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct DenyObserve;
impl AuthorizationEvaluator for DenyObserve {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if request.permission == CALL_OBSERVE_PERMISSION {
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

fn oid(value: impl AsRef<str>) -> OpaqueId {
    OpaqueId::new(value.as_ref()).expect("test id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-conference")),
        namespace_id: None,
    }
}
fn principal(name: impl AsRef<str>) -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid(name.as_ref())),
        kind: PrincipalKind::Person,
    }
}
fn subject(name: impl AsRef<str>) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: principal(name),
    }
}
fn crypto_state(epoch: u64) -> GroupCryptoState {
    GroupCryptoState {
        capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
        epoch,
        state_ref: Some(oid(format!("mls-conference-{epoch}"))),
    }
}

fn base_group(store: &MemoryLocalStore, creator: &ScopedPrincipal) -> GroupRecord {
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conference-conversation")),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = GroupRecord {
        scope: scope(),
        group_id: GroupId::from_opaque(oid("conference-group")),
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::PersonOwned(creator.principal.clone()),
        history_policy: GroupHistoryPolicy::FullHistory,
        delivery_policy: DeliveryPolicy::Durable,
        crypto_state: crypto_state(0),
        public_policy: None,
        media_state: GroupMediaState::Idle,
        bridge_mappings: Vec::new(),
        replication_generation: 0,
        revision: 0,
    };
    assert_eq!(
        store.create_group(&conversation, &group, creator),
        Ok(DurableRecordStatus::Persisted)
    );
    group
}

fn add_member(
    store: &MemoryLocalStore,
    actor: &ScopedPrincipal,
    group: &GroupRecord,
    member: PrincipalRef,
    event: impl AsRef<str>,
) -> GroupRecord {
    let change = GroupChange {
        event_id: EventId::from_opaque(oid(event)),
        scope: group.scope.clone(),
        group_id: group.group_id.clone(),
        expected_revision: group.revision,
        kind: GroupChangeKind::AddMember {
            member,
            role: GroupRole::Member,
        },
        next_crypto_state: Some(crypto_state(group.crypto_state.epoch + 1)),
    };
    assert_eq!(
        store.apply_group_change(actor, &change),
        Ok(DurableRecordStatus::Persisted)
    );
    store
        .group(&group.scope, &group.group_id)
        .expect("group read")
        .expect("group")
}

fn runtime<'a, A: AuthorizationEvaluator>(
    authorization: &'a A,
    store: &'a MemoryLocalStore,
    e2ee: &'a PreparedGroupMediaE2eeCapabilities,
    sfu: &'a PreparedSfuCapabilities,
    conference: &'a PreparedConferenceCapabilities,
) -> ConferenceRuntime<
    'a,
    A,
    MemoryLocalStore,
    PreparedGroupMediaE2eeCapabilities,
    PreparedSfuCapabilities,
    PreparedConferenceCapabilities,
> {
    ConferenceRuntime::new(authorization, store, e2ee, sfu, conference)
}

fn start_request(group: &GroupRecord, invitees: Vec<PrincipalRef>) -> ConferenceStart {
    ConferenceStart {
        scope: scope(),
        call_id: CallId::from_opaque(oid("conference-call")),
        group_id: group.group_id.clone(),
        invitees,
    }
}

#[test]
fn conference_start_dedup_and_lifecycle_reuse_canonical_call_owner() {
    let store = MemoryLocalStore::default();
    let alice = subject("alice");
    let bob = subject("bob");
    let charlie = subject("charlie");
    let mut group = base_group(&store, &alice);
    group = add_member(&store, &alice, &group, bob.principal.clone(), "add-bob");
    group = add_member(
        &store,
        &alice,
        &group,
        charlie.principal.clone(),
        "add-charlie",
    );
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let conference = PreparedConferenceCapabilities;
    let coordinator = runtime(&AllowAll, &store, &e2ee, &sfu, &conference);
    let start = start_request(
        &group,
        vec![bob.principal.clone(), charlie.principal.clone()],
    );

    let (status, snapshot) = coordinator.start(&alice, &start).expect("start");
    assert_eq!(status, DurableRecordStatus::Persisted);
    assert_eq!(snapshot.topology, ConferenceTopology::Sfu);
    assert_eq!(snapshot.group_id, group.group_id);
    assert_eq!(snapshot.call.participants.len(), 3);
    assert_eq!(
        snapshot.call.signalling_state,
        CallSignallingState::Inviting
    );
    assert_eq!(
        coordinator.start(&alice, &start).map(|value| value.0),
        Ok(DurableRecordStatus::Duplicate)
    );

    let signal = CallSignal {
        event_id: EventId::from_opaque(oid("bob-accept")),
        scope: scope(),
        call_id: start.call_id.clone(),
        expected_revision: snapshot.call.revision,
        kind: CallSignalKind::Accept,
    };
    assert_eq!(
        coordinator.signal(&bob, &signal),
        Ok(DurableRecordStatus::Persisted)
    );
    let active = coordinator
        .snapshot(&alice, &scope(), &start.call_id)
        .expect("active snapshot");
    assert_eq!(active.call.signalling_state, CallSignallingState::Active);
    assert_eq!(active.group_crypto_epoch, group.crypto_state.epoch);
}

#[test]
fn conference_participant_addition_requires_current_group_membership() {
    let store = MemoryLocalStore::default();
    let alice = subject("alice");
    let bob = subject("bob");
    let outsider = subject("outsider");
    let mut group = base_group(&store, &alice);
    group = add_member(&store, &alice, &group, bob.principal.clone(), "add-bob");
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let conference = PreparedConferenceCapabilities;
    let coordinator = runtime(&AllowAll, &store, &e2ee, &sfu, &conference);
    let start = start_request(&group, vec![bob.principal.clone()]);
    let (_, snapshot) = coordinator.start(&alice, &start).expect("start");
    let add = CallSignal {
        event_id: EventId::from_opaque(oid("invite-outsider")),
        scope: scope(),
        call_id: start.call_id,
        expected_revision: snapshot.call.revision,
        kind: CallSignalKind::ParticipantUpdate {
            participant: outsider.principal,
            kind: CallParticipantUpdateKind::Add,
        },
    };
    assert_eq!(
        coordinator.signal(&alice, &add),
        Err(ConferenceError::MembershipUnavailable)
    );
}

#[test]
fn signalling_permission_does_not_require_observe_permission() {
    let store = MemoryLocalStore::default();
    let alice = subject("alice");
    let bob = subject("bob");
    let mut group = base_group(&store, &alice);
    group = add_member(&store, &alice, &group, bob.principal.clone(), "add-bob");
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let conference = PreparedConferenceCapabilities;
    let coordinator = runtime(&DenyObserve, &store, &e2ee, &sfu, &conference);
    let start = start_request(&group, vec![bob.principal.clone()]);
    let (_, snapshot) = coordinator
        .start(&alice, &start)
        .expect("start without observe");
    let signal = CallSignal {
        event_id: EventId::from_opaque(oid("bob-accept")),
        scope: scope(),
        call_id: start.call_id.clone(),
        expected_revision: snapshot.call.revision,
        kind: CallSignalKind::Accept,
    };
    assert_eq!(
        coordinator.signal(&bob, &signal),
        Ok(DurableRecordStatus::Persisted)
    );
    assert!(matches!(
        coordinator.snapshot(&bob, &scope(), &start.call_id),
        Err(ConferenceError::Authorization(error))
            if error.code == CanonicalErrorCode::PermissionDenied
    ));
}

#[test]
fn subscriptions_require_accepted_sources_and_are_recipient_owned() {
    let store = MemoryLocalStore::default();
    let alice = subject("alice");
    let bob = subject("bob");
    let charlie = subject("charlie");
    let mut group = base_group(&store, &alice);
    group = add_member(&store, &alice, &group, bob.principal.clone(), "add-bob-sub");
    group = add_member(
        &store,
        &alice,
        &group,
        charlie.principal.clone(),
        "add-charlie-sub",
    );
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let conference = PreparedConferenceCapabilities;
    let coordinator = runtime(&AllowAll, &store, &e2ee, &sfu, &conference);
    let start = start_request(
        &group,
        vec![bob.principal.clone(), charlie.principal.clone()],
    );
    let (_, initial) = coordinator.start(&alice, &start).expect("start");
    let accept_bob = CallSignal {
        event_id: EventId::from_opaque(oid("bob-accept-sub")),
        scope: scope(),
        call_id: start.call_id.clone(),
        expected_revision: initial.call.revision,
        kind: CallSignalKind::Accept,
    };
    coordinator.signal(&bob, &accept_bob).expect("bob accept");

    let alice_audio = ConferenceSubscriptionSet {
        scope: scope(),
        call_id: start.call_id.clone(),
        subscriptions: vec![ConferenceMediaSubscription {
            source: alice.principal.clone(),
            media_kind: MediaKind::Audio,
        }],
    };
    assert_eq!(coordinator.set_subscriptions(&bob, &alice_audio), Ok(1));
    let charlie_video = ConferenceSubscriptionSet {
        scope: scope(),
        call_id: start.call_id.clone(),
        subscriptions: vec![ConferenceMediaSubscription {
            source: charlie.principal.clone(),
            media_kind: MediaKind::Video,
        }],
    };
    assert_eq!(
        coordinator.set_subscriptions(&bob, &charlie_video),
        Err(ConferenceError::SourceUnavailable)
    );
    let clear = ConferenceSubscriptionSet {
        scope: scope(),
        call_id: start.call_id,
        subscriptions: Vec::new(),
    };
    assert_eq!(coordinator.set_subscriptions(&bob, &clear), Ok(0));
}

#[test]
fn thousand_person_sfu_conference_fits_bounded_call_ceiling() {
    assert_eq!(MAX_CALL_PARTICIPANTS, 1024);
    let store = MemoryLocalStore::default();
    let host = subject("person-000");
    let mut group = base_group(&store, &host);
    let mut invitees = Vec::new();
    for index in 1..1000 {
        let member = principal(format!("person-{index:03}"));
        group = add_member(
            &store,
            &host,
            &group,
            member.clone(),
            format!("add-person-{index:03}"),
        );
        invitees.push(member);
    }
    let e2ee = PreparedGroupMediaE2eeCapabilities;
    let sfu = PreparedSfuCapabilities;
    let conference = PreparedConferenceCapabilities;
    let coordinator = runtime(&AllowAll, &store, &e2ee, &sfu, &conference);
    let start = start_request(&group, invitees.clone());
    let (_, snapshot) = coordinator
        .start(&host, &start)
        .expect("1000-person conference");
    assert_eq!(snapshot.call.participants.len(), 1000);
    assert_eq!(snapshot.topology, ConferenceTopology::Sfu);

    for (offset, participant) in invitees.iter().enumerate() {
        let accept = CallSignal {
            event_id: EventId::from_opaque(oid(format!("accept-person-{:03}", offset + 1))),
            scope: scope(),
            call_id: start.call_id.clone(),
            expected_revision: offset as u64,
            kind: CallSignalKind::Accept,
        };
        coordinator
            .signal(
                &ScopedPrincipal {
                    scope: scope(),
                    principal: participant.clone(),
                },
                &accept,
            )
            .expect("participant accept");
    }
    let active = coordinator
        .snapshot(&host, &scope(), &start.call_id)
        .expect("1000 accepted snapshot");
    assert_eq!(
        active
            .call
            .participants
            .iter()
            .filter(|participant| participant.state == CallParticipantState::Accepted)
            .count(),
        1000
    );
    assert_eq!(active.call.signalling_state, CallSignallingState::Active);
}

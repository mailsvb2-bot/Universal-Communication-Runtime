//! Canonical first-party webinar control plane.
//!
//! Room intent and membership live ONLY in UniversalConferenceStore (the same
//! production SQLite as Realtime). The browser cannot choose a principal,
//! Device or signing authority. No media readiness/grant is fabricated here;
//! endpoint MLS and the universal conference runtime still own media admission.

use super::*;
use ucr_api_grpc::{
    canonical_universal_conference_lifecycle_event, issue_authenticated_first_party_room_join,
    prepare_authenticated_first_party_room_call, reconcile_canonical_conference_permissions,
};
use ucr_core::{DurableRecordStatus, DurableStoreError, GroupCallLookupStore, UniversalConferenceStore};
use ucr_model::{
    ConferenceParticipantRole, ConferenceScheduleMetadata, GroupId, UniversalConferenceLifecycle,
    UniversalConferenceMode, UniversalConferenceParticipantProfile, UniversalConferenceProfile,
};

const INTEGRATION: &str = "ucr-first-party-room";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateRoom {
    binding: Binding,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomRef {
    binding: Binding,
    room_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomEntryChange {
    binding: Binding,
    room_id: String,
    expected_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomJoin {
    binding: Binding,
    room_id: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomCallAccept {
    binding: Binding,
    room_id: String,
    expected_call_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomMlsCreate {
    binding: Binding,
    room_id: String,
    expected_revision: u64,
    crypto_state_ref: String,
    signature_base64_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomMlsOffer {
    binding: Binding,
    room_id: String,
    signer_key_id: String,
    key_package_base64_url: String,
    signature_base64_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoomMlsAddMember {
    binding: Binding,
    room_id: String,
    expected_room_revision: u64,
    group_revision: u64,
    event_id: String,
    crypto_epoch: u64,
    crypto_state_ref: String,
    recipient_device_id: String,
    recipient_signer_key_id: String,
    recipient_key_package_base64_url: String,
    recipient_signature_base64_url: String,
    commit_base64_url: String,
    welcome_base64_url: String,
    signature_base64_url: String,
}

fn integration() -> Result<IntegrationId, StatusCode> {
    Ok(IntegrationId::from_opaque(opaque(INTEGRATION)?))
}

fn scoped_room_id(auth: &Session, key: &str) -> Result<GroupId, StatusCode> {
    if !(16..=90).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut digest = Sha256::new();
    digest.update(b"ucr-first-party-webinar-id.v1\0");
    for field in [
        auth.subject.scope.tenant_id.as_opaque().as_wire_bytes(),
        auth.subject
            .principal
            .principal_id
            .as_opaque()
            .as_wire_bytes(),
        key.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    match &auth.subject.scope.namespace_id {
        Some(namespace) => {
            digest.update([1]);
            digest.update(namespace.as_opaque().as_wire_bytes());
        }
        None => digest.update([0]),
    }
    let mut identifier = String::from("fp-room-");
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        write!(&mut identifier, "{byte:02x}").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(GroupId::from_opaque(opaque(&identifier)?))
}

fn owned_room(
    state: &State,
    auth: &Session,
    room_id: &GroupId,
) -> Result<
    (
        UniversalConferenceProfile,
        UniversalConferenceParticipantProfile,
    ),
    StatusCode,
> {
    let profile = state
        .store
        .universal_conference_profile(&auth.subject.scope, room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if profile.integration_id != integration()? || profile.mode != UniversalConferenceMode::Webinar
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let owner = state
        .store
        .universal_conference_participant(&auth.subject.scope, room_id, &auth.subject.principal)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if owner.role != ConferenceParticipantRole::Owner || !owner.active {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((profile, owner))
}

// Reuse the exact PermissionGrantStore reconciler from UniversalConferenceService,
// never invent Room-scoped role grants or silently claim successful media Join.
fn reconcile_room_permissions(
    state: &State,
    participant: &UniversalConferenceParticipantProfile,
) -> Result<(), StatusCode> {
    reconcile_canonical_conference_permissions(
        state.store.as_ref(),
        participant,
        UniversalConferenceMode::Webinar,
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn owner_profile(
    auth: &Session,
    room_id: &GroupId,
    integration_id: &IntegrationId,
) -> UniversalConferenceParticipantProfile {
    UniversalConferenceParticipantProfile {
        scope: auth.subject.scope.clone(),
        conference_id: room_id.clone(),
        integration_id: integration_id.clone(),
        external_user_id: auth.binding.participant_id.as_bytes().to_vec(),
        participant: auth.subject.principal.clone(),
        role: ConferenceParticipantRole::Owner,
        audio_muted: false,
        camera_allowed: true,
        publish_audio_allowed: true,
        publish_video_allowed: true,
        screen_share_allowed: true,
        active: true,
        revision: 1,
    }
}

fn create_room(state: &State, auth: &Session, input: &CreateRoom) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = scoped_room_id(auth, &input.idempotency_key)?;
    let integration_id = integration()?;
    let owner = owner_profile(auth, &room_id, &integration_id);
    // Querying the canonical owner before creating prevents a retry from
    // generating a new schedule. A racy retry is reconciled after the atomic
    // write; a conflicting owner can never succeed.
    if let Some(existing) = state
        .store
        .universal_conference_profile(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        let (_, recorded_owner) = owned_room(state, auth, &room_id)?;
        if existing.create_idempotency_key != input.idempotency_key || recorded_owner != owner {
            return Err(StatusCode::CONFLICT);
        }
        reconcile_room_permissions(state, &recorded_owner)?;
        return Ok(describe_room(&existing, false));
    }
    let profile = UniversalConferenceProfile {
        scope: auth.subject.scope.clone(),
        conference_id: room_id.clone(),
        integration_id: integration_id.clone(),
        external_conference_id: room_id.as_opaque().as_wire_bytes().to_vec(),
        create_idempotency_key: input.idempotency_key.clone(),
        mode: UniversalConferenceMode::Webinar,
        lifecycle: UniversalConferenceLifecycle::Scheduled,
        schedule: ConferenceScheduleMetadata {
            starts_at_unix_ms: now_unix_ms()?,
            planned_end_unix_ms: None,
            join_before_seconds: 900,
            join_after_seconds: 0,
            timezone: Some("UTC".to_owned()),
        },
        metadata: Vec::new(),
        entry_open: false,
        revision: 1,
    };
    let inserted = state
        .store
        .persist_first_party_room_with_owner(&profile, &owner);
    match inserted {
        Ok(DurableRecordStatus::Persisted | DurableRecordStatus::Duplicate) => {
            reconcile_room_permissions(state, &owner)?;
            Ok(describe_room(&profile, false))
        }
        Err(DurableStoreError::Conflict) => {
            // Exact safe reconciliation of two devices racing with the same
            // owner/key; never accept only a coordinator without its owner.
            let (found, saved_owner) = owned_room(state, auth, &room_id)?;
            if found.create_idempotency_key != input.idempotency_key || saved_owner != owner {
                return Err(StatusCode::CONFLICT);
            }
            reconcile_room_permissions(state, &saved_owner)?;
            Ok(describe_room(&found, false))
        }
        Err(DurableStoreError::Full) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(DurableStoreError::InvalidRecord) => Err(StatusCode::BAD_REQUEST),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

// A viewer must be a previously proven canonical Person Device, not an
// anonymous name or a fabricated external-user reference. This persists
// membership only; runtime MLS and signed media Join are separate authorities.
fn enroll_attendee(state: &State, auth: &Session, input: &RoomRef) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let profile = state
        .store
        .universal_conference_profile(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if profile.mode != UniversalConferenceMode::Webinar || profile.integration_id != integration()?
    {
        return Err(StatusCode::NOT_FOUND);
    }
    if !profile.entry_open
        || !matches!(
            profile.lifecycle,
            UniversalConferenceLifecycle::Waiting | UniversalConferenceLifecycle::Live
        )
    {
        return Err(StatusCode::CONFLICT);
    }
    let attendee = UniversalConferenceParticipantProfile {
        scope: auth.subject.scope.clone(),
        conference_id: room_id.clone(),
        integration_id: profile.integration_id,
        external_user_id: auth.binding.participant_id.as_bytes().to_vec(),
        participant: auth.subject.principal.clone(),
        role: ConferenceParticipantRole::Attendee,
        audio_muted: true,
        camera_allowed: false,
        publish_audio_allowed: false,
        publish_video_allowed: false,
        screen_share_allowed: false,
        active: true,
        revision: 1,
    };
    match state.store.persist_first_party_room_attendee(&attendee) {
        Ok(DurableRecordStatus::Persisted | DurableRecordStatus::Duplicate) => {
            reconcile_room_permissions(state, &attendee)?;
            Ok(json!({
                "roomId": input.room_id,
                "enrolled": true,
                "role": "attendee",
                "mediaReady": false,
            }))
        }
        Err(DurableStoreError::Conflict | DurableStoreError::InvalidRecord) => {
            Err(StatusCode::CONFLICT)
        }
        Err(DurableStoreError::Full) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

// This is only the canonical scheduling/entry gate. It does not activate
// Group MLS, publish a media-ready claim or mint an unsigned Join.
fn change_room_entry(
    state: &State,
    auth: &Session,
    input: &RoomEntryChange,
    open: bool,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (profile, _) = owned_room(state, auth, &room_id)?;
    if profile.revision != input.expected_revision {
        return Err(StatusCode::CONFLICT);
    }
    if !matches!(
        profile.lifecycle,
        UniversalConferenceLifecycle::Scheduled | UniversalConferenceLifecycle::Waiting
    ) {
        return Err(StatusCode::CONFLICT);
    }
    if profile.lifecycle == UniversalConferenceLifecycle::Waiting && profile.entry_open == open {
        return Ok(describe_room(&profile, false));
    }
    // Never reopen a previously closed waiting room: earlier signed Join
    // leases could otherwise regain authority on the same Conference.
    if (open && profile.lifecycle != UniversalConferenceLifecycle::Scheduled)
        || (!open && profile.lifecycle != UniversalConferenceLifecycle::Waiting)
    {
        return Err(StatusCode::CONFLICT);
    }
    let next = state
        .store
        .transition_universal_conference(
            &auth.subject.scope,
            &room_id,
            profile.revision,
            UniversalConferenceLifecycle::Waiting,
            open,
        )
        .map_err(|error| match error {
            DurableStoreError::Conflict | DurableStoreError::InvalidRecord => StatusCode::CONFLICT,
            DurableStoreError::Full => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        })?;
    Ok(describe_room(&next, false))
}

// Cancel pre-live rooms using the SAME Conference event constructor and
// atomic lifecycle/Event transition as universal conference integrations.
// Live rooms must use their own media teardown first; they cannot be silently
// marked Ended while SFU or MLS sessions are still present.
// A Waiting Room cannot go Live on the strength of a button or a Join URL.
// Require one Active canonical Call whose endpoint-owned MLS Group is
// committed and not held in the server's OpenMLS provider.
fn go_live_room(
    state: &State,
    auth: &Session,
    input: &RoomEntryChange,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (room, _) = owned_room(state, auth, &room_id)?;
    if room.revision != input.expected_revision
        || room.lifecycle != UniversalConferenceLifecycle::Waiting
        || !room.entry_open
    {
        return Err(StatusCode::CONFLICT);
    }
    let mut calls = state
        .store
        .active_calls_for_group(&auth.subject.scope, &room_id, 2)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if calls.len() != 1 || calls.pop().is_none_or(|call| {
        call.signalling_state != CallSignallingState::Active
            || call.initiated_by != auth.subject.principal
    }) {
        return Err(StatusCode::CONFLICT);
    }
    let group = state
        .store
        .group(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::CONFLICT)?;
    if group.crypto_state.capability_id.as_deref() != Some(ucr_protocol::GROUP_MLS_CAPABILITY)
        || group.crypto_state.epoch == 0
        || ucr_group_mls::GroupMlsServerCustodyProbe::server_possesses_mls_group(
            state.store.as_ref(),
            &auth.subject.scope,
            &room_id,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::CONFLICT);
    }
    let command_id = ucr_model::CommandId::from_opaque(
        generate_opaque_id().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    );
    let key = format!("fp-room-live-{}-{}", input.room_id, room.revision);
    let event = canonical_universal_conference_lifecycle_event(
        &room,
        UniversalConferenceLifecycle::Live,
        &command_id,
        &key,
        now_unix_ms()?,
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let current = state
        .store
        .transition_universal_conference_with_event(
            &auth.subject.scope,
            &room_id,
            room.revision,
            UniversalConferenceLifecycle::Live,
            true,
            Some(&event),
        )
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(describe_room(&current, false))
}

fn end_unstarted_room(
    state: &State,
    auth: &Session,
    input: &RoomEntryChange,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (profile, _) = owned_room(state, auth, &room_id)?;
    if profile.lifecycle == UniversalConferenceLifecycle::Ended {
        return Ok(describe_room(&profile, false));
    }
    if profile.revision != input.expected_revision
        || !matches!(
            profile.lifecycle,
            UniversalConferenceLifecycle::Scheduled | UniversalConferenceLifecycle::Waiting
        )
    {
        return Err(StatusCode::CONFLICT);
    }
    // A Room with a prepared Group may already have SFU/MLS sessions. Its
    // end must go through media termination, not a control-plane-only update.
    if state
        .store
        .group(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }
    let command_id = ucr_model::CommandId::from_opaque(
        generate_opaque_id().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    );
    let idempotency_key = format!("fp-room-end-{}-{}", input.room_id, input.expected_revision);
    let event = canonical_universal_conference_lifecycle_event(
        &profile,
        UniversalConferenceLifecycle::Ended,
        &command_id,
        &idempotency_key,
        now_unix_ms()?,
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let ended = state
        .store
        .transition_universal_conference_with_event(
            &auth.subject.scope,
            &room_id,
            profile.revision,
            UniversalConferenceLifecycle::Ended,
            false,
            Some(&event),
        )
        .map_err(|error| match error {
            DurableStoreError::Conflict | DurableStoreError::InvalidRecord => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        })?;
    Ok(describe_room(&ended, false))
}

// Exact canonical Person/Device session is checked by the enclosing first-
// party BFF. This route uses only the already-mounted production issuer/store;
// it creates no synthetic attendee, MLS leaf or second grant signer.
// Call creation is owned by the same UniversalConferenceService CallStore
// reconciler, after each Person endpoint has already contributed a signed
// MLS Add. It cannot create any MLS key or Group membership itself.
fn prepare_room_call(state: &State, auth: &Session, input: &RoomJoin) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (room, _) = owned_room(state, auth, &room_id)?;
    let call_prepared = prepare_authenticated_first_party_room_call(
        state.store.as_ref(),
        &auth.subject.scope,
        &room_id,
        &auth.subject.principal,
        &input.idempotency_key,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    Ok(json!({
        "roomId": input.room_id,
        "revision": room.revision,
        "callPrepared": call_prepared,
        "mediaReady": false
    }))
}

// The authenticated Owner's browser publishes an endpoint-created epoch-0
// MLS Group. Neither the UCR server nor the operator holds the Group secret.
fn publish_room_endpoint_group(
    state: &State,
    auth: &Session,
    input: &RoomMlsCreate,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (room, _) = owned_room(state, auth, &room_id)?;
    if room.revision != input.expected_revision
        || room.lifecycle != UniversalConferenceLifecycle::Waiting
        || !room.entry_open
    {
        return Err(StatusCode::CONFLICT);
    }
    let state_ref = opaque(&input.crypto_state_ref)?;
    let proof = encoded_proof(
        "ucr-first-party-room-endpoint-mls-create.v1",
        &json!([
            auth.binding.tenant_id,
            auth.binding.namespace_id,
            auth.binding.participant_id,
            auth.binding.device,
            auth.signer_key_id,
            input.room_id,
            input.expected_revision,
            0,
            input.crypto_state_ref
        ]),
    )?;
    verify_ed25519(auth.signer_public_key, &proof, &input.signature_base64_url)?;
    if ucr_group_mls::GroupMlsServerCustodyProbe::server_possesses_mls_group(
        state.store.as_ref(),
        &auth.subject.scope,
        &room_id,
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::CONFLICT);
    }
    let conversation = ConversationRecord {
        scope: auth.subject.scope.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(opaque(&format!(
                "fp-room-conv-{}",
                input.room_id
            ))?),
            kind: ConversationKind::PrivateGroup,
        },
        parent_conversation_id: None,
    };
    let group = GroupRecord {
        scope: auth.subject.scope.clone(),
        group_id: room_id,
        conversation: conversation.conversation.clone(),
        ownership: GroupOwnership::PersonOwned(auth.subject.principal.clone()),
        history_policy: GroupHistoryPolicy::NoHistory,
        delivery_policy: DeliveryPolicy::NoExternalBridge,
        crypto_state: GroupCryptoState {
            capability_id: Some(ucr_protocol::GROUP_MLS_CAPABILITY.to_owned()),
            epoch: 0,
            state_ref: Some(state_ref),
        },
        public_policy: None,
        media_state: GroupMediaState::Idle,
        bridge_mappings: Vec::new(),
        replication_generation: 0,
        revision: 0,
    };
    state
        .store
        .create_group(&conversation, &group, &auth.subject)
        .map_err(|_| StatusCode::CONFLICT)?;
    confirm_endpoint_mls_group_publication(state, &group)?;
    Ok(json!({
        "roomId": input.room_id,
        "groupId": input.room_id,
        "cryptoEpoch": 0,
        "cryptoStateRef": input.crypto_state_ref,
        "requiresEndpointOwnedCommit": true,
        "mediaReady": false
    }))
}

// An already-proven Person Device deposits only a public MLS KeyPackage,
// authenticated with its current Device signer. Private MLS keys stay on the
// browser. The Room Owner can read it only after canonical enrollment.
fn publish_room_mls_offer(
    state: &State,
    auth: &Session,
    input: &RoomMlsOffer,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    if input.signer_key_id != auth.signer_key_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let room = state
        .store
        .universal_conference_profile(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let enrolled = state
        .store
        .universal_conference_participant(&auth.subject.scope, &room_id, &auth.subject.principal)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if room.integration_id != integration()?
        || !room.entry_open
        || room.lifecycle != UniversalConferenceLifecycle::Waiting
        || enrolled.role != ConferenceParticipantRole::Attendee
        || !enrolled.active
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let bytes = decode_mls_public_wire(&input.key_package_base64_url)?;
    let proof = encoded_proof(
        "ucr-first-party-room-endpoint-mls-key-package.v1",
        &json!([
            auth.binding.tenant_id,
            auth.binding.namespace_id,
            auth.binding.participant_id,
            auth.binding.device,
            auth.signer_key_id,
            input.room_id,
            sha256_b64(&bytes),
        ]),
    )?;
    verify_ed25519(auth.signer_public_key, &proof, &input.signature_base64_url)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&input.signature_base64_url)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .put_endpoint_mls_offer(
            &auth.subject.scope,
            &room_id,
            &device(&auth.binding)?,
            &EndpointMlsKeyPackageOffer {
                signer_key_id: input.signer_key_id.clone(),
                package: bytes,
                signature,
            },
        )
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(json!({
        "roomId": input.room_id,
        "deviceId": auth.binding.device,
        "offerStored": true,
        "mediaReady": false
    }))
}

// The Owner receives only offers from currently enrolled, trusted People.
// Never return another Device's offer merely because its ID is in the
// SQLite public-package table.
fn load_room_mls_offers(
    state: &State,
    auth: &Session,
    input: &RoomRef,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (room, _) = owned_room(state, auth, &room_id)?;
    if !room.entry_open || room.lifecycle != UniversalConferenceLifecycle::Waiting {
        return Err(StatusCode::CONFLICT);
    }
    let candidates = state
        .store
        .endpoint_mls_offer_device_ids(&auth.subject.scope, &room_id, 16)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let participants = state
        .store
        .active_universal_conference_participants(&auth.subject.scope, &room_id, 1025)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut offers = Vec::new();
    for candidate in candidates {
        let device_id = DeviceId::from_opaque(opaque(&candidate)?);
        let Some(descriptor) = state
            .store
            .device(&auth.subject.scope, &device_id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        else {
            continue;
        };
        if !ucr_protocol::device_allows_protected_access(&descriptor) {
            continue;
        }
        let mut selected = None;
        for person in &participants {
            if person.role == ConferenceParticipantRole::Owner {
                continue;
            }
            let Some(binding) = state
                .store
                .principal_identity_binding(&auth.subject.scope, &person.participant)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            else {
                continue;
            };
            if binding.identity_id == descriptor.identity_id {
                selected = Some(person);
                break;
            }
        }
        let Some(person) = selected else { continue };
        let Some(key) = state
            .store
            .active_trusted_signing_key(&auth.subject.scope, &device_id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        else {
            continue;
        };
        let Some(offer) = state
            .store
            .endpoint_mls_offer(&auth.subject.scope, &room_id, &device_id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        else {
            continue;
        };
        if offer.signer_key_id != key.key_id.as_opaque().as_str() {
            continue;
        }
        let verified: [u8; 32] = key
            .public_key
            .try_into()
            .map_err(|_| StatusCode::CONFLICT)?;
        let proof = encoded_proof(
            "ucr-first-party-room-endpoint-mls-key-package.v1",
            &json!([
                auth.binding.tenant_id,
                auth.binding.namespace_id,
                String::from_utf8(person.external_user_id.clone())
                    .map_err(|_| StatusCode::CONFLICT)?,
                candidate,
                offer.signer_key_id,
                input.room_id,
                sha256_b64(&offer.package),
            ]),
        )?;
        // Recipient originally signed their external participant ID. The
        // server binds that ID to canonical attendee identity above; never
        // authorize based on this array or the public KeyPackage alone.
        verify_ed25519(verified, &proof, &URL_SAFE_NO_PAD.encode(&offer.signature))?;
        offers.push(json!({
            "recipientDeviceId": candidate,
            "recipientSignerKeyId": offer.signer_key_id,
            "recipientKeyPackageBase64Url": URL_SAFE_NO_PAD.encode(&offer.package),
            "recipientSignatureBase64Url": URL_SAFE_NO_PAD.encode(&offer.signature)
        }));
    }
    Ok(json!({"roomId":input.room_id,"offers":offers}))
}

// Adds one canonical enrolled Person Device to the endpoint-owned Group.
// The Owner signs the entire commitment and the recipient signs its own public
// KeyPackage. The server verifies both Device signers, then delegates the
// durable Group CAS + MLS Commit/Welcome to EndpointMlsCommitStore.
fn commit_room_endpoint_member(
    state: &State,
    auth: &Session,
    input: &RoomMlsAddMember,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let (room, _) = owned_room(state, auth, &room_id)?;
    if room.revision != input.expected_room_revision
        || !room.entry_open
        || room.lifecycle != UniversalConferenceLifecycle::Waiting
    {
        return Err(StatusCode::CONFLICT);
    }
    let group = state
        .store
        .group(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::CONFLICT)?;
    if group.ownership != GroupOwnership::PersonOwned(auth.subject.principal.clone()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let recipient_device = DeviceId::from_opaque(opaque(&input.recipient_device_id)?);
    let descriptor = state
        .store
        .device(&auth.subject.scope, &recipient_device)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if !ucr_protocol::device_allows_protected_access(&descriptor) {
        return Err(StatusCode::FORBIDDEN);
    }
    let participants = state
        .store
        .active_universal_conference_participants(&auth.subject.scope, &room_id, 1025)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut recipient = None;
    for person in participants {
        if person.role != ConferenceParticipantRole::Attendee {
            continue;
        }
        let Some(binding) = state
            .store
            .principal_identity_binding(&auth.subject.scope, &person.participant)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        else {
            continue;
        };
        if binding.identity_id == descriptor.identity_id {
            if recipient.is_some() {
                return Err(StatusCode::CONFLICT);
            }
            recipient = Some(person);
        }
    }
    let recipient = recipient.ok_or(StatusCode::FORBIDDEN)?;
    let current_signer = state
        .store
        .active_trusted_signing_key(&auth.subject.scope, &recipient_device)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if current_signer.key_id.as_opaque().as_str() != input.recipient_signer_key_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let offer = state
        .store
        .endpoint_mls_offer(&auth.subject.scope, &room_id, &recipient_device)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if offer.signer_key_id != input.recipient_signer_key_id
        || URL_SAFE_NO_PAD.encode(&offer.signature) != input.recipient_signature_base64_url
        || URL_SAFE_NO_PAD.encode(&offer.package) != input.recipient_key_package_base64_url
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let package = decode_mls_public_wire(&input.recipient_key_package_base64_url)?;
    let commit = decode_mls_public_wire(&input.commit_base64_url)?;
    let welcome = decode_mls_public_wire(&input.welcome_base64_url)?;
    let signer_key: [u8; 32] = current_signer
        .public_key
        .try_into()
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let recipient_identity =
        String::from_utf8(recipient.external_user_id.clone()).map_err(|_| StatusCode::CONFLICT)?;
    let offer_proof = encoded_proof(
        "ucr-first-party-room-endpoint-mls-key-package.v1",
        &json!([
            auth.binding.tenant_id,
            auth.binding.namespace_id,
            recipient_identity,
            input.recipient_device_id,
            input.recipient_signer_key_id,
            input.room_id,
            sha256_b64(&package),
        ]),
    )?;
    verify_ed25519(
        signer_key,
        &offer_proof,
        &input.recipient_signature_base64_url,
    )?;
    let owner_proof = encoded_proof(
        "ucr-first-party-room-endpoint-mls-add-member.v1",
        &json!([
            auth.binding.tenant_id,
            auth.binding.namespace_id,
            auth.binding.participant_id,
            auth.binding.device,
            auth.signer_key_id,
            input.room_id,
            input.expected_room_revision,
            input.group_revision,
            input.event_id,
            input.crypto_epoch,
            input.crypto_state_ref,
            input.recipient_device_id,
            input.recipient_signer_key_id,
            sha256_b64(&package),
            sha256_b64(&commit),
            sha256_b64(&welcome),
        ]),
    )?;
    verify_ed25519(
        auth.signer_public_key,
        &owner_proof,
        &input.signature_base64_url,
    )?;
    let fingerprint: [u8; 32] = Sha256::digest(owner_proof.as_bytes()).into();
    let change = GroupChange {
        event_id: EventId::from_opaque(opaque(&input.event_id)?),
        scope: auth.subject.scope.clone(),
        group_id: room_id.clone(),
        expected_revision: input.group_revision,
        kind: GroupChangeKind::AddMember {
            member: recipient.participant,
            role: GroupRole::Member,
        },
        next_crypto_state: None,
    };
    let artifacts = MlsCommitArtifacts {
        commit,
        welcome: Some(welcome),
        next_crypto_state: GroupCryptoState {
            capability_id: Some(ucr_protocol::GROUP_MLS_CAPABILITY.to_owned()),
            epoch: input.crypto_epoch,
            state_ref: Some(opaque(&input.crypto_state_ref)?),
        },
    };
    let status = state
        .store
        .persist_endpoint_mls_commit(
            &auth.subject,
            &device(&auth.binding)?,
            &change,
            &MlsDeviceAdmission {
                device_id: recipient_device,
                key_package: package,
            },
            &artifacts,
            fingerprint,
        )
        .map_err(|_| StatusCode::CONFLICT)?;
    // A close racing an accepted endpoint Commit must not yield a false live
    // acknowledgement, and the unchanged room is never automatically reopened.
    let latest = state
        .store
        .universal_conference_profile(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::CONFLICT)?;
    if latest != room {
        return Err(StatusCode::CONFLICT);
    }
    Ok(json!({
        "roomId": input.room_id,
        "groupId": input.room_id,
        "recipientDeviceId": input.recipient_device_id,
        "cryptoEpoch": input.crypto_epoch,
        "commitAccepted": matches!(status, ucr_core::DurableRecordStatus::Persisted | ucr_core::DurableRecordStatus::Duplicate),
        "mediaReady": false
    }))
}

// Return an encrypted endpoint-owned Welcome only to its original, currently
// trusted receiving Device. A copied room invite or Join URL never authorizes
// recovery of someone else's MLS Group state.
fn room_endpoint_bootstrap(
    state: &State,
    auth: &Session,
    input: &RoomRef,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let room = state
        .store
        .universal_conference_profile(&auth.subject.scope, &room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let participant = state
        .store
        .universal_conference_participant(&auth.subject.scope, &room_id, &auth.subject.principal)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if room.integration_id != integration()?
        || !room.entry_open
        || !matches!(
            room.lifecycle,
            UniversalConferenceLifecycle::Waiting | UniversalConferenceLifecycle::Live
        )
        || !participant.active
        || participant.role != ConferenceParticipantRole::Attendee
    {
        return Err(StatusCode::FORBIDDEN);
    }
    if ucr_group_mls::GroupMlsServerCustodyProbe::server_possesses_mls_group(
        state.store.as_ref(),
        &auth.subject.scope,
        &room_id,
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::CONFLICT);
    }
    let bootstrap = state
        .store
        .mls_bootstrap_for_device(&auth.subject.scope, &room_id, &device(&auth.binding)?)
        .map_err(|_| StatusCode::CONFLICT)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(json!({
        "roomId": input.room_id,
        "deviceId": auth.binding.device,
        "admissionEventId": bootstrap.admission_event_id.as_opaque().as_str(),
        "welcomeBase64Url": URL_SAFE_NO_PAD.encode(bootstrap.welcome),
        "welcomeEpoch": bootstrap.welcome_crypto_state.epoch,
        "welcomeStateRef": bootstrap.welcome_crypto_state.state_ref.as_ref()
            .ok_or(StatusCode::CONFLICT)?.as_str(),
        "commits": bootstrap.subsequent_commits.iter().map(|item| json!({
            "commitBase64Url":URL_SAFE_NO_PAD.encode(&item.commit),
            "cryptoEpoch":item.next_crypto_state.epoch,
            "cryptoStateRef":item.next_crypto_state.state_ref.as_ref().map(OpaqueId::as_str),
        })).collect::<Vec<_>>(),
        "cryptoEpoch":bootstrap.current_crypto_state.epoch,
        "cryptoStateRef":bootstrap.current_crypto_state.state_ref.as_ref()
            .ok_or(StatusCode::CONFLICT)?.as_str(),
        "mediaReady": false
    }))
}

// A Room's Call is the canonical Group Call, never a second room-specific
// call table. Every participant must be an active, authenticated Person already
// enrolled in the same tenant/namespace and conference.
fn room_call(
    state: &State,
    auth: &Session,
    room_id: &GroupId,
) -> Result<Option<CallSession>, StatusCode> {
    let room = state
        .store
        .universal_conference_profile(&auth.subject.scope, room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let attendee = state
        .store
        .universal_conference_participant(
            &auth.subject.scope,
            room_id,
            &auth.subject.principal,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if room.integration_id != integration()? || !attendee.active {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut calls = state
        .store
        .active_calls_for_group(&auth.subject.scope, room_id, 2)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if calls.len() > 1 {
        return Err(StatusCode::CONFLICT);
    }
    let call = calls.pop();
    if let Some(current) = &call {
        if !current.participants.iter().any(|p| {
            p.principal == auth.subject.principal && p.left_revision.is_none()
        }) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(call)
}

fn call_status(state: &State, auth: &Session, input: &RoomRef) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let call = room_call(state, auth, &room_id)?;
    Ok(if let Some(call) = call {
        json!({
            "roomId": input.room_id,
            "callId": call.call_id.as_opaque().as_str(),
            "callRevision": call.revision,
            "callState": format!("{:?}", call.signalling_state),
            "participants": call.participants.iter().map(|p| json!({
                "participantId": p.principal.principal_id.as_opaque().as_str(),
                "state": format!("{:?}", p.state),
            })).collect::<Vec<_>>(),
            "mediaReady": false,
        })
    } else {
        json!({"roomId":input.room_id,"callPrepared":false,"mediaReady":false})
    })
}

// Attendee consent is an ordinary CallSignal::Accept on the ONE Group Call.
// It cannot be performed by the owner on behalf of somebody else.
fn accept_room_call(
    state: &State,
    auth: &Session,
    input: &RoomCallAccept,
) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let call = room_call(state, auth, &room_id)?
        .ok_or(StatusCode::CONFLICT)?;
    if call.revision != input.expected_call_revision
        || !call.participants.iter().any(|p| {
            p.principal == auth.subject.principal
                && matches!(
                    p.state,
                    CallParticipantState::Invited | CallParticipantState::Ringing
                )
                && p.left_revision.is_none()
        })
    {
        return Err(StatusCode::CONFLICT);
    }
    let signal = CallSignal {
        event_id: EventId::from_opaque(
            generate_opaque_id().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        scope: auth.subject.scope.clone(),
        call_id: call.call_id.clone(),
        expected_revision: input.expected_call_revision,
        kind: CallSignalKind::Accept,
    };
    state
        .store
        .apply_call_signal(&auth.subject, &signal)
        .map_err(|_| StatusCode::CONFLICT)?;
    let current = state
        .store
        .call(&auth.subject.scope, &call.call_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::CONFLICT)?;
    Ok(json!({
        "roomId":input.room_id,
        "callId":current.call_id.as_opaque().as_str(),
        "callRevision":current.revision,
        "callState":format!("{:?}",current.signalling_state),
        "mediaReady":false
    }))
}

fn issue_room_join(state: &State, auth: &Session, input: &RoomJoin) -> Result<Value, StatusCode> {
    ensure_binding(&input.binding, auth)?;
    let room_id = GroupId::from_opaque(opaque(&input.room_id)?);
    let grant = issue_authenticated_first_party_room_join(
        state.store.as_ref(),
        state.issuer.as_ref(),
        &auth.subject.scope,
        &room_id,
        &auth.subject.principal,
        &device(&auth.binding)?,
        &input.idempotency_key,
        now_unix_ms()?,
    )
    .map_err(|_| StatusCode::CONFLICT)?;
    let fragment = grant
        .join_url
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"))
        .filter(|fragment| fragment.starts_with("#ucr_join="))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(json!({
        "roomId": input.room_id,
        "joinFragment": fragment,
        "expiresAtUnixMs": grant.expires_at_unix_ms,
        // A signed grant is not evidence that browser endpoint MLS joined.
        "mediaReady": false
    }))
}

fn describe_room(profile: &UniversalConferenceProfile, media_ready: bool) -> Value {
    let lifecycle = match profile.lifecycle {
        UniversalConferenceLifecycle::Scheduled => "scheduled",
        UniversalConferenceLifecycle::Waiting => "waiting",
        UniversalConferenceLifecycle::Live => "live",
        UniversalConferenceLifecycle::Ending => "ending",
        UniversalConferenceLifecycle::Ended => "ended",
    };
    json!({
        "roomId": profile.conference_id.as_opaque().as_str(),
        "state": lifecycle,
        "entryOpen": profile.entry_open,
        "mediaReady": media_ready,
        "revision": profile.revision,
    })
}

pub(super) fn dispatch(
    state: &State,
    auth: &Session,
    path: &str,
    body: &[u8],
) -> Result<Value, StatusCode> {
    match path {
        "/v1/first-party/room/create" => {
            let request: CreateRoom = parse(body)?;
            create_room(state, auth, &request)
        }
        "/v1/first-party/room/open" => {
            let request: RoomEntryChange = parse(body)?;
            change_room_entry(state, auth, &request, true)
        }
        "/v1/first-party/room/close" => {
            let request: RoomEntryChange = parse(body)?;
            change_room_entry(state, auth, &request, false)
        }
        "/v1/first-party/room/go-live" => {
            let request: RoomEntryChange = parse(body)?;
            go_live_room(state, auth, &request)
        }
        "/v1/first-party/room/end" => {
            let request: RoomEntryChange = parse(body)?;
            end_unstarted_room(state, auth, &request)
        }
        "/v1/first-party/room/mls-create" => {
            let request: RoomMlsCreate = parse(body)?;
            publish_room_endpoint_group(state, auth, &request)
        }
        "/v1/first-party/room/mls-offer" => {
            let request: RoomMlsOffer = parse(body)?;
            publish_room_mls_offer(state, auth, &request)
        }
        "/v1/first-party/room/mls-offers" => {
            let request: RoomRef = parse(body)?;
            load_room_mls_offers(state, auth, &request)
        }
        "/v1/first-party/room/mls-add-member" => {
            let request: RoomMlsAddMember = parse(body)?;
            commit_room_endpoint_member(state, auth, &request)
        }
        "/v1/first-party/room/mls-bootstrap" => {
            let request: RoomRef = parse(body)?;
            room_endpoint_bootstrap(state, auth, &request)
        }
        "/v1/first-party/room/prepare" => {
            let request: RoomJoin = parse(body)?;
            prepare_room_call(state, auth, &request)
        }
        "/v1/first-party/room/call-status" => {
            let request: RoomRef = parse(body)?;
            call_status(state, auth, &request)
        }
        "/v1/first-party/room/call-accept" => {
            let request: RoomCallAccept = parse(body)?;
            accept_room_call(state, auth, &request)
        }
        "/v1/first-party/room/join" => {
            let request: RoomJoin = parse(body)?;
            issue_room_join(state, auth, &request)
        }
        "/v1/first-party/room/attend" => {
            let request: RoomRef = parse(body)?;
            enroll_attendee(state, auth, &request)
        }
        "/v1/first-party/room/get" => {
            let request: RoomRef = parse(body)?;
            ensure_binding(&request.binding, auth)?;
            let room_id = GroupId::from_opaque(opaque(&request.room_id)?);
            let (profile, _) = owned_room(state, auth, &room_id)?;
            // Control-plane is not a signed Join; no media-ready claim.
            Ok(describe_room(&profile, false))
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_persists_canonical_ended_event_and_frees_room_quota() {
        let temp = std::env::temp_dir().join(format!(
            "ucr-canonical-room-cancel-{}.sqlite",
            generate_opaque_id()
                .expect("unique test identifier")
                .as_str()
        ));
        let store = SqliteLocalStore::open(&temp).expect("test storage");
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(opaque("room-test-tenant").unwrap()),
            namespace_id: None,
        };
        let integration_id = IntegrationId::from_opaque(opaque(INTEGRATION).unwrap());
        let room_id = GroupId::from_opaque(opaque("room-test-owner-cancel").unwrap());
        let person = ucr_model::PrincipalRef {
            principal_id: ucr_model::PrincipalId::from_opaque(
                opaque("room-test-owner-person").unwrap(),
            ),
            kind: PrincipalKind::Person,
        };
        let profile = UniversalConferenceProfile {
            scope: scope.clone(),
            conference_id: room_id.clone(),
            integration_id: integration_id.clone(),
            external_conference_id: b"room-test-owner-cancel".to_vec(),
            create_idempotency_key: "room-test-create-owner-cancel".to_owned(),
            mode: UniversalConferenceMode::Webinar,
            lifecycle: UniversalConferenceLifecycle::Scheduled,
            schedule: ConferenceScheduleMetadata {
                starts_at_unix_ms: 1000,
                planned_end_unix_ms: None,
                join_before_seconds: 900,
                join_after_seconds: 0,
                timezone: Some("UTC".to_owned()),
            },
            metadata: Vec::new(),
            entry_open: false,
            revision: 1,
        };
        let owner = UniversalConferenceParticipantProfile {
            scope: scope.clone(),
            conference_id: room_id.clone(),
            integration_id,
            external_user_id: b"room-test-owner-person".to_vec(),
            participant: person,
            role: ConferenceParticipantRole::Owner,
            audio_muted: false,
            camera_allowed: true,
            publish_audio_allowed: true,
            publish_video_allowed: true,
            screen_share_allowed: true,
            active: true,
            revision: 1,
        };
        assert_eq!(
            store.persist_first_party_room_with_owner(&profile, &owner),
            Ok(DurableRecordStatus::Persisted)
        );
        let command_id =
            ucr_model::CommandId::from_opaque(opaque("room-test-end-command").unwrap());
        let event = canonical_universal_conference_lifecycle_event(
            &profile,
            UniversalConferenceLifecycle::Ended,
            &command_id,
            "room-test-end-once",
            2000,
        )
        .expect("canonical event")
        .expect("ended event");
        assert_eq!(event.event_type, "ucr.conference.ended");
        assert_eq!(event.logical_order, 2);
        let ended = store
            .transition_universal_conference_with_event(
                &scope,
                &room_id,
                profile.revision,
                UniversalConferenceLifecycle::Ended,
                false,
                Some(&event),
            )
            .expect("atomic cancellation and event");
        assert_eq!(ended.lifecycle, UniversalConferenceLifecycle::Ended);
        assert_eq!(ended.revision, 2);
        assert!(!ended.entry_open);
        assert_eq!(
            store.universal_conference_profile(&scope, &room_id),
            Ok(Some(ended))
        );
        drop(store);
        let _ = std::fs::remove_file(&temp);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = temp.as_os_str().to_os_string();
            sidecar.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(sidecar));
        }
    }

    #[test]
    fn owner_role_cannot_be_downgraded_by_room_policy() {
        assert_eq!(INTEGRATION, "ucr-first-party-room");
        assert_ne!(
            ConferenceParticipantRole::Owner,
            ConferenceParticipantRole::Attendee
        );
    }
}

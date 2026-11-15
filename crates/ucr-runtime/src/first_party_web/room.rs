//! Canonical first-party webinar control plane.
//!
//! Room intent and membership live ONLY in UniversalConferenceStore (the same
//! production SQLite as Realtime). The browser cannot choose a principal,
//! Device or signing authority. No media readiness/grant is fabricated here;
//! endpoint MLS and the universal conference runtime still own media admission.

use super::*;
use ucr_api_grpc::{
    canonical_universal_conference_lifecycle_event, issue_authenticated_first_party_room_join,
    reconcile_canonical_conference_permissions,
};
use ucr_core::{DurableRecordStatus, DurableStoreError, UniversalConferenceStore};
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
        "/v1/first-party/room/end" => {
            let request: RoomEntryChange = parse(body)?;
            end_unstarted_room(state, auth, &request)
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

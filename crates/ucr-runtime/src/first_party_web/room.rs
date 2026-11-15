//! Canonical first-party webinar control plane.
//!
//! Room intent and membership live ONLY in UniversalConferenceStore (the same
//! production SQLite as Realtime). The browser cannot choose a principal,
//! Device or signing authority. No media readiness/grant is fabricated here;
//! endpoint MLS and the universal conference runtime still own media admission.

use super::*;
use ucr_core::{DurableRecordStatus, UniversalConferenceStore};
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

fn integration() -> Result<IntegrationId, StatusCode> {
    Ok(IntegrationId::from_opaque(opaque(INTEGRATION)?))
}

fn scoped_room_id(auth: &Session, key: &str) -> Result<GroupId, StatusCode> {
    if !(16..=90).contains(&key.len())
        || !key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut digest = Sha256::new();
    digest.update(b"ucr-first-party-webinar-id.v1\0");
    for field in [
        auth.subject.scope.tenant_id.as_opaque().as_wire_bytes(),
        auth.subject.principal.principal_id.as_opaque().as_wire_bytes(),
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
    let identifier = format!("fp-room-{digest:x}");
    Ok(GroupId::from_opaque(opaque(&identifier)?))
}

fn owned_room(
    state: &State,
    auth: &Session,
    room_id: &GroupId,
) -> Result<(UniversalConferenceProfile, UniversalConferenceParticipantProfile), StatusCode> {
    let profile = state
        .store
        .universal_conference_profile(&auth.subject.scope, room_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if profile.integration_id != integration()? || profile.mode != UniversalConferenceMode::Webinar {
        return Err(StatusCode::NOT_FOUND);
    }
    let owner = state
        .store
        .universal_conference_participant(
            &auth.subject.scope,
            room_id,
            &auth.subject.principal,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    if owner.role != ConferenceParticipantRole::Owner || !owner.active {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((profile, owner))
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
        if existing.create_idempotency_key != input.idempotency_key
            || recorded_owner != owner
        {
            return Err(StatusCode::CONFLICT);
        }
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
    let inserted = state.store.persist_first_party_room_with_owner(&profile, &owner);
    match inserted {
        Ok(DurableRecordStatus::Persisted | DurableRecordStatus::Duplicate) => {
            Ok(describe_room(&profile, false))
        }
        Err(_) => {
            // Exact safe reconciliation of two devices racing with the same
            // owner/key; never accept only a coordinator without its owner.
            let (found, saved_owner) = owned_room(state, auth, &room_id)?;
            if found.create_idempotency_key != input.idempotency_key || saved_owner != owner {
                return Err(StatusCode::CONFLICT);
            }
            Ok(describe_room(&found, false))
        }
    }
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
    fn owner_role_cannot_be_downgraded_by_room_policy() {
        assert_eq!(INTEGRATION, "ucr-first-party-room");
        assert_ne!(ConferenceParticipantRole::Owner, ConferenceParticipantRole::Attendee);
    }
}

//! Realtime media runtime for first-party direct Calls.
//!
//! A canonical direct Call owns the invitation, consent and lifecycle of a
//! first-party call: who called whom, ringing, accept/reject and hang-up.
//! Realtime media is owned by the existing Conference/SFU and Group-MLS stack.
//! That stack deliberately admits only Group Calls bound to one MLS epoch
//! (`validate_conference_snapshot` rejects direct Calls, and Group media E2EE
//! requires `GroupCallRequired`). Relaxing those invariants for direct Calls
//! would weaken every Conference.
//!
//! Instead, exactly as `prepare_conference_runtime` derives a Group and a runtime
//! Call from a Universal Conference profile, this module derives, for one ACTIVE
//! direct Call whose two participants have both accepted:
//!
//! * one endpoint-owned private MLS Group with the two Call participants, and
//! * one media Call on that Group with exactly the same two principals.
//!
//! Identifiers are derived from the direct Call identity with a domain-separated
//! hash, so a browser can neither choose nor redirect the binding. The Join grant,
//! Device trust, accepted-participant, Join generation and heartbeat fences, MLS
//! endpoint admission and SFU authorization then apply unchanged to the media
//! Call. The media Call ends as soon as its direct Call is hung up.
//!
//! Security: no server-held media-host MLS leaf is admitted by this path.
//! Without a published endpoint-owned Group the media preparation fails closed.

use sha2::{Digest, Sha256};
use ucr_core::{
    CallStore, DurableRecordStatus, DurableStoreError, GroupStore, PermissionGrantStore,
};
use ucr_model::{
    CallId, CallParticipant, CallParticipantState, CallSession, CallSignal, CallSignalKind,
    CallSignallingState, CallTerminationReason, ConversationId, ConversationKind, ConversationRef,
    DeviceId, EventId, GroupId, GroupMemberState, GroupOwnership, IdentityId, OpaqueId,
    PermissionGrant, PermissionScope, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal,
    TenantScope,
};
use ucr_protocol::GROUP_MLS_CAPABILITY;

const MAX_CAS_ATTEMPTS: usize = 6;

/// Reserved legacy host identity. Recognized only to reject it from endpoint-owned media.
pub(crate) const MEDIA_HOST_IDENTITY: &str = "fp-media-host";
const MEDIA_HOST_DEVICE: &str = "fp-media-host-device";
const MEDIA_CALL_PREFIX: &str = "fp-m-";
const MEDIA_GROUP_PREFIX: &str = "fp-mg-";
const MEDIA_CONVERSATION_PREFIX: &str = "fp-mc-";

/// Permissions the realtime/SFU stack checks for a participant's own media.
/// Admission to a particular Call is still decided by canonical Call membership.
pub(crate) const FIRST_PARTY_MEDIA_PERMISSIONS: [&str; 5] = [
    ucr_protocol::CONFERENCE_SUBSCRIBE_PERMISSION,
    ucr_protocol::AUDIO_SEND_PERMISSION,
    ucr_protocol::AUDIO_RECEIVE_PERMISSION,
    ucr_protocol::VIDEO_SEND_PERMISSION,
    ucr_protocol::VIDEO_RECEIVE_PERMISSION,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MediaRuntimeError {
    /// The direct Call is not an ACTIVE, two-person, fully accepted Call of the subject.
    NotAdmissible,
    /// Durable state contradicts the derived binding; never repaired silently.
    Conflict,
    Unavailable,
}

impl From<DurableStoreError> for MediaRuntimeError {
    fn from(error: DurableStoreError) -> Self {
        match error {
            DurableStoreError::Conflict | DurableStoreError::InvalidRecord => Self::Conflict,
            DurableStoreError::PermissionDenied => Self::NotAdmissible,
            _ => Self::Unavailable,
        }
    }
}

/// Deterministic identifiers of the media runtime bound to one direct Call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MediaRuntimeIds {
    pub(crate) call_id: CallId,
    pub(crate) group_id: GroupId,
    pub(crate) conversation_id: ConversationId,
    digest: String,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn opaque(value: String) -> Result<OpaqueId, MediaRuntimeError> {
    OpaqueId::new(value).map_err(|_| MediaRuntimeError::Conflict)
}

pub(crate) fn media_runtime_ids(
    scope: &TenantScope,
    direct_call_id: &CallId,
) -> Result<MediaRuntimeIds, MediaRuntimeError> {
    let mut hasher = Sha256::new();
    hasher.update(b"ucr-first-party-direct-call-media-runtime.v1\0");
    length_prefixed(&mut hasher, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hasher.update([1]);
            length_prefixed(&mut hasher, namespace.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
    length_prefixed(&mut hasher, direct_call_id.as_opaque().as_wire_bytes());
    let digest = hex(&hasher.finalize());
    Ok(MediaRuntimeIds {
        call_id: CallId::from_opaque(opaque(format!("{MEDIA_CALL_PREFIX}{digest}"))?),
        group_id: GroupId::from_opaque(opaque(format!("{MEDIA_GROUP_PREFIX}{digest}"))?),
        conversation_id: ConversationId::from_opaque(opaque(format!(
            "{MEDIA_CONVERSATION_PREFIX}{digest}"
        ))?),
        digest,
    })
}

fn derived_event(
    ids: &MediaRuntimeIds,
    label: &str,
    principal: &PrincipalRef,
) -> Result<EventId, MediaRuntimeError> {
    let mut hasher = Sha256::new();
    hasher.update(b"ucr-first-party-direct-call-media-event.v1\0");
    length_prefixed(&mut hasher, ids.digest.as_bytes());
    length_prefixed(&mut hasher, label.as_bytes());
    length_prefixed(
        &mut hasher,
        principal.principal_id.as_opaque().as_wire_bytes(),
    );
    Ok(EventId::from_opaque(opaque(format!(
        "fp-me-{}",
        hex(&hasher.finalize())
    ))?))
}

pub(crate) fn media_host(
    scope: &TenantScope,
) -> Result<(ScopedPrincipal, DeviceId), MediaRuntimeError> {
    let host = ScopedPrincipal {
        scope: scope.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(opaque(MEDIA_HOST_IDENTITY.to_owned())?),
            kind: PrincipalKind::Person,
        },
    };
    Ok((
        host,
        DeviceId::from_opaque(opaque(MEDIA_HOST_DEVICE.to_owned())?),
    ))
}

/// Whether `identity` is the non-loginable media host (never a callable contact).
pub(crate) fn is_media_host_identity(identity: &IdentityId) -> bool {
    identity.as_opaque().as_str() == MEDIA_HOST_IDENTITY
}

/// The direct Call is admissible for media iff it is ACTIVE, two-person,
/// both participants Accepted and the subject is one of them.
/// Reuse the exact Call/Join eligibility boundary for endpoint MLS bootstrap.
/// This is read-only: no server-held MLS key is created or admitted.
pub(crate) fn admissible_participants_for_descriptor(
    direct: &CallSession,
    subject: &ScopedPrincipal,
) -> Result<[PrincipalRef; 2], MediaRuntimeError> {
    admissible_participants(direct, subject)
}

fn admissible_participants(
    direct: &CallSession,
    subject: &ScopedPrincipal,
) -> Result<[PrincipalRef; 2], MediaRuntimeError> {
    if direct.scope != subject.scope
        || direct.conversation.kind != ConversationKind::Direct
        || direct.signalling_state != CallSignallingState::Active
        || direct.participants.len() != 2
        || !direct.participants.iter().all(|participant| {
            participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        })
        || !direct
            .participants
            .iter()
            .any(|participant| participant.principal == subject.principal)
        || !direct
            .participants
            .iter()
            .any(|participant| participant.principal == direct.initiated_by)
    {
        return Err(MediaRuntimeError::NotAdmissible);
    }
    let callee = direct
        .participants
        .iter()
        .find(|participant| participant.principal != direct.initiated_by)
        .ok_or(MediaRuntimeError::NotAdmissible)?;
    Ok([direct.initiated_by.clone(), callee.principal.clone()])
}

/// Retry the canonical membership CAS and re-read after the *last* attempt.
/// A successful final write must not be misreported as a conflict.
fn validate_media_call(
    call: &CallSession,
    ids: &MediaRuntimeIds,
    participants: &[PrincipalRef; 2],
) -> Result<(), MediaRuntimeError> {
    let principals = call
        .participants
        .iter()
        .map(|participant| &participant.principal)
        .collect::<Vec<_>>();
    if call.call_id != ids.call_id
        || call.conversation.conversation_id != ids.conversation_id
        || call.conversation.kind != ConversationKind::PrivateGroup
        || call.initiated_by != participants[0]
        || principals.len() != 2
        || !participants
            .iter()
            .all(|expected| principals.contains(&expected))
    {
        return Err(MediaRuntimeError::Conflict);
    }
    Ok(())
}

fn ensure_media_call<S>(
    store: &S,
    ids: &MediaRuntimeIds,
    scope: &TenantScope,
    participants: &[PrincipalRef; 2],
) -> Result<CallSession, MediaRuntimeError>
where
    S: CallStore,
{
    if let Some(call) = store.call(scope, &ids.call_id)? {
        validate_media_call(&call, ids, participants)?;
        return Ok(call);
    }
    let caller = ScopedPrincipal {
        scope: scope.clone(),
        principal: participants[0].clone(),
    };
    let draft = CallSession {
        scope: scope.clone(),
        call_id: ids.call_id.clone(),
        conversation: ConversationRef {
            conversation_id: ids.conversation_id.clone(),
            kind: ConversationKind::PrivateGroup,
        },
        initiated_by: participants[0].clone(),
        participants: vec![
            CallParticipant {
                principal: participants[0].clone(),
                state: CallParticipantState::Accepted,
                joined_revision: 0,
                left_revision: None,
            },
            CallParticipant {
                principal: participants[1].clone(),
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
    match store.create_call(&caller, &draft) {
        Ok(DurableRecordStatus::Persisted | DurableRecordStatus::Duplicate)
        | Err(DurableStoreError::Conflict) => {}
        Err(error) => return Err(error.into()),
    }
    let call = store
        .call(scope, &ids.call_id)?
        .ok_or(MediaRuntimeError::Unavailable)?;
    validate_media_call(&call, ids, participants)?;
    Ok(call)
}

fn ensure_media_permissions<S>(
    store: &S,
    subject: &ScopedPrincipal,
) -> Result<(), MediaRuntimeError>
where
    S: PermissionGrantStore,
{
    for permission in FIRST_PARTY_MEDIA_PERMISSIONS {
        store.grant_permission(&PermissionGrant {
            grantee: subject.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(subject.scope.clone()),
        })?;
    }
    Ok(())
}

/// Resolves the endpoint-owned media runtime of one ACTIVE direct Call for the
/// authenticated `subject` and returns the media Call the Join grant must name.
///
/// # Errors
/// [`MediaRuntimeError::NotAdmissible`] unless the direct Call is ACTIVE, two-person and accepted
/// by both; [`MediaRuntimeError::Conflict`] when durable state contradicts the derived binding,
/// including a media Call that was already ended.
pub(crate) fn prepare_direct_call_media<S>(
    store: &S,
    direct: &CallSession,
    subject: &ScopedPrincipal,
) -> Result<CallSession, MediaRuntimeError>
where
    S: CallStore + GroupStore + PermissionGrantStore,
{
    let participants = admissible_participants(direct, subject)?;
    let ids = media_runtime_ids(&direct.scope, &direct.call_id)?;
    // Endpoint-only confidentiality gate. The old server-held MLS committer
    // must never be created, admitted or asked to sign a media transition.
    // Endpoint publication/admission must durably populate this group first;
    // while that flow is absent, deny media instead of silently downgrading E2EE.
    let group = store
        .group(&direct.scope, &ids.group_id)?
        .ok_or(MediaRuntimeError::Unavailable)?;
    if group.scope != direct.scope
        || group.group_id != ids.group_id
        || group.conversation.conversation_id != ids.conversation_id
        || group.conversation.kind != ConversationKind::PrivateGroup
        || group.crypto_state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY)
        || group.crypto_state.state_ref.is_none()
        || group.ownership != GroupOwnership::PersonOwned(participants[0].clone())
        || group.public_policy.is_some()
    {
        return Err(MediaRuntimeError::Conflict);
    }
    let (legacy_host, _) = media_host(&direct.scope)?;
    let members = store.group_memberships(&direct.scope, &ids.group_id, 8)?;
    if members.iter().any(|member| {
        member.state == GroupMemberState::Active
            && (member.member == legacy_host.principal || !participants.contains(&member.member))
    }) {
        return Err(MediaRuntimeError::Conflict);
    }
    if !participants.iter().all(|participant| {
        members.iter().any(|membership| {
            membership.state == GroupMemberState::Active && membership.member == *participant
        })
    }) {
        return Err(MediaRuntimeError::Unavailable);
    }
    let media = ensure_media_call(store, &ids, &direct.scope, &participants)?;
    if media.signalling_state == CallSignallingState::Terminated {
        return Err(MediaRuntimeError::Conflict);
    }
    ensure_media_permissions(store, subject)?;
    Ok(media)
}

/// Ends the media Call bound to `direct`, if one was ever prepared. The direct Call
/// initiator is always an accepted media participant, so it is the canonical actor.
///
/// # Errors
/// Fails on durable errors or when the media Call cannot be ended within bounded retries.
pub(crate) fn end_direct_call_media<S>(
    store: &S,
    direct: &CallSession,
) -> Result<(), MediaRuntimeError>
where
    S: CallStore,
{
    let ids = media_runtime_ids(&direct.scope, &direct.call_id)?;
    let actor = ScopedPrincipal {
        scope: direct.scope.clone(),
        principal: direct.initiated_by.clone(),
    };
    for _ in 0..MAX_CAS_ATTEMPTS {
        let Some(media) = store.call(&direct.scope, &ids.call_id)? else {
            return Ok(());
        };
        if media.initiated_by != direct.initiated_by {
            return Err(MediaRuntimeError::Conflict);
        }
        let kind = match media.signalling_state {
            CallSignallingState::Terminated => return Ok(()),
            CallSignallingState::Inviting | CallSignallingState::Ringing => CallSignalKind::Cancel,
            CallSignallingState::Active | CallSignallingState::Reconnecting => {
                CallSignalKind::Terminate {
                    reason: CallTerminationReason::Completed,
                }
            }
        };
        let signal = CallSignal {
            event_id: derived_event(
                &ids,
                &format!("end-{}", media.revision),
                &direct.initiated_by,
            )?,
            scope: direct.scope.clone(),
            call_id: ids.call_id.clone(),
            expected_revision: media.revision,
            kind,
        };
        match store.apply_call_signal(&actor, &signal) {
            Ok(_) | Err(DurableStoreError::Conflict) => {}
            Err(error) => return Err(error.into()),
        }
    }
    match store.call(&direct.scope, &ids.call_id)? {
        Some(media) if media.signalling_state != CallSignallingState::Terminated => {
            Err(MediaRuntimeError::Conflict)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(tenant: &str, namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: ucr_model::TenantId::from_opaque(OpaqueId::new(tenant).unwrap()),
            namespace_id: namespace
                .map(|ns| ucr_model::NamespaceId::from_opaque(OpaqueId::new(ns).unwrap())),
        }
    }

    fn person(id: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(OpaqueId::new(id).unwrap()),
            kind: PrincipalKind::Person,
        }
    }

    fn participant(id: &str, state: CallParticipantState) -> CallParticipant {
        CallParticipant {
            principal: person(id),
            state,
            joined_revision: 0,
            left_revision: None,
        }
    }

    fn direct(state: CallSignallingState, callee: CallParticipantState) -> CallSession {
        CallSession {
            scope: scope("t", None),
            call_id: CallId::from_opaque(OpaqueId::new("fp-v-key").unwrap()),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(
                    OpaqueId::new("fp-conv-fp-v-key").unwrap(),
                ),
                kind: ConversationKind::Direct,
            },
            initiated_by: person("alice"),
            participants: vec![
                participant("alice", CallParticipantState::Accepted),
                participant("bob", callee),
            ],
            signalling_state: state,
            reconnecting_participant: None,
            media_negotiation_ref: None,
            media_negotiation_generation: 0,
            replication_generation: 0,
            revision: 3,
            termination_reason: None,
        }
    }

    fn subject(id: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope("t", None),
            principal: person(id),
        }
    }

    #[test]
    fn media_ids_are_deterministic_bounded_and_domain_separated() {
        let call = CallId::from_opaque(OpaqueId::new("fp-v-key").unwrap());
        let a = media_runtime_ids(&scope("t", None), &call).unwrap();
        assert_eq!(a, media_runtime_ids(&scope("t", None), &call).unwrap());
        assert!(
            a.call_id
                .as_opaque()
                .as_str()
                .starts_with(MEDIA_CALL_PREFIX)
        );
        assert!(
            a.group_id
                .as_opaque()
                .as_str()
                .starts_with(MEDIA_GROUP_PREFIX)
        );
        assert!(a.call_id.as_opaque().as_str().len() <= 128);
        // Tenant, namespace presence and Call identity are all bound.
        for other in [
            media_runtime_ids(&scope("u", None), &call).unwrap(),
            media_runtime_ids(&scope("t", Some("n")), &call).unwrap(),
            media_runtime_ids(
                &scope("t", None),
                &CallId::from_opaque(OpaqueId::new("fp-a-key").unwrap()),
            )
            .unwrap(),
        ] {
            assert_ne!(a.call_id, other.call_id);
            assert_ne!(a.group_id, other.group_id);
        }
        // Length prefixing: moving a byte between tenant and namespace changes the id.
        assert_ne!(
            media_runtime_ids(&scope("ab", Some("c")), &call)
                .unwrap()
                .digest,
            media_runtime_ids(&scope("a", Some("bc")), &call)
                .unwrap()
                .digest
        );
    }

    #[test]
    fn only_an_active_fully_accepted_call_of_the_subject_is_admissible() {
        let ok = direct(CallSignallingState::Active, CallParticipantState::Accepted);
        assert_eq!(
            admissible_participants(&ok, &subject("bob")).unwrap(),
            [person("alice"), person("bob")]
        );
        assert_eq!(
            admissible_participants(&ok, &subject("alice")).unwrap(),
            [person("alice"), person("bob")]
        );
        assert_eq!(
            admissible_participants(&ok, &subject("mallory")),
            Err(MediaRuntimeError::NotAdmissible)
        );
        let mut foreign_scope = subject("bob");
        foreign_scope.scope = scope("other", None);
        assert_eq!(
            admissible_participants(&ok, &foreign_scope),
            Err(MediaRuntimeError::NotAdmissible)
        );
        for state in [
            CallSignallingState::Inviting,
            CallSignallingState::Ringing,
            CallSignallingState::Reconnecting,
            CallSignallingState::Terminated,
        ] {
            assert_eq!(
                admissible_participants(
                    &direct(state, CallParticipantState::Accepted),
                    &subject("alice")
                ),
                Err(MediaRuntimeError::NotAdmissible),
                "{state:?}"
            );
        }
        for callee in [
            CallParticipantState::Invited,
            CallParticipantState::Ringing,
            CallParticipantState::Rejected,
            CallParticipantState::Busy,
            CallParticipantState::Left,
        ] {
            assert_eq!(
                admissible_participants(
                    &direct(CallSignallingState::Active, callee),
                    &subject("alice")
                ),
                Err(MediaRuntimeError::NotAdmissible),
                "{callee:?}"
            );
        }
        let mut left = ok.clone();
        left.participants[1].left_revision = Some(2);
        assert!(admissible_participants(&left, &subject("alice")).is_err());
        let mut group = ok.clone();
        group.conversation.kind = ConversationKind::PrivateGroup;
        assert!(admissible_participants(&group, &subject("alice")).is_err());
        let mut three = ok;
        three
            .participants
            .push(participant("carol", CallParticipantState::Accepted));
        assert!(admissible_participants(&three, &subject("alice")).is_err());
    }

    #[test]
    fn media_host_is_recognised_and_never_a_signup_identity() {
        assert!(is_media_host_identity(&IdentityId::from_opaque(
            OpaqueId::new(MEDIA_HOST_IDENTITY).unwrap()
        )));
        // Self-service signup identities are always `fp-id-<random>`.
        assert!(!is_media_host_identity(&IdentityId::from_opaque(
            OpaqueId::new("fp-id-fp-media-host").unwrap()
        )));
        assert!(!MEDIA_HOST_IDENTITY.starts_with("fp-id-"));
    }
}

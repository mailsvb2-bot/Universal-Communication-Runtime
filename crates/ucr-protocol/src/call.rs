use sha2::{Digest, Sha256};
use ucr_model::{
    CallParticipant, CallParticipantState, CallParticipantUpdateKind, CallReconnectPhase,
    CallSession, CallSignal, CallSignalKind, CallSignallingState, CallTerminationReason,
    ConversationKind, PrincipalKind, PrincipalRef, TenantScope,
};

pub const MAX_CALL_PARTICIPANTS: usize = 64;
pub const CALL_CREATION_FINGERPRINT_V1_DOMAIN: &[u8] = b"UCR-CALL-CREATION-V1\0";
pub const CALL_SIGNAL_FINGERPRINT_V1_DOMAIN: &[u8] = b"UCR-CALL-SIGNAL-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSignallingError {
    InvalidConversationKind,
    InvalidSession,
    InvalidParticipant,
    DuplicateParticipant,
    TooManyParticipants,
    ScopeMismatch,
    CallMismatch,
    RevisionMismatch,
    PermissionDenied,
    InvalidTransition,
    ParticipantNotActive,
    ParticipantAlreadyExists,
    WouldRemoveInitiator,
    Overflow,
}

#[must_use]
pub const fn is_call_conversation_kind(kind: ConversationKind) -> bool {
    matches!(
        kind,
        ConversationKind::Direct | ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    )
}

/// Canonicalizes one transport-independent signalling session.
///
/// # Errors
/// Rejects malformed lifecycle state, duplicate/full participant identities, or media-state claims
/// that cannot be represented by Phase 19 signalling metadata.
pub fn canonical_call_session(session: &CallSession) -> Result<CallSession, CallSignallingError> {
    if !is_call_conversation_kind(session.conversation.kind) {
        return Err(CallSignallingError::InvalidConversationKind);
    }
    if session.participants.len() < 2 {
        return Err(CallSignallingError::InvalidSession);
    }
    if session.participants.len() > MAX_CALL_PARTICIPANTS {
        return Err(CallSignallingError::TooManyParticipants);
    }
    let mut canonical = session.clone();
    canonical.participants.sort_by(compare_participants);
    if canonical
        .participants
        .windows(2)
        .any(|pair| pair[0].principal == pair[1].principal)
    {
        return Err(CallSignallingError::DuplicateParticipant);
    }
    for participant in &canonical.participants {
        validate_participant(participant, canonical.revision)?;
    }
    let initiator = participant(&canonical, &canonical.initiated_by)
        .ok_or(CallSignallingError::InvalidSession)?;
    if initiator.state != CallParticipantState::Accepted || initiator.left_revision.is_some() {
        return Err(CallSignallingError::InvalidSession);
    }
    match (
        canonical.media_negotiation_generation,
        canonical.media_negotiation_ref.is_some(),
    ) {
        (0, false) | (1.., true) => {}
        _ => return Err(CallSignallingError::InvalidSession),
    }
    match canonical.signalling_state {
        CallSignallingState::Reconnecting => {
            let reconnecting = canonical
                .reconnecting_participant
                .as_ref()
                .ok_or(CallSignallingError::InvalidSession)?;
            let value =
                participant(&canonical, reconnecting).ok_or(CallSignallingError::InvalidSession)?;
            if value.state != CallParticipantState::Accepted || value.left_revision.is_some() {
                return Err(CallSignallingError::InvalidSession);
            }
        }
        CallSignallingState::Inviting
        | CallSignallingState::Ringing
        | CallSignallingState::Active
        | CallSignallingState::Terminated
            if canonical.reconnecting_participant.is_some() =>
        {
            return Err(CallSignallingError::InvalidSession);
        }
        _ => {}
    }
    let remote = canonical
        .participants
        .iter()
        .filter(|value| value.principal != canonical.initiated_by)
        .collect::<Vec<_>>();
    let any_accepted = remote
        .iter()
        .any(|value| value.state == CallParticipantState::Accepted);
    let any_ringing = remote
        .iter()
        .any(|value| value.state == CallParticipantState::Ringing);
    let any_pending = remote.iter().any(|value| {
        matches!(
            value.state,
            CallParticipantState::Invited | CallParticipantState::Ringing
        )
    });
    match canonical.signalling_state {
        CallSignallingState::Inviting if any_accepted || any_ringing => {
            return Err(CallSignallingError::InvalidSession);
        }
        CallSignallingState::Inviting if !any_pending => {
            return Err(CallSignallingError::InvalidSession);
        }
        CallSignallingState::Ringing if any_accepted || !any_ringing => {
            return Err(CallSignallingError::InvalidSession);
        }
        CallSignallingState::Active | CallSignallingState::Reconnecting if !any_accepted => {
            return Err(CallSignallingError::InvalidSession);
        }
        CallSignallingState::Terminated if canonical.termination_reason.is_none() => {
            return Err(CallSignallingError::InvalidSession);
        }
        CallSignallingState::Inviting
        | CallSignallingState::Ringing
        | CallSignallingState::Active
        | CallSignallingState::Reconnecting
            if canonical.termination_reason.is_some() =>
        {
            return Err(CallSignallingError::InvalidSession);
        }
        _ => {}
    }
    Ok(canonical)
}

/// Validates the initial call invite. The initiator is already part of the signalling session; all
/// other principals are invited and have not yet asserted ringing/acceptance.
///
/// # Errors
/// Rejects non-zero initial revisions/generations and any pre-claimed remote acceptance.
pub fn canonical_call_creation(
    session: &CallSession,
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
) -> Result<CallSession, CallSignallingError> {
    if actor_scope != &session.scope {
        return Err(CallSignallingError::ScopeMismatch);
    }
    if actor != &session.initiated_by {
        return Err(CallSignallingError::PermissionDenied);
    }
    if session.revision != 0
        || session.replication_generation != 0
        || session.media_negotiation_generation != 0
        || session.media_negotiation_ref.is_some()
        || session.reconnecting_participant.is_some()
        || session.termination_reason.is_some()
        || session.signalling_state != CallSignallingState::Inviting
    {
        return Err(CallSignallingError::InvalidSession);
    }
    let canonical = canonical_call_session(session)?;
    for participant in &canonical.participants {
        let expected = if participant.principal == canonical.initiated_by {
            CallParticipantState::Accepted
        } else {
            CallParticipantState::Invited
        };
        if participant.state != expected
            || participant.joined_revision != 0
            || participant.left_revision.is_some()
        {
            return Err(CallSignallingError::InvalidParticipant);
        }
    }
    Ok(canonical)
}

/// Returns the immutable creation fingerprint for a canonical call. The fingerprint intentionally
/// excludes mutable signalling state and includes only revision-zero participants, so the original
/// `StartCall` remains exactly retryable after later signalling transitions or restart.
///
/// # Errors
/// Rejects malformed current sessions or a stored session whose revision-zero origin cannot be
/// represented as a valid initial call fact.
pub fn call_creation_fingerprint(session: &CallSession) -> Result<[u8; 32], CallSignallingError> {
    let canonical = canonical_call_session(session)?;
    let origin_participants = canonical
        .participants
        .iter()
        .filter(|value| value.joined_revision == 0)
        .collect::<Vec<_>>();
    if origin_participants.len() < 2
        || !origin_participants
            .iter()
            .any(|value| value.principal == canonical.initiated_by)
    {
        return Err(CallSignallingError::InvalidSession);
    }
    let mut bytes = Vec::new();
    push_scope(&mut bytes, &canonical.scope);
    push_bytes(&mut bytes, canonical.call_id.as_opaque().as_wire_bytes());
    push_bytes(
        &mut bytes,
        canonical
            .conversation
            .conversation_id
            .as_opaque()
            .as_wire_bytes(),
    );
    bytes.push(conversation_kind_code(canonical.conversation.kind));
    push_principal(&mut bytes, &canonical.initiated_by);
    let participant_count =
        u32::try_from(origin_participants.len()).map_err(|_| CallSignallingError::Overflow)?;
    bytes.extend_from_slice(&participant_count.to_be_bytes());
    for value in origin_participants {
        push_principal(&mut bytes, &value.principal);
    }
    let mut hasher = Sha256::new();
    hasher.update(CALL_CREATION_FINGERPRINT_V1_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

/// Returns whether an exact `PrincipalRef` currently has signalling authority in the session.
#[must_use]
pub fn active_call_participant(session: &CallSession, actor: &PrincipalRef) -> bool {
    participant(session, actor).is_some_and(|value| {
        matches!(
            value.state,
            CallParticipantState::Invited
                | CallParticipantState::Ringing
                | CallParticipantState::Accepted
        ) && value.left_revision.is_none()
    })
}

/// Applies one optimistic, actor-bound, idempotency-ready signalling transition.
///
/// # Errors
/// Rejects stale revisions, cross-scope actors, invalid participant authority, or lifecycle changes
/// that contradict the canonical call state machine.
pub fn apply_call_signal(
    current: &CallSession,
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
    signal: &CallSignal,
) -> Result<CallSession, CallSignallingError> {
    let mut next = canonical_call_session(current)?;
    if actor_scope != &next.scope || signal.scope != next.scope {
        return Err(CallSignallingError::ScopeMismatch);
    }
    if signal.call_id != next.call_id {
        return Err(CallSignallingError::CallMismatch);
    }
    if signal.expected_revision != next.revision {
        return Err(CallSignallingError::RevisionMismatch);
    }
    if next.signalling_state == CallSignallingState::Terminated {
        return Err(CallSignallingError::InvalidTransition);
    }
    if !active_call_participant(&next, actor) {
        return Err(CallSignallingError::PermissionDenied);
    }
    let revision = next
        .revision
        .checked_add(1)
        .ok_or(CallSignallingError::Overflow)?;
    let generation = next
        .replication_generation
        .checked_add(1)
        .ok_or(CallSignallingError::Overflow)?;
    match &signal.kind {
        CallSignalKind::Ringing => apply_ringing(&mut next, actor)?,
        CallSignalKind::Accept => apply_accept(&mut next, actor)?,
        CallSignalKind::Reject => apply_decline(
            &mut next,
            actor,
            CallParticipantState::Rejected,
            CallTerminationReason::Rejected,
        )?,
        CallSignalKind::Busy => apply_decline(
            &mut next,
            actor,
            CallParticipantState::Busy,
            CallTerminationReason::Busy,
        )?,
        CallSignalKind::Cancel => {
            apply_pre_accept_termination(&mut next, actor, CallTerminationReason::Cancelled)?;
        }
        CallSignalKind::Timeout => {
            apply_pre_accept_termination(&mut next, actor, CallTerminationReason::TimedOut)?;
        }
        CallSignalKind::Reconnect { phase } => apply_reconnect(&mut next, actor, *phase)?,
        CallSignalKind::ParticipantUpdate { participant, kind } => {
            apply_participant_update(&mut next, actor, participant, *kind, revision)?;
        }
        CallSignalKind::MediaRenegotiation { negotiation_ref } => {
            apply_media_renegotiation(&mut next, actor, negotiation_ref)?;
        }
        CallSignalKind::Terminate { reason } => {
            apply_explicit_termination(&mut next, actor, *reason)?;
        }
    }
    next.revision = revision;
    next.replication_generation = generation;
    canonical_call_session(&next)
}

/// Reconciles a Group-backed call with the canonical active Group membership set.
///
/// Group membership remains the authority owner. This transition only projects membership revocation
/// into signalling state so a removed reconnect owner cannot leave the `CallSession` permanently stuck.
/// The projection advances the Call revision/generation when it changes signalling state.
///
/// # Errors
/// Rejects non-Group calls, malformed current sessions, or revision/generation overflow.
pub fn reconcile_group_call_membership(
    current: &CallSession,
    active_members: &[PrincipalRef],
) -> Result<CallSession, CallSignallingError> {
    let mut next = canonical_call_session(current)?;
    if !matches!(
        next.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return Err(CallSignallingError::InvalidConversationKind);
    }
    if next.signalling_state == CallSignallingState::Terminated {
        return Ok(next);
    }

    let is_current_member =
        |principal: &PrincipalRef| active_members.iter().any(|member| member == principal);
    let initiator_revoked = !is_current_member(&next.initiated_by);
    let has_revoked_active_participant = next.participants.iter().any(|participant| {
        participant.principal != next.initiated_by
            && matches!(
                participant.state,
                CallParticipantState::Invited
                    | CallParticipantState::Ringing
                    | CallParticipantState::Accepted
            )
            && participant.left_revision.is_none()
            && !is_current_member(&participant.principal)
    });
    if !initiator_revoked && !has_revoked_active_participant {
        return Ok(next);
    }

    let revision = next
        .revision
        .checked_add(1)
        .ok_or(CallSignallingError::Overflow)?;
    let generation = next
        .replication_generation
        .checked_add(1)
        .ok_or(CallSignallingError::Overflow)?;

    if initiator_revoked {
        terminate(&mut next, CallTerminationReason::Completed);
    } else {
        let reconnect_owner_revoked = next
            .reconnecting_participant
            .as_ref()
            .is_some_and(|owner| !is_current_member(owner));
        for participant in &mut next.participants {
            if participant.principal != next.initiated_by
                && matches!(
                    participant.state,
                    CallParticipantState::Invited
                        | CallParticipantState::Ringing
                        | CallParticipantState::Accepted
                )
                && participant.left_revision.is_none()
                && !is_current_member(&participant.principal)
            {
                participant.state = CallParticipantState::Left;
                participant.left_revision = Some(revision);
            }
        }
        if reconnect_owner_revoked {
            next.reconnecting_participant = None;
            next.signalling_state = CallSignallingState::Active;
        }
        settle_if_no_viable_remote(&mut next, CallTerminationReason::Completed);
    }
    next.revision = revision;
    next.replication_generation = generation;
    canonical_call_session(&next)
}

/// Stable exact-fact fingerprint used by durable stores for duplicate-or-conflict signalling.
///
/// # Errors
/// Returns only if the signal contains values that cannot be represented by the canonical encoder.
pub fn call_signal_fingerprint(signal: &CallSignal) -> Result<[u8; 32], CallSignallingError> {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, signal.event_id.as_opaque().as_wire_bytes());
    push_scope(&mut bytes, &signal.scope);
    push_bytes(&mut bytes, signal.call_id.as_opaque().as_wire_bytes());
    bytes.extend_from_slice(&signal.expected_revision.to_be_bytes());
    match &signal.kind {
        CallSignalKind::Ringing => bytes.push(1),
        CallSignalKind::Accept => bytes.push(2),
        CallSignalKind::Reject => bytes.push(3),
        CallSignalKind::Busy => bytes.push(4),
        CallSignalKind::Cancel => bytes.push(5),
        CallSignalKind::Timeout => bytes.push(6),
        CallSignalKind::Reconnect { phase } => {
            bytes.push(7);
            bytes.push(match phase {
                CallReconnectPhase::Started => 1,
                CallReconnectPhase::Restored => 2,
            });
        }
        CallSignalKind::ParticipantUpdate { participant, kind } => {
            bytes.push(8);
            push_principal(&mut bytes, participant);
            bytes.push(match kind {
                CallParticipantUpdateKind::Add => 1,
                CallParticipantUpdateKind::Remove => 2,
            });
        }
        CallSignalKind::MediaRenegotiation { negotiation_ref } => {
            bytes.push(9);
            push_bytes(&mut bytes, negotiation_ref.as_wire_bytes());
        }
        CallSignalKind::Terminate { reason } => {
            bytes.push(10);
            bytes.push(termination_reason_code(*reason));
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(CALL_SIGNAL_FINGERPRINT_V1_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

#[must_use]
pub fn call_signal_event_type(signal: &CallSignal) -> &'static str {
    match signal.kind {
        CallSignalKind::Ringing => "ucr.call.ringing",
        CallSignalKind::Accept => "ucr.call.accepted",
        CallSignalKind::Reject => "ucr.call.rejected",
        CallSignalKind::Busy => "ucr.call.busy",
        CallSignalKind::Cancel => "ucr.call.cancelled",
        CallSignalKind::Timeout => "ucr.call.timed_out",
        CallSignalKind::Reconnect {
            phase: CallReconnectPhase::Started,
        } => "ucr.call.reconnect_started",
        CallSignalKind::Reconnect {
            phase: CallReconnectPhase::Restored,
        } => "ucr.call.reconnect_restored",
        CallSignalKind::ParticipantUpdate { .. } => "ucr.call.participant_updated",
        CallSignalKind::MediaRenegotiation { .. } => "ucr.call.media_renegotiation_signalled",
        CallSignalKind::Terminate { .. } => "ucr.call.terminated",
    }
}

fn apply_ringing(
    session: &mut CallSession,
    actor: &PrincipalRef,
) -> Result<(), CallSignallingError> {
    let initiated_by = session.initiated_by.clone();
    let value = participant_mut(session, actor)?;
    if value.principal == initiated_by || value.state != CallParticipantState::Invited {
        return Err(CallSignallingError::InvalidTransition);
    }
    value.state = CallParticipantState::Ringing;
    if !matches!(
        session.signalling_state,
        CallSignallingState::Active | CallSignallingState::Reconnecting
    ) {
        session.signalling_state = CallSignallingState::Ringing;
    }
    Ok(())
}

fn apply_accept(
    session: &mut CallSession,
    actor: &PrincipalRef,
) -> Result<(), CallSignallingError> {
    let initiated_by = session.initiated_by.clone();
    let value = participant_mut(session, actor)?;
    if value.principal == initiated_by
        || !matches!(
            value.state,
            CallParticipantState::Invited | CallParticipantState::Ringing
        )
    {
        return Err(CallSignallingError::InvalidTransition);
    }
    value.state = CallParticipantState::Accepted;
    if session.signalling_state != CallSignallingState::Reconnecting {
        session.signalling_state = CallSignallingState::Active;
    }
    Ok(())
}

fn apply_decline(
    session: &mut CallSession,
    actor: &PrincipalRef,
    participant_state: CallParticipantState,
    termination_reason: CallTerminationReason,
) -> Result<(), CallSignallingError> {
    reject_or_busy(session, actor, participant_state)?;
    settle_if_no_viable_remote(session, termination_reason);
    Ok(())
}

fn apply_pre_accept_termination(
    session: &mut CallSession,
    actor: &PrincipalRef,
    reason: CallTerminationReason,
) -> Result<(), CallSignallingError> {
    require_initiator_without_remote_accept(session, actor)?;
    terminate(session, reason);
    Ok(())
}

fn apply_reconnect(
    session: &mut CallSession,
    actor: &PrincipalRef,
    phase: CallReconnectPhase,
) -> Result<(), CallSignallingError> {
    let value = participant(session, actor).ok_or(CallSignallingError::PermissionDenied)?;
    if value.state != CallParticipantState::Accepted {
        return Err(CallSignallingError::PermissionDenied);
    }
    match (phase, session.signalling_state) {
        (CallReconnectPhase::Started, CallSignallingState::Active) => {
            session.reconnecting_participant = Some(actor.clone());
            session.signalling_state = CallSignallingState::Reconnecting;
        }
        (CallReconnectPhase::Restored, CallSignallingState::Reconnecting) => {
            if session.reconnecting_participant.as_ref() != Some(actor) {
                return Err(CallSignallingError::PermissionDenied);
            }
            session.reconnecting_participant = None;
            session.signalling_state = CallSignallingState::Active;
        }
        _ => return Err(CallSignallingError::InvalidTransition),
    }
    Ok(())
}

fn apply_participant_update(
    session: &mut CallSession,
    actor: &PrincipalRef,
    target: &PrincipalRef,
    kind: CallParticipantUpdateKind,
    revision: u64,
) -> Result<(), CallSignallingError> {
    match kind {
        CallParticipantUpdateKind::Add => add_participant(session, actor, target, revision),
        CallParticipantUpdateKind::Remove => remove_participant(session, actor, target, revision),
    }
}

fn add_participant(
    session: &mut CallSession,
    actor: &PrincipalRef,
    target: &PrincipalRef,
    revision: u64,
) -> Result<(), CallSignallingError> {
    if actor != &session.initiated_by {
        return Err(CallSignallingError::PermissionDenied);
    }
    if session.participants.len() >= MAX_CALL_PARTICIPANTS {
        return Err(CallSignallingError::TooManyParticipants);
    }
    if participant(session, target).is_some() {
        return Err(CallSignallingError::ParticipantAlreadyExists);
    }
    session.participants.push(CallParticipant {
        principal: target.clone(),
        state: CallParticipantState::Invited,
        joined_revision: revision,
        left_revision: None,
    });
    Ok(())
}

fn remove_participant(
    session: &mut CallSession,
    actor: &PrincipalRef,
    target: &PrincipalRef,
    revision: u64,
) -> Result<(), CallSignallingError> {
    if target == &session.initiated_by {
        return Err(CallSignallingError::WouldRemoveInitiator);
    }
    if actor != &session.initiated_by && actor != target {
        return Err(CallSignallingError::PermissionDenied);
    }
    let value = participant_mut(session, target)?;
    if matches!(
        value.state,
        CallParticipantState::Rejected | CallParticipantState::Busy | CallParticipantState::Left
    ) {
        return Err(CallSignallingError::InvalidTransition);
    }
    value.state = CallParticipantState::Left;
    value.left_revision = Some(revision);
    if session.reconnecting_participant.as_ref() == Some(target) {
        session.reconnecting_participant = None;
        session.signalling_state = CallSignallingState::Active;
    }
    settle_if_no_viable_remote(session, CallTerminationReason::Completed);
    Ok(())
}

fn apply_media_renegotiation(
    session: &mut CallSession,
    actor: &PrincipalRef,
    negotiation_ref: &ucr_model::OpaqueId,
) -> Result<(), CallSignallingError> {
    let accepted = participant(session, actor)
        .is_some_and(|value| value.state == CallParticipantState::Accepted);
    if !matches!(
        session.signalling_state,
        CallSignallingState::Active | CallSignallingState::Reconnecting
    ) || !accepted
    {
        return Err(CallSignallingError::PermissionDenied);
    }
    session.media_negotiation_generation = session
        .media_negotiation_generation
        .checked_add(1)
        .ok_or(CallSignallingError::Overflow)?;
    session.media_negotiation_ref = Some(negotiation_ref.clone());
    Ok(())
}

fn apply_explicit_termination(
    session: &mut CallSession,
    actor: &PrincipalRef,
    reason: CallTerminationReason,
) -> Result<(), CallSignallingError> {
    if !matches!(
        reason,
        CallTerminationReason::Completed | CallTerminationReason::Failed
    ) {
        return Err(CallSignallingError::InvalidTransition);
    }
    let value = participant(session, actor).ok_or(CallSignallingError::PermissionDenied)?;
    if actor != &session.initiated_by
        && (value.state != CallParticipantState::Accepted
            || matches!(
                session.conversation.kind,
                ConversationKind::PrivateGroup | ConversationKind::PublicGroup
            ))
    {
        return Err(CallSignallingError::PermissionDenied);
    }
    terminate(session, reason);
    Ok(())
}

fn validate_participant(
    participant: &CallParticipant,
    session_revision: u64,
) -> Result<(), CallSignallingError> {
    if participant.joined_revision > session_revision {
        return Err(CallSignallingError::InvalidParticipant);
    }
    match participant.state {
        CallParticipantState::Left => {
            let left = participant
                .left_revision
                .ok_or(CallSignallingError::InvalidParticipant)?;
            if left < participant.joined_revision || left > session_revision {
                return Err(CallSignallingError::InvalidParticipant);
            }
        }
        CallParticipantState::Invited
        | CallParticipantState::Ringing
        | CallParticipantState::Accepted
        | CallParticipantState::Rejected
        | CallParticipantState::Busy
            if participant.left_revision.is_some() =>
        {
            return Err(CallSignallingError::InvalidParticipant);
        }
        _ => {}
    }
    Ok(())
}

fn compare_participants(left: &CallParticipant, right: &CallParticipant) -> core::cmp::Ordering {
    left.principal
        .principal_id
        .cmp(&right.principal.principal_id)
        .then_with(|| {
            principal_kind_code(left.principal.kind).cmp(&principal_kind_code(right.principal.kind))
        })
}

fn participant<'a>(
    session: &'a CallSession,
    principal: &PrincipalRef,
) -> Option<&'a CallParticipant> {
    session
        .participants
        .iter()
        .find(|value| value.principal == *principal)
}

fn participant_mut<'a>(
    session: &'a mut CallSession,
    principal: &PrincipalRef,
) -> Result<&'a mut CallParticipant, CallSignallingError> {
    session
        .participants
        .iter_mut()
        .find(|value| value.principal == *principal)
        .ok_or(CallSignallingError::ParticipantNotActive)
}

fn reject_or_busy(
    session: &mut CallSession,
    actor: &PrincipalRef,
    state: CallParticipantState,
) -> Result<(), CallSignallingError> {
    let initiated_by = session.initiated_by.clone();
    let value = participant_mut(session, actor)?;
    if value.principal == initiated_by
        || !matches!(
            value.state,
            CallParticipantState::Invited | CallParticipantState::Ringing
        )
    {
        return Err(CallSignallingError::InvalidTransition);
    }
    value.state = state;
    Ok(())
}

fn settle_if_no_viable_remote(session: &mut CallSession, reason: CallTerminationReason) {
    let viable = session.participants.iter().any(|value| {
        value.principal != session.initiated_by
            && matches!(
                value.state,
                CallParticipantState::Invited
                    | CallParticipantState::Ringing
                    | CallParticipantState::Accepted
            )
    });
    if !viable {
        terminate(session, reason);
    } else if session.participants.iter().any(|value| {
        value.principal != session.initiated_by && value.state == CallParticipantState::Accepted
    }) {
        if session.signalling_state != CallSignallingState::Reconnecting {
            session.signalling_state = CallSignallingState::Active;
        }
    } else if session
        .participants
        .iter()
        .any(|value| value.state == CallParticipantState::Ringing)
    {
        session.reconnecting_participant = None;
        session.signalling_state = CallSignallingState::Ringing;
    } else {
        session.reconnecting_participant = None;
        session.signalling_state = CallSignallingState::Inviting;
    }
}

fn require_initiator_without_remote_accept(
    session: &CallSession,
    actor: &PrincipalRef,
) -> Result<(), CallSignallingError> {
    if actor != &session.initiated_by
        || session.participants.iter().any(|value| {
            value.principal != session.initiated_by && value.state == CallParticipantState::Accepted
        })
    {
        return Err(CallSignallingError::PermissionDenied);
    }
    Ok(())
}

fn terminate(session: &mut CallSession, reason: CallTerminationReason) {
    session.reconnecting_participant = None;
    session.signalling_state = CallSignallingState::Terminated;
    session.termination_reason = Some(reason);
}

fn push_scope(bytes: &mut Vec<u8>, scope: &TenantScope) {
    push_bytes(bytes, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            bytes.push(1);
            push_bytes(bytes, namespace.as_opaque().as_wire_bytes());
        }
        None => bytes.push(0),
    }
}

fn push_principal(bytes: &mut Vec<u8>, principal: &PrincipalRef) {
    bytes.push(principal_kind_code(principal.kind));
    push_bytes(bytes, principal.principal_id.as_opaque().as_wire_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("canonical opaque/string budget fits u32");
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
}

const fn conversation_kind_code(kind: ConversationKind) -> u8 {
    match kind {
        ConversationKind::Direct => 1,
        ConversationKind::PrivateGroup => 2,
        ConversationKind::PublicGroup => 3,
        ConversationKind::Broadcast => 4,
        ConversationKind::Community => 5,
        ConversationKind::Room => 6,
        ConversationKind::Topic => 7,
        ConversationKind::Thread => 8,
        ConversationKind::System => 9,
    }
}

const fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Person => 1,
        PrincipalKind::Device => 2,
        PrincipalKind::ServiceAccount => 3,
        PrincipalKind::AiAgent => 4,
        PrincipalKind::Bot => 5,
        PrincipalKind::Organization => 6,
        PrincipalKind::Automation => 7,
        PrincipalKind::ExternalPlatform => 8,
    }
}

const fn termination_reason_code(reason: CallTerminationReason) -> u8 {
    match reason {
        CallTerminationReason::Rejected => 1,
        CallTerminationReason::Busy => 2,
        CallTerminationReason::Cancelled => 3,
        CallTerminationReason::TimedOut => 4,
        CallTerminationReason::Completed => 5,
        CallTerminationReason::Failed => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{CallId, ConversationId, ConversationRef, OpaqueId, PrincipalId, TenantId};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).unwrap()
    }

    fn principal(value: &str, kind: PrincipalKind) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind,
        }
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant")),
            namespace_id: None,
        }
    }

    fn session() -> CallSession {
        let initiator = principal("alice", PrincipalKind::Person);
        CallSession {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call")),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation")),
                kind: ConversationKind::Direct,
            },
            initiated_by: initiator.clone(),
            participants: vec![
                CallParticipant {
                    principal: initiator,
                    state: CallParticipantState::Accepted,
                    joined_revision: 0,
                    left_revision: None,
                },
                CallParticipant {
                    principal: principal("bob", PrincipalKind::Person),
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
        }
    }

    fn signal(session: &CallSession, event: &str, kind: CallSignalKind) -> CallSignal {
        CallSignal {
            event_id: ucr_model::EventId::from_opaque(oid(event)),
            scope: session.scope.clone(),
            call_id: session.call_id.clone(),
            expected_revision: session.revision,
            kind,
        }
    }

    #[test]
    fn invite_ringing_accept_reconnect_and_opaque_renegotiation_are_canonical() {
        let initial = session();
        let alice = initial.initiated_by.clone();
        let bob = principal("bob", PrincipalKind::Person);
        let initial = canonical_call_creation(&initial, &scope(), &alice).unwrap();
        let ringing = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "ring", CallSignalKind::Ringing),
        )
        .unwrap();
        assert_eq!(ringing.signalling_state, CallSignallingState::Ringing);
        let active = apply_call_signal(
            &ringing,
            &scope(),
            &bob,
            &signal(&ringing, "accept", CallSignalKind::Accept),
        )
        .unwrap();
        assert_eq!(active.signalling_state, CallSignallingState::Active);
        let reconnecting = apply_call_signal(
            &active,
            &scope(),
            &alice,
            &signal(
                &active,
                "reconnect",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        assert_eq!(
            reconnecting.signalling_state,
            CallSignallingState::Reconnecting
        );
        let restored = apply_call_signal(
            &reconnecting,
            &scope(),
            &alice,
            &signal(
                &reconnecting,
                "restored",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Restored,
                },
            ),
        )
        .unwrap();
        let renegotiated = apply_call_signal(
            &restored,
            &scope(),
            &bob,
            &signal(
                &restored,
                "renegotiate",
                CallSignalKind::MediaRenegotiation {
                    negotiation_ref: oid("opaque-negotiation"),
                },
            ),
        )
        .unwrap();
        assert_eq!(renegotiated.media_negotiation_generation, 1);
        assert_eq!(
            renegotiated.media_negotiation_ref,
            Some(oid("opaque-negotiation"))
        );
    }

    #[test]
    fn unrelated_participant_progress_does_not_clear_reconnecting() {
        let mut initial = session();
        for name in ["charlie", "dave"] {
            initial.participants.push(CallParticipant {
                principal: principal(name, PrincipalKind::Person),
                state: CallParticipantState::Invited,
                joined_revision: 0,
                left_revision: None,
            });
        }
        let alice = initial.initiated_by.clone();
        let bob = principal("bob", PrincipalKind::Person);
        let charlie = principal("charlie", PrincipalKind::Person);
        let dave = principal("dave", PrincipalKind::Person);
        let active = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "accept-bob", CallSignalKind::Accept),
        )
        .unwrap();
        let reconnecting = apply_call_signal(
            &active,
            &scope(),
            &alice,
            &signal(
                &active,
                "reconnect-alice",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        assert_eq!(reconnecting.reconnecting_participant, Some(alice.clone()));
        let wrong_restore = signal(
            &reconnecting,
            "restore-by-bob",
            CallSignalKind::Reconnect {
                phase: CallReconnectPhase::Restored,
            },
        );
        assert_eq!(
            apply_call_signal(&reconnecting, &scope(), &bob, &wrong_restore),
            Err(CallSignallingError::PermissionDenied)
        );
        let rejected = apply_call_signal(
            &reconnecting,
            &scope(),
            &dave,
            &signal(&reconnecting, "reject-dave", CallSignalKind::Reject),
        )
        .unwrap();
        assert_eq!(rejected.signalling_state, CallSignallingState::Reconnecting);
        let accepted = apply_call_signal(
            &rejected,
            &scope(),
            &charlie,
            &signal(&rejected, "accept-charlie", CallSignalKind::Accept),
        )
        .unwrap();
        assert_eq!(accepted.signalling_state, CallSignallingState::Reconnecting);
        let restored = apply_call_signal(
            &accepted,
            &scope(),
            &alice,
            &signal(
                &accepted,
                "restore-alice",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Restored,
                },
            ),
        )
        .unwrap();
        assert_eq!(restored.signalling_state, CallSignallingState::Active);
        assert_eq!(restored.reconnecting_participant, None);
    }

    #[test]
    fn removing_reconnect_owner_exits_reconnecting_before_settle() {
        let mut initial = session();
        initial.conversation.kind = ConversationKind::PrivateGroup;
        let alice = initial.initiated_by.clone();
        let bob = principal("bob", PrincipalKind::Person);
        let charlie = principal("charlie", PrincipalKind::Person);
        initial.participants.push(CallParticipant {
            principal: charlie.clone(),
            state: CallParticipantState::Invited,
            joined_revision: 0,
            left_revision: None,
        });

        let bob_active = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "accept-bob-owner", CallSignalKind::Accept),
        )
        .unwrap();
        let active = apply_call_signal(
            &bob_active,
            &scope(),
            &charlie,
            &signal(&bob_active, "accept-charlie-peer", CallSignalKind::Accept),
        )
        .unwrap();
        let reconnecting = apply_call_signal(
            &active,
            &scope(),
            &bob,
            &signal(
                &active,
                "reconnect-bob-owner",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        assert_eq!(
            reconnecting.signalling_state,
            CallSignallingState::Reconnecting
        );
        assert_eq!(reconnecting.reconnecting_participant, Some(bob.clone()));

        let self_left = apply_call_signal(
            &reconnecting,
            &scope(),
            &bob,
            &signal(
                &reconnecting,
                "bob-leaves-reconnect",
                CallSignalKind::ParticipantUpdate {
                    participant: bob.clone(),
                    kind: CallParticipantUpdateKind::Remove,
                },
            ),
        )
        .unwrap();
        assert_eq!(self_left.signalling_state, CallSignallingState::Active);
        assert_eq!(self_left.reconnecting_participant, None);
        assert_eq!(
            participant(&self_left, &charlie).unwrap().state,
            CallParticipantState::Accepted
        );

        let reconnecting_again = apply_call_signal(
            &active,
            &scope(),
            &bob,
            &signal(
                &active,
                "reconnect-bob-removed",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        let removed = apply_call_signal(
            &reconnecting_again,
            &scope(),
            &alice,
            &signal(
                &reconnecting_again,
                "alice-removes-reconnect-owner",
                CallSignalKind::ParticipantUpdate {
                    participant: bob.clone(),
                    kind: CallParticipantUpdateKind::Remove,
                },
            ),
        )
        .unwrap();
        assert_eq!(removed.signalling_state, CallSignallingState::Active);
        assert_eq!(removed.reconnecting_participant, None);
        assert_eq!(
            participant(&removed, &charlie).unwrap().state,
            CallParticipantState::Accepted
        );
    }

    #[test]
    fn canonical_group_membership_revocation_reconciles_reconnect_owner() {
        let mut initial = session();
        initial.conversation.kind = ConversationKind::PrivateGroup;
        let alice = initial.initiated_by.clone();
        let bob = principal("bob", PrincipalKind::Person);
        let charlie = principal("charlie", PrincipalKind::Person);
        initial.participants.push(CallParticipant {
            principal: charlie.clone(),
            state: CallParticipantState::Invited,
            joined_revision: 0,
            left_revision: None,
        });

        let active = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "membership-bob-accept", CallSignalKind::Accept),
        )
        .unwrap();
        let active = apply_call_signal(
            &active,
            &scope(),
            &charlie,
            &signal(&active, "membership-charlie-accept", CallSignalKind::Accept),
        )
        .unwrap();
        let bob_reconnecting = apply_call_signal(
            &active,
            &scope(),
            &bob,
            &signal(
                &active,
                "membership-bob-reconnect",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        let reconciled =
            reconcile_group_call_membership(&bob_reconnecting, &[alice.clone(), charlie.clone()])
                .unwrap();
        assert_eq!(reconciled.signalling_state, CallSignallingState::Active);
        assert_eq!(reconciled.reconnecting_participant, None);
        assert_eq!(
            participant(&reconciled, &bob).unwrap().state,
            CallParticipantState::Left
        );
        assert_eq!(
            participant(&reconciled, &charlie).unwrap().state,
            CallParticipantState::Accepted
        );
        assert_eq!(reconciled.revision, bob_reconnecting.revision + 1);

        let alice_reconnecting = apply_call_signal(
            &active,
            &scope(),
            &alice,
            &signal(
                &active,
                "membership-alice-reconnect",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        let ended =
            reconcile_group_call_membership(&alice_reconnecting, &[bob.clone(), charlie.clone()])
                .unwrap();
        assert_eq!(ended.signalling_state, CallSignallingState::Terminated);
        assert_eq!(ended.reconnecting_participant, None);
        assert_eq!(
            ended.termination_reason,
            Some(CallTerminationReason::Completed)
        );
        assert_eq!(ended.revision, alice_reconnecting.revision + 1);
    }

    #[test]
    fn reconnect_exits_when_last_accepted_remote_is_removed_but_owner_remains() {
        let mut initial = session();
        initial.conversation.kind = ConversationKind::PrivateGroup;
        let alice = initial.initiated_by.clone();
        let bob = principal("bob", PrincipalKind::Person);
        let charlie = principal("charlie", PrincipalKind::Person);
        initial.participants.push(CallParticipant {
            principal: charlie.clone(),
            state: CallParticipantState::Invited,
            joined_revision: 0,
            left_revision: None,
        });
        let active = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "last-accepted-bob", CallSignalKind::Accept),
        )
        .unwrap();
        let reconnecting = apply_call_signal(
            &active,
            &scope(),
            &alice,
            &signal(
                &active,
                "last-accepted-owner-reconnect",
                CallSignalKind::Reconnect {
                    phase: CallReconnectPhase::Started,
                },
            ),
        )
        .unwrap();
        let reconciled =
            reconcile_group_call_membership(&reconnecting, &[alice.clone(), charlie]).unwrap();
        assert_eq!(reconciled.signalling_state, CallSignallingState::Inviting);
        assert_eq!(reconciled.reconnecting_participant, None);
        assert_eq!(
            participant(&reconciled, &bob).unwrap().state,
            CallParticipantState::Left
        );
    }

    #[test]
    fn group_participant_cannot_terminate_everyone_but_can_leave_self() {
        let mut initial = session();
        initial.conversation.kind = ConversationKind::PrivateGroup;
        let bob = principal("bob", PrincipalKind::Person);
        let active = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "group-accept", CallSignalKind::Accept),
        )
        .unwrap();
        let terminate = signal(
            &active,
            "group-terminate-by-member",
            CallSignalKind::Terminate {
                reason: CallTerminationReason::Completed,
            },
        );
        assert_eq!(
            apply_call_signal(&active, &scope(), &bob, &terminate),
            Err(CallSignallingError::PermissionDenied)
        );
        let leave = signal(
            &active,
            "group-leave-self",
            CallSignalKind::ParticipantUpdate {
                participant: bob.clone(),
                kind: CallParticipantUpdateKind::Remove,
            },
        );
        let ended = apply_call_signal(&active, &scope(), &bob, &leave).unwrap();
        assert_eq!(ended.signalling_state, CallSignallingState::Terminated);
        assert_eq!(
            ended.termination_reason,
            Some(CallTerminationReason::Completed)
        );
    }

    #[test]
    fn creation_fingerprint_survives_lifecycle_progress_but_not_origin_change() {
        let initial = session();
        let bob = principal("bob", PrincipalKind::Person);
        let initial_fingerprint = call_creation_fingerprint(&initial).unwrap();
        let active = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "accept-origin", CallSignalKind::Accept),
        )
        .unwrap();
        assert_eq!(
            call_creation_fingerprint(&active).unwrap(),
            initial_fingerprint
        );

        let mut conflicting = initial.clone();
        conflicting.participants[1].principal = principal("charlie", PrincipalKind::Person);
        assert_ne!(
            call_creation_fingerprint(&conflicting).unwrap(),
            initial_fingerprint
        );
    }

    #[test]
    fn stale_revision_and_foreign_actor_fail_closed() {
        let initial = session();
        let bob = principal("bob", PrincipalKind::Person);
        let mallory = principal("mallory", PrincipalKind::Person);
        let mut stale = signal(&initial, "stale", CallSignalKind::Ringing);
        stale.expected_revision = 8;
        assert_eq!(
            apply_call_signal(&initial, &scope(), &bob, &stale),
            Err(CallSignallingError::RevisionMismatch)
        );
        assert_eq!(
            apply_call_signal(
                &initial,
                &scope(),
                &mallory,
                &signal(&initial, "foreign", CallSignalKind::Ringing)
            ),
            Err(CallSignallingError::PermissionDenied)
        );
    }

    #[test]
    fn full_principal_ref_identity_is_not_aliased_by_opaque_id() {
        let initial = session();
        let alias = principal("bob", PrincipalKind::Organization);
        assert!(!active_call_participant(&initial, &alias));
        assert_eq!(
            apply_call_signal(
                &initial,
                &scope(),
                &alias,
                &signal(&initial, "alias", CallSignalKind::Accept)
            ),
            Err(CallSignallingError::PermissionDenied)
        );
    }

    #[test]
    fn signal_fingerprint_is_exact_and_deterministic() {
        let initial = session();
        let a = signal(&initial, "same", CallSignalKind::Ringing);
        let b = a.clone();
        let mut c = a.clone();
        c.kind = CallSignalKind::Busy;
        assert_eq!(call_signal_fingerprint(&a), call_signal_fingerprint(&b));
        assert_ne!(call_signal_fingerprint(&a), call_signal_fingerprint(&c));
    }

    #[test]
    fn cancel_timeout_and_reject_are_signalling_not_media_evidence() {
        let initial = session();
        let alice = initial.initiated_by.clone();
        let bob = principal("bob", PrincipalKind::Person);
        let cancelled = apply_call_signal(
            &initial,
            &scope(),
            &alice,
            &signal(&initial, "cancel", CallSignalKind::Cancel),
        )
        .unwrap();
        assert_eq!(cancelled.signalling_state, CallSignallingState::Terminated);
        assert_eq!(
            cancelled.termination_reason,
            Some(CallTerminationReason::Cancelled)
        );

        let rejected = apply_call_signal(
            &initial,
            &scope(),
            &bob,
            &signal(&initial, "reject", CallSignalKind::Reject),
        )
        .unwrap();
        assert_eq!(rejected.signalling_state, CallSignallingState::Terminated);
        assert_eq!(
            rejected.termination_reason,
            Some(CallTerminationReason::Rejected)
        );
    }
}

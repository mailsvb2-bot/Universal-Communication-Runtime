use std::collections::HashSet;

use ucr_model::{PrincipalRef, RecordingConsentState, RecordingSession, RecordingState};

pub const MIN_RECORDING_RETENTION_SECONDS: u64 = 60;
pub const MAX_RECORDING_RETENTION_SECONDS: u64 = 31_536_000;
pub const MAX_RECORDING_POLICY_REFERENCE_BYTES: usize = 512;
pub const MAX_RECORDING_CONSENTS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingProtocolError {
    InvalidPolicy,
    InvalidSession,
    InvalidConsent,
    InvalidTransition,
    ConsentRequired,
    Expired,
    Overflow,
}

/// Validates a durable recording lifecycle snapshot without inspecting or owning Call membership.
///
/// # Errors
/// Rejects malformed policy, retention, consent evidence, timestamps, or impossible lifecycle state.
pub fn validate_recording_session(
    session: &RecordingSession,
) -> Result<(), RecordingProtocolError> {
    if session.revision == 0
        || session.requested_at_unix_ms < 0
        || !session.policy.notify_all_participants
        || !(MIN_RECORDING_RETENTION_SECONDS..=MAX_RECORDING_RETENTION_SECONDS)
            .contains(&session.policy.retention_seconds)
        || session
            .policy
            .policy_reference
            .as_ref()
            .is_some_and(|value| {
                value.is_empty() || value.len() > MAX_RECORDING_POLICY_REFERENCE_BYTES
            })
        || session.consents.len() > MAX_RECORDING_CONSENTS
    {
        return Err(RecordingProtocolError::InvalidPolicy);
    }

    let retention_ms = i64::try_from(session.policy.retention_seconds)
        .map_err(|_| RecordingProtocolError::Overflow)?
        .checked_mul(1000)
        .ok_or(RecordingProtocolError::Overflow)?;
    let expected_expiry = session
        .requested_at_unix_ms
        .checked_add(retention_ms)
        .ok_or(RecordingProtocolError::Overflow)?;
    if session.expires_at_unix_ms != expected_expiry {
        return Err(RecordingProtocolError::InvalidSession);
    }

    let mut participants = HashSet::with_capacity(session.consents.len());
    for consent in &session.consents {
        if !participants.insert(consent.participant.clone()) {
            return Err(RecordingProtocolError::InvalidConsent);
        }
        match consent.state {
            RecordingConsentState::Pending if consent.decided_at_unix_ms == 0 => {}
            RecordingConsentState::Granted
            | RecordingConsentState::Denied
            | RecordingConsentState::Revoked
                if consent.decided_at_unix_ms >= session.requested_at_unix_ms
                    && consent.decided_at_unix_ms < session.expires_at_unix_ms => {}
            _ => return Err(RecordingProtocolError::InvalidConsent),
        }
    }

    let all_required_consents_granted = !session.policy.require_all_participant_consent
        || session
            .consents
            .iter()
            .all(|consent| consent.state == RecordingConsentState::Granted);
    match session.state {
        RecordingState::WaitingForConsent => {
            if !session.policy.require_all_participant_consent || all_required_consents_granted {
                return Err(RecordingProtocolError::InvalidSession);
            }
            if session.started_at_unix_ms.is_some() || session.stopped_at_unix_ms.is_some() {
                return Err(RecordingProtocolError::InvalidSession);
            }
        }
        RecordingState::Ready => {
            if !all_required_consents_granted
                || session.started_at_unix_ms.is_some()
                || session.stopped_at_unix_ms.is_some()
            {
                return Err(RecordingProtocolError::InvalidSession);
            }
        }
        RecordingState::Active => {
            if !all_required_consents_granted
                || session.started_at_unix_ms.is_none()
                || session.stopped_at_unix_ms.is_some()
            {
                return Err(RecordingProtocolError::InvalidSession);
            }
        }
        RecordingState::Stopped => {
            if session.stopped_at_unix_ms.is_none() {
                return Err(RecordingProtocolError::InvalidSession);
            }
        }
        RecordingState::Expired | RecordingState::Deleted => {}
    }
    Ok(())
}

/// Applies one participant-authenticated consent decision.
///
/// # Errors
/// Rejects unknown participants, pending pseudo-decisions, expired/final sessions, or invalid time.
pub fn apply_recording_consent(
    current: &RecordingSession,
    participant: &PrincipalRef,
    state: RecordingConsentState,
    now_unix_ms: i64,
) -> Result<RecordingSession, RecordingProtocolError> {
    validate_recording_session(current)?;
    if state == RecordingConsentState::Pending
        || now_unix_ms < current.requested_at_unix_ms
        || now_unix_ms >= current.expires_at_unix_ms
    {
        return Err(RecordingProtocolError::InvalidConsent);
    }
    if matches!(
        current.state,
        RecordingState::Stopped | RecordingState::Expired | RecordingState::Deleted
    ) {
        return Err(RecordingProtocolError::InvalidTransition);
    }

    let mut next = current.clone();
    let consent = next
        .consents
        .iter_mut()
        .find(|consent| consent.participant == *participant)
        .ok_or(RecordingProtocolError::InvalidConsent)?;
    consent.state = state;
    consent.decided_at_unix_ms = now_unix_ms;

    if next.state == RecordingState::Active && state != RecordingConsentState::Granted {
        next.state = RecordingState::Stopped;
        next.stopped_at_unix_ms = Some(now_unix_ms);
    } else if next.state != RecordingState::Active {
        let all_granted = next
            .consents
            .iter()
            .all(|consent| consent.state == RecordingConsentState::Granted);
        next.state = if !next.policy.require_all_participant_consent || all_granted {
            RecordingState::Ready
        } else {
            RecordingState::WaitingForConsent
        };
    }
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(RecordingProtocolError::Overflow)?;
    validate_recording_session(&next)?;
    Ok(next)
}

/// Starts capture lifecycle after consent and retention gates have passed.
///
/// # Errors
/// Rejects non-ready, expired, or malformed sessions.
pub fn start_recording(
    current: &RecordingSession,
    now_unix_ms: i64,
) -> Result<RecordingSession, RecordingProtocolError> {
    validate_recording_session(current)?;
    if now_unix_ms < current.requested_at_unix_ms || now_unix_ms >= current.expires_at_unix_ms {
        return Err(RecordingProtocolError::Expired);
    }
    if current.state != RecordingState::Ready {
        return Err(if current.state == RecordingState::WaitingForConsent {
            RecordingProtocolError::ConsentRequired
        } else {
            RecordingProtocolError::InvalidTransition
        });
    }
    let mut next = current.clone();
    next.state = RecordingState::Active;
    next.started_at_unix_ms = Some(now_unix_ms);
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(RecordingProtocolError::Overflow)?;
    validate_recording_session(&next)?;
    Ok(next)
}

/// Stops a waiting, ready, or active recording lifecycle.
///
/// # Errors
/// Rejects already-final/malformed sessions or invalid time.
pub fn stop_recording(
    current: &RecordingSession,
    now_unix_ms: i64,
) -> Result<RecordingSession, RecordingProtocolError> {
    validate_recording_session(current)?;
    if now_unix_ms < current.requested_at_unix_ms || now_unix_ms > current.expires_at_unix_ms {
        return Err(RecordingProtocolError::InvalidTransition);
    }
    if !matches!(
        current.state,
        RecordingState::WaitingForConsent | RecordingState::Ready | RecordingState::Active
    ) {
        return Err(RecordingProtocolError::InvalidTransition);
    }
    let mut next = current.clone();
    next.state = RecordingState::Stopped;
    next.stopped_at_unix_ms = Some(now_unix_ms);
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(RecordingProtocolError::Overflow)?;
    validate_recording_session(&next)?;
    Ok(next)
}

/// Applies finite-retention expiry.
///
/// # Errors
/// Rejects early expiry, deleted/malformed sessions, or revision overflow.
pub fn expire_recording(
    current: &RecordingSession,
    now_unix_ms: i64,
) -> Result<RecordingSession, RecordingProtocolError> {
    validate_recording_session(current)?;
    if now_unix_ms < current.expires_at_unix_ms {
        return Err(RecordingProtocolError::InvalidTransition);
    }
    if current.state == RecordingState::Deleted {
        return Err(RecordingProtocolError::InvalidTransition);
    }
    if current.state == RecordingState::Expired {
        return Ok(current.clone());
    }
    let mut next = current.clone();
    next.state = RecordingState::Expired;
    if current.state == RecordingState::Active && next.stopped_at_unix_ms.is_none() {
        next.stopped_at_unix_ms = Some(current.expires_at_unix_ms);
    }
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(RecordingProtocolError::Overflow)?;
    validate_recording_session(&next)?;
    Ok(next)
}

/// Marks controlled recording state deleted. Physical provider deletion is a separate boundary.
///
/// # Errors
/// Rejects malformed sessions or revision overflow.
pub fn delete_recording(
    current: &RecordingSession,
    now_unix_ms: i64,
) -> Result<RecordingSession, RecordingProtocolError> {
    validate_recording_session(current)?;
    if current.state == RecordingState::Deleted {
        return Ok(current.clone());
    }
    if now_unix_ms < current.requested_at_unix_ms {
        return Err(RecordingProtocolError::InvalidTransition);
    }
    let mut next = current.clone();
    if current.state == RecordingState::Active && next.stopped_at_unix_ms.is_none() {
        next.stopped_at_unix_ms = Some(now_unix_ms.min(current.expires_at_unix_ms));
    }
    next.state = RecordingState::Deleted;
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(RecordingProtocolError::Overflow)?;
    validate_recording_session(&next)?;
    Ok(next)
}

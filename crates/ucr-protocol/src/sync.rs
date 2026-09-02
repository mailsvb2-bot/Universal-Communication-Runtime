use std::collections::HashSet;

use ucr_model::{SyncCheckpoint, SyncMode, SyncSession, SyncState};

pub const MAX_PARTIAL_SYNC_CONVERSATIONS: usize = 256;
pub const MAX_SYNC_RESUME_TOKEN_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    SameEndpoint,
    InvalidInitialState,
    FullSelectionHasConversations,
    PartialSelectionEmpty,
    TooManyConversations,
    DuplicateConversation,
    IllegalTransition,
    CheckpointBindingMismatch,
    CheckpointRequiresActiveSession,
    EmptyResumeToken,
    ResumeTokenTooLarge,
    InvalidCheckpointGeneration,
    AppliedItemsRegression,
}
/// Validates and canonicalizes a sync session before persistence or wire use.
///
/// Partial conversation selection is set-like: order is not semantic, so the
/// canonical representation is sorted. Changing the selection requires a new
/// session rather than mutating an in-flight session.
///
/// # Errors
/// Returns a fail-closed validation error for unsafe or ambiguous sessions.
pub fn canonical_sync_session(mut session: SyncSession) -> Result<SyncSession, SyncError> {
    if session.source_endpoint_id == session.target_endpoint_id {
        return Err(SyncError::SameEndpoint);
    }
    if session.state != SyncState::Prepared {
        return Err(SyncError::InvalidInitialState);
    }
    if session.selection.conversation_ids.len() > MAX_PARTIAL_SYNC_CONVERSATIONS {
        return Err(SyncError::TooManyConversations);
    }

    match session.selection.mode {
        SyncMode::Full if !session.selection.conversation_ids.is_empty() => {
            return Err(SyncError::FullSelectionHasConversations);
        }
        SyncMode::Partial if session.selection.conversation_ids.is_empty() => {
            return Err(SyncError::PartialSelectionEmpty);
        }
        _ => {}
    }
    let mut seen = HashSet::with_capacity(session.selection.conversation_ids.len());
    for conversation_id in &session.selection.conversation_ids {
        if !seen.insert(conversation_id.clone()) {
            return Err(SyncError::DuplicateConversation);
        }
    }
    session.selection.conversation_ids.sort();
    Ok(session)
}

#[must_use]
pub const fn is_terminal_sync_state(state: SyncState) -> bool {
    matches!(
        state,
        SyncState::Completed | SyncState::Cancelled | SyncState::Failed
    )
}

#[must_use]
pub const fn can_transition_sync(from: SyncState, to: SyncState) -> bool {
    matches!(
        (from, to),
        (SyncState::Prepared | SyncState::Paused, SyncState::Active)
            | (
                SyncState::Prepared | SyncState::Active | SyncState::Paused,
                SyncState::Cancelled | SyncState::Failed
            )
            | (SyncState::Active, SyncState::Paused | SyncState::Completed)
            | (SyncState::Paused, SyncState::Completed)
    )
}
/// Validates one sync lifecycle transition.
///
/// `Paused` is the durable delayed-sync state. Terminal sessions are never
/// reopened in place; a new session is required for a later sync operation.
///
/// # Errors
/// Returns [`SyncError::IllegalTransition`] for skips, rewinds, or reopening.
pub const fn validate_sync_transition(from: SyncState, to: SyncState) -> Result<(), SyncError> {
    if can_transition_sync(from, to) {
        Ok(())
    } else {
        Err(SyncError::IllegalTransition)
    }
}

/// Validates a new checkpoint against its session and previous checkpoint.
///
/// Resume tokens are opaque source-issued cursors. They are not a security
/// authority, are not globally comparable, and do not perform anti-entropy.
///
/// # Errors
/// Returns explicit binding, budget, generation, or progress failures.
pub fn validate_sync_checkpoint(
    session: &SyncSession,
    previous: Option<&SyncCheckpoint>,
    checkpoint: &SyncCheckpoint,
) -> Result<(), SyncError> {
    if checkpoint.session_id != session.session_id || checkpoint.scope != session.scope {
        return Err(SyncError::CheckpointBindingMismatch);
    }
    if !matches!(session.state, SyncState::Active | SyncState::Paused) {
        return Err(SyncError::CheckpointRequiresActiveSession);
    }
    if checkpoint.resume_token.is_empty() {
        return Err(SyncError::EmptyResumeToken);
    }
    if checkpoint.resume_token.len() > MAX_SYNC_RESUME_TOKEN_LEN {
        return Err(SyncError::ResumeTokenTooLarge);
    }
    let expected_generation = match previous {
        None => 1,
        Some(previous) => {
            if previous.session_id != session.session_id || previous.scope != session.scope {
                return Err(SyncError::CheckpointBindingMismatch);
            }
            if checkpoint.applied_items < previous.applied_items {
                return Err(SyncError::AppliedItemsRegression);
            }
            previous
                .generation
                .checked_add(1)
                .ok_or(SyncError::InvalidCheckpointGeneration)?
        }
    };
    if checkpoint.generation != expected_generation {
        return Err(SyncError::InvalidCheckpointGeneration);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        ConversationId, EndpointId, OpaqueId, SessionId, SyncCheckpoint, SyncLinkKind, SyncMode,
        SyncSelection, SyncSession, SyncState, TenantId, TenantScope,
    };

    use super::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    fn session(mode: SyncMode, conversations: &[&str]) -> SyncSession {
        SyncSession {
            session_id: SessionId::from_opaque(oid("sync-session-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: None,
            },
            source_endpoint_id: EndpointId::from_opaque(oid("endpoint-local")),
            target_endpoint_id: EndpointId::from_opaque(oid("endpoint-remote")),
            link_kind: SyncLinkKind::DeviceDevice,
            selection: SyncSelection {
                mode,
                conversation_ids: conversations
                    .iter()
                    .map(|value| ConversationId::from_opaque(oid(value)))
                    .collect(),
            },
            state: SyncState::Prepared,
        }
    }

    fn checkpoint(session: &SyncSession, generation: u64, applied_items: u64) -> SyncCheckpoint {
        SyncCheckpoint {
            session_id: session.session_id.clone(),
            scope: session.scope.clone(),
            generation,
            resume_token: format!("resume-{generation}").into_bytes(),
            applied_items,
        }
    }
    #[test]
    fn partial_selection_is_required_bounded_unique_and_canonical() {
        let canonical = canonical_sync_session(session(
            SyncMode::Partial,
            &["conversation-b", "conversation-a"],
        ))
        .expect("valid partial session");
        assert_eq!(
            canonical.selection.conversation_ids[0].as_opaque().as_str(),
            "conversation-a"
        );
        assert_eq!(
            canonical_sync_session(session(SyncMode::Partial, &[])),
            Err(SyncError::PartialSelectionEmpty)
        );
        assert_eq!(
            canonical_sync_session(session(
                SyncMode::Partial,
                &["conversation-a", "conversation-a"]
            )),
            Err(SyncError::DuplicateConversation)
        );
    }

    #[test]
    fn full_sync_cannot_smuggle_partial_selection() {
        assert_eq!(
            canonical_sync_session(session(SyncMode::Full, &["conversation-a"])),
            Err(SyncError::FullSelectionHasConversations)
        );
        assert!(canonical_sync_session(session(SyncMode::Full, &[])).is_ok());
    }
    #[test]
    fn delayed_sync_can_pause_resume_and_terminal_state_cannot_reopen() {
        assert_eq!(
            validate_sync_transition(SyncState::Prepared, SyncState::Active),
            Ok(())
        );
        assert_eq!(
            validate_sync_transition(SyncState::Active, SyncState::Paused),
            Ok(())
        );
        assert_eq!(
            validate_sync_transition(SyncState::Paused, SyncState::Active),
            Ok(())
        );
        assert_eq!(
            validate_sync_transition(SyncState::Completed, SyncState::Active),
            Err(SyncError::IllegalTransition)
        );
    }

    #[test]
    fn checkpoint_progress_is_session_bound_and_monotonic() {
        let mut active = canonical_sync_session(session(SyncMode::Full, &[])).expect("session");
        active.state = SyncState::Active;
        let first = checkpoint(&active, 1, 4);
        assert_eq!(validate_sync_checkpoint(&active, None, &first), Ok(()));
        let second = checkpoint(&active, 2, 9);
        assert_eq!(
            validate_sync_checkpoint(&active, Some(&first), &second),
            Ok(())
        );
        let regressed = checkpoint(&active, 3, 8);
        assert_eq!(
            validate_sync_checkpoint(&active, Some(&second), &regressed),
            Err(SyncError::AppliedItemsRegression)
        );
    }
}

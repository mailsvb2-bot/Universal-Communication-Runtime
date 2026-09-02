use ucr_model::{DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryError {
    InvalidInitialState,
    IllegalTransition,
    ScopeMismatch,
    MessageMismatch,
    DeliveryMismatch,
    EvidenceRegression,
    EvidenceDoesNotProveState,
}

#[must_use]
pub const fn is_terminal_delivery_state(state: DeliveryState) -> bool {
    matches!(
        state,
        DeliveryState::Read | DeliveryState::Failed | DeliveryState::Expired
    )
}

#[must_use]
pub const fn can_transition_delivery(from: DeliveryState, to: DeliveryState) -> bool {
    matches!(
        (from, to),
        (DeliveryState::Persisted, DeliveryState::Encrypted)
            | (DeliveryState::Encrypted, DeliveryState::Queued)
            | (DeliveryState::Queued, DeliveryState::RoutePlanned)
            | (DeliveryState::RoutePlanned, DeliveryState::InFlight)
            | (DeliveryState::InFlight, DeliveryState::Acknowledged)
            | (DeliveryState::Acknowledged, DeliveryState::Delivered)
            | (DeliveryState::Delivered, DeliveryState::Read)
    ) || (!is_terminal_delivery_state(from)
        && matches!(to, DeliveryState::Failed | DeliveryState::Expired))
}

/// Validates the first persisted `DeliveryAttempt`.
///
/// # Errors
/// A `DeliveryAttempt` starts only after Message persistence.
pub fn validate_delivery_attempt(attempt: &DeliveryAttempt) -> Result<(), DeliveryError> {
    if attempt.state != DeliveryState::Persisted {
        return Err(DeliveryError::InvalidInitialState);
    }
    Ok(())
}

/// Validates one monotonic transition for a single `DeliveryAttempt`.
///
/// # Errors
/// Returns [`DeliveryError::IllegalTransition`] for skips, rewinds, or retrying
/// a terminal attempt in-place.
pub fn validate_delivery_transition(
    current: &DeliveryAttempt,
    next: DeliveryState,
) -> Result<(), DeliveryError> {
    if can_transition_delivery(current.state, next) {
        Ok(())
    } else {
        Err(DeliveryError::IllegalTransition)
    }
}

/// Checks that evidence belongs to one exact `DeliveryAttempt` and can support
/// the claimed state without confusing relay/transport ACK with user delivery.
///
/// # Errors
/// Returns a mismatch or proof error when the evidence cannot support `state`.
pub fn validate_delivery_evidence_binding(
    attempt: &DeliveryAttempt,
    evidence: &DeliveryEvidence,
) -> Result<(), DeliveryError> {
    if evidence.delivery_id != attempt.delivery_id {
        return Err(DeliveryError::DeliveryMismatch);
    }
    if evidence.scope != attempt.scope {
        return Err(DeliveryError::ScopeMismatch);
    }
    if evidence.message_id != attempt.message_id {
        return Err(DeliveryError::MessageMismatch);
    }
    Ok(())
}

/// Validates that bound evidence can support the claimed Delivery state.
///
/// # Errors
/// Returns binding mismatch or proof errors when evidence cannot support `state`.
pub fn validate_delivery_evidence(
    attempt: &DeliveryAttempt,
    evidence: &DeliveryEvidence,
    state: DeliveryState,
) -> Result<(), DeliveryError> {
    validate_delivery_evidence_binding(attempt, evidence)?;
    if !evidence_supports_state(evidence.kind, state) {
        return Err(DeliveryError::EvidenceDoesNotProveState);
    }
    Ok(())
}

/// Validates monotonic evidence ordering for one `DeliveryAttempt`.
///
/// Equal order is permitted here so storage can distinguish exact duplicate
/// from conflicting reuse of the same order.
///
/// # Errors
/// Returns [`DeliveryError::EvidenceRegression`] when incoming evidence is older.
pub const fn validate_delivery_evidence_order(
    previous_order: Option<u64>,
    incoming_order: u64,
) -> Result<(), DeliveryError> {
    if let Some(previous) = previous_order
        && incoming_order < previous
    {
        return Err(DeliveryError::EvidenceRegression);
    }
    Ok(())
}

#[must_use]
pub const fn evidence_supports_state(evidence: DeliveryEvidenceKind, state: DeliveryState) -> bool {
    matches!(
        (evidence, state),
        (
            DeliveryEvidenceKind::PersistedLocal,
            DeliveryState::Persisted
        ) | (
            DeliveryEvidenceKind::AcceptedByTransport,
            DeliveryState::Acknowledged
        ) | (
            DeliveryEvidenceKind::ReceivedByDevice
                | DeliveryEvidenceKind::DecryptedByDevice
                | DeliveryEvidenceKind::PresentedToUser,
            DeliveryState::Delivered,
        ) | (DeliveryEvidenceKind::ReadByUser, DeliveryState::Read)
    )
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryId, DeliveryState,
        MessageId, OpaqueId, TenantId, TenantScope,
    };

    use super::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    fn attempt(state: DeliveryState) -> DeliveryAttempt {
        DeliveryAttempt {
            delivery_id: DeliveryId::from_opaque(oid("delivery-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: None,
            },
            message_id: MessageId::from_opaque(oid("message-a")),
            state,
        }
    }

    #[test]
    fn relay_replication_never_proves_user_delivery() {
        let current = attempt(DeliveryState::Acknowledged);
        let evidence = DeliveryEvidence {
            delivery_id: current.delivery_id.clone(),
            scope: current.scope.clone(),
            message_id: current.message_id.clone(),
            kind: DeliveryEvidenceKind::ReplicatedToRelay,
            logical_order: 1,
        };
        assert_eq!(
            validate_delivery_evidence(&current, &evidence, DeliveryState::Delivered),
            Err(DeliveryError::EvidenceDoesNotProveState)
        );
    }

    #[test]
    fn delivery_attempt_cannot_skip_or_reopen_terminal_state() {
        assert_eq!(
            validate_delivery_attempt(&attempt(DeliveryState::Persisted)),
            Ok(())
        );
        assert_eq!(
            validate_delivery_attempt(&attempt(DeliveryState::Created)),
            Err(DeliveryError::InvalidInitialState)
        );
        assert_eq!(
            validate_delivery_transition(
                &attempt(DeliveryState::Persisted),
                DeliveryState::Encrypted
            ),
            Ok(())
        );
        assert_eq!(
            validate_delivery_transition(&attempt(DeliveryState::Persisted), DeliveryState::Queued),
            Err(DeliveryError::IllegalTransition)
        );
        assert_eq!(
            validate_delivery_transition(&attempt(DeliveryState::Failed), DeliveryState::Queued),
            Err(DeliveryError::IllegalTransition)
        );
    }

    #[test]
    fn evidence_order_rejects_regression() {
        assert_eq!(validate_delivery_evidence_order(Some(7), 8), Ok(()));
        assert_eq!(validate_delivery_evidence_order(Some(7), 7), Ok(()));
        assert_eq!(
            validate_delivery_evidence_order(Some(7), 6),
            Err(DeliveryError::EvidenceRegression)
        );
    }

    #[test]
    fn read_requires_user_read_evidence() {
        let current = attempt(DeliveryState::Delivered);
        let mut evidence = DeliveryEvidence {
            delivery_id: current.delivery_id.clone(),
            scope: current.scope.clone(),
            message_id: current.message_id.clone(),
            kind: DeliveryEvidenceKind::PresentedToUser,
            logical_order: 9,
        };
        assert_eq!(
            validate_delivery_evidence(&current, &evidence, DeliveryState::Read),
            Err(DeliveryError::EvidenceDoesNotProveState)
        );
        evidence.kind = DeliveryEvidenceKind::ReadByUser;
        assert_eq!(
            validate_delivery_evidence(&current, &evidence, DeliveryState::Read),
            Ok(())
        );
    }
}

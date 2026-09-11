use std::time::{SystemTime, UNIX_EPOCH};

use ucr_core::{
    CanonicalTransportError, PolicyDecision, TransportFailureDisposition, TransportHealth,
};
use ucr_model::{
    CommunicationIntent, TransportFailoverAttemptDecision, TransportFailoverAttemptOutcome,
    TransportFailoverDecision, TransportFailoverPolicy, TransportFailoverStopReason,
};
use ucr_protocol::{
    DEFAULT_MAX_PAYLOAD_LEN, canonical_communication_intent, validate_transport_failover_policy,
};

use super::{TransportOrchestrator, TransportPlan, capability_is_usable};

pub trait TransportFailoverClock: core::fmt::Debug + Send + Sync {
    fn now_unix_ms(&self) -> i64;
}

#[derive(Debug, Default)]
pub struct SystemTransportFailoverClock;

impl TransportFailoverClock for SystemTransportFailoverClock {
    fn now_unix_ms(&self) -> i64 {
        let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return 0;
        };
        i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailoverExecutionError {
    pub error: CanonicalTransportError,
    pub decision: TransportFailoverDecision,
}

impl TransportFailoverExecutionError {
    fn new(
        error: CanonicalTransportError,
        attempts: Vec<TransportFailoverAttemptDecision>,
        stop_reason: TransportFailoverStopReason,
    ) -> Self {
        Self {
            error,
            decision: TransportFailoverDecision {
                attempts,
                stop_reason,
            },
        }
    }
}

impl TransportOrchestrator<'_> {
    /// Executes bounded sequential cross-route failover over an existing ranked plan.
    ///
    /// A later route is attempted only when the previous provider proves that the encrypted envelope
    /// was not accepted. Ambiguous acceptance stops fail closed, preventing duplicate cross-route
    /// effects without claiming exactly-once delivery.
    ///
    /// # Errors
    /// Returns the canonical failure plus a redacted public decision trail when policy/deadline/budget
    /// prevents progress, a route fails terminally, acceptance is ambiguous, or all routes are exhausted.
    pub fn transmit_with_failover(
        &self,
        intent: &CommunicationIntent,
        plan: &TransportPlan<'_>,
        encrypted_envelope: &[u8],
        failover_policy: TransportFailoverPolicy,
        clock: &dyn TransportFailoverClock,
    ) -> Result<TransportFailoverDecision, TransportFailoverExecutionError> {
        let canonical = validate_execution(intent, plan, encrypted_envelope, failover_policy)?;
        execute_ranked_routes(
            self,
            &canonical,
            plan,
            encrypted_envelope,
            failover_policy,
            clock,
        )
    }
}

fn validate_execution(
    intent: &CommunicationIntent,
    plan: &TransportPlan<'_>,
    encrypted_envelope: &[u8],
    policy: TransportFailoverPolicy,
) -> Result<CommunicationIntent, TransportFailoverExecutionError> {
    if validate_transport_failover_policy(&policy).is_err() {
        return Err(error_without_attempts(
            CanonicalTransportError::Rejected,
            TransportFailoverStopReason::TerminalFailure,
        ));
    }
    let canonical = canonical_communication_intent(intent).map_err(|_| {
        error_without_attempts(
            CanonicalTransportError::PolicyDenied,
            TransportFailoverStopReason::PolicyChanged,
        )
    })?;
    if plan.binding.intent_id != canonical.intent_id
        || plan.binding.scope != canonical.scope
        || plan.binding.target_identity_id != canonical.target_identity_id
        || plan.binding.constraints != canonical.constraints
    {
        return Err(error_without_attempts(
            CanonicalTransportError::PolicyDenied,
            TransportFailoverStopReason::PolicyChanged,
        ));
    }
    if encrypted_envelope.is_empty() || encrypted_envelope.len() > DEFAULT_MAX_PAYLOAD_LEN as usize
    {
        return Err(error_without_attempts(
            CanonicalTransportError::ResourceExhausted,
            TransportFailoverStopReason::TerminalFailure,
        ));
    }
    Ok(canonical)
}

fn execute_ranked_routes(
    orchestrator: &TransportOrchestrator<'_>,
    intent: &CommunicationIntent,
    plan: &TransportPlan<'_>,
    encrypted_envelope: &[u8],
    policy: TransportFailoverPolicy,
    clock: &dyn TransportFailoverClock,
) -> Result<TransportFailoverDecision, TransportFailoverExecutionError> {
    let mut attempts = Vec::new();
    let mut provider_attempts = 0_u16;
    let mut last_error = CanonicalTransportError::Unavailable;
    for planned in &plan.ranked_routes {
        pre_route_gate(orchestrator, intent, policy, clock, attempts.clone())?;
        if planned.provider.health() == TransportHealth::Unavailable {
            last_error = CanonicalTransportError::Unavailable;
            attempts.push(attempt(
                planned,
                TransportFailoverAttemptOutcome::SkippedUnavailable,
            ));
            continue;
        }
        if !capability_is_usable(
            &planned.provider.capabilities(),
            &planned.route.transport_capability,
        ) {
            last_error = CanonicalTransportError::UnsupportedCapability;
            attempts.push(attempt(
                planned,
                TransportFailoverAttemptOutcome::SkippedUnsupportedCapability,
            ));
            continue;
        }
        if provider_attempts >= policy.max_route_attempts {
            return Err(TransportFailoverExecutionError::new(
                last_error,
                attempts,
                TransportFailoverStopReason::AttemptBudgetExhausted,
            ));
        }
        provider_attempts += 1;
        match planned.provider.transmit_classified(
            &intent.scope,
            &planned.route,
            encrypted_envelope,
        ) {
            Ok(()) => return Ok(accepted(attempts, planned)),
            Err(failure)
                if failure.disposition == TransportFailureDisposition::AcceptanceUnknown =>
            {
                attempts.push(attempt(
                    planned,
                    TransportFailoverAttemptOutcome::AcceptanceUnknown,
                ));
                return Err(TransportFailoverExecutionError::new(
                    failure.error,
                    attempts,
                    TransportFailoverStopReason::AcceptanceUnknown,
                ));
            }
            Err(failure) if cross_route_retryable(failure.error) => {
                last_error = failure.error;
                attempts.push(attempt(
                    planned,
                    TransportFailoverAttemptOutcome::FailedBeforeAcceptance,
                ));
            }
            Err(failure) => {
                attempts.push(attempt(
                    planned,
                    TransportFailoverAttemptOutcome::TerminalFailure,
                ));
                return Err(TransportFailoverExecutionError::new(
                    failure.error,
                    attempts,
                    TransportFailoverStopReason::TerminalFailure,
                ));
            }
        }
    }
    Err(TransportFailoverExecutionError::new(
        last_error,
        attempts,
        TransportFailoverStopReason::RoutesExhausted,
    ))
}

fn pre_route_gate(
    orchestrator: &TransportOrchestrator<'_>,
    intent: &CommunicationIntent,
    policy: TransportFailoverPolicy,
    clock: &dyn TransportFailoverClock,
    attempts: Vec<TransportFailoverAttemptDecision>,
) -> Result<(), TransportFailoverExecutionError> {
    if deadline_expired(policy, clock) {
        return Err(TransportFailoverExecutionError::new(
            CanonicalTransportError::Timeout,
            attempts,
            TransportFailoverStopReason::DeadlineExpired,
        ));
    }
    if orchestrator.policy.evaluate_intent(intent) != PolicyDecision::Allow {
        return Err(TransportFailoverExecutionError::new(
            CanonicalTransportError::PolicyDenied,
            attempts,
            TransportFailoverStopReason::PolicyChanged,
        ));
    }
    Ok(())
}

fn accepted(
    mut attempts: Vec<TransportFailoverAttemptDecision>,
    planned: &super::PlannedTransportRoute<'_>,
) -> TransportFailoverDecision {
    attempts.push(attempt(
        planned,
        TransportFailoverAttemptOutcome::AcceptedByTransport,
    ));
    TransportFailoverDecision {
        attempts,
        stop_reason: TransportFailoverStopReason::AcceptedByTransport,
    }
}

fn error_without_attempts(
    error: CanonicalTransportError,
    stop_reason: TransportFailoverStopReason,
) -> TransportFailoverExecutionError {
    TransportFailoverExecutionError::new(error, Vec::new(), stop_reason)
}

fn deadline_expired(policy: TransportFailoverPolicy, clock: &dyn TransportFailoverClock) -> bool {
    policy
        .expires_at_unix_ms
        .is_some_and(|expires_at| clock.now_unix_ms() >= expires_at)
}

fn cross_route_retryable(error: CanonicalTransportError) -> bool {
    matches!(
        error,
        CanonicalTransportError::Unavailable
            | CanonicalTransportError::Timeout
            | CanonicalTransportError::UnsupportedCapability
    )
}

fn attempt(
    planned: &super::PlannedTransportRoute<'_>,
    outcome: TransportFailoverAttemptOutcome,
) -> TransportFailoverAttemptDecision {
    TransportFailoverAttemptDecision {
        route: planned.decision.clone(),
        outcome,
    }
}

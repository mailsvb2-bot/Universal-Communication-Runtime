use crate::TransportRouteDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportFailoverPolicy {
    pub max_route_attempts: u16,
    pub expires_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailoverAttemptOutcome {
    SkippedUnavailable,
    SkippedUnsupportedCapability,
    FailedBeforeAcceptance,
    AcceptanceUnknown,
    AcceptedByTransport,
    TerminalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailoverStopReason {
    AcceptedByTransport,
    RoutesExhausted,
    AttemptBudgetExhausted,
    DeadlineExpired,
    PolicyChanged,
    AcceptanceUnknown,
    TerminalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailoverAttemptDecision {
    pub route: TransportRouteDecision,
    pub outcome: TransportFailoverAttemptOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFailoverDecision {
    pub attempts: Vec<TransportFailoverAttemptDecision>,
    pub stop_reason: TransportFailoverStopReason,
}

use ucr_model::{CapabilityDescriptor, CapabilityMaturity, TransportFailoverPolicy};

pub const TRANSPORT_FAILOVER_CAPABILITY: &str = "ucr.transport.failover";
pub const MAX_TRANSPORT_FAILOVER_ROUTE_ATTEMPTS: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailoverProtocolError {
    ZeroRouteAttemptBudget,
    TooManyRouteAttempts,
}

#[must_use]
pub fn phase25_transport_failover_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: TRANSPORT_FAILOVER_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Validates the finite cross-route execution budget. Provider-internal retry policy remains owned
/// by each `TransportProvider` and is not multiplied here.
///
/// # Errors
/// Rejects zero or a budget larger than the bounded Phase-24 route plan.
pub const fn validate_transport_failover_policy(
    policy: &TransportFailoverPolicy,
) -> Result<(), TransportFailoverProtocolError> {
    if policy.max_route_attempts == 0 {
        return Err(TransportFailoverProtocolError::ZeroRouteAttemptBudget);
    }
    if policy.max_route_attempts > MAX_TRANSPORT_FAILOVER_ROUTE_ATTEMPTS {
        return Err(TransportFailoverProtocolError::TooManyRouteAttempts);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_budget_is_finite_and_bounded_by_route_plan() {
        let valid = TransportFailoverPolicy {
            max_route_attempts: 64,
            expires_at_unix_ms: Some(123),
        };
        assert_eq!(validate_transport_failover_policy(&valid), Ok(()));
        assert_eq!(
            validate_transport_failover_policy(&TransportFailoverPolicy {
                max_route_attempts: 0,
                expires_at_unix_ms: None,
            }),
            Err(TransportFailoverProtocolError::ZeroRouteAttemptBudget)
        );
        assert_eq!(
            validate_transport_failover_policy(&TransportFailoverPolicy {
                max_route_attempts: 65,
                expires_at_unix_ms: None,
            }),
            Err(TransportFailoverProtocolError::TooManyRouteAttempts)
        );
    }
}

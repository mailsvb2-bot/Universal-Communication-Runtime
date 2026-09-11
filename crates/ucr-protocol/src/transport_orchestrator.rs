use std::collections::BTreeSet;

use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, TransportResourceSnapshot, TransportRouteTelemetry,
    TransportRoutingHint,
};

use crate::MAX_INTENT_POLICY_VALUE_LEN;

pub const TRANSPORT_ORCHESTRATOR_CAPABILITY: &str = "ucr.transport.orchestrator";
pub const MAX_TRANSPORT_ROUTE_CANDIDATES: usize = 64;
pub const MAX_TRANSPORT_HINTS: usize = 3;
pub const MAX_TRANSPORT_BANDWIDTH_BPS: u64 = 10_000_000_000;
pub const MAX_TRANSPORT_LATENCY_MS: u32 = 120_000;
pub const MAX_TRANSPORT_PRIORITY_CLASS: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportOrchestratorProtocolError {
    TooManyCandidates,
    TooManyHints,
    DuplicateHint,
    BandwidthOutOfRange,
    PacketLossOutOfRange,
    LatencyOutOfRange,
    EnergyCostOutOfRange,
    ReliabilityOutOfRange,
    BatteryOutOfRange,
    PolicyValueTooLong,
    PriorityClassOutOfRange,
}

/// Validates the bounded Runtime -> Transport candidate-set size.
///
/// # Errors
/// Rejects candidate sets larger than the Phase-24 planning budget.
pub const fn validate_transport_route_candidate_count(
    count: usize,
) -> Result<(), TransportOrchestratorProtocolError> {
    if count > MAX_TRANSPORT_ROUTE_CANDIDATES {
        return Err(TransportOrchestratorProtocolError::TooManyCandidates);
    }
    Ok(())
}

#[must_use]
pub fn phase24_transport_orchestrator_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: TRANSPORT_ORCHESTRATOR_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Validates one transient route observation. Route address and capability ownership remain owned
/// by Endpoint/TransportProvider and are deliberately not duplicated here.
///
/// # Errors
/// Rejects impossible percentages or measurements outside the bounded reference envelope.
pub fn validate_transport_route_telemetry(
    value: &TransportRouteTelemetry,
) -> Result<(), TransportOrchestratorProtocolError> {
    if value.estimated_bandwidth_bps > MAX_TRANSPORT_BANDWIDTH_BPS {
        return Err(TransportOrchestratorProtocolError::BandwidthOutOfRange);
    }
    if value.packet_loss_basis_points > 10_000 {
        return Err(TransportOrchestratorProtocolError::PacketLossOutOfRange);
    }
    if value.jitter_ms > MAX_TRANSPORT_LATENCY_MS || value.rtt_ms > MAX_TRANSPORT_LATENCY_MS {
        return Err(TransportOrchestratorProtocolError::LatencyOutOfRange);
    }
    if value.energy_cost_percent > 100 {
        return Err(TransportOrchestratorProtocolError::EnergyCostOutOfRange);
    }
    if value.reliability_basis_points > 10_000 {
        return Err(TransportOrchestratorProtocolError::ReliabilityOutOfRange);
    }
    for field in [value.privacy_profile.as_deref(), value.region.as_deref()]
        .into_iter()
        .flatten()
    {
        if field.len() > MAX_INTENT_POLICY_VALUE_LEN {
            return Err(TransportOrchestratorProtocolError::PolicyValueTooLong);
        }
    }
    Ok(())
}

/// Validates local resource inputs used only for route ranking.
///
/// # Errors
/// Rejects impossible battery percentages.
pub const fn validate_transport_resource_snapshot(
    value: &TransportResourceSnapshot,
) -> Result<(), TransportOrchestratorProtocolError> {
    if value.battery_percent > 100 {
        return Err(TransportOrchestratorProtocolError::BatteryOutOfRange);
    }
    Ok(())
}

/// Canonicalizes bounded external routing hints. Hints can express preference classes only; they
/// cannot name endpoints, providers, ranks, or routing-graph edges.
///
/// # Errors
/// Rejects duplicate or over-budget hint sets.
pub fn canonical_transport_routing_hints(
    hints: &[TransportRoutingHint],
) -> Result<Vec<TransportRoutingHint>, TransportOrchestratorProtocolError> {
    if hints.len() > MAX_TRANSPORT_HINTS {
        return Err(TransportOrchestratorProtocolError::TooManyHints);
    }
    let mut seen = BTreeSet::new();
    for hint in hints {
        if !seen.insert(*hint) {
            return Err(TransportOrchestratorProtocolError::DuplicateHint);
        }
    }
    Ok(seen.into_iter().collect())
}

/// Validates the Phase-24 priority-class interpretation from Communication Intent.
///
/// # Errors
/// Rejects values outside Canon P0..P7.
pub const fn validate_transport_priority_class(
    priority_class: Option<u32>,
) -> Result<(), TransportOrchestratorProtocolError> {
    if let Some(value) = priority_class
        && value > MAX_TRANSPORT_PRIORITY_CLASS
    {
        return Err(TransportOrchestratorProtocolError::PriorityClassOutOfRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        MediaThermalState, TransportResourceSnapshot, TransportRouteTelemetry, TransportRoutingHint,
    };

    use super::*;

    fn telemetry() -> TransportRouteTelemetry {
        TransportRouteTelemetry {
            estimated_bandwidth_bps: 10_000_000,
            packet_loss_basis_points: 10,
            jitter_ms: 5,
            rtt_ms: 20,
            cost_microunits: 100,
            energy_cost_percent: 10,
            reliability_basis_points: 9_900,
            recipient_reachable: true,
            privacy_profile: Some("ucr.privacy.private".to_owned()),
            region: Some("eu".to_owned()),
        }
    }

    #[test]
    fn telemetry_and_resources_are_bounded() {
        assert_eq!(validate_transport_route_telemetry(&telemetry()), Ok(()));
        let resource = TransportResourceSnapshot {
            battery_percent: 50,
            external_power: false,
            thermal_state: MediaThermalState::Nominal,
        };
        assert_eq!(validate_transport_resource_snapshot(&resource), Ok(()));
        let mut invalid = telemetry();
        invalid.reliability_basis_points = 10_001;
        assert_eq!(
            validate_transport_route_telemetry(&invalid),
            Err(TransportOrchestratorProtocolError::ReliabilityOutOfRange)
        );
    }

    #[test]
    fn routing_hints_are_bounded_preference_classes_not_order() {
        let canonical = canonical_transport_routing_hints(&[
            TransportRoutingHint::PreferLocal,
            TransportRoutingHint::Urgent,
        ])
        .expect("hints");
        assert_eq!(
            canonical,
            vec![
                TransportRoutingHint::Urgent,
                TransportRoutingHint::PreferLocal
            ]
        );
        assert_eq!(
            canonical_transport_routing_hints(&[
                TransportRoutingHint::Urgent,
                TransportRoutingHint::Urgent,
            ]),
            Err(TransportOrchestratorProtocolError::DuplicateHint)
        );
    }

    #[test]
    fn priority_is_exactly_canon_p0_through_p7() {
        assert_eq!(validate_transport_route_candidate_count(64), Ok(()));
        assert_eq!(
            validate_transport_route_candidate_count(65),
            Err(TransportOrchestratorProtocolError::TooManyCandidates)
        );
        assert_eq!(validate_transport_priority_class(Some(0)), Ok(()));
        assert_eq!(validate_transport_priority_class(Some(7)), Ok(()));
        assert_eq!(
            validate_transport_priority_class(Some(8)),
            Err(TransportOrchestratorProtocolError::PriorityClassOutOfRange)
        );
    }
}

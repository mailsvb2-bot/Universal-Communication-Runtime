use core::fmt;

use crate::{EndpointId, MediaThermalState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportRoutingHint {
    Urgent,
    PreferLocal,
    AvoidExpensive,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransportRouteTelemetry {
    pub estimated_bandwidth_bps: u64,
    pub packet_loss_basis_points: u16,
    pub jitter_ms: u32,
    pub rtt_ms: u32,
    pub cost_microunits: u64,
    pub energy_cost_percent: u8,
    pub reliability_basis_points: u16,
    pub recipient_reachable: bool,
    pub privacy_profile: Option<String>,
    pub region: Option<String>,
}

impl fmt::Debug for TransportRouteTelemetry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportRouteTelemetry")
            .field("estimated_bandwidth_bps", &self.estimated_bandwidth_bps)
            .field("packet_loss_basis_points", &self.packet_loss_basis_points)
            .field("jitter_ms", &self.jitter_ms)
            .field("rtt_ms", &self.rtt_ms)
            .field("cost_microunits", &self.cost_microunits)
            .field("energy_cost_percent", &self.energy_cost_percent)
            .field("reliability_basis_points", &self.reliability_basis_points)
            .field("recipient_reachable", &self.recipient_reachable)
            .field("has_privacy_profile", &self.privacy_profile.is_some())
            .field("has_region", &self.region.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportResourceSnapshot {
    pub battery_percent: u8,
    pub external_power: bool,
    pub thermal_state: MediaThermalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRouteDecision {
    pub endpoint_id: EndpointId,
    pub transport_capability: String,
    pub rank: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportOrchestrationDecision {
    pub ranked_routes: Vec<TransportRouteDecision>,
}

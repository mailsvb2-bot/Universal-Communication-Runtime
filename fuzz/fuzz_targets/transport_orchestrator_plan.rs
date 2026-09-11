#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_core::{
    CanonicalTransportError, PolicyDecision, PolicyEvaluator, RouteCandidate, TransportHealth,
    TransportProvider,
};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, CommunicationIntent, CorrelationContext, DeviceId,
    EndpointAddress, EndpointDescriptor, EndpointId, EndpointKind, IdentityId, IntentConstraints,
    IntentId, MediaThermalState, OpaqueId, TenantId, TenantScope, TransportResourceSnapshot,
    TransportRouteTelemetry, TransportRoutingHint,
};
use ucr_transport_orchestrator::{TransportOrchestrator, TransportRouteOption};

#[derive(Debug)]
struct Allow;
impl PolicyEvaluator for Allow {
    fn evaluate_intent(&self, _: &CommunicationIntent) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug)]
struct Provider {
    capability: &'static str,
    health: TransportHealth,
}
impl TransportProvider for Provider {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: self.capability.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }]
    }
    fn health(&self) -> TransportHealth {
        self.health
    }
    fn transmit(
        &self,
        _: &TenantScope,
        _: &RouteCandidate,
        _: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        Ok(())
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static fuzz id")
}
fn u16_at(data: &[u8], offset: usize) -> u16 {
    let mut bytes = [0_u8; 2];
    for (target, source) in bytes.iter_mut().zip(data.get(offset..).unwrap_or_default()) {
        *target = *source;
    }
    u16::from_le_bytes(bytes)
}
fn u32_at(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0_u8; 4];
    for (target, source) in bytes.iter_mut().zip(data.get(offset..).unwrap_or_default()) {
        *target = *source;
    }
    u32::from_le_bytes(bytes)
}
fn u64_at(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (target, source) in bytes.iter_mut().zip(data.get(offset..).unwrap_or_default()) {
        *target = *source;
    }
    u64::from_le_bytes(bytes)
}

fn option<'a>(
    provider: &'a dyn TransportProvider,
    capability: &str,
    endpoint_name: &str,
    data: &[u8],
    offset: usize,
) -> TransportRouteOption<'a> {
    let endpoint_id = EndpointId::from_opaque(oid(endpoint_name));
    let address = EndpointAddress {
        scheme: "ucr.fuzz.route".to_owned(),
        value: endpoint_name.as_bytes().to_vec(),
    };
    TransportRouteOption {
        provider,
        route: RouteCandidate {
            endpoint_id: endpoint_id.clone(),
            transport_capability: capability.to_owned(),
            address: address.clone(),
        },
        recipient_endpoint: EndpointDescriptor {
            endpoint_id,
            kind: EndpointKind::Device,
            identity_id: Some(IdentityId::from_opaque(oid("recipient"))),
            device_id: Some(DeviceId::from_opaque(oid(&format!(
                "device-{endpoint_name}"
            )))),
            capabilities: vec![CapabilityDescriptor {
                id: capability.to_owned(),
                maturity: CapabilityMaturity::Prepared,
                extensions: Vec::new(),
            }],
            addresses: vec![address],
        },
        telemetry: TransportRouteTelemetry {
            estimated_bandwidth_bps: u64_at(data, offset),
            packet_loss_basis_points: u16_at(data, offset + 8),
            jitter_ms: u32_at(data, offset + 10),
            rtt_ms: u32_at(data, offset + 14),
            cost_microunits: u64_at(data, offset + 18),
            energy_cost_percent: data.get(offset + 26).copied().unwrap_or_default(),
            reliability_basis_points: u16_at(data, offset + 27),
            recipient_reachable: data.get(offset + 29).copied().unwrap_or_default() & 1 == 1,
            privacy_profile: Some("private".to_owned()),
            region: Some("eu".to_owned()),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    let health = |byte: u8| match byte % 3 {
        0 => TransportHealth::Healthy,
        1 => TransportHealth::Degraded,
        _ => TransportHealth::Unavailable,
    };
    let local = Provider {
        capability: "ucr.transport.local.tcp",
        health: health(data.first().copied().unwrap_or_default()),
    };
    let internet = Provider {
        capability: "ucr.transport.internet.tcp",
        health: health(data.get(1).copied().unwrap_or_default()),
    };
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant")),
        namespace_id: None,
    };
    let intent = CommunicationIntent {
        intent_id: IntentId::from_opaque(oid("intent")),
        scope,
        target_identity_id: IdentityId::from_opaque(oid("recipient")),
        payload: b"payload".to_vec(),
        constraints: IntentConstraints {
            allowed_transport_capabilities: Vec::new(),
            forbidden_transport_capabilities: Vec::new(),
            privacy_profile: Some("private".to_owned()),
            region_constraint: Some("eu".to_owned()),
            max_cost_microunits: Some(u64_at(data, 2)),
            priority_class: Some(u32::from(data.get(10).copied().unwrap_or_default() % 8)),
        },
        correlation: CorrelationContext {
            correlation_id: oid("correlation"),
            causation_id: None,
            idempotency_key: None,
        },
        extensions: Vec::new(),
    };
    let resources = TransportResourceSnapshot {
        battery_percent: data.get(11).copied().unwrap_or_default() % 101,
        external_power: data.get(12).copied().unwrap_or_default() & 1 == 1,
        thermal_state: match data.get(13).copied().unwrap_or_default() & 3 {
            0 => MediaThermalState::Nominal,
            1 => MediaThermalState::Elevated,
            2 => MediaThermalState::Serious,
            _ => MediaThermalState::Critical,
        },
    };
    let mut hints = Vec::new();
    let hint_bits = data.get(14).copied().unwrap_or_default();
    if hint_bits & 1 != 0 {
        hints.push(TransportRoutingHint::Urgent);
    }
    if hint_bits & 2 != 0 {
        hints.push(TransportRoutingHint::PreferLocal);
    }
    if hint_bits & 4 != 0 {
        hints.push(TransportRoutingHint::AvoidExpensive);
    }

    let orchestrator = TransportOrchestrator::new(&Allow);
    if let Ok(plan) = orchestrator.plan(
        &intent,
        resources,
        &hints,
        vec![
            option(&local, local.capability, "local", data, 16),
            option(&internet, internet.capability, "internet", data, 48),
        ],
    ) {
        let decision = plan.decision();
        assert!(!decision.ranked_routes.is_empty());
        let _ = orchestrator.transmit_primary(&intent, &plan, b"encrypted-envelope");
    }
});

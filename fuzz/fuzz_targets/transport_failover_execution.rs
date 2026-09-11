#![no_main]

use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use ucr_core::{
    CanonicalTransportError, ClassifiedTransportFailure, PolicyDecision, PolicyEvaluator,
    RouteCandidate, TransportHealth, TransportProvider,
};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, CommunicationIntent, CorrelationContext, DeviceId,
    EndpointAddress, EndpointDescriptor, EndpointId, EndpointKind, IdentityId, IntentConstraints,
    IntentId, MediaThermalState, OpaqueId, TenantId, TenantScope, TransportFailoverPolicy,
    TransportFailoverStopReason, TransportResourceSnapshot, TransportRouteTelemetry,
};
use ucr_transport_orchestrator::{
    TransportFailoverClock, TransportOrchestrator, TransportRouteOption,
};

#[derive(Debug)]
struct Allow;
impl PolicyEvaluator for Allow {
    fn evaluate_intent(&self, _: &CommunicationIntent) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug)]
struct Clock(i64);
impl TransportFailoverClock for Clock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

#[derive(Debug)]
struct Provider {
    capability: &'static str,
    behavior: u8,
    calls: Arc<Mutex<Vec<&'static str>>>,
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
        if self.behavior == 3 {
            TransportHealth::Unavailable
        } else {
            TransportHealth::Healthy
        }
    }
    fn transmit(
        &self,
        _: &TenantScope,
        _: &RouteCandidate,
        _: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        Ok(())
    }
    fn transmit_classified(
        &self,
        _: &TenantScope,
        _: &RouteCandidate,
        _: &[u8],
    ) -> Result<(), ClassifiedTransportFailure> {
        self.calls.lock().expect("calls").push(self.capability);
        match self.behavior % 4 {
            0 => Ok(()),
            1 => Err(ClassifiedTransportFailure::not_accepted(
                CanonicalTransportError::Unavailable,
            )),
            2 => Err(ClassifiedTransportFailure::acceptance_unknown(
                CanonicalTransportError::Timeout,
            )),
            _ => Ok(()),
        }
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant")),
        namespace_id: None,
    }
}
fn identity() -> IdentityId {
    IdentityId::from_opaque(oid("recipient"))
}
fn option<'a>(
    provider: &'a dyn TransportProvider,
    capability: &str,
    name: &str,
    rtt_ms: u32,
) -> TransportRouteOption<'a> {
    let endpoint_id = EndpointId::from_opaque(oid(name));
    let address = EndpointAddress {
        scheme: "ucr.fuzz.route".to_owned(),
        value: name.as_bytes().to_vec(),
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
            identity_id: Some(identity()),
            device_id: Some(DeviceId::from_opaque(oid(&format!("device-{name}")))),
            capabilities: vec![CapabilityDescriptor {
                id: capability.to_owned(),
                maturity: CapabilityMaturity::Prepared,
                extensions: Vec::new(),
            }],
            addresses: vec![address],
        },
        telemetry: TransportRouteTelemetry {
            estimated_bandwidth_bps: 5_000_000,
            packet_loss_basis_points: 10,
            jitter_ms: 5,
            rtt_ms,
            cost_microunits: 10,
            energy_cost_percent: 5,
            reliability_basis_points: 9_900,
            recipient_reachable: true,
            privacy_profile: Some("private".to_owned()),
            region: Some("eu".to_owned()),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first_behavior = data.first().copied().unwrap_or_default() % 4;
    let second_behavior = data.get(1).copied().unwrap_or_default() % 4;
    let first = Provider {
        capability: "ucr.transport.first",
        behavior: first_behavior,
        calls: calls.clone(),
    };
    let second = Provider {
        capability: "ucr.transport.second",
        behavior: second_behavior,
        calls: calls.clone(),
    };
    let intent = CommunicationIntent {
        intent_id: IntentId::from_opaque(oid("intent")),
        scope: scope(),
        target_identity_id: identity(),
        payload: b"payload".to_vec(),
        constraints: IntentConstraints {
            allowed_transport_capabilities: Vec::new(),
            forbidden_transport_capabilities: Vec::new(),
            privacy_profile: Some("private".to_owned()),
            region_constraint: Some("eu".to_owned()),
            max_cost_microunits: Some(100),
            priority_class: Some(2),
        },
        correlation: CorrelationContext {
            correlation_id: oid("corr"),
            causation_id: None,
            idempotency_key: Some("send".to_owned()),
        },
        extensions: Vec::new(),
    };
    let resources = TransportResourceSnapshot {
        battery_percent: 80,
        external_power: false,
        thermal_state: MediaThermalState::Nominal,
    };
    let orchestrator = TransportOrchestrator::new(&Allow);
    let Ok(plan) = orchestrator.plan(
        &intent,
        resources,
        &[],
        vec![
            option(&first, first.capability, "first", 5),
            option(&second, second.capability, "second", 50),
        ],
    ) else {
        return;
    };
    let max_route_attempts = u16::from(data.get(2).copied().unwrap_or(1) % 2 + 1);
    let now = i64::from(data.get(3).copied().unwrap_or_default());
    let expires = if data.get(4).copied().unwrap_or_default() & 1 == 0 {
        None
    } else {
        Some(i64::from(data.get(5).copied().unwrap_or_default()))
    };
    let result = orchestrator.transmit_with_failover(
        &intent,
        &plan,
        b"encrypted",
        TransportFailoverPolicy {
            max_route_attempts,
            expires_at_unix_ms: expires,
        },
        &Clock(now),
    );
    if first_behavior == 2 && expires.is_none() {
        let error = result.expect_err("ambiguous first route must stop");
        assert_eq!(
            error.decision.stop_reason,
            TransportFailoverStopReason::AcceptanceUnknown
        );
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            &["ucr.transport.first"]
        );
    }
});

use std::sync::{Arc, Mutex};

use ucr_core::{
    CanonicalTransportError, ClassifiedTransportFailure, PolicyDecision, PolicyEvaluator,
    RouteCandidate, TransportHealth, TransportProvider,
};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, CommunicationIntent, CorrelationContext,
    EndpointAddress, EndpointDescriptor, EndpointId, EndpointKind, IdentityId, IntentConstraints,
    IntentId, MediaThermalState, OpaqueId, TenantId, TenantScope, TransportFailoverAttemptOutcome,
    TransportFailoverPolicy, TransportFailoverStopReason, TransportResourceSnapshot,
    TransportRouteTelemetry,
};
use ucr_transport_orchestrator::{
    TransportFailoverClock, TransportOrchestrator, TransportRouteOption,
};

#[derive(Debug)]
struct AllowPolicy;
impl PolicyEvaluator for AllowPolicy {
    fn evaluate_intent(&self, _: &CommunicationIntent) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug)]
struct SequencePolicy(Mutex<Vec<PolicyDecision>>);
impl PolicyEvaluator for SequencePolicy {
    fn evaluate_intent(&self, _: &CommunicationIntent) -> PolicyDecision {
        let mut values = self.0.lock().expect("policy");
        if values.len() > 1 {
            values.remove(0)
        } else {
            values[0]
        }
    }
}

#[derive(Debug)]
struct FixedClock(i64);
impl TransportFailoverClock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy)]
enum ProviderBehavior {
    Accepted,
    NotAccepted(CanonicalTransportError),
    AcceptanceUnknown(CanonicalTransportError),
}

#[derive(Debug)]
struct TestProvider {
    capability: String,
    health: TransportHealth,
    behavior: ProviderBehavior,
    calls: Arc<Mutex<Vec<String>>>,
}

impl TransportProvider for TestProvider {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: self.capability.clone(),
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
        route: &RouteCandidate,
        _: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        self.calls
            .lock()
            .expect("calls")
            .push(route.transport_capability.clone());
        match self.behavior {
            ProviderBehavior::Accepted => Ok(()),
            ProviderBehavior::NotAccepted(error) | ProviderBehavior::AcceptanceUnknown(error) => {
                Err(error)
            }
        }
    }

    fn transmit_classified(
        &self,
        _scope: &TenantScope,
        route: &RouteCandidate,
        _encrypted_envelope: &[u8],
    ) -> Result<(), ClassifiedTransportFailure> {
        self.calls
            .lock()
            .expect("calls")
            .push(route.transport_capability.clone());
        match self.behavior {
            ProviderBehavior::Accepted => Ok(()),
            ProviderBehavior::NotAccepted(error) => {
                Err(ClassifiedTransportFailure::not_accepted(error))
            }
            ProviderBehavior::AcceptanceUnknown(error) => {
                Err(ClassifiedTransportFailure::acceptance_unknown(error))
            }
        }
    }
}

#[derive(Debug)]
struct LegacyProvider {
    capability: String,
    error: CanonicalTransportError,
    calls: Arc<Mutex<Vec<String>>>,
}

impl TransportProvider for LegacyProvider {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: self.capability.clone(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }]
    }

    fn health(&self) -> TransportHealth {
        TransportHealth::Healthy
    }

    fn transmit(
        &self,
        _: &TenantScope,
        route: &RouteCandidate,
        _: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        self.calls
            .lock()
            .expect("calls")
            .push(route.transport_capability.clone());
        Err(self.error)
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
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

fn intent() -> CommunicationIntent {
    CommunicationIntent {
        intent_id: IntentId::from_opaque(oid("intent")),
        scope: scope(),
        target_identity_id: identity(),
        payload: b"canonical-intent-payload".to_vec(),
        constraints: IntentConstraints {
            allowed_transport_capabilities: Vec::new(),
            forbidden_transport_capabilities: Vec::new(),
            privacy_profile: Some("private".to_owned()),
            region_constraint: Some("eu".to_owned()),
            max_cost_microunits: Some(1_000),
            priority_class: Some(2),
        },
        correlation: CorrelationContext {
            correlation_id: oid("corr"),
            causation_id: None,
            idempotency_key: Some("logical-send-1".to_owned()),
        },
        extensions: Vec::new(),
    }
}

fn resources() -> TransportResourceSnapshot {
    TransportResourceSnapshot {
        battery_percent: 80,
        external_power: false,
        thermal_state: MediaThermalState::Nominal,
    }
}

fn option<'a>(
    provider: &'a dyn TransportProvider,
    capability: &str,
    endpoint: &str,
    rtt: u32,
) -> TransportRouteOption<'a> {
    let endpoint_id = EndpointId::from_opaque(oid(endpoint));
    let address = EndpointAddress {
        scheme: "ucr.test.route".to_owned(),
        value: endpoint.as_bytes().to_vec(),
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
            device_id: Some(ucr_model::DeviceId::from_opaque(oid(&format!(
                "device-{endpoint}"
            )))),
            capabilities: vec![CapabilityDescriptor {
                id: capability.to_owned(),
                maturity: CapabilityMaturity::Prepared,
                extensions: Vec::new(),
            }],
            addresses: vec![address],
        },
        telemetry: TransportRouteTelemetry {
            estimated_bandwidth_bps: 5_000_000,
            packet_loss_basis_points: 50,
            jitter_ms: 5,
            rtt_ms: rtt,
            cost_microunits: 10,
            energy_cost_percent: 5,
            reliability_basis_points: 9_900,
            recipient_reachable: true,
            privacy_profile: Some("private".to_owned()),
            region: Some("eu".to_owned()),
        },
    }
}

fn policy(max_route_attempts: u16) -> TransportFailoverPolicy {
    TransportFailoverPolicy {
        max_route_attempts,
        expires_at_unix_ms: Some(2_000),
    }
}

#[test]
fn proven_not_accepted_failure_advances_to_next_ranked_route() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first = TestProvider {
        capability: "ucr.transport.first".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::NotAccepted(CanonicalTransportError::Unavailable),
        calls: calls.clone(),
    };
    let second = TestProvider {
        capability: "ucr.transport.second".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let orchestrator = TransportOrchestrator::new(&AllowPolicy);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                option(&first, "ucr.transport.first", "first", 5),
                option(&second, "ucr.transport.second", "second", 50),
            ],
        )
        .expect("plan");
    let decision = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(2), &FixedClock(1_000))
        .expect("second route accepts");
    assert_eq!(
        decision.stop_reason,
        TransportFailoverStopReason::AcceptedByTransport
    );
    assert_eq!(decision.attempts.len(), 2);
    assert_eq!(
        decision.attempts[0].outcome,
        TransportFailoverAttemptOutcome::FailedBeforeAcceptance
    );
    assert_eq!(
        decision.attempts[1].outcome,
        TransportFailoverAttemptOutcome::AcceptedByTransport
    );
    assert_eq!(
        *calls.lock().expect("calls"),
        vec!["ucr.transport.first", "ucr.transport.second"]
    );
}

#[test]
fn ambiguous_acceptance_never_attempts_second_route() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first = TestProvider {
        capability: "ucr.transport.first".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::AcceptanceUnknown(CanonicalTransportError::Timeout),
        calls: calls.clone(),
    };
    let second = TestProvider {
        capability: "ucr.transport.second".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let orchestrator = TransportOrchestrator::new(&AllowPolicy);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                option(&first, "ucr.transport.first", "first", 5),
                option(&second, "ucr.transport.second", "second", 50),
            ],
        )
        .expect("plan");
    let error = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(2), &FixedClock(1_000))
        .unwrap_err();
    assert_eq!(error.error, CanonicalTransportError::Timeout);
    assert_eq!(
        error.decision.stop_reason,
        TransportFailoverStopReason::AcceptanceUnknown
    );
    assert_eq!(*calls.lock().expect("calls"), vec!["ucr.transport.first"]);
}

#[test]
fn legacy_provider_default_is_conservative_and_cannot_fail_over() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first = LegacyProvider {
        capability: "ucr.transport.legacy".into(),
        error: CanonicalTransportError::Unavailable,
        calls: calls.clone(),
    };
    let second = TestProvider {
        capability: "ucr.transport.second".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let orchestrator = TransportOrchestrator::new(&AllowPolicy);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                option(&first, "ucr.transport.legacy", "legacy", 5),
                option(&second, "ucr.transport.second", "second", 50),
            ],
        )
        .expect("plan");
    let error = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(2), &FixedClock(1_000))
        .unwrap_err();
    assert_eq!(
        error.decision.stop_reason,
        TransportFailoverStopReason::AcceptanceUnknown
    );
    assert_eq!(*calls.lock().expect("calls"), vec!["ucr.transport.legacy"]);
}

#[test]
fn route_attempt_budget_prevents_unbounded_cross_provider_retry() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first = TestProvider {
        capability: "ucr.transport.first".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::NotAccepted(CanonicalTransportError::Unavailable),
        calls: calls.clone(),
    };
    let second = TestProvider {
        capability: "ucr.transport.second".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let orchestrator = TransportOrchestrator::new(&AllowPolicy);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                option(&first, "ucr.transport.first", "first", 5),
                option(&second, "ucr.transport.second", "second", 50),
            ],
        )
        .expect("plan");
    let error = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(1), &FixedClock(1_000))
        .unwrap_err();
    assert_eq!(
        error.decision.stop_reason,
        TransportFailoverStopReason::AttemptBudgetExhausted
    );
    assert_eq!(*calls.lock().expect("calls"), vec!["ucr.transport.first"]);
}

#[test]
fn expired_deadline_stops_before_any_transport_call() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let provider = TestProvider {
        capability: "ucr.transport.test".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let orchestrator = TransportOrchestrator::new(&AllowPolicy);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![option(&provider, "ucr.transport.test", "only", 5)],
        )
        .expect("plan");
    let error = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(1), &FixedClock(2_000))
        .unwrap_err();
    assert_eq!(error.error, CanonicalTransportError::Timeout);
    assert_eq!(
        error.decision.stop_reason,
        TransportFailoverStopReason::DeadlineExpired
    );
    assert!(calls.lock().expect("calls").is_empty());
}

#[test]
fn policy_change_between_routes_stops_before_second_provider() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first = TestProvider {
        capability: "ucr.transport.first".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::NotAccepted(CanonicalTransportError::Unavailable),
        calls: calls.clone(),
    };
    let second = TestProvider {
        capability: "ucr.transport.second".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let policy_gate = SequencePolicy(Mutex::new(vec![
        PolicyDecision::Allow,
        PolicyDecision::Allow,
        PolicyDecision::Deny,
    ]));
    let orchestrator = TransportOrchestrator::new(&policy_gate);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                option(&first, "ucr.transport.first", "first", 5),
                option(&second, "ucr.transport.second", "second", 50),
            ],
        )
        .expect("plan");
    let error = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(2), &FixedClock(1_000))
        .unwrap_err();
    assert_eq!(error.error, CanonicalTransportError::PolicyDenied);
    assert_eq!(
        error.decision.stop_reason,
        TransportFailoverStopReason::PolicyChanged
    );
    assert_eq!(*calls.lock().expect("calls"), vec!["ucr.transport.first"]);
}

#[test]
fn terminal_pre_accept_failure_does_not_walk_the_route_list() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first = TestProvider {
        capability: "ucr.transport.first".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::NotAccepted(CanonicalTransportError::PolicyDenied),
        calls: calls.clone(),
    };
    let second = TestProvider {
        capability: "ucr.transport.second".into(),
        health: TransportHealth::Healthy,
        behavior: ProviderBehavior::Accepted,
        calls: calls.clone(),
    };
    let orchestrator = TransportOrchestrator::new(&AllowPolicy);
    let value = intent();
    let plan = orchestrator
        .plan(
            &value,
            resources(),
            &[],
            vec![
                option(&first, "ucr.transport.first", "first", 5),
                option(&second, "ucr.transport.second", "second", 50),
            ],
        )
        .expect("plan");
    let error = orchestrator
        .transmit_with_failover(&value, &plan, b"encrypted", policy(2), &FixedClock(1_000))
        .unwrap_err();
    assert_eq!(error.error, CanonicalTransportError::PolicyDenied);
    assert_eq!(
        error.decision.stop_reason,
        TransportFailoverStopReason::TerminalFailure
    );
    assert_eq!(*calls.lock().expect("calls"), vec!["ucr.transport.first"]);
}

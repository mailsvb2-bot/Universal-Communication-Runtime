#![forbid(unsafe_code)]

mod failover;
pub use failover::{
    SystemTransportFailoverClock, TransportFailoverClock, TransportFailoverExecutionError,
};

use core::{cmp::Ordering, fmt};
use std::collections::BTreeSet;

use ucr_core::{
    CanonicalTransportError, PolicyDecision, PolicyEvaluator, RouteCandidate, TransportHealth,
    TransportProvider,
};
use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, CommunicationIntent, EndpointDescriptor,
    IntentConstraints, MediaThermalState, TenantScope, TransportOrchestrationDecision,
    TransportResourceSnapshot, TransportRouteDecision, TransportRouteTelemetry,
    TransportRoutingHint,
};
use ucr_protocol::{
    DEFAULT_MAX_PAYLOAD_LEN, IntentError, MAX_TRANSPORT_BANDWIDTH_BPS,
    TransportOrchestratorProtocolError, canonical_communication_intent,
    canonical_transport_routing_hints, validate_endpoint_descriptor,
    validate_transport_priority_class, validate_transport_resource_snapshot,
    validate_transport_route_candidate_count, validate_transport_route_telemetry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportOrchestratorError {
    Intent(IntentError),
    Protocol(TransportOrchestratorProtocolError),
    InvalidEndpoint,
    TooManyRoutes,
    DuplicateRoute,
    PolicyDenied,
    PolicyPending,
    NoEligibleRoute,
}

impl From<IntentError> for TransportOrchestratorError {
    fn from(error: IntentError) -> Self {
        Self::Intent(error)
    }
}

impl From<TransportOrchestratorProtocolError> for TransportOrchestratorError {
    fn from(error: TransportOrchestratorProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// One transient route discovered outside the orchestrator. Endpoint and Provider remain the
/// canonical owners of address/capability semantics; telemetry is ranking input only.
pub struct TransportRouteOption<'a> {
    pub provider: &'a dyn TransportProvider,
    pub route: RouteCandidate,
    pub recipient_endpoint: EndpointDescriptor,
    pub telemetry: TransportRouteTelemetry,
}

impl fmt::Debug for TransportRouteOption<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportRouteOption")
            .field("endpoint_id", &self.route.endpoint_id)
            .field("transport_capability", &self.route.transport_capability)
            .field("telemetry", &self.telemetry)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanBinding {
    intent_id: ucr_model::IntentId,
    scope: TenantScope,
    target_identity_id: ucr_model::IdentityId,
    constraints: IntentConstraints,
}

struct PlannedTransportRoute<'a> {
    provider: &'a dyn TransportProvider,
    route: RouteCandidate,
    decision: TransportRouteDecision,
}

impl fmt::Debug for PlannedTransportRoute<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlannedTransportRoute")
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct TransportPlan<'a> {
    binding: PlanBinding,
    ranked_routes: Vec<PlannedTransportRoute<'a>>,
}

impl TransportPlan<'_> {
    #[must_use]
    pub fn decision(&self) -> TransportOrchestrationDecision {
        TransportOrchestrationDecision {
            ranked_routes: self
                .ranked_routes
                .iter()
                .map(|route| route.decision.clone())
                .collect(),
        }
    }

    #[must_use]
    pub fn route_count(&self) -> usize {
        self.ranked_routes.len()
    }
}

#[derive(Debug)]
pub struct TransportOrchestrator<'a> {
    policy: &'a dyn PolicyEvaluator,
}

impl<'a> TransportOrchestrator<'a> {
    #[must_use]
    pub const fn new(policy: &'a dyn PolicyEvaluator) -> Self {
        Self { policy }
    }

    /// Produces a deterministic transient route plan. Hard policy/identity/capability constraints
    /// filter candidates before metrics or hints can affect ordering.
    ///
    /// # Errors
    /// Rejects malformed/badly bounded inputs, policy denial, duplicate discovered routes, and an
    /// empty eligible set.
    pub fn plan<'b>(
        &self,
        intent: &CommunicationIntent,
        resources: TransportResourceSnapshot,
        hints: &[TransportRoutingHint],
        options: Vec<TransportRouteOption<'b>>,
    ) -> Result<TransportPlan<'b>, TransportOrchestratorError> {
        let intent = canonical_communication_intent(intent)?;
        validate_transport_resource_snapshot(&resources)?;
        validate_transport_priority_class(intent.constraints.priority_class)?;
        let hints = canonical_transport_routing_hints(hints)?;
        validate_transport_route_candidate_count(options.len())
            .map_err(|_| TransportOrchestratorError::TooManyRoutes)?;
        match self.policy.evaluate_intent(&intent) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny => return Err(TransportOrchestratorError::PolicyDenied),
            PolicyDecision::PendingNoAllowedRoute => {
                return Err(TransportOrchestratorError::PolicyPending);
            }
        }

        let mut seen = BTreeSet::new();
        let mut eligible = Vec::new();
        for option in options {
            validate_transport_route_telemetry(&option.telemetry)?;
            validate_endpoint_descriptor(&option.recipient_endpoint)
                .map_err(|_| TransportOrchestratorError::InvalidEndpoint)?;
            let route_key = (
                option.route.endpoint_id.as_opaque().as_str().to_owned(),
                option.route.transport_capability.clone(),
                option.route.address.scheme.clone(),
                option.route.address.value.clone(),
            );
            if !seen.insert(route_key) {
                return Err(TransportOrchestratorError::DuplicateRoute);
            }
            if option_is_eligible(&intent, &option) {
                let score = RouteScore::new(&intent, resources, &hints, &option);
                eligible.push((score, option));
            }
        }
        if eligible.is_empty() {
            return Err(TransportOrchestratorError::NoEligibleRoute);
        }
        eligible.sort_by(|(left_score, left), (right_score, right)| {
            compare_scores(left_score, right_score, &intent, &hints)
                .then_with(|| stable_route_cmp(&left.route, &right.route))
        });

        let mut ranked_routes = Vec::with_capacity(eligible.len());
        for (index, (_, option)) in eligible.into_iter().enumerate() {
            let rank =
                u16::try_from(index + 1).map_err(|_| TransportOrchestratorError::TooManyRoutes)?;
            ranked_routes.push(PlannedTransportRoute {
                provider: option.provider,
                decision: TransportRouteDecision {
                    endpoint_id: option.route.endpoint_id.clone(),
                    transport_capability: option.route.transport_capability.clone(),
                    rank,
                },
                route: option.route,
            });
        }

        Ok(TransportPlan {
            binding: PlanBinding {
                intent_id: intent.intent_id,
                scope: intent.scope,
                target_identity_id: intent.target_identity_id,
                constraints: intent.constraints,
            },
            ranked_routes,
        })
    }

    /// Transmits through the primary planned route exactly once at the orchestrator layer.
    /// Provider-internal bounded reconnect semantics remain provider-owned. A transport error is
    /// returned directly: Phase 24 does not try the next ranked route (Automatic Failover is Phase 25).
    ///
    /// # Errors
    /// Fails closed when the plan no longer matches current Intent policy, provider health/capability
    /// changed, or Runtime->Transport backpressure bounds are exceeded.
    pub fn transmit_primary(
        &self,
        intent: &CommunicationIntent,
        plan: &TransportPlan<'_>,
        encrypted_envelope: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        let canonical = canonical_communication_intent(intent)
            .map_err(|_| CanonicalTransportError::PolicyDenied)?;
        if plan.binding.intent_id != canonical.intent_id
            || plan.binding.scope != canonical.scope
            || plan.binding.target_identity_id != canonical.target_identity_id
            || plan.binding.constraints != canonical.constraints
        {
            return Err(CanonicalTransportError::PolicyDenied);
        }
        if self.policy.evaluate_intent(&canonical) != PolicyDecision::Allow {
            return Err(CanonicalTransportError::PolicyDenied);
        }
        if encrypted_envelope.is_empty()
            || encrypted_envelope.len() > DEFAULT_MAX_PAYLOAD_LEN as usize
        {
            return Err(CanonicalTransportError::ResourceExhausted);
        }
        let primary = plan
            .ranked_routes
            .first()
            .ok_or(CanonicalTransportError::Unavailable)?;
        if primary.provider.health() == TransportHealth::Unavailable {
            return Err(CanonicalTransportError::Unavailable);
        }
        if !capability_is_usable(
            &primary.provider.capabilities(),
            &primary.route.transport_capability,
        ) {
            return Err(CanonicalTransportError::UnsupportedCapability);
        }
        primary
            .provider
            .transmit(&canonical.scope, &primary.route, encrypted_envelope)
    }
}

fn option_is_eligible(intent: &CommunicationIntent, option: &TransportRouteOption<'_>) -> bool {
    if option.provider.health() == TransportHealth::Unavailable
        || !option.telemetry.recipient_reachable
    {
        return false;
    }
    if option.route.endpoint_id != option.recipient_endpoint.endpoint_id
        || option.recipient_endpoint.identity_id.as_ref() != Some(&intent.target_identity_id)
        || !option
            .recipient_endpoint
            .addresses
            .contains(&option.route.address)
    {
        return false;
    }
    let capability = option.route.transport_capability.as_str();
    if !capability_is_usable(&option.provider.capabilities(), capability)
        || !capability_is_usable(&option.recipient_endpoint.capabilities, capability)
    {
        return false;
    }
    if !intent.constraints.allowed_transport_capabilities.is_empty()
        && !intent
            .constraints
            .allowed_transport_capabilities
            .iter()
            .any(|allowed| allowed == capability)
    {
        return false;
    }
    if intent
        .constraints
        .forbidden_transport_capabilities
        .iter()
        .any(|forbidden| forbidden == capability)
    {
        return false;
    }
    if intent.constraints.privacy_profile.as_deref() != option.telemetry.privacy_profile.as_deref()
        && intent.constraints.privacy_profile.is_some()
    {
        return false;
    }
    if intent.constraints.region_constraint.as_deref() != option.telemetry.region.as_deref()
        && intent.constraints.region_constraint.is_some()
    {
        return false;
    }
    if intent
        .constraints
        .max_cost_microunits
        .is_some_and(|max| option.telemetry.cost_microunits > max)
    {
        return false;
    }
    true
}

fn capability_is_usable(capabilities: &[CapabilityDescriptor], required: &str) -> bool {
    capabilities.iter().any(|capability| {
        capability.id == required
            && matches!(
                capability.maturity,
                CapabilityMaturity::Prepared
                    | CapabilityMaturity::Beta
                    | CapabilityMaturity::Production
            )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteScore {
    availability: u8,
    latency: u64,
    loss: u16,
    reliability_inverse: u16,
    bandwidth_inverse: u64,
    cost: u64,
    energy: u64,
    local_penalty: u8,
}

impl RouteScore {
    fn new(
        _intent: &CommunicationIntent,
        resources: TransportResourceSnapshot,
        hints: &[TransportRoutingHint],
        option: &TransportRouteOption<'_>,
    ) -> Self {
        let thermal_pressure = match resources.thermal_state {
            MediaThermalState::Nominal => 0_u64,
            MediaThermalState::Elevated => 25,
            MediaThermalState::Serious => 60,
            MediaThermalState::Critical => 100,
        };
        let battery_pressure = if resources.external_power {
            0
        } else {
            u64::from(100 - resources.battery_percent)
        };
        let resource_pressure = 1 + battery_pressure + thermal_pressure;
        let prefer_local = hints.contains(&TransportRoutingHint::PreferLocal);
        Self {
            availability: match option.provider.health() {
                TransportHealth::Healthy => 0,
                TransportHealth::Degraded => 1,
                TransportHealth::Unavailable => 2,
            },
            latency: u64::from(option.telemetry.rtt_ms) + u64::from(option.telemetry.jitter_ms),
            loss: option.telemetry.packet_loss_basis_points,
            reliability_inverse: 10_000 - option.telemetry.reliability_basis_points,
            bandwidth_inverse: MAX_TRANSPORT_BANDWIDTH_BPS
                - option.telemetry.estimated_bandwidth_bps,
            cost: option.telemetry.cost_microunits,
            energy: u64::from(option.telemetry.energy_cost_percent)
                .saturating_mul(resource_pressure),
            local_penalty: u8::from(
                prefer_local
                    && !option
                        .route
                        .transport_capability
                        .starts_with("ucr.transport.local."),
            ),
        }
    }
}

fn compare_scores(
    left: &RouteScore,
    right: &RouteScore,
    intent: &CommunicationIntent,
    hints: &[TransportRoutingHint],
) -> Ordering {
    let urgent = hints.contains(&TransportRoutingHint::Urgent)
        || intent
            .constraints
            .priority_class
            .is_some_and(|value| value <= 1);
    let economy = intent
        .constraints
        .priority_class
        .is_some_and(|value| value >= 6);
    let prefer_local = hints.contains(&TransportRoutingHint::PreferLocal);
    let avoid_expensive = hints.contains(&TransportRoutingHint::AvoidExpensive);

    let mut ordering = left.availability.cmp(&right.availability);
    macro_rules! compare {
        ($field:ident) => {
            if ordering == Ordering::Equal {
                ordering = left.$field.cmp(&right.$field);
            }
        };
    }
    if prefer_local {
        compare!(local_penalty);
    }
    if avoid_expensive {
        compare!(cost);
    }
    if urgent {
        compare!(latency);
        compare!(loss);
        compare!(reliability_inverse);
        compare!(bandwidth_inverse);
        compare!(energy);
        compare!(cost);
    } else if economy {
        compare!(energy);
        compare!(cost);
        compare!(reliability_inverse);
        compare!(loss);
        compare!(latency);
        compare!(bandwidth_inverse);
    } else {
        compare!(reliability_inverse);
        compare!(loss);
        compare!(latency);
        compare!(bandwidth_inverse);
        compare!(energy);
        compare!(cost);
    }
    compare!(local_penalty);
    ordering
}

fn stable_route_cmp(left: &RouteCandidate, right: &RouteCandidate) -> Ordering {
    left.transport_capability
        .cmp(&right.transport_capability)
        .then_with(|| {
            left.endpoint_id
                .as_opaque()
                .as_str()
                .cmp(right.endpoint_id.as_opaque().as_str())
        })
        .then_with(|| left.address.scheme.cmp(&right.address.scheme))
        .then_with(|| left.address.value.cmp(&right.address.value))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ucr_core::{
        CanonicalTransportError, PolicyDecision, PolicyEvaluator, RouteCandidate, TransportHealth,
        TransportProvider,
    };
    use ucr_model::{
        CapabilityDescriptor, CapabilityMaturity, CommunicationIntent, CorrelationContext,
        EndpointAddress, EndpointDescriptor, EndpointId, EndpointKind, IdentityId,
        IntentConstraints, IntentId, MediaThermalState, OpaqueId, TenantId, TenantScope,
        TransportResourceSnapshot, TransportRouteTelemetry, TransportRoutingHint,
    };

    use super::{TransportOrchestrator, TransportOrchestratorError, TransportRouteOption};

    #[derive(Debug)]
    struct AllowPolicy;
    impl PolicyEvaluator for AllowPolicy {
        fn evaluate_intent(&self, _: &CommunicationIntent) -> PolicyDecision {
            PolicyDecision::Allow
        }
    }

    #[derive(Debug)]
    struct FixedPolicy(PolicyDecision);
    impl PolicyEvaluator for FixedPolicy {
        fn evaluate_intent(&self, _: &CommunicationIntent) -> PolicyDecision {
            self.0
        }
    }

    #[derive(Debug)]
    struct MutableProvider {
        capability: String,
        maturity: Arc<Mutex<CapabilityMaturity>>,
        health: Arc<Mutex<TransportHealth>>,
        calls: Arc<Mutex<Vec<String>>>,
    }
    impl TransportProvider for MutableProvider {
        fn capabilities(&self) -> Vec<CapabilityDescriptor> {
            vec![CapabilityDescriptor {
                id: self.capability.clone(),
                maturity: *self.maturity.lock().expect("maturity"),
                extensions: Vec::new(),
            }]
        }
        fn health(&self) -> TransportHealth {
            *self.health.lock().expect("health")
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
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MockProvider {
        capability: String,
        health: TransportHealth,
        calls: Arc<Mutex<Vec<String>>>,
        result: Result<(), CanonicalTransportError>,
    }
    impl TransportProvider for MockProvider {
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
            self.result
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
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
            payload: b"ciphertext-source".to_vec(),
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
                idempotency_key: None,
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
        cap: &str,
        endpoint: &str,
        rtt: u32,
        cost: u64,
        reliability: u16,
        energy: u8,
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
                transport_capability: cap.to_owned(),
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
                    id: cap.to_owned(),
                    maturity: CapabilityMaturity::Prepared,
                    extensions: Vec::new(),
                }],
                addresses: vec![address],
            },
            telemetry: TransportRouteTelemetry {
                estimated_bandwidth_bps: 5_000_000,
                packet_loss_basis_points: 100,
                jitter_ms: 10,
                rtt_ms: rtt,
                cost_microunits: cost,
                energy_cost_percent: energy,
                reliability_basis_points: reliability,
                recipient_reachable: true,
                privacy_profile: Some("private".to_owned()),
                region: Some("eu".to_owned()),
            },
        }
    }

    #[test]
    fn policy_and_hard_intent_constraints_filter_before_ranking() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let local = MockProvider {
            capability: "ucr.transport.local.tcp".into(),
            health: TransportHealth::Healthy,
            calls: calls.clone(),
            result: Ok(()),
        };
        let internet = MockProvider {
            capability: "ucr.transport.internet.tcp".into(),
            health: TransportHealth::Healthy,
            calls,
            result: Ok(()),
        };
        let mut value = intent();
        value.constraints.allowed_transport_capabilities = vec!["ucr.transport.local.tcp".into()];
        let plan = TransportOrchestrator::new(&AllowPolicy)
            .plan(
                &value,
                resources(),
                &[],
                vec![
                    option(
                        &internet,
                        "ucr.transport.internet.tcp",
                        "inet",
                        20,
                        5,
                        9999,
                        1,
                    ),
                    option(
                        &local,
                        "ucr.transport.local.tcp",
                        "local",
                        100,
                        900,
                        9000,
                        50,
                    ),
                ],
            )
            .expect("plan");
        assert_eq!(plan.route_count(), 1);
        assert_eq!(
            plan.decision().ranked_routes[0].transport_capability,
            "ucr.transport.local.tcp"
        );
    }

    #[test]
    fn hints_change_preferences_but_cannot_name_or_order_routes() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let local = MockProvider {
            capability: "ucr.transport.local.tcp".into(),
            health: TransportHealth::Healthy,
            calls: calls.clone(),
            result: Ok(()),
        };
        let internet = MockProvider {
            capability: "ucr.transport.internet.tcp".into(),
            health: TransportHealth::Healthy,
            calls,
            result: Ok(()),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);
        let baseline = orchestrator
            .plan(
                &intent(),
                resources(),
                &[],
                vec![
                    option(
                        &local,
                        "ucr.transport.local.tcp",
                        "local",
                        80,
                        500,
                        9300,
                        20,
                    ),
                    option(
                        &internet,
                        "ucr.transport.internet.tcp",
                        "inet",
                        20,
                        100,
                        9900,
                        20,
                    ),
                ],
            )
            .expect("baseline");
        assert_eq!(
            baseline.decision().ranked_routes[0].transport_capability,
            "ucr.transport.internet.tcp"
        );
        let preferred = orchestrator
            .plan(
                &intent(),
                resources(),
                &[TransportRoutingHint::PreferLocal],
                vec![
                    option(
                        &local,
                        "ucr.transport.local.tcp",
                        "local",
                        80,
                        500,
                        9300,
                        20,
                    ),
                    option(
                        &internet,
                        "ucr.transport.internet.tcp",
                        "inet",
                        20,
                        100,
                        9900,
                        20,
                    ),
                ],
            )
            .expect("prefer local");
        assert_eq!(
            preferred.decision().ranked_routes[0].transport_capability,
            "ucr.transport.local.tcp"
        );
    }

    #[test]
    fn urgent_priority_prefers_latency_while_background_prefers_resource_cost() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fast = MockProvider {
            capability: "ucr.transport.fast".into(),
            health: TransportHealth::Healthy,
            calls: calls.clone(),
            result: Ok(()),
        };
        let efficient = MockProvider {
            capability: "ucr.transport.efficient".into(),
            health: TransportHealth::Healthy,
            calls,
            result: Ok(()),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);
        let mut urgent = intent();
        urgent.constraints.priority_class = Some(0);
        let plan = orchestrator
            .plan(
                &urgent,
                resources(),
                &[],
                vec![
                    option(&fast, "ucr.transport.fast", "fast", 10, 900, 9500, 80),
                    option(
                        &efficient,
                        "ucr.transport.efficient",
                        "efficient",
                        80,
                        10,
                        9990,
                        1,
                    ),
                ],
            )
            .expect("urgent");
        assert_eq!(
            plan.decision().ranked_routes[0].transport_capability,
            "ucr.transport.fast"
        );
        let mut background = intent();
        background.constraints.priority_class = Some(7);
        let plan = orchestrator
            .plan(
                &background,
                resources(),
                &[],
                vec![
                    option(&fast, "ucr.transport.fast", "fast", 10, 900, 9500, 80),
                    option(
                        &efficient,
                        "ucr.transport.efficient",
                        "efficient",
                        80,
                        10,
                        9990,
                        1,
                    ),
                ],
            )
            .expect("background");
        assert_eq!(
            plan.decision().ranked_routes[0].transport_capability,
            "ucr.transport.efficient"
        );
    }

    #[test]
    fn unreachable_wrong_identity_or_unavailable_routes_never_rank() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = MockProvider {
            capability: "ucr.transport.test".into(),
            health: TransportHealth::Healthy,
            calls,
            result: Ok(()),
        };
        let mut unreachable = option(&provider, "ucr.transport.test", "route", 10, 10, 9999, 1);
        unreachable.telemetry.recipient_reachable = false;
        assert_eq!(
            TransportOrchestrator::new(&AllowPolicy)
                .plan(&intent(), resources(), &[], vec![unreachable])
                .unwrap_err(),
            TransportOrchestratorError::NoEligibleRoute
        );
        let mut wrong = option(&provider, "ucr.transport.test", "wrong", 10, 10, 9999, 1);
        wrong.recipient_endpoint.identity_id = Some(IdentityId::from_opaque(oid("attacker")));
        assert_eq!(
            TransportOrchestrator::new(&AllowPolicy)
                .plan(&intent(), resources(), &[], vec![wrong])
                .unwrap_err(),
            TransportOrchestratorError::NoEligibleRoute
        );
    }

    #[test]
    fn transmit_uses_only_primary_and_does_not_implement_phase25_failover() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let first = MockProvider {
            capability: "ucr.transport.first".into(),
            health: TransportHealth::Healthy,
            calls: calls.clone(),
            result: Err(CanonicalTransportError::Timeout),
        };
        let second = MockProvider {
            capability: "ucr.transport.second".into(),
            health: TransportHealth::Healthy,
            calls: calls.clone(),
            result: Ok(()),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);
        let value = intent();
        let plan = orchestrator
            .plan(
                &value,
                resources(),
                &[TransportRoutingHint::Urgent],
                vec![
                    option(&first, "ucr.transport.first", "first", 5, 10, 9999, 1),
                    option(&second, "ucr.transport.second", "second", 50, 10, 9999, 1),
                ],
            )
            .expect("plan");
        assert_eq!(
            orchestrator.transmit_primary(&value, &plan, b"encrypted"),
            Err(CanonicalTransportError::Timeout)
        );
        assert_eq!(
            *calls.lock().expect("calls"),
            vec!["ucr.transport.first".to_owned()]
        );
    }

    #[test]
    fn stale_constraints_and_runtime_backpressure_fail_before_provider() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = MockProvider {
            capability: "ucr.transport.test".into(),
            health: TransportHealth::Healthy,
            calls: calls.clone(),
            result: Ok(()),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);
        let value = intent();
        let plan = orchestrator
            .plan(
                &value,
                resources(),
                &[],
                vec![option(
                    &provider,
                    "ucr.transport.test",
                    "route",
                    10,
                    10,
                    9999,
                    1,
                )],
            )
            .expect("plan");
        let mut changed = value.clone();
        changed.constraints.max_cost_microunits = Some(5);
        assert_eq!(
            orchestrator.transmit_primary(&changed, &plan, b"encrypted"),
            Err(CanonicalTransportError::PolicyDenied)
        );
        let oversized = vec![0_u8; ucr_protocol::DEFAULT_MAX_PAYLOAD_LEN as usize + 1];
        assert_eq!(
            orchestrator.transmit_primary(&value, &plan, &oversized),
            Err(CanonicalTransportError::ResourceExhausted)
        );
        assert!(calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn privacy_region_cost_and_endpoint_maturity_are_hard_filters() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = MockProvider {
            capability: "ucr.transport.test".into(),
            health: TransportHealth::Healthy,
            calls,
            result: Ok(()),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);

        let mut privacy = option(&provider, "ucr.transport.test", "privacy", 10, 10, 9999, 1);
        privacy.telemetry.privacy_profile = Some("public".to_owned());
        assert_eq!(
            orchestrator
                .plan(&intent(), resources(), &[], vec![privacy])
                .unwrap_err(),
            TransportOrchestratorError::NoEligibleRoute
        );

        let mut region = option(&provider, "ucr.transport.test", "region", 10, 10, 9999, 1);
        region.telemetry.region = Some("us".to_owned());
        assert_eq!(
            orchestrator
                .plan(&intent(), resources(), &[], vec![region])
                .unwrap_err(),
            TransportOrchestratorError::NoEligibleRoute
        );

        let expensive = option(&provider, "ucr.transport.test", "cost", 10, 1_001, 9999, 1);
        assert_eq!(
            orchestrator
                .plan(&intent(), resources(), &[], vec![expensive])
                .unwrap_err(),
            TransportOrchestratorError::NoEligibleRoute
        );

        let mut disabled = option(&provider, "ucr.transport.test", "disabled", 10, 10, 9999, 1);
        disabled.recipient_endpoint.capabilities[0].maturity = CapabilityMaturity::Disabled;
        assert_eq!(
            orchestrator
                .plan(&intent(), resources(), &[], vec![disabled])
                .unwrap_err(),
            TransportOrchestratorError::NoEligibleRoute
        );
    }

    #[test]
    fn duplicate_routes_and_non_allow_policy_fail_closed() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = MockProvider {
            capability: "ucr.transport.test".into(),
            health: TransportHealth::Healthy,
            calls,
            result: Ok(()),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);
        assert_eq!(
            orchestrator
                .plan(
                    &intent(),
                    resources(),
                    &[],
                    vec![
                        option(&provider, "ucr.transport.test", "same", 10, 10, 9999, 1),
                        option(&provider, "ucr.transport.test", "same", 20, 20, 9998, 2),
                    ],
                )
                .unwrap_err(),
            TransportOrchestratorError::DuplicateRoute
        );
        for decision in [PolicyDecision::Deny, PolicyDecision::PendingNoAllowedRoute] {
            let policy = FixedPolicy(decision);
            let error = TransportOrchestrator::new(&policy)
                .plan(
                    &intent(),
                    resources(),
                    &[],
                    vec![option(
                        &provider,
                        "ucr.transport.test",
                        "policy",
                        10,
                        10,
                        9999,
                        1,
                    )],
                )
                .unwrap_err();
            assert!(matches!(
                (decision, error),
                (
                    PolicyDecision::Deny,
                    TransportOrchestratorError::PolicyDenied
                ) | (
                    PolicyDecision::PendingNoAllowedRoute,
                    TransportOrchestratorError::PolicyPending
                )
            ));
        }
    }

    #[test]
    fn provider_health_and_capability_are_revalidated_before_primary_transmit() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let health = Arc::new(Mutex::new(TransportHealth::Healthy));
        let maturity = Arc::new(Mutex::new(CapabilityMaturity::Prepared));
        let provider = MutableProvider {
            capability: "ucr.transport.mutable".into(),
            maturity: maturity.clone(),
            health: health.clone(),
            calls: calls.clone(),
        };
        let orchestrator = TransportOrchestrator::new(&AllowPolicy);
        let value = intent();
        let plan = orchestrator
            .plan(
                &value,
                resources(),
                &[],
                vec![option(
                    &provider,
                    "ucr.transport.mutable",
                    "mutable",
                    10,
                    10,
                    9999,
                    1,
                )],
            )
            .expect("plan");

        *health.lock().expect("health") = TransportHealth::Unavailable;
        assert_eq!(
            orchestrator.transmit_primary(&value, &plan, b"encrypted"),
            Err(CanonicalTransportError::Unavailable)
        );
        assert!(calls.lock().expect("calls").is_empty());

        *health.lock().expect("health") = TransportHealth::Healthy;
        *maturity.lock().expect("maturity") = CapabilityMaturity::Disabled;
        assert_eq!(
            orchestrator.transmit_primary(&value, &plan, b"encrypted"),
            Err(CanonicalTransportError::UnsupportedCapability)
        );
        assert!(calls.lock().expect("calls").is_empty());
    }
}

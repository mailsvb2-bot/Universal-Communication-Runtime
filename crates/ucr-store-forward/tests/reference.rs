use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, Ordering},
};

use ucr_core::{
    CanonicalTransportError, ClassifiedTransportFailure, CommunicationIntentStore,
    ConversationStore, DeliveryStore, MessageStore, PolicyDecision, PolicyEvaluator,
    RouteCandidate, StoreForwardStore, TransportFailureDisposition, TransportHealth,
    TransportProvider,
};
use ucr_model::{
    ActorId, ActorKind, ActorRef, CapabilityDescriptor, CapabilityMaturity, CommunicationIntent,
    ConversationKind, ConversationRecord, ConversationRef, CorrelationContext, DeliveryPolicy,
    DeliveryState, DeviceId, DeviceRef, EndpointAddress, EndpointDescriptor, EndpointId,
    EndpointKind, IdentityId, IntentConstraints, IntentId, MediaThermalState, MessageEnvelope,
    MessageId, OpaqueId, OriginRef, PrincipalId, StoreForwardId, StoreForwardJob,
    StoreForwardOutcome, StoreForwardPolicy, TenantId, TenantScope, TransportResourceSnapshot,
    TransportRouteTelemetry,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_store_forward::{
    STORE_FORWARD_INTERNET_CAPABILITY, StoreForwardClock, StoreForwardRuntime,
};
use ucr_transport_orchestrator::TransportRouteOption;

#[derive(Debug, Default)]
struct AllowPolicy;

impl PolicyEvaluator for AllowPolicy {
    fn evaluate_intent(&self, _intent: &CommunicationIntent) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug)]
struct MutableClock(AtomicI64);

impl MutableClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl StoreForwardClock for MutableClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy)]
enum ProviderOutcome {
    Accepted,
    NotAccepted,
    AcceptanceUnknown,
}

#[derive(Debug)]
struct MockProvider {
    outcome: ProviderOutcome,
    calls: Arc<Mutex<u32>>,
}

impl MockProvider {
    fn new(outcome: ProviderOutcome) -> Self {
        Self {
            outcome,
            calls: Arc::new(Mutex::new(0)),
        }
    }

    fn calls(&self) -> u32 {
        *self.calls.lock().expect("calls lock")
    }
}

impl TransportProvider for MockProvider {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: STORE_FORWARD_INTERNET_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }]
    }

    fn health(&self) -> TransportHealth {
        TransportHealth::Healthy
    }

    fn transmit(
        &self,
        _scope: &TenantScope,
        _route: &RouteCandidate,
        _encrypted_envelope: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        match self.outcome {
            ProviderOutcome::Accepted => Ok(()),
            ProviderOutcome::NotAccepted => Err(CanonicalTransportError::Unavailable),
            ProviderOutcome::AcceptanceUnknown => Err(CanonicalTransportError::Timeout),
        }
    }

    fn transmit_classified(
        &self,
        _scope: &TenantScope,
        _route: &RouteCandidate,
        _encrypted_envelope: &[u8],
    ) -> Result<(), ClassifiedTransportFailure> {
        *self.calls.lock().expect("calls lock") += 1;
        match self.outcome {
            ProviderOutcome::Accepted => Ok(()),
            ProviderOutcome::NotAccepted => Err(ClassifiedTransportFailure {
                error: CanonicalTransportError::Unavailable,
                disposition: TransportFailureDisposition::NotAccepted,
            }),
            ProviderOutcome::AcceptanceUnknown => Err(ClassifiedTransportFailure {
                error: CanonicalTransportError::Timeout,
                disposition: TransportFailureDisposition::AcceptanceUnknown,
            }),
        }
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("sf-tenant")),
        namespace_id: None,
    }
}

fn target_identity() -> IdentityId {
    IdentityId::from_opaque(oid("sf-target"))
}

fn resources() -> TransportResourceSnapshot {
    TransportResourceSnapshot {
        battery_percent: 80,
        external_power: false,
        thermal_state: MediaThermalState::Nominal,
    }
}

fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ucr_model::ConversationId::from_opaque(oid("sf-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}

fn message() -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid("sf-message")),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("sf-actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("sf-device")),
            identity_id: IdentityId::from_opaque(oid("sf-author-identity")),
        },
        created_at_unix_ms: 1_000,
        logical_order: 1,
        content: b"message".to_vec(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("sf-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("sf-message-correlation"),
            causation_id: None,
            idempotency_key: Some("sf-message-idempotency".to_owned()),
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    }
}

fn intent() -> CommunicationIntent {
    CommunicationIntent {
        intent_id: IntentId::from_opaque(oid("sf-intent")),
        scope: scope(),
        target_identity_id: target_identity(),
        payload: b"intent-payload".to_vec(),
        constraints: IntentConstraints {
            allowed_transport_capabilities: Vec::new(),
            forbidden_transport_capabilities: Vec::new(),
            privacy_profile: None,
            region_constraint: None,
            max_cost_microunits: None,
            priority_class: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("sf-intent-correlation"),
            causation_id: None,
            idempotency_key: Some("sf-intent-idempotency".to_owned()),
        },
        extensions: Vec::new(),
    }
}

fn job() -> StoreForwardJob {
    StoreForwardJob {
        store_forward_id: StoreForwardId::from_opaque(oid("sf-job")),
        scope: scope(),
        intent_id: intent().intent_id,
        message_id: message().message_id,
        encrypted_envelope: b"opaque-encrypted-envelope".to_vec(),
        policy: StoreForwardPolicy {
            max_delivery_attempts: 3,
            base_retry_delay_ms: 100,
            max_retry_delay_ms: 1_000,
            lease_duration_ms: 5_000,
            expires_at_unix_ms: None,
        },
        attempts_used: 0,
        next_attempt_at_unix_ms: 1_000,
        last_delivery_id: None,
    }
}

fn seed(store: &MemoryLocalStore) {
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    store.persist_message(&message()).expect("message");
    store
        .persist_communication_intent(&intent())
        .expect("intent");
}

fn option<'a>(provider: &'a dyn TransportProvider, endpoint: &str) -> TransportRouteOption<'a> {
    let endpoint_id = EndpointId::from_opaque(oid(endpoint));
    let address = EndpointAddress {
        scheme: "ucr.internet.tcp".to_owned(),
        value: b"203.0.113.10:443".to_vec(),
    };
    TransportRouteOption {
        provider,
        route: RouteCandidate {
            endpoint_id: endpoint_id.clone(),
            transport_capability: STORE_FORWARD_INTERNET_CAPABILITY.to_owned(),
            address: address.clone(),
        },
        recipient_endpoint: EndpointDescriptor {
            endpoint_id,
            kind: EndpointKind::Device,
            identity_id: Some(target_identity()),
            device_id: Some(DeviceId::from_opaque(oid("sf-recipient-device"))),
            capabilities: provider.capabilities(),
            addresses: vec![address],
        },
        telemetry: TransportRouteTelemetry {
            estimated_bandwidth_bps: 1_000_000,
            packet_loss_basis_points: 0,
            jitter_ms: 1,
            rtt_ms: 10,
            cost_microunits: 0,
            energy_cost_percent: 1,
            reliability_basis_points: 10_000,
            recipient_reachable: true,
            privacy_profile: None,
            region: None,
        },
    }
}

#[test]
fn no_route_reschedules_without_consuming_delivery_attempt() {
    let store = MemoryLocalStore::default();
    seed(&store);
    let clock = MutableClock::new(1_000);
    let policy = AllowPolicy;
    let runtime = StoreForwardRuntime::new(&store, &policy, &clock);
    let initial = job();
    runtime.enqueue(&initial).expect("enqueue");

    assert_eq!(
        runtime.process_one(
            &scope(),
            &initial.store_forward_id,
            resources(),
            &[],
            Vec::new()
        ),
        Ok(StoreForwardOutcome::RescheduledNoRoute)
    );
    let loaded = store
        .store_forward_job(&scope(), &initial.store_forward_id)
        .expect("load")
        .expect("job remains");
    assert_eq!(loaded.attempts_used, 0);
    assert!(loaded.last_delivery_id.is_none());
    assert_eq!(loaded.next_attempt_at_unix_ms, 1_100);
}

#[test]
fn proven_failure_gets_new_delivery_id_and_later_success_tombstones_job() {
    let store = MemoryLocalStore::default();
    seed(&store);
    let clock = MutableClock::new(1_000);
    let policy = AllowPolicy;
    let runtime = StoreForwardRuntime::new(&store, &policy, &clock);
    let initial = job();
    runtime.enqueue(&initial).expect("enqueue");
    let failing = MockProvider::new(ProviderOutcome::NotAccepted);

    assert_eq!(
        runtime.process_one(
            &scope(),
            &initial.store_forward_id,
            resources(),
            &[],
            vec![option(&failing, "sf-endpoint-fail")],
        ),
        Ok(StoreForwardOutcome::RescheduledAfterFailure)
    );
    let after_first = store
        .store_forward_job(&scope(), &initial.store_forward_id)
        .expect("load")
        .expect("job remains");
    assert_eq!(after_first.attempts_used, 1);
    let first_delivery = after_first
        .last_delivery_id
        .clone()
        .expect("first delivery");
    assert_eq!(
        store
            .delivery_attempt(&scope(), &first_delivery)
            .expect("delivery")
            .expect("first exists")
            .state,
        DeliveryState::Failed
    );

    clock.set(after_first.next_attempt_at_unix_ms);
    let accepted = MockProvider::new(ProviderOutcome::Accepted);
    assert_eq!(
        runtime.process_one(
            &scope(),
            &initial.store_forward_id,
            resources(),
            &[],
            vec![option(&accepted, "sf-endpoint-ok")],
        ),
        Ok(StoreForwardOutcome::AcceptedByTransport)
    );
    assert!(
        store
            .store_forward_job(&scope(), &initial.store_forward_id)
            .expect("load completed")
            .is_none()
    );
    assert_eq!(
        runtime.enqueue(&initial),
        Ok(ucr_core::DurableRecordStatus::Duplicate)
    );
    assert_eq!(failing.calls(), 1);
    assert_eq!(accepted.calls(), 1);
}

#[test]
fn ambiguous_acceptance_blocks_automatic_replay_even_after_lease_expiry() {
    let store = MemoryLocalStore::default();
    seed(&store);
    let clock = MutableClock::new(1_000);
    let policy = AllowPolicy;
    let runtime = StoreForwardRuntime::new(&store, &policy, &clock);
    let initial = job();
    runtime.enqueue(&initial).expect("enqueue");
    let provider = MockProvider::new(ProviderOutcome::AcceptanceUnknown);

    assert_eq!(
        runtime.process_one(
            &scope(),
            &initial.store_forward_id,
            resources(),
            &[],
            vec![option(&provider, "sf-endpoint-unknown")],
        ),
        Ok(StoreForwardOutcome::AcceptanceUnknown)
    );
    let loaded = store
        .store_forward_job(&scope(), &initial.store_forward_id)
        .expect("load")
        .expect("job remains");
    let delivery_id = loaded.last_delivery_id.clone().expect("delivery id");
    assert_eq!(loaded.attempts_used, 1);
    assert_eq!(
        store
            .delivery_attempt(&scope(), &delivery_id)
            .expect("delivery")
            .expect("exists")
            .state,
        DeliveryState::InFlight
    );

    clock.set(50_000);
    assert_eq!(runtime.due_jobs(&scope(), 8), Ok(Vec::new()));
    assert_eq!(
        runtime.process_one(
            &scope(),
            &initial.store_forward_id,
            resources(),
            &[],
            vec![option(&provider, "sf-endpoint-unknown-2")],
        ),
        Ok(StoreForwardOutcome::AcceptanceUnknown)
    );
    assert_eq!(
        provider.calls(),
        1,
        "ambiguous acceptance must never auto-replay"
    );
}

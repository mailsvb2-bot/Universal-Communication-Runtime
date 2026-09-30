use std::time::Duration;

use ucr_core::{
    EventJournalStore, EventSubscriptionStore, EventWebhookDispatcher, SystemEventDeliveryClock,
    WebhookDispatchOutcome,
};
use ucr_model::{
    ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EventEnvelope, EventId,
    EventSubscription, EventSubscriptionId, EventSubscriptionMode, EventSubscriptionStart,
    IdentityId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, ProtocolVersion,
    ScopedPrincipal, TenantId, TenantScope,
};
use ucr_storage_memory::MemoryLocalStore;
use ucr_webhook::{
    HardenedWebhookSink, NativeTlsWebhookExecutor, SystemWebhookDnsResolver, WebhookSigningSecret,
};

const EVENT_TYPE: &str = "ucr.conformance.public-webhook.v1";

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-public-webhook-conformance")),
        namespace_id: None,
    }
}

fn owner(scope: &TenantScope) -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("integration-public-webhook-conformance")),
            kind: PrincipalKind::ServiceAccount,
        },
    }
}

fn subscription(scope: &TenantScope, endpoint: String) -> EventSubscription {
    EventSubscription {
        subscription_id: EventSubscriptionId::from_opaque(oid(
            "subscription-public-webhook-conformance",
        )),
        scope: scope.clone(),
        mode: EventSubscriptionMode::Webhook,
        webhook_uri: Some(endpoint),
        event_types: vec![EVENT_TYPE.to_owned()],
        max_in_flight: 1,
        max_attempts: 3,
        start: EventSubscriptionStart::Beginning,
    }
}

fn event(scope: &TenantScope, owner: &ScopedPrincipal) -> EventEnvelope {
    EventEnvelope {
        event_id: EventId::from_opaque(oid("event-public-webhook-conformance")),
        scope: scope.clone(),
        event_type: EVENT_TYPE.to_owned(),
        payload: b"synthetic public HTTPS webhook conformance event".to_vec(),
        actor: ActorRef {
            actor_id: ActorId::from_opaque(oid("actor-public-webhook-conformance")),
            kind: ActorKind::System,
            on_behalf_of: Some(owner.principal.principal_id.clone()),
        },
        source_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("device-public-webhook-conformance")),
            identity_id: IdentityId::from_opaque(oid("identity-public-webhook-conformance")),
        },
        wall_time_unix_ms: 1_000,
        logical_order: 1,
        correlation: CorrelationContext {
            correlation_id: oid("correlation-public-webhook-conformance"),
            causation_id: None,
            idempotency_key: None,
        },
        schema_version: ProtocolVersion { major: 1, minor: 0 },
        integrity_metadata: Vec::new(),
        extensions: Vec::new(),
    }
}

#[test]
#[ignore = "requires explicit public Internet conformance endpoint"]
fn dispatcher_delivers_over_real_public_https_and_acks() {
    let endpoint = std::env::var("UCR_PUBLIC_WEBHOOK_CONFORMANCE_URL")
        .expect("UCR_PUBLIC_WEBHOOK_CONFORMANCE_URL must be configured explicitly");
    let scope = scope();
    let owner = owner(&scope);
    let subscription = subscription(&scope, endpoint);
    let subscription_id = subscription.subscription_id.clone();
    let store = MemoryLocalStore::default();

    store
        .persist_event_subscription(&owner, &subscription)
        .expect("persist webhook subscription");
    store
        .append_event(&event(&scope, &owner))
        .expect("append synthetic webhook event");

    let executor =
        NativeTlsWebhookExecutor::new(Duration::from_secs(10)).expect("bounded HTTPS executor");
    let sink = HardenedWebhookSink::new(
        SystemWebhookDnsResolver,
        executor,
        WebhookSigningSecret::from_bytes([0xA5; 32]),
    );
    let clock = SystemEventDeliveryClock;
    let dispatcher = EventWebhookDispatcher::new(&clock, &store, &sink);

    assert_eq!(
        dispatcher.dispatch_once(&scope, &subscription_id),
        Ok(WebhookDispatchOutcome::Delivered)
    );
    assert_eq!(
        dispatcher.dispatch_once(&scope, &subscription_id),
        Ok(WebhookDispatchOutcome::Idle)
    );
}

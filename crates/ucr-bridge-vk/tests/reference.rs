use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use ucr_bridge::{
    BridgeError, BridgeProvider, BridgeProviderFailure, BridgeProviderFailureKind, BridgeRuntime,
};
use ucr_bridge_vk::{
    VK_PROVIDER_ID, VkApiClient, VkApiFailure, VkEventBatch, VkPeerTarget, VkProvider,
    VkSentMessage, VkTextEvent,
};
use ucr_core::{AuthorizationEvaluator, ConversationStore, MessageStore};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AuthorizationRequest, BridgeAction, BridgeActionId,
    BridgeCapability, BridgeDataPermission, BridgeEventCursor, ConversationId, ConversationKind,
    ConversationRecord, ConversationRef, CorrelationContext, DeliveryPolicy, DeliveryState,
    DeviceId, DeviceRef, IdentityId, IntegrationId, MessageEnvelope, MessageId, NamespaceId,
    OpaqueId, OriginRef, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId,
    TenantScope,
};
use ucr_protocol::CanonicalError;
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Default, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ScriptedClient {
    sends: AtomicUsize,
    polls: AtomicUsize,
    random_ids: Mutex<Vec<i32>>,
    send_steps: Mutex<Vec<Result<VkSentMessage, VkApiFailure>>>,
    poll_steps: Mutex<Vec<Result<VkEventBatch, VkApiFailure>>>,
}

impl ScriptedClient {
    fn new(
        send_steps: Vec<Result<VkSentMessage, VkApiFailure>>,
        poll_steps: Vec<Result<VkEventBatch, VkApiFailure>>,
    ) -> Self {
        Self {
            sends: AtomicUsize::new(0),
            polls: AtomicUsize::new(0),
            random_ids: Mutex::new(vec![]),
            send_steps: Mutex::new(send_steps.into_iter().rev().collect()),
            poll_steps: Mutex::new(poll_steps.into_iter().rev().collect()),
        }
    }
}

impl VkApiClient for ScriptedClient {
    fn send_text(
        &self,
        _target: VkPeerTarget,
        random_id: i32,
        _text: &str,
    ) -> Result<VkSentMessage, VkApiFailure> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        self.random_ids.lock().expect("random ids").push(random_id);
        self.send_steps
            .lock()
            .expect("send steps")
            .pop()
            .unwrap_or(Ok(VkSentMessage { message_id: 999 }))
    }

    fn poll_text_events(
        &self,
        cursor: Option<&str>,
        _limit: usize,
    ) -> Result<VkEventBatch, VkApiFailure> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        self.poll_steps
            .lock()
            .expect("poll steps")
            .pop()
            .unwrap_or(Ok(VkEventBatch {
                events: vec![],
                next_ts: cursor.unwrap_or("1").to_owned(),
            }))
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("vk-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("vk-namespace"))),
    }
}
fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("vk-actor")),
            kind: PrincipalKind::Person,
        },
    }
}
fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("vk-integration"))
}
fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("vk-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}
fn message(id: &str, policy: DeliveryPolicy) -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid(id)),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("vk-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("vk-device")),
            identity_id: IdentityId::from_opaque(oid("vk-identity")),
        },
        created_at_unix_ms: 1_700_000_000_000,
        logical_order: 1,
        content: b"hello vk".to_vec(),
        attachment_ids: vec![],
        reply_to: None,
        relations: vec![],
        crypto_metadata: None,
        delivery_policy: policy,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("vk-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
        extensions: vec![],
        external_mappings: vec![],
        signature: None,
    }
}
fn action(id: &str, canonical: &MessageEnvelope) -> BridgeAction {
    BridgeAction {
        action_id: BridgeActionId::from_opaque(oid(id)),
        scope: scope(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        external_target: b"2000000001".to_vec(),
        canonical_message_id: Some(canonical.message_id.clone()),
        provider_payload: canonical.content.clone(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid(&format!("action-corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("action-idem-{id}")),
        },
    }
}
fn direct_action(id: &str) -> BridgeAction {
    BridgeAction {
        action_id: BridgeActionId::from_opaque(oid(id)),
        scope: scope(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        external_target: b"2000000001".to_vec(),
        canonical_message_id: Some(MessageId::from_opaque(oid("vk-direct-message"))),
        provider_payload: b"hello vk".to_vec(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid("vk-direct-correlation"),
            causation_id: None,
            idempotency_key: Some("vk-direct-idempotency".to_owned()),
        },
    }
}

#[test]
fn vk_manifest_declares_only_real_phase33_text_surface() {
    let provider = VkProvider::new(ScriptedClient::new(vec![], vec![]));
    let manifest = provider.manifest();
    assert_eq!(manifest.provider_id, VK_PROVIDER_ID);
    assert_eq!(manifest.capabilities, vec![BridgeCapability::Text]);
    assert_eq!(
        manifest.permissions,
        vec![
            BridgeDataPermission::MessageContent,
            BridgeDataPermission::ExternalIdentityReferences,
            BridgeDataPermission::InboundEvents,
        ]
    );
}

#[test]
fn vk_send_uses_stable_random_id_and_returns_no_delivery_claim() {
    let provider = VkProvider::new(ScriptedClient::new(
        vec![
            Ok(VkSentMessage { message_id: 321 }),
            Ok(VkSentMessage { message_id: 322 }),
        ],
        vec![],
    ));
    let action = direct_action("stable-action");
    let first = provider.execute(&action).expect("first");
    let second = provider
        .execute(&action)
        .expect("second direct provider call");
    assert_eq!(
        first.external_message_id.as_deref(),
        Some(b"321".as_slice())
    );
    assert!(first.degradation.is_none());
    assert_eq!(
        second.external_message_id.as_deref(),
        Some(b"322".as_slice())
    );
    let ids = provider.client().random_ids.lock().expect("ids");
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1]);
    assert_ne!(ids[0], 0);
}

#[test]
fn vk_failure_classification_prevents_blind_duplicate_retry() {
    let provider = VkProvider::new(ScriptedClient::new(
        vec![Err(VkApiFailure::Ambiguous)],
        vec![],
    ));
    assert_eq!(
        provider.execute(&direct_action("ambiguous-action")),
        Err(BridgeProviderFailure::AcceptanceUnknown(
            BridgeProviderFailureKind::Unavailable
        ))
    );
    let rate = VkProvider::new(ScriptedClient::new(
        vec![Err(VkApiFailure::RateLimited)],
        vec![],
    ));
    assert_eq!(
        rate.execute(&direct_action("rate-action")),
        Err(BridgeProviderFailure::NotAccepted(
            BridgeProviderFailureKind::RateLimited
        ))
    );
}

#[test]
fn vk_poll_maps_text_and_opaque_ts_cursor() {
    let provider = VkProvider::new(ScriptedClient::new(
        vec![],
        vec![Ok(VkEventBatch {
            events: vec![VkTextEvent {
                event_id: "event-51".to_owned(),
                peer_id: 2_000_000_001,
                actor_id: 77,
                text: "inbound".to_owned(),
                occurred_at_unix_seconds: 1_700_000_000,
            }],
            next_ts: "52".to_owned(),
        })],
    ));
    let page = provider
        .poll_events(
            &scope(),
            &integration(),
            Some(&BridgeEventCursor {
                token: b"50".to_vec(),
            }),
            10,
        )
        .expect("page");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].external_event_id, b"event-51");
    assert_eq!(page.events[0].external_conversation_id, b"2000000001");
    assert_eq!(
        page.events[0].external_actor_id.as_deref(),
        Some(b"77".as_slice())
    );
    assert_eq!(page.events[0].payload, b"inbound");
    assert_eq!(page.next_cursor.expect("cursor").token, b"52");
}

#[test]
fn vk_runtime_reuses_core_policy_and_phase31_dedup_ledger() {
    let store = MemoryLocalStore::default();
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    let provider = VkProvider::new(ScriptedClient::new(
        vec![Ok(VkSentMessage { message_id: 777 })],
        vec![],
    ));
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    let forbidden = message("vk-forbidden", DeliveryPolicy::NoExternalBridge);
    store.persist_message(&forbidden).expect("forbidden");
    assert_eq!(
        runtime.execute(
            &actor(),
            &action("vk-forbidden-action", &forbidden),
            &provider
        ),
        Err(BridgeError::ExternalBridgeForbidden)
    );
    assert_eq!(provider.client().sends.load(Ordering::SeqCst), 0);

    let allowed = message("vk-allowed", DeliveryPolicy::Durable);
    store.persist_message(&allowed).expect("allowed");
    let outbound = action("vk-allowed-action", &allowed);
    let first = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("send");
    let replay = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(provider.client().sends.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .message(&scope(), &allowed.message_id)
            .expect("load")
            .expect("message")
            .delivery_state,
        DeliveryState::Persisted
    );
}

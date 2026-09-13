use std::sync::atomic::{AtomicUsize, Ordering};

use ucr_bridge::{BridgeError, BridgeRuntime};
use ucr_bridge_vk::{
    VkAccessToken, VkApiClient, VkApiFailure, VkEventBatch, VkPeerTarget, VkProvider,
    VkSentMessage, VkTextEvent,
};
use ucr_core::{AuthorizationEvaluator, ConversationStore, MessageStore};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AuthorizationRequest, BridgeAction, BridgeActionId,
    BridgeCapability, BridgeEventCursor, ConversationId, ConversationKind, ConversationRecord,
    ConversationRef, CorrelationContext, DeliveryPolicy, DeliveryState, DeviceId, DeviceRef,
    IdentityId, IntegrationId, MessageEnvelope, MessageId, NamespaceId, OpaqueId, OriginRef,
    PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
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
struct CountingVkApi {
    sends: AtomicUsize,
    polls: AtomicUsize,
}
impl CountingVkApi {
    const fn new() -> Self {
        Self {
            sends: AtomicUsize::new(0),
            polls: AtomicUsize::new(0),
        }
    }
}
impl VkApiClient for CountingVkApi {
    fn send_text(
        &self,
        _target: VkPeerTarget,
        _random_id: i32,
        _text: &str,
    ) -> Result<VkSentMessage, VkApiFailure> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(VkSentMessage { message_id: 55 })
    }

    fn poll_text_events(
        &self,
        _cursor: Option<&str>,
        _limit: usize,
    ) -> Result<VkEventBatch, VkApiFailure> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(VkEventBatch {
            events: vec![VkTextEvent {
                event_id: "event-91".to_owned(),
                peer_id: 2_000_000_999,
                actor_id: 44,
                text: "provider text".to_owned(),
                occurred_at_unix_seconds: 1_700_000_000,
            }],
            next_ts: "92".to_owned(),
        })
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("vk-threat-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("vk-threat-namespace"))),
    }
}
fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("vk-threat-actor")),
            kind: PrincipalKind::Person,
        },
    }
}
fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("vk-threat-integration"))
}
fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("vk-threat-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}
fn message() -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid("vk-threat-message")),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("vk-threat-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("vk-threat-device")),
            identity_id: IdentityId::from_opaque(oid("vk-threat-identity")),
        },
        created_at_unix_ms: 1_700_000_000_000,
        logical_order: 1,
        content: b"must stay inside core".to_vec(),
        attachment_ids: vec![],
        reply_to: None,
        relations: vec![],
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::NoExternalBridge,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("vk-threat-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("vk-threat-message-correlation"),
            causation_id: None,
            idempotency_key: Some("vk-threat-message".to_owned()),
        },
        extensions: vec![],
        external_mappings: vec![],
        signature: None,
    }
}

#[test]
fn compromised_vk_boundary_cannot_bypass_core_policy_or_choose_ucr_scope() {
    let store = MemoryLocalStore::default();
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    let canonical = message();
    store.persist_message(&canonical).expect("message");

    let provider = VkProvider::new(CountingVkApi::new());
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    let outbound = BridgeAction {
        action_id: BridgeActionId::from_opaque(oid("vk-threat-action")),
        scope: scope(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        external_target: b"2000000999".to_vec(),
        canonical_message_id: Some(canonical.message_id),
        provider_payload: b"must stay inside core".to_vec(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid("vk-threat-action-correlation"),
            causation_id: None,
            idempotency_key: Some("vk-threat-action".to_owned()),
        },
    };
    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::ExternalBridgeForbidden)
    );
    assert_eq!(provider.client().sends.load(Ordering::SeqCst), 0);

    let page = runtime
        .poll_events(
            &actor(),
            &integration(),
            &provider,
            Some(&BridgeEventCursor {
                token: b"91".to_vec(),
            }),
            10,
        )
        .expect("page");
    assert_eq!(provider.client().polls.load(Ordering::SeqCst), 1);
    assert_eq!(page.events[0].scope, scope());
    assert_eq!(page.events[0].integration_id, integration());
    assert_eq!(page.events[0].external_conversation_id, b"2000000999");

    let token = VkAccessToken::new("vk1.secret-token_ABC").expect("token");
    assert!(!format!("{token:?}").contains("secret-token"));
}

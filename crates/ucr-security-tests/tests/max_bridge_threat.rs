use std::sync::atomic::{AtomicUsize, Ordering};

use ucr_bridge::{BridgeError, BridgeRuntime};
use ucr_bridge_max::{
    MaxApiClient, MaxApiFailure, MaxBotToken, MaxProvider, MaxSentMessage, MaxTarget,
    MaxTextUpdate, MaxUpdateBatch,
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
struct CountingMaxApi {
    sends: AtomicUsize,
    polls: AtomicUsize,
}
impl CountingMaxApi {
    const fn new() -> Self {
        Self {
            sends: AtomicUsize::new(0),
            polls: AtomicUsize::new(0),
        }
    }
}
impl MaxApiClient for CountingMaxApi {
    fn send_text(&self, _target: MaxTarget, _text: &str) -> Result<MaxSentMessage, MaxApiFailure> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(MaxSentMessage {
            message_id: "mid.55".to_owned(),
        })
    }

    fn poll_text_updates(
        &self,
        marker: Option<i64>,
        _limit: usize,
    ) -> Result<MaxUpdateBatch, MaxApiFailure> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(MaxUpdateBatch {
            updates: vec![MaxTextUpdate {
                event_id: "mid.91".to_owned(),
                chat_id: -999,
                actor_id: Some(44),
                text: "provider text".to_owned(),
                occurred_at_unix_ms: 1_700_000_000_123,
            }],
            next_marker: marker.or(Some(92)),
        })
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("max-threat-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("max-threat-namespace"))),
    }
}
fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("max-threat-actor")),
            kind: PrincipalKind::Person,
        },
    }
}
fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("max-threat-integration"))
}
fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("max-threat-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}
fn message() -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid("max-threat-message")),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("max-threat-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("max-threat-device")),
            identity_id: IdentityId::from_opaque(oid("max-threat-identity")),
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
            principal_id: Some(PrincipalId::from_opaque(oid("max-threat-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("max-threat-message-correlation"),
            causation_id: None,
            idempotency_key: Some("max-threat-message".to_owned()),
        },
        extensions: vec![],
        external_mappings: vec![],
        signature: None,
    }
}

#[test]
fn compromised_max_boundary_cannot_bypass_core_policy_or_choose_ucr_scope() {
    let store = MemoryLocalStore::default();
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    let canonical = message();
    store.persist_message(&canonical).expect("message");

    let provider = MaxProvider::new(CountingMaxApi::new());
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    let outbound = BridgeAction {
        action_id: BridgeActionId::from_opaque(oid("max-threat-action")),
        scope: scope(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        external_target: b"chat:-999".to_vec(),
        canonical_message_id: Some(canonical.message_id),
        provider_payload: b"must stay inside core".to_vec(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid("max-threat-action-correlation"),
            causation_id: None,
            idempotency_key: Some("max-threat-action".to_owned()),
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
    assert_eq!(page.events[0].external_conversation_id, b"chat:-999");

    let token = MaxBotToken::new("max.secret-token_ABC").expect("token");
    assert!(!format!("{token:?}").contains("secret-token"));
}

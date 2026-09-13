use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use ucr_bridge::{
    BridgeError, BridgeProvider, BridgeProviderFailure, BridgeProviderFailureKind, BridgeRuntime,
};
use ucr_bridge_telegram::{
    TELEGRAM_PROVIDER_ID, TelegramApiClient, TelegramApiFailure, TelegramProvider,
    TelegramSentMessage, TelegramTextUpdate, TelegramUpdateBatch,
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
    send_steps: Mutex<Vec<Result<TelegramSentMessage, TelegramApiFailure>>>,
    poll_steps: Mutex<Vec<Result<TelegramUpdateBatch, TelegramApiFailure>>>,
    send_calls: AtomicUsize,
    poll_calls: AtomicUsize,
    last_poll: Mutex<Option<(Option<i64>, usize)>>,
}

impl ScriptedClient {
    fn new(
        send_steps: Vec<Result<TelegramSentMessage, TelegramApiFailure>>,
        poll_steps: Vec<Result<TelegramUpdateBatch, TelegramApiFailure>>,
    ) -> Self {
        Self {
            send_steps: Mutex::new(send_steps.into_iter().rev().collect()),
            poll_steps: Mutex::new(poll_steps.into_iter().rev().collect()),
            send_calls: AtomicUsize::new(0),
            poll_calls: AtomicUsize::new(0),
            last_poll: Mutex::new(None),
        }
    }

    fn send_calls(&self) -> usize {
        self.send_calls.load(Ordering::SeqCst)
    }

    fn poll_calls(&self) -> usize {
        self.poll_calls.load(Ordering::SeqCst)
    }
}

impl TelegramApiClient for ScriptedClient {
    fn send_text(
        &self,
        _target: &ucr_bridge_telegram::TelegramChatTarget,
        _text: &str,
    ) -> Result<TelegramSentMessage, TelegramApiFailure> {
        self.send_calls.fetch_add(1, Ordering::SeqCst);
        self.send_steps
            .lock()
            .expect("send steps")
            .pop()
            .unwrap_or(Ok(TelegramSentMessage { message_id: 999 }))
    }

    fn poll_text_updates(
        &self,
        offset: Option<i64>,
        limit: usize,
    ) -> Result<TelegramUpdateBatch, TelegramApiFailure> {
        self.poll_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_poll.lock().expect("last poll") = Some((offset, limit));
        self.poll_steps
            .lock()
            .expect("poll steps")
            .pop()
            .unwrap_or(Ok(TelegramUpdateBatch {
                updates: vec![],
                next_offset: offset,
            }))
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("telegram-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("telegram-namespace"))),
    }
}

fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("telegram-actor")),
            kind: PrincipalKind::Person,
        },
    }
}

fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("telegram-integration"))
}

fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("telegram-conversation")),
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
            actor_id: ActorId::from_opaque(oid("telegram-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("telegram-device")),
            identity_id: IdentityId::from_opaque(oid("telegram-identity")),
        },
        created_at_unix_ms: 1_700_000_000_000,
        logical_order: 1,
        content: b"hello telegram".to_vec(),
        attachment_ids: vec![],
        reply_to: None,
        relations: vec![],
        crypto_metadata: None,
        delivery_policy: policy,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("telegram-origin"))),
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
        external_target: b"-1001234567890".to_vec(),
        canonical_message_id: Some(canonical.message_id.clone()),
        provider_payload: canonical.content.clone(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid(&format!("corr-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idem-{id}")),
        },
    }
}

fn direct_action(capability: BridgeCapability, target: &[u8]) -> BridgeAction {
    BridgeAction {
        action_id: BridgeActionId::from_opaque(oid("telegram-direct-action")),
        scope: scope(),
        integration_id: integration(),
        capability,
        external_target: target.to_vec(),
        canonical_message_id: Some(MessageId::from_opaque(oid("telegram-direct-message"))),
        provider_payload: b"hello telegram".to_vec(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid("telegram-direct-correlation"),
            causation_id: None,
            idempotency_key: Some("telegram-direct-idempotency".to_owned()),
        },
    }
}

#[test]
fn telegram_manifest_declares_only_real_phase32_text_surface() {
    let provider = TelegramProvider::new(ScriptedClient::new(vec![], vec![]));
    let manifest = provider.manifest();
    assert_eq!(manifest.provider_id, TELEGRAM_PROVIDER_ID);
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
fn telegram_text_send_returns_acceptance_without_delivery_claim() {
    let provider = TelegramProvider::new(ScriptedClient::new(
        vec![Ok(TelegramSentMessage { message_id: 321 })],
        vec![],
    ));
    let accepted = provider
        .execute(&direct_action(BridgeCapability::Text, b"-100123"))
        .expect("accepted");
    assert_eq!(
        accepted.external_message_id.as_deref(),
        Some(b"321".as_slice())
    );
    assert!(accepted.degradation.is_none());
    assert_eq!(provider.client().send_calls(), 1);
}

#[test]
fn telegram_failure_classification_prevents_blind_duplicate_retry() {
    let rate_limited = TelegramProvider::new(ScriptedClient::new(
        vec![Err(TelegramApiFailure::RateLimited)],
        vec![],
    ));
    assert_eq!(
        rate_limited.execute(&direct_action(BridgeCapability::Text, b"-100123")),
        Err(BridgeProviderFailure::NotAccepted(
            BridgeProviderFailureKind::RateLimited
        ))
    );

    let ambiguous = TelegramProvider::new(ScriptedClient::new(
        vec![Err(TelegramApiFailure::Ambiguous)],
        vec![],
    ));
    assert_eq!(
        ambiguous.execute(&direct_action(BridgeCapability::Text, b"-100123")),
        Err(BridgeProviderFailure::AcceptanceUnknown(
            BridgeProviderFailureKind::Unavailable
        ))
    );
}

#[test]
fn telegram_poll_maps_text_and_advances_opaque_cursor() {
    let provider = TelegramProvider::new(ScriptedClient::new(
        vec![],
        vec![Ok(TelegramUpdateBatch {
            updates: vec![TelegramTextUpdate {
                update_id: 51,
                chat_id: -100_123,
                actor_id: Some(77),
                text: "inbound".to_owned(),
                occurred_at_unix_seconds: 1_700_000_000,
            }],
            next_offset: Some(52),
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
    assert_eq!(page.events[0].external_event_id, b"51");
    assert_eq!(page.events[0].external_conversation_id, b"-100123");
    assert_eq!(
        page.events[0].external_actor_id.as_deref(),
        Some(b"77".as_slice())
    );
    assert_eq!(page.events[0].payload, b"inbound");
    assert_eq!(page.next_cursor.expect("cursor").token, b"52");
    assert_eq!(
        *provider.client().last_poll.lock().expect("last poll"),
        Some((Some(50), 10))
    );
}

#[test]
fn telegram_rejects_unsupported_or_malformed_action_before_api_side_effect() {
    let provider = TelegramProvider::new(ScriptedClient::new(vec![], vec![]));
    assert_eq!(
        provider.execute(&direct_action(BridgeCapability::Video, b"-100123")),
        Err(BridgeProviderFailure::NotAccepted(
            BridgeProviderFailureKind::Rejected
        ))
    );
    assert_eq!(
        provider.execute(&direct_action(BridgeCapability::Text, b"bad target")),
        Err(BridgeProviderFailure::NotAccepted(
            BridgeProviderFailureKind::Rejected
        ))
    );
    assert_eq!(provider.client().send_calls(), 0);
}

#[test]
fn telegram_runtime_reuses_core_policy_and_phase31_dedup_ledger() {
    let store = MemoryLocalStore::default();
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    let provider = TelegramProvider::new(ScriptedClient::new(
        vec![Ok(TelegramSentMessage { message_id: 777 })],
        vec![],
    ));
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    let forbidden = message("telegram-forbidden", DeliveryPolicy::NoExternalBridge);
    store
        .persist_message(&forbidden)
        .expect("forbidden message");
    assert_eq!(
        runtime.execute(
            &actor(),
            &action("telegram-forbidden-action", &forbidden),
            &provider
        ),
        Err(BridgeError::ExternalBridgeForbidden)
    );
    assert_eq!(provider.client().send_calls(), 0);

    let allowed = message("telegram-allowed", DeliveryPolicy::Durable);
    store.persist_message(&allowed).expect("allowed message");
    let outbound = action("telegram-allowed-action", &allowed);
    let first = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("send");
    let replay = runtime
        .execute(&actor(), &outbound, &provider)
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.acceptance, replay.acceptance);
    assert_eq!(provider.client().send_calls(), 1);
    assert_eq!(
        store
            .message(&scope(), &allowed.message_id)
            .expect("load")
            .expect("message")
            .delivery_state,
        DeliveryState::Persisted
    );
}

#[test]
fn invalid_cursor_fails_before_telegram_poll() {
    let provider = TelegramProvider::new(ScriptedClient::new(vec![], vec![]));
    assert_eq!(
        provider.poll_events(
            &scope(),
            &integration(),
            Some(&BridgeEventCursor {
                token: b"not-an-offset".to_vec(),
            }),
            10,
        ),
        Err(BridgeProviderFailure::NotAccepted(
            BridgeProviderFailureKind::Rejected
        ))
    );
    assert_eq!(provider.client().poll_calls(), 0);
}

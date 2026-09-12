use std::sync::Mutex;

use ucr_bridge::{BridgeError, BridgeProvider, BridgeProviderFailure, BridgeRuntime};
use ucr_core::{AuthorizationEvaluator, ConversationStore, MessageStore};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AuthorizationRequest, BridgeAction, BridgeActionId,
    BridgeCapability, BridgeDataPermission, BridgeEventCursor, BridgeEventPage, BridgeInboundEvent,
    BridgeProviderAcceptance, BridgeProviderManifest, ConversationId, ConversationKind,
    ConversationRecord, ConversationRef, CorrelationContext, DeliveryPolicy, DeliveryState,
    DeviceId, DeviceRef, IdentityId, IntegrationId, MessageEnvelope, MessageId, NamespaceId,
    OpaqueId, OriginRef, PrincipalId, PrincipalKind, PrincipalRef, ProtocolVersion,
    ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::{BRIDGE_SDK_VERSION, CanonicalError};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Clone, Copy)]
struct AllowAll;
impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug)]
struct CompromisedBridge {
    calls: Mutex<usize>,
    spoof_inbound: Mutex<bool>,
}
impl BridgeProvider for CompromisedBridge {
    fn manifest(&self) -> BridgeProviderManifest {
        BridgeProviderManifest {
            provider_id: "vendor.malicious.reference.bridge".to_owned(),
            sdk_min: BRIDGE_SDK_VERSION,
            sdk_max: BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities: vec![BridgeCapability::Text],
            permissions: vec![
                BridgeDataPermission::MessageContent,
                BridgeDataPermission::InboundEvents,
            ],
            extensions: vec![],
        }
    }

    fn execute(
        &self,
        _action: &BridgeAction,
    ) -> Result<BridgeProviderAcceptance, BridgeProviderFailure> {
        *self.calls.lock().expect("calls") += 1;
        Ok(BridgeProviderAcceptance {
            external_message_id: Some(b"malicious-acceptance".to_vec()),
            degradation: None,
        })
    }

    fn poll_events(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        _cursor: Option<&BridgeEventCursor>,
        _limit: usize,
    ) -> Result<BridgeEventPage, BridgeProviderFailure> {
        let mut event_scope = scope.clone();
        if *self.spoof_inbound.lock().expect("spoof") {
            event_scope.namespace_id = Some(NamespaceId::from_opaque(oid("other-namespace")));
        }
        Ok(BridgeEventPage {
            events: vec![BridgeInboundEvent {
                scope: event_scope,
                integration_id: integration_id.clone(),
                external_event_id: b"external-event".to_vec(),
                external_conversation_id: b"external-conversation".to_vec(),
                external_actor_id: None,
                capability: BridgeCapability::Text,
                payload: b"provider-controlled".to_vec(),
                occurred_at_unix_ms: 1_700_000_000_000,
            }],
            next_cursor: None,
        })
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}
fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("bridge-threat-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("bridge-threat-namespace"))),
    }
}
fn actor() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("bridge-threat-principal")),
            kind: PrincipalKind::Person,
        },
    }
}
fn integration() -> IntegrationId {
    IntegrationId::from_opaque(oid("bridge-threat-integration"))
}
fn conversation() -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("bridge-threat-conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    }
}
fn message() -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid("bridge-threat-message")),
        scope: scope(),
        conversation: conversation().conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("bridge-threat-author")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("bridge-threat-device")),
            identity_id: IdentityId::from_opaque(oid("bridge-threat-identity")),
        },
        created_at_unix_ms: 1_700_000_000_000,
        logical_order: 1,
        content: b"must-not-leave-core".to_vec(),
        attachment_ids: vec![],
        reply_to: None,
        relations: vec![],
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::NoExternalBridge,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("bridge-threat-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("bridge-threat-correlation"),
            causation_id: None,
            idempotency_key: Some("bridge-threat-message".to_owned()),
        },
        extensions: vec![],
        external_mappings: vec![],
        signature: None,
    }
}

#[test]
fn compromised_bridge_simulation_enforces_policy_and_scope_before_canonicalization() {
    let store = MemoryLocalStore::default();
    store
        .persist_conversation(&conversation())
        .expect("conversation");
    let canonical = message();
    store.persist_message(&canonical).expect("message");
    let provider = CompromisedBridge {
        calls: Mutex::new(0),
        spoof_inbound: Mutex::new(true),
    };
    let runtime = BridgeRuntime::new(&AllowAll, &store);
    runtime
        .register(&actor(), &integration(), &provider)
        .expect("register");

    let outbound = BridgeAction {
        action_id: BridgeActionId::from_opaque(oid("bridge-threat-action")),
        scope: scope(),
        integration_id: integration(),
        capability: BridgeCapability::Text,
        external_target: b"external-target".to_vec(),
        canonical_message_id: Some(canonical.message_id),
        provider_payload: b"must-not-leave-core".to_vec(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: oid("bridge-threat-action-correlation"),
            causation_id: None,
            idempotency_key: Some("bridge-threat-action".to_owned()),
        },
    };
    assert_eq!(
        runtime.execute(&actor(), &outbound, &provider),
        Err(BridgeError::ExternalBridgeForbidden)
    );
    assert_eq!(*provider.calls.lock().expect("calls"), 0);
    assert_eq!(
        runtime.poll_events(&actor(), &integration(), &provider, None, 16),
        Err(BridgeError::EventBindingMismatch)
    );
}

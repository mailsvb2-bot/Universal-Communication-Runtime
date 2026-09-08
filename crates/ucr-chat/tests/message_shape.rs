use ucr_chat::{ChatClock, ChatClockError, ChatError, ChatRuntime, EphemeralChatError, EphemeralChatSink};
use ucr_core::AuthorizationEvaluator;
use ucr_model::{
    ActorId, ActorKind, ActorRef, AttachmentId, AuthorizationRequest, ConversationId,
    ConversationKind, ConversationRecord, ConversationRef, CorrelationContext, DeliveryPolicy,
    DeliveryState, DeviceId, DeviceRef, IdentityId, MessageEnvelope, MessageId, OpaqueId, OriginRef,
    PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::CanonicalError;
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Clone, Copy)]
struct Allow;
impl AuthorizationEvaluator for Allow {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}
#[derive(Debug, Clone, Copy)]
struct Clock;
impl ChatClock for Clock {
    fn now_unix_ms(&self) -> Result<i64, ChatClockError> {
        Ok(0)
    }
}
#[derive(Debug, Clone, Copy)]
struct Sink;
impl EphemeralChatSink for Sink {
    fn publish_typing(
        &self,
        _subject: &ScopedPrincipal,
        _update: &ucr_chat::TypingUpdate,
    ) -> Result<(), EphemeralChatError> {
        Ok(())
    }
}
fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}
#[test]
fn attachment_is_not_silently_claimed_as_phase17_text_chat() {
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant")),
        namespace_id: None,
    };
    let subject = ScopedPrincipal {
        scope: scope.clone(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("principal")),
            kind: PrincipalKind::Person,
        },
    };
    let conversation = ConversationRecord {
        scope: scope.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };
    let message = MessageEnvelope {
        message_id: MessageId::from_opaque(oid("message")),
        scope: scope.clone(),
        conversation: conversation.conversation.clone(),
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("actor")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("device")),
            identity_id: IdentityId::from_opaque(oid("identity")),
        },
        created_at_unix_ms: 1,
        logical_order: 1,
        content: b"text".to_vec(),
        attachment_ids: vec![AttachmentId::from_opaque(oid("attachment"))],
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid("correlation"),
            causation_id: None,
            idempotency_key: Some("idempotency".to_owned()),
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    };
    let store = MemoryLocalStore::default();
    let chat = ChatRuntime::new(&Clock, &Allow, &store, &Sink);
    chat.open_direct_chat(&subject, &conversation).expect("open chat");
    assert_eq!(
        chat.send_text(&subject, &message),
        Err(ChatError::AttachmentsOutsidePhase17)
    );
}

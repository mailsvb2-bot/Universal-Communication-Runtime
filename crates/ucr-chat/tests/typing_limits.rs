use ucr_chat::{
    ChatClock, ChatClockError, ChatError, ChatRuntime, EphemeralChatError, EphemeralChatSink,
    MAX_TYPING_TTL_MS, TypingState, TypingUpdate,
};
use ucr_core::AuthorizationEvaluator;
use ucr_model::{
    AuthorizationRequest, ConversationId, ConversationKind, ConversationRecord, ConversationRef,
    OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
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
        Ok(1_000)
    }
}
#[derive(Debug, Clone, Copy)]
struct Sink;
impl EphemeralChatSink for Sink {
    fn publish_typing(
        &self,
        _subject: &ScopedPrincipal,
        _update: &TypingUpdate,
    ) -> Result<(), EphemeralChatError> {
        Ok(())
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
fn subject() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("principal")),
            kind: PrincipalKind::Person,
        },
    }
}
#[test]
fn typing_above_ttl_ceiling_is_rejected() {
    let store = MemoryLocalStore::default();
    let chat = ChatRuntime::new(&Clock, &Allow, &store, &Sink);
    let conversation = ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };
    chat.open_direct_chat(&subject(), &conversation).expect("chat");
    let update = TypingUpdate {
        scope: scope(),
        conversation_id: conversation.conversation.conversation_id,
        state: TypingState::Started,
        expires_at_unix_ms: 1_000 + MAX_TYPING_TTL_MS + 1,
    };
    assert_eq!(
        chat.publish_typing(&subject(), &update),
        Err(ChatError::InvalidTypingTtl)
    );
}

use ucr_chat::{ChatClock, ChatClockError, ChatRuntime, EphemeralChatError, EphemeralChatSink};
use ucr_core::{AuthorizationEvaluator, ConversationStore};
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
fn direct_chat_is_immediately_visible_through_existing_conversation_store() {
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
    let record = ConversationRecord {
        scope: scope.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };
    let store = MemoryLocalStore::default();
    let chat = ChatRuntime::new(&Clock, &Allow, &store, &Sink);
    chat.open_direct_chat(&subject, &record).expect("open chat");
    assert_eq!(
        store
            .conversation(&scope, &record.conversation.conversation_id)
            .expect("canonical read"),
        Some(record)
    );
}

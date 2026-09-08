use ucr_chat::{
    ChatClock, ChatClockError, ChatError, ChatRuntime, EphemeralChatError, EphemeralChatSink,
    MAX_TRANSCRIPT_BATCH_ITEMS,
};
use ucr_core::AuthorizationEvaluator;
use ucr_model::{
    AuthorizationRequest, ConversationId, MessageId, OpaqueId, PrincipalId, PrincipalKind,
    PrincipalRef, ScopedPrincipal, TenantId, TenantScope,
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
fn oid(value: impl Into<String>) -> OpaqueId {
    OpaqueId::new(value).expect("id")
}
#[test]
fn transcript_rejects_empty_and_oversized_batches_before_message_reads() {
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
    let ids = (0..=MAX_TRANSCRIPT_BATCH_ITEMS)
        .map(|index| MessageId::from_opaque(oid(format!("message-{index}"))))
        .collect::<Vec<_>>();
    let store = MemoryLocalStore::default();
    let chat = ChatRuntime::new(&Clock, &Allow, &store, &Sink);
    let conversation_id = ConversationId::from_opaque(oid("conversation"));
    assert_eq!(
        chat.load_transcript_batch(&subject, &scope, &conversation_id, &[]),
        Err(ChatError::TranscriptBatchSize)
    );
    assert_eq!(
        chat.load_transcript_batch(&subject, &scope, &conversation_id, &ids),
        Err(ChatError::TranscriptBatchSize)
    );
}

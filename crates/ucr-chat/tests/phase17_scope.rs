use ucr_chat::{
    ChatClock, ChatClockError, ChatError, ChatRuntime, EphemeralChatError, EphemeralChatSink,
};
use ucr_core::AuthorizationEvaluator;
use ucr_model::{
    AuthorizationRequest, ConversationId, ConversationKind, ConversationRecord, ConversationRef,
    NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId,
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

#[derive(Debug, Default, Clone, Copy)]
struct Clock;
impl ChatClock for Clock {
    fn now_unix_ms(&self) -> Result<i64, ChatClockError> {
        Ok(1_000)
    }
}

#[derive(Debug, Default, Clone, Copy)]
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
    OpaqueId::new(value).expect("test id")
}

fn scope(tenant: &str) -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid(tenant)),
        namespace_id: Some(NamespaceId::from_opaque(oid("namespace"))),
    }
}

#[test]
fn subject_cannot_cross_tenant_even_with_permissive_authorizer() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let clock = Clock;
    let sink = Sink;
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    let subject = ScopedPrincipal {
        scope: scope("tenant-a"),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("principal")),
            kind: PrincipalKind::Person,
        },
    };
    let conversation = ConversationRecord {
        scope: scope("tenant-b"),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(oid("conversation")),
            kind: ConversationKind::Direct,
        },
        parent_conversation_id: None,
    };

    assert_eq!(
        chat.open_direct_chat(&subject, &conversation),
        Err(ChatError::ScopeMismatch)
    );
}

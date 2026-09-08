use std::sync::Mutex;

use ucr_chat::{
    ChatClock, ChatClockError, ChatError, ChatRuntime, EphemeralChatError, EphemeralChatSink,
    MAX_TRANSCRIPT_BATCH_BYTES, TypingState, TypingUpdate,
};
use ucr_core::{
    AuthorizationEvaluator, AuthorizedMutationError, ConversationStore, DeliveryStore,
    DurableRecordStatus, MessageStore,
};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AuthorizationRequest, ConversationKind, ConversationRecord,
    ConversationRef, CorrelationContext, DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind,
    DeliveryId, DeliveryPolicy, DeliveryState, DeviceId, DeviceRef, IdentityId, MessageEnvelope,
    MessageId, NamespaceId, OpaqueId, OriginRef, PrincipalId, PrincipalKind, PrincipalRef,
    ScopedPrincipal, TenantId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, DEFAULT_MAX_PAYLOAD_LEN, DELIVERY_WRITE_PERMISSION,
};
use ucr_storage_memory::MemoryLocalStore;

#[derive(Debug, Default, Clone, Copy)]
struct AllowAll;

impl AuthorizationEvaluator for AllowAll {
    fn authorize(&self, _request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct DenyDeliveryWrite;

impl AuthorizationEvaluator for DenyDeliveryWrite {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        if request.permission == DELIVERY_WRITE_PERMISSION {
            Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FixedClock(i64);

impl ChatClock for FixedClock {
    fn now_unix_ms(&self) -> Result<i64, ChatClockError> {
        Ok(self.0)
    }
}

#[derive(Debug, Default)]
struct RecordingSink {
    updates: Mutex<Vec<(ScopedPrincipal, TypingUpdate)>>,
}

impl EphemeralChatSink for RecordingSink {
    fn publish_typing(
        &self,
        subject: &ScopedPrincipal,
        update: &TypingUpdate,
    ) -> Result<(), EphemeralChatError> {
        self.updates
            .lock()
            .expect("typing sink lock")
            .push((subject.clone(), update.clone()));
        Ok(())
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-chat")),
        namespace_id: Some(NamespaceId::from_opaque(oid("namespace-chat"))),
    }
}

fn subject() -> ScopedPrincipal {
    ScopedPrincipal {
        scope: scope(),
        principal: PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("principal-chat")),
            kind: PrincipalKind::Person,
        },
    }
}

fn conversation(kind: ConversationKind) -> ConversationRecord {
    ConversationRecord {
        scope: scope(),
        conversation: ConversationRef {
            conversation_id: ucr_model::ConversationId::from_opaque(oid("conversation-chat")),
            kind,
        },
        parent_conversation_id: None,
    }
}

fn message(id: &str, logical_order: u64, content: &[u8]) -> MessageEnvelope {
    MessageEnvelope {
        message_id: MessageId::from_opaque(oid(id)),
        scope: scope(),
        conversation: conversation(ConversationKind::Direct).conversation,
        author: ActorRef {
            actor_id: ActorId::from_opaque(oid("actor-chat")),
            kind: ActorKind::Person,
            on_behalf_of: None,
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(oid("device-chat")),
            identity_id: IdentityId::from_opaque(oid("identity-chat")),
        },
        created_at_unix_ms: 1_700_000_000_000,
        logical_order,
        content: content.to_vec(),
        attachment_ids: Vec::new(),
        reply_to: None,
        relations: Vec::new(),
        crypto_metadata: None,
        delivery_policy: DeliveryPolicy::Durable,
        delivery_state: DeliveryState::Created,
        origin: OriginRef {
            principal_id: Some(PrincipalId::from_opaque(oid("principal-origin"))),
            endpoint_id: None,
            integration_id: None,
        },
        correlation: CorrelationContext {
            correlation_id: oid(&format!("correlation-{id}")),
            causation_id: None,
            idempotency_key: Some(format!("idempotency-{id}")),
        },
        extensions: Vec::new(),
        external_mappings: Vec::new(),
        signature: None,
    }
}

fn create_persisted_delivery(store: &MemoryLocalStore, message: &MessageEnvelope) -> DeliveryId {
    let delivery_id = DeliveryId::from_opaque(oid("delivery-read"));
    let attempt = DeliveryAttempt {
        delivery_id: delivery_id.clone(),
        scope: scope(),
        message_id: message.message_id.clone(),
        state: DeliveryState::Persisted,
    };
    let persisted = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: scope(),
        message_id: message.message_id.clone(),
        kind: DeliveryEvidenceKind::PersistedLocal,
        logical_order: 1,
    };
    store
        .create_delivery_attempt(&attempt, &persisted)
        .expect("create delivery");
    delivery_id
}

fn advance_delivery_to_delivered(
    store: &MemoryLocalStore,
    delivery_id: &DeliveryId,
    message_id: &MessageId,
) {
    for (from, to) in [
        (DeliveryState::Persisted, DeliveryState::Encrypted),
        (DeliveryState::Encrypted, DeliveryState::Queued),
        (DeliveryState::Queued, DeliveryState::RoutePlanned),
        (DeliveryState::RoutePlanned, DeliveryState::InFlight),
    ] {
        store
            .transition_delivery(&scope(), delivery_id, from, to, None)
            .expect("advance delivery");
    }
    let acknowledged = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: scope(),
        message_id: message_id.clone(),
        kind: DeliveryEvidenceKind::AcceptedByTransport,
        logical_order: 2,
    };
    store
        .transition_delivery(
            &scope(),
            delivery_id,
            DeliveryState::InFlight,
            DeliveryState::Acknowledged,
            Some(&acknowledged),
        )
        .expect("acknowledge delivery");
    let delivered = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: scope(),
        message_id: message_id.clone(),
        kind: DeliveryEvidenceKind::PresentedToUser,
        logical_order: 3,
    };
    store
        .transition_delivery(
            &scope(),
            delivery_id,
            DeliveryState::Acknowledged,
            DeliveryState::Delivered,
            Some(&delivered),
        )
        .expect("deliver message");
}

fn advance_delivery_to_read(
    store: &MemoryLocalStore,
    delivery_id: &DeliveryId,
    message_id: &MessageId,
) {
    advance_delivery_to_delivered(store, delivery_id, message_id);
    let read = DeliveryEvidence {
        delivery_id: delivery_id.clone(),
        scope: scope(),
        message_id: message_id.clone(),
        kind: DeliveryEvidenceKind::ReadByUser,
        logical_order: 4,
    };
    store
        .transition_delivery(
            &scope(),
            delivery_id,
            DeliveryState::Delivered,
            DeliveryState::Read,
            Some(&read),
        )
        .expect("read message");
}

fn setup_chat_message(store: &MemoryLocalStore) -> MessageEnvelope {
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, store, &sink);
    chat.open_direct_chat(&subject(), &conversation(ConversationKind::Direct))
        .expect("open direct chat");
    let chat_message = message("message-read", 10, b"read me");
    chat.send_text(&subject(), &chat_message)
        .expect("send message");
    chat_message
}

#[test]
fn direct_chat_send_and_bounded_transcript_reuse_canonical_message_store() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    let direct = conversation(ConversationKind::Direct);

    assert_eq!(
        chat.open_direct_chat(&subject(), &direct),
        Ok(DurableRecordStatus::Persisted)
    );
    let later = message("message-later", 20, b"later");
    let earlier = message("message-earlier", 10, b"earlier");
    assert_eq!(
        chat.send_text(&subject(), &later),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        chat.send_text(&subject(), &earlier),
        Ok(DurableRecordStatus::Persisted)
    );

    let transcript = chat
        .load_transcript_batch(
            &subject(),
            &scope(),
            &direct.conversation.conversation_id,
            &[
                later.message_id.clone(),
                earlier.message_id.clone(),
                later.message_id.clone(),
            ],
        )
        .expect("load transcript");
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[0].message_id, earlier.message_id);
    assert_eq!(transcript[1].message_id, later.message_id);
    assert!(
        store
            .message(&scope(), &transcript[0].message_id)
            .expect("canonical message read")
            .is_some()
    );
}

#[test]
fn transcript_enforces_aggregate_semantic_byte_budget() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    let direct = conversation(ConversationKind::Direct);
    chat.open_direct_chat(&subject(), &direct)
        .expect("open direct chat");

    assert_eq!(
        MAX_TRANSCRIPT_BATCH_BYTES,
        2 * DEFAULT_MAX_PAYLOAD_LEN as usize
    );
    let first = message(
        "message-byte-budget-a",
        10,
        &vec![b'a'; DEFAULT_MAX_PAYLOAD_LEN as usize],
    );
    let second = message(
        "message-byte-budget-b",
        20,
        &vec![b'b'; DEFAULT_MAX_PAYLOAD_LEN as usize],
    );
    chat.send_text(&subject(), &first).expect("persist first");
    chat.send_text(&subject(), &second).expect("persist second");

    assert_eq!(
        chat.load_transcript_batch(
            &subject(),
            &scope(),
            &direct.conversation.conversation_id,
            &[first.message_id.clone(), second.message_id.clone()],
        ),
        Err(ChatError::TranscriptBatchBytes)
    );
}

#[test]
fn phase17_rejects_group_conversation_instead_of_implementing_phase18_implicitly() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);

    assert_eq!(
        chat.open_direct_chat(&subject(), &conversation(ConversationKind::PrivateGroup)),
        Err(ChatError::NonDirectConversation)
    );
    assert!(
        store
            .conversation(
                &scope(),
                &conversation(ConversationKind::PrivateGroup)
                    .conversation
                    .conversation_id
            )
            .expect("conversation lookup")
            .is_none()
    );
}

#[test]
fn read_requires_delivered_state_and_records_read_by_user_through_delivery_owner() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    let chat_message = setup_chat_message(&store);
    let delivery_id = create_persisted_delivery(&store, &chat_message);

    assert_eq!(
        chat.mark_read(
            &subject(),
            &scope(),
            &delivery_id,
            &chat_message.message_id,
            4
        ),
        Err(ChatError::ReadRequiresDelivered)
    );
    advance_delivery_to_delivered(&store, &delivery_id, &chat_message.message_id);
    assert_eq!(
        chat.mark_read(
            &subject(),
            &scope(),
            &delivery_id,
            &chat_message.message_id,
            4
        ),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        chat.mark_read(
            &subject(),
            &scope(),
            &delivery_id,
            &chat_message.message_id,
            5
        ),
        Ok(DurableRecordStatus::Duplicate)
    );
    assert_eq!(
        store
            .delivery_attempt(&scope(), &delivery_id)
            .expect("read delivery")
            .expect("delivery exists")
            .state,
        DeliveryState::Read
    );
}

#[test]
fn already_read_retry_still_requires_delivery_write_permission() {
    let store = MemoryLocalStore::default();
    let chat_message = setup_chat_message(&store);
    let delivery_id = create_persisted_delivery(&store, &chat_message);
    advance_delivery_to_read(&store, &delivery_id, &chat_message.message_id);

    let authorization = DenyDeliveryWrite;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    assert_eq!(
        chat.mark_read(
            &subject(),
            &scope(),
            &delivery_id,
            &chat_message.message_id,
            5
        ),
        Err(ChatError::Authorized(
            AuthorizedMutationError::Authorization(CanonicalError::new(
                CanonicalErrorCode::PermissionDenied
            ))
        ))
    );
}

#[test]
fn already_read_retry_recovers_cas_conflict_as_duplicate() {
    let store = MemoryLocalStore::default();
    let chat_message = setup_chat_message(&store);
    let delivery_id = create_persisted_delivery(&store, &chat_message);
    advance_delivery_to_read(&store, &delivery_id, &chat_message.message_id);

    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    assert_eq!(
        chat.mark_read(
            &subject(),
            &scope(),
            &delivery_id,
            &chat_message.message_id,
            5
        ),
        Ok(DurableRecordStatus::Duplicate)
    );
}

#[test]
fn typing_is_ttl_bounded_and_only_published_to_ephemeral_sink() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    let direct = conversation(ConversationKind::Direct);
    chat.open_direct_chat(&subject(), &direct)
        .expect("open direct chat");

    let update = TypingUpdate {
        scope: scope(),
        conversation_id: direct.conversation.conversation_id,
        state: TypingState::Started,
        expires_at_unix_ms: 11_000,
    };
    chat.publish_typing(&subject(), &update)
        .expect("publish typing");
    assert_eq!(sink.updates.lock().expect("typing lock").len(), 1);

    let stale = TypingUpdate {
        expires_at_unix_ms: 10_000,
        ..update
    };
    assert_eq!(
        chat.publish_typing(&subject(), &stale),
        Err(ChatError::InvalidTypingTtl)
    );
}

#[test]
fn service_account_typing_fails_closed_without_ephemeral_admission_gate() {
    let store = MemoryLocalStore::default();
    let authorization = AllowAll;
    let sink = RecordingSink::default();
    let clock = FixedClock(10_000);
    let chat = ChatRuntime::new(&clock, &authorization, &store, &sink);
    let direct = conversation(ConversationKind::Direct);
    chat.open_direct_chat(&subject(), &direct)
        .expect("open direct chat");
    let mut service = subject();
    service.principal.kind = PrincipalKind::ServiceAccount;
    let update = TypingUpdate {
        scope: scope(),
        conversation_id: direct.conversation.conversation_id,
        state: TypingState::Started,
        expires_at_unix_ms: 11_000,
    };

    assert_eq!(
        chat.publish_typing(&service, &update),
        Err(ChatError::Authorization(CanonicalError::new(
            CanonicalErrorCode::PermissionDenied
        )))
    );
    assert!(sink.updates.lock().expect("typing lock").is_empty());
}

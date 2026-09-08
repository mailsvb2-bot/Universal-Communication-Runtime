#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fmt, time::SystemTime};

use ucr_core::{
    AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError, DeliveryStore,
    DurableRecordStatus,
};
use ucr_model::{
    AuthorizationRequest, ConversationId, ConversationKind, ConversationRecord, DeliveryEvidence,
    DeliveryEvidenceKind, DeliveryId, DeliveryState, MessageEnvelope, MessageId,
    MessageRelationKind, PrincipalKind, ScopedPrincipal, TenantScope,
};
use ucr_protocol::{CanonicalError, CanonicalErrorCode, MESSAGE_WRITE_PERMISSION};

pub const MAX_TRANSCRIPT_BATCH_ITEMS: usize = 256;
pub const MAX_TYPING_TTL_MS: i64 = 15_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatClockError {
    BeforeUnixEpoch,
    Overflow,
}

pub trait ChatClock: fmt::Debug + Send + Sync {
    /// Returns wall-clock milliseconds used only for ephemeral TTL evaluation.
    ///
    /// # Errors
    /// Returns an explicit clock error rather than silently accepting an invalid TTL.
    fn now_unix_ms(&self) -> Result<i64, ChatClockError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemChatClock;

impl ChatClock for SystemChatClock {
    fn now_unix_ms(&self) -> Result<i64, ChatClockError> {
        let elapsed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| ChatClockError::BeforeUnixEpoch)?;
        i64::try_from(elapsed.as_millis()).map_err(|_| ChatClockError::Overflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingState {
    Started,
    Stopped,
}

/// Ephemeral Phase-17 typing update.
///
/// It deliberately carries no message content, durable event ID, delivery state, or actor override.
/// The authenticated [`ScopedPrincipal`] is supplied separately to the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypingUpdate {
    pub scope: TenantScope,
    pub conversation_id: ConversationId,
    pub state: TypingState,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralChatError {
    Unavailable,
    Backpressure,
    Internal,
}

/// Non-durable realtime boundary for typing and future Phase-17 ephemeral hints.
///
/// Implementations must not turn this into a second Message/Event journal.
pub trait EphemeralChatSink: fmt::Debug + Send + Sync {
    /// Publishes a best-effort typing update.
    ///
    /// # Errors
    /// Ephemeral delivery failures are explicit but are never converted to durable chat state.
    fn publish_typing(
        &self,
        subject: &ScopedPrincipal,
        update: &TypingUpdate,
    ) -> Result<(), EphemeralChatError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    Authorized(AuthorizedMutationError),
    Authorization(CanonicalError),
    Clock(ChatClockError),
    Ephemeral(EphemeralChatError),
    ScopeMismatch,
    NonDirectConversation,
    ParentConversationNotAllowed,
    TextContentRequired,
    AttachmentsOutsidePhase17,
    UnsupportedMessageRelation,
    TranscriptBatchSize,
    NotFound,
    MessageOutsideConversation,
    DeliveryMessageMismatch,
    ReadRequiresDelivered,
    InvalidTypingTtl,
}

impl From<AuthorizedMutationError> for ChatError {
    fn from(error: AuthorizedMutationError) -> Self {
        Self::Authorized(error)
    }
}

impl From<ChatClockError> for ChatError {
    fn from(error: ChatClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<EphemeralChatError> for ChatError {
    fn from(error: EphemeralChatError) -> Self {
        Self::Ephemeral(error)
    }
}

/// Prepared Phase-17 reference Chat layer over the canonical durable owners.
///
/// This type owns no Message, Conversation, Delivery, Identity, queue, or routing state.
#[derive(Debug)]
pub struct ChatRuntime<'a, C, A, S, E> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
    ephemeral: &'a E,
}

impl<'a, C, A, S, E> ChatRuntime<'a, C, A, S, E> {
    #[must_use]
    pub const fn new(clock: &'a C, authorization: &'a A, store: &'a S, ephemeral: &'a E) -> Self {
        Self {
            clock,
            authorization,
            store,
            ephemeral,
        }
    }
}

impl<C, A, S, E> ChatRuntime<'_, C, A, S, E>
where
    C: ChatClock,
    A: AuthorizationEvaluator,
    S: DeliveryStore,
    E: EphemeralChatSink,
{
    /// Creates/deduplicates one 1:1 chat through the existing Conversation owner.
    ///
    /// # Errors
    /// Rejects cross-scope, non-DIRECT, parented, unauthorized, or invalid durable state.
    pub fn open_direct_chat(
        &self,
        subject: &ScopedPrincipal,
        conversation: &ConversationRecord,
    ) -> Result<DurableRecordStatus, ChatError> {
        require_exact_subject_scope(subject, &conversation.scope)?;
        require_direct_conversation(conversation)?;
        AuthorizedDurableRuntime::new(self.authorization, self.store)
            .persist_conversation(subject, conversation)
            .map_err(ChatError::from)
    }

    /// Persists/deduplicates one text chat Message through the canonical Message owner.
    ///
    /// Phase 17 intentionally does not claim attachments, edits, reactions, threads, forwards,
    /// groups, calls, or routing orchestration.
    ///
    /// # Errors
    /// Rejects unsupported Phase-17 shapes, scope mismatches, authorization, or durable failures.
    pub fn send_text(
        &self,
        subject: &ScopedPrincipal,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, ChatError> {
        require_exact_subject_scope(subject, &message.scope)?;
        require_direct_message(message)?;
        AuthorizedDurableRuntime::new(self.authorization, self.store)
            .persist_message(subject, message)
            .map_err(ChatError::from)
    }

    /// Reads one exact direct-chat Message through the canonical Message owner.
    ///
    /// # Errors
    /// Returns explicit authorization/storage/not-found/scope errors and never probes another scope.
    pub fn message(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<MessageEnvelope, ChatError> {
        require_exact_subject_scope(subject, scope)?;
        let message = AuthorizedDurableRuntime::new(self.authorization, self.store)
            .message(subject, scope, message_id)?
            .ok_or(ChatError::NotFound)?;
        require_direct_message(&message)?;
        Ok(message)
    }

    /// Loads a bounded transcript projection for explicit canonical Message IDs.
    ///
    /// IDs normally come from Sync/Event/query layers. This deliberately avoids creating a second
    /// timeline index or Message owner inside Chat. Returned Messages are ordered by canonical
    /// logical order and then Message ID for deterministic ties.
    ///
    /// # Errors
    /// Rejects empty/oversized batches, cross-scope/cross-conversation Messages, or read failures.
    pub fn load_transcript_batch(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        conversation_id: &ConversationId,
        message_ids: &[MessageId],
    ) -> Result<Vec<MessageEnvelope>, ChatError> {
        require_exact_subject_scope(subject, scope)?;
        if message_ids.is_empty() || message_ids.len() > MAX_TRANSCRIPT_BATCH_ITEMS {
            return Err(ChatError::TranscriptBatchSize);
        }

        let unique_ids = message_ids.iter().cloned().collect::<BTreeSet<_>>();
        let runtime = AuthorizedDurableRuntime::new(self.authorization, self.store);
        let mut messages = Vec::with_capacity(unique_ids.len());
        for message_id in unique_ids {
            let message = runtime
                .message(subject, scope, &message_id)?
                .ok_or(ChatError::NotFound)?;
            require_direct_message(&message)?;
            if message.conversation.conversation_id != *conversation_id {
                return Err(ChatError::MessageOutsideConversation);
            }
            messages.push(message);
        }
        messages.sort_by(|left, right| {
            left.logical_order
                .cmp(&right.logical_order)
                .then_with(|| left.message_id.cmp(&right.message_id))
        });
        Ok(messages)
    }

    /// Records explicit `READ_BY_USER` evidence and advances Delivered -> Read.
    ///
    /// Transport/relay acknowledgement is intentionally insufficient; the caller must invoke this
    /// only after an actual user-read action. Retrying an already-Read delivery is idempotent.
    ///
    /// # Errors
    /// Rejects non-direct Messages, mismatched delivery binding, premature read, or auth/store errors.
    pub fn mark_read(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
        message_id: &MessageId,
        logical_order: u64,
    ) -> Result<DurableRecordStatus, ChatError> {
        require_exact_subject_scope(subject, scope)?;
        let runtime = AuthorizedDurableRuntime::new(self.authorization, self.store);
        let message = runtime
            .message(subject, scope, message_id)?
            .ok_or(ChatError::NotFound)?;
        require_direct_message(&message)?;
        let attempt = runtime
            .delivery_attempt(subject, scope, delivery_id)?
            .ok_or(ChatError::NotFound)?;
        if attempt.message_id != *message_id {
            return Err(ChatError::DeliveryMessageMismatch);
        }
        if attempt.state == DeliveryState::Read {
            return Ok(DurableRecordStatus::Duplicate);
        }
        if attempt.state != DeliveryState::Delivered {
            return Err(ChatError::ReadRequiresDelivered);
        }
        let evidence = DeliveryEvidence {
            delivery_id: delivery_id.clone(),
            scope: scope.clone(),
            message_id: message_id.clone(),
            kind: DeliveryEvidenceKind::ReadByUser,
            logical_order,
        };
        runtime
            .transition_delivery(
                subject,
                scope,
                delivery_id,
                DeliveryState::Delivered,
                DeliveryState::Read,
                Some(&evidence),
            )
            .map_err(ChatError::from)
    }

    /// Publishes a bounded-TTL best-effort typing hint without persisting it.
    ///
    /// # Errors
    /// Rejects stale/oversized TTL, non-direct conversations, insufficient permission, or sink errors.
    pub fn publish_typing(
        &self,
        subject: &ScopedPrincipal,
        update: &TypingUpdate,
    ) -> Result<(), ChatError> {
        require_exact_subject_scope(subject, &update.scope)?;
        let conversation = AuthorizedDurableRuntime::new(self.authorization, self.store)
            .conversation(subject, &update.scope, &update.conversation_id)?
            .ok_or(ChatError::NotFound)?;
        require_direct_conversation(&conversation)?;
        self.authorize_message_write(subject, &update.scope)?;

        let now = self.clock.now_unix_ms()?;
        let ttl = update
            .expires_at_unix_ms
            .checked_sub(now)
            .ok_or(ChatError::InvalidTypingTtl)?;
        if ttl <= 0 || ttl > MAX_TYPING_TTL_MS {
            return Err(ChatError::InvalidTypingTtl);
        }
        self.ephemeral.publish_typing(subject, update)?;
        Ok(())
    }

    fn authorize_message_write(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
    ) -> Result<(), ChatError> {
        let request = AuthorizationRequest {
            subject: subject.clone(),
            permission: MESSAGE_WRITE_PERMISSION.to_owned(),
            resource_scope: scope.clone(),
        };
        if subject.principal.kind == PrincipalKind::ServiceAccount
            && !self
                .authorization
                .service_principal_admission_proof()
                .is_some_and(|proof| proof.matches(&request))
        {
            return Err(ChatError::Authorization(CanonicalError::new(
                CanonicalErrorCode::PermissionDenied,
            )));
        }
        self.authorization
            .authorize(&request)
            .map_err(ChatError::Authorization)
    }
}

fn require_exact_subject_scope(
    subject: &ScopedPrincipal,
    scope: &TenantScope,
) -> Result<(), ChatError> {
    if subject.scope == *scope {
        Ok(())
    } else {
        Err(ChatError::ScopeMismatch)
    }
}

fn require_direct_conversation(conversation: &ConversationRecord) -> Result<(), ChatError> {
    if conversation.conversation.kind != ConversationKind::Direct {
        return Err(ChatError::NonDirectConversation);
    }
    if conversation.parent_conversation_id.is_some() {
        return Err(ChatError::ParentConversationNotAllowed);
    }
    Ok(())
}

fn require_direct_message(message: &MessageEnvelope) -> Result<(), ChatError> {
    if message.conversation.kind != ConversationKind::Direct {
        return Err(ChatError::NonDirectConversation);
    }
    if message.content.is_empty() {
        return Err(ChatError::TextContentRequired);
    }
    if !message.attachment_ids.is_empty() {
        return Err(ChatError::AttachmentsOutsidePhase17);
    }
    if message.relations.iter().any(|relation| {
        !matches!(
            relation.kind,
            MessageRelationKind::Reply | MessageRelationKind::Quote | MessageRelationKind::Reference
        )
    }) {
        return Err(ChatError::UnsupportedMessageRelation);
    }
    Ok(())
}

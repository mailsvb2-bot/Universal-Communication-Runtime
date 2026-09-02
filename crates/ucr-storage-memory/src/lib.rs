#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Mutex,
};

use ucr_core::{
    CommandAcceptanceStore, CommandOutcomeStore, ConversationStore, DeliveryStore,
    DurableRecordStatus, DurableStoreError, EventAppendStatus, EventJournalStore, MessageStore,
    RecoveryPlanStore, StorageHealth, StorageProvider,
};
use ucr_crypto::{ReplayError, ReplayProtector, TranscriptBinding, VerifyingKeyBytes};
use ucr_model::{
    CommandEnvelope, CommandId, ConversationId, ConversationRecord, DeliveryAttempt,
    DeliveryEvidence, DeliveryId, DeliveryState, EventEnvelope, EventId, IdentityId,
    MessageEnvelope, MessageId, RecoveryPlan, RecoveryPlanId, TenantScope,
};
use ucr_protocol::{
    CommandError, CommandReceipt, CommandReceiptStatus, EventError, IdempotencyDecision,
    canonical_message, canonical_recovery_plan, compare_command_idempotency, validate_command,
    validate_conversation, validate_conversation_parent_kind, validate_delivery_attempt,
    validate_delivery_evidence, validate_delivery_evidence_binding,
    validate_delivery_evidence_order, validate_delivery_transition, validate_event,
};

const SCHEMA_VERSION: u32 = 5;
type ScopeKey = (String, Option<String>);
type CommandKey = (ScopeKey, String);
type CommandRefKey = (ScopeKey, String);
type EventKey = (ScopeKey, String);
type ReplayKey = ([u8; 32], [u8; 32]);
type RecoveryIdentityKey = (ScopeKey, String);
type ConversationKey = (ScopeKey, String);
type MessageKey = (ScopeKey, String);
type DeliveryKey = (ScopeKey, String);

#[derive(Default)]
struct MemoryState {
    accepted: HashMap<CommandKey, CommandEnvelope>,
    accepted_by_id: HashMap<CommandRefKey, CommandEnvelope>,
    events: HashMap<EventKey, EventEnvelope>,
    terminal_events: HashMap<CommandRefKey, EventId>,
    seen_handshakes: HashSet<ReplayKey>,
    recovery_plans: HashMap<String, RecoveryPlan>,
    active_recovery_plans: HashMap<RecoveryIdentityKey, String>,
    conversations: HashMap<ConversationKey, ConversationRecord>,
    messages: HashMap<MessageKey, MessageEnvelope>,
    deliveries: HashMap<DeliveryKey, DeliveryAttempt>,
    delivery_evidence: HashMap<DeliveryKey, Vec<DeliveryEvidence>>,
}

#[derive(Default)]
pub struct MemoryLocalStore {
    state: Mutex<MemoryState>,
}

impl fmt::Debug for MemoryLocalStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryLocalStore")
            .field("state", &"<redacted>")
            .finish()
    }
}

impl StorageProvider for MemoryLocalStore {
    fn schema_version(&self) -> Result<u32, DurableStoreError> {
        Ok(SCHEMA_VERSION)
    }

    fn health(&self) -> Result<StorageHealth, DurableStoreError> {
        self.state
            .lock()
            .map(|_| StorageHealth::Healthy)
            .map_err(|_| DurableStoreError::Internal)
    }
}

impl ReplayProtector for MemoryLocalStore {
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError> {
        let mut state = self.state.lock().map_err(|_| ReplayError::Internal)?;
        if !state
            .seen_handshakes
            .insert((peer_verifying_key.0, *binding.as_bytes()))
        {
            return Err(ReplayError::Replayed);
        }
        Ok(())
    }
}

impl RecoveryPlanStore for MemoryLocalStore {
    fn install_recovery_plan(&self, plan: &RecoveryPlan) -> Result<(), DurableStoreError> {
        let plan = canonical_recovery_plan(plan).map_err(|_| DurableStoreError::InvalidRecord)?;
        let plan_id = plan.plan_id.as_opaque().as_str().to_owned();
        let identity_key = recovery_identity_key(&plan.scope, &plan.identity_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.recovery_plans.get(&plan_id) {
            return if existing == &plan
                && state.active_recovery_plans.get(&identity_key) == Some(&plan_id)
            {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.active_recovery_plans.contains_key(&identity_key) {
            return Err(DurableStoreError::Conflict);
        }
        state.recovery_plans.insert(plan_id.clone(), plan);
        state.active_recovery_plans.insert(identity_key, plan_id);
        Ok(())
    }

    fn rotate_recovery_plan(
        &self,
        expected_current: &RecoveryPlanId,
        replacement: &RecoveryPlan,
    ) -> Result<(), DurableStoreError> {
        let replacement =
            canonical_recovery_plan(replacement).map_err(|_| DurableStoreError::InvalidRecord)?;
        let expected_id = expected_current.as_opaque().as_str();
        let replacement_id = replacement.plan_id.as_opaque().as_str().to_owned();
        let identity_key = recovery_identity_key(&replacement.scope, &replacement.identity_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let current = state
            .recovery_plans
            .get(expected_id)
            .ok_or(DurableStoreError::Conflict)?;
        if current.scope != replacement.scope || current.identity_id != replacement.identity_id {
            return Err(DurableStoreError::Conflict);
        }
        if state
            .active_recovery_plans
            .get(&identity_key)
            .map(String::as_str)
            != Some(expected_id)
        {
            return Err(DurableStoreError::Conflict);
        }
        if replacement_id == expected_id {
            return if current == &replacement {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.recovery_plans.contains_key(&replacement_id) {
            return Err(DurableStoreError::Conflict);
        }
        state
            .recovery_plans
            .insert(replacement_id.clone(), replacement.clone());
        state
            .active_recovery_plans
            .insert(identity_key, replacement_id);
        Ok(())
    }

    fn revoke_recovery_plan(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
        expected_current: &RecoveryPlanId,
    ) -> Result<(), DurableStoreError> {
        let expected_id = expected_current.as_opaque().as_str();
        let identity_key = recovery_identity_key(scope, identity_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        match state.active_recovery_plans.get(&identity_key) {
            Some(active) if active == expected_id => {
                state.active_recovery_plans.remove(&identity_key);
                Ok(())
            }
            Some(_) => Err(DurableStoreError::Conflict),
            None => match state.recovery_plans.get(expected_id) {
                Some(plan) if &plan.scope == scope && &plan.identity_id == identity_id => Ok(()),
                _ => Err(DurableStoreError::Conflict),
            },
        }
    }

    fn active_recovery_plan(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<RecoveryPlan>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let Some(plan_id) = state
            .active_recovery_plans
            .get(&recovery_identity_key(scope, identity_id))
        else {
            return Ok(None);
        };
        state
            .recovery_plans
            .get(plan_id)
            .cloned()
            .map(Some)
            .ok_or(DurableStoreError::Corrupt)
    }
}

fn recovery_identity_key(scope: &TenantScope, identity_id: &IdentityId) -> RecoveryIdentityKey {
    (
        scope_key(scope),
        identity_id.as_opaque().as_str().to_owned(),
    )
}

fn conversation_key(scope: &TenantScope, conversation_id: &ConversationId) -> ConversationKey {
    (
        scope_key(scope),
        conversation_id.as_opaque().as_str().to_owned(),
    )
}

fn message_key(scope: &TenantScope, message_id: &MessageId) -> MessageKey {
    (scope_key(scope), message_id.as_opaque().as_str().to_owned())
}

fn delivery_key(scope: &TenantScope, delivery_id: &DeliveryId) -> DeliveryKey {
    (
        scope_key(scope),
        delivery_id.as_opaque().as_str().to_owned(),
    )
}

impl ConversationStore for MemoryLocalStore {
    fn persist_conversation(
        &self,
        conversation: &ConversationRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_conversation(conversation).map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = conversation_key(
            &conversation.scope,
            &conversation.conversation.conversation_id,
        );
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(parent_id) = &conversation.parent_conversation_id {
            let parent = state
                .conversations
                .get(&conversation_key(&conversation.scope, parent_id))
                .ok_or(DurableStoreError::InvalidRecord)?;
            validate_conversation_parent_kind(
                conversation.conversation.kind,
                parent.conversation.kind,
            )
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        }
        if let Some(existing) = state.conversations.get(&key) {
            return if existing == conversation {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.conversations.insert(key, conversation.clone());
        Ok(DurableRecordStatus::Persisted)
    }

    fn conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<ConversationRecord>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .conversations
            .get(&conversation_key(scope, conversation_id))
            .cloned())
    }
}

impl MessageStore for MemoryLocalStore {
    fn persist_message(
        &self,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut persisted =
            canonical_message(message).map_err(|_| DurableStoreError::InvalidRecord)?;
        if !matches!(
            message.delivery_state,
            DeliveryState::Created | DeliveryState::Persisted
        ) {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let conversation_key =
            conversation_key(&message.scope, &message.conversation.conversation_id);
        let conversation = state
            .conversations
            .get(&conversation_key)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if conversation.conversation != message.conversation {
            return Err(DurableStoreError::Conflict);
        }
        let key = message_key(&message.scope, &message.message_id);
        persisted.delivery_state = DeliveryState::Persisted;
        if let Some(existing) = state.messages.get(&key) {
            return if existing == &persisted {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.messages.insert(key, persisted);
        Ok(DurableRecordStatus::Persisted)
    }

    fn message(
        &self,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state.messages.get(&message_key(scope, message_id)).cloned())
    }
}

impl DeliveryStore for MemoryLocalStore {
    fn create_delivery_attempt(
        &self,
        attempt: &DeliveryAttempt,
        persisted_evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_delivery_attempt(attempt).map_err(|_| DurableStoreError::InvalidRecord)?;
        validate_delivery_evidence(attempt, persisted_evidence, DeliveryState::Persisted)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = delivery_key(&attempt.scope, &attempt.delivery_id);
        let message_key = message_key(&attempt.scope, &attempt.message_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let message = state
            .messages
            .get(&message_key)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if message.delivery_state != DeliveryState::Persisted {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(existing) = state.deliveries.get(&key) {
            if existing != attempt {
                return Err(DurableStoreError::Conflict);
            }
            let evidence = state
                .delivery_evidence
                .get(&key)
                .ok_or(DurableStoreError::Corrupt)?;
            return if evidence.first() == Some(persisted_evidence) {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.deliveries.insert(key.clone(), attempt.clone());
        state
            .delivery_evidence
            .insert(key, vec![persisted_evidence.clone()]);
        Ok(DurableRecordStatus::Persisted)
    }

    fn transition_delivery(
        &self,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
        expected_state: DeliveryState,
        next_state: DeliveryState,
        evidence: Option<&DeliveryEvidence>,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = delivery_key(scope, delivery_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let current = state
            .deliveries
            .get(&key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        if current.state != expected_state {
            return Err(DurableStoreError::Conflict);
        }
        validate_delivery_transition(&current, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let proof_required = matches!(
            next_state,
            DeliveryState::Acknowledged | DeliveryState::Delivered | DeliveryState::Read
        );
        if proof_required && evidence.is_none() {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(evidence) = evidence {
            validate_delivery_evidence(&current, evidence, next_state)
                .map_err(|_| DurableStoreError::InvalidRecord)?;
            append_delivery_evidence(&mut state, &key, evidence)?;
        }
        let attempt = state
            .deliveries
            .get_mut(&key)
            .ok_or(DurableStoreError::Corrupt)?;
        attempt.state = next_state;
        Ok(DurableRecordStatus::Persisted)
    }

    fn record_delivery_evidence(
        &self,
        evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = delivery_key(&evidence.scope, &evidence.delivery_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let current = state
            .deliveries
            .get(&key)
            .ok_or(DurableStoreError::InvalidRecord)?;
        validate_delivery_evidence_binding(current, evidence)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        append_delivery_evidence(&mut state, &key, evidence)
    }

    fn delivery_attempt(
        &self,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
    ) -> Result<Option<DeliveryAttempt>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .deliveries
            .get(&delivery_key(scope, delivery_id))
            .cloned())
    }
}

fn append_delivery_evidence(
    state: &mut MemoryState,
    key: &DeliveryKey,
    evidence: &DeliveryEvidence,
) -> Result<DurableRecordStatus, DurableStoreError> {
    let journal = state.delivery_evidence.entry(key.clone()).or_default();
    if let Some(existing) = journal
        .iter()
        .find(|item| item.logical_order == evidence.logical_order)
    {
        return if existing == evidence {
            Ok(DurableRecordStatus::Duplicate)
        } else {
            Err(DurableStoreError::Conflict)
        };
    }
    validate_delivery_evidence_order(
        journal.last().map(|last| last.logical_order),
        evidence.logical_order,
    )
    .map_err(|_| DurableStoreError::Conflict)?;
    journal.push(evidence.clone());
    Ok(DurableRecordStatus::Persisted)
}

impl CommandAcceptanceStore for MemoryLocalStore {
    fn accept_command(
        &self,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, DurableStoreError> {
        validate_command(command).map_err(map_command_error)?;
        let key = command_key(command)?;
        let command_ref = command_ref_key(&command.scope, &command.command_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;

        if let Some(original) = state.accepted.get(&key) {
            return receipt_for_existing(original, command);
        }
        if state.accepted_by_id.contains_key(&command_ref) {
            return Err(DurableStoreError::Conflict);
        }

        state.accepted.insert(key, command.clone());
        state.accepted_by_id.insert(command_ref, command.clone());
        Ok(CommandReceipt {
            command_id: command.command_id.clone(),
            status: CommandReceiptStatus::Accepted,
            original_command_id: None,
        })
    }
}

fn map_command_error(error: CommandError) -> DurableStoreError {
    match error {
        CommandError::IdempotencyConflict => DurableStoreError::Conflict,
        CommandError::InvalidCommandType
        | CommandError::MissingIdempotencyKey
        | CommandError::EmptyIdempotencyKey
        | CommandError::IdempotencyKeyTooLong
        | CommandError::PayloadTooLarge => DurableStoreError::InvalidRecord,
    }
}

fn scope_key(scope: &TenantScope) -> ScopeKey {
    (
        scope.tenant_id.as_opaque().as_str().to_owned(),
        scope
            .namespace_id
            .as_ref()
            .map(|value| value.as_opaque().as_str().to_owned()),
    )
}

fn command_key(command: &CommandEnvelope) -> Result<CommandKey, DurableStoreError> {
    let idempotency_key = command
        .correlation
        .idempotency_key
        .clone()
        .ok_or(DurableStoreError::InvalidRecord)?;
    Ok((scope_key(&command.scope), idempotency_key))
}

fn command_ref_key(scope: &TenantScope, command_id: &CommandId) -> CommandRefKey {
    (scope_key(scope), command_id.as_opaque().as_str().to_owned())
}

fn event_key(event: &EventEnvelope) -> EventKey {
    (
        scope_key(&event.scope),
        event.event_id.as_opaque().as_str().to_owned(),
    )
}

fn receipt_for_existing(
    original: &CommandEnvelope,
    incoming: &CommandEnvelope,
) -> Result<CommandReceipt, DurableStoreError> {
    match compare_command_idempotency(original, incoming).map_err(map_command_error)? {
        IdempotencyDecision::DuplicateOf(original_command_id) => Ok(CommandReceipt {
            command_id: incoming.command_id.clone(),
            status: CommandReceiptStatus::Duplicate,
            original_command_id: Some(original_command_id),
        }),
        IdempotencyDecision::New => Err(DurableStoreError::Internal),
    }
}

fn map_event_error(_error: EventError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

impl EventJournalStore for MemoryLocalStore {
    fn append_event(&self, event: &EventEnvelope) -> Result<EventAppendStatus, DurableStoreError> {
        validate_event(event).map_err(map_event_error)?;
        let key = event_key(event);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(original) = state.events.get(&key) {
            return if original == event {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.events.insert(key, event.clone());
        Ok(EventAppendStatus::Appended)
    }
}

impl CommandOutcomeStore for MemoryLocalStore {
    fn record_terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError> {
        validate_event(event).map_err(map_event_error)?;
        if &event.scope != scope
            || event.correlation.causation_id.as_ref() != Some(command_id.as_opaque())
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let command_ref = command_ref_key(scope, command_id);
        let event_key = event_key(event);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if !state.accepted_by_id.contains_key(&command_ref) {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(existing_id) = state.terminal_events.get(&command_ref) {
            if existing_id != &event.event_id {
                return Err(DurableStoreError::Conflict);
            }
            return match state.events.get(&event_key) {
                Some(original) if original == event => Ok(EventAppendStatus::Duplicate),
                _ => Err(DurableStoreError::Conflict),
            };
        }
        if let Some(original) = state.events.get(&event_key) {
            if original != event {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            state.events.insert(event_key, event.clone());
        }
        state
            .terminal_events
            .insert(command_ref, event.event_id.clone());
        Ok(EventAppendStatus::Appended)
    }

    fn terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
    ) -> Result<Option<EventId>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .terminal_events
            .get(&command_ref_key(scope, command_id))
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use ucr_core::{
        CommandAcceptanceStore, CommandOutcomeStore, DurableStoreError, EventAppendStatus,
        EventJournalStore, StorageProvider,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CommandEnvelope, CommandId, CorrelationContext, DeviceId,
        DeviceRef, EventEnvelope, EventId, IdentityId, NamespaceId, OpaqueId, ProtocolVersion,
        TenantId, TenantScope,
    };
    use ucr_protocol::CommandReceiptStatus;

    use super::MemoryLocalStore;

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn command(id: &str, key: &str, payload: &[u8]) -> CommandEnvelope {
        CommandEnvelope {
            command_id: CommandId::from_opaque(opaque(id)),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(opaque("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(opaque("namespace-a"))),
            },
            command_type: "ucr.message.send".to_owned(),
            payload: payload.to_vec(),
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: None,
                idempotency_key: Some(key.to_owned()),
            },
        }
    }

    fn event(id: &str, causation: &str, payload: &[u8]) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(opaque(id)),
            scope: command("scope-source", "scope-key", b"").scope,
            event_type: "ucr.command.completed".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(opaque("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(opaque("device-a")),
                identity_id: IdentityId::from_opaque(opaque("identity-a")),
            },
            wall_time_unix_ms: 1_788_330_000_000,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: Some(opaque(causation)),
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
        }
    }

    #[test]
    fn memory_store_is_healthy_and_versioned() {
        let store = MemoryLocalStore::default();
        assert_eq!(store.schema_version(), Ok(5));
        assert_eq!(store.health(), Ok(ucr_core::StorageHealth::Healthy));
    }

    #[test]
    fn memory_store_accepts_then_deduplicates() {
        let store = MemoryLocalStore::default();
        let first = command("command-a", "retry-a", b"payload");
        let retry = command("command-b", "retry-a", b"payload");

        let accepted = store.accept_command(&first).expect("accepted");
        assert_eq!(accepted.status, CommandReceiptStatus::Accepted);
        assert!(accepted.original_command_id.is_none());

        let duplicate = store.accept_command(&retry).expect("duplicate");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(first.command_id));
    }

    #[test]
    fn memory_store_conflict_fails_closed() {
        let store = MemoryLocalStore::default();
        store
            .accept_command(&command("command-a", "retry-a", b"payload-a"))
            .expect("accepted");
        assert_eq!(
            store.accept_command(&command("command-b", "retry-a", b"payload-b")),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn scoped_command_id_cannot_be_reused_with_another_idempotency_key() {
        let store = MemoryLocalStore::default();
        store
            .accept_command(&command("command-a", "retry-a", b"payload"))
            .expect("accepted");
        assert_eq!(
            store.accept_command(&command("command-a", "retry-b", b"payload")),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn event_append_is_idempotent_but_event_id_reuse_conflicts() {
        let store = MemoryLocalStore::default();
        let first = event("event-a", "command-a", b"done");
        assert_eq!(store.append_event(&first), Ok(EventAppendStatus::Appended));
        assert_eq!(store.append_event(&first), Ok(EventAppendStatus::Duplicate));
        let changed = event("event-a", "command-a", b"different");
        assert_eq!(
            store.append_event(&changed),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn terminal_event_requires_accepted_command_and_matching_causation() {
        let store = MemoryLocalStore::default();
        let accepted = command("command-a", "retry-a", b"payload");
        let terminal = event("event-a", "command-a", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Err(DurableStoreError::InvalidRecord)
        );
        store.accept_command(&accepted).expect("accepted");
        let wrong = event("event-b", "command-b", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &wrong),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn terminal_event_is_atomic_and_idempotent() {
        let store = MemoryLocalStore::default();
        let accepted = command("command-a", "retry-a", b"payload");
        store.accept_command(&accepted).expect("accepted");
        let terminal = event("event-a", "command-a", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.terminal_event(&accepted.scope, &accepted.command_id),
            Ok(Some(terminal.event_id.clone()))
        );
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Duplicate)
        );
        let second = event("event-b", "command-a", b"also-done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &second),
            Err(DurableStoreError::Conflict)
        );
    }
}

#[cfg(test)]
mod replay_tests {
    use ucr_crypto::{ReplayError, ReplayProtector, TranscriptBinding, VerifyingKeyBytes};

    use super::MemoryLocalStore;

    #[test]
    fn memory_replay_guard_accepts_once() {
        let store = MemoryLocalStore::default();
        let peer = VerifyingKeyBytes([7_u8; 32]);
        let binding = TranscriptBinding::from_bytes([9_u8; 32]);
        assert_eq!(store.record_once(&peer, &binding), Ok(()));
        assert_eq!(
            store.record_once(&peer, &binding),
            Err(ReplayError::Replayed)
        );
    }
}

#[cfg(test)]
mod recovery_tests {
    use ucr_core::{DurableStoreError, RecoveryPlanStore};
    use ucr_model::{
        DeviceId, DeviceLifecycleState, HistoricalMessageAccess, IdentityId, OpaqueId,
        RecoveryAuthority, RecoveryPlan, RecoveryPlanId, RecoveryTrustModel, TenantId, TenantScope,
    };

    use super::MemoryLocalStore;

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn plan(plan_id: &str, identity: &str) -> RecoveryPlan {
        RecoveryPlan {
            plan_id: RecoveryPlanId::from_opaque(id(plan_id)),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(id("tenant-a")),
                namespace_id: None,
            },
            identity_id: IdentityId::from_opaque(id(identity)),
            authorities: vec![
                RecoveryAuthority::RecoveryKey,
                RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(id("trusted-device"))),
            ],
            historical_message_access: HistoricalMessageAccess::ExplicitEncryptedRecovery,
            trust_model: RecoveryTrustModel::UserControlled,
            recovered_device_state: DeviceLifecycleState::ReverificationRequired,
        }
    }

    #[test]
    fn recovery_plan_install_rotate_and_revoke_are_fail_closed() {
        let store = MemoryLocalStore::default();
        let first = plan("plan-a", "identity-a");
        store.install_recovery_plan(&first).expect("install first");
        assert_eq!(
            store
                .active_recovery_plan(&first.scope, &first.identity_id)
                .expect("lookup"),
            Some(first.clone())
        );

        let replacement = plan("plan-b", "identity-a");
        store
            .rotate_recovery_plan(&first.plan_id, &replacement)
            .expect("rotate");
        assert_eq!(
            store
                .active_recovery_plan(&replacement.scope, &replacement.identity_id)
                .expect("lookup replacement"),
            Some(replacement.clone())
        );

        store
            .revoke_recovery_plan(
                &replacement.scope,
                &replacement.identity_id,
                &replacement.plan_id,
            )
            .expect("revoke");
        assert_eq!(
            store
                .active_recovery_plan(&replacement.scope, &replacement.identity_id)
                .expect("lookup revoked"),
            None
        );
        store
            .revoke_recovery_plan(
                &replacement.scope,
                &replacement.identity_id,
                &replacement.plan_id,
            )
            .expect("idempotent revoke");
        assert_eq!(
            store.install_recovery_plan(&replacement),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn recovery_rotation_cannot_change_identity_or_skip_expected_plan() {
        let store = MemoryLocalStore::default();
        let first = plan("plan-a", "identity-a");
        store.install_recovery_plan(&first).expect("install first");

        let wrong_identity = plan("plan-b", "identity-b");
        assert_eq!(
            store.rotate_recovery_plan(&first.plan_id, &wrong_identity),
            Err(DurableStoreError::Conflict)
        );
        let unknown = RecoveryPlanId::from_opaque(id("unknown-plan"));
        assert_eq!(
            store.rotate_recovery_plan(&unknown, &plan("plan-c", "identity-a")),
            Err(DurableStoreError::Conflict)
        );
    }
}

#[cfg(test)]
mod message_tests {
    use ucr_core::{ConversationStore, DurableRecordStatus, DurableStoreError, MessageStore};
    use ucr_model::{
        ActorId, ActorKind, ActorRef, ConversationId, ConversationKind, ConversationRecord,
        ConversationRef, CorrelationContext, DeliveryPolicy, DeliveryState, DeviceId, DeviceRef,
        IdentityId, MessageEnvelope, MessageId, OpaqueId, OriginRef, PrincipalId, TenantId,
        TenantScope,
    };

    use super::MemoryLocalStore;

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    pub(super) fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(id("tenant-message")),
            namespace_id: None,
        }
    }
    pub(super) fn conversation() -> ConversationRecord {
        ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(id("conversation-message")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        }
    }

    pub(super) fn message() -> MessageEnvelope {
        MessageEnvelope {
            message_id: MessageId::from_opaque(id("message-memory")),
            scope: scope(),
            conversation: conversation().conversation,
            author: ActorRef {
                actor_id: ActorId::from_opaque(id("actor-message")),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(id("device-message")),
                identity_id: IdentityId::from_opaque(id("identity-message")),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"hello".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(PrincipalId::from_opaque(id("principal-message"))),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: id("correlation-message"),
                causation_id: None,
                idempotency_key: Some("message-memory-key".into()),
            },
            external_mappings: Vec::new(),
            signature: None,
        }
    }

    #[test]
    fn conversation_and_message_persist_and_deduplicate() {
        let store = MemoryLocalStore::default();
        assert_eq!(
            store.persist_conversation(&conversation()),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_conversation(&conversation()),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert_eq!(
            store.persist_message(&message()),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_message(&message()),
            Ok(DurableRecordStatus::Duplicate)
        );
        let loaded = store
            .message(&scope(), &message().message_id)
            .expect("load message")
            .expect("message exists");
        assert_eq!(loaded.delivery_state, DeliveryState::Persisted);
    }

    #[test]
    fn conversation_hierarchy_requires_existing_parent_with_valid_kind() {
        let store = MemoryLocalStore::default();
        let root = conversation();
        store.persist_conversation(&root).expect("persist root");

        let topic = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(id("topic-memory")),
                kind: ConversationKind::Topic,
            },
            parent_conversation_id: Some(root.conversation.conversation_id.clone()),
        };
        assert_eq!(
            store.persist_conversation(&topic),
            Ok(DurableRecordStatus::Persisted)
        );

        let thread = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(id("thread-memory")),
                kind: ConversationKind::Thread,
            },
            parent_conversation_id: Some(topic.conversation.conversation_id.clone()),
        };
        assert_eq!(
            store.persist_conversation(&thread),
            Ok(DurableRecordStatus::Persisted)
        );

        let invalid_thread = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(id("thread-invalid")),
                kind: ConversationKind::Thread,
            },
            parent_conversation_id: Some(root.conversation.conversation_id.clone()),
        };
        assert_eq!(
            store.persist_conversation(&invalid_thread),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn message_requires_matching_persisted_conversation() {
        let store = MemoryLocalStore::default();
        assert_eq!(
            store.persist_message(&message()),
            Err(DurableStoreError::InvalidRecord)
        );
        store
            .persist_conversation(&conversation())
            .expect("persist conversation");
        let mut conflicting = message();
        conflicting.content = b"changed".to_vec();
        store.persist_message(&message()).expect("persist message");
        assert_eq!(
            store.persist_message(&conflicting),
            Err(DurableStoreError::Conflict)
        );
    }
}

#[cfg(test)]
mod delivery_tests {
    use ucr_core::{
        ConversationStore, DeliveryStore, DurableRecordStatus, DurableStoreError, MessageStore,
    };
    use ucr_model::{
        DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryId, DeliveryState,
        OpaqueId,
    };

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }
    fn attempt(id: &str) -> DeliveryAttempt {
        let message = super::message_tests::message();
        DeliveryAttempt {
            delivery_id: DeliveryId::from_opaque(oid(id)),
            scope: message.scope,
            message_id: message.message_id,
            state: DeliveryState::Persisted,
        }
    }
    fn evidence(
        attempt: &DeliveryAttempt,
        kind: DeliveryEvidenceKind,
        order: u64,
    ) -> DeliveryEvidence {
        DeliveryEvidence {
            delivery_id: attempt.delivery_id.clone(),
            scope: attempt.scope.clone(),
            message_id: attempt.message_id.clone(),
            kind,
            logical_order: order,
        }
    }
    fn seeded_store() -> MemoryLocalStore {
        let store = MemoryLocalStore::default();
        store
            .persist_conversation(&super::message_tests::conversation())
            .expect("persist conversation");
        store
            .persist_message(&super::message_tests::message())
            .expect("persist message");
        store
    }

    #[test]
    fn delivery_attempt_starts_with_persisted_local_evidence() {
        let store = seeded_store();
        let attempt = attempt("delivery-a");
        let evidence = evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1);
        assert_eq!(
            store.create_delivery_attempt(&attempt, &evidence),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.create_delivery_attempt(&attempt, &evidence),
            Ok(DurableRecordStatus::Duplicate)
        );
    }

    #[test]
    fn relay_evidence_does_not_inflate_delivery_state() {
        let store = seeded_store();
        let attempt = attempt("delivery-relay");
        store
            .create_delivery_attempt(
                &attempt,
                &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1),
            )
            .expect("create attempt");
        assert_eq!(
            store.record_delivery_evidence(&evidence(
                &attempt,
                DeliveryEvidenceKind::ReplicatedToRelay,
                2,
            )),
            Ok(DurableRecordStatus::Persisted)
        );
        let loaded = store
            .delivery_attempt(&attempt.scope, &attempt.delivery_id)
            .expect("load attempt")
            .expect("attempt exists");
        assert_eq!(loaded.state, DeliveryState::Persisted);
    }

    #[test]
    fn proof_required_transitions_fail_closed_without_matching_evidence() {
        let store = seeded_store();
        let attempt = attempt("delivery-proof");
        store
            .create_delivery_attempt(
                &attempt,
                &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 1),
            )
            .expect("create attempt");
        for (expected, next) in [
            (DeliveryState::Persisted, DeliveryState::Encrypted),
            (DeliveryState::Encrypted, DeliveryState::Queued),
            (DeliveryState::Queued, DeliveryState::RoutePlanned),
            (DeliveryState::RoutePlanned, DeliveryState::InFlight),
        ] {
            store
                .transition_delivery(&attempt.scope, &attempt.delivery_id, expected, next, None)
                .expect("advance local state");
        }
        assert_eq!(
            store.transition_delivery(
                &attempt.scope,
                &attempt.delivery_id,
                DeliveryState::InFlight,
                DeliveryState::Acknowledged,
                None,
            ),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn evidence_order_is_monotonic_and_conflicting_order_fails() {
        let store = seeded_store();
        let attempt = attempt("delivery-order");
        store
            .create_delivery_attempt(
                &attempt,
                &evidence(&attempt, DeliveryEvidenceKind::PersistedLocal, 10),
            )
            .expect("create attempt");
        assert_eq!(
            store.record_delivery_evidence(&evidence(
                &attempt,
                DeliveryEvidenceKind::ReplicatedToRelay,
                9,
            )),
            Err(DurableStoreError::Conflict)
        );
        let relay = evidence(&attempt, DeliveryEvidenceKind::ReplicatedToRelay, 11);
        assert_eq!(
            store.record_delivery_evidence(&relay),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.record_delivery_evidence(&relay),
            Ok(DurableRecordStatus::Duplicate)
        );
    }
}

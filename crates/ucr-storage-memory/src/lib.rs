#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Mutex,
};

use ucr_core::{
    AntiEntropyStore, CommandAcceptanceStore, CommandOutcomeStore, ConversationStore,
    DeliveryStore, DurableRecordStatus, DurableStoreError, EventAppendStatus, EventJournalStore,
    MessageStore, RecoveryPlanStore, StorageHealth, StorageProvider, SyncStore,
    TrustedSigningKeyStore,
};
use ucr_crypto::{
    ReplayError, ReplayProtector, TranscriptBinding, TrustedKeyResolutionError,
    TrustedSigningKeyResolver, VerifyingKeyBytes,
};
use ucr_model::{
    AntiEntropyCursor, AntiEntropyPage, CommandEnvelope, CommandId, ConversationId,
    ConversationRecord, DeliveryAttempt, DeliveryEvidence, DeliveryId, DeliveryState, DeviceId,
    EventEnvelope, EventId, EventReconciliation, EventReplicaState, EventSummary, IdentityId,
    KeyId, MessageEnvelope, MessageId, PublicKeyDescriptor, RecoveryPlan, RecoveryPlanId,
    SessionId, SyncCheckpoint, SyncSession, SyncState, TenantScope, TrustedSigningKeyRecord,
    TrustedSigningKeyState,
};
use ucr_protocol::{
    AntiEntropyError, CommandError, CommandReceipt, EventError, IdempotencyDecision,
    accepted_command_receipt, anti_entropy_session_binding, canonical_command, canonical_event,
    canonical_message, canonical_recovery_plan, canonical_sync_session,
    compare_command_idempotency, duplicate_command_receipt, event_fingerprint,
    validate_anti_entropy_cursor, validate_anti_entropy_page_size, validate_anti_entropy_session,
    validate_anti_entropy_summary_count, validate_conversation, validate_conversation_parent_kind,
    validate_delivery_attempt, validate_delivery_evidence, validate_delivery_evidence_binding,
    validate_delivery_evidence_order, validate_delivery_transition, validate_sync_checkpoint,
    validate_sync_transition, validate_trusted_signing_key_descriptor,
};

const SCHEMA_VERSION: u32 = 9;
type ScopeKey = (String, Option<String>);
type CommandKey = (ScopeKey, String);
type CommandRefKey = (ScopeKey, String);
type EventKey = (ScopeKey, String);
type ReplayKey = ([u8; 32], [u8; 32]);
type RecoveryIdentityKey = (ScopeKey, String);
type ConversationKey = (ScopeKey, String);
type MessageKey = (ScopeKey, String);
type DeliveryKey = (ScopeKey, String);
type SyncKey = (ScopeKey, String);
type TrustedSigningKeyRef = (ScopeKey, String);
type TrustedSigningDeviceRef = (ScopeKey, String);

#[derive(Default)]
struct MemoryState {
    accepted: HashMap<CommandKey, CommandEnvelope>,
    accepted_by_id: HashMap<CommandRefKey, CommandEnvelope>,
    events: HashMap<EventKey, EventEnvelope>,
    event_order: Vec<EventKey>,
    terminal_events: HashMap<CommandRefKey, EventId>,
    seen_handshakes: HashSet<ReplayKey>,
    recovery_plans: HashMap<String, RecoveryPlan>,
    active_recovery_plans: HashMap<RecoveryIdentityKey, String>,
    conversations: HashMap<ConversationKey, ConversationRecord>,
    messages: HashMap<MessageKey, MessageEnvelope>,
    deliveries: HashMap<DeliveryKey, DeliveryAttempt>,
    delivery_evidence: HashMap<DeliveryKey, Vec<DeliveryEvidence>>,
    sync_sessions: HashMap<SyncKey, SyncSession>,
    sync_checkpoints: HashMap<SyncKey, Vec<SyncCheckpoint>>,
    trusted_signing_keys: HashMap<TrustedSigningKeyRef, TrustedSigningKeyRecord>,
    active_trusted_signing_keys: HashMap<TrustedSigningDeviceRef, String>,
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

impl TrustedSigningKeyStore for MemoryLocalStore {
    fn provision_trusted_signing_key(
        &self,
        scope: &TenantScope,
        descriptor: &PublicKeyDescriptor,
    ) -> Result<(), DurableStoreError> {
        validate_trusted_signing_key_descriptor(descriptor)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let key_ref = trusted_key_ref(scope, &descriptor.key_id);
        let device_ref = trusted_device_ref(scope, &descriptor.device_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;

        if let Some(existing) = state.trusted_signing_keys.get(&key_ref) {
            return if existing.state == TrustedSigningKeyState::Active
                && existing.descriptor == *descriptor
                && state.active_trusted_signing_keys.get(&device_ref)
                    == Some(&descriptor.key_id.as_opaque().as_str().to_owned())
            {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if state.active_trusted_signing_keys.contains_key(&device_ref) {
            return Err(DurableStoreError::Conflict);
        }

        state.trusted_signing_keys.insert(
            key_ref,
            TrustedSigningKeyRecord {
                scope: scope.clone(),
                descriptor: descriptor.clone(),
                state: TrustedSigningKeyState::Active,
            },
        );
        state.active_trusted_signing_keys.insert(
            device_ref,
            descriptor.key_id.as_opaque().as_str().to_owned(),
        );
        Ok(())
    }

    fn rotate_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
        replacement: &PublicKeyDescriptor,
    ) -> Result<(), DurableStoreError> {
        validate_trusted_signing_key_descriptor(replacement)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if replacement.device_id != *device_id || replacement.key_id == *expected_current {
            return Err(DurableStoreError::Conflict);
        }
        let device_ref = trusted_device_ref(scope, device_id);
        let expected_ref = trusted_key_ref(scope, expected_current);
        let replacement_ref = trusted_key_ref(scope, &replacement.key_id);
        let expected_id = expected_current.as_opaque().as_str();
        let replacement_id = replacement.key_id.as_opaque().as_str();
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;

        match state.active_trusted_signing_keys.get(&device_ref) {
            Some(active) if active == replacement_id => {
                let old = state.trusted_signing_keys.get(&expected_ref);
                let new = state.trusted_signing_keys.get(&replacement_ref);
                return if old.is_some_and(|record| {
                    record.state == TrustedSigningKeyState::Revoked
                        && record.descriptor.device_id == *device_id
                }) && new.is_some_and(|record| {
                    record.state == TrustedSigningKeyState::Active
                        && record.descriptor == *replacement
                }) {
                    Ok(())
                } else {
                    Err(DurableStoreError::Conflict)
                };
            }
            Some(active) if active == expected_id => {}
            _ => return Err(DurableStoreError::Conflict),
        }
        if state.trusted_signing_keys.contains_key(&replacement_ref) {
            return Err(DurableStoreError::Conflict);
        }
        let current = state
            .trusted_signing_keys
            .get_mut(&expected_ref)
            .ok_or(DurableStoreError::Corrupt)?;
        if current.state != TrustedSigningKeyState::Active
            || current.descriptor.device_id != *device_id
        {
            return Err(DurableStoreError::Corrupt);
        }
        current.state = TrustedSigningKeyState::Revoked;
        state.trusted_signing_keys.insert(
            replacement_ref,
            TrustedSigningKeyRecord {
                scope: scope.clone(),
                descriptor: replacement.clone(),
                state: TrustedSigningKeyState::Active,
            },
        );
        state
            .active_trusted_signing_keys
            .insert(device_ref, replacement_id.to_owned());
        Ok(())
    }

    fn revoke_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
    ) -> Result<(), DurableStoreError> {
        let device_ref = trusted_device_ref(scope, device_id);
        let key_ref = trusted_key_ref(scope, expected_current);
        let expected_id = expected_current.as_opaque().as_str();
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        match state.active_trusted_signing_keys.get(&device_ref) {
            Some(active) if active == expected_id => {
                let current = state
                    .trusted_signing_keys
                    .get_mut(&key_ref)
                    .ok_or(DurableStoreError::Corrupt)?;
                if current.state != TrustedSigningKeyState::Active
                    || current.descriptor.device_id != *device_id
                {
                    return Err(DurableStoreError::Corrupt);
                }
                current.state = TrustedSigningKeyState::Revoked;
                state.active_trusted_signing_keys.remove(&device_ref);
                Ok(())
            }
            Some(_) => Err(DurableStoreError::Conflict),
            None => match state.trusted_signing_keys.get(&key_ref) {
                Some(record)
                    if record.state == TrustedSigningKeyState::Revoked
                        && record.descriptor.device_id == *device_id =>
                {
                    Ok(())
                }
                _ => Err(DurableStoreError::Conflict),
            },
        }
    }

    fn trusted_signing_key(
        &self,
        scope: &TenantScope,
        key_id: &KeyId,
    ) -> Result<Option<TrustedSigningKeyRecord>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .trusted_signing_keys
            .get(&trusted_key_ref(scope, key_id))
            .cloned())
    }

    fn active_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<PublicKeyDescriptor>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let device_ref = trusted_device_ref(scope, device_id);
        let Some(key_id) = state.active_trusted_signing_keys.get(&device_ref) else {
            return Ok(None);
        };
        let key_ref = (device_ref.0.clone(), key_id.clone());
        let record = state
            .trusted_signing_keys
            .get(&key_ref)
            .ok_or(DurableStoreError::Corrupt)?;
        if record.state != TrustedSigningKeyState::Active
            || record.descriptor.device_id != *device_id
        {
            return Err(DurableStoreError::Corrupt);
        }
        Ok(Some(record.descriptor.clone()))
    }
}

impl TrustedSigningKeyResolver for MemoryLocalStore {
    fn resolve_active_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        key_id: &KeyId,
    ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TrustedKeyResolutionError::Internal)?;
        let device_ref = trusted_device_ref(scope, device_id);
        if state.active_trusted_signing_keys.get(&device_ref)
            != Some(&key_id.as_opaque().as_str().to_owned())
        {
            return Err(TrustedKeyResolutionError::NotTrusted);
        }
        let record = state
            .trusted_signing_keys
            .get(&trusted_key_ref(scope, key_id))
            .ok_or(TrustedKeyResolutionError::Corrupt)?;
        if record.state != TrustedSigningKeyState::Active
            || record.descriptor.device_id != *device_id
        {
            return Err(TrustedKeyResolutionError::Corrupt);
        }
        validate_trusted_signing_key_descriptor(&record.descriptor)
            .map_err(|_| TrustedKeyResolutionError::Corrupt)?;
        Ok(record.descriptor.clone())
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

fn sync_key(scope: &TenantScope, session_id: &SessionId) -> SyncKey {
    (scope_key(scope), session_id.as_opaque().as_str().to_owned())
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

impl SyncStore for MemoryLocalStore {
    fn create_sync_session(
        &self,
        session: &SyncSession,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_sync_session(session.clone())
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = sync_key(&canonical.scope, &canonical.session_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.sync_sessions.get(&key) {
            return if existing == &canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.sync_sessions.insert(key, canonical);
        Ok(DurableRecordStatus::Persisted)
    }

    fn transition_sync(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        expected_state: SyncState,
        next_state: SyncState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = sync_key(scope, session_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let session = state
            .sync_sessions
            .get_mut(&key)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if session.state != expected_state {
            return Err(DurableStoreError::Conflict);
        }
        if expected_state == next_state {
            return Ok(DurableRecordStatus::Duplicate);
        }
        validate_sync_transition(expected_state, next_state)
            .map_err(|_| DurableStoreError::Conflict)?;
        session.state = next_state;
        Ok(DurableRecordStatus::Persisted)
    }

    fn record_sync_checkpoint(
        &self,
        checkpoint: &SyncCheckpoint,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = sync_key(&checkpoint.scope, &checkpoint.session_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let session = state
            .sync_sessions
            .get(&key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        let journal = state.sync_checkpoints.entry(key).or_default();
        if let Some(existing) = journal
            .iter()
            .find(|item| item.generation == checkpoint.generation)
        {
            return if existing == checkpoint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        validate_sync_checkpoint(&session, journal.last(), checkpoint).map_err(
            |error| match error {
                ucr_protocol::SyncError::InvalidCheckpointGeneration
                | ucr_protocol::SyncError::AppliedItemsRegression => DurableStoreError::Conflict,
                _ => DurableStoreError::InvalidRecord,
            },
        )?;
        journal.push(checkpoint.clone());
        Ok(DurableRecordStatus::Persisted)
    }

    fn sync_session(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncSession>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .sync_sessions
            .get(&sync_key(scope, session_id))
            .cloned())
    }

    fn latest_sync_checkpoint(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncCheckpoint>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .sync_checkpoints
            .get(&sync_key(scope, session_id))
            .and_then(|journal| journal.last().cloned()))
    }
}

impl CommandAcceptanceStore for MemoryLocalStore {
    fn accept_command(
        &self,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, DurableStoreError> {
        let command = canonical_command(command).map_err(map_command_error)?;
        let key = command_key(&command)?;
        let command_ref = command_ref_key(&command.scope, &command.command_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;

        if let Some(original) = state.accepted.get(&key) {
            return receipt_for_existing(original, &command);
        }
        if state.accepted_by_id.contains_key(&command_ref) {
            return Err(DurableStoreError::Conflict);
        }

        state.accepted.insert(key, command.clone());
        state.accepted_by_id.insert(command_ref, command.clone());
        Ok(accepted_command_receipt(command.command_id.clone()))
    }
}

fn map_command_error(error: CommandError) -> DurableStoreError {
    match error {
        CommandError::IdempotencyConflict => DurableStoreError::Conflict,
        CommandError::InvalidCommandType
        | CommandError::MissingIdempotencyKey
        | CommandError::EmptyIdempotencyKey
        | CommandError::IdempotencyKeyTooLong
        | CommandError::PayloadTooLarge
        | CommandError::InvalidSchemaVersion
        | CommandError::InvalidExtension
        | CommandError::DuplicateExtension
        | CommandError::TooManyExtensions
        | CommandError::ExtensionPayloadTooLarge => DurableStoreError::InvalidRecord,
    }
}

fn trusted_key_ref(scope: &TenantScope, key_id: &KeyId) -> TrustedSigningKeyRef {
    (scope_key(scope), key_id.as_opaque().as_str().to_owned())
}

fn trusted_device_ref(scope: &TenantScope, device_id: &DeviceId) -> TrustedSigningDeviceRef {
    (scope_key(scope), device_id.as_opaque().as_str().to_owned())
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
        IdempotencyDecision::DuplicateOf(original_command_id) => Ok(duplicate_command_receipt(
            incoming.command_id.clone(),
            original_command_id,
        )),
        IdempotencyDecision::New => Err(DurableStoreError::Internal),
    }
}

fn map_event_error(_error: EventError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

impl EventJournalStore for MemoryLocalStore {
    fn append_event(&self, event: &EventEnvelope) -> Result<EventAppendStatus, DurableStoreError> {
        let event = canonical_event(event).map_err(map_event_error)?;
        let key = event_key(&event);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(original) = state.events.get(&key) {
            return if original == &event {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.events.insert(key.clone(), event);
        state.event_order.push(key);
        Ok(EventAppendStatus::Appended)
    }
}

const MEMORY_CURSOR_VERSION: u8 = 1;
const MEMORY_CURSOR_LEN: usize = 1 + 32 + 8 + 8;

fn load_anti_entropy_session<'a>(
    state: &'a MemoryState,
    scope: &TenantScope,
    session_id: &SessionId,
) -> Result<&'a SyncSession, DurableStoreError> {
    let session = state
        .sync_sessions
        .get(&sync_key(scope, session_id))
        .ok_or(DurableStoreError::InvalidRecord)?;
    validate_anti_entropy_session(session).map_err(map_anti_entropy_error)?;
    Ok(session)
}

fn map_anti_entropy_error(_error: AntiEntropyError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

fn encode_memory_cursor(session: &SyncSession, snapshot: u64, position: u64) -> AntiEntropyCursor {
    let mut token = Vec::with_capacity(MEMORY_CURSOR_LEN);
    token.push(MEMORY_CURSOR_VERSION);
    token.extend_from_slice(&anti_entropy_session_binding(session));
    token.extend_from_slice(&snapshot.to_be_bytes());
    token.extend_from_slice(&position.to_be_bytes());
    AntiEntropyCursor { token }
}

fn decode_memory_cursor(
    session: &SyncSession,
    cursor: &AntiEntropyCursor,
) -> Result<(u64, u64), DurableStoreError> {
    validate_anti_entropy_cursor(&cursor.token).map_err(map_anti_entropy_error)?;
    if cursor.token.len() != MEMORY_CURSOR_LEN || cursor.token[0] != MEMORY_CURSOR_VERSION {
        return Err(DurableStoreError::InvalidRecord);
    }
    let binding = anti_entropy_session_binding(session);
    if cursor.token[1..33] != binding {
        return Err(DurableStoreError::InvalidRecord);
    }
    let snapshot = u64::from_be_bytes(
        cursor.token[33..41]
            .try_into()
            .map_err(|_| DurableStoreError::InvalidRecord)?,
    );
    let position = u64::from_be_bytes(
        cursor.token[41..49]
            .try_into()
            .map_err(|_| DurableStoreError::InvalidRecord)?,
    );
    if position > snapshot {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok((snapshot, position))
}

impl AntiEntropyStore for MemoryLocalStore {
    fn anti_entropy_summary_page(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        cursor: Option<&AntiEntropyCursor>,
        max_items: usize,
    ) -> Result<AntiEntropyPage, DurableStoreError> {
        validate_anti_entropy_page_size(max_items).map_err(map_anti_entropy_error)?;
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let session = load_anti_entropy_session(&state, scope, session_id)?;
        let (snapshot, mut position) = match cursor {
            Some(cursor) => decode_memory_cursor(session, cursor)?,
            None => (
                u64::try_from(state.event_order.len()).map_err(|_| DurableStoreError::Internal)?,
                0,
            ),
        };
        let available =
            u64::try_from(state.event_order.len()).map_err(|_| DurableStoreError::Internal)?;
        if snapshot > available {
            return Err(DurableStoreError::Corrupt);
        }
        let wanted_scope = scope_key(scope);
        let mut summaries = Vec::with_capacity(max_items);
        while position < snapshot && summaries.len() < max_items {
            let index = usize::try_from(position).map_err(|_| DurableStoreError::Corrupt)?;
            let key = state
                .event_order
                .get(index)
                .ok_or(DurableStoreError::Corrupt)?;
            position = position.checked_add(1).ok_or(DurableStoreError::Corrupt)?;
            if key.0 != wanted_scope {
                continue;
            }
            let event = state.events.get(key).ok_or(DurableStoreError::Corrupt)?;
            summaries.push(EventSummary {
                event_id: event.event_id.clone(),
                fingerprint: event_fingerprint(event).map_err(|_| DurableStoreError::Corrupt)?,
            });
        }
        let next_cursor =
            (position < snapshot).then(|| encode_memory_cursor(session, snapshot, position));
        Ok(AntiEntropyPage {
            session_id: session.session_id.clone(),
            scope: session.scope.clone(),
            summaries,
            next_cursor,
        })
    }

    fn classify_event_summaries(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        summaries: &[EventSummary],
    ) -> Result<Vec<EventReconciliation>, DurableStoreError> {
        validate_anti_entropy_summary_count(summaries.len()).map_err(map_anti_entropy_error)?;
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let _session = load_anti_entropy_session(&state, scope, session_id)?;
        let mut seen = HashSet::with_capacity(summaries.len());
        let mut result = Vec::with_capacity(summaries.len());
        for summary in summaries {
            if !seen.insert(summary.event_id.clone()) {
                return Err(DurableStoreError::InvalidRecord);
            }
            let key = (
                scope_key(scope),
                summary.event_id.as_opaque().as_str().to_owned(),
            );
            let state_kind = match state.events.get(&key) {
                None => EventReplicaState::Missing,
                Some(local) => {
                    let local_fingerprint =
                        event_fingerprint(local).map_err(|_| DurableStoreError::Corrupt)?;
                    if local_fingerprint == summary.fingerprint {
                        EventReplicaState::Matching
                    } else {
                        EventReplicaState::Damaged
                    }
                }
            };
            result.push(EventReconciliation {
                event_id: summary.event_id.clone(),
                state: state_kind,
            });
        }
        Ok(result)
    }

    fn reconcile_event(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError> {
        let event = canonical_event(event).map_err(map_event_error)?;
        if &event.scope != scope {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let _session = load_anti_entropy_session(&state, scope, session_id)?;
        let key = event_key(&event);
        if let Some(local) = state.events.get(&key) {
            return if event_fingerprint(local).map_err(|_| DurableStoreError::Corrupt)?
                == event_fingerprint(&event).map_err(map_event_error)?
            {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.events.insert(key.clone(), event);
        state.event_order.push(key);
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
        let event = canonical_event(event).map_err(map_event_error)?;
        if &event.scope != scope
            || event.correlation.causation_id.as_ref() != Some(command_id.as_opaque())
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let command_ref = command_ref_key(scope, command_id);
        let event_key = event_key(&event);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if !state.accepted_by_id.contains_key(&command_ref) {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(existing_id) = state.terminal_events.get(&command_ref) {
            if existing_id != &event.event_id {
                return Err(DurableStoreError::Conflict);
            }
            return match state.events.get(&event_key) {
                Some(original) if original == &event => Ok(EventAppendStatus::Duplicate),
                _ => Err(DurableStoreError::Conflict),
            };
        }
        if let Some(original) = state.events.get(&event_key) {
            if original != &event {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            state.events.insert(event_key.clone(), event.clone());
            state.event_order.push(event_key);
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
        DeviceRef, EventEnvelope, EventId, IdentityId, NamespaceId, OpaqueId, ProtocolExtension,
        ProtocolVersion, TenantId, TenantScope,
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
            schema_version: ProtocolVersion::new(1, 0),
            extensions: Vec::new(),
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
            extensions: Vec::new(),
        }
    }

    #[test]
    fn memory_store_is_healthy_and_versioned() {
        let store = MemoryLocalStore::default();
        assert_eq!(store.schema_version(), Ok(crate::SCHEMA_VERSION));
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
        assert_eq!(accepted.schema_version, ProtocolVersion::new(1, 0));
        assert!(accepted.extensions.is_empty());

        let duplicate = store.accept_command(&retry).expect("duplicate");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(first.command_id));
        assert_eq!(duplicate.schema_version, ProtocolVersion::new(1, 0));
        assert!(duplicate.extensions.is_empty());
    }

    #[test]
    fn command_extensions_and_schema_are_semantic_but_extension_order_is_not() {
        let store = MemoryLocalStore::default();
        let mut first = command("command-ext-a", "retry-ext", b"payload");
        first.extensions = vec![
            ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: true,
                payload: b"a".to_vec(),
            },
        ];
        assert_eq!(
            store.accept_command(&first).expect("accept").status,
            CommandReceiptStatus::Accepted
        );

        let mut reordered = command("command-ext-b", "retry-ext", b"payload");
        reordered.extensions = first.extensions.clone();
        reordered.extensions.reverse();
        assert_eq!(
            store
                .accept_command(&reordered)
                .expect("deduplicate")
                .status,
            CommandReceiptStatus::Duplicate
        );

        let mut changed_extension = reordered.clone();
        changed_extension.command_id = CommandId::from_opaque(opaque("command-ext-c"));
        changed_extension.extensions[0].payload.push(b'!');
        assert_eq!(
            store.accept_command(&changed_extension),
            Err(DurableStoreError::Conflict)
        );

        let mut changed_schema = reordered;
        changed_schema.command_id = CommandId::from_opaque(opaque("command-ext-d"));
        changed_schema.schema_version = ProtocolVersion::new(1, 1);
        assert_eq!(
            store.accept_command(&changed_schema),
            Err(DurableStoreError::Conflict)
        );
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
    fn terminal_link_creation_is_appended_even_when_event_already_exists() {
        let store = MemoryLocalStore::default();
        let accepted = command("command-preexisting", "retry-preexisting", b"payload");
        let terminal = event("event-preexisting", "command-preexisting", b"done");
        store.accept_command(&accepted).expect("accepted");
        assert_eq!(
            store.append_event(&terminal),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.terminal_event(&accepted.scope, &accepted.command_id),
            Ok(Some(terminal.event_id.clone()))
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
            extensions: Vec::new(),
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
    fn message_extensions_are_semantic_but_extension_order_is_not() {
        let store = MemoryLocalStore::default();
        store
            .persist_conversation(&conversation())
            .expect("persist conversation");
        let mut first = message();
        first.extensions = vec![
            ucr_model::ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ucr_model::ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: false,
                payload: b"a".to_vec(),
            },
        ];
        assert_eq!(
            store.persist_message(&first),
            Ok(DurableRecordStatus::Persisted)
        );

        let mut reordered = first.clone();
        reordered.extensions.reverse();
        assert_eq!(
            store.persist_message(&reordered),
            Ok(DurableRecordStatus::Duplicate)
        );

        let mut changed = reordered;
        changed.extensions[0].payload.push(b'!');
        assert_eq!(
            store.persist_message(&changed),
            Err(DurableStoreError::Conflict)
        );
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

#[cfg(test)]
mod sync_tests {
    use ucr_core::{DurableRecordStatus, DurableStoreError, SyncStore};
    use ucr_model::{
        ConversationId, EndpointId, OpaqueId, SessionId, SyncCheckpoint, SyncLinkKind, SyncMode,
        SyncSelection, SyncSession, SyncState, TenantId, TenantScope,
    };

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn session() -> SyncSession {
        SyncSession {
            session_id: SessionId::from_opaque(oid("sync-memory")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-sync")),
                namespace_id: None,
            },
            source_endpoint_id: EndpointId::from_opaque(oid("endpoint-local")),
            target_endpoint_id: EndpointId::from_opaque(oid("endpoint-remote")),
            link_kind: SyncLinkKind::DeviceDevice,
            selection: SyncSelection {
                mode: SyncMode::Partial,
                conversation_ids: vec![
                    ConversationId::from_opaque(oid("conversation-b")),
                    ConversationId::from_opaque(oid("conversation-a")),
                ],
            },
            state: SyncState::Prepared,
        }
    }

    fn checkpoint(session: &SyncSession, generation: u64, applied_items: u64) -> SyncCheckpoint {
        SyncCheckpoint {
            session_id: session.session_id.clone(),
            scope: session.scope.clone(),
            generation,
            resume_token: format!("resume-{generation}").into_bytes(),
            applied_items,
        }
    }

    #[test]
    fn sync_session_is_canonical_and_idempotent() {
        let store = MemoryLocalStore::default();
        let session = session();
        assert_eq!(
            store.create_sync_session(&session),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.create_sync_session(&session),
            Ok(DurableRecordStatus::Duplicate)
        );
        let loaded = store
            .sync_session(&session.scope, &session.session_id)
            .expect("load session")
            .expect("session exists");
        assert_eq!(
            loaded.selection.conversation_ids[0].as_opaque().as_str(),
            "conversation-a"
        );
    }

    #[test]
    fn sync_checkpoint_and_pause_resume_are_durable_semantics() {
        let store = MemoryLocalStore::default();
        let session = session();
        store.create_sync_session(&session).expect("create session");
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("activate");
        let mut active = store
            .sync_session(&session.scope, &session.session_id)
            .expect("load")
            .expect("exists");
        let first = checkpoint(&active, 1, 3);
        assert_eq!(
            store.record_sync_checkpoint(&first),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.record_sync_checkpoint(&first),
            Ok(DurableRecordStatus::Duplicate)
        );
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Active,
                SyncState::Paused,
            )
            .expect("pause");
        active.state = SyncState::Paused;
        let second = checkpoint(&active, 2, 7);
        assert_eq!(
            store.record_sync_checkpoint(&second),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.latest_sync_checkpoint(&session.scope, &session.session_id),
            Ok(Some(second))
        );
        assert_eq!(
            store.transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Paused,
                SyncState::Active,
            ),
            Ok(DurableRecordStatus::Persisted)
        );
    }

    #[test]
    fn stale_checkpoint_and_terminal_reopen_fail_closed() {
        let store = MemoryLocalStore::default();
        let session = session();
        store.create_sync_session(&session).expect("create session");
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("activate");
        let mut active = store
            .sync_session(&session.scope, &session.session_id)
            .expect("load")
            .expect("exists");
        let first = checkpoint(&active, 1, 5);
        store.record_sync_checkpoint(&first).expect("checkpoint");
        let stale = checkpoint(&active, 3, 6);
        assert_eq!(
            store.record_sync_checkpoint(&stale),
            Err(DurableStoreError::Conflict)
        );
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Active,
                SyncState::Completed,
            )
            .expect("complete");
        active.state = SyncState::Completed;
        assert_eq!(
            store.transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Completed,
                SyncState::Active,
            ),
            Err(DurableStoreError::Conflict)
        );
    }
}

#[cfg(test)]
mod anti_entropy_tests {
    use ucr_core::{
        AntiEntropyStore, DurableStoreError, EventAppendStatus, EventJournalStore, SyncStore,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EndpointId,
        EventEnvelope, EventFingerprint, EventFingerprintAlgorithm, EventId, EventReplicaState,
        EventSummary, IdentityId, OpaqueId, ProtocolExtension, ProtocolVersion, SessionId,
        SyncLinkKind, SyncMode, SyncSelection, SyncSession, SyncState, TenantId, TenantScope,
    };

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-a")),
            namespace_id: None,
        }
    }

    fn session(id: &str, target: &str, mode: SyncMode) -> SyncSession {
        SyncSession {
            session_id: SessionId::from_opaque(oid(id)),
            scope: scope(),
            source_endpoint_id: EndpointId::from_opaque(oid("endpoint-source")),
            target_endpoint_id: EndpointId::from_opaque(oid(target)),
            link_kind: SyncLinkKind::DeviceDevice,
            selection: SyncSelection {
                mode,
                conversation_ids: if mode == SyncMode::Partial {
                    vec![ucr_model::ConversationId::from_opaque(oid(
                        "conversation-a",
                    ))]
                } else {
                    Vec::new()
                },
            },
            state: SyncState::Prepared,
        }
    }

    fn activate(store: &MemoryLocalStore, session: &SyncSession) {
        store.create_sync_session(session).expect("create session");
        store
            .transition_sync(
                &session.scope,
                &session.session_id,
                SyncState::Prepared,
                SyncState::Active,
            )
            .expect("activate session");
    }

    fn event(id: &str, payload: &[u8]) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid(id)),
            scope: scope(),
            event_type: "ucr.test.event".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn snapshot_resume_does_not_lose_events_added_during_pass() {
        let store = MemoryLocalStore::default();
        let sync = session("sync-a", "endpoint-target", SyncMode::Full);
        activate(&store, &sync);
        store
            .append_event(&event("event-a", b"a"))
            .expect("event a");
        store
            .append_event(&event("event-b", b"b"))
            .expect("event b");

        let first = store
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 1)
            .expect("first page");
        assert_eq!(first.summaries.len(), 1);
        assert_eq!(first.summaries[0].event_id.as_opaque().as_str(), "event-a");
        let cursor = first.next_cursor.expect("resume cursor");

        store
            .append_event(&event("event-c", b"c"))
            .expect("event c");
        let resumed = store
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, Some(&cursor), 8)
            .expect("resumed page");
        assert_eq!(resumed.summaries.len(), 1);
        assert_eq!(
            resumed.summaries[0].event_id.as_opaque().as_str(),
            "event-b"
        );
        assert!(resumed.next_cursor.is_none());

        let next_pass = store
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 8)
            .expect("next pass");
        assert_eq!(next_pass.summaries.len(), 3);
        assert_eq!(
            next_pass.summaries[2].event_id.as_opaque().as_str(),
            "event-c"
        );
    }

    #[test]
    fn cursor_is_bound_to_exact_session_and_direction() {
        let store = MemoryLocalStore::default();
        let first = session("sync-a", "endpoint-target-a", SyncMode::Full);
        let second = session("sync-b", "endpoint-target-b", SyncMode::Full);
        activate(&store, &first);
        activate(&store, &second);
        store
            .append_event(&event("event-a", b"a"))
            .expect("event a");
        store
            .append_event(&event("event-b", b"b"))
            .expect("event b");
        let cursor = store
            .anti_entropy_summary_page(&first.scope, &first.session_id, None, 1)
            .expect("first page")
            .next_cursor
            .expect("cursor");
        assert_eq!(
            store.anti_entropy_summary_page(&second.scope, &second.session_id, Some(&cursor), 1),
            Err(DurableStoreError::InvalidRecord)
        );
        let oversized = vec![
            EventSummary {
                event_id: EventId::from_opaque(oid("event-summary")),
                fingerprint: EventFingerprint {
                    algorithm: EventFingerprintAlgorithm::Sha256V1,
                    digest: [0; 32],
                },
            };
            ucr_protocol::MAX_ANTI_ENTROPY_PAGE_ITEMS + 1
        ];
        assert_eq!(
            store.classify_event_summaries(&first.scope, &first.session_id, &oversized),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn reconciliation_distinguishes_missing_matching_and_damaged_without_overwrite() {
        let source = MemoryLocalStore::default();
        let target = MemoryLocalStore::default();
        let sync = session("sync-a", "endpoint-target", SyncMode::Full);
        activate(&source, &sync);
        activate(&target, &sync);
        let matching = event("event-a", b"same");
        let damaged_source = event("event-b", b"source");
        let missing = event("event-c", b"missing");
        for value in [&matching, &damaged_source, &missing] {
            source.append_event(value).expect("source event");
        }
        target.append_event(&matching).expect("matching local");
        target
            .append_event(&event("event-b", b"different-local"))
            .expect("damaged local");

        let page = source
            .anti_entropy_summary_page(&sync.scope, &sync.session_id, None, 8)
            .expect("source summaries");
        let states = target
            .classify_event_summaries(&sync.scope, &sync.session_id, &page.summaries)
            .expect("classification");
        assert_eq!(states[0].state, EventReplicaState::Matching);
        assert_eq!(states[1].state, EventReplicaState::Damaged);
        assert_eq!(states[2].state, EventReplicaState::Missing);
        assert_eq!(
            target.reconcile_event(&sync.scope, &sync.session_id, &matching),
            Ok(EventAppendStatus::Duplicate)
        );
        assert_eq!(
            target.reconcile_event(&sync.scope, &sync.session_id, &damaged_source),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            target.reconcile_event(&sync.scope, &sync.session_id, &missing),
            Ok(EventAppendStatus::Appended)
        );
    }

    #[test]
    fn partial_event_reconciliation_and_extension_order_fail_or_deduplicate_canonically() {
        let partial_store = MemoryLocalStore::default();
        let partial = session("sync-partial", "endpoint-target", SyncMode::Partial);
        activate(&partial_store, &partial);
        assert_eq!(
            partial_store.anti_entropy_summary_page(&partial.scope, &partial.session_id, None, 1),
            Err(DurableStoreError::InvalidRecord)
        );

        let store = MemoryLocalStore::default();
        let mut original = event("event-ext", b"payload");
        original.extensions = vec![
            ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: true,
                payload: b"a".to_vec(),
            },
        ];
        let mut reordered = original.clone();
        reordered.extensions.reverse();
        assert_eq!(
            store.append_event(&original),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.append_event(&reordered),
            Ok(EventAppendStatus::Duplicate)
        );
    }
}

#[cfg(test)]
mod trusted_signing_key_tests {
    use ucr_core::{DurableStoreError, TrustedSigningKeyStore};
    use ucr_crypto::{
        AgreementKeyPair, MessageSignatureVerificationError, SessionRole, SigningKeyMaterial,
        TranscriptBinding, TrustedKeyResolutionError, TrustedMessageSignatureError,
        TrustedSessionError, TrustedSessionHandshakeInput, TrustedSigningKeyResolver,
        begin_session_with_trusted_peer, verify_message_signature_with_trust,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, ConversationId, ConversationKind, ConversationRef,
        CorrelationContext, CryptoSuite, DeliveryPolicy, DeliveryState, DeviceId, DeviceRef,
        IdentityId, KeyId, KeyPurpose, MessageEnvelope, MessageId, MessageSignature, NamespaceId,
        OpaqueId, OriginRef, PrincipalId, PublicKeyDescriptor, TenantId, TenantScope,
        TrustedSigningKeyState,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, message_signing_binding,
    };

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope(tenant: &str, namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid(tenant)),
            namespace_id: namespace.map(|value| NamespaceId::from_opaque(oid(value))),
        }
    }

    fn descriptor(key: &str, device: &str, byte: u8) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(key)),
            device_id: DeviceId::from_opaque(oid(device)),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![byte; 32],
        }
    }

    #[test]
    fn trusted_signing_key_lifecycle_is_atomic_idempotent_and_irreversible() {
        let store = MemoryLocalStore::default();
        let scope = scope("tenant-a", Some("namespace-a"));
        let first = descriptor("key-a", "device-a", 1);
        let second = descriptor("key-b", "device-a", 2);

        assert_eq!(store.provision_trusted_signing_key(&scope, &first), Ok(()));
        assert_eq!(store.provision_trusted_signing_key(&scope, &first), Ok(()));
        assert_eq!(
            store.active_trusted_signing_key(&scope, &first.device_id),
            Ok(Some(first.clone()))
        );

        let mut conflicting = first.clone();
        conflicting.public_key[0] ^= 1;
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &conflicting),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &second),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.rotate_trusted_signing_key(
                &scope,
                &first.device_id,
                &KeyId::from_opaque(oid("wrong-current")),
                &second,
            ),
            Err(DurableStoreError::Conflict)
        );

        assert_eq!(
            store.rotate_trusted_signing_key(&scope, &first.device_id, &first.key_id, &second),
            Ok(())
        );
        assert_eq!(
            store.rotate_trusted_signing_key(&scope, &first.device_id, &first.key_id, &second),
            Ok(())
        );
        assert_eq!(
            store
                .trusted_signing_key(&scope, &first.key_id)
                .expect("old record")
                .expect("old key")
                .state,
            TrustedSigningKeyState::Revoked
        );
        assert_eq!(
            store.resolve_active_signing_key(&scope, &first.device_id, &first.key_id),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            store.resolve_active_signing_key(&scope, &second.device_id, &second.key_id),
            Ok(second.clone())
        );

        assert_eq!(
            store.revoke_trusted_signing_key(&scope, &second.device_id, &second.key_id),
            Ok(())
        );
        assert_eq!(
            store.revoke_trusted_signing_key(&scope, &second.device_id, &second.key_id),
            Ok(())
        );
        assert_eq!(
            store.resolve_active_signing_key(&scope, &second.device_id, &second.key_id),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &first),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn trusted_signing_keys_are_exact_scope_and_device_bound() {
        let store = MemoryLocalStore::default();
        let scope_a = scope("tenant-a", Some("namespace-a"));
        let scope_b = scope("tenant-b", Some("namespace-a"));
        let key_a = descriptor("shared-key-id", "device-a", 3);
        let key_b = descriptor("shared-key-id", "device-a", 4);

        store
            .provision_trusted_signing_key(&scope_a, &key_a)
            .expect("scope a provision");
        assert_eq!(
            store.resolve_active_signing_key(&scope_b, &key_a.device_id, &key_a.key_id),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            store.active_trusted_signing_key(&scope_b, &key_a.device_id),
            Ok(None)
        );
        assert_eq!(
            store.provision_trusted_signing_key(&scope_b, &key_b),
            Ok(())
        );
        assert_eq!(
            store.resolve_active_signing_key(&scope_b, &key_b.device_id, &key_b.key_id),
            Ok(key_b)
        );
        assert_eq!(
            store.resolve_active_signing_key(
                &scope_a,
                &DeviceId::from_opaque(oid("device-other")),
                &key_a.key_id,
            ),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
    }

    fn signed_message(
        signer: &SigningKeyMaterial,
        descriptor: &PublicKeyDescriptor,
        scope: &TenantScope,
    ) -> MessageEnvelope {
        let mut message = MessageEnvelope {
            message_id: MessageId::from_opaque(oid("message-trusted")),
            scope: scope.clone(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation-trusted")),
                kind: ConversationKind::Direct,
            },
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-trusted")),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: descriptor.device_id.clone(),
                identity_id: IdentityId::from_opaque(oid("identity-trusted")),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"trusted message".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(PrincipalId::from_opaque(oid("principal-trusted"))),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-trusted"),
                causation_id: None,
                idempotency_key: None,
            },
            extensions: Vec::new(),
            external_mappings: Vec::new(),
            signature: None,
        };
        let binding = message_signing_binding(&message).expect("message binding");
        let signature = signer.sign_message_binding(&binding);
        message.signature = Some(MessageSignature {
            key_id: descriptor.key_id.clone(),
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            signature: signature.0.to_vec(),
        });
        message
    }

    #[test]
    fn active_trust_controls_message_verification_and_revocation_denies_same_signature() {
        let store = MemoryLocalStore::default();
        let scope = scope("tenant-runtime", None);
        let signer = SigningKeyMaterial::generate().expect("signing key");
        let descriptor = PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid("runtime-key")),
            device_id: DeviceId::from_opaque(oid("runtime-device")),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: signer.verifying_key().0.to_vec(),
        };
        store
            .provision_trusted_signing_key(&scope, &descriptor)
            .expect("provision trust");
        let message = signed_message(&signer, &descriptor, &scope);
        assert_eq!(
            verify_message_signature_with_trust(&message, &store),
            Ok(())
        );

        let mut tampered = message.clone();
        tampered.content.push(b'!');
        assert_eq!(
            verify_message_signature_with_trust(&tampered, &store),
            Err(TrustedMessageSignatureError::Verification(
                MessageSignatureVerificationError::InvalidSignature
            ))
        );

        store
            .revoke_trusted_signing_key(&scope, &descriptor.device_id, &descriptor.key_id)
            .expect("revoke trust");
        assert_eq!(
            verify_message_signature_with_trust(&message, &store),
            Err(TrustedMessageSignatureError::Trust(
                TrustedKeyResolutionError::NotTrusted
            ))
        );
    }

    #[test]
    fn active_trust_controls_handshake_and_peer_claim_cannot_self_provision() {
        let store = MemoryLocalStore::default();
        let scope = scope("tenant-handshake", None);
        let signer = SigningKeyMaterial::generate().expect("signing key");
        let descriptor = PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid("handshake-key")),
            device_id: DeviceId::from_opaque(oid("handshake-device")),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: signer.verifying_key().0.to_vec(),
        };
        store
            .provision_trusted_signing_key(&scope, &descriptor)
            .expect("provision trust");

        let local = AgreementKeyPair::generate().expect("local agreement");
        let peer = AgreementKeyPair::generate().expect("peer agreement");
        let binding = TranscriptBinding::from_bytes([11_u8; 32]);
        let input = TrustedSessionHandshakeInput {
            scope: scope.clone(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: peer.public_key(),
            initiator_public: local.public_key(),
            responder_public: peer.public_key(),
            peer_signing_descriptor: descriptor.clone(),
            peer_signature: signer.sign_transcript(&binding),
            binding,
        };
        assert!(begin_session_with_trusted_peer(local, &input, &store, &store).is_ok());

        let local_claim = AgreementKeyPair::generate().expect("local claim agreement");
        let peer_claim = AgreementKeyPair::generate().expect("peer claim agreement");
        let claim_binding = TranscriptBinding::from_bytes([12_u8; 32]);
        let mut false_claim = descriptor.clone();
        false_claim.public_key[0] ^= 1;
        let false_input = TrustedSessionHandshakeInput {
            scope: scope.clone(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: peer_claim.public_key(),
            initiator_public: local_claim.public_key(),
            responder_public: peer_claim.public_key(),
            peer_signing_descriptor: false_claim,
            peer_signature: signer.sign_transcript(&claim_binding),
            binding: claim_binding,
        };
        assert_eq!(
            begin_session_with_trusted_peer(local_claim, &false_input, &store, &store)
                .expect_err("peer claim must not self-provision"),
            TrustedSessionError::Trust(TrustedKeyResolutionError::NotTrusted)
        );

        store
            .revoke_trusted_signing_key(&scope, &descriptor.device_id, &descriptor.key_id)
            .expect("revoke trust");
        let local_revoked = AgreementKeyPair::generate().expect("local revoked agreement");
        let peer_revoked = AgreementKeyPair::generate().expect("peer revoked agreement");
        let revoked_binding = TranscriptBinding::from_bytes([13_u8; 32]);
        let revoked_input = TrustedSessionHandshakeInput {
            scope: scope.clone(),
            suite: CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: peer_revoked.public_key(),
            initiator_public: local_revoked.public_key(),
            responder_public: peer_revoked.public_key(),
            peer_signing_descriptor: descriptor,
            peer_signature: signer.sign_transcript(&revoked_binding),
            binding: revoked_binding,
        };
        assert_eq!(
            begin_session_with_trusted_peer(local_revoked, &revoked_input, &store, &store)
                .expect_err("revoked key must not authenticate"),
            TrustedSessionError::Trust(TrustedKeyResolutionError::NotTrusted)
        );
    }

    #[test]
    fn malformed_or_non_signing_descriptors_never_enter_trust_state() {
        let store = MemoryLocalStore::default();
        let scope = scope("tenant-a", None);
        let mut agreement = descriptor("key-agreement", "device-a", 5);
        agreement.purpose = KeyPurpose::KeyAgreement;
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &agreement),
            Err(DurableStoreError::InvalidRecord)
        );

        let mut malformed = descriptor("key-short", "device-a", 6);
        malformed.public_key.pop();
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &malformed),
            Err(DurableStoreError::InvalidRecord)
        );
    }
}

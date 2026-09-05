#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Mutex,
};

use ucr_core::{
    AntiEntropyStore, AuthorizationEvaluator, CommandAcceptanceStore, CommandOutcomeStore,
    CommunicationIntentStore, ConversationStore, DeliveryStore, DeviceLifecycleStore,
    DeviceReverificationProof, DurableRecordStatus, DurableStoreError, EventAppendStatus,
    EventJournalStore, ExternalIdentityBindingStore, MessageStore, PermissionGrantStore,
    RecoveryAdmissionProof, RecoveryDeviceStagingStore, RecoveryPlanStore,
    ReverifiedDeviceActivationStore, ServiceAuditStore, ServiceCredentialStore,
    ServiceQuotaConsumeError, ServiceQuotaStore, StorageHealth, StorageProvider, SyncStore,
    TrustedSigningKeyStore,
};
use ucr_crypto::{
    ReplayError, ReplayProtector, TranscriptBinding, TrustedKeyResolutionError,
    TrustedSigningKeyResolver, VerifyingKeyBytes,
};
use ucr_model::{
    AntiEntropyCursor, AntiEntropyPage, AuthorizationRequest, CommandEnvelope, CommandId,
    CommunicationIntent, ConversationId, ConversationRecord, DeliveryAttempt, DeliveryEvidence,
    DeliveryId, DeliveryState, DeviceDescriptor, DeviceId, DeviceLifecycleState, EventEnvelope,
    EventId, EventReconciliation, EventReplicaState, EventSummary, ExternalIdentityBinding,
    IdentityId, IntegrationId, IntentId, KeyId, MessageEnvelope, MessageId, PermissionGrant,
    PublicKeyDescriptor, RecoveryPlan, RecoveryPlanId, ScopedPrincipal, ServiceAuditOperationRef,
    ServiceAuditRecord, ServiceCredentialId, ServiceCredentialRecord, ServiceCredentialState,
    ServiceQuotaPolicy, SessionId, SyncCheckpoint, SyncSession, SyncState, TenantScope,
    TrustedSigningKeyRecord, TrustedSigningKeyState,
};
use ucr_protocol::{
    AntiEntropyError, CanonicalError, CanonicalErrorCode, CommandError, CommandReceipt, EventError,
    IdempotencyDecision, MAX_SERVICE_AUDIT_READ_ITEMS, accepted_command_receipt,
    anti_entropy_session_binding, canonical_command, canonical_communication_intent,
    canonical_event, canonical_message, canonical_recovery_plan, canonical_sync_session,
    compare_command_idempotency, device_allows_protected_access, duplicate_command_receipt,
    event_fingerprint, service_audit_hash, validate_anti_entropy_cursor,
    validate_anti_entropy_page_size, validate_anti_entropy_session,
    validate_anti_entropy_summary_count, validate_conversation, validate_conversation_parent_kind,
    validate_delivery_attempt, validate_delivery_evidence, validate_delivery_evidence_binding,
    validate_delivery_evidence_order, validate_delivery_transition,
    validate_external_identity_binding, validate_external_identity_binding_key,
    validate_permission_grant, validate_service_audit_record, validate_service_quota_policy,
    validate_sync_checkpoint, validate_sync_transition, validate_trusted_signing_key_descriptor,
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
type IntentKey = (ScopeKey, String);
type ExternalIdentityBindingKey = (ScopeKey, String, String, Vec<u8>);
type DeliveryKey = (ScopeKey, String);
type SyncKey = (ScopeKey, String);
type TrustedSigningKeyRef = (ScopeKey, String);
type TrustedSigningDeviceRef = (ScopeKey, String);
type DeviceKey = (ScopeKey, String);
type ServiceCredentialRef = (ScopeKey, String);
type ServicePrincipalKey = (ScopeKey, String);

#[derive(Debug, Clone, Copy)]
struct MemoryQuotaUsage {
    window_start_unix_ms: i64,
    used_requests: u64,
    last_observed_unix_ms: i64,
}

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
    intents: HashMap<IntentKey, CommunicationIntent>,
    external_identity_bindings: HashMap<ExternalIdentityBindingKey, ExternalIdentityBinding>,
    deliveries: HashMap<DeliveryKey, DeliveryAttempt>,
    delivery_evidence: HashMap<DeliveryKey, Vec<DeliveryEvidence>>,
    sync_sessions: HashMap<SyncKey, SyncSession>,
    sync_checkpoints: HashMap<SyncKey, Vec<SyncCheckpoint>>,
    trusted_signing_keys: HashMap<TrustedSigningKeyRef, TrustedSigningKeyRecord>,
    active_trusted_signing_keys: HashMap<TrustedSigningDeviceRef, String>,
    devices: HashMap<DeviceKey, DeviceDescriptor>,
    permission_grants: Vec<PermissionGrant>,
    service_credentials: HashMap<ServiceCredentialRef, ServiceCredentialRecord>,
    service_quota_policies: HashMap<ServicePrincipalKey, ServiceQuotaPolicy>,
    service_quota_usage: HashMap<ServicePrincipalKey, MemoryQuotaUsage>,
    service_audit_records: Vec<(ServiceAuditRecord, [u8; 32])>,
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

impl PermissionGrantStore for MemoryLocalStore {
    fn grant_permission(&self, grant: &PermissionGrant) -> Result<(), DurableStoreError> {
        validate_permission_grant(grant).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if !state.permission_grants.contains(grant) {
            state.permission_grants.push(grant.clone());
        }
        Ok(())
    }

    fn revoke_permission(&self, grant: &PermissionGrant) -> Result<(), DurableStoreError> {
        validate_permission_grant(grant).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        state.permission_grants.retain(|existing| existing != grant);
        Ok(())
    }

    fn permission_grants_for(
        &self,
        subject: &ScopedPrincipal,
    ) -> Result<Vec<PermissionGrant>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .permission_grants
            .iter()
            .filter(|grant| grant.grantee == *subject)
            .cloned()
            .collect())
    }
}

impl AuthorizationEvaluator for MemoryLocalStore {
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        let grants = self
            .permission_grants_for(&request.subject)
            .map_err(map_authorization_store_error)?;
        ucr_protocol::authorize(request, &grants).map_err(CanonicalError::from)
    }
}

impl ServiceCredentialStore for MemoryLocalStore {
    fn provision_service_credential(
        &self,
        record: &ServiceCredentialRecord,
    ) -> Result<(), DurableStoreError> {
        validate_service_credential_record(record)?;
        let key = service_credential_ref(&record.subject.scope, &record.credential_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.service_credentials.get(&key) {
            return if existing == record {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.service_credentials.insert(key, record.clone());
        Ok(())
    }

    fn revoke_service_credential(
        &self,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<(), DurableStoreError> {
        let key = service_credential_ref(scope, credential_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(record) = state.service_credentials.get_mut(&key) {
            record.state = ServiceCredentialState::Revoked;
        }
        Ok(())
    }

    fn service_credential(
        &self,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<Option<ServiceCredentialRecord>, DurableStoreError> {
        let key = service_credential_ref(scope, credential_id);
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state.service_credentials.get(&key).cloned())
    }
}

impl ServiceQuotaStore for MemoryLocalStore {
    fn set_service_quota_policy(
        &self,
        policy: &ServiceQuotaPolicy,
    ) -> Result<(), DurableStoreError> {
        validate_service_quota_policy(policy).map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = service_principal_key(&policy.subject);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if state.service_quota_policies.get(&key) == Some(policy) {
            return Ok(());
        }
        state
            .service_quota_policies
            .insert(key.clone(), policy.clone());
        state.service_quota_usage.remove(&key);
        Ok(())
    }

    fn service_quota_policy(
        &self,
        subject: &ScopedPrincipal,
    ) -> Result<Option<ServiceQuotaPolicy>, DurableStoreError> {
        validate_service_subject(subject)?;
        let key = service_principal_key(subject);
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state.service_quota_policies.get(&key).cloned())
    }

    fn consume_service_request(
        &self,
        subject: &ScopedPrincipal,
        now_unix_ms: i64,
    ) -> Result<(), ServiceQuotaConsumeError> {
        validate_service_subject(subject).map_err(ServiceQuotaConsumeError::Store)?;
        if now_unix_ms < 0 {
            return Err(ServiceQuotaConsumeError::ClockRollback);
        }
        let key = service_principal_key(subject);
        let mut state = self
            .state
            .lock()
            .map_err(|_| ServiceQuotaConsumeError::Store(DurableStoreError::Internal))?;
        let policy = state
            .service_quota_policies
            .get(&key)
            .cloned()
            .ok_or(ServiceQuotaConsumeError::NotConfigured)?;
        let window_ms = i64::try_from(policy.window_ms)
            .map_err(|_| ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
        let window_start_unix_ms = now_unix_ms - now_unix_ms.rem_euclid(window_ms);
        let usage = state
            .service_quota_usage
            .entry(key)
            .or_insert(MemoryQuotaUsage {
                window_start_unix_ms,
                used_requests: 0,
                last_observed_unix_ms: now_unix_ms,
            });
        if now_unix_ms < usage.last_observed_unix_ms
            || window_start_unix_ms < usage.window_start_unix_ms
        {
            return Err(ServiceQuotaConsumeError::ClockRollback);
        }
        if window_start_unix_ms > usage.window_start_unix_ms {
            usage.window_start_unix_ms = window_start_unix_ms;
            usage.used_requests = 0;
        }
        usage.last_observed_unix_ms = now_unix_ms;
        if usage.used_requests >= policy.max_requests {
            let window_end = window_start_unix_ms
                .checked_add(window_ms)
                .ok_or(ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
            let retry_after_ms = u64::try_from(window_end.saturating_sub(now_unix_ms))
                .map_err(|_| ServiceQuotaConsumeError::Store(DurableStoreError::Corrupt))?;
            return Err(ServiceQuotaConsumeError::RateLimited { retry_after_ms });
        }
        usage.used_requests += 1;
        Ok(())
    }
}

impl ServiceAuditStore for MemoryLocalStore {
    fn append_service_audit(&self, record: &ServiceAuditRecord) -> Result<(), DurableStoreError> {
        validate_service_audit_record(record).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some((existing, _)) = state
            .service_audit_records
            .iter()
            .find(|(existing, _)| existing.audit_id == record.audit_id)
        {
            return if existing == record {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let previous_hash = state
            .service_audit_records
            .last()
            .map_or([0_u8; 32], |(_, hash)| *hash);
        let record_hash = service_audit_hash(previous_hash, record);
        state
            .service_audit_records
            .push((record.clone(), record_hash));
        Ok(())
    }

    fn service_audit_records(
        &self,
        scope: &TenantScope,
        max_items: usize,
    ) -> Result<Vec<ServiceAuditRecord>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_SERVICE_AUDIT_READ_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let mut records = state
            .service_audit_records
            .iter()
            .rev()
            .filter(|(record, _)| record.presented_scope == *scope)
            .take(max_items)
            .map(|(record, _)| record.clone())
            .collect::<Vec<_>>();
        records.reverse();
        Ok(records)
    }

    fn service_audit_records_for_operation(
        &self,
        scope: &TenantScope,
        operation: &ServiceAuditOperationRef,
        max_items: usize,
    ) -> Result<Vec<ServiceAuditRecord>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_SERVICE_AUDIT_READ_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        ucr_protocol::validate_service_audit_operation_ref(operation)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let mut records = state
            .service_audit_records
            .iter()
            .rev()
            .filter(|(record, _)| {
                record.presented_scope == *scope && record.operation.as_ref() == Some(operation)
            })
            .take(max_items)
            .map(|(record, _)| record.clone())
            .collect::<Vec<_>>();
        records.reverse();
        Ok(records)
    }
}

impl DeviceLifecycleStore for MemoryLocalStore {
    fn register_device(
        &self,
        scope: &TenantScope,
        descriptor: &DeviceDescriptor,
    ) -> Result<(), DurableStoreError> {
        let key = device_key(scope, &descriptor.device_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.devices.get(&key) {
            return if existing == descriptor {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if !device_allows_protected_access(descriptor) {
            let trusted_ref = trusted_device_ref(scope, &descriptor.device_id);
            if let Some(active_key_id) =
                state.active_trusted_signing_keys.get(&trusted_ref).cloned()
            {
                let active_key_ref = (trusted_ref.0.clone(), active_key_id);
                let record = state
                    .trusted_signing_keys
                    .get_mut(&active_key_ref)
                    .ok_or(DurableStoreError::Corrupt)?;
                if record.state != TrustedSigningKeyState::Active
                    || record.descriptor.device_id != descriptor.device_id
                {
                    return Err(DurableStoreError::Corrupt);
                }
                record.state = TrustedSigningKeyState::Revoked;
                state.active_trusted_signing_keys.remove(&trusted_ref);
            }
        }
        state.devices.insert(key, descriptor.clone());
        Ok(())
    }

    fn revoke_device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_identity_id: &IdentityId,
    ) -> Result<(), DurableStoreError> {
        let key = device_key(scope, device_id);
        let trusted_ref = trusted_device_ref(scope, device_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let device = state.devices.get(&key).ok_or(DurableStoreError::Conflict)?;
        if device.identity_id != *expected_identity_id {
            return Err(DurableStoreError::Conflict);
        }
        if device.state == DeviceLifecycleState::Revoked {
            return if state.active_trusted_signing_keys.contains_key(&trusted_ref) {
                Err(DurableStoreError::Corrupt)
            } else {
                Ok(())
            };
        }
        if let Some(active_key_id) = state.active_trusted_signing_keys.get(&trusted_ref).cloned() {
            let active_key_ref = (trusted_ref.0.clone(), active_key_id);
            let key_record = state
                .trusted_signing_keys
                .get(&active_key_ref)
                .ok_or(DurableStoreError::Corrupt)?;
            if key_record.state != TrustedSigningKeyState::Active
                || key_record.descriptor.device_id != *device_id
            {
                return Err(DurableStoreError::Corrupt);
            }
            state
                .trusted_signing_keys
                .get_mut(&active_key_ref)
                .ok_or(DurableStoreError::Corrupt)?
                .state = TrustedSigningKeyState::Revoked;
            state.active_trusted_signing_keys.remove(&trusted_ref);
        }
        state
            .devices
            .get_mut(&key)
            .ok_or(DurableStoreError::Corrupt)?
            .state = DeviceLifecycleState::Revoked;
        Ok(())
    }

    fn device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<DeviceDescriptor>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state.devices.get(&device_key(scope, device_id)).cloned())
    }
}

impl ReverifiedDeviceActivationStore for MemoryLocalStore {
    fn activate_reverified_device(
        &self,
        proof: &DeviceReverificationProof,
    ) -> Result<(), DurableStoreError> {
        let key = device_key(proof.scope(), proof.device_id());
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let device = state
            .devices
            .get_mut(&key)
            .ok_or(DurableStoreError::Conflict)?;
        if device.identity_id != *proof.identity_id()
            || device.state != DeviceLifecycleState::ReverificationRequired
        {
            return Err(DurableStoreError::Conflict);
        }
        device.state = DeviceLifecycleState::Active;
        Ok(())
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
        if !memory_device_allows_protected_access(&state, scope, &descriptor.device_id, None) {
            return Err(DurableStoreError::PermissionDenied);
        }

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
        if !memory_device_allows_protected_access(&state, scope, device_id, None) {
            return Err(DurableStoreError::PermissionDenied);
        }

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
        if !memory_device_allows_protected_access(&state, scope, device_id, None) {
            return Ok(None);
        }
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
        identity_id: Option<&IdentityId>,
        key_id: &KeyId,
    ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TrustedKeyResolutionError::Internal)?;
        if !memory_device_allows_protected_access(&state, scope, device_id, identity_id) {
            return Err(TrustedKeyResolutionError::NotTrusted);
        }
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

impl RecoveryDeviceStagingStore for MemoryLocalStore {
    fn stage_recovered_device(
        &self,
        proof: &RecoveryAdmissionProof,
    ) -> Result<(), DurableStoreError> {
        if proof.recovered_device_state() != DeviceLifecycleState::ReverificationRequired {
            return Err(DurableStoreError::InvalidRecord);
        }
        let identity_key = recovery_identity_key(proof.scope(), proof.identity_id());
        let expected_plan = proof.plan_id().as_opaque().as_str();
        let device_key = device_key(proof.scope(), proof.target_device_id());
        let descriptor = proof.recovered_device();
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if state
            .active_recovery_plans
            .get(&identity_key)
            .map(String::as_str)
            != Some(expected_plan)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        if let Some(existing) = state.devices.get(&device_key) {
            return if existing == &descriptor {
                Ok(())
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let trusted_ref = trusted_device_ref(proof.scope(), proof.target_device_id());
        if let Some(active_key_id) = state.active_trusted_signing_keys.get(&trusted_ref).cloned() {
            let active_key_ref = (trusted_ref.0.clone(), active_key_id);
            let record = state
                .trusted_signing_keys
                .get_mut(&active_key_ref)
                .ok_or(DurableStoreError::Corrupt)?;
            if record.state != TrustedSigningKeyState::Active
                || record.descriptor.device_id != *proof.target_device_id()
            {
                return Err(DurableStoreError::Corrupt);
            }
            record.state = TrustedSigningKeyState::Revoked;
            state.active_trusted_signing_keys.remove(&trusted_ref);
        }
        state.devices.insert(device_key, descriptor);
        Ok(())
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

fn intent_key(scope: &TenantScope, intent_id: &IntentId) -> IntentKey {
    (scope_key(scope), intent_id.as_opaque().as_str().to_owned())
}

fn external_identity_binding_key(
    scope: &TenantScope,
    integration_id: &IntegrationId,
    external_namespace: &str,
    external_entity_id: &[u8],
) -> ExternalIdentityBindingKey {
    (
        scope_key(scope),
        integration_id.as_opaque().as_str().to_owned(),
        external_namespace.to_owned(),
        external_entity_id.to_vec(),
    )
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

impl ExternalIdentityBindingStore for MemoryLocalStore {
    fn persist_external_identity_binding(
        &self,
        binding: &ExternalIdentityBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_external_identity_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = external_identity_binding_key(
            &binding.scope,
            &binding.integration_id,
            &binding.external_namespace,
            &binding.external_entity_id,
        );
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.external_identity_bindings.get(&key) {
            return if existing == binding {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state
            .external_identity_bindings
            .insert(key, binding.clone());
        Ok(DurableRecordStatus::Persisted)
    }

    fn external_identity_binding(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        external_namespace: &str,
        external_entity_id: &[u8],
    ) -> Result<Option<ExternalIdentityBinding>, DurableStoreError> {
        validate_external_identity_binding_key(external_namespace, external_entity_id)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .external_identity_bindings
            .get(&external_identity_binding_key(
                scope,
                integration_id,
                external_namespace,
                external_entity_id,
            ))
            .cloned())
    }
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

impl CommunicationIntentStore for MemoryLocalStore {
    fn persist_communication_intent(
        &self,
        intent: &CommunicationIntent,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical =
            canonical_communication_intent(intent).map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = intent_key(&canonical.scope, &canonical.intent_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.intents.get(&key) {
            return if existing == &canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.intents.insert(key, canonical);
        Ok(DurableRecordStatus::Persisted)
    }

    fn communication_intent(
        &self,
        scope: &TenantScope,
        intent_id: &IntentId,
    ) -> Result<Option<CommunicationIntent>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state.intents.get(&intent_key(scope, intent_id)).cloned())
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

const fn map_authorization_store_error(error: DurableStoreError) -> CanonicalError {
    let code = match error {
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::InvalidRecord
        | DurableStoreError::Conflict
        | DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

fn device_key(scope: &TenantScope, device_id: &DeviceId) -> DeviceKey {
    (scope_key(scope), device_id.as_opaque().as_str().to_owned())
}

fn memory_device_allows_protected_access(
    state: &MemoryState,
    scope: &TenantScope,
    device_id: &DeviceId,
    identity_id: Option<&IdentityId>,
) -> bool {
    state
        .devices
        .get(&device_key(scope, device_id))
        .is_some_and(|device| {
            device_allows_protected_access(device)
                && identity_id.is_none_or(|expected| device.identity_id == *expected)
        })
}

fn trusted_key_ref(scope: &TenantScope, key_id: &KeyId) -> TrustedSigningKeyRef {
    (scope_key(scope), key_id.as_opaque().as_str().to_owned())
}

fn trusted_device_ref(scope: &TenantScope, device_id: &DeviceId) -> TrustedSigningDeviceRef {
    (scope_key(scope), device_id.as_opaque().as_str().to_owned())
}

fn validate_service_subject(subject: &ScopedPrincipal) -> Result<(), DurableStoreError> {
    if subject.principal.kind != ucr_model::PrincipalKind::ServiceAccount {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
}

fn service_principal_key(subject: &ScopedPrincipal) -> ServicePrincipalKey {
    (
        scope_key(&subject.scope),
        subject
            .principal
            .principal_id
            .as_opaque()
            .as_str()
            .to_owned(),
    )
}

fn service_credential_ref(
    scope: &TenantScope,
    credential_id: &ServiceCredentialId,
) -> ServiceCredentialRef {
    (
        scope_key(scope),
        credential_id.as_opaque().as_str().to_owned(),
    )
}

fn validate_service_credential_record(
    record: &ServiceCredentialRecord,
) -> Result<(), DurableStoreError> {
    if record.subject.principal.kind != ucr_model::PrincipalKind::ServiceAccount
        || record.state != ServiceCredentialState::Active
    {
        return Err(DurableStoreError::InvalidRecord);
    }
    Ok(())
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ucr_core::{
        DeviceLifecycleStore, DeviceReverificationGate, DeviceReverificationVerificationError,
        DeviceReverificationVerifier, DurableStoreError, RecoveryAuthorityVerificationError,
        RecoveryAuthorityVerifier, RecoveryDeviceStagingStore, RecoveryPlanStore,
        RecoveryRequestGate, ReverifiedDeviceActivationStore, TrustedSigningKeyStore,
        authorize_and_activate_reverified_device, authorize_and_stage_recovered_device,
    };
    use ucr_model::{
        DeviceId, DeviceLifecycleState, HistoricalMessageAccess, IdentityId, KeyId, KeyPurpose,
        OpaqueId, PublicKeyDescriptor, RecoveryAuthority, RecoveryPlan, RecoveryPlanId,
        RecoveryRequest, RecoveryTrustModel, TenantId, TenantScope,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, CanonicalErrorCode, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID,
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

    #[derive(Debug)]
    struct TestVerifier {
        outcome: Result<(), RecoveryAuthorityVerificationError>,
        calls: AtomicUsize,
    }

    impl TestVerifier {
        fn allow() -> Self {
            Self {
                outcome: Ok(()),
                calls: AtomicUsize::new(0),
            }
        }

        fn deny() -> Self {
            Self {
                outcome: Err(RecoveryAuthorityVerificationError::Denied),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl RecoveryAuthorityVerifier for TestVerifier {
        fn verify_authority(
            &self,
            _plan: &RecoveryPlan,
            _request: &RecoveryRequest,
        ) -> Result<(), RecoveryAuthorityVerificationError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.outcome
        }
    }

    #[derive(Debug)]
    struct ReverificationVerifier {
        outcome: Result<(), DeviceReverificationVerificationError>,
        calls: AtomicUsize,
    }

    impl ReverificationVerifier {
        fn allow() -> Self {
            Self {
                outcome: Ok(()),
                calls: AtomicUsize::new(0),
            }
        }

        fn deny() -> Self {
            Self {
                outcome: Err(DeviceReverificationVerificationError::Denied),
                calls: AtomicUsize::new(0),
            }
        }

        fn unavailable() -> Self {
            Self {
                outcome: Err(DeviceReverificationVerificationError::Unavailable),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl DeviceReverificationVerifier for ReverificationVerifier {
        fn verify_reverification(
            &self,
            _device: &ucr_model::DeviceDescriptor,
        ) -> Result<(), DeviceReverificationVerificationError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.outcome
        }
    }

    fn request(plan: &RecoveryPlan, target: &str, authority: RecoveryAuthority) -> RecoveryRequest {
        RecoveryRequest {
            plan_id: plan.plan_id.clone(),
            scope: plan.scope.clone(),
            identity_id: plan.identity_id.clone(),
            authority,
            target_device_id: DeviceId::from_opaque(id(target)),
        }
    }

    fn signing_key(device_id: &DeviceId) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(id("recovered-key")),
            device_id: device_id.clone(),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![9_u8; 32],
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
    #[test]
    fn recovery_staging_requires_verified_authority_and_never_auto_trusts_device() {
        let store = MemoryLocalStore::default();
        let active = plan("plan-stage", "identity-stage");
        store.install_recovery_plan(&active).expect("install plan");
        let exact = request(&active, "device-recovered", RecoveryAuthority::RecoveryKey);

        let denied = TestVerifier::deny();
        let error = authorize_and_stage_recovered_device(&denied, &store, &exact)
            .expect_err("denied proof must fail");
        assert_eq!(error.code, CanonicalErrorCode::PermissionDenied);
        assert_eq!(denied.calls(), 1);
        assert_eq!(
            store.device(&active.scope, &exact.target_device_id),
            Ok(None)
        );

        let allowed = TestVerifier::allow();
        let wrong_method = request(
            &active,
            "device-wrong-method",
            RecoveryAuthority::RecoveryCode,
        );
        let before = allowed.calls();
        let error = authorize_and_stage_recovered_device(&allowed, &store, &wrong_method)
            .expect_err("method outside plan must fail before provider");
        assert_eq!(error.code, CanonicalErrorCode::PermissionDenied);
        assert_eq!(allowed.calls(), before);

        let staged = authorize_and_stage_recovered_device(&allowed, &store, &exact)
            .expect("verified recovery stages device");
        assert_eq!(staged.state, DeviceLifecycleState::ReverificationRequired);
        assert_eq!(
            store.device(&active.scope, &exact.target_device_id),
            Ok(Some(staged.clone()))
        );
        assert_eq!(
            store.provision_trusted_signing_key(
                &active.scope,
                &signing_key(&exact.target_device_id)
            ),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            authorize_and_stage_recovered_device(&allowed, &store, &exact),
            Ok(staged)
        );
    }

    #[test]
    fn recovery_proof_is_invalidated_by_plan_revoke_and_cannot_overwrite_existing_device() {
        let store = MemoryLocalStore::default();
        let active = plan("plan-proof", "identity-proof");
        store.install_recovery_plan(&active).expect("install plan");
        let verifier = TestVerifier::allow();
        let exact = request(&active, "device-proof", RecoveryAuthority::RecoveryKey);
        let proof = RecoveryRequestGate::new(&verifier, &store)
            .authorize_recovery(&exact)
            .expect("issue proof");
        store
            .revoke_recovery_plan(&active.scope, &active.identity_id, &active.plan_id)
            .expect("revoke plan");
        assert_eq!(
            store.stage_recovered_device(&proof),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            store.device(&active.scope, &exact.target_device_id),
            Ok(None)
        );

        let second = plan("plan-second", "identity-proof");
        store
            .install_recovery_plan(&second)
            .expect("install replacement lifecycle");
        let target = request(&second, "device-existing", RecoveryAuthority::RecoveryKey);
        store
            .register_device(
                &second.scope,
                &ucr_model::DeviceDescriptor {
                    device_id: target.target_device_id.clone(),
                    identity_id: second.identity_id.clone(),
                    state: DeviceLifecycleState::Active,
                },
            )
            .expect("register existing active device");
        let error = authorize_and_stage_recovered_device(&verifier, &store, &target)
            .expect_err("recovery cannot downgrade existing active device");
        assert_eq!(error.code, CanonicalErrorCode::Conflict);
    }

    #[test]
    fn recovered_device_requires_independent_reverification_before_active() {
        let store = MemoryLocalStore::default();
        let active = plan("plan-reverify", "identity-reverify");
        store.install_recovery_plan(&active).expect("install plan");
        let request = request(&active, "device-reverify", RecoveryAuthority::RecoveryKey);
        let recovery = TestVerifier::allow();
        let staged = authorize_and_stage_recovered_device(&recovery, &store, &request)
            .expect("stage recovered device");
        assert_eq!(staged.state, DeviceLifecycleState::ReverificationRequired);

        let denied = ReverificationVerifier::deny();
        let error = authorize_and_activate_reverified_device(
            &denied,
            &store,
            &active.scope,
            &request.target_device_id,
            &active.identity_id,
        )
        .expect_err("reverification denial must fail closed");
        assert_eq!(error.code, CanonicalErrorCode::PermissionDenied);
        assert_eq!(denied.calls(), 1);

        let wrong_identity = IdentityId::from_opaque(id("wrong-reverify-identity"));
        let before = denied.calls();
        let error = authorize_and_activate_reverified_device(
            &denied,
            &store,
            &active.scope,
            &request.target_device_id,
            &wrong_identity,
        )
        .expect_err("identity mismatch must fail before verifier");
        assert_eq!(error.code, CanonicalErrorCode::PermissionDenied);
        assert_eq!(denied.calls(), before);

        let unavailable = ReverificationVerifier::unavailable();
        let error = authorize_and_activate_reverified_device(
            &unavailable,
            &store,
            &active.scope,
            &request.target_device_id,
            &active.identity_id,
        )
        .expect_err("unavailable verifier must fail closed");
        assert_eq!(error.code, CanonicalErrorCode::TemporarilyUnavailable);
        assert_eq!(unavailable.calls(), 1);

        assert_eq!(
            store
                .device(&active.scope, &request.target_device_id)
                .expect("device")
                .expect("exists")
                .state,
            DeviceLifecycleState::ReverificationRequired
        );

        let allowed = ReverificationVerifier::allow();
        let activated = authorize_and_activate_reverified_device(
            &allowed,
            &store,
            &active.scope,
            &request.target_device_id,
            &active.identity_id,
        )
        .expect("independently reverified device activates");
        assert_eq!(activated.state, DeviceLifecycleState::Active);
        assert_eq!(allowed.calls(), 1);
        store
            .provision_trusted_signing_key(&active.scope, &signing_key(&request.target_device_id))
            .expect("active reverified device may receive trusted key");
    }

    #[test]
    fn stale_reverification_proof_cannot_resurrect_revoked_device() {
        let store = MemoryLocalStore::default();
        let descriptor = ucr_model::DeviceDescriptor {
            device_id: DeviceId::from_opaque(id("device-stale-proof")),
            identity_id: IdentityId::from_opaque(id("identity-stale-proof")),
            state: DeviceLifecycleState::ReverificationRequired,
        };
        store
            .register_device(&plan("unused", "identity-stale-proof").scope, &descriptor)
            .expect("stage fixture");
        let scope = plan("unused-2", "identity-stale-proof").scope;
        let verifier = ReverificationVerifier::allow();
        let proof = DeviceReverificationGate::new(&verifier, &store)
            .authorize_reverification(&scope, &descriptor.device_id, &descriptor.identity_id)
            .expect("mint re-verification proof");
        store
            .revoke_device(&scope, &descriptor.device_id, &descriptor.identity_id)
            .expect("revoke wins race");
        assert_eq!(
            store.activate_reverified_device(&proof),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store
                .device(&scope, &descriptor.device_id)
                .expect("device")
                .expect("exists")
                .state,
            DeviceLifecycleState::Revoked
        );
    }
}

#[cfg(test)]
mod external_identity_binding_tests {
    use ucr_core::{DurableRecordStatus, DurableStoreError, ExternalIdentityBindingStore};
    use ucr_model::{
        ExternalIdentityBinding, IdentityId, IntegrationId, NamespaceId, OpaqueId, TenantId,
        TenantScope,
    };

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-binding-memory")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-binding-memory"))),
        }
    }

    fn binding(entity: &[u8], identity: &str) -> ExternalIdentityBinding {
        ExternalIdentityBinding {
            scope: scope(),
            integration_id: IntegrationId::from_opaque(oid("integration-binding-memory")),
            external_namespace: "vendor.example.customer".to_owned(),
            external_entity_id: entity.to_vec(),
            identity_id: IdentityId::from_opaque(oid(identity)),
        }
    }

    #[test]
    fn exact_external_identity_binding_is_deduplicated_and_never_relinked() {
        let store = MemoryLocalStore::default();
        let original = binding(b"Customer-42", "identity-original");
        assert_eq!(
            store.persist_external_identity_binding(&original),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_external_identity_binding(&original),
            Ok(DurableRecordStatus::Duplicate)
        );
        let changed = binding(b"Customer-42", "identity-other");
        assert_eq!(
            store.persist_external_identity_binding(&changed),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.external_identity_binding(
                &original.scope,
                &original.integration_id,
                &original.external_namespace,
                &original.external_entity_id,
            ),
            Ok(Some(original))
        );
    }

    #[test]
    fn external_identity_key_preserves_namespace_and_opaque_bytes_exactly() {
        let store = MemoryLocalStore::default();
        let upper = binding(b"User", "identity-upper");
        let lower = binding(b"user", "identity-lower");
        store
            .persist_external_identity_binding(&upper)
            .expect("persist upper");
        store
            .persist_external_identity_binding(&lower)
            .expect("persist lower");
        assert_ne!(
            store
                .external_identity_binding(
                    &scope(),
                    &upper.integration_id,
                    "vendor.example.customer",
                    b"User",
                )
                .expect("upper lookup"),
            store
                .external_identity_binding(
                    &scope(),
                    &upper.integration_id,
                    "vendor.example.customer",
                    b"user",
                )
                .expect("lower lookup")
        );
        assert_eq!(
            store.external_identity_binding(
                &scope(),
                &upper.integration_id,
                "vendor.example.contact",
                b"User",
            ),
            Ok(None)
        );
    }

    #[test]
    fn invalid_external_identity_lookup_key_fails_closed() {
        let store = MemoryLocalStore::default();
        let integration = IntegrationId::from_opaque(oid("integration-binding-memory"));
        assert_eq!(
            store.external_identity_binding(&scope(), &integration, "not namespaced", b"entity"),
            Err(DurableStoreError::InvalidRecord)
        );
        assert_eq!(
            store.external_identity_binding(&scope(), &integration, "vendor.example.customer", b""),
            Err(DurableStoreError::InvalidRecord)
        );
    }
}

#[cfg(test)]
mod intent_tests {
    use ucr_core::{CommunicationIntentStore, DurableRecordStatus, DurableStoreError};
    use ucr_model::{
        CommunicationIntent, CorrelationContext, IdentityId, IntentConstraints, IntentId,
        NamespaceId, OpaqueId, ProtocolExtension, TenantId, TenantScope,
    };
    use ucr_protocol::canonical_communication_intent;

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    pub(super) fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-intent-memory")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-intent-memory"))),
        }
    }

    pub(super) fn intent() -> CommunicationIntent {
        CommunicationIntent {
            intent_id: IntentId::from_opaque(oid("intent-memory")),
            scope: scope(),
            target_identity_id: IdentityId::from_opaque(oid("identity-target")),
            payload: b"memory intent".to_vec(),
            constraints: IntentConstraints {
                allowed_transport_capabilities: vec![
                    "ucr.transport.wifi".to_owned(),
                    "ucr.transport.direct".to_owned(),
                ],
                forbidden_transport_capabilities: vec!["ucr.transport.bridge".to_owned()],
                privacy_profile: Some("vendor.example.private".to_owned()),
                region_constraint: Some("region-eu".to_owned()),
                max_cost_microunits: Some(u64::MAX),
                priority_class: Some(u32::MAX),
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-intent-memory"),
                causation_id: Some(oid("causation-intent-memory")),
                idempotency_key: Some("intent-memory-key".to_owned()),
            },
            extensions: vec![
                ProtocolExtension {
                    name: "vendor.example.z".to_owned(),
                    critical: false,
                    payload: b"z".to_vec(),
                },
                ProtocolExtension {
                    name: "ucr.intent.a".to_owned(),
                    critical: false,
                    payload: b"a".to_vec(),
                },
            ],
        }
    }

    #[test]
    fn communication_intent_persists_canonically_and_conflicts_on_changed_semantics() {
        let store = MemoryLocalStore::default();
        let first = intent();
        let expected = canonical_communication_intent(&first).expect("canonical intent");
        assert_eq!(
            store.persist_communication_intent(&first),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.communication_intent(&first.scope, &first.intent_id),
            Ok(Some(expected))
        );

        let mut reordered = first.clone();
        reordered
            .constraints
            .allowed_transport_capabilities
            .reverse();
        reordered.extensions.reverse();
        assert_eq!(
            store.persist_communication_intent(&reordered),
            Ok(DurableRecordStatus::Duplicate)
        );

        let mut changed = first;
        changed.payload.push(b'!');
        assert_eq!(
            store.persist_communication_intent(&changed),
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
mod device_lifecycle_tests {
    use ucr_core::{DeviceLifecycleStore, DurableStoreError, TrustedSigningKeyStore};
    use ucr_crypto::{TrustedKeyResolutionError, TrustedSigningKeyResolver};
    use ucr_model::{
        DeviceDescriptor, DeviceId, DeviceLifecycleState, IdentityId, KeyId, KeyPurpose,
        NamespaceId, OpaqueId, PublicKeyDescriptor, TenantId, TenantScope, TrustedSigningKeyState,
    };
    use ucr_protocol::{ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID};

    use super::MemoryLocalStore;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-device")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-device"))),
        }
    }

    fn device(state: DeviceLifecycleState) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid("device-a")),
            identity_id: IdentityId::from_opaque(oid("identity-a")),
            state,
        }
    }

    fn key(id: &str, byte: u8) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(id)),
            device_id: DeviceId::from_opaque(oid("device-a")),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: vec![byte; 32],
        }
    }

    #[test]
    fn device_revocation_atomically_revokes_key_and_cannot_be_reactivated() {
        let store = MemoryLocalStore::default();
        let scope = scope();
        let active = device(DeviceLifecycleState::Active);
        let first = key("key-a", 9);
        store.register_device(&scope, &active).expect("register");
        store
            .provision_trusted_signing_key(&scope, &first)
            .expect("provision key");
        assert_eq!(
            store.resolve_active_signing_key(
                &scope,
                &active.device_id,
                Some(&active.identity_id),
                &first.key_id,
            ),
            Ok(first.clone())
        );

        let wrong_identity = IdentityId::from_opaque(oid("identity-other"));
        assert_eq!(
            store.revoke_device(&scope, &active.device_id, &wrong_identity),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.revoke_device(&scope, &active.device_id, &active.identity_id),
            Ok(())
        );
        assert_eq!(
            store.revoke_device(&scope, &active.device_id, &active.identity_id),
            Ok(())
        );
        let revoked = store
            .device(&scope, &active.device_id)
            .expect("device lookup")
            .expect("device exists");
        assert_eq!(revoked.state, DeviceLifecycleState::Revoked);
        assert_eq!(
            store.active_trusted_signing_key(&scope, &active.device_id),
            Ok(None)
        );
        assert_eq!(
            store
                .trusted_signing_key(&scope, &first.key_id)
                .expect("key lookup")
                .expect("key exists")
                .state,
            TrustedSigningKeyState::Revoked
        );
        assert_eq!(
            store.resolve_active_signing_key(
                &scope,
                &active.device_id,
                Some(&active.identity_id),
                &first.key_id,
            ),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &key("key-b", 10)),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            store.register_device(&scope, &active),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn protected_key_access_requires_active_device_and_exact_identity_binding() {
        let store = MemoryLocalStore::default();
        let scope = scope();
        let recovering = device(DeviceLifecycleState::ReverificationRequired);
        let first = key("key-recovering", 11);
        store
            .register_device(&scope, &recovering)
            .expect("register recovering device");
        assert_eq!(
            store.provision_trusted_signing_key(&scope, &first),
            Err(DurableStoreError::PermissionDenied)
        );

        let other_scope = TenantScope {
            tenant_id: scope.tenant_id.clone(),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-active"))),
        };
        let active = device(DeviceLifecycleState::Active);
        store
            .register_device(&other_scope, &active)
            .expect("register active device");
        let active_key = key("key-active", 12);
        store
            .provision_trusted_signing_key(&other_scope, &active_key)
            .expect("active device gets key");
        let wrong_identity = IdentityId::from_opaque(oid("identity-wrong"));
        assert_eq!(
            store.resolve_active_signing_key(
                &other_scope,
                &active.device_id,
                Some(&wrong_identity),
                &active_key.key_id,
            ),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            store.resolve_active_signing_key(
                &other_scope,
                &active.device_id,
                Some(&active.identity_id),
                &active_key.key_id,
            ),
            Ok(active_key)
        );
    }
}

#[cfg(test)]
mod trusted_signing_key_tests {
    use ucr_core::{DeviceLifecycleStore, DurableStoreError, TrustedSigningKeyStore};
    use ucr_crypto::{
        AgreementKeyPair, MessageSignatureVerificationError, SessionRole, SigningKeyMaterial,
        TranscriptBinding, TrustedKeyResolutionError, TrustedMessageSignatureError,
        TrustedSessionError, TrustedSessionHandshakeInput, TrustedSigningKeyResolver,
        begin_session_with_trusted_peer, verify_message_signature_with_trust,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, ConversationId, ConversationKind, ConversationRef,
        CorrelationContext, CryptoSuite, DeliveryPolicy, DeliveryState, DeviceDescriptor, DeviceId,
        DeviceLifecycleState, DeviceRef, IdentityId, KeyId, KeyPurpose, MessageEnvelope, MessageId,
        MessageSignature, NamespaceId, OpaqueId, OriginRef, PrincipalId, PublicKeyDescriptor,
        TenantId, TenantScope, TrustedSigningKeyState,
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

    fn register_active_device(
        store: &MemoryLocalStore,
        scope: &TenantScope,
        device_id: &DeviceId,
        identity: &str,
    ) {
        store
            .register_device(
                scope,
                &DeviceDescriptor {
                    device_id: device_id.clone(),
                    identity_id: IdentityId::from_opaque(oid(identity)),
                    state: DeviceLifecycleState::Active,
                },
            )
            .expect("register active device");
    }

    #[test]
    fn trusted_signing_key_lifecycle_is_atomic_idempotent_and_irreversible() {
        let store = MemoryLocalStore::default();
        let scope = scope("tenant-a", Some("namespace-a"));
        let first = descriptor("key-a", "device-a", 1);
        let second = descriptor("key-b", "device-a", 2);
        register_active_device(&store, &scope, &first.device_id, "identity-a");

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
            store.resolve_active_signing_key(&scope, &first.device_id, None, &first.key_id),
            Err(TrustedKeyResolutionError::NotTrusted)
        );
        assert_eq!(
            store.resolve_active_signing_key(&scope, &second.device_id, None, &second.key_id),
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
            store.resolve_active_signing_key(&scope, &second.device_id, None, &second.key_id),
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
        register_active_device(&store, &scope_a, &key_a.device_id, "identity-a");
        register_active_device(&store, &scope_b, &key_b.device_id, "identity-b");

        store
            .provision_trusted_signing_key(&scope_a, &key_a)
            .expect("scope a provision");
        assert_eq!(
            store.resolve_active_signing_key(&scope_b, &key_a.device_id, None, &key_a.key_id),
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
            store.resolve_active_signing_key(&scope_b, &key_b.device_id, None, &key_b.key_id),
            Ok(key_b)
        );
        assert_eq!(
            store.resolve_active_signing_key(
                &scope_a,
                &DeviceId::from_opaque(oid("device-other")),
                None,
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
        register_active_device(&store, &scope, &descriptor.device_id, "identity-trusted");
        store
            .provision_trusted_signing_key(&scope, &descriptor)
            .expect("provision trust");
        let message = signed_message(&signer, &descriptor, &scope);
        assert_eq!(
            verify_message_signature_with_trust(&message, &store),
            Ok(())
        );

        let mut rebound_identity = message.clone();
        rebound_identity.author_device.identity_id = IdentityId::from_opaque(oid("identity-other"));
        let rebound_binding = message_signing_binding(&rebound_identity).expect("rebound binding");
        rebound_identity
            .signature
            .as_mut()
            .expect("signature")
            .signature = signer.sign_message_binding(&rebound_binding).0.to_vec();
        assert_eq!(
            verify_message_signature_with_trust(&rebound_identity, &store),
            Err(TrustedMessageSignatureError::Trust(
                TrustedKeyResolutionError::NotTrusted
            ))
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
        register_active_device(&store, &scope, &descriptor.device_id, "identity-handshake");
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

#[cfg(test)]
mod permission_enforcement_tests {
    use ucr_core::{
        AuthorizedDurableRuntime, AuthorizedMutationError, AuthorizedTrustedSigningKeyMutations,
        CommunicationIntentStore, ConversationStore, DeviceLifecycleStore, DurableRecordStatus,
        DurableStoreError, ExternalIdentityBindingStore, MessageStore, PermissionGrantStore,
        TrustedSigningKeyStore,
    };
    use ucr_model::{
        DeviceDescriptor, DeviceId, DeviceLifecycleState, ExternalIdentityBinding, IdentityId,
        IntegrationId, KeyId, KeyPurpose, NamespaceId, OpaqueId, PermissionGrant, PermissionScope,
        PrincipalId, PrincipalKind, PrincipalRef, PublicKeyDescriptor, ScopedPrincipal, TenantId,
        TenantScope,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, COMMUNICATION_INTENT_READ_PERMISSION,
        COMMUNICATION_INTENT_WRITE_PERMISSION, CONVERSATION_READ_PERMISSION,
        CONVERSATION_WRITE_PERMISSION, CanonicalError, CanonicalErrorCode, DEVICE_READ_PERMISSION,
        DEVICE_REGISTER_PERMISSION, DEVICE_REVOKE_PERMISSION,
        EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION, EXTERNAL_IDENTITY_BINDING_READ_PERMISSION,
        KEY_FORMAT_VERSION, MESSAGE_READ_PERMISSION, MESSAGE_WRITE_PERMISSION,
        PERMISSION_GRANT_CREATE_PERMISSION, PERMISSION_GRANT_READ_PERMISSION,
        PERMISSION_GRANT_REVOKE_PERMISSION, SIGNATURE_ALGORITHM_ID,
        TRUSTED_SIGNING_KEY_PROVISION_PERMISSION, TRUSTED_SIGNING_KEY_REVOKE_PERMISSION,
        TRUSTED_SIGNING_KEY_ROTATE_PERMISSION, canonical_communication_intent,
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

    fn subject(tenant: &str, namespace: Option<&str>) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(tenant, namespace),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("principal-a")),
                kind: PrincipalKind::Person,
            },
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

    fn register_active_device(
        store: &MemoryLocalStore,
        resource: &TenantScope,
        device_id: &DeviceId,
        identity: &str,
    ) {
        store
            .register_device(
                resource,
                &DeviceDescriptor {
                    device_id: device_id.clone(),
                    identity_id: IdentityId::from_opaque(oid(identity)),
                    state: DeviceLifecycleState::Active,
                },
            )
            .expect("register active device fixture");
    }

    fn exact_grant(
        grantee: &ScopedPrincipal,
        permission: &str,
        resource: &TenantScope,
    ) -> PermissionGrant {
        PermissionGrant {
            grantee: grantee.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(resource.clone()),
        }
    }

    fn denied() -> AuthorizedMutationError {
        AuthorizedMutationError::Authorization(CanonicalError::new(
            CanonicalErrorCode::PermissionDenied,
        ))
    }

    #[test]
    fn persisted_permission_is_deny_by_default_revocable_and_storage_is_not_reached_on_denial() {
        let store = MemoryLocalStore::default();
        let subject = subject("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-a", Some("namespace-a"));
        let first = descriptor("key-a", "device-a", 1);
        let second = descriptor("key-b", "device-b", 2);
        register_active_device(&store, &resource, &first.device_id, "identity-a");
        register_active_device(&store, &resource, &second.device_id, "identity-b");
        let authorized = AuthorizedTrustedSigningKeyMutations::new(&store, &store);

        assert_eq!(
            authorized.provision(&subject, &resource, &first),
            Err(denied())
        );
        assert_eq!(
            store.active_trusted_signing_key(&resource, &first.device_id),
            Ok(None)
        );

        let grant = exact_grant(
            &subject,
            TRUSTED_SIGNING_KEY_PROVISION_PERMISSION,
            &resource,
        );
        store.grant_permission(&grant).expect("grant provision");
        store.grant_permission(&grant).expect("idempotent grant");
        assert_eq!(authorized.provision(&subject, &resource, &first), Ok(()));

        store.revoke_permission(&grant).expect("revoke provision");
        store
            .revoke_permission(&grant)
            .expect("idempotent grant revocation");
        assert_eq!(
            authorized.provision(&subject, &resource, &second),
            Err(denied())
        );
        assert_eq!(
            store.active_trusted_signing_key(&resource, &second.device_id),
            Ok(None)
        );
    }

    #[test]
    fn provision_rotate_and_revoke_permissions_are_not_interchangeable() {
        let store = MemoryLocalStore::default();
        let subject = subject("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-a", Some("namespace-a"));
        let first = descriptor("key-a", "device-a", 3);
        let second = descriptor("key-b", "device-a", 4);
        register_active_device(&store, &resource, &first.device_id, "identity-a");
        let authorized = AuthorizedTrustedSigningKeyMutations::new(&store, &store);

        store
            .grant_permission(&exact_grant(
                &subject,
                TRUSTED_SIGNING_KEY_PROVISION_PERMISSION,
                &resource,
            ))
            .expect("grant provision");
        authorized
            .provision(&subject, &resource, &first)
            .expect("authorized provision");
        assert_eq!(
            authorized.rotate(
                &subject,
                &resource,
                &first.device_id,
                &first.key_id,
                &second,
            ),
            Err(denied())
        );

        store
            .grant_permission(&exact_grant(
                &subject,
                TRUSTED_SIGNING_KEY_ROTATE_PERMISSION,
                &resource,
            ))
            .expect("grant rotate");
        authorized
            .rotate(
                &subject,
                &resource,
                &first.device_id,
                &first.key_id,
                &second,
            )
            .expect("authorized rotate");
        assert_eq!(
            authorized.revoke(&subject, &resource, &second.device_id, &second.key_id),
            Err(denied())
        );

        store
            .grant_permission(&exact_grant(
                &subject,
                TRUSTED_SIGNING_KEY_REVOKE_PERMISSION,
                &resource,
            ))
            .expect("grant revoke");
        authorized
            .revoke(&subject, &resource, &second.device_id, &second.key_id)
            .expect("authorized revoke");
    }

    #[test]
    fn explicit_tenant_wide_grant_authorizes_only_same_tenant_namespaces() {
        let store = MemoryLocalStore::default();
        let subject = subject("tenant-a", None);
        let grant = PermissionGrant {
            grantee: subject.clone(),
            permission: TRUSTED_SIGNING_KEY_PROVISION_PERMISSION.to_owned(),
            scope: PermissionScope::TenantWide(TenantId::from_opaque(oid("tenant-a"))),
        };
        store.grant_permission(&grant).expect("grant tenant wide");
        let authorized = AuthorizedTrustedSigningKeyMutations::new(&store, &store);
        let namespace_a = scope("tenant-a", Some("namespace-a"));
        let namespace_b = scope("tenant-a", Some("namespace-b"));
        let other_tenant = scope("tenant-b", Some("namespace-a"));
        let key_a = descriptor("key-a", "device-a", 5);
        let key_b = descriptor("key-b", "device-b", 6);
        let key_c = descriptor("key-c", "device-c", 7);
        register_active_device(&store, &namespace_a, &key_a.device_id, "identity-a");
        register_active_device(&store, &namespace_b, &key_b.device_id, "identity-b");
        register_active_device(&store, &other_tenant, &key_c.device_id, "identity-c");

        assert_eq!(authorized.provision(&subject, &namespace_a, &key_a), Ok(()));
        assert_eq!(authorized.provision(&subject, &namespace_b, &key_b), Ok(()));
        assert_eq!(
            authorized.provision(&subject, &other_tenant, &key_c),
            Err(denied())
        );
    }

    #[test]
    fn device_lifecycle_administration_uses_independent_permissions_and_cannot_reactivate() {
        let store = MemoryLocalStore::default();
        let admin = subject("tenant-device-admin", Some("namespace-a"));
        let resource = scope("tenant-device-admin", Some("namespace-a"));
        let device = DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid("device-admin")),
            identity_id: IdentityId::from_opaque(oid("identity-admin")),
            state: DeviceLifecycleState::Active,
        };
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.register_device(&admin, &resource, &device),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(&admin, DEVICE_REGISTER_PERMISSION, &resource))
            .expect("bootstrap device register authority");
        runtime
            .register_device(&admin, &resource, &device)
            .expect("authorized device registration");

        assert_eq!(
            runtime.device(&admin, &resource, &device.device_id),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(&admin, DEVICE_READ_PERMISSION, &resource))
            .expect("bootstrap device read authority");
        assert_eq!(
            runtime.device(&admin, &resource, &device.device_id),
            Ok(Some(device.clone()))
        );

        assert_eq!(
            runtime.revoke_device(&admin, &resource, &device.device_id, &device.identity_id),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(&admin, DEVICE_REVOKE_PERMISSION, &resource))
            .expect("bootstrap device revoke authority");
        runtime
            .revoke_device(&admin, &resource, &device.device_id, &device.identity_id)
            .expect("authorized device revoke");
        let mut revoked = device.clone();
        revoked.state = DeviceLifecycleState::Revoked;
        assert_eq!(
            runtime.device(&admin, &resource, &device.device_id),
            Ok(Some(revoked))
        );
        assert_eq!(
            runtime.register_device(&admin, &resource, &device),
            Err(AuthorizedMutationError::Store(DurableStoreError::Conflict))
        );
    }

    #[test]
    fn runtime_permission_administration_cannot_self_bootstrap_and_is_scope_bound() {
        let store = MemoryLocalStore::default();
        let admin = subject("tenant-a", Some("namespace-a"));
        let resource = scope("tenant-a", Some("namespace-a"));
        let mut target = subject("tenant-a", Some("namespace-a"));
        target.principal.principal_id = PrincipalId::from_opaque(oid("service-target"));
        let target_grant = exact_grant(&target, MESSAGE_WRITE_PERMISSION, &resource);
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.grant_permission(&admin, &target_grant),
            Err(denied())
        );
        assert!(
            store
                .permission_grants_for(&target)
                .expect("target grants")
                .is_empty()
        );

        let create_admin = exact_grant(&admin, PERMISSION_GRANT_CREATE_PERMISSION, &resource);
        assert_eq!(
            runtime.grant_permission(&admin, &create_admin),
            Err(denied())
        );
        store
            .grant_permission(&create_admin)
            .expect("out-of-band bootstrap create authority");
        runtime
            .grant_permission(&admin, &target_grant)
            .expect("authorized grant creation");

        assert_eq!(
            runtime.permission_grants_for(&admin, &target),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &admin,
                PERMISSION_GRANT_READ_PERMISSION,
                &resource,
            ))
            .expect("bootstrap grant read authority");
        assert_eq!(
            runtime.permission_grants_for(&admin, &target),
            Ok(vec![target_grant.clone()])
        );

        assert_eq!(
            runtime.revoke_permission(&admin, &target_grant),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &admin,
                PERMISSION_GRANT_REVOKE_PERMISSION,
                &resource,
            ))
            .expect("bootstrap revoke authority");
        runtime
            .revoke_permission(&admin, &target_grant)
            .expect("authorized grant revocation");
        assert!(
            runtime
                .permission_grants_for(&admin, &target)
                .expect("grants after revoke")
                .is_empty()
        );

        let other_resource = scope("tenant-b", Some("namespace-a"));
        let other_target = subject("tenant-b", Some("namespace-a"));
        let cross_tenant_grant =
            exact_grant(&other_target, MESSAGE_WRITE_PERMISSION, &other_resource);
        assert_eq!(
            runtime.grant_permission(&admin, &cross_tenant_grant),
            Err(denied())
        );
        assert!(
            store
                .permission_grants_for(&other_target)
                .expect("other tenant grants")
                .is_empty()
        );
    }

    #[test]
    fn unified_runtime_enforces_external_identity_binding_permissions_without_relink_bypass() {
        let store = MemoryLocalStore::default();
        let subject = subject("tenant-binding-runtime", Some("namespace-binding-runtime"));
        let resource = scope("tenant-binding-runtime", Some("namespace-binding-runtime"));
        let binding = ExternalIdentityBinding {
            scope: resource.clone(),
            integration_id: IntegrationId::from_opaque(oid("integration-binding-runtime")),
            external_namespace: "vendor.example.customer".to_owned(),
            external_entity_id: b"customer-42".to_vec(),
            identity_id: IdentityId::from_opaque(oid("identity-binding-runtime")),
        };
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.link_external_identity(&subject, &binding),
            Err(denied())
        );
        assert_eq!(
            store.external_identity_binding(
                &resource,
                &binding.integration_id,
                &binding.external_namespace,
                &binding.external_entity_id,
            ),
            Ok(None)
        );
        store
            .grant_permission(&exact_grant(
                &subject,
                EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
                &resource,
            ))
            .expect("bootstrap binding link");
        assert_eq!(
            runtime.link_external_identity(&subject, &binding),
            Ok(DurableRecordStatus::Persisted)
        );

        assert_eq!(
            runtime.external_identity_binding(
                &subject,
                &resource,
                &binding.integration_id,
                &binding.external_namespace,
                &binding.external_entity_id,
            ),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &subject,
                EXTERNAL_IDENTITY_BINDING_READ_PERMISSION,
                &resource,
            ))
            .expect("bootstrap binding read");
        assert_eq!(
            runtime.external_identity_binding(
                &subject,
                &resource,
                &binding.integration_id,
                &binding.external_namespace,
                &binding.external_entity_id,
            ),
            Ok(Some(binding.clone()))
        );
        let mut changed = binding;
        changed.identity_id = IdentityId::from_opaque(oid("identity-binding-other"));
        assert_eq!(
            runtime.link_external_identity(&subject, &changed),
            Err(AuthorizedMutationError::Store(DurableStoreError::Conflict))
        );
    }

    #[test]
    fn unified_runtime_enforces_independent_communication_intent_permissions() {
        let store = MemoryLocalStore::default();
        let subject = subject("tenant-intent-memory", Some("namespace-intent-memory"));
        let resource = super::intent_tests::scope();
        let intent = super::intent_tests::intent();
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.persist_communication_intent(&subject, &intent),
            Err(denied())
        );
        assert_eq!(
            store.communication_intent(&resource, &intent.intent_id),
            Ok(None)
        );
        store
            .grant_permission(&exact_grant(
                &subject,
                COMMUNICATION_INTENT_WRITE_PERMISSION,
                &resource,
            ))
            .expect("bootstrap intent write");
        runtime
            .persist_communication_intent(&subject, &intent)
            .expect("authorized intent persist");

        assert_eq!(
            runtime.communication_intent(&subject, &resource, &intent.intent_id),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &subject,
                COMMUNICATION_INTENT_READ_PERMISSION,
                &resource,
            ))
            .expect("bootstrap intent read");
        assert_eq!(
            runtime.communication_intent(&subject, &resource, &intent.intent_id),
            Ok(Some(
                canonical_communication_intent(&intent).expect("canonical intent")
            ))
        );
    }

    #[test]
    fn unified_runtime_enforces_independent_conversation_and_message_permissions() {
        let store = MemoryLocalStore::default();
        let subject = subject("tenant-message", None);
        let resource = super::message_tests::scope();
        let conversation = super::message_tests::conversation();
        let message = super::message_tests::message();
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.persist_conversation(&subject, &conversation),
            Err(denied())
        );
        assert_eq!(
            store
                .conversation(&resource, &conversation.conversation.conversation_id)
                .expect("raw conversation lookup"),
            None
        );

        store
            .grant_permission(&exact_grant(
                &subject,
                CONVERSATION_WRITE_PERMISSION,
                &resource,
            ))
            .expect("bootstrap conversation write");
        runtime
            .persist_conversation(&subject, &conversation)
            .expect("authorized conversation persist");
        assert_eq!(
            runtime.conversation(
                &subject,
                &resource,
                &conversation.conversation.conversation_id
            ),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &subject,
                CONVERSATION_READ_PERMISSION,
                &resource,
            ))
            .expect("bootstrap conversation read");
        assert_eq!(
            runtime
                .conversation(
                    &subject,
                    &resource,
                    &conversation.conversation.conversation_id
                )
                .expect("authorized conversation read"),
            Some(conversation)
        );

        assert_eq!(runtime.persist_message(&subject, &message), Err(denied()));
        assert_eq!(
            store
                .message(&resource, &message.message_id)
                .expect("raw message lookup"),
            None
        );
        store
            .grant_permission(&exact_grant(&subject, MESSAGE_WRITE_PERMISSION, &resource))
            .expect("bootstrap message write");
        runtime
            .persist_message(&subject, &message)
            .expect("authorized message persist");
        assert_eq!(
            runtime.message(&subject, &resource, &message.message_id),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(&subject, MESSAGE_READ_PERMISSION, &resource))
            .expect("bootstrap message read");
        let mut persisted_message = message;
        persisted_message.delivery_state = ucr_model::DeliveryState::Persisted;
        assert_eq!(
            runtime
                .message(&subject, &resource, &persisted_message.message_id)
                .expect("authorized message read"),
            Some(persisted_message)
        );
    }
}

#[cfg(test)]
mod service_principal_authentication_tests {
    use ucr_core::{
        AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError,
        PermissionGrantStore, ServiceAuthenticationError, ServiceCredentialSecret,
        ServiceCredentialStore, authenticate_service_principal, issue_service_credential,
    };
    use ucr_model::{
        AuthorizationRequest, ConversationId, NamespaceId, OpaqueId, PermissionGrant,
        PermissionScope, PrincipalId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantId,
        TenantScope,
    };
    use ucr_protocol::{
        CONVERSATION_READ_PERMISSION, CanonicalError, CanonicalErrorCode,
        SERVICE_CREDENTIAL_PROVISION_PERMISSION, SERVICE_CREDENTIAL_REVOKE_PERMISSION,
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

    fn service_subject(id: &str, tenant: &str, namespace: Option<&str>) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(tenant, namespace),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn exact_grant(
        grantee: &ScopedPrincipal,
        permission: &str,
        resource: &TenantScope,
    ) -> PermissionGrant {
        PermissionGrant {
            grantee: grantee.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(resource.clone()),
        }
    }

    fn denied() -> AuthorizedMutationError {
        AuthorizedMutationError::Authorization(CanonicalError::new(
            CanonicalErrorCode::PermissionDenied,
        ))
    }

    #[test]
    fn credential_authentication_is_non_disclosing_revocable_and_raw_runtime_cannot_bypass_gate() {
        let store = MemoryLocalStore::default();
        let mut admin = service_subject("admin-a", "tenant-a", Some("namespace-a"));
        admin.principal.kind = PrincipalKind::Person;
        let service = service_subject("service-a", "tenant-a", Some("namespace-a"));
        let resource = service.scope.clone();
        let (record, secret) = issue_service_credential(&service).expect("issue credential");
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.provision_service_credential(&admin, &record),
            Err(denied())
        );
        assert_eq!(
            store.service_credential(&resource, &record.credential_id),
            Ok(None)
        );

        store
            .grant_permission(&exact_grant(
                &admin,
                SERVICE_CREDENTIAL_PROVISION_PERMISSION,
                &resource,
            ))
            .expect("bootstrap credential provision authority");
        runtime
            .provision_service_credential(&admin, &record)
            .expect("authorized credential provision");

        let wrong_secret = ServiceCredentialSecret::from_bytes([0xA5; 32]);
        assert_eq!(
            authenticate_service_principal(&store, &resource, &record.credential_id, &wrong_secret),
            Err(ServiceAuthenticationError::AuthenticationFailed)
        );
        let wrong_scope = scope("tenant-a", Some("namespace-b"));
        assert_eq!(
            authenticate_service_principal(&store, &wrong_scope, &record.credential_id, &secret),
            Err(ServiceAuthenticationError::AuthenticationFailed)
        );
        let authenticated =
            authenticate_service_principal(&store, &resource, &record.credential_id, &secret)
                .expect("valid credential authenticates");
        assert_eq!(authenticated, service);

        let conversation_id = ConversationId::from_opaque(oid("missing-conversation"));
        assert_eq!(
            runtime.conversation(&authenticated, &resource, &conversation_id),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &authenticated,
                CONVERSATION_READ_PERMISSION,
                &resource,
            ))
            .expect("grant minimum read authority");
        assert_eq!(
            runtime.conversation(&authenticated, &resource, &conversation_id),
            Err(denied())
        );

        assert_eq!(
            runtime.revoke_service_credential(&admin, &resource, &record.credential_id),
            Err(denied())
        );
        store
            .grant_permission(&exact_grant(
                &admin,
                SERVICE_CREDENTIAL_REVOKE_PERMISSION,
                &resource,
            ))
            .expect("bootstrap credential revoke authority");
        runtime
            .revoke_service_credential(&admin, &resource, &record.credential_id)
            .expect("authorized revoke");
        assert_eq!(
            authenticate_service_principal(&store, &resource, &record.credential_id, &secret),
            Err(ServiceAuthenticationError::AuthenticationFailed)
        );

        assert_eq!(
            store.authorize(&AuthorizationRequest {
                subject: authenticated,
                permission: CONVERSATION_READ_PERMISSION.to_owned(),
                resource_scope: resource,
            }),
            Ok(())
        );
    }
}

#[cfg(test)]
mod service_principal_quota_audit_tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use ucr_core::{
        AuthorizedDurableRuntime, AuthorizedMutationError, PermissionGrantStore, ServiceAuditStore,
        ServiceCredentialSecret, ServiceCredentialStore, ServicePrincipalRequestGate,
        ServiceQuotaClock, ServiceQuotaClockError, ServiceQuotaStore, issue_service_credential,
    };
    use ucr_model::{
        ConversationId, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalKind, PrincipalRef, ScopedPrincipal, ServiceAuditOutcome, ServiceQuotaPolicy,
        TenantId, TenantScope,
    };
    use ucr_protocol::{
        CONVERSATION_READ_PERMISSION, CanonicalError, CanonicalErrorCode,
        SERVICE_AUDIT_READ_PERMISSION, SERVICE_QUOTA_READ_PERMISSION,
        SERVICE_QUOTA_WRITE_PERMISSION,
    };

    use super::MemoryLocalStore;

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::Release);
        }
    }

    impl ServiceQuotaClock for TestClock {
        fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-quota")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-quota"))),
        }
    }

    fn service(id: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid(id)),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn grant(subject: &ScopedPrincipal, permission: &str) -> PermissionGrant {
        PermissionGrant {
            grantee: subject.clone(),
            permission: permission.to_owned(),
            scope: PermissionScope::Exact(scope()),
        }
    }

    fn denied() -> AuthorizedMutationError {
        AuthorizedMutationError::Authorization(CanonicalError::new(
            CanonicalErrorCode::PermissionDenied,
        ))
    }

    #[test]
    fn service_request_gate_enforces_fixed_window_quota_and_audits_decisions() {
        let store = MemoryLocalStore::default();
        let service = service("service-quota");
        let resource = scope();
        let (credential, secret) = issue_service_credential(&service).expect("issue");
        store
            .provision_service_credential(&credential)
            .expect("bootstrap credential");
        store
            .grant_permission(&grant(&service, CONVERSATION_READ_PERMISSION))
            .expect("bootstrap least privilege");
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: service,
                max_requests: 2,
                window_ms: 1_000,
            })
            .expect("bootstrap quota");
        let clock = TestClock::new(10_000);
        let conversation_id = ConversationId::from_opaque(oid("missing-conversation"));

        for _ in 0..2 {
            let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
            let request = gate
                .authenticate_request(
                    &resource,
                    &credential.credential_id,
                    &secret,
                    CONVERSATION_READ_PERMISSION,
                    &resource,
                )
                .expect("authenticate request");
            let runtime = AuthorizedDurableRuntime::new(&request, &store);
            assert_eq!(
                runtime.conversation(request.subject(), &resource, &conversation_id),
                Ok(None)
            );
        }

        let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
        let limited = gate
            .authenticate_request(
                &resource,
                &credential.credential_id,
                &secret,
                CONVERSATION_READ_PERMISSION,
                &resource,
            )
            .expect("authentication still succeeds before quota");
        let runtime = AuthorizedDurableRuntime::new(&limited, &store);
        assert_eq!(
            runtime.conversation(limited.subject(), &resource, &conversation_id),
            Err(AuthorizedMutationError::Authorization(
                CanonicalError::new(CanonicalErrorCode::RateLimited).with_retry_after(1_000)
            ))
        );

        let audit = store
            .service_audit_records(&resource, 8)
            .expect("read raw audit fixture");
        assert_eq!(
            audit
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![
                ServiceAuditOutcome::Authorized,
                ServiceAuditOutcome::Authorized,
                ServiceAuditOutcome::RateLimited,
            ]
        );
    }

    #[test]
    fn service_request_gate_audits_bad_secret_clock_rollback_and_context_reuse() {
        let store = MemoryLocalStore::default();
        let service = service("service-guard");
        let resource = scope();
        let (credential, secret) = issue_service_credential(&service).expect("issue");
        store
            .provision_service_credential(&credential)
            .expect("bootstrap credential");
        store
            .grant_permission(&grant(&service, CONVERSATION_READ_PERMISSION))
            .expect("bootstrap least privilege");
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: service,
                max_requests: 5,
                window_ms: 1_000,
            })
            .expect("bootstrap quota");
        let clock = TestClock::new(10_000);
        let conversation_id = ConversationId::from_opaque(oid("missing-guard-conversation"));

        let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
        let valid = gate
            .authenticate_request(
                &resource,
                &credential.credential_id,
                &secret,
                CONVERSATION_READ_PERMISSION,
                &resource,
            )
            .expect("authenticate first request");
        let runtime = AuthorizedDurableRuntime::new(&valid, &store);
        assert_eq!(
            runtime.conversation(valid.subject(), &resource, &conversation_id),
            Ok(None)
        );

        let wrong = ServiceCredentialSecret::from_bytes([0xA5; 32]);
        let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
        assert!(matches!(
            gate.authenticate_request(
                &resource,
                &credential.credential_id,
                &wrong,
                CONVERSATION_READ_PERMISSION,
                &resource,
            ),
            Err(CanonicalError {
                code: CanonicalErrorCode::Unauthenticated,
                ..
            })
        ));

        clock.set(9_999);
        let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
        let rollback = gate
            .authenticate_request(
                &resource,
                &credential.credential_id,
                &secret,
                CONVERSATION_READ_PERMISSION,
                &resource,
            )
            .expect("authenticate before rollback check");
        let runtime = AuthorizedDurableRuntime::new(&rollback, &store);
        assert_eq!(
            runtime.conversation(rollback.subject(), &resource, &conversation_id),
            Err(AuthorizedMutationError::Authorization(CanonicalError::new(
                CanonicalErrorCode::TemporarilyUnavailable,
            )))
        );

        clock.set(11_000);
        let gate = ServicePrincipalRequestGate::new(&clock, &store, &store);
        let one_shot = gate
            .authenticate_request(
                &resource,
                &credential.credential_id,
                &secret,
                CONVERSATION_READ_PERMISSION,
                &resource,
            )
            .expect("new window request");
        let runtime = AuthorizedDurableRuntime::new(&one_shot, &store);
        assert_eq!(
            runtime.conversation(one_shot.subject(), &resource, &conversation_id),
            Ok(None)
        );
        assert_eq!(
            runtime.conversation(one_shot.subject(), &resource, &conversation_id),
            Err(denied())
        );

        let audit = store.service_audit_records(&resource, 8).expect("audit");
        assert_eq!(audit.len(), 5);
        assert_eq!(audit[0].outcome, ServiceAuditOutcome::Authorized);
        assert_eq!(audit[1].outcome, ServiceAuditOutcome::AuthenticationFailed);
        assert!(audit[1].subject.is_none());
        assert_eq!(audit[2].outcome, ServiceAuditOutcome::QuotaUnavailable);
        assert_eq!(audit[3].outcome, ServiceAuditOutcome::Authorized);
        assert_eq!(audit[4].outcome, ServiceAuditOutcome::PermissionDenied);
    }

    #[test]
    fn quota_policy_and_audit_read_use_independent_admin_permissions() {
        let store = MemoryLocalStore::default();
        let mut admin = service("admin-quota");
        admin.principal.kind = PrincipalKind::Person;
        let target = service("target-quota");
        let policy = ServiceQuotaPolicy {
            subject: target.clone(),
            max_requests: 10,
            window_ms: 60_000,
        };
        let runtime = AuthorizedDurableRuntime::new(&store, &store);

        assert_eq!(
            runtime.set_service_quota_policy(&admin, &policy),
            Err(denied())
        );
        store
            .grant_permission(&grant(&admin, SERVICE_QUOTA_WRITE_PERMISSION))
            .expect("bootstrap quota write");
        runtime
            .set_service_quota_policy(&admin, &policy)
            .expect("authorized quota write");

        assert_eq!(runtime.service_quota_policy(&admin, &target), Err(denied()));
        store
            .grant_permission(&grant(&admin, SERVICE_QUOTA_READ_PERMISSION))
            .expect("bootstrap quota read");
        assert_eq!(
            runtime.service_quota_policy(&admin, &target),
            Ok(Some(policy))
        );

        assert_eq!(
            runtime.service_audit_records(&admin, &scope(), 10),
            Err(denied())
        );
        store
            .grant_permission(&grant(&admin, SERVICE_AUDIT_READ_PERMISSION))
            .expect("bootstrap audit read");
        assert_eq!(
            runtime.service_audit_records(&admin, &scope(), 10),
            Ok(Vec::new())
        );
    }
}

#[cfg(test)]
mod integration_api_tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use ucr_core::{
        IntegrationCommandIngress, PermissionGrantStore, ServiceAuditStore, ServiceCredentialStore,
        ServiceQuotaClock, ServiceQuotaClockError, ServiceQuotaStore, issue_service_credential,
    };
    use ucr_model::{
        CommandEnvelope, CommandId, CorrelationContext, NamespaceId, OpaqueId, PermissionGrant,
        PermissionScope, PrincipalId, PrincipalKind, PrincipalRef, ProtocolVersion,
        ScopedPrincipal, ServiceAuditOperationRef, ServiceAuditOutcome, ServiceQuotaPolicy,
        TenantId, TenantScope,
    };
    use ucr_protocol::{
        COMMAND_ACCEPT_PERMISSION, CanonicalErrorCode, CommandReceiptStatus,
        SERVICE_AUDIT_COMMAND_OPERATION_KIND, SERVICE_AUDIT_READ_PERMISSION,
    };

    use super::MemoryLocalStore;

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }
        fn set(&self, now: i64) {
            self.0.store(now, Ordering::Release);
        }
    }

    impl ServiceQuotaClock for TestClock {
        fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
            Ok(self.0.load(Ordering::Acquire))
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-integration")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-integration"))),
        }
    }

    fn service() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("service-integration")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn grant(subject: &ScopedPrincipal) -> PermissionGrant {
        PermissionGrant {
            grantee: subject.clone(),
            permission: COMMAND_ACCEPT_PERMISSION.to_owned(),
            scope: PermissionScope::Exact(scope()),
        }
    }

    fn command(id: &str, key: &str, payload: &[u8]) -> CommandEnvelope {
        CommandEnvelope {
            command_id: CommandId::from_opaque(oid(id)),
            scope: scope(),
            command_type: "ucr.message.send".to_owned(),
            payload: payload.to_vec(),
            correlation: CorrelationContext {
                correlation_id: oid("correlation-integration"),
                causation_id: None,
                idempotency_key: Some(key.to_owned()),
            },
            schema_version: ProtocolVersion::new(1, 0),
            extensions: Vec::new(),
        }
    }

    fn operation(command: &CommandEnvelope) -> ServiceAuditOperationRef {
        ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_COMMAND_OPERATION_KIND.to_owned(),
            operation_id: command.command_id.as_opaque().clone(),
        }
    }

    fn install_quota(store: &MemoryLocalStore, subject: &ScopedPrincipal, max_requests: u64) {
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: subject.clone(),
                max_requests,
                window_ms: 1_000,
            })
            .expect("bootstrap quota");
    }

    #[test]
    fn integration_ingress_authenticates_audits_authorizes_and_deduplicates() {
        let store = MemoryLocalStore::default();
        let subject = service();
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&credential)
            .expect("bootstrap credential");
        store
            .grant_permission(&grant(&subject))
            .expect("bootstrap command permission");
        install_quota(&store, &subject, 3);
        let clock = TestClock::new(10_000);
        let ingress = IntegrationCommandIngress::new(&clock, &store, &store);
        let value = command("command-integration", "integration-key", b"hello");

        let accepted = ingress
            .submit_command(&subject.scope, &credential.credential_id, &secret, &value)
            .expect("first external command accepted");
        assert_eq!(accepted.status, CommandReceiptStatus::Accepted);

        let duplicate = ingress
            .submit_command(&subject.scope, &credential.credential_id, &secret, &value)
            .expect("retry deduplicated");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(
            duplicate.original_command_id,
            Some(value.command_id.clone())
        );

        let mut conflicting = value.clone();
        conflicting.payload = b"changed".to_vec();
        let error = ingress
            .submit_command(
                &subject.scope,
                &credential.credential_id,
                &secret,
                &conflicting,
            )
            .expect_err("changed semantics under same command id conflict");
        assert_eq!(error.code, CanonicalErrorCode::Conflict);

        let audit = store
            .service_audit_records(&subject.scope, 8)
            .expect("read audit");
        assert_eq!(
            audit
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![
                ServiceAuditOutcome::Authorized,
                ServiceAuditOutcome::Authorized,
                ServiceAuditOutcome::Authorized,
            ]
        );
        let expected_operation = operation(&value);
        assert!(
            audit
                .iter()
                .all(|record| record.operation.as_ref() == Some(&expected_operation))
        );
        assert_eq!(
            store
                .service_audit_records_for_operation(&subject.scope, &expected_operation, 8)
                .expect("lookup exact operation audit")
                .len(),
            3
        );
    }

    #[test]
    fn integration_ingress_denials_never_create_ghost_acceptance() {
        let store = MemoryLocalStore::default();
        let subject = service();
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&credential)
            .expect("bootstrap credential");
        install_quota(&store, &subject, 4);
        let clock = TestClock::new(20_000);
        let ingress = IntegrationCommandIngress::new(&clock, &store, &store);
        let value = command("command-denied", "denied-key", b"payload");

        let denied = ingress
            .submit_command(&subject.scope, &credential.credential_id, &secret, &value)
            .expect_err("missing command permission denied");
        assert_eq!(denied.code, CanonicalErrorCode::PermissionDenied);

        let wrong = ucr_core::ServiceCredentialSecret::from_bytes([0xA5; 32]);
        let unauthenticated = ingress
            .submit_command(&subject.scope, &credential.credential_id, &wrong, &value)
            .expect_err("wrong secret rejected");
        assert_eq!(unauthenticated.code, CanonicalErrorCode::Unauthenticated);

        store
            .grant_permission(&grant(&subject))
            .expect("grant command permission after denials");
        let accepted = ingress
            .submit_command(&subject.scope, &credential.credential_id, &secret, &value)
            .expect("same command must still be new after denied requests");
        assert_eq!(accepted.status, CommandReceiptStatus::Accepted);

        let audit = store
            .service_audit_records(&subject.scope, 8)
            .expect("read audit");
        assert_eq!(
            audit
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![
                ServiceAuditOutcome::PermissionDenied,
                ServiceAuditOutcome::AuthenticationFailed,
                ServiceAuditOutcome::Authorized,
            ]
        );
        assert!(audit[1].subject.is_none());
        let expected_operation = operation(&value);
        assert!(
            audit
                .iter()
                .all(|record| record.operation.as_ref() == Some(&expected_operation))
        );
    }

    #[test]
    fn integration_ingress_rate_limit_fails_before_command_acceptance() {
        let store = MemoryLocalStore::default();
        let subject = service();
        let (credential, secret) = issue_service_credential(&subject).expect("issue credential");
        store
            .provision_service_credential(&credential)
            .expect("bootstrap credential");
        store
            .grant_permission(&grant(&subject))
            .expect("bootstrap command permission");
        install_quota(&store, &subject, 1);
        let clock = TestClock::new(30_000);
        let ingress = IntegrationCommandIngress::new(&clock, &store, &store);

        let first = command("command-quota-a", "quota-key-a", b"a");
        assert_eq!(
            ingress
                .submit_command(&subject.scope, &credential.credential_id, &secret, &first)
                .expect("first request")
                .status,
            CommandReceiptStatus::Accepted
        );

        let second = command("command-quota-b", "quota-key-b", b"b");
        let limited = ingress
            .submit_command(&subject.scope, &credential.credential_id, &secret, &second)
            .expect_err("second request in same window must be rate limited");
        assert_eq!(limited.code, CanonicalErrorCode::RateLimited);
        assert_eq!(limited.retry_after_ms, Some(1_000));

        clock.set(31_000);
        assert_eq!(
            ingress
                .submit_command(&subject.scope, &credential.credential_id, &secret, &second)
                .expect("rate-limited command was never ghost-accepted")
                .status,
            CommandReceiptStatus::Accepted
        );

        let audit = store
            .service_audit_records(&subject.scope, 8)
            .expect("read audit");
        assert_eq!(
            audit
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![
                ServiceAuditOutcome::Authorized,
                ServiceAuditOutcome::RateLimited,
                ServiceAuditOutcome::Authorized,
            ]
        );
        assert_eq!(audit[0].operation.as_ref(), Some(&operation(&first)));
        assert_eq!(audit[1].operation.as_ref(), Some(&operation(&second)));
        assert_eq!(audit[2].operation.as_ref(), Some(&operation(&second)));
    }

    #[test]
    fn operation_audit_lookup_uses_existing_audit_read_permission() {
        let store = MemoryLocalStore::default();
        let mut admin = service();
        admin.principal.kind = PrincipalKind::Person;
        admin.principal.principal_id = PrincipalId::from_opaque(oid("audit-admin"));
        let command = command("command-audit-lookup", "lookup-key", b"payload");
        let operation = operation(&command);
        let service = service();
        let (credential, secret) = issue_service_credential(&service).expect("issue credential");
        store
            .provision_service_credential(&credential)
            .expect("bootstrap credential");
        store
            .grant_permission(&grant(&service))
            .expect("bootstrap command permission");
        install_quota(&store, &service, 2);
        IntegrationCommandIngress::new(&TestClock::new(40_000), &store, &store)
            .submit_command(&service.scope, &credential.credential_id, &secret, &command)
            .expect("create operation-bound audit");

        let runtime = ucr_core::AuthorizedDurableRuntime::new(&store, &store);
        assert!(matches!(
            runtime.service_audit_records_for_operation(&admin, &scope(), &operation, 8),
            Err(ucr_core::AuthorizedMutationError::Authorization(_))
        ));
        store
            .grant_permission(&PermissionGrant {
                grantee: admin.clone(),
                permission: SERVICE_AUDIT_READ_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant existing audit read permission");
        let rows = runtime
            .service_audit_records_for_operation(&admin, &scope(), &operation, 8)
            .expect("authorized exact operation lookup");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].operation.as_ref(), Some(&operation));
    }
}

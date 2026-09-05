use ucr_model::{
    AntiEntropyCursor, AntiEntropyPage, AuthorizationRequest, CommandEnvelope, CommandId,
    ConversationId, ConversationRecord, DeliveryAttempt, DeliveryEvidence, DeliveryId,
    DeliveryState, DeviceDescriptor, DeviceId, EventEnvelope, EventId, EventReconciliation,
    EventSummary, ExternalIdentityBinding, IdentityId, IdentityRecord, IntegrationId, IntentId,
    KeyId, MessageEnvelope, MessageId, PermissionGrant, PermissionScope, PrincipalKind,
    PublicKeyDescriptor, RecoveryPlan, RecoveryPlanId, ScopedPrincipal, ServiceAuditOperationRef,
    ServiceAuditRecord, ServiceCredentialId, ServiceCredentialRecord, ServiceQuotaPolicy,
    SessionId, SyncCheckpoint, SyncSession, SyncState, TenantScope, TrustedSigningKeyRecord,
};
use ucr_protocol::{
    ANTI_ENTROPY_READ_PERMISSION, ANTI_ENTROPY_RECONCILE_PERMISSION, COMMAND_ACCEPT_PERMISSION,
    COMMAND_OUTCOME_READ_PERMISSION, COMMAND_OUTCOME_WRITE_PERMISSION,
    COMMUNICATION_INTENT_READ_PERMISSION, COMMUNICATION_INTENT_WRITE_PERMISSION,
    CONVERSATION_READ_PERMISSION, CONVERSATION_WRITE_PERMISSION, DELIVERY_READ_PERMISSION,
    DELIVERY_WRITE_PERMISSION, DEVICE_READ_PERMISSION, DEVICE_REGISTER_PERMISSION,
    DEVICE_REVOKE_PERMISSION, EVENT_APPEND_PERMISSION, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
    EXTERNAL_IDENTITY_BINDING_READ_PERMISSION, IDENTITY_CREATE_PERMISSION,
    IDENTITY_READ_PERMISSION, MESSAGE_READ_PERMISSION, MESSAGE_WRITE_PERMISSION,
    PERMISSION_GRANT_CREATE_PERMISSION, PERMISSION_GRANT_READ_PERMISSION,
    PERMISSION_GRANT_REVOKE_PERMISSION, RECOVERY_PLAN_INSTALL_PERMISSION,
    RECOVERY_PLAN_READ_PERMISSION, RECOVERY_PLAN_REVOKE_PERMISSION,
    RECOVERY_PLAN_ROTATE_PERMISSION, SERVICE_AUDIT_READ_PERMISSION,
    SERVICE_CREDENTIAL_PROVISION_PERMISSION, SERVICE_CREDENTIAL_REVOKE_PERMISSION,
    SERVICE_QUOTA_READ_PERMISSION, SERVICE_QUOTA_WRITE_PERMISSION, SYNC_READ_PERMISSION,
    SYNC_WRITE_PERMISSION, TRUSTED_SIGNING_KEY_PROVISION_PERMISSION,
    TRUSTED_SIGNING_KEY_READ_PERMISSION, TRUSTED_SIGNING_KEY_REVOKE_PERMISSION,
    TRUSTED_SIGNING_KEY_ROTATE_PERMISSION,
};

use crate::{
    AntiEntropyStore, AuthorizationEvaluator, AuthorizedMutationError, CommandAcceptanceStore,
    CommandOutcomeStore, CommunicationIntentStore, ConversationStore, DeliveryStore,
    DeviceLifecycleStore, DurableRecordStatus, DurableStoreError, EventAppendStatus,
    EventJournalStore, ExternalIdentityBindingStore, IdentityStore, MessageStore,
    PermissionGrantStore, RecoveryPlanStore, ServiceAuditStore, ServiceCredentialStore,
    ServiceQuotaStore, SyncStore, TrustedSigningKeyStore,
};

/// Authorization-enforcing runtime boundary over tenant-scoped durable capabilities.
///
/// The caller supplies an already authenticated [`ScopedPrincipal`]. Raw stores remain
/// persistence capabilities and are not an external authorization bypass.
#[derive(Debug)]
pub struct AuthorizedDurableRuntime<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> AuthorizedDurableRuntime<'a, A, S>
where
    A: AuthorizationEvaluator,
{
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }

    fn require(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        permission: &str,
    ) -> Result<(), AuthorizedMutationError> {
        let request = AuthorizationRequest {
            subject: subject.clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        };
        if subject.principal.kind == PrincipalKind::ServiceAccount
            && !self
                .authorization
                .service_principal_admission_proof()
                .is_some_and(|proof| proof.matches(&request))
        {
            return Err(AuthorizedMutationError::Authorization(
                ucr_protocol::CanonicalError::new(
                    ucr_protocol::CanonicalErrorCode::PermissionDenied,
                ),
            ));
        }
        self.authorization
            .authorize(&request)
            .map_err(AuthorizedMutationError::Authorization)
    }
}

fn permission_grant_resource_scope(grant: &PermissionGrant) -> TenantScope {
    match &grant.scope {
        PermissionScope::Exact(scope) => scope.clone(),
        PermissionScope::TenantWide(tenant_id) => TenantScope {
            tenant_id: tenant_id.clone(),
            namespace_id: None,
        },
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: PermissionGrantStore,
{
    /// Lists grants for one scoped principal only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn permission_grants_for(
        &self,
        subject: &ScopedPrincipal,
        target: &ScopedPrincipal,
    ) -> Result<Vec<PermissionGrant>, AuthorizedMutationError> {
        self.require(subject, &target.scope, PERMISSION_GRANT_READ_PERMISSION)?;
        self.store
            .permission_grants_for(target)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Adds one grant through the runtime administration boundary.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures. Runtime callers cannot
    /// bootstrap this permission through the same path.
    pub fn grant_permission(
        &self,
        subject: &ScopedPrincipal,
        grant: &PermissionGrant,
    ) -> Result<(), AuthorizedMutationError> {
        let resource_scope = permission_grant_resource_scope(grant);
        self.require(subject, &resource_scope, PERMISSION_GRANT_CREATE_PERMISSION)?;
        self.store
            .grant_permission(grant)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Removes one exact grant through the runtime administration boundary.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn revoke_permission(
        &self,
        subject: &ScopedPrincipal,
        grant: &PermissionGrant,
    ) -> Result<(), AuthorizedMutationError> {
        let resource_scope = permission_grant_resource_scope(grant);
        self.require(subject, &resource_scope, PERMISSION_GRANT_REVOKE_PERMISSION)?;
        self.store
            .revoke_permission(grant)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore,
{
    /// Provisions one Service Principal credential only after administrator authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures. Credential plaintext is never persisted.
    pub fn provision_service_credential(
        &self,
        subject: &ScopedPrincipal,
        record: &ServiceCredentialRecord,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(
            subject,
            &record.subject.scope,
            SERVICE_CREDENTIAL_PROVISION_PERMISSION,
        )?;
        self.store
            .provision_service_credential(record)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Revokes one Service Principal credential only after administrator authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures. Revocation is irreversible.
    pub fn revoke_service_credential(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, SERVICE_CREDENTIAL_REVOKE_PERMISSION)?;
        self.store
            .revoke_service_credential(scope, credential_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: ServiceQuotaStore,
{
    /// Reads one Service Principal quota policy only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn service_quota_policy(
        &self,
        subject: &ScopedPrincipal,
        target: &ScopedPrincipal,
    ) -> Result<Option<ServiceQuotaPolicy>, AuthorizedMutationError> {
        self.require(subject, &target.scope, SERVICE_QUOTA_READ_PERMISSION)?;
        self.store
            .service_quota_policy(target)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Installs or replaces one Service Principal quota policy only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn set_service_quota_policy(
        &self,
        subject: &ScopedPrincipal,
        policy: &ServiceQuotaPolicy,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(
            subject,
            &policy.subject.scope,
            SERVICE_QUOTA_WRITE_PERMISSION,
        )?;
        self.store
            .set_service_quota_policy(policy)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: ServiceAuditStore,
{
    /// Reads the newest bounded Service Principal admission audit records after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn service_audit_records(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        max_items: usize,
    ) -> Result<Vec<ServiceAuditRecord>, AuthorizedMutationError> {
        self.require(subject, scope, SERVICE_AUDIT_READ_PERMISSION)?;
        self.store
            .service_audit_records(scope, max_items)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Reads admission audit records bound to one exact canonical operation reference.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn service_audit_records_for_operation(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        operation: &ServiceAuditOperationRef,
        max_items: usize,
    ) -> Result<Vec<ServiceAuditRecord>, AuthorizedMutationError> {
        self.require(subject, scope, SERVICE_AUDIT_READ_PERMISSION)?;
        self.store
            .service_audit_records_for_operation(scope, operation, max_items)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: DeviceLifecycleStore,
{
    /// Registers one exact-scoped canonical Device only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn register_device(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        descriptor: &DeviceDescriptor,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, DEVICE_REGISTER_PERMISSION)?;
        self.store
            .register_device(scope, descriptor)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Irreversibly revokes one exact-scoped Device and its current device-bound
    /// trusted signing material only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn revoke_device(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_identity_id: &IdentityId,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, DEVICE_REVOKE_PERMISSION)?;
        self.store
            .revoke_device(scope, device_id, expected_identity_id)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Reads one exact-scoped canonical Device only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn device(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<DeviceDescriptor>, AuthorizedMutationError> {
        self.require(subject, scope, DEVICE_READ_PERMISSION)?;
        self.store
            .device(scope, device_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: TrustedSigningKeyStore,
{
    /// Provisions a trusted signing key only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn provision_trusted_signing_key(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        descriptor: &PublicKeyDescriptor,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, TRUSTED_SIGNING_KEY_PROVISION_PERMISSION)?;
        self.store
            .provision_trusted_signing_key(scope, descriptor)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Rotates the expected trusted signing key only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn rotate_trusted_signing_key(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
        replacement: &PublicKeyDescriptor,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, TRUSTED_SIGNING_KEY_ROTATE_PERMISSION)?;
        self.store
            .rotate_trusted_signing_key(scope, device_id, expected_current, replacement)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Revokes the expected trusted signing key only after authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn revoke_trusted_signing_key(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, TRUSTED_SIGNING_KEY_REVOKE_PERMISSION)?;
        self.store
            .revoke_trusted_signing_key(scope, device_id, expected_current)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn trusted_signing_key(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        key_id: &KeyId,
    ) -> Result<Option<TrustedSigningKeyRecord>, AuthorizedMutationError> {
        self.require(subject, scope, TRUSTED_SIGNING_KEY_READ_PERMISSION)?;
        self.store
            .trusted_signing_key(scope, key_id)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn active_trusted_signing_key(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<PublicKeyDescriptor>, AuthorizedMutationError> {
        self.require(subject, scope, TRUSTED_SIGNING_KEY_READ_PERMISSION)?;
        self.store
            .active_trusted_signing_key(scope, device_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: RecoveryPlanStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn install_recovery_plan(
        &self,
        subject: &ScopedPrincipal,
        plan: &RecoveryPlan,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, &plan.scope, RECOVERY_PLAN_INSTALL_PERMISSION)?;
        self.store
            .install_recovery_plan(plan)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn rotate_recovery_plan(
        &self,
        subject: &ScopedPrincipal,
        expected_current: &RecoveryPlanId,
        replacement: &RecoveryPlan,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, &replacement.scope, RECOVERY_PLAN_ROTATE_PERMISSION)?;
        self.store
            .rotate_recovery_plan(expected_current, replacement)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn revoke_recovery_plan(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        identity_id: &IdentityId,
        expected_current: &RecoveryPlanId,
    ) -> Result<(), AuthorizedMutationError> {
        self.require(subject, scope, RECOVERY_PLAN_REVOKE_PERMISSION)?;
        self.store
            .revoke_recovery_plan(scope, identity_id, expected_current)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn active_recovery_plan(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<RecoveryPlan>, AuthorizedMutationError> {
        self.require(subject, scope, RECOVERY_PLAN_READ_PERMISSION)?;
        self.store
            .active_recovery_plan(scope, identity_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: CommandAcceptanceStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn accept_command(
        &self,
        subject: &ScopedPrincipal,
        command: &CommandEnvelope,
    ) -> Result<ucr_protocol::CommandReceipt, AuthorizedMutationError> {
        self.require(subject, &command.scope, COMMAND_ACCEPT_PERMISSION)?;
        self.store
            .accept_command(command)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: CommunicationIntentStore,
{
    /// Persists one Communication Intent only after exact-scope authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures; denied calls never reach storage.
    pub fn persist_communication_intent(
        &self,
        subject: &ScopedPrincipal,
        intent: &ucr_model::CommunicationIntent,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(
            subject,
            &intent.scope,
            COMMUNICATION_INTENT_WRITE_PERMISSION,
        )?;
        self.store
            .persist_communication_intent(intent)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Loads one Communication Intent only after exact-scope authorization.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn communication_intent(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        intent_id: &IntentId,
    ) -> Result<Option<ucr_model::CommunicationIntent>, AuthorizedMutationError> {
        self.require(subject, scope, COMMUNICATION_INTENT_READ_PERMISSION)?;
        self.store
            .communication_intent(scope, intent_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: IdentityStore,
{
    /// Creates one canonical Root Identity after exact-scope authorization.
    ///
    /// # Errors
    /// Returns authorization before storage access, then explicit validation/conflict/storage errors.
    pub fn persist_identity(
        &self,
        subject: &ScopedPrincipal,
        identity: &IdentityRecord,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, &identity.scope, IDENTITY_CREATE_PERMISSION)?;
        self.store
            .persist_identity(identity)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Loads one canonical Root Identity after exact-scope authorization.
    ///
    /// # Errors
    /// Returns authorization before storage access, then explicit storage/corruption errors.
    pub fn identity(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<IdentityRecord>, AuthorizedMutationError> {
        self.require(subject, scope, IDENTITY_READ_PERMISSION)?;
        self.store
            .identity(scope, identity_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: ExternalIdentityBindingStore,
{
    /// Links one exact integration-scoped external entity to canonical Identity.
    ///
    /// Existing keys cannot be silently reassigned to another Identity.
    ///
    /// # Errors
    /// Returns authorization before storage access, then explicit validation/conflict/storage errors.
    pub fn link_external_identity(
        &self,
        subject: &ScopedPrincipal,
        binding: &ExternalIdentityBinding,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(
            subject,
            &binding.scope,
            EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
        )?;
        self.store
            .persist_external_identity_binding(binding)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Loads one exact integration-scoped external Identity binding after authorization.
    ///
    /// # Errors
    /// Returns authorization before storage access, then explicit validation/storage errors.
    pub fn external_identity_binding(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        external_namespace: &str,
        external_entity_id: &[u8],
    ) -> Result<Option<ExternalIdentityBinding>, AuthorizedMutationError> {
        self.require(subject, scope, EXTERNAL_IDENTITY_BINDING_READ_PERMISSION)?;
        self.store
            .external_identity_binding(
                scope,
                integration_id,
                external_namespace,
                external_entity_id,
            )
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: ConversationStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn persist_conversation(
        &self,
        subject: &ScopedPrincipal,
        conversation: &ConversationRecord,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, &conversation.scope, CONVERSATION_WRITE_PERMISSION)?;
        self.store
            .persist_conversation(conversation)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn conversation(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<ConversationRecord>, AuthorizedMutationError> {
        self.require(subject, scope, CONVERSATION_READ_PERMISSION)?;
        self.store
            .conversation(scope, conversation_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: MessageStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn persist_message(
        &self,
        subject: &ScopedPrincipal,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, &message.scope, MESSAGE_WRITE_PERMISSION)?;
        self.store
            .persist_message(message)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn message(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, AuthorizedMutationError> {
        self.require(subject, scope, MESSAGE_READ_PERMISSION)?;
        self.store
            .message(scope, message_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: DeliveryStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn create_delivery_attempt(
        &self,
        subject: &ScopedPrincipal,
        attempt: &DeliveryAttempt,
        persisted_evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        if attempt.scope != persisted_evidence.scope {
            return Err(AuthorizedMutationError::Store(
                DurableStoreError::InvalidRecord,
            ));
        }
        self.require(subject, &attempt.scope, DELIVERY_WRITE_PERMISSION)?;
        self.store
            .create_delivery_attempt(attempt, persisted_evidence)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn transition_delivery(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
        expected_state: DeliveryState,
        next_state: DeliveryState,
        evidence: Option<&DeliveryEvidence>,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        if evidence.is_some_and(|value| &value.scope != scope) {
            return Err(AuthorizedMutationError::Store(
                DurableStoreError::InvalidRecord,
            ));
        }
        self.require(subject, scope, DELIVERY_WRITE_PERMISSION)?;
        self.store
            .transition_delivery(scope, delivery_id, expected_state, next_state, evidence)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn record_delivery_evidence(
        &self,
        subject: &ScopedPrincipal,
        evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, &evidence.scope, DELIVERY_WRITE_PERMISSION)?;
        self.store
            .record_delivery_evidence(evidence)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn delivery_attempt(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
    ) -> Result<Option<DeliveryAttempt>, AuthorizedMutationError> {
        self.require(subject, scope, DELIVERY_READ_PERMISSION)?;
        self.store
            .delivery_attempt(scope, delivery_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: SyncStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn create_sync_session(
        &self,
        subject: &ScopedPrincipal,
        session: &SyncSession,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, &session.scope, SYNC_WRITE_PERMISSION)?;
        self.store
            .create_sync_session(session)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn transition_sync(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        session_id: &SessionId,
        expected_state: SyncState,
        next_state: SyncState,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, scope, SYNC_WRITE_PERMISSION)?;
        self.store
            .transition_sync(scope, session_id, expected_state, next_state)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn record_sync_checkpoint(
        &self,
        subject: &ScopedPrincipal,
        checkpoint: &SyncCheckpoint,
    ) -> Result<DurableRecordStatus, AuthorizedMutationError> {
        self.require(subject, &checkpoint.scope, SYNC_WRITE_PERMISSION)?;
        self.store
            .record_sync_checkpoint(checkpoint)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn sync_session(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncSession>, AuthorizedMutationError> {
        self.require(subject, scope, SYNC_READ_PERMISSION)?;
        self.store
            .sync_session(scope, session_id)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn latest_sync_checkpoint(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncCheckpoint>, AuthorizedMutationError> {
        self.require(subject, scope, SYNC_READ_PERMISSION)?;
        self.store
            .latest_sync_checkpoint(scope, session_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: EventJournalStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn append_event(
        &self,
        subject: &ScopedPrincipal,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, AuthorizedMutationError> {
        self.require(subject, &event.scope, EVENT_APPEND_PERMISSION)?;
        self.store
            .append_event(event)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: AntiEntropyStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn anti_entropy_summary_page(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        session_id: &SessionId,
        cursor: Option<&AntiEntropyCursor>,
        max_items: usize,
    ) -> Result<AntiEntropyPage, AuthorizedMutationError> {
        self.require(subject, scope, ANTI_ENTROPY_READ_PERMISSION)?;
        self.store
            .anti_entropy_summary_page(scope, session_id, cursor, max_items)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn classify_event_summaries(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        session_id: &SessionId,
        summaries: &[EventSummary],
    ) -> Result<Vec<EventReconciliation>, AuthorizedMutationError> {
        self.require(subject, scope, ANTI_ENTROPY_READ_PERMISSION)?;
        self.store
            .classify_event_summaries(scope, session_id, summaries)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn reconcile_event(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        session_id: &SessionId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, AuthorizedMutationError> {
        if &event.scope != scope {
            return Err(AuthorizedMutationError::Store(
                DurableStoreError::InvalidRecord,
            ));
        }
        self.require(subject, scope, ANTI_ENTROPY_RECONCILE_PERMISSION)?;
        self.store
            .reconcile_event(scope, session_id, event)
            .map_err(AuthorizedMutationError::Store)
    }
}

impl<A, S> AuthorizedDurableRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: CommandOutcomeStore,
{
    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn record_terminal_event(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        command_id: &CommandId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, AuthorizedMutationError> {
        if &event.scope != scope {
            return Err(AuthorizedMutationError::Store(
                DurableStoreError::InvalidRecord,
            ));
        }
        self.require(subject, scope, COMMAND_OUTCOME_WRITE_PERMISSION)?;
        self.store
            .record_terminal_event(scope, command_id, event)
            .map_err(AuthorizedMutationError::Store)
    }

    /// Executes this tenant-scoped durable operation only after authorization.
    ///
    /// # Errors
    /// Returns an authorization failure before storage access, an invalid-record failure
    /// for contradictory scoped inputs, or the underlying durable-store failure.
    pub fn terminal_event(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        command_id: &CommandId,
    ) -> Result<Option<EventId>, AuthorizedMutationError> {
        self.require(subject, scope, COMMAND_OUTCOME_READ_PERMISSION)?;
        self.store
            .terminal_event(scope, command_id)
            .map_err(AuthorizedMutationError::Store)
    }
}

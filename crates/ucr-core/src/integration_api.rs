use core::fmt;

use ucr_model::{
    CommandEnvelope, ConversationId, ConversationRecord, ExternalIdentityBinding, IdentityId,
    IdentityRecord, IntegrationId, ServiceAuditOperationRef, ServiceCredentialId, TenantScope,
};
use ucr_protocol::{
    COMMAND_ACCEPT_PERMISSION, CONVERSATION_READ_PERMISSION, CONVERSATION_WRITE_PERMISSION,
    CanonicalError, CanonicalErrorCode, CommandReceipt, EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
    EXTERNAL_IDENTITY_BINDING_READ_PERMISSION, IDENTITY_CREATE_PERMISSION,
    IDENTITY_READ_PERMISSION, SERVICE_AUDIT_COMMAND_OPERATION_KIND,
    SERVICE_AUDIT_CONVERSATION_CREATE_OPERATION_KIND,
    SERVICE_AUDIT_CONVERSATION_READ_OPERATION_KIND,
    SERVICE_AUDIT_EXTERNAL_IDENTITY_LINK_OPERATION_KIND,
    SERVICE_AUDIT_EXTERNAL_IDENTITY_READ_OPERATION_KIND,
    SERVICE_AUDIT_IDENTITY_CREATE_OPERATION_KIND, SERVICE_AUDIT_IDENTITY_READ_OPERATION_KIND,
};

use crate::{
    AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError,
    CommandAcceptanceStore, ConversationStore, DurableStoreError, ExternalIdentityBindingStore,
    IdentityStore, ServiceAuditStore, ServiceCredentialSecret, ServiceCredentialStore,
    ServicePrincipalRequestGate, ServiceQuotaClock, ServiceQuotaStore,
};

/// Transport-neutral Phase-13 ingress for external Service Principal operations.
///
/// Concrete gRPC, HTTP, local-IPC, or embedded adapters terminate their binding-specific
/// credential presentation before calling this boundary. They do not receive raw store access.
pub struct IntegrationIngress<'a, C, A, S> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
}

/// Borrowed exact key for one external Identity-binding lookup at the Rust reference boundary.
///
/// This is a parameter bundle only, not a durable owner or alternate public contract. The
/// language-independent wire shape remains `IntegrationResolveIdentityBindingRequest`.
#[derive(Clone, Copy)]
pub struct ExternalIdentityBindingLookup<'a> {
    pub scope: &'a TenantScope,
    pub integration_id: &'a IntegrationId,
    pub external_namespace: &'a str,
    pub external_entity_id: &'a [u8],
}

impl<'a> ExternalIdentityBindingLookup<'a> {
    #[must_use]
    pub const fn new(
        scope: &'a TenantScope,
        integration_id: &'a IntegrationId,
        external_namespace: &'a str,
        external_entity_id: &'a [u8],
    ) -> Self {
        Self {
            scope,
            integration_id,
            external_namespace,
            external_entity_id,
        }
    }
}

impl fmt::Debug for ExternalIdentityBindingLookup<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalIdentityBindingLookup")
            .field("scope", self.scope)
            .field("integration_id", self.integration_id)
            .field("external_namespace", &"<redacted>")
            .field("external_entity_id", &"<redacted>")
            .field("external_entity_id_len", &self.external_entity_id.len())
            .finish()
    }
}

impl<C, A, S> fmt::Debug for IntegrationIngress<'_, C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationIngress")
            .finish_non_exhaustive()
    }
}

impl<'a, C, A, S> IntegrationIngress<'a, C, A, S> {
    #[must_use]
    pub const fn new(clock: &'a C, authorization: &'a A, store: &'a S) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }
}

impl<C, A, S> IntegrationIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + CommandAcceptanceStore,
{
    /// Authenticates, rate-limits, audits, authorizes, then durably accepts one command.
    ///
    /// The returned receipt proves acceptance or deduplication only; it never proves that
    /// the command's requested external effect completed.
    ///
    /// # Errors
    /// Authentication, quota, permission, validation, conflict, and storage failures map to
    /// stable canonical errors. No failure is treated as implicit command acceptance.
    pub fn submit_command(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_COMMAND_OPERATION_KIND.to_owned(),
            operation_id: command.command_id.as_opaque().clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                COMMAND_ACCEPT_PERMISSION,
                &command.scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .accept_command(&subject, command)
            .map_err(map_authorized_error)
    }
}

impl<C, A, S> IntegrationIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + IdentityStore,
{
    /// Authenticates, rate-limits, audits, authorizes, then durably creates one Root Identity.
    ///
    /// Canonically identical retries return the same Identity. A scoped `IdentityId` cannot be
    /// silently redefined with different ownership, evidence, or expiry metadata.
    ///
    /// # Errors
    /// Authentication, quota, permission, validation, conflict, and storage failures map to
    /// stable canonical errors. Denied/failed calls never create an Identity.
    pub fn create_identity(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        identity: &IdentityRecord,
    ) -> Result<IdentityRecord, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_IDENTITY_CREATE_OPERATION_KIND.to_owned(),
            operation_id: identity.identity_id.as_opaque().clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                IDENTITY_CREATE_PERMISSION,
                &identity.scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .persist_identity(&subject, identity)
            .map_err(map_authorized_error)?;
        Ok(identity.clone())
    }
}

impl<C, A, S> IntegrationIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + ExternalIdentityBindingStore,
{
    /// Authenticates, rate-limits, audits, authorizes, then durably links one external Identity.
    ///
    /// A canonically identical retry returns the same binding. The exact external key cannot be
    /// silently reassigned to another canonical Identity.
    ///
    /// # Errors
    /// Authentication, quota, permission, validation, conflict, and storage failures map to
    /// stable canonical errors. Denied/failed calls never create a binding.
    pub fn link_identity(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        binding: &ExternalIdentityBinding,
    ) -> Result<ExternalIdentityBinding, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_EXTERNAL_IDENTITY_LINK_OPERATION_KIND.to_owned(),
            operation_id: binding.identity_id.as_opaque().clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION,
                &binding.scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .link_external_identity(&subject, binding)
            .map_err(map_authorized_error)?;
        Ok(binding.clone())
    }
}

impl<C, A, S> IntegrationIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + IdentityStore,
{
    /// Authenticates, rate-limits, audits, authorizes, then reads one exact Root Identity.
    ///
    /// Absence is exposed as canonical `NOT_FOUND` only after the caller passes the complete
    /// Service Principal admission and read-permission boundary.
    ///
    /// # Errors
    /// Authentication, quota, permission, not-found, and storage failures map to stable canonical
    /// errors. Unauthorized callers cannot use this method as an Identity-existence oracle.
    pub fn get_identity(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<IdentityRecord, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_IDENTITY_READ_OPERATION_KIND.to_owned(),
            operation_id: identity_id.as_opaque().clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                IDENTITY_READ_PERMISSION,
                scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .identity(&subject, scope, identity_id)
            .map_err(map_authorized_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
    }
}

impl<C, A, S> IntegrationIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + ConversationStore,
{
    /// Authenticates, rate-limits, audits, authorizes, then durably creates one Conversation.
    ///
    /// Canonically identical retries return the same Conversation. The existing Conversation
    /// owner remains authoritative for hierarchy validation, deduplication, and conflicts.
    ///
    /// # Errors
    /// Authentication, quota, permission, validation, conflict, and storage failures map to
    /// stable canonical errors. Denied or failed requests never create a Conversation.
    pub fn create_conversation(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        conversation: &ConversationRecord,
    ) -> Result<ConversationRecord, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_CONVERSATION_CREATE_OPERATION_KIND.to_owned(),
            operation_id: conversation
                .conversation
                .conversation_id
                .as_opaque()
                .clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                CONVERSATION_WRITE_PERMISSION,
                &conversation.scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .persist_conversation(&subject, conversation)
            .map_err(map_authorized_error)?;
        Ok(conversation.clone())
    }

    /// Authenticates, rate-limits, audits, authorizes, then reads one exact Conversation.
    ///
    /// Absence becomes canonical `NOT_FOUND` only after the complete Service Principal admission
    /// and Conversation-read permission boundary succeeds.
    ///
    /// # Errors
    /// Authentication, quota, permission, not-found, and storage failures map to stable canonical
    /// errors. Unauthorized callers cannot probe Conversation existence.
    pub fn get_conversation(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<ConversationRecord, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_CONVERSATION_READ_OPERATION_KIND.to_owned(),
            operation_id: conversation_id.as_opaque().clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                CONVERSATION_READ_PERMISSION,
                scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .conversation(&subject, scope, conversation_id)
            .map_err(map_authorized_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
    }
}

impl<C, A, S> IntegrationIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + ExternalIdentityBindingStore,
{
    /// Resolves one exact external Identity binding through the canonical durable owner.
    ///
    /// Audit attribution records the canonical `IntegrationId` only. Sensitive external namespace
    /// and entity bytes remain authorized request data and are not copied into admission audit.
    ///
    /// # Errors
    /// Authentication, quota, permission, validation, not-found, and storage failures map to
    /// stable canonical errors. Absence is disclosed only after successful authorization.
    pub fn resolve_identity_binding(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        lookup: ExternalIdentityBindingLookup<'_>,
    ) -> Result<ExternalIdentityBinding, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_EXTERNAL_IDENTITY_READ_OPERATION_KIND.to_owned(),
            operation_id: lookup.integration_id.as_opaque().clone(),
        };
        let request = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                EXTERNAL_IDENTITY_BINDING_READ_PERMISSION,
                lookup.scope,
                &operation,
            )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .external_identity_binding(
                &subject,
                lookup.scope,
                lookup.integration_id,
                lookup.external_namespace,
                lookup.external_entity_id,
            )
            .map_err(map_authorized_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
    }
}

/// Backward-compatible Phase-13 name retained while the public ingress grows beyond Commands.
pub type IntegrationCommandIngress<'a, C, A, S> = IntegrationIngress<'a, C, A, S>;

const fn map_authorized_error(error: AuthorizedMutationError) -> CanonicalError {
    match error {
        AuthorizedMutationError::Authorization(error) => error,
        AuthorizedMutationError::Store(error) => CanonicalError::new(match error {
            DurableStoreError::InvalidRecord => CanonicalErrorCode::InvalidArgument,
            DurableStoreError::Conflict => CanonicalErrorCode::Conflict,
            DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
            DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
            DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
            DurableStoreError::Corrupt
            | DurableStoreError::UnsupportedSchemaVersion
            | DurableStoreError::ForeignStore
            | DurableStoreError::Internal => CanonicalErrorCode::Internal,
        }),
    }
}

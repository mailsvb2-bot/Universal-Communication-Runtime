use core::fmt;

use ucr_model::{
    CommandEnvelope, ExternalIdentityBinding, IdentityRecord, ServiceAuditOperationRef,
    ServiceCredentialId, TenantScope,
};
use ucr_protocol::{
    COMMAND_ACCEPT_PERMISSION, CanonicalError, CanonicalErrorCode, CommandReceipt,
    EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION, IDENTITY_CREATE_PERMISSION,
    SERVICE_AUDIT_COMMAND_OPERATION_KIND, SERVICE_AUDIT_EXTERNAL_IDENTITY_LINK_OPERATION_KIND,
    SERVICE_AUDIT_IDENTITY_CREATE_OPERATION_KIND,
};

use crate::{
    AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError,
    CommandAcceptanceStore, DurableStoreError, ExternalIdentityBindingStore, IdentityStore,
    ServiceAuditStore, ServiceCredentialSecret, ServiceCredentialStore,
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

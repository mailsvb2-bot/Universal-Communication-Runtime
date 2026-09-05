use core::fmt;

use ucr_model::{CommandEnvelope, ServiceAuditOperationRef, ServiceCredentialId, TenantScope};
use ucr_protocol::{
    COMMAND_ACCEPT_PERMISSION, CanonicalError, CanonicalErrorCode, CommandReceipt,
    SERVICE_AUDIT_COMMAND_OPERATION_KIND,
};

use crate::{
    AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError,
    CommandAcceptanceStore, DurableStoreError, ServiceAuditStore, ServiceCredentialSecret,
    ServiceCredentialStore, ServicePrincipalRequestGate, ServiceQuotaClock, ServiceQuotaStore,
};

/// Transport-neutral Phase-13 ingress for an external Service Principal command.
///
/// Concrete gRPC, HTTP, local-IPC, or embedded adapters terminate their binding-specific
/// credential presentation before calling this boundary. They do not receive raw store access.
pub struct IntegrationCommandIngress<'a, C, A, S> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
}

impl<C, A, S> fmt::Debug for IntegrationCommandIngress<'_, C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationCommandIngress")
            .finish_non_exhaustive()
    }
}
impl<'a, C, A, S> IntegrationCommandIngress<'a, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + CommandAcceptanceStore,
{
    #[must_use]
    pub const fn new(clock: &'a C, authorization: &'a A, store: &'a S) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }

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

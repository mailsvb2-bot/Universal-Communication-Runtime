use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use ucr_model::{
    AuditRecordId, AuthorizationRequest, ScopedPrincipal, ServiceAuditOperationRef,
    ServiceAuditOutcome, ServiceAuditRecord, ServiceCredentialId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, MAX_SERVICE_AUDIT_OPERATION_KIND_LEN,
    MAX_SERVICE_REQUEST_PERMISSION_LEN, validate_namespaced_identifier,
    validate_service_audit_operation_ref,
};

use crate::{
    AuthorizationEvaluator, DurableStoreError, IdGenerationError, ServiceAuditStore,
    ServiceAuthenticationError, ServiceCredentialSecret, ServiceCredentialStore,
    ServiceQuotaConsumeError, ServiceQuotaStore, authenticate_service_principal,
    generate_opaque_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceQuotaClockError {
    Unavailable,
}

/// Trusted local time source used only for quota windows and audit context.
/// Authentication, identity, replay, and authorization never derive from this clock.
pub trait ServiceQuotaClock: fmt::Debug + Send + Sync {
    /// Returns current Unix epoch milliseconds.
    ///
    /// # Errors
    /// Fails closed when a usable timestamp cannot be produced.
    fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError>;
}

/// Core-owned proof that one authenticated Service Principal request is bound to an exact
/// permission/resource tuple. Fields are private so external callers cannot fabricate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipalAdmissionProof {
    subject: ScopedPrincipal,
    permission: String,
    resource_scope: TenantScope,
}

impl ServicePrincipalAdmissionProof {
    pub(crate) fn matches(&self, request: &AuthorizationRequest) -> bool {
        request.subject == self.subject
            && request.permission == self.permission
            && request.resource_scope == self.resource_scope
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemServiceQuotaClock;

impl ServiceQuotaClock for SystemServiceQuotaClock {
    fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServiceQuotaClockError::Unavailable)?;
        i64::try_from(duration.as_millis()).map_err(|_| ServiceQuotaClockError::Unavailable)
    }
}

/// Entry boundary for one external Service Principal request.
///
/// Authentication happens once here. The returned evaluator is single-use and bound to one
/// permission/resource tuple; it applies quota, delegates to the existing authorization owner,
/// and persists an audit decision before any authorized durable operation is reached.
#[derive(Clone, Copy)]
struct ServiceAuditRequestContext<'a> {
    credential_id: &'a ServiceCredentialId,
    presented_scope: &'a TenantScope,
    permission: &'a str,
    resource_scope: &'a TenantScope,
    operation: Option<&'a ServiceAuditOperationRef>,
}

pub struct ServicePrincipalRequestGate<'a, C, A, S> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
}

impl<C, A, S> fmt::Debug for ServicePrincipalRequestGate<'_, C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServicePrincipalRequestGate")
            .finish_non_exhaustive()
    }
}

impl<'a, C, A, S> ServicePrincipalRequestGate<'a, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    #[must_use]
    pub const fn new(clock: &'a C, authorization: &'a A, store: &'a S) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }

    /// Authenticates one request and returns a single-use authorization evaluator bound to it.
    ///
    /// # Errors
    /// Invalid permission syntax, authentication failure, clock failure, entropy failure, and
    /// mandatory audit failure all fail closed before a runtime operation can be authorized.
    pub fn authenticate_request(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        permission: &str,
        resource_scope: &TenantScope,
    ) -> Result<ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        self.authenticate_request_inner(
            presented_scope,
            credential_id,
            secret,
            permission,
            resource_scope,
            None,
        )
    }

    /// Authenticates one request while binding its audit trail to one canonical operation.
    ///
    /// # Errors
    /// Fails closed for malformed operation metadata plus all ordinary request-admission errors.
    pub fn authenticate_request_for_operation(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        permission: &str,
        resource_scope: &TenantScope,
        operation: &ServiceAuditOperationRef,
    ) -> Result<ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        if operation.operation_kind.len() > MAX_SERVICE_AUDIT_OPERATION_KIND_LEN {
            return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
        }
        validate_service_audit_operation_ref(operation)
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::InvalidArgument))?;
        self.authenticate_request_inner(
            presented_scope,
            credential_id,
            secret,
            permission,
            resource_scope,
            Some(operation),
        )
    }

    fn authenticate_request_inner(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        permission: &str,
        resource_scope: &TenantScope,
        operation: Option<&ServiceAuditOperationRef>,
    ) -> Result<ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        if permission.len() > MAX_SERVICE_REQUEST_PERMISSION_LEN {
            return Err(CanonicalError::new(CanonicalErrorCode::ResourceExhausted));
        }
        validate_namespaced_identifier(permission)
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::InvalidArgument))?;
        let audit_context = ServiceAuditRequestContext {
            credential_id,
            presented_scope,
            permission,
            resource_scope,
            operation,
        };
        let now = self.clock.now_unix_ms().map_err(map_clock_error)?;
        let subject = match authenticate_service_principal(
            self.store,
            presented_scope,
            credential_id,
            secret,
        ) {
            Ok(subject) => subject,
            Err(error) => {
                let outcome = match error {
                    ServiceAuthenticationError::AuthenticationFailed => {
                        ServiceAuditOutcome::AuthenticationFailed
                    }
                    ServiceAuthenticationError::Store(_) => {
                        ServiceAuditOutcome::AuthenticationUnavailable
                    }
                };
                let record = new_audit_record(audit_context, None, outcome, now)?;
                self.store
                    .append_service_audit(&record)
                    .map_err(map_store_error)?;
                return Err(error.into());
            }
        };
        Ok(ServicePrincipalRequestAuthorization {
            clock: self.clock,
            authorization: self.authorization,
            store: self.store,
            proof: ServicePrincipalAdmissionProof {
                subject,
                permission: permission.to_owned(),
                resource_scope: resource_scope.clone(),
            },
            credential_id: credential_id.clone(),
            operation: operation.cloned(),
            used: AtomicBool::new(false),
        })
    }
}

pub struct ServicePrincipalRequestAuthorization<'a, C, A, S> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
    proof: ServicePrincipalAdmissionProof,
    credential_id: ServiceCredentialId,
    operation: Option<ServiceAuditOperationRef>,
    used: AtomicBool,
}

impl<C, A, S> fmt::Debug for ServicePrincipalRequestAuthorization<'_, C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServicePrincipalRequestAuthorization")
            .field("proof", &self.proof)
            .field("credential_id", &self.credential_id)
            .field("has_operation", &self.operation.is_some())
            .field("used", &self.used.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<C, A, S> ServicePrincipalRequestAuthorization<'_, C, A, S> {
    #[must_use]
    pub const fn subject(&self) -> &ScopedPrincipal {
        &self.proof.subject
    }
}

impl<C, A, S> AuthorizationEvaluator for ServicePrincipalRequestAuthorization<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError> {
        let now = self.clock.now_unix_ms().map_err(map_clock_error)?;
        if self.used.swap(true, Ordering::AcqRel) {
            return self.audit_and_return(
                ServiceAuditOutcome::PermissionDenied,
                now,
                Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied)),
            );
        }

        let quota_result = self.store.consume_service_request(&self.proof.subject, now);
        if let Err(error) = quota_result {
            let (outcome, canonical) = map_quota_error(error);
            return self.audit_and_return(outcome, now, Err(canonical));
        }

        if !self.proof.matches(request) {
            return self.audit_and_return(
                ServiceAuditOutcome::PermissionDenied,
                now,
                Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied)),
            );
        }

        match self.authorization.authorize(request) {
            Ok(()) => self.audit_and_return(ServiceAuditOutcome::Authorized, now, Ok(())),
            Err(error) => {
                let outcome = if error.code == CanonicalErrorCode::PermissionDenied {
                    ServiceAuditOutcome::PermissionDenied
                } else {
                    ServiceAuditOutcome::AuthorizationUnavailable
                };
                self.audit_and_return(outcome, now, Err(error))
            }
        }
    }

    fn service_principal_admission_proof(&self) -> Option<&ServicePrincipalAdmissionProof> {
        Some(&self.proof)
    }
}

impl<C, A, S> ServicePrincipalRequestAuthorization<'_, C, A, S>
where
    S: ServiceAuditStore,
{
    fn audit_and_return<T>(
        &self,
        outcome: ServiceAuditOutcome,
        now_unix_ms: i64,
        result: Result<T, CanonicalError>,
    ) -> Result<T, CanonicalError> {
        let context = ServiceAuditRequestContext {
            credential_id: &self.credential_id,
            presented_scope: &self.proof.subject.scope,
            permission: &self.proof.permission,
            resource_scope: &self.proof.resource_scope,
            operation: self.operation.as_ref(),
        };
        let record = new_audit_record(
            context,
            Some(self.proof.subject.clone()),
            outcome,
            now_unix_ms,
        )?;
        self.store
            .append_service_audit(&record)
            .map_err(map_store_error)?;
        result
    }
}

fn new_audit_record(
    context: ServiceAuditRequestContext<'_>,
    subject: Option<ScopedPrincipal>,
    outcome: ServiceAuditOutcome,
    now_unix_ms: i64,
) -> Result<ServiceAuditRecord, CanonicalError> {
    let audit_id = AuditRecordId::from_opaque(generate_opaque_id().map_err(map_id_error)?);
    Ok(ServiceAuditRecord {
        audit_id,
        credential_id: context.credential_id.clone(),
        presented_scope: context.presented_scope.clone(),
        subject,
        permission: context.permission.to_owned(),
        resource_scope: context.resource_scope.clone(),
        outcome,
        occurred_at_unix_ms: now_unix_ms,
        operation: context.operation.cloned(),
    })
}

const fn map_clock_error(_: ServiceQuotaClockError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
}

const fn map_id_error(_: IdGenerationError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Internal)
}

const fn map_store_error(error: DurableStoreError) -> CanonicalError {
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

const fn map_quota_error(error: ServiceQuotaConsumeError) -> (ServiceAuditOutcome, CanonicalError) {
    match error {
        ServiceQuotaConsumeError::NotConfigured => (
            ServiceAuditOutcome::RateLimited,
            CanonicalError::new(CanonicalErrorCode::RateLimited),
        ),
        ServiceQuotaConsumeError::RateLimited { retry_after_ms } => (
            ServiceAuditOutcome::RateLimited,
            CanonicalError::new(CanonicalErrorCode::RateLimited).with_retry_after(retry_after_ms),
        ),
        ServiceQuotaConsumeError::ClockRollback => (
            ServiceAuditOutcome::QuotaUnavailable,
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable),
        ),
        ServiceQuotaConsumeError::Store(error) => (
            ServiceAuditOutcome::QuotaUnavailable,
            map_store_error(error),
        ),
    }
}

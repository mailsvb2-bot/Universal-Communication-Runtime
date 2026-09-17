use core::fmt;

use ucr_model::{
    AuthorizationRequest, DeviceDescriptor, DeviceId, DeviceLifecycleState, IdentityId,
    RecoveryAuthority, RecoveryPlan, RecoveryPlanId, RecoveryRequest, ServiceAuditOperationRef,
    ServiceCredentialId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, RECOVERY_ACTIVATE_PERMISSION,
    RECOVERY_PLAN_INSTALL_PERMISSION, RECOVERY_PLAN_READ_PERMISSION,
    RECOVERY_PLAN_REVOKE_PERMISSION, RECOVERY_PLAN_ROTATE_PERMISSION, RECOVERY_STAGE_PERMISSION,
    RecoveryError, SERVICE_AUDIT_RECOVERY_ACTIVATE_OPERATION_KIND,
    SERVICE_AUDIT_RECOVERY_PLAN_INSTALL_OPERATION_KIND,
    SERVICE_AUDIT_RECOVERY_PLAN_READ_OPERATION_KIND,
    SERVICE_AUDIT_RECOVERY_PLAN_REVOKE_OPERATION_KIND,
    SERVICE_AUDIT_RECOVERY_PLAN_ROTATE_OPERATION_KIND, SERVICE_AUDIT_RECOVERY_STAGE_OPERATION_KIND,
    validate_recovery_request,
};

use crate::{
    AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError,
    DeviceLifecycleStore, DurableStoreError, RecoveryPlanStore, ServiceAuditStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServicePrincipalRequestGate,
    ServiceQuotaClock, ServiceQuotaStore, StorageProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAuthorityVerificationError {
    Denied,
    Unavailable,
}

/// Trusted provider boundary that proves the concrete recovery authority selected by a request.
///
/// The protocol validator only proves that an authority is named by the active plan. This
/// verifier must prove possession/control of that authority. Implementations may use a secure
/// recovery-key provider, trusted-device challenge, hardware-backed attestation, encrypted
/// backup capability, or organization-managed authority without changing canonical recovery
/// semantics.
pub trait RecoveryAuthorityVerifier: fmt::Debug + Send + Sync {
    /// Verifies the concrete authority selected by `request` under the already loaded active plan.
    ///
    /// # Errors
    /// `Denied` means the proof was absent/invalid. `Unavailable` means the trusted verifier could
    /// not establish a result and recovery must fail closed.
    fn verify_authority(
        &self,
        plan: &RecoveryPlan,
        request: &RecoveryRequest,
    ) -> Result<(), RecoveryAuthorityVerificationError>;
}

/// Core-owned proof that one exact recovery request passed active-plan validation and an
/// independent authority verifier. Fields are private so callers cannot fabricate a staging
/// capability and bypass authority verification.
pub struct RecoveryAdmissionProof {
    plan_id: RecoveryPlanId,
    scope: TenantScope,
    identity_id: IdentityId,
    authority: RecoveryAuthority,
    target_device_id: DeviceId,
    recovered_device_state: DeviceLifecycleState,
}

impl fmt::Debug for RecoveryAdmissionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryAdmissionProof")
            .field("plan_id", &self.plan_id)
            .field("scope", &self.scope)
            .field("identity_id", &self.identity_id)
            .field("authority", &"<verified>")
            .field("target_device_id", &self.target_device_id)
            .field("recovered_device_state", &self.recovered_device_state)
            .finish()
    }
}

impl RecoveryAdmissionProof {
    #[must_use]
    pub const fn plan_id(&self) -> &RecoveryPlanId {
        &self.plan_id
    }

    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }

    #[must_use]
    pub const fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    #[must_use]
    pub const fn authority(&self) -> &RecoveryAuthority {
        &self.authority
    }

    #[must_use]
    pub const fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }

    #[must_use]
    pub const fn recovered_device_state(&self) -> DeviceLifecycleState {
        self.recovered_device_state
    }

    #[must_use]
    pub fn recovered_device(&self) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: self.target_device_id.clone(),
            identity_id: self.identity_id.clone(),
            state: self.recovered_device_state,
        }
    }
}

/// Atomic durable staging boundary for a verified recovery admission proof.
///
/// Implementations must re-check that `proof.plan_id()` is still the active recovery plan for
/// `proof.scope()` + `proof.identity_id()` in the same atomic action that stages the Device.
/// This closes the revoke/rotate TOCTOU window between recovery verification and Device creation.
pub trait RecoveryDeviceStagingStore: StorageProvider {
    /// Atomically stages the exact recovered Device described by a Core-owned proof.
    ///
    /// # Errors
    /// Fails if the proof's plan is no longer active, the Device ID is already bound to different
    /// semantics, or durable state cannot be committed safely.
    fn stage_recovered_device(
        &self,
        proof: &RecoveryAdmissionProof,
    ) -> Result<(), DurableStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceReverificationVerificationError {
    Denied,
    Unavailable,
}

/// Trusted boundary that independently proves a staged recovered Device has completed
/// the deployment-specific re-verification required before it may become Active.
///
/// Implementations may bind an interactive challenge, an existing trusted Device,
/// hardware attestation, organization approval, or another reviewed mechanism. The
/// verifier owns that evidence; the canonical Device model does not grow provider data.
pub trait DeviceReverificationVerifier: fmt::Debug + Send + Sync {
    /// Verifies one exact currently staged `REVERIFICATION_REQUIRED` Device.
    ///
    /// # Errors
    /// `Denied` means re-verification evidence is absent/invalid. `Unavailable` means
    /// the trusted verifier cannot establish a result and activation must fail closed.
    fn verify_reverification(
        &self,
        device: &DeviceDescriptor,
    ) -> Result<(), DeviceReverificationVerificationError>;
}

/// Core-owned, non-forgeable capability to perform exactly one lifecycle promotion
/// from `REVERIFICATION_REQUIRED` to `ACTIVE` for the bound Device/Identity.
pub struct DeviceReverificationProof {
    scope: TenantScope,
    device_id: DeviceId,
    identity_id: IdentityId,
}

impl fmt::Debug for DeviceReverificationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceReverificationProof")
            .field("scope", &self.scope)
            .field("device_id", &self.device_id)
            .field("identity_id", &self.identity_id)
            .field("reverification", &"<verified>")
            .finish()
    }
}

impl DeviceReverificationProof {
    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    #[must_use]
    pub const fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }
}

/// Atomic durable owner for the security-sensitive re-verification promotion.
/// Implementations must compare the current durable Device state and Identity in the
/// same atomic action that changes state to Active. A Revoked Device can never be
/// resurrected by a stale proof.
pub trait ReverifiedDeviceActivationStore: StorageProvider {
    /// Atomically promotes the proof-bound Device from re-verification-required to Active.
    ///
    /// # Errors
    /// Returns Conflict when the Device is absent, rebound, already Active, Revoked, or
    /// otherwise no longer exactly `REVERIFICATION_REQUIRED`; storage failures are explicit.
    fn activate_reverified_device(
        &self,
        proof: &DeviceReverificationProof,
    ) -> Result<(), DurableStoreError>;
}

pub struct DeviceReverificationGate<'a, V, S> {
    verifier: &'a V,
    store: &'a S,
}

impl<V, S> fmt::Debug for DeviceReverificationGate<'_, V, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceReverificationGate")
            .finish_non_exhaustive()
    }
}

impl<'a, V, S> DeviceReverificationGate<'a, V, S>
where
    V: DeviceReverificationVerifier,
    S: DeviceLifecycleStore,
{
    #[must_use]
    pub const fn new(verifier: &'a V, store: &'a S) -> Self {
        Self { verifier, store }
    }

    /// Loads the exact durable Device, requires the recovery staging state, then invokes
    /// the independent verifier before minting an unforgeable activation proof.
    ///
    /// # Errors
    /// Missing/mismatched/non-staged Devices and denied proofs are non-disclosing
    /// `PERMISSION_DENIED`; verifier/storage unavailability fails closed.
    pub fn authorize_reverification(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_identity_id: &IdentityId,
    ) -> Result<DeviceReverificationProof, CanonicalError> {
        let Some(device) = self
            .store
            .device(scope, device_id)
            .map_err(map_store_read_error)?
        else {
            return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
        };
        if device.identity_id != *expected_identity_id
            || device.state != DeviceLifecycleState::ReverificationRequired
        {
            return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
        }
        self.verifier
            .verify_reverification(&device)
            .map_err(map_reverification_verifier_error)?;
        Ok(DeviceReverificationProof {
            scope: scope.clone(),
            device_id: device.device_id,
            identity_id: device.identity_id,
        })
    }
}

/// Verifies and atomically activates one recovered Device. Re-verification authority is
/// intentionally separate from ordinary `PermissionGrant` administration.
///
/// # Errors
/// Returns fail-closed canonical errors from durable lookup, independent verification,
/// or the atomic lifecycle promotion.
pub fn authorize_and_activate_reverified_device<V, S>(
    verifier: &V,
    store: &S,
    scope: &TenantScope,
    device_id: &DeviceId,
    expected_identity_id: &IdentityId,
) -> Result<DeviceDescriptor, CanonicalError>
where
    V: DeviceReverificationVerifier,
    S: DeviceLifecycleStore + ReverifiedDeviceActivationStore,
{
    let proof = DeviceReverificationGate::new(verifier, store).authorize_reverification(
        scope,
        device_id,
        expected_identity_id,
    )?;
    store
        .activate_reverified_device(&proof)
        .map_err(map_stage_error)?;
    Ok(DeviceDescriptor {
        device_id: proof.device_id.clone(),
        identity_id: proof.identity_id.clone(),
        state: DeviceLifecycleState::Active,
    })
}

/// Service-Principal ingress for Recovery Plan administration only.
///
/// Recovery execution uses a separate Service Principal channel-admission boundary, but ordinary
/// permissions never establish recovery authority. The active Recovery Plan plus independent
/// recovery/re-verification verifiers remain the only security authority for Device recovery.
pub struct RecoveryPlanIngress<'a, C, A, S> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
}

impl<C, A, S> fmt::Debug for RecoveryPlanIngress<'_, C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPlanIngress")
            .finish_non_exhaustive()
    }
}

impl<'a, C, A, S> RecoveryPlanIngress<'a, C, A, S> {
    #[must_use]
    pub const fn new(clock: &'a C, authorization: &'a A, store: &'a S) -> Self {
        Self {
            clock,
            authorization,
            store,
        }
    }
}

#[derive(Clone, Copy)]
struct RecoveryPlanAdmission<'a> {
    permission: &'a str,
    resource_scope: &'a TenantScope,
    operation_kind: &'a str,
    operation_id: &'a ucr_model::OpaqueId,
}

impl<C, A, S> RecoveryPlanIngress<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: RecoveryPlanStore + ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    /// Installs one canonical Recovery Plan after ordinary Service Principal administration
    /// admission. This permission never substitutes for recovery authority proof.
    ///
    /// # Errors
    /// Fails closed for authentication, quota, permission, malformed plan, conflict, or storage failure.
    pub fn install_plan(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        plan: &RecoveryPlan,
    ) -> Result<(), CanonicalError> {
        let request = self.admit(
            presented_scope,
            credential_id,
            secret,
            RecoveryPlanAdmission {
                permission: RECOVERY_PLAN_INSTALL_PERMISSION,
                resource_scope: &plan.scope,
                operation_kind: SERVICE_AUDIT_RECOVERY_PLAN_INSTALL_OPERATION_KIND,
                operation_id: plan.plan_id.as_opaque(),
            },
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .install_recovery_plan(&subject, plan)
            .map_err(map_authorized_plan_error)
    }

    /// Rotates the active Recovery Plan using the canonical expected-current compare-and-swap.
    ///
    /// # Errors
    /// Fails closed for authentication, quota, permission, stale expected plan, malformed replacement, or storage failure.
    pub fn rotate_plan(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        expected_current: &RecoveryPlanId,
        replacement: &RecoveryPlan,
    ) -> Result<(), CanonicalError> {
        let request = self.admit(
            presented_scope,
            credential_id,
            secret,
            RecoveryPlanAdmission {
                permission: RECOVERY_PLAN_ROTATE_PERMISSION,
                resource_scope: &replacement.scope,
                operation_kind: SERVICE_AUDIT_RECOVERY_PLAN_ROTATE_OPERATION_KIND,
                operation_id: replacement.plan_id.as_opaque(),
            },
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .rotate_recovery_plan(&subject, expected_current, replacement)
            .map_err(map_authorized_plan_error)
    }

    /// Revokes the active Recovery Plan using the canonical expected-current identifier.
    ///
    /// # Errors
    /// Fails closed for authentication, quota, permission, stale expected plan, scope mismatch, or storage failure.
    pub fn revoke_plan(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        identity_id: &IdentityId,
        expected_current: &RecoveryPlanId,
    ) -> Result<(), CanonicalError> {
        let request = self.admit(
            presented_scope,
            credential_id,
            secret,
            RecoveryPlanAdmission {
                permission: RECOVERY_PLAN_REVOKE_PERMISSION,
                resource_scope: scope,
                operation_kind: SERVICE_AUDIT_RECOVERY_PLAN_REVOKE_OPERATION_KIND,
                operation_id: expected_current.as_opaque(),
            },
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .revoke_recovery_plan(&subject, scope, identity_id, expected_current)
            .map_err(map_authorized_plan_error)
    }

    /// Reads the active Recovery Plan only after ordinary plan-read permission admission.
    ///
    /// # Errors
    /// Fails closed for authentication, quota, permission, absence, corruption, or storage failure.
    pub fn active_plan(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<RecoveryPlan, CanonicalError> {
        let request = self.admit(
            presented_scope,
            credential_id,
            secret,
            RecoveryPlanAdmission {
                permission: RECOVERY_PLAN_READ_PERMISSION,
                resource_scope: scope,
                operation_kind: SERVICE_AUDIT_RECOVERY_PLAN_READ_OPERATION_KIND,
                operation_id: identity_id.as_opaque(),
            },
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .active_recovery_plan(&subject, scope, identity_id)
            .map_err(map_authorized_plan_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
    }

    fn admit<'a>(
        &'a self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        admission: RecoveryPlanAdmission<'_>,
    ) -> Result<crate::ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: admission.operation_kind.to_owned(),
            operation_id: admission.operation_id.clone(),
        };
        ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                admission.permission,
                admission.resource_scope,
                &operation,
            )
    }
}

/// Public-channel admission for recovery execution without turning ordinary permissions into
/// recovery authority. Service Principal permissions only allow an application to invoke these
/// sensitive RPCs; the canonical Recovery Plan and independent verifiers make the security
/// decision that stages or activates a Device.
pub struct RecoveryExecutionIngress<'a, C, A, S, RV, DV> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
    recovery_verifier: &'a RV,
    reverification_verifier: &'a DV,
}

impl<C, A, S, RV, DV> fmt::Debug for RecoveryExecutionIngress<'_, C, A, S, RV, DV> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryExecutionIngress")
            .finish_non_exhaustive()
    }
}

impl<'a, C, A, S, RV, DV> RecoveryExecutionIngress<'a, C, A, S, RV, DV> {
    #[must_use]
    pub const fn new(
        clock: &'a C,
        authorization: &'a A,
        store: &'a S,
        recovery_verifier: &'a RV,
        reverification_verifier: &'a DV,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            recovery_verifier,
            reverification_verifier,
        }
    }
}

impl<C, A, S, RV, DV> RecoveryExecutionIngress<'_, C, A, S, RV, DV>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: RecoveryPlanStore
        + ServiceCredentialStore
        + ServiceQuotaStore
        + ServiceAuditStore
        + RecoveryDeviceStagingStore
        + DeviceLifecycleStore
        + ReverifiedDeviceActivationStore,
    RV: RecoveryAuthorityVerifier,
    DV: DeviceReverificationVerifier,
{
    /// Admits the public application channel, then independently verifies Recovery authority and
    /// atomically stages the recovered Device as `REVERIFICATION_REQUIRED`.
    ///
    /// # Errors
    /// Fails closed for authentication, quota, channel permission, recovery authority,
    /// active-plan mismatch, semantic conflict, or durable storage failure.
    pub fn stage_recovered_device(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        recovery: &RecoveryRequest,
    ) -> Result<DeviceDescriptor, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_RECOVERY_STAGE_OPERATION_KIND.to_owned(),
            operation_id: recovery.target_device_id.as_opaque().clone(),
        };
        let admission =
            ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
                .authenticate_request_for_operation(
                    presented_scope,
                    credential_id,
                    secret,
                    RECOVERY_STAGE_PERMISSION,
                    &recovery.scope,
                    &operation,
                )?;
        admission.authorize(&AuthorizationRequest {
            subject: admission.subject().clone(),
            permission: RECOVERY_STAGE_PERMISSION.to_owned(),
            resource_scope: recovery.scope.clone(),
        })?;
        authorize_and_stage_recovered_device(self.recovery_verifier, self.store, recovery)
    }

    /// Admits the public application channel, then independently re-verifies and atomically
    /// activates one exact staged recovered Device.
    ///
    /// # Errors
    /// Fails closed for authentication, quota, channel permission, absent/mismatched staged Device,
    /// failed independent re-verification, concurrent lifecycle change, or storage failure.
    pub fn activate_recovered_device(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        device_id: &DeviceId,
        identity_id: &IdentityId,
    ) -> Result<DeviceDescriptor, CanonicalError> {
        let operation = ServiceAuditOperationRef {
            operation_kind: SERVICE_AUDIT_RECOVERY_ACTIVATE_OPERATION_KIND.to_owned(),
            operation_id: device_id.as_opaque().clone(),
        };
        let admission =
            ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store)
                .authenticate_request_for_operation(
                    presented_scope,
                    credential_id,
                    secret,
                    RECOVERY_ACTIVATE_PERMISSION,
                    scope,
                    &operation,
                )?;
        admission.authorize(&AuthorizationRequest {
            subject: admission.subject().clone(),
            permission: RECOVERY_ACTIVATE_PERMISSION.to_owned(),
            resource_scope: scope.clone(),
        })?;
        authorize_and_activate_reverified_device(
            self.reverification_verifier,
            self.store,
            scope,
            device_id,
            identity_id,
        )
    }
}

pub struct RecoveryRequestGate<'a, V, S> {
    verifier: &'a V,
    store: &'a S,
}

impl<V, S> fmt::Debug for RecoveryRequestGate<'_, V, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRequestGate")
            .finish_non_exhaustive()
    }
}

impl<'a, V, S> RecoveryRequestGate<'a, V, S>
where
    V: RecoveryAuthorityVerifier,
    S: RecoveryPlanStore,
{
    #[must_use]
    pub const fn new(verifier: &'a V, store: &'a S) -> Self {
        Self { verifier, store }
    }

    /// Resolves the active plan, validates exact request binding, and invokes the independent
    /// recovery-authority verifier before producing an unforgeable staging proof.
    ///
    /// # Errors
    /// Missing/mismatched plans and denied authority proofs are intentionally non-disclosing
    /// `PERMISSION_DENIED`; verifier/storage unavailability fails closed.
    pub fn authorize_recovery(
        &self,
        request: &RecoveryRequest,
    ) -> Result<RecoveryAdmissionProof, CanonicalError> {
        let Some(plan) = self
            .store
            .active_recovery_plan(&request.scope, &request.identity_id)
            .map_err(map_store_read_error)?
        else {
            return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
        };
        validate_recovery_request(&plan, request).map_err(map_request_error)?;
        self.verifier
            .verify_authority(&plan, request)
            .map_err(map_verifier_error)?;
        Ok(RecoveryAdmissionProof {
            plan_id: plan.plan_id,
            scope: plan.scope,
            identity_id: plan.identity_id,
            authority: request.authority.clone(),
            target_device_id: request.target_device_id.clone(),
            recovered_device_state: plan.recovered_device_state,
        })
    }
}

/// Verifies and stages a recovered Device through the only proof-aware durable staging boundary.
///
/// # Errors
/// Returns fail-closed canonical errors from active-plan lookup, authority verification, or the
/// atomic durable staging action.
pub fn authorize_and_stage_recovered_device<V, S>(
    verifier: &V,
    store: &S,
    request: &RecoveryRequest,
) -> Result<DeviceDescriptor, CanonicalError>
where
    V: RecoveryAuthorityVerifier,
    S: RecoveryPlanStore + RecoveryDeviceStagingStore,
{
    let proof = RecoveryRequestGate::new(verifier, store).authorize_recovery(request)?;
    let descriptor = proof.recovered_device();
    store
        .stage_recovered_device(&proof)
        .map_err(map_stage_error)?;
    Ok(descriptor)
}

const fn map_authorized_plan_error(error: AuthorizedMutationError) -> CanonicalError {
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

const fn map_request_error(error: RecoveryError) -> CanonicalError {
    match error {
        RecoveryError::MethodNotAllowed
        | RecoveryError::PlanMismatch
        | RecoveryError::ScopeMismatch
        | RecoveryError::IdentityMismatch => {
            CanonicalError::new(CanonicalErrorCode::PermissionDenied)
        }
        RecoveryError::EncodingTooLarge
        | RecoveryError::TooManyAuthorities
        | RecoveryError::NoAuthorities
        | RecoveryError::DuplicateAuthority
        | RecoveryError::UnsafeRecoveredDeviceState
        | RecoveryError::HistoricalAccessNotExplicit
        | RecoveryError::TrustModelAuthorityMismatch => {
            CanonicalError::new(CanonicalErrorCode::Internal)
        }
    }
}

const fn map_verifier_error(error: RecoveryAuthorityVerificationError) -> CanonicalError {
    match error {
        RecoveryAuthorityVerificationError::Denied => {
            CanonicalError::new(CanonicalErrorCode::PermissionDenied)
        }
        RecoveryAuthorityVerificationError::Unavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
    }
}

const fn map_reverification_verifier_error(
    error: DeviceReverificationVerificationError,
) -> CanonicalError {
    match error {
        DeviceReverificationVerificationError::Denied => {
            CanonicalError::new(CanonicalErrorCode::PermissionDenied)
        }
        DeviceReverificationVerificationError::Unavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
    }
}

const fn map_store_read_error(error: DurableStoreError) -> CanonicalError {
    match error {
        DurableStoreError::Unavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
        DurableStoreError::PermissionDenied => {
            CanonicalError::new(CanonicalErrorCode::PermissionDenied)
        }
        DurableStoreError::Full
        | DurableStoreError::InvalidRecord
        | DurableStoreError::Conflict
        | DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalError::new(CanonicalErrorCode::Internal),
    }
}

const fn map_stage_error(error: DurableStoreError) -> CanonicalError {
    match error {
        DurableStoreError::Conflict => CanonicalError::new(CanonicalErrorCode::Conflict),
        DurableStoreError::PermissionDenied => {
            CanonicalError::new(CanonicalErrorCode::PermissionDenied)
        }
        DurableStoreError::Full => CanonicalError::new(CanonicalErrorCode::ResourceExhausted),
        DurableStoreError::Unavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
        DurableStoreError::InvalidRecord
        | DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalError::new(CanonicalErrorCode::Internal),
    }
}

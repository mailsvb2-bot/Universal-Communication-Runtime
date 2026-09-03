use core::fmt;

use ucr_model::{
    DeviceDescriptor, DeviceId, DeviceLifecycleState, IdentityId, RecoveryAuthority, RecoveryPlan,
    RecoveryPlanId, RecoveryRequest, TenantScope,
};
use ucr_protocol::{CanonicalError, CanonicalErrorCode, RecoveryError, validate_recovery_request};

use crate::{DurableStoreError, RecoveryPlanStore, StorageProvider};

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

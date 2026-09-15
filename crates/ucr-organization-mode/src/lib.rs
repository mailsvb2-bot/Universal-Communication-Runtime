#![forbid(unsafe_code)]

use ucr_core::{
    AuthorizationEvaluator, BridgeRegistrationStore, DeviceLifecycleStore, DurableRecordStatus,
    DurableStoreError, IdentityStore, OrganizationModeStore, StoreForwardStore,
};
use ucr_model::{
    AuthorizationRequest, BridgeRegistration, BridgeRegistrationState, DeliveryPolicy, DeviceId,
    IdentityId, IdentityOwnership, IdentityRecord, IntegrationId, OrganizationManagedDeviceBinding,
    OrganizationManagedIdentityBinding, OrganizationModeProfile, OrganizationModeState,
    OrganizationService, PrincipalRef, ScopedPrincipal, StoreForwardId, StoreForwardJob,
    TenantScope,
};
use ucr_protocol::{
    BRIDGE_REGISTRATION_READ_PERMISSION, DEVICE_READ_PERMISSION, IDENTITY_READ_PERMISSION,
    ORGANIZATION_BRIDGE_USE_PERMISSION, ORGANIZATION_DEVICE_MANAGE_PERMISSION,
    ORGANIZATION_DISCOVERY_READ_PERMISSION, ORGANIZATION_IDENTITY_MANAGE_PERMISSION,
    ORGANIZATION_MANAGE_PERMISSION, ORGANIZATION_READ_PERMISSION,
    ORGANIZATION_RELAY_USE_PERMISSION, ORGANIZATION_SFU_USE_PERMISSION,
    device_allows_protected_access,
};

pub const ORGANIZATION_MODE_RUNTIME_CAPABILITY: &str = "ucr.organization_mode";

#[derive(Debug)]
pub enum OrganizationModeError {
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    MissingProfile,
    ModeDisabled,
    ServiceDisabled,
    MissingIdentity,
    IdentityNotOrganizationManaged,
    MissingIdentityBinding,
    MissingDevice,
    DeviceNotEligible,
    DeviceIdentityNotManaged,
    MissingStoreForwardJob,
    RelayPolicyDenied,
    MissingBridgeRegistration,
    BridgeInactive,
}
impl From<DurableStoreError> for OrganizationModeError {
    fn from(value: DurableStoreError) -> Self {
        Self::Store(value)
    }
}

pub trait OrganizationModeRuntimeStore:
    OrganizationModeStore
    + IdentityStore
    + DeviceLifecycleStore
    + StoreForwardStore
    + BridgeRegistrationStore
{
}
impl<T> OrganizationModeRuntimeStore for T where
    T: OrganizationModeStore
        + IdentityStore
        + DeviceLifecycleStore
        + StoreForwardStore
        + BridgeRegistrationStore
{
}

#[derive(Debug)]
pub struct OrganizationModeRuntime<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> OrganizationModeRuntime<'a, A, S> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }
}
impl<A, S> OrganizationModeRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: OrganizationModeRuntimeStore,
{
    /// Organization Mode operation `install_profile`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn install_profile(
        &self,
        actor: &ScopedPrincipal,
        profile: &OrganizationModeProfile,
    ) -> Result<DurableRecordStatus, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            &profile.scope,
            ORGANIZATION_MANAGE_PERMISSION,
        )?;
        self.store
            .install_organization_mode_profile(profile)
            .map_err(Into::into)
    }

    /// Organization Mode operation `profile`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn profile(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
    ) -> Result<Option<OrganizationModeProfile>, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_READ_PERMISSION,
        )?;
        self.store
            .organization_mode_profile(scope, organization)
            .map_err(Into::into)
    }

    /// Organization Mode operation `transition_profile`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn transition_profile(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        expected_generation: u64,
        next_state: OrganizationModeState,
    ) -> Result<DurableRecordStatus, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_MANAGE_PERMISSION,
        )?;
        self.store
            .transition_organization_mode_profile(
                scope,
                organization,
                expected_generation,
                next_state,
            )
            .map_err(Into::into)
    }
    /// Organization Mode operation `bind_managed_identity`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn bind_managed_identity(
        &self,
        actor: &ScopedPrincipal,
        binding: &OrganizationManagedIdentityBinding,
    ) -> Result<DurableRecordStatus, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            &binding.scope,
            ORGANIZATION_IDENTITY_MANAGE_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            &binding.scope,
            IDENTITY_READ_PERMISSION,
        )?;
        self.require_active_service(
            &binding.scope,
            &binding.organization,
            OrganizationService::ManagedIdentities,
        )?;
        let identity = self
            .store
            .identity(&binding.scope, &binding.identity_id)?
            .ok_or(OrganizationModeError::MissingIdentity)?;
        if identity.ownership != IdentityOwnership::OrganizationManaged {
            return Err(OrganizationModeError::IdentityNotOrganizationManaged);
        }
        self.store
            .bind_organization_managed_identity(binding)
            .map_err(Into::into)
    }

    /// Organization Mode operation `unbind_managed_identity`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn unbind_managed_identity(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        identity_id: &IdentityId,
    ) -> Result<DurableRecordStatus, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_IDENTITY_MANAGE_PERMISSION,
        )?;
        self.require_active_service(scope, organization, OrganizationService::ManagedIdentities)?;
        let existing = self
            .store
            .organization_managed_identity_binding(scope, identity_id)?
            .ok_or(OrganizationModeError::MissingIdentityBinding)?;
        if existing.organization != *organization {
            return Err(OrganizationModeError::MissingIdentityBinding);
        }
        self.store
            .unbind_organization_managed_identity(scope, identity_id)
            .map_err(Into::into)
    }
    /// Organization Mode operation `private_directory`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn private_directory(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<IdentityRecord>, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_DISCOVERY_READ_PERMISSION,
        )?;
        authorize(self.authorization, actor, scope, IDENTITY_READ_PERMISSION)?;
        self.require_active_service(scope, organization, OrganizationService::PrivateDiscovery)?;
        self.require_active_service(scope, organization, OrganizationService::ManagedIdentities)?;
        let bindings =
            self.store
                .organization_managed_identities(scope, organization, max_items)?;
        let mut identities = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let identity = self
                .store
                .identity(scope, &binding.identity_id)?
                .ok_or(OrganizationModeError::MissingIdentity)?;
            if identity.ownership != IdentityOwnership::OrganizationManaged {
                return Err(OrganizationModeError::IdentityNotOrganizationManaged);
            }
            identities.push(identity);
        }
        Ok(identities)
    }

    /// Organization Mode operation `bind_managed_device`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn bind_managed_device(
        &self,
        actor: &ScopedPrincipal,
        binding: &OrganizationManagedDeviceBinding,
    ) -> Result<DurableRecordStatus, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            &binding.scope,
            ORGANIZATION_DEVICE_MANAGE_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            &binding.scope,
            DEVICE_READ_PERMISSION,
        )?;
        self.require_active_service(
            &binding.scope,
            &binding.organization,
            OrganizationService::ManagedDevices,
        )?;
        let device = self
            .store
            .device(&binding.scope, &binding.device_id)?
            .ok_or(OrganizationModeError::MissingDevice)?;
        if !device_allows_protected_access(&device) {
            return Err(OrganizationModeError::DeviceNotEligible);
        }
        let identity_binding = self
            .store
            .organization_managed_identity_binding(&binding.scope, &device.identity_id)?
            .ok_or(OrganizationModeError::DeviceIdentityNotManaged)?;
        if identity_binding.organization != binding.organization {
            return Err(OrganizationModeError::DeviceIdentityNotManaged);
        }
        self.store
            .bind_organization_managed_device(binding)
            .map_err(Into::into)
    }

    /// Organization Mode operation `unbind_managed_device`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn unbind_managed_device(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        device_id: &DeviceId,
    ) -> Result<DurableRecordStatus, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_DEVICE_MANAGE_PERMISSION,
        )?;
        self.require_active_service(scope, organization, OrganizationService::ManagedDevices)?;
        let existing = self
            .store
            .organization_managed_device_binding(scope, device_id)?
            .ok_or(OrganizationModeError::MissingDevice)?;
        if existing.organization != *organization {
            return Err(OrganizationModeError::MissingDevice);
        }
        self.store
            .unbind_organization_managed_device(scope, device_id)
            .map_err(Into::into)
    }

    /// Organization Mode operation `managed_devices`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn managed_devices(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<ucr_model::DeviceDescriptor>, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_DISCOVERY_READ_PERMISSION,
        )?;
        authorize(self.authorization, actor, scope, DEVICE_READ_PERMISSION)?;
        self.require_active_service(scope, organization, OrganizationService::ManagedDevices)?;
        let bindings = self
            .store
            .organization_managed_devices(scope, organization, max_items)?;
        let mut devices = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let device = self
                .store
                .device(scope, &binding.device_id)?
                .ok_or(OrganizationModeError::MissingDevice)?;
            if !device_allows_protected_access(&device) {
                return Err(OrganizationModeError::DeviceNotEligible);
            }
            devices.push(device);
        }
        Ok(devices)
    }
    /// Organization Mode operation `admit_relay`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn admit_relay(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        store_forward_id: &StoreForwardId,
    ) -> Result<StoreForwardJob, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_RELAY_USE_PERMISSION,
        )?;
        self.require_active_service(scope, organization, OrganizationService::PrivateRelay)?;
        let job = self
            .store
            .store_forward_job(scope, store_forward_id)?
            .ok_or(OrganizationModeError::MissingStoreForwardJob)?;
        let message = self
            .store
            .message(scope, &job.message_id)?
            .ok_or(OrganizationModeError::MissingStoreForwardJob)?;
        if !relay_policy_allowed(message.delivery_policy) {
            return Err(OrganizationModeError::RelayPolicyDenied);
        }
        Ok(job)
    }
    /// Organization Mode operation `admit_sfu`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn admit_sfu(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
    ) -> Result<OrganizationModeProfile, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_SFU_USE_PERMISSION,
        )?;
        self.require_active_service(scope, organization, OrganizationService::PrivateSfu)
    }

    /// Organization Mode operation `admit_bridge`.
    ///
    /// # Errors
    /// Returns explicit authorization, canonical-owner validation, lifecycle, policy, or durable-store failures.
    pub fn admit_bridge(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        organization: &PrincipalRef,
        integration_id: &IntegrationId,
    ) -> Result<BridgeRegistration, OrganizationModeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            ORGANIZATION_BRIDGE_USE_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            scope,
            BRIDGE_REGISTRATION_READ_PERMISSION,
        )?;
        self.require_active_service(scope, organization, OrganizationService::PrivateBridge)?;
        let registration = self
            .store
            .bridge_registration(scope, integration_id)?
            .ok_or(OrganizationModeError::MissingBridgeRegistration)?;
        if registration.state != BridgeRegistrationState::Active {
            return Err(OrganizationModeError::BridgeInactive);
        }
        Ok(registration)
    }

    fn require_active_service(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        service: OrganizationService,
    ) -> Result<OrganizationModeProfile, OrganizationModeError> {
        let profile = self
            .store
            .organization_mode_profile(scope, organization)?
            .ok_or(OrganizationModeError::MissingProfile)?;
        if profile.state != OrganizationModeState::Active {
            return Err(OrganizationModeError::ModeDisabled);
        }
        if !profile.services.contains(&service) {
            return Err(OrganizationModeError::ServiceDisabled);
        }
        Ok(profile)
    }
}

fn authorize<A: AuthorizationEvaluator>(
    authorization: &A,
    actor: &ScopedPrincipal,
    scope: &TenantScope,
    permission: &str,
) -> Result<(), OrganizationModeError> {
    authorization
        .authorize(&AuthorizationRequest {
            subject: actor.clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        })
        .map_err(OrganizationModeError::Authorization)
}

fn relay_policy_allowed(policy: DeliveryPolicy) -> bool {
    matches!(
        policy,
        DeliveryPolicy::BestEffort
            | DeliveryPolicy::Durable
            | DeliveryPolicy::Urgent
            | DeliveryPolicy::Expiring
            | DeliveryPolicy::NoExternalBridge
    )
}

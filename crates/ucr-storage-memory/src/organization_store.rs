use ucr_core::{DurableRecordStatus, DurableStoreError, OrganizationModeStore};
use ucr_model::{
    DeviceId, IdentityId, OrganizationManagedDeviceBinding, OrganizationManagedIdentityBinding,
    OrganizationModeProfile, OrganizationModeState, PrincipalRef, TenantScope,
};
use ucr_protocol::{
    MAX_ORGANIZATION_DIRECTORY_ITEMS, canonical_organization_mode_profile,
    validate_organization_managed_device_binding, validate_organization_managed_identity_binding,
    validate_organization_mode_transition,
};

use super::{
    MemoryLocalStore, OrganizationDeviceKey, OrganizationIdentityKey, OrganizationProfileKey,
    scope_key,
};

impl OrganizationModeStore for MemoryLocalStore {
    fn install_organization_mode_profile(
        &self,
        profile: &OrganizationModeProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_organization_mode_profile(profile)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if canonical.state != OrganizationModeState::Active || canonical.generation != 1 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let key = profile_key(&canonical.scope, &canonical.organization);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        match state.organization_profiles.get(&key) {
            Some(existing) if existing == &canonical => Ok(DurableRecordStatus::Duplicate),
            Some(_) => Err(DurableStoreError::Conflict),
            None => {
                state.organization_profiles.insert(key, canonical);
                Ok(DurableRecordStatus::Persisted)
            }
        }
    }
    fn organization_mode_profile(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
    ) -> Result<Option<OrganizationModeProfile>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .organization_profiles
            .get(&profile_key(scope, organization))
            .cloned())
    }

    fn transition_organization_mode_profile(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        expected_generation: u64,
        next_state: OrganizationModeState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = profile_key(scope, organization);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let profile = state
            .organization_profiles
            .get_mut(&key)
            .ok_or(DurableStoreError::Conflict)?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if profile.generation == next_generation && profile.state == next_state {
            return Ok(DurableRecordStatus::Duplicate);
        }
        if profile.generation != expected_generation {
            return Err(DurableStoreError::Conflict);
        }
        validate_organization_mode_transition(profile.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        profile.state = next_state;
        profile.generation = next_generation;
        Ok(DurableRecordStatus::Persisted)
    }

    fn bind_organization_managed_identity(
        &self,
        binding: &OrganizationManagedIdentityBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_organization_managed_identity_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = identity_key(&binding.scope, &binding.identity_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let profile = state
            .organization_profiles
            .get(&profile_key(&binding.scope, &binding.organization))
            .ok_or(DurableStoreError::PermissionDenied)?;
        if profile.state != OrganizationModeState::Active
            || !profile
                .services
                .contains(&ucr_model::OrganizationService::ManagedIdentities)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        match state.organization_identities.get(&key) {
            Some(existing) if existing == binding => Ok(DurableRecordStatus::Duplicate),
            Some(_) => Err(DurableStoreError::Conflict),
            None => {
                state.organization_identities.insert(key, binding.clone());
                Ok(DurableRecordStatus::Persisted)
            }
        }
    }
    fn organization_managed_identity_binding(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<OrganizationManagedIdentityBinding>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .organization_identities
            .get(&identity_key(scope, identity_id))
            .cloned())
    }

    fn organization_managed_identities(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<OrganizationManagedIdentityBinding>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_ORGANIZATION_DIRECTORY_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let mut items = state
            .organization_identities
            .values()
            .filter(|binding| binding.scope == *scope && binding.organization == *organization)
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.identity_id
                .as_opaque()
                .cmp(right.identity_id.as_opaque())
        });
        items.truncate(max_items);
        Ok(items)
    }
    fn unbind_organization_managed_identity(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        state
            .organization_identities
            .remove(&identity_key(scope, identity_id))
            .map(|_| DurableRecordStatus::Persisted)
            .ok_or(DurableStoreError::Conflict)
    }

    fn bind_organization_managed_device(
        &self,
        binding: &OrganizationManagedDeviceBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_organization_managed_device_binding(binding)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let key = device_key(&binding.scope, &binding.device_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let profile = state
            .organization_profiles
            .get(&profile_key(&binding.scope, &binding.organization))
            .ok_or(DurableStoreError::PermissionDenied)?;
        if profile.state != OrganizationModeState::Active
            || !profile
                .services
                .contains(&ucr_model::OrganizationService::ManagedDevices)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        match state.organization_devices.get(&key) {
            Some(existing) if existing == binding => Ok(DurableRecordStatus::Duplicate),
            Some(_) => Err(DurableStoreError::Conflict),
            None => {
                state.organization_devices.insert(key, binding.clone());
                Ok(DurableRecordStatus::Persisted)
            }
        }
    }
    fn organization_managed_device_binding(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<OrganizationManagedDeviceBinding>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .organization_devices
            .get(&device_key(scope, device_id))
            .cloned())
    }

    fn organization_managed_devices(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<OrganizationManagedDeviceBinding>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_ORGANIZATION_DIRECTORY_ITEMS {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let mut items = state
            .organization_devices
            .values()
            .filter(|binding| binding.scope == *scope && binding.organization == *organization)
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.device_id.as_opaque().cmp(right.device_id.as_opaque()));
        items.truncate(max_items);
        Ok(items)
    }
    fn unbind_organization_managed_device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        state
            .organization_devices
            .remove(&device_key(scope, device_id))
            .map(|_| DurableRecordStatus::Persisted)
            .ok_or(DurableStoreError::Conflict)
    }
}

fn profile_key(scope: &TenantScope, organization: &PrincipalRef) -> OrganizationProfileKey {
    (scope_key(scope), organization.clone())
}

fn identity_key(scope: &TenantScope, identity_id: &IdentityId) -> OrganizationIdentityKey {
    (
        scope_key(scope),
        identity_id.as_opaque().as_str().to_owned(),
    )
}

fn device_key(scope: &TenantScope, device_id: &DeviceId) -> OrganizationDeviceKey {
    (scope_key(scope), device_id.as_opaque().as_str().to_owned())
}

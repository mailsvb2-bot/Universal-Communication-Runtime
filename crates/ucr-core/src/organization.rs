use ucr_model::{
    DeviceId, IdentityId, OrganizationManagedDeviceBinding, OrganizationManagedIdentityBinding,
    OrganizationModeProfile, OrganizationModeState, PrincipalRef, TenantScope,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

/// Durable owner for Organization Mode policy associations only.
///
/// This store never owns canonical Identity, Device, Message, Delivery, Bridge, relay or SFU state.
pub trait OrganizationModeStore: StorageProvider {
    /// Organization Mode durable operation `install_organization_mode_profile`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn install_organization_mode_profile(
        &self,
        profile: &OrganizationModeProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Organization Mode durable operation `organization_mode_profile`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn organization_mode_profile(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
    ) -> Result<Option<OrganizationModeProfile>, DurableStoreError>;
    /// Organization Mode durable operation `transition_organization_mode_profile`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn transition_organization_mode_profile(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        expected_generation: u64,
        next_state: OrganizationModeState,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Organization Mode durable operation `bind_organization_managed_identity`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn bind_organization_managed_identity(
        &self,
        binding: &OrganizationManagedIdentityBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Organization Mode durable operation `organization_managed_identity_binding`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn organization_managed_identity_binding(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<OrganizationManagedIdentityBinding>, DurableStoreError>;

    /// Organization Mode durable operation `organization_managed_identities`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn organization_managed_identities(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<OrganizationManagedIdentityBinding>, DurableStoreError>;
    /// Organization Mode durable operation `unbind_organization_managed_identity`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn unbind_organization_managed_identity(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Organization Mode durable operation `bind_organization_managed_device`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn bind_organization_managed_device(
        &self,
        binding: &OrganizationManagedDeviceBinding,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Organization Mode durable operation `organization_managed_device_binding`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn organization_managed_device_binding(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<OrganizationManagedDeviceBinding>, DurableStoreError>;

    /// Organization Mode durable operation `organization_managed_devices`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn organization_managed_devices(
        &self,
        scope: &TenantScope,
        organization: &PrincipalRef,
        max_items: usize,
    ) -> Result<Vec<OrganizationManagedDeviceBinding>, DurableStoreError>;
    /// Organization Mode durable operation `unbind_organization_managed_device`.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, corruption, permission, bound, or storage failures.
    fn unbind_organization_managed_device(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<DurableRecordStatus, DurableStoreError>;
}

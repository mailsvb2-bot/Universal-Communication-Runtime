use crate::{DeviceId, EndpointId, EndpointKind, IdentityId, PrincipalRef, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrganizationService {
    PrivateDiscovery,
    PrivateRelay,
    PrivateSfu,
    PrivateBridge,
    ManagedIdentities,
    ManagedDevices,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationModeState {
    Active,
    Disabled,
}

/// Prepared Organization Mode policy for one exact tenant/namespace boundary.
/// Canonical Identity, Device, Bridge, SFU, relay, Message and Delivery state stay with their owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationModeProfile {
    pub scope: TenantScope,
    pub organization: PrincipalRef,
    pub endpoint_id: EndpointId,
    pub endpoint_kind: EndpointKind,
    pub services: Vec<OrganizationService>,
    pub state: OrganizationModeState,
    pub generation: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationManagedIdentityBinding {
    pub scope: TenantScope,
    pub organization: PrincipalRef,
    pub identity_id: IdentityId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationManagedDeviceBinding {
    pub scope: TenantScope,
    pub organization: PrincipalRef,
    pub device_id: DeviceId,
}

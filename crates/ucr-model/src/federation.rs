use crate::{DeviceId, EndpointId, EndpointKind, KeyId, TenantScope};

/// Durable local policy state for one explicitly configured independent UCR peer.
///
/// `Authenticated` records that the configured credential has been proven at least once, but it is
/// never sufficient by itself for a new operation: every admission must re-check the live
/// `EstablishedSession` and current trusted signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FederationTrustState {
    Known = 1,
    Authenticated = 2,
    Authorized = 3,
    Trusted = 4,
    Revoked = 5,
    Blocked = 6,
}

/// Exact local policy binding between one local node endpoint and one remote independent UCR node.
///
/// A remote scope is data, not authority. The remote node cannot choose or mutate this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPeerRecord {
    pub local_scope: TenantScope,
    pub remote_scope: TenantScope,
    pub local_endpoint_id: EndpointId,
    pub remote_endpoint_id: EndpointId,
    pub remote_endpoint_kind: EndpointKind,
    pub expected_device_id: DeviceId,
    pub expected_signing_key_id: KeyId,
    pub allowed_capabilities: Vec<String>,
    pub state: FederationTrustState,
    pub generation: u64,
}

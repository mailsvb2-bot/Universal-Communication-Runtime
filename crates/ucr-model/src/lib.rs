#![forbid(unsafe_code)]

use core::fmt;

/// Opaque canonical identifier value.
///
/// The concrete offline generation algorithm is intentionally not selected in
/// Phase 0; callers must not infer provider, network, tenant or business
/// semantics from this value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueIdError {
    Empty,
    TooLong,
}

impl OpaqueId {
    pub const MAX_LEN: usize = 128;

    /// Creates an opaque ID after applying only representation-safety checks.
    ///
    /// # Errors
    /// Returns [`OpaqueIdError::Empty`] for an empty value and
    /// [`OpaqueIdError::TooLong`] when the representation exceeds the Phase-0
    /// protocol budget.
    pub fn new(value: impl Into<String>) -> Result<Self, OpaqueIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(OpaqueIdError::Empty);
        }
        if value.len() > Self::MAX_LEN {
            return Err(OpaqueIdError::TooLong);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueId")
            .field(&"<opaque>")
            .finish()
    }
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(OpaqueId);

        impl $name {
            /// Wraps a canonical opaque identifier.
            #[must_use]
            pub const fn from_opaque(value: OpaqueId) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_opaque(&self) -> &OpaqueId {
                &self.0
            }
        }
    };
}

id_type!(TenantId);
id_type!(NamespaceId);
id_type!(PrincipalId);
id_type!(ActorId);
id_type!(PersonId);
id_type!(PersonaId);
id_type!(DeviceId);
id_type!(IdentityId);
id_type!(EndpointId);
id_type!(ConversationId);
id_type!(GroupId);
id_type!(CommunityId);
id_type!(MessageId);
id_type!(AttachmentId);
id_type!(CallId);
id_type!(SessionId);
id_type!(DeliveryId);
id_type!(IntegrationId);
id_type!(CommandId);
id_type!(EventId);
id_type!(IntentId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    Person,
    Device,
    ServiceAccount,
    AiAgent,
    Bot,
    Organization,
    Automation,
    ExternalPlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    Person,
    AiAgent,
    Bot,
    Organization,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
    Direct,
    PrivateGroup,
    PublicGroup,
    Broadcast,
    Community,
    Room,
    Topic,
    Thread,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryPolicy {
    BestEffort,
    Durable,
    Urgent,
    Expiring,
    LocalOnly,
    DirectOnly,
    NoRelay,
    NoExternalBridge,
    PrivateNetworkOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    Created,
    Persisted,
    Encrypted,
    Queued,
    RoutePlanned,
    InFlight,
    Acknowledged,
    Delivered,
    Read,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityEvidence {
    Unverified,
    SelfAsserted,
    DeviceVerified,
    ContactVerified,
    OrganizationVerified,
    ExternalProviderVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLifecycleState {
    Active,
    Stale,
    ReverificationRequired,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDescriptor {
    pub device_id: DeviceId,
    pub identity_id: IdentityId,
    pub state: DeviceLifecycleState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityMaturity {
    Experimental,
    Prepared,
    Beta,
    Production,
    Deprecated,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    Standard,
    Private,
    Strict,
    LocalOnly,
    OrganizationManaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    pub tenant_id: TenantId,
    pub namespace_id: Option<NamespaceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRef {
    pub principal_id: PrincipalId,
    pub kind: PrincipalKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorRef {
    pub actor_id: ActorId,
    pub kind: ActorKind,
    pub on_behalf_of: Option<PrincipalId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRef {
    pub device_id: DeviceId,
    pub identity_id: IdentityId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginRef {
    pub principal_id: Option<PrincipalId>,
    pub endpoint_id: Option<EndpointId>,
    pub integration_id: Option<IntegrationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentConstraints {
    pub allowed_transport_capabilities: Vec<String>,
    pub forbidden_transport_capabilities: Vec<String>,
    pub privacy_profile: SecurityProfile,
    pub region_constraint: Option<String>,
    pub max_cost_microunits: Option<u64>,
    pub priority_class: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunicationIntent {
    pub intent_id: IntentId,
    pub scope: TenantScope,
    pub target_identity_id: IdentityId,
    pub payload: Vec<u8>,
    pub constraints: IntentConstraints,
}

#[cfg(test)]
mod tests {
    use super::{OpaqueId, OpaqueIdError};

    #[test]
    fn opaque_id_rejects_empty_values() {
        assert_eq!(OpaqueId::new(""), Err(OpaqueIdError::Empty));
    }

    #[test]
    fn opaque_id_debug_does_not_disclose_value() {
        let id = OpaqueId::new("provider-or-secret-looking-value").expect("valid id");
        let debug = format!("{id:?}");
        assert!(!debug.contains(id.as_str()));
    }
}

/// Canonical capability descriptor shared by Core, Protocol, and SDK boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    pub id: String,
    pub maturity: CapabilityMaturity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Device,
    ExternalAccount,
    WebSession,
    PersonalNode,
    OrganizationNode,
    TemporaryPeer,
}

/// Address material belongs to an Endpoint and is never canonical Identity.
#[derive(Clone, PartialEq, Eq)]
pub struct EndpointAddress {
    pub scheme: String,
    pub value: Vec<u8>,
}

impl fmt::Debug for EndpointAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointAddress")
            .field("scheme", &self.scheme)
            .field("value", &"<opaque>")
            .field("value_len", &self.value.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDescriptor {
    pub endpoint_id: EndpointId,
    pub kind: EndpointKind,
    pub identity_id: Option<IdentityId>,
    pub device_id: Option<DeviceId>,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub addresses: Vec<EndpointAddress>,
}

/// Mapping owned by UCR between an external entity and canonical Identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalIdentityBinding {
    pub scope: TenantScope,
    pub integration_id: IntegrationId,
    pub external_namespace: String,
    pub external_entity_id: Vec<u8>,
    pub identity_id: IdentityId,
}

impl fmt::Debug for ExternalIdentityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalIdentityBinding")
            .field("scope", &self.scope)
            .field("integration_id", &self.integration_id)
            .field("external_namespace", &self.external_namespace)
            .field("external_entity_id", &"<opaque>")
            .field("external_entity_id_len", &self.external_entity_id.len())
            .field("identity_id", &self.identity_id)
            .finish()
    }
}

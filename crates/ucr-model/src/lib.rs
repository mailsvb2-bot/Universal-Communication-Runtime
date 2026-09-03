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
id_type!(KeyId);
id_type!(RecoveryPlanId);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryEvidenceKind {
    CreatedLocal,
    PersistedLocal,
    AcceptedByTransport,
    ReplicatedToRelay,
    ReceivedByDevice,
    DecryptedByDevice,
    PresentedToUser,
    ReadByUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryAttempt {
    pub delivery_id: DeliveryId,
    pub scope: TenantScope,
    pub message_id: MessageId,
    pub state: DeliveryState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryEvidence {
    pub delivery_id: DeliveryId,
    pub scope: TenantScope,
    pub message_id: MessageId,
    pub kind: DeliveryEvidenceKind,
    pub logical_order: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncLinkKind {
    DeviceDevice,
    DeviceNode,
    PeerPeer,
    DeviceCloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Full,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Prepared,
    Active,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSelection {
    pub mode: SyncMode,
    pub conversation_ids: Vec<ConversationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSession {
    pub session_id: SessionId,
    pub scope: TenantScope,
    pub source_endpoint_id: EndpointId,
    pub target_endpoint_id: EndpointId,
    pub link_kind: SyncLinkKind,
    pub selection: SyncSelection,
    pub state: SyncState,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SyncCheckpoint {
    pub session_id: SessionId,
    pub scope: TenantScope,
    pub generation: u64,
    pub resume_token: Vec<u8>,
    pub applied_items: u64,
}

impl fmt::Debug for SyncCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncCheckpoint")
            .field("session_id", &self.session_id)
            .field("scope", &self.scope)
            .field("generation", &self.generation)
            .field("resume_token", &"<opaque>")
            .field("resume_token_len", &self.resume_token.len())
            .field("applied_items", &self.applied_items)
            .finish()
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecoveryMethod {
    RecoveryCode = 1,
    RecoveryKey = 2,
    TrustedDevice = 3,
    HardwareBacked = 4,
    EncryptedBackup = 5,
    OrganizationManaged = 6,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveryAuthority {
    RecoveryCode,
    RecoveryKey,
    TrustedDevice(DeviceId),
    HardwareBacked(DeviceId),
    EncryptedBackup,
    OrganizationManaged(PrincipalId),
}

impl RecoveryAuthority {
    #[must_use]
    pub const fn method(&self) -> RecoveryMethod {
        match self {
            Self::RecoveryCode => RecoveryMethod::RecoveryCode,
            Self::RecoveryKey => RecoveryMethod::RecoveryKey,
            Self::TrustedDevice(_) => RecoveryMethod::TrustedDevice,
            Self::HardwareBacked(_) => RecoveryMethod::HardwareBacked,
            Self::EncryptedBackup => RecoveryMethod::EncryptedBackup,
            Self::OrganizationManaged(_) => RecoveryMethod::OrganizationManaged,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalMessageAccess {
    None,
    ExplicitEncryptedRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTrustModel {
    UserControlled,
    OrganizationManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum RecoveryPackageAlgorithm {
    UcrV1 = 1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedRecoveryPackage {
    pub algorithm: RecoveryPackageAlgorithm,
    pub format_version: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedRecoveryPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedRecoveryPackage")
            .field("algorithm", &self.algorithm)
            .field("format_version", &self.format_version)
            .field("nonce", &"<nonce>")
            .field("ciphertext", &"<encrypted>")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub plan_id: RecoveryPlanId,
    pub scope: TenantScope,
    pub identity_id: IdentityId,
    pub authorities: Vec<RecoveryAuthority>,
    pub historical_message_access: HistoricalMessageAccess,
    pub trust_model: RecoveryTrustModel,
    pub recovered_device_state: DeviceLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub plan_id: RecoveryPlanId,
    pub scope: TenantScope,
    pub identity_id: IdentityId,
    pub authority: RecoveryAuthority,
    pub target_device_id: DeviceId,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CryptoSuite {
    UcrV1 = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    Signing,
    KeyAgreement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyDescriptor {
    pub key_id: KeyId,
    pub device_id: DeviceId,
    pub purpose: KeyPurpose,
    pub algorithm_id: String,
    pub algorithm_version: u32,
    pub key_format_version: u32,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeNonce([u8; 32]);

impl HandshakeNonce {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn is_all_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Debug for HandshakeNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HandshakeNonce")
            .field(&"<nonce>")
            .finish()
    }
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

/// A principal bound to an explicit tenant/namespace security scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPrincipal {
    pub scope: TenantScope,
    pub principal: PrincipalRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionScope {
    Exact(TenantScope),
    TenantWide(TenantId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrant {
    pub grantee: ScopedPrincipal,
    pub permission: String,
    pub scope: PermissionScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub subject: ScopedPrincipal,
    pub permission: String,
    pub resource_scope: TenantScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationContext {
    pub correlation_id: OpaqueId,
    pub causation_id: Option<OpaqueId>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommandEnvelope {
    pub command_id: CommandId,
    pub scope: TenantScope,
    pub command_type: String,
    pub payload: Vec<u8>,
    pub correlation: CorrelationContext,
    pub schema_version: ProtocolVersion,
    pub extensions: Vec<ProtocolExtension>,
}

impl fmt::Debug for CommandEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandEnvelope")
            .field("command_id", &self.command_id)
            .field("scope", &self.scope)
            .field("command_type", &self.command_type)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .field("correlation", &"<redacted>")
            .field(
                "has_idempotency_key",
                &self.correlation.idempotency_key.is_some(),
            )
            .field("schema_version", &self.schema_version)
            .field("extensions", &self.extensions)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProtocolExtension {
    pub name: String,
    pub critical: bool,
    pub payload: Vec<u8>,
}

impl fmt::Debug for ProtocolExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolExtension")
            .field("name", &self.name)
            .field("critical", &self.critical)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub scope: TenantScope,
    pub event_type: String,
    pub payload: Vec<u8>,
    pub actor: ActorRef,
    pub source_device: DeviceRef,
    pub wall_time_unix_ms: i64,
    pub logical_order: u64,
    pub correlation: CorrelationContext,
    pub schema_version: ProtocolVersion,
    pub integrity_metadata: Vec<u8>,
    pub extensions: Vec<ProtocolExtension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum EventFingerprintAlgorithm {
    Sha256V1 = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFingerprint {
    pub algorithm: EventFingerprintAlgorithm,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSummary {
    pub event_id: EventId,
    pub fingerprint: EventFingerprint,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AntiEntropyCursor {
    pub token: Vec<u8>,
}

impl fmt::Debug for AntiEntropyCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AntiEntropyCursor")
            .field("token", &"<opaque>")
            .field("token_len", &self.token.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiEntropyPage {
    pub session_id: SessionId,
    pub scope: TenantScope,
    pub summaries: Vec<EventSummary>,
    pub next_cursor: Option<AntiEntropyCursor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventReplicaState {
    Missing,
    Matching,
    Damaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReconciliation {
    pub event_id: EventId,
    pub state: EventReplicaState,
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
pub struct ConversationRef {
    pub conversation_id: ConversationId,
    pub kind: ConversationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationRecord {
    pub scope: TenantScope,
    pub conversation: ConversationRef,
    pub parent_conversation_id: Option<ConversationId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRelationKind {
    Reply,
    Quote,
    Edit,
    Reaction,
    ThreadParent,
    Forward,
    Reference,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRelation {
    pub kind: MessageRelationKind,
    pub target_message_id: MessageId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalMessageMapping {
    pub integration_id: IntegrationId,
    pub external_message_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageCryptoMetadata {
    pub suite: CryptoSuite,
    pub key_id: Option<KeyId>,
    pub opaque_metadata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSignature {
    pub key_id: KeyId,
    pub algorithm_id: String,
    pub algorithm_version: u32,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub message_id: MessageId,
    pub scope: TenantScope,
    pub conversation: ConversationRef,
    pub author: ActorRef,
    pub author_device: DeviceRef,
    pub created_at_unix_ms: i64,
    pub logical_order: u64,
    pub content: Vec<u8>,
    pub attachment_ids: Vec<AttachmentId>,
    pub reply_to: Option<MessageId>,
    pub relations: Vec<MessageRelation>,
    pub crypto_metadata: Option<MessageCryptoMetadata>,
    pub delivery_policy: DeliveryPolicy,
    pub delivery_state: DeliveryState,
    pub origin: OriginRef,
    pub correlation: CorrelationContext,
    pub external_mappings: Vec<ExternalMessageMapping>,
    pub signature: Option<MessageSignature>,
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

    #[test]
    fn command_debug_redacts_nested_extension_payload() {
        let command = super::CommandEnvelope {
            command_id: super::CommandId::from_opaque(
                super::OpaqueId::new("command-redaction").expect("command id"),
            ),
            scope: super::TenantScope {
                tenant_id: super::TenantId::from_opaque(
                    super::OpaqueId::new("tenant-redaction").expect("tenant id"),
                ),
                namespace_id: None,
            },
            command_type: "ucr.test.command".to_owned(),
            payload: b"ordinary-command-payload".to_vec(),
            correlation: super::CorrelationContext {
                correlation_id: super::OpaqueId::new("correlation-redaction")
                    .expect("correlation id"),
                causation_id: None,
                idempotency_key: Some("redaction-retry".to_owned()),
            },
            schema_version: super::ProtocolVersion::new(1, 0),
            extensions: vec![super::ProtocolExtension {
                name: "ucr.test.secret".to_owned(),
                critical: false,
                payload: b"command-extension-secret".to_vec(),
            }],
        };
        let debug = format!("{command:?}");
        assert!(!debug.contains("command-extension-secret"));
        assert!(!debug.contains("ordinary-command-payload"));
        assert!(!debug.contains("redaction-retry"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("payload_len"));
    }

    #[test]
    fn protocol_extension_and_anti_entropy_cursor_debug_redact_payloads() {
        let extension = super::ProtocolExtension {
            name: "ucr.test.secret".to_owned(),
            critical: false,
            payload: b"extension-secret".to_vec(),
        };
        let cursor = super::AntiEntropyCursor {
            token: b"cursor-secret".to_vec(),
        };
        let extension_debug = format!("{extension:?}");
        let cursor_debug = format!("{cursor:?}");
        assert!(!extension_debug.contains("extension-secret"));
        assert!(!cursor_debug.contains("cursor-secret"));
        assert!(extension_debug.contains("<redacted>"));
        assert!(cursor_debug.contains("<opaque>"));
    }
}

/// Canonical capability descriptor shared by Core, Protocol, and SDK boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDescriptor {
    pub id: String,
    pub maturity: CapabilityMaturity,
    pub extensions: Vec<ProtocolExtension>,
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

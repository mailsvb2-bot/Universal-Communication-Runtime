#![forbid(unsafe_code)]

use core::fmt;

/// Opaque canonical identifier value.
///
/// Native offline generation is specified by UCR Protocol ADR-0023; this model
/// remains the representation/validation owner. Callers must not infer provider,
/// network, tenant, business, authority, or chronology semantics from this value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueIdError {
    Empty,
    InvalidUtf8,
    TooLong,
}

impl OpaqueId {
    pub const MAX_LEN: usize = 128;

    /// Creates an opaque ID from its canonical UTF-8 token representation.
    ///
    /// The representation is byte-preserving: no Unicode normalization,
    /// case-folding, trimming, or provider-specific interpretation is applied.
    ///
    /// # Errors
    /// Returns [`OpaqueIdError::Empty`] for an empty value and
    /// [`OpaqueIdError::TooLong`] when its UTF-8 encoding exceeds the canonical
    /// 128-byte protocol budget.
    pub fn new(value: impl Into<String>) -> Result<Self, OpaqueIdError> {
        let value = value.into();
        validate_opaque_id_bytes(value.as_bytes())?;
        Ok(Self(value))
    }

    /// Semantically decodes the public `ucr.v1.OpaqueId.value` byte field.
    ///
    /// # Errors
    /// Returns [`OpaqueIdError::Empty`] for an empty value,
    /// [`OpaqueIdError::InvalidUtf8`] for a non-UTF-8 byte sequence, and
    /// [`OpaqueIdError::TooLong`] when the exact wire representation exceeds
    /// the canonical 128-byte budget.
    pub fn from_wire_bytes(value: &[u8]) -> Result<Self, OpaqueIdError> {
        validate_opaque_id_bytes(value)?;
        let value = core::str::from_utf8(value).map_err(|_| OpaqueIdError::InvalidUtf8)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the exact canonical bytes carried by public `OpaqueId.value`.
    #[must_use]
    pub fn as_wire_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn validate_opaque_id_bytes(value: &[u8]) -> Result<(), OpaqueIdError> {
    if value.is_empty() {
        return Err(OpaqueIdError::Empty);
    }
    if value.len() > OpaqueId::MAX_LEN {
        return Err(OpaqueIdError::TooLong);
    }
    core::str::from_utf8(value).map_err(|_| OpaqueIdError::InvalidUtf8)?;
    Ok(())
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

#[derive(Clone, PartialEq, Eq)]
pub struct CorrelationContext {
    pub correlation_id: OpaqueId,
    pub causation_id: Option<OpaqueId>,
    pub idempotency_key: Option<String>,
}

impl fmt::Debug for CorrelationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorrelationContext")
            .field("correlation_id", &self.correlation_id)
            .field("causation_id", &self.causation_id)
            .field("idempotency_key", &"<redacted>")
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .finish()
    }
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

#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for EventEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventEnvelope")
            .field("event_id", &self.event_id)
            .field("scope", &self.scope)
            .field("event_type", &self.event_type)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .field("actor", &self.actor)
            .field("source_device", &self.source_device)
            .field("wall_time_unix_ms", &self.wall_time_unix_ms)
            .field("logical_order", &self.logical_order)
            .field("correlation", &self.correlation)
            .field("schema_version", &self.schema_version)
            .field("integrity_metadata", &"<opaque>")
            .field("integrity_metadata_len", &self.integrity_metadata.len())
            .field("extensions", &self.extensions)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum EventFingerprintAlgorithm {
    Sha256V1 = 1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EventFingerprint {
    pub algorithm: EventFingerprintAlgorithm,
    pub digest: [u8; 32],
}

impl fmt::Debug for EventFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventFingerprint")
            .field("algorithm", &self.algorithm)
            .field("digest", &"<opaque>")
            .field("digest_len", &self.digest.len())
            .finish()
    }
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

#[derive(Clone, PartialEq, Eq)]
pub struct ExternalMessageMapping {
    pub integration_id: IntegrationId,
    pub external_message_id: Vec<u8>,
}

impl fmt::Debug for ExternalMessageMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalMessageMapping")
            .field("integration_id", &self.integration_id)
            .field("external_message_id", &"<opaque>")
            .field("external_message_id_len", &self.external_message_id.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MessageCryptoMetadata {
    pub suite: CryptoSuite,
    pub key_id: Option<KeyId>,
    pub opaque_metadata: Vec<u8>,
}

impl fmt::Debug for MessageCryptoMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageCryptoMetadata")
            .field("suite", &self.suite)
            .field("key_id", &self.key_id)
            .field("opaque_metadata", &"<opaque>")
            .field("opaque_metadata_len", &self.opaque_metadata.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MessageSignature {
    pub key_id: KeyId,
    pub algorithm_id: String,
    pub algorithm_version: u32,
    pub signature: Vec<u8>,
}

impl fmt::Debug for MessageSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageSignature")
            .field("key_id", &self.key_id)
            .field("algorithm_id", &self.algorithm_id)
            .field("algorithm_version", &self.algorithm_version)
            .field("signature", &"<opaque>")
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
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
    pub extensions: Vec<ProtocolExtension>,
    pub external_mappings: Vec<ExternalMessageMapping>,
    pub signature: Option<MessageSignature>,
}

impl fmt::Debug for MessageEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageEnvelope")
            .field("message_id", &self.message_id)
            .field("scope", &self.scope)
            .field("conversation", &self.conversation)
            .field("author", &self.author)
            .field("author_device", &self.author_device)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("logical_order", &self.logical_order)
            .field("content", &"<redacted>")
            .field("content_len", &self.content.len())
            .field("attachment_ids", &self.attachment_ids)
            .field("reply_to", &self.reply_to)
            .field("relations", &self.relations)
            .field("crypto_metadata", &self.crypto_metadata)
            .field("delivery_policy", &self.delivery_policy)
            .field("delivery_state", &self.delivery_state)
            .field("origin", &self.origin)
            .field("correlation", &self.correlation)
            .field("extensions", &self.extensions)
            .field("external_mappings", &self.external_mappings)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IntentConstraints {
    pub allowed_transport_capabilities: Vec<String>,
    pub forbidden_transport_capabilities: Vec<String>,
    pub privacy_profile: Option<String>,
    pub region_constraint: Option<String>,
    pub max_cost_microunits: Option<u64>,
    pub priority_class: Option<u32>,
}

impl fmt::Debug for IntentConstraints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntentConstraints")
            .field(
                "allowed_transport_capability_count",
                &self.allowed_transport_capabilities.len(),
            )
            .field(
                "forbidden_transport_capability_count",
                &self.forbidden_transport_capabilities.len(),
            )
            .field("privacy_profile", &"<redacted>")
            .field("has_privacy_profile", &self.privacy_profile.is_some())
            .field("region_constraint", &"<redacted>")
            .field("has_region_constraint", &self.region_constraint.is_some())
            .field("has_max_cost", &self.max_cost_microunits.is_some())
            .field("has_priority_class", &self.priority_class.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommunicationIntent {
    pub intent_id: IntentId,
    pub scope: TenantScope,
    pub target_identity_id: IdentityId,
    pub payload: Vec<u8>,
    pub constraints: IntentConstraints,
    pub correlation: CorrelationContext,
    pub extensions: Vec<ProtocolExtension>,
}

impl fmt::Debug for CommunicationIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommunicationIntent")
            .field("intent_id", &self.intent_id)
            .field("scope", &self.scope)
            .field("target_identity_id", &self.target_identity_id)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .field("constraints", &self.constraints)
            .field("correlation", &self.correlation)
            .field("extensions", &self.extensions)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{OpaqueId, OpaqueIdError};

    #[test]
    fn opaque_id_rejects_empty_values() {
        assert_eq!(OpaqueId::new(""), Err(OpaqueIdError::Empty));
    }

    #[test]
    fn opaque_id_wire_bytes_have_explicit_utf8_and_byte_budget_semantics() {
        let exact = "идентификатор-é".as_bytes();
        let decoded = OpaqueId::from_wire_bytes(exact).expect("decode wire ID");
        assert_eq!(decoded.as_wire_bytes(), exact);
        assert_eq!(decoded.as_str().as_bytes(), exact);
        assert_eq!(
            OpaqueId::from_wire_bytes(&[0xff, 0xfe]),
            Err(OpaqueIdError::InvalidUtf8)
        );
        assert_eq!(
            OpaqueId::from_wire_bytes(&[b'a'; OpaqueId::MAX_LEN + 1]),
            Err(OpaqueIdError::TooLong)
        );
        assert!(OpaqueId::new("é".repeat(64)).is_ok());
        assert_eq!(OpaqueId::new("é".repeat(65)), Err(OpaqueIdError::TooLong));
    }

    #[test]
    fn opaque_id_does_not_normalize_distinct_utf8_tokens() {
        let composed = OpaqueId::from_wire_bytes("é".as_bytes()).expect("composed ID");
        let decomposed_text = format!("e{}", '\u{301}');
        let decomposed =
            OpaqueId::from_wire_bytes(decomposed_text.as_bytes()).expect("decomposed ID");
        assert_ne!(composed, decomposed);
        assert_ne!(composed.as_wire_bytes(), decomposed.as_wire_bytes());
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

    #[test]
    fn correlation_and_event_debug_do_not_disclose_sensitive_material() {
        let correlation = super::CorrelationContext {
            correlation_id: super::OpaqueId::new("correlation-sensitive-marker")
                .expect("correlation id"),
            causation_id: Some(
                super::OpaqueId::new("causation-sensitive-marker").expect("causation id"),
            ),
            idempotency_key: Some("idempotency-sensitive-marker".to_owned()),
        };
        let event = super::EventEnvelope {
            event_id: super::EventId::from_opaque(
                super::OpaqueId::new("event-sensitive-marker").expect("event id"),
            ),
            scope: super::TenantScope {
                tenant_id: super::TenantId::from_opaque(
                    super::OpaqueId::new("tenant-sensitive-marker").expect("tenant id"),
                ),
                namespace_id: None,
            },
            event_type: "ucr.test.event".to_owned(),
            payload: b"event-plaintext-sensitive-marker".to_vec(),
            actor: super::ActorRef {
                actor_id: super::ActorId::from_opaque(
                    super::OpaqueId::new("actor-sensitive-marker").expect("actor id"),
                ),
                kind: super::ActorKind::System,
                on_behalf_of: None,
            },
            source_device: super::DeviceRef {
                device_id: super::DeviceId::from_opaque(
                    super::OpaqueId::new("device-sensitive-marker").expect("device id"),
                ),
                identity_id: super::IdentityId::from_opaque(
                    super::OpaqueId::new("identity-sensitive-marker").expect("identity id"),
                ),
            },
            wall_time_unix_ms: 1,
            logical_order: 2,
            correlation: correlation.clone(),
            schema_version: super::ProtocolVersion::new(1, 0),
            integrity_metadata: b"integrity-sensitive-marker".to_vec(),
            extensions: vec![super::ProtocolExtension {
                name: "ucr.test.extension".to_owned(),
                critical: false,
                payload: b"event-extension-sensitive-marker".to_vec(),
            }],
        };
        let fingerprint = super::EventFingerprint {
            algorithm: super::EventFingerprintAlgorithm::Sha256V1,
            digest: [0xaa; 32],
        };
        let correlation_debug = format!("{correlation:?}");
        let event_debug = format!("{event:?}");
        let fingerprint_debug = format!("{fingerprint:?}");
        for secret in [
            "correlation-sensitive-marker",
            "causation-sensitive-marker",
            "idempotency-sensitive-marker",
        ] {
            assert!(!correlation_debug.contains(secret));
            assert!(!event_debug.contains(secret));
        }
        for secret in [
            "event-plaintext-sensitive-marker",
            "integrity-sensitive-marker",
            "event-extension-sensitive-marker",
        ] {
            assert!(!event_debug.contains(secret));
        }
        assert!(!fingerprint_debug.contains("170, 170"));
        assert!(event_debug.contains("payload_len"));
        assert!(event_debug.contains("integrity_metadata_len"));
        assert!(fingerprint_debug.contains("<opaque>"));
    }

    fn sensitive_message_parts() -> (
        super::ExternalMessageMapping,
        super::MessageCryptoMetadata,
        super::MessageSignature,
    ) {
        let external_mapping = super::ExternalMessageMapping {
            integration_id: super::IntegrationId::from_opaque(
                super::OpaqueId::new("integration-sensitive-marker").expect("integration id"),
            ),
            external_message_id: b"external-message-sensitive-marker".to_vec(),
        };
        let crypto_metadata = super::MessageCryptoMetadata {
            suite: super::CryptoSuite::UcrV1,
            key_id: Some(super::KeyId::from_opaque(
                super::OpaqueId::new("key-sensitive-marker").expect("key id"),
            )),
            opaque_metadata: b"crypto-metadata-sensitive-marker".to_vec(),
        };
        let signature = super::MessageSignature {
            key_id: super::KeyId::from_opaque(
                super::OpaqueId::new("signature-key-sensitive-marker").expect("key id"),
            ),
            algorithm_id: "ucr.signature.test".to_owned(),
            algorithm_version: 1,
            signature: b"signature-sensitive-marker".to_vec(),
        };
        (external_mapping, crypto_metadata, signature)
    }

    fn sensitive_message() -> super::MessageEnvelope {
        let (external_mapping, crypto_metadata, signature) = sensitive_message_parts();
        super::MessageEnvelope {
            message_id: super::MessageId::from_opaque(
                super::OpaqueId::new("message-sensitive-marker").expect("message id"),
            ),
            scope: super::TenantScope {
                tenant_id: super::TenantId::from_opaque(
                    super::OpaqueId::new("message-tenant-sensitive-marker").expect("tenant id"),
                ),
                namespace_id: None,
            },
            conversation: super::ConversationRef {
                conversation_id: super::ConversationId::from_opaque(
                    super::OpaqueId::new("conversation-sensitive-marker").expect("conversation id"),
                ),
                kind: super::ConversationKind::Direct,
            },
            author: super::ActorRef {
                actor_id: super::ActorId::from_opaque(
                    super::OpaqueId::new("message-actor-sensitive-marker").expect("actor id"),
                ),
                kind: super::ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: super::DeviceRef {
                device_id: super::DeviceId::from_opaque(
                    super::OpaqueId::new("message-device-sensitive-marker").expect("device id"),
                ),
                identity_id: super::IdentityId::from_opaque(
                    super::OpaqueId::new("message-identity-sensitive-marker").expect("identity id"),
                ),
            },
            created_at_unix_ms: 1,
            logical_order: 1,
            content: b"message-plaintext-sensitive-marker".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: Some(crypto_metadata),
            delivery_policy: super::DeliveryPolicy::Durable,
            delivery_state: super::DeliveryState::Persisted,
            origin: super::OriginRef {
                principal_id: None,
                endpoint_id: None,
                integration_id: None,
            },
            correlation: super::CorrelationContext {
                correlation_id: super::OpaqueId::new("message-correlation-sensitive-marker")
                    .expect("correlation id"),
                causation_id: None,
                idempotency_key: Some("message-idempotency-sensitive-marker".to_owned()),
            },
            extensions: vec![super::ProtocolExtension {
                name: "ucr.test.message-extension".to_owned(),
                critical: false,
                payload: b"message-extension-sensitive-marker".to_vec(),
            }],
            external_mappings: vec![external_mapping],
            signature: Some(signature),
        }
    }

    #[test]
    fn message_nested_debug_does_not_disclose_sensitive_material() {
        let (external_mapping, crypto_metadata, signature) = sensitive_message_parts();
        let mapping_debug = format!("{external_mapping:?}");
        let metadata_debug = format!("{crypto_metadata:?}");
        let signature_debug = format!("{signature:?}");
        assert!(!mapping_debug.contains("external-message-sensitive-marker"));
        assert!(!metadata_debug.contains("crypto-metadata-sensitive-marker"));
        assert!(!signature_debug.contains("signature-sensitive-marker"));
        assert!(mapping_debug.contains("external_message_id_len"));
        assert!(metadata_debug.contains("opaque_metadata_len"));
        assert!(signature_debug.contains("signature_len"));
    }

    #[test]
    fn message_envelope_debug_does_not_disclose_sensitive_material() {
        let debug = format!("{:?}", sensitive_message());
        for secret in [
            "message-plaintext-sensitive-marker",
            "message-idempotency-sensitive-marker",
            "message-extension-sensitive-marker",
            "external-message-sensitive-marker",
            "crypto-metadata-sensitive-marker",
            "signature-sensitive-marker",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("content_len"));
    }

    #[test]
    fn communication_intent_and_constraints_debug_redact_private_policy_and_payload() {
        let constraints = super::IntentConstraints {
            allowed_transport_capabilities: vec![
                "ucr.transport.allowed-sensitive-marker".to_owned(),
            ],
            forbidden_transport_capabilities: vec![
                "ucr.transport.forbidden-sensitive-marker".to_owned(),
            ],
            privacy_profile: Some("privacy-sensitive-marker".to_owned()),
            region_constraint: Some("region-sensitive-marker".to_owned()),
            max_cost_microunits: Some(987_654_321),
            priority_class: Some(777),
        };
        let intent = super::CommunicationIntent {
            intent_id: super::IntentId::from_opaque(
                super::OpaqueId::new("intent-sensitive-marker").expect("intent id"),
            ),
            scope: super::TenantScope {
                tenant_id: super::TenantId::from_opaque(
                    super::OpaqueId::new("intent-tenant-sensitive-marker").expect("tenant id"),
                ),
                namespace_id: None,
            },
            target_identity_id: super::IdentityId::from_opaque(
                super::OpaqueId::new("target-sensitive-marker").expect("identity id"),
            ),
            payload: b"intent-plaintext-sensitive-marker".to_vec(),
            constraints: constraints.clone(),
            correlation: super::CorrelationContext {
                correlation_id: super::OpaqueId::new("intent-correlation-sensitive-marker")
                    .expect("correlation id"),
                causation_id: None,
                idempotency_key: Some("intent-idempotency-sensitive-marker".to_owned()),
            },
            extensions: vec![super::ProtocolExtension {
                name: "ucr.test.intent-extension".to_owned(),
                critical: false,
                payload: b"intent-extension-sensitive-marker".to_vec(),
            }],
        };
        let constraints_debug = format!("{constraints:?}");
        let intent_debug = format!("{intent:?}");
        for secret in [
            "ucr.transport.allowed-sensitive-marker",
            "ucr.transport.forbidden-sensitive-marker",
            "privacy-sensitive-marker",
            "region-sensitive-marker",
            "987654321",
            "777",
        ] {
            assert!(!constraints_debug.contains(secret));
            assert!(!intent_debug.contains(secret));
        }
        for secret in [
            "intent-plaintext-sensitive-marker",
            "intent-idempotency-sensitive-marker",
            "intent-extension-sensitive-marker",
        ] {
            assert!(!intent_debug.contains(secret));
        }
        assert!(intent_debug.contains("payload_len"));
        assert!(constraints_debug.contains("allowed_transport_capability_count"));
        assert!(constraints_debug.contains("has_privacy_profile"));
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

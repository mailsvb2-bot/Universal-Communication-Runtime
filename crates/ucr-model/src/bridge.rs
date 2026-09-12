use core::fmt;

use crate::{
    AttachmentId, BridgeActionId, CorrelationContext, IntegrationId, MessageId, ProtocolExtension,
    ProtocolVersion, TenantScope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BridgeCapability {
    Text = 1,
    Edit = 2,
    Delete = 3,
    Reaction = 4,
    Files = 5,
    Audio = 6,
    Video = 7,
    Group = 8,
    Presence = 9,
    Typing = 10,
    Calls = 11,
    Threads = 12,
    Reply = 13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BridgeDataPermission {
    MessageContent = 1,
    AttachmentReferences = 2,
    ExternalIdentityReferences = 3,
    InboundEvents = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeRegistrationState {
    Active,
    Disabled,
    Revoked,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeProviderManifest {
    pub provider_id: String,
    pub sdk_min: ProtocolVersion,
    pub sdk_max: ProtocolVersion,
    pub protocol_min: ProtocolVersion,
    pub protocol_max: ProtocolVersion,
    pub capabilities: Vec<BridgeCapability>,
    pub permissions: Vec<BridgeDataPermission>,
    pub extensions: Vec<ProtocolExtension>,
}

impl fmt::Debug for BridgeProviderManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeProviderManifest")
            .field("provider_id", &self.provider_id)
            .field("sdk_min", &self.sdk_min)
            .field("sdk_max", &self.sdk_max)
            .field("protocol_min", &self.protocol_min)
            .field("protocol_max", &self.protocol_max)
            .field("capabilities", &self.capabilities)
            .field("permissions", &self.permissions)
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRegistration {
    pub scope: TenantScope,
    pub integration_id: IntegrationId,
    pub manifest: BridgeProviderManifest,
    pub state: BridgeRegistrationState,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeAction {
    pub action_id: BridgeActionId,
    pub scope: TenantScope,
    pub integration_id: IntegrationId,
    pub capability: BridgeCapability,
    pub external_target: Vec<u8>,
    pub canonical_message_id: Option<MessageId>,
    pub provider_payload: Vec<u8>,
    pub attachment_ids: Vec<AttachmentId>,
    pub correlation: CorrelationContext,
}

impl fmt::Debug for BridgeAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeAction")
            .field("action_id", &self.action_id)
            .field("scope", &self.scope)
            .field("integration_id", &self.integration_id)
            .field("capability", &self.capability)
            .field("external_target", &"<opaque>")
            .field("external_target_len", &self.external_target.len())
            .field("canonical_message_id", &self.canonical_message_id)
            .field("provider_payload", &"<redacted>")
            .field("provider_payload_len", &self.provider_payload.len())
            .field("attachment_ids", &self.attachment_ids)
            .field("correlation", &self.correlation)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeDegradationReason {
    UnsupportedCapability,
    PolicyRestricted,
    ProviderLimited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeDegradation {
    pub requested: BridgeCapability,
    pub fallback: Option<BridgeCapability>,
    pub reason: BridgeDegradationReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProviderAcceptance {
    pub external_message_id: Option<Vec<u8>>,
    pub degradation: Option<BridgeDegradation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeActionState {
    Prepared,
    InFlight,
    Accepted,
    FailedNotAccepted,
    AcceptanceUnknown,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeActionRecord {
    pub scope: TenantScope,
    pub action_id: BridgeActionId,
    pub integration_id: IntegrationId,
    pub capability: BridgeCapability,
    pub fingerprint: [u8; 32],
    pub state: BridgeActionState,
    pub acceptance: Option<BridgeProviderAcceptance>,
    pub generation: u64,
}

impl fmt::Debug for BridgeActionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeActionRecord")
            .field("scope", &self.scope)
            .field("action_id", &self.action_id)
            .field("integration_id", &self.integration_id)
            .field("capability", &self.capability)
            .field("fingerprint", &"<redacted>")
            .field("state", &self.state)
            .field("has_provider_acceptance", &self.acceptance.is_some())
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeInboundEvent {
    pub scope: TenantScope,
    pub integration_id: IntegrationId,
    pub external_event_id: Vec<u8>,
    pub external_conversation_id: Vec<u8>,
    pub external_actor_id: Option<Vec<u8>>,
    pub capability: BridgeCapability,
    pub payload: Vec<u8>,
    pub occurred_at_unix_ms: i64,
}

impl fmt::Debug for BridgeInboundEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeInboundEvent")
            .field("scope", &self.scope)
            .field("integration_id", &self.integration_id)
            .field("external_event_id", &"<opaque>")
            .field("external_conversation_id", &"<opaque>")
            .field("has_external_actor_id", &self.external_actor_id.is_some())
            .field("capability", &self.capability)
            .field("payload", &"<redacted>")
            .field("payload_len", &self.payload.len())
            .field("occurred_at_unix_ms", &self.occurred_at_unix_ms)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct BridgeEventCursor {
    pub token: Vec<u8>,
}

impl fmt::Debug for BridgeEventCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeEventCursor")
            .field("token", &"<opaque>")
            .field("token_len", &self.token.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeEventPage {
    pub events: Vec<BridgeInboundEvent>,
    pub next_cursor: Option<BridgeEventCursor>,
}

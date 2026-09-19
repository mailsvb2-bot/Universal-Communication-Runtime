use crate::{
    CallId, DeviceId, GroupId, IntegrationId, PrincipalRef, SessionId, TenantScope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalConferenceMode {
    Meeting,
    Webinar,
    Broadcast,
    AudioRoom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalConferenceLifecycle {
    Scheduled,
    Waiting,
    Live,
    Ending,
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConferenceParticipantRole {
    Owner,
    Host,
    Moderator,
    Speaker,
    Attendee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConferenceJoinGrantUsePolicy {
    SingleUse,
    Reusable,
}

/// Durable control-plane state for one signed Conference join grant.
///
/// The signed bearer token itself is deliberately not persisted. This record is the canonical
/// revocation/redeem state required to preserve join semantics across runtime restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceJoinGrantRecord {
    pub scope: TenantScope,
    pub conference_id: GroupId,
    pub integration_id: IntegrationId,
    pub call_id: CallId,
    pub participant: PrincipalRef,
    pub device_id: DeviceId,
    pub session_id: SessionId,
    pub issued_at_unix_ms: i64,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub use_policy: ConferenceJoinGrantUsePolicy,
    pub revoked: bool,
    pub redeemed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceScheduleMetadata {
    pub starts_at_unix_ms: i64,
    pub planned_end_unix_ms: Option<i64>,
    pub join_before_seconds: u32,
    pub join_after_seconds: u32,
    pub timezone: Option<String>,
}

/// Durable coordinator metadata for a Group-backed universal conference.
///
/// This record owns only integration-facing mode/schedule/lifecycle policy. Group remains
/// membership authority and `CallSession` remains realtime signalling authority.
#[derive(Clone, PartialEq, Eq)]
pub struct UniversalConferenceProfile {
    pub scope: TenantScope,
    /// Public conference handle. In v1 this is the canonical Group-backed room identifier.
    pub conference_id: GroupId,
    pub integration_id: IntegrationId,
    pub external_conference_id: Vec<u8>,
    pub create_idempotency_key: String,
    pub mode: UniversalConferenceMode,
    pub lifecycle: UniversalConferenceLifecycle,
    pub schedule: ConferenceScheduleMetadata,
    pub entry_open: bool,
    pub revision: u64,
}

impl core::fmt::Debug for UniversalConferenceProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UniversalConferenceProfile")
            .field("scope", &self.scope)
            .field("conference_id", &self.conference_id)
            .field("integration_id", &self.integration_id)
            .field("external_conference_id", &"<opaque>")
            .field(
                "external_conference_id_len",
                &self.external_conference_id.len(),
            )
            .field("create_idempotency_key", &"<redacted>")
            .field("mode", &self.mode)
            .field("lifecycle", &self.lifecycle)
            .field("schedule", &self.schedule)
            .field("entry_open", &self.entry_open)
            .field("revision", &self.revision)
            .finish()
    }
}

/// Conference-specific role/media policy projection for one canonical Group member.
///
/// The external reference is integration context only. It never replaces `ExternalIdentityBinding`,
/// canonical Group membership, authorization, Device trust or Call participation.
#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Public conference media policy has independent wire-level toggles.
pub struct UniversalConferenceParticipantProfile {
    pub scope: TenantScope,
    pub conference_id: GroupId,
    pub integration_id: IntegrationId,
    pub external_user_id: Vec<u8>,
    pub participant: PrincipalRef,
    pub role: ConferenceParticipantRole,
    pub audio_muted: bool,
    pub camera_allowed: bool,
    pub publish_audio_allowed: bool,
    pub publish_video_allowed: bool,
    pub active: bool,
    pub revision: u64,
}

impl core::fmt::Debug for UniversalConferenceParticipantProfile {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UniversalConferenceParticipantProfile")
            .field("scope", &self.scope)
            .field("conference_id", &self.conference_id)
            .field("integration_id", &self.integration_id)
            .field("external_user_id", &"<opaque>")
            .field("external_user_id_len", &self.external_user_id.len())
            .field("participant", &self.participant)
            .field("role", &self.role)
            .field("audio_muted", &self.audio_muted)
            .field("camera_allowed", &self.camera_allowed)
            .field("publish_audio_allowed", &self.publish_audio_allowed)
            .field("publish_video_allowed", &self.publish_video_allowed)
            .field("active", &self.active)
            .field("revision", &self.revision)
            .finish()
    }
}

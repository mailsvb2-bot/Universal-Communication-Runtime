use ucr_model::{
    ConferenceParticipantRole, GroupId, IntegrationId, PrincipalRef, TenantScope,
    UniversalConferenceLifecycle, UniversalConferenceParticipantProfile,
    UniversalConferenceProfile,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

/// Durable coordinator metadata for the high-level Conference integration boundary.
///
/// This store owns only integration-facing schedule/mode/lifecycle and role/media-policy projection.
/// Canonical Group membership and `CallSession` signalling stay owned by their existing stores.
pub trait UniversalConferenceStore: StorageProvider {
    /// Creates or deduplicates one conference profile.
    ///
    /// The exact external key (scope, `integration_id`, `external_conference_id`) is immutable.
    /// Equal retries return Duplicate; changed semantics conflict.
    ///
    /// # Errors
    /// Rejects malformed/conflicting records and explicit durable-store failures.
    fn persist_universal_conference_profile(
        &self,
        profile: &UniversalConferenceProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact conference coordinator record; absence is not an error.
    ///
    /// # Errors
    /// Returns explicit durable-store failures or corruption evidence.
    fn universal_conference_profile(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
    ) -> Result<Option<UniversalConferenceProfile>, DurableStoreError>;

    /// Resolves one exact external conference reference; absence is not an error.
    ///
    /// # Errors
    /// Rejects malformed lookup keys and returns explicit durable-store failures.
    fn universal_conference_profile_for_external(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        external_conference_id: &[u8],
    ) -> Result<Option<UniversalConferenceProfile>, DurableStoreError>;

    /// Applies one optimistic lifecycle transition and increments revision exactly once.
    ///
    /// # Errors
    /// Rejects invalid/stale transitions and explicit durable-store failures.
    fn transition_universal_conference(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        expected_revision: u64,
        lifecycle: UniversalConferenceLifecycle,
        entry_open: bool,
    ) -> Result<UniversalConferenceProfile, DurableStoreError>;

    /// Creates or deduplicates one integration-facing participant projection.
    ///
    /// # Errors
    /// Rejects malformed/conflicting participant records and explicit durable-store failures.
    fn persist_universal_conference_participant(
        &self,
        participant: &UniversalConferenceParticipantProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact conference participant projection; absence is not an error.
    ///
    /// # Errors
    /// Returns explicit durable-store failures or corruption evidence.
    fn universal_conference_participant(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        participant: &PrincipalRef,
    ) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError>;

    /// Resolves one integration-owned participant by the caller's stable external user reference.
    ///
    /// The exact key (scope, conference, integration, external user) is unique. Absence is not an
    /// error and implementations must never return an arbitrary principal when the durable key is
    /// ambiguous.
    ///
    /// # Errors
    /// Rejects malformed lookup keys and returns explicit durable-store failures or corruption.
    fn universal_conference_participant_for_external(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        integration_id: &IntegrationId,
        external_user_id: &[u8],
    ) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError>;

    /// Lists a bounded participant projection set for one conference.
    ///
    /// # Errors
    /// Rejects invalid bounds and returns explicit durable-store failures.
    fn universal_conference_participants(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError>;

    /// Replaces the conference-specific role/media policy under optimistic revision.
    ///
    /// # Errors
    /// Rejects stale/malformed updates and returns explicit durable-store failures.
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    fn update_universal_conference_participant(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        participant: &PrincipalRef,
        expected_revision: u64,
        role: ConferenceParticipantRole,
        audio_muted: bool,
        camera_allowed: bool,
        publish_audio_allowed: bool,
        publish_video_allowed: bool,
        active: bool,
    ) -> Result<UniversalConferenceParticipantProfile, DurableStoreError>;
}

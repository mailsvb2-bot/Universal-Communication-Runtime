use ucr_model::{
    ConferenceParticipantRole, GroupId, IntegrationId, PrincipalRef, TenantScope,
    UniversalConferenceLifecycle, UniversalConferenceParticipantProfile,
    UniversalConferenceProfile,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

/// Durable coordinator metadata for the high-level Conference integration boundary.
///
/// This store owns only integration-facing schedule/mode/lifecycle and role/media-policy projection.
/// Canonical Group membership and CallSession signalling stay owned by their existing stores.
pub trait UniversalConferenceStore: StorageProvider {
    /// Creates or deduplicates one conference profile.
    ///
    /// The exact external key (scope, integration_id, external_conference_id) is immutable.
    /// Equal retries return Duplicate; changed semantics conflict.
    fn persist_universal_conference_profile(
        &self,
        profile: &UniversalConferenceProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    fn universal_conference_profile(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
    ) -> Result<Option<UniversalConferenceProfile>, DurableStoreError>;

    fn universal_conference_profile_for_external(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        external_conference_id: &[u8],
    ) -> Result<Option<UniversalConferenceProfile>, DurableStoreError>;

    /// Applies one optimistic lifecycle transition and increments revision exactly once.
    fn transition_universal_conference(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        expected_revision: u64,
        lifecycle: UniversalConferenceLifecycle,
        entry_open: bool,
    ) -> Result<UniversalConferenceProfile, DurableStoreError>;

    /// Creates or deduplicates one integration-facing participant projection.
    fn persist_universal_conference_participant(
        &self,
        participant: &UniversalConferenceParticipantProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    fn universal_conference_participant(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        participant: &PrincipalRef,
    ) -> Result<Option<UniversalConferenceParticipantProfile>, DurableStoreError>;

    fn universal_conference_participants(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        max_items: usize,
    ) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError>;

    /// Replaces the conference-specific role/media policy under optimistic revision.
    #[allow(clippy::too_many_arguments)]
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

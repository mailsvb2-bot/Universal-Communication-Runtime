use ucr_model::{
    ConferenceJoinGrantRecord, ConferenceParticipantRole, EventEnvelope, GroupId, IntegrationId,
    PrincipalRef, SessionId, TenantScope, UniversalConferenceLifecycle,
    UniversalConferenceMetadataEntry, UniversalConferenceParticipantProfile,
    UniversalConferenceProfile,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

pub const MAX_CONFERENCE_METADATA_ENTRIES: usize = 32;
pub const MAX_CONFERENCE_METADATA_KEY_BYTES: usize = 255;
pub const MAX_CONFERENCE_METADATA_VALUE_BYTES: usize = 4096;
pub const MAX_CONFERENCE_METADATA_TOTAL_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConferenceMetadataError {
    TooManyEntries,
    InvalidKey,
    DuplicateKey,
    ValueTooLarge,
    TotalTooLarge,
}

/// Validates and canonically orders integration-owned Conference metadata.
///
/// Keys use a reverse-DNS-like namespace with at least three dot-separated ASCII identifier
/// segments (for example `com.example.crm.customer_id`). Values are opaque bounded bytes.
/// Metadata never grants UCR authority and is intentionally budgeted so this surface cannot become
/// an arbitrary integration database.
///
/// # Errors
/// Rejects malformed/duplicate keys or count/per-entry/aggregate budget violations.
pub fn canonical_conference_metadata(
    metadata: &[UniversalConferenceMetadataEntry],
) -> Result<Vec<UniversalConferenceMetadataEntry>, ConferenceMetadataError> {
    if metadata.len() > MAX_CONFERENCE_METADATA_ENTRIES {
        return Err(ConferenceMetadataError::TooManyEntries);
    }
    let mut total = 0usize;
    let mut canonical = metadata.to_vec();
    for entry in &canonical {
        if !valid_metadata_key(&entry.key) {
            return Err(ConferenceMetadataError::InvalidKey);
        }
        if entry.value.len() > MAX_CONFERENCE_METADATA_VALUE_BYTES {
            return Err(ConferenceMetadataError::ValueTooLarge);
        }
        total = total
            .checked_add(entry.key.len())
            .and_then(|value| value.checked_add(entry.value.len()))
            .ok_or(ConferenceMetadataError::TotalTooLarge)?;
        if total > MAX_CONFERENCE_METADATA_TOTAL_BYTES {
            return Err(ConferenceMetadataError::TotalTooLarge);
        }
    }
    canonical.sort_by(|left, right| left.key.cmp(&right.key));
    if canonical.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(ConferenceMetadataError::DuplicateKey);
    }
    Ok(canonical)
}

fn valid_metadata_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_CONFERENCE_METADATA_KEY_BYTES {
        return false;
    }
    let mut segments = 0usize;
    for segment in key.split('.') {
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return false;
        }
        segments += 1;
    }
    segments >= 3
}

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

    /// Atomically replaces the bounded integration-owned metadata set and advances Conference
    /// revision exactly once.
    ///
    /// Exact retries may return the already-applied next revision when metadata matches. Changed
    /// content under a stale revision conflicts.
    ///
    /// # Errors
    /// Rejects invalid metadata, stale revisions, unknown conferences and durable-store failures.
    fn replace_universal_conference_metadata(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        expected_revision: u64,
        metadata: &[UniversalConferenceMetadataEntry],
    ) -> Result<UniversalConferenceProfile, DurableStoreError>;

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

    /// Applies one optimistic lifecycle transition and, when supplied, appends its canonical
    /// integration Event in the same durable atomic action.
    ///
    /// This is the required boundary for externally observable lifecycle facts: implementations
    /// must never expose a transitioned Conference without the paired Event, nor an Event without
    /// the corresponding Conference revision. Stores that cannot provide that guarantee fail
    /// closed rather than falling back to two independent writes.
    ///
    /// # Errors
    /// Rejects invalid/stale transitions, malformed/conflicting Events, unsupported atomicity,
    /// and explicit durable-store failures.
    fn transition_universal_conference_with_event(
        &self,
        scope: &TenantScope,
        conference_id: &GroupId,
        expected_revision: u64,
        lifecycle: UniversalConferenceLifecycle,
        entry_open: bool,
        event: Option<&EventEnvelope>,
    ) -> Result<UniversalConferenceProfile, DurableStoreError> {
        let _ = (
            scope,
            conference_id,
            expected_revision,
            lifecycle,
            entry_open,
            event,
        );
        Err(DurableStoreError::Unavailable)
    }

    /// Creates or deduplicates one integration-facing participant projection.
    ///
    /// At most one active participant with role `Owner` may exist for a conference. Implementations
    /// must enforce that invariant atomically with the write rather than relying on a caller-side
    /// read-before-write check. Live participant capacity is likewise an atomic storage invariant;
    /// inactive historical participant projections do not consume that live capacity.
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

    /// Lists a bounded active participant projection set for runtime reconciliation.
    ///
    /// Implementations must apply the active predicate inside the same storage read rather than
    /// truncate an unfiltered participant set and filter it in the caller. This keeps historical
    /// inactive participant tombstones from consuming the live Conference capacity budget.
    ///
    /// # Errors
    /// Rejects invalid bounds and returns explicit durable-store failures.
    fn active_universal_conference_participants(
        &self,
        _scope: &TenantScope,
        _conference_id: &GroupId,
        _max_items: usize,
    ) -> Result<Vec<UniversalConferenceParticipantProfile>, DurableStoreError> {
        Err(DurableStoreError::Unavailable)
    }

    /// Replaces the conference-specific role/media policy under optimistic revision.
    ///
    /// The single-active-owner invariant is part of this same atomic mutation boundary.
    ///
    /// # Errors
    /// Rejects stale/malformed/conflicting updates and returns explicit durable-store failures.
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
        screen_share_allowed: bool,
        active: bool,
    ) -> Result<UniversalConferenceParticipantProfile, DurableStoreError>;
}

/// Durable owner for Conference join-grant control state.
///
/// Token signing remains a realtime cryptographic concern; this store owns only the minimum
/// metadata required for exact retry, revocation and single-use semantics across restarts.
pub trait ConferenceJoinGrantStore: StorageProvider {
    /// Persists one exact grant. Equal retries deduplicate; session-id reuse conflicts.
    ///
    /// # Errors
    /// Rejects malformed/conflicting records and explicit durable-store failures.
    fn persist_conference_join_grant(
        &self,
        grant: &ConferenceJoinGrantRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact scoped grant; absence is not an error.
    ///
    /// # Errors
    /// Returns explicit durable-store failures or corruption evidence.
    fn conference_join_grant(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<ConferenceJoinGrantRecord>, DurableStoreError>;

    /// Irreversibly revokes one exact grant. Repeating the same revocation is idempotent.
    ///
    /// # Errors
    /// Rejects unknown grants and explicit durable-store failures.
    fn revoke_conference_join_grant(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<ConferenceJoinGrantRecord, DurableStoreError>;

    /// Marks one exact grant redeemed. Reusable grants may be redeemed repeatedly; single-use
    /// grants fail closed after the first successful redemption.
    ///
    /// # Errors
    /// Rejects unknown, revoked or already-consumed single-use grants and storage failures.
    fn redeem_conference_join_grant(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<ConferenceJoinGrantRecord, DurableStoreError>;
}

#[cfg(test)]
mod metadata_tests {
    use ucr_model::UniversalConferenceMetadataEntry;

    use super::{ConferenceMetadataError, canonical_conference_metadata};

    #[test]
    fn conference_metadata_is_namespaced_bounded_and_canonical() {
        let metadata = vec![
            UniversalConferenceMetadataEntry {
                key: "org.example.webinar.source".to_owned(),
                value: b"landing".to_vec(),
            },
            UniversalConferenceMetadataEntry {
                key: "com.example.crm.customer_id".to_owned(),
                value: b"customer-42".to_vec(),
            },
        ];
        let canonical = canonical_conference_metadata(&metadata).expect("metadata");
        assert_eq!(canonical[0].key, "com.example.crm.customer_id");
        assert_eq!(canonical[1].key, "org.example.webinar.source");
    }

    #[test]
    fn conference_metadata_rejects_unscoped_duplicate_and_oversized_values() {
        assert_eq!(
            canonical_conference_metadata(&[UniversalConferenceMetadataEntry {
                key: "customer_id".to_owned(),
                value: Vec::new(),
            }]),
            Err(ConferenceMetadataError::InvalidKey)
        );
        let duplicate = UniversalConferenceMetadataEntry {
            key: "com.example.crm.customer_id".to_owned(),
            value: b"a".to_vec(),
        };
        assert_eq!(
            canonical_conference_metadata(&[duplicate.clone(), duplicate]),
            Err(ConferenceMetadataError::DuplicateKey)
        );
        assert_eq!(
            canonical_conference_metadata(&[UniversalConferenceMetadataEntry {
                key: "com.example.crm.payload".to_owned(),
                value: vec![0; 4097],
            }]),
            Err(ConferenceMetadataError::ValueTooLarge)
        );
    }
}

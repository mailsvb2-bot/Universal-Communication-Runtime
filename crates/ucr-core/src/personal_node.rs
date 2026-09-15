use ucr_model::{
    EndpointId, PersonalNodeObject, PersonalNodeObjectId, PersonalNodeObjectKind,
    PersonalNodeProfile, PersonalNodeState, TenantScope,
};

use crate::{DurableRecordStatus, DurableStoreError, StorageProvider};

/// Durable Personal Node profile and encrypted mailbox/cache sidecar owner.
///
/// This capability does not own canonical Message, Delivery, Sync, routing, relay, or Bridge state.
/// The stored objects are opaque ciphertext selected by the node owner and cannot become a second
/// communication source of truth.
pub trait PersonalNodeStore: StorageProvider {
    /// Installs or deduplicates one explicit Personal Node profile.
    ///
    /// # Errors
    /// Returns validation, conflict, corruption, permission, capacity, or storage failures.
    fn install_personal_node_profile(
        &self,
        profile: &PersonalNodeProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact scoped Personal Node profile when present.
    ///
    /// # Errors
    /// Returns explicit storage or corruption failures.
    fn personal_node_profile(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
    ) -> Result<Option<PersonalNodeProfile>, DurableStoreError>;

    /// Advances Active/Disabled lifecycle using optimistic generation.
    ///
    /// # Errors
    /// Returns validation, stale-generation conflict, corruption, or storage failures.
    fn transition_personal_node_profile(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        expected_generation: u64,
        next_state: PersonalNodeState,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Persists or deduplicates one opaque encrypted mailbox/cache object.
    ///
    /// # Errors
    /// Returns validation, conflict, disabled-service, capacity, corruption, or storage failures.
    fn persist_personal_node_object(
        &self,
        object: &PersonalNodeObject,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one exact encrypted object when present.
    ///
    /// # Errors
    /// Returns explicit storage or corruption failures.
    fn personal_node_object(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<Option<PersonalNodeObject>, DurableStoreError>;

    /// Lists a bounded deterministic set of encrypted objects for one node.
    ///
    /// # Errors
    /// Returns invalid-bound, storage, or corruption failures.
    fn personal_node_objects(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        kind: Option<PersonalNodeObjectKind>,
        max_items: usize,
    ) -> Result<Vec<PersonalNodeObject>, DurableStoreError>;

    /// Removes one exact node-owned encrypted object.
    ///
    /// # Errors
    /// Returns conflict when the object is absent, or explicit storage/corruption failures.
    fn remove_personal_node_object(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<DurableRecordStatus, DurableStoreError>;
}

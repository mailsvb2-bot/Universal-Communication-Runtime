use ucr_core::{DurableRecordStatus, DurableStoreError, PersonalNodeStore};
use ucr_model::{
    EndpointId, PersonalNodeObject, PersonalNodeObjectId, PersonalNodeObjectKind,
    PersonalNodeProfile, PersonalNodeState, TenantScope,
};
use ucr_protocol::{
    MAX_PERSONAL_NODE_OBJECTS_PER_LIST, canonical_personal_node_object,
    canonical_personal_node_profile, validate_personal_node_transition,
};

use super::{MemoryLocalStore, PersonalNodeObjectKey, PersonalNodeProfileKey, scope_key};

impl PersonalNodeStore for MemoryLocalStore {
    fn install_personal_node_profile(
        &self,
        profile: &PersonalNodeProfile,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical = canonical_personal_node_profile(profile)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        if canonical.state != PersonalNodeState::Active || canonical.generation != 1 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let key = personal_node_profile_key(&canonical.scope, &canonical.endpoint_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.personal_node_profiles.get(&key) {
            return if existing == &canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.personal_node_profiles.insert(key, canonical);
        Ok(DurableRecordStatus::Persisted)
    }

    fn personal_node_profile(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
    ) -> Result<Option<PersonalNodeProfile>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .personal_node_profiles
            .get(&personal_node_profile_key(scope, endpoint_id))
            .cloned())
    }

    fn transition_personal_node_profile(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        expected_generation: u64,
        next_state: PersonalNodeState,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = personal_node_profile_key(scope, endpoint_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let current = state
            .personal_node_profiles
            .get(&key)
            .cloned()
            .ok_or(DurableStoreError::Conflict)?;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if current.generation == next_generation && current.state == next_state {
            return Ok(DurableRecordStatus::Duplicate);
        }
        if current.generation != expected_generation {
            return Err(DurableStoreError::Conflict);
        }
        validate_personal_node_transition(current.state, next_state)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut next = current;
        next.state = next_state;
        next.generation = next_generation;
        let canonical =
            canonical_personal_node_profile(&next).map_err(|_| DurableStoreError::InvalidRecord)?;
        state.personal_node_profiles.insert(key, canonical);
        Ok(DurableRecordStatus::Persisted)
    }

    fn persist_personal_node_object(
        &self,
        object: &PersonalNodeObject,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let canonical =
            canonical_personal_node_object(object).map_err(|_| DurableStoreError::InvalidRecord)?;
        let profile_key = personal_node_profile_key(&canonical.scope, &canonical.endpoint_id);
        let object_key = personal_node_object_key(
            &canonical.scope,
            &canonical.endpoint_id,
            &canonical.object_id,
        );
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(existing) = state.personal_node_objects.get(&object_key) {
            return if existing == &canonical {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        let profile = state
            .personal_node_profiles
            .get(&profile_key)
            .ok_or(DurableStoreError::InvalidRecord)?;
        if profile.state != PersonalNodeState::Active
            || !personal_node_profile_allows_object(profile, canonical.kind)
        {
            return Err(DurableStoreError::PermissionDenied);
        }
        let used = state
            .personal_node_objects
            .values()
            .filter(|existing| {
                existing.scope == canonical.scope
                    && existing.endpoint_id == canonical.endpoint_id
                    && existing.kind == canonical.kind
            })
            .map(|existing| existing.ciphertext.len() as u64)
            .try_fold(0_u64, |sum, len| {
                sum.checked_add(len).ok_or(DurableStoreError::Full)
            })?;
        let incoming = canonical.ciphertext.len() as u64;
        let capacity = match canonical.kind {
            PersonalNodeObjectKind::Mailbox => profile.mailbox_capacity_bytes,
            PersonalNodeObjectKind::Cache => profile.cache_capacity_bytes,
        };
        if used.checked_add(incoming).ok_or(DurableStoreError::Full)? > capacity {
            return Err(DurableStoreError::Full);
        }
        state.personal_node_objects.insert(object_key, canonical);
        Ok(DurableRecordStatus::Persisted)
    }

    fn personal_node_object(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<Option<PersonalNodeObject>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .personal_node_objects
            .get(&personal_node_object_key(scope, endpoint_id, object_id))
            .cloned())
    }

    fn personal_node_objects(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        kind: Option<PersonalNodeObjectKind>,
        max_items: usize,
    ) -> Result<Vec<PersonalNodeObject>, DurableStoreError> {
        if max_items == 0 || max_items > MAX_PERSONAL_NODE_OBJECTS_PER_LIST {
            return Err(DurableStoreError::InvalidRecord);
        }
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let mut objects = state
            .personal_node_objects
            .values()
            .filter(|object| {
                object.scope == *scope
                    && object.endpoint_id == *endpoint_id
                    && kind.is_none_or(|expected| object.kind == expected)
            })
            .cloned()
            .collect::<Vec<_>>();
        objects.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        objects.truncate(max_items);
        Ok(objects)
    }

    fn remove_personal_node_object(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let key = personal_node_object_key(scope, endpoint_id, object_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(if state.personal_node_objects.remove(&key).is_some() {
            DurableRecordStatus::Persisted
        } else {
            DurableRecordStatus::Duplicate
        })
    }
}

fn personal_node_profile_key(
    scope: &TenantScope,
    endpoint_id: &EndpointId,
) -> PersonalNodeProfileKey {
    (
        scope_key(scope),
        endpoint_id.as_opaque().as_str().to_owned(),
    )
}

fn personal_node_object_key(
    scope: &TenantScope,
    endpoint_id: &EndpointId,
    object_id: &PersonalNodeObjectId,
) -> PersonalNodeObjectKey {
    (
        scope_key(scope),
        endpoint_id.as_opaque().as_str().to_owned(),
        object_id.as_opaque().as_str().to_owned(),
    )
}

fn personal_node_profile_allows_object(
    profile: &PersonalNodeProfile,
    kind: PersonalNodeObjectKind,
) -> bool {
    let required = match kind {
        PersonalNodeObjectKind::Mailbox => ucr_model::PersonalNodeService::EncryptedMailbox,
        PersonalNodeObjectKind::Cache => ucr_model::PersonalNodeService::Cache,
    };
    profile.services.contains(&required)
}

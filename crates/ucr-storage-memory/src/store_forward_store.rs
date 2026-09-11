use ucr_core::{DurableRecordStatus, DurableStoreError, StoreForwardStore};
use ucr_model::{
    DeliveryId, DeliveryState, StoreForwardId, StoreForwardJob, StoreForwardLease,
    StoreForwardLeaseId, TenantScope,
};
use ucr_protocol::{
    store_forward_delivery_id, store_forward_job_fingerprint, validate_store_forward_job,
    validate_store_forward_page_size,
};

use super::{
    MemoryLocalStore, MemoryStoreForwardState, delivery_key, intent_key, message_key, scope_key,
    store_forward_key,
};

impl StoreForwardStore for MemoryLocalStore {
    fn persist_store_forward_job(
        &self,
        job: &StoreForwardJob,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_store_forward_job(job).map_err(|_| DurableStoreError::InvalidRecord)?;
        if job.attempts_used != 0 || job.last_delivery_id.is_some() {
            return Err(DurableStoreError::InvalidRecord);
        }
        let fingerprint =
            store_forward_job_fingerprint(job).map_err(|_| DurableStoreError::InvalidRecord)?;
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if !state
            .intents
            .contains_key(&intent_key(&job.scope, &job.intent_id))
            || !state
                .messages
                .contains_key(&message_key(&job.scope, &job.message_id))
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let key = store_forward_key(&job.scope, &job.store_forward_id);
        if let Some(existing) = state.store_forward_tombstones.get(&key) {
            return if existing == &fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        if let Some(existing) = state.store_forward_jobs.get(&key) {
            return if existing.fingerprint == fingerprint {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.store_forward_jobs.insert(
            key,
            MemoryStoreForwardState {
                job: job.clone(),
                fingerprint,
                lease: None,
            },
        );
        Ok(DurableRecordStatus::Persisted)
    }

    fn store_forward_job(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
    ) -> Result<Option<StoreForwardJob>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .store_forward_jobs
            .get(&store_forward_key(scope, store_forward_id))
            .map(|value| value.job.clone()))
    }

    fn due_store_forward_jobs(
        &self,
        scope: &TenantScope,
        now_unix_ms: i64,
        max_items: usize,
    ) -> Result<Vec<StoreForwardId>, DurableStoreError> {
        validate_store_forward_page_size(max_items)
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let scope_key = scope_key(scope);
        let mut due = state
            .store_forward_jobs
            .iter()
            .filter_map(|((job_scope, _), value)| {
                if job_scope != &scope_key
                    || value.job.next_attempt_at_unix_ms > now_unix_ms
                    || value
                        .lease
                        .as_ref()
                        .is_some_and(|(_, lease_until)| *lease_until > now_unix_ms)
                {
                    return None;
                }
                if let Some(delivery_id) = value.job.last_delivery_id.as_ref()
                    && state
                        .deliveries
                        .get(&delivery_key(&value.job.scope, delivery_id))
                        .is_some_and(|attempt| attempt.state == DeliveryState::InFlight)
                {
                    return None;
                }
                Some((
                    value.job.next_attempt_at_unix_ms,
                    value.store_forward_id_sort_key(),
                    value.job.store_forward_id.clone(),
                ))
            })
            .collect::<Vec<_>>();
        due.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
        Ok(due
            .into_iter()
            .take(max_items)
            .map(|(_, _, id)| id)
            .collect())
    }

    fn claim_store_forward_job(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
        lease_id: &StoreForwardLeaseId,
        now_unix_ms: i64,
        lease_until_unix_ms: i64,
    ) -> Result<Option<StoreForwardLease>, DurableStoreError> {
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let key = store_forward_key(scope, store_forward_id);
        let snapshot = match state.store_forward_jobs.get(&key) {
            Some(value) => value.clone(),
            None => return Ok(None),
        };
        let max_lease_until = now_unix_ms
            .checked_add(
                i64::try_from(snapshot.job.policy.lease_duration_ms)
                    .map_err(|_| DurableStoreError::InvalidRecord)?,
            )
            .ok_or(DurableStoreError::InvalidRecord)?;
        if lease_until_unix_ms <= now_unix_ms
            || lease_until_unix_ms > max_lease_until
            || snapshot.job.next_attempt_at_unix_ms > now_unix_ms
            || snapshot
                .lease
                .as_ref()
                .is_some_and(|(_, until)| *until > now_unix_ms)
        {
            return Ok(None);
        }
        if let Some(delivery_id) = snapshot.job.last_delivery_id.as_ref()
            && state
                .deliveries
                .get(&delivery_key(scope, delivery_id))
                .is_some_and(|attempt| attempt.state == DeliveryState::InFlight)
        {
            return Ok(None);
        }
        let value = state
            .store_forward_jobs
            .get_mut(&key)
            .ok_or(DurableStoreError::Internal)?;
        value.lease = Some((lease_id.clone(), lease_until_unix_ms));
        Ok(Some(StoreForwardLease {
            job: value.job.clone(),
            lease_id: lease_id.clone(),
            lease_until_unix_ms,
        }))
    }

    fn record_store_forward_attempt(
        &self,
        lease: &StoreForwardLease,
        delivery_id: &DeliveryId,
        attempts_used: u16,
        now_unix_ms: i64,
    ) -> Result<StoreForwardJob, DurableStoreError> {
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let key = store_forward_key(&lease.job.scope, &lease.job.store_forward_id);
        let snapshot = state
            .store_forward_jobs
            .get(&key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_lease(&snapshot, lease, now_unix_ms)?;
        if attempts_used != snapshot.job.attempts_used.saturating_add(1)
            || attempts_used > snapshot.job.policy.max_delivery_attempts
            || *delivery_id
                != store_forward_delivery_id(
                    &snapshot.job.scope,
                    &snapshot.job.store_forward_id,
                    attempts_used,
                )
        {
            return Err(DurableStoreError::Conflict);
        }
        let attempt = state
            .deliveries
            .get(&delivery_key(&snapshot.job.scope, delivery_id))
            .ok_or(DurableStoreError::InvalidRecord)?;
        if attempt.message_id != snapshot.job.message_id
            || attempt.state != DeliveryState::Persisted
        {
            return Err(DurableStoreError::Conflict);
        }
        let value = state
            .store_forward_jobs
            .get_mut(&key)
            .ok_or(DurableStoreError::Internal)?;
        value.job.attempts_used = attempts_used;
        value.job.last_delivery_id = Some(delivery_id.clone());
        validate_store_forward_job(&value.job).map_err(|_| DurableStoreError::InvalidRecord)?;
        Ok(value.job.clone())
    }

    fn reschedule_store_forward_job(
        &self,
        lease: &StoreForwardLease,
        next_attempt_at_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<StoreForwardJob, DurableStoreError> {
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let key = store_forward_key(&lease.job.scope, &lease.job.store_forward_id);
        let value = state
            .store_forward_jobs
            .get_mut(&key)
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_lease(value, lease, now_unix_ms)?;
        value.job.next_attempt_at_unix_ms = next_attempt_at_unix_ms;
        value.lease = None;
        validate_store_forward_job(&value.job).map_err(|_| DurableStoreError::InvalidRecord)?;
        Ok(value.job.clone())
    }

    fn complete_store_forward_job(
        &self,
        lease: &StoreForwardLease,
        now_unix_ms: i64,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        let key = store_forward_key(&lease.job.scope, &lease.job.store_forward_id);
        let value = state
            .store_forward_jobs
            .get(&key)
            .cloned()
            .ok_or(DurableStoreError::InvalidRecord)?;
        require_lease(&value, lease, now_unix_ms)?;
        state
            .store_forward_tombstones
            .insert(key.clone(), value.fingerprint);
        state.store_forward_jobs.remove(&key);
        Ok(DurableRecordStatus::Persisted)
    }
}

fn require_lease(
    value: &MemoryStoreForwardState,
    lease: &StoreForwardLease,
    now_unix_ms: i64,
) -> Result<(), DurableStoreError> {
    let Some((lease_id, lease_until)) = value.lease.as_ref() else {
        return Err(DurableStoreError::Conflict);
    };
    if lease_id != &lease.lease_id
        || *lease_until != lease.lease_until_unix_ms
        || now_unix_ms >= *lease_until
    {
        return Err(DurableStoreError::Conflict);
    }
    Ok(())
}

trait StoreForwardSortKey {
    fn store_forward_id_sort_key(&self) -> &str;
}

impl StoreForwardSortKey for MemoryStoreForwardState {
    fn store_forward_id_sort_key(&self) -> &str {
        self.job.store_forward_id.as_opaque().as_str()
    }
}

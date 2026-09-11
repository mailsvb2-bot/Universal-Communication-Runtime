use sha2::{Digest, Sha256};
use ucr_model::{
    DeliveryId, OpaqueId, StoreForwardId, StoreForwardJob, StoreForwardPolicy, TenantScope,
};

use crate::DEFAULT_MAX_PAYLOAD_LEN;

pub const MAX_STORE_FORWARD_DELIVERY_ATTEMPTS: u16 = 64;
pub const MAX_STORE_FORWARD_PAGE_ITEMS: usize = 256;
pub const MAX_STORE_FORWARD_RETRY_DELAY_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const MAX_STORE_FORWARD_LEASE_MS: u64 = 5 * 60 * 1000;
const STORE_FORWARD_DELIVERY_ID_DOMAIN: &[u8] = b"UCR-STORE-FORWARD-DELIVERY-ID-V1";
const STORE_FORWARD_JOB_FINGERPRINT_DOMAIN: &[u8] = b"UCR-STORE-FORWARD-JOB-FINGERPRINT-V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreForwardError {
    InvalidAttemptBudget,
    InvalidRetryDelay,
    InvalidLeaseDuration,
    InvalidExpiry,
    InvalidEnvelope,
    InvalidAttemptState,
    InvalidPageSize,
    ClockOverflow,
}

/// Validates one durable Store-and-Forward scheduling policy.
///
/// # Errors
/// Rejects unbounded/zero attempt, retry, lease, or already-invalid expiry semantics.
pub const fn validate_store_forward_policy(
    policy: &StoreForwardPolicy,
) -> Result<(), StoreForwardError> {
    if policy.max_delivery_attempts == 0
        || policy.max_delivery_attempts > MAX_STORE_FORWARD_DELIVERY_ATTEMPTS
    {
        return Err(StoreForwardError::InvalidAttemptBudget);
    }
    if policy.base_retry_delay_ms == 0
        || policy.max_retry_delay_ms < policy.base_retry_delay_ms
        || policy.max_retry_delay_ms > MAX_STORE_FORWARD_RETRY_DELAY_MS
    {
        return Err(StoreForwardError::InvalidRetryDelay);
    }
    if policy.lease_duration_ms == 0 || policy.lease_duration_ms > MAX_STORE_FORWARD_LEASE_MS {
        return Err(StoreForwardError::InvalidLeaseDuration);
    }
    Ok(())
}

/// Validates persisted job invariants without treating scheduling state as Delivery truth.
///
/// # Errors
/// Rejects malformed policies, oversized/empty ciphertext, impossible attempt counters, and
/// last-attempt linkage that disagrees with the number of provider-bearing delivery attempts.
pub fn validate_store_forward_job(job: &StoreForwardJob) -> Result<(), StoreForwardError> {
    validate_store_forward_policy(&job.policy)?;
    if job.encrypted_envelope.is_empty()
        || job.encrypted_envelope.len() > DEFAULT_MAX_PAYLOAD_LEN as usize
    {
        return Err(StoreForwardError::InvalidEnvelope);
    }
    if job.attempts_used > job.policy.max_delivery_attempts
        || (job.attempts_used == 0 && job.last_delivery_id.is_some())
        || (job.attempts_used > 0 && job.last_delivery_id.is_none())
    {
        return Err(StoreForwardError::InvalidAttemptState);
    }
    if job
        .policy
        .expires_at_unix_ms
        .is_some_and(|expiry| job.next_attempt_at_unix_ms > expiry)
    {
        return Err(StoreForwardError::InvalidExpiry);
    }
    Ok(())
}

/// Validates the scheduler's bounded page size.
///
/// # Errors
/// Rejects zero or more than 256 jobs per scheduler scan.
pub const fn validate_store_forward_page_size(max_items: usize) -> Result<(), StoreForwardError> {
    if max_items == 0 || max_items > MAX_STORE_FORWARD_PAGE_ITEMS {
        Err(StoreForwardError::InvalidPageSize)
    } else {
        Ok(())
    }
}

/// Returns deterministic capped exponential backoff after one consumed delivery attempt.
#[must_use]
pub const fn store_forward_retry_delay_ms(policy: &StoreForwardPolicy, attempts_used: u16) -> u64 {
    let shift = if attempts_used > 1 {
        if attempts_used - 1 > 31 {
            31
        } else {
            (attempts_used - 1) as u32
        }
    } else {
        0
    };
    let scaled = policy.base_retry_delay_ms.saturating_mul(1_u64 << shift);
    if scaled > policy.max_retry_delay_ms {
        policy.max_retry_delay_ms
    } else {
        scaled
    }
}

/// Computes the next scheduler timestamp without wrapping signed wall-clock space.
///
/// # Errors
/// Returns `ClockOverflow` if the delay cannot be represented as an `i64` timestamp.
pub fn store_forward_next_attempt_at(
    now_unix_ms: i64,
    policy: &StoreForwardPolicy,
    attempts_used: u16,
) -> Result<i64, StoreForwardError> {
    let delay = store_forward_retry_delay_ms(policy, attempts_used);
    let delay = i64::try_from(delay).map_err(|_| StoreForwardError::ClockOverflow)?;
    let next = now_unix_ms
        .checked_add(delay)
        .ok_or(StoreForwardError::ClockOverflow)?;
    if let Some(expiry) = policy.expires_at_unix_ms {
        Ok(next.min(expiry))
    } else {
        Ok(next)
    }
}

/// Computes a stable fingerprint for the immutable enqueue semantics of one initial job.
///
/// The fingerprint is idempotency evidence only. It is not a Message identity, Delivery identity,
/// signature, authorization proof, or route token.
///
/// # Errors
/// Rejects malformed or already-progressed jobs.
pub fn store_forward_job_fingerprint(job: &StoreForwardJob) -> Result<[u8; 32], StoreForwardError> {
    validate_store_forward_job(job)?;
    if job.attempts_used != 0 || job.last_delivery_id.is_some() {
        return Err(StoreForwardError::InvalidAttemptState);
    }
    let mut hasher = Sha256::new();
    hasher.update(STORE_FORWARD_JOB_FINGERPRINT_DOMAIN);
    append_scope(&mut hasher, &job.scope);
    append_len_prefixed(
        &mut hasher,
        job.store_forward_id.as_opaque().as_wire_bytes(),
    );
    append_len_prefixed(&mut hasher, job.intent_id.as_opaque().as_wire_bytes());
    append_len_prefixed(&mut hasher, job.message_id.as_opaque().as_wire_bytes());
    append_len_prefixed(&mut hasher, &job.encrypted_envelope);
    hasher.update(job.policy.max_delivery_attempts.to_be_bytes());
    hasher.update(job.policy.base_retry_delay_ms.to_be_bytes());
    hasher.update(job.policy.max_retry_delay_ms.to_be_bytes());
    hasher.update(job.policy.lease_duration_ms.to_be_bytes());
    match job.policy.expires_at_unix_ms {
        Some(expiry) => {
            hasher.update([1]);
            hasher.update(expiry.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(job.next_attempt_at_unix_ms.to_be_bytes());
    Ok(hasher.finalize().into())
}

fn append_scope(hasher: &mut Sha256, scope: &TenantScope) {
    append_len_prefixed(hasher, scope.tenant_id.as_opaque().as_wire_bytes());
    match scope.namespace_id.as_ref() {
        Some(namespace) => {
            hasher.update([1]);
            append_len_prefixed(hasher, namespace.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
}

/// Derives the canonical retry `DeliveryId` for one job/ordinal.
///
/// Re-running after a crash yields the same ID, so attempt creation is safely idempotent. The ID
/// carries no clock, host, route, provider, tenant, or business meaning.
///
/// # Panics
/// Panics only if the fixed 64-byte lowercase SHA-256 hex token violates the canonical opaque-ID
/// invariant. That would indicate an internal protocol implementation defect.
#[must_use]
pub fn store_forward_delivery_id(
    scope: &TenantScope,
    store_forward_id: &StoreForwardId,
    attempt_ordinal: u16,
) -> DeliveryId {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FORWARD_DELIVERY_ID_DOMAIN);
    append_scope(&mut hasher, scope);
    append_len_prefixed(&mut hasher, store_forward_id.as_opaque().as_wire_bytes());
    hasher.update(attempt_ordinal.to_be_bytes());
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    DeliveryId::from_opaque(OpaqueId::new(text).expect("SHA-256 hex fits opaque ID"))
}

fn append_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("opaque IDs are <=128 bytes");
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{
        IntentId, MessageId, NamespaceId, StoreForwardJob, StoreForwardPolicy, TenantId,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope(namespace: Option<&str>) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("sf-tenant")),
            namespace_id: namespace.map(|value| NamespaceId::from_opaque(oid(value))),
        }
    }

    fn policy() -> StoreForwardPolicy {
        StoreForwardPolicy {
            max_delivery_attempts: 5,
            base_retry_delay_ms: 100,
            max_retry_delay_ms: 350,
            lease_duration_ms: 5_000,
            expires_at_unix_ms: None,
        }
    }

    #[test]
    fn retry_delay_is_bounded_exponential() {
        let policy = policy();
        assert_eq!(store_forward_retry_delay_ms(&policy, 1), 100);
        assert_eq!(store_forward_retry_delay_ms(&policy, 2), 200);
        assert_eq!(store_forward_retry_delay_ms(&policy, 3), 350);
        assert_eq!(store_forward_retry_delay_ms(&policy, 20), 350);
    }

    #[test]
    fn deterministic_delivery_id_binds_scope_job_and_ordinal() {
        let job = StoreForwardId::from_opaque(oid("sf-job"));
        let first = store_forward_delivery_id(&scope(None), &job, 1);
        assert_eq!(first, store_forward_delivery_id(&scope(None), &job, 1));
        assert_ne!(first, store_forward_delivery_id(&scope(None), &job, 2));
        assert_ne!(
            first,
            store_forward_delivery_id(&scope(Some("ns")), &job, 1)
        );
    }

    #[test]
    fn enqueue_fingerprint_binds_ciphertext_policy_and_initial_due_time() {
        let job = StoreForwardJob {
            store_forward_id: StoreForwardId::from_opaque(oid("sf-job-fingerprint")),
            scope: scope(None),
            intent_id: IntentId::from_opaque(oid("sf-intent")),
            message_id: MessageId::from_opaque(oid("sf-message")),
            encrypted_envelope: vec![1, 2, 3],
            policy: policy(),
            attempts_used: 0,
            next_attempt_at_unix_ms: 10,
            last_delivery_id: None,
        };
        let fingerprint = store_forward_job_fingerprint(&job).expect("fingerprint");
        assert_eq!(
            fingerprint,
            store_forward_job_fingerprint(&job).expect("stable fingerprint")
        );
        let mut changed = job.clone();
        changed.encrypted_envelope.push(4);
        assert_ne!(
            fingerprint,
            store_forward_job_fingerprint(&changed).expect("changed fingerprint")
        );
        let mut changed_due = job;
        changed_due.next_attempt_at_unix_ms += 1;
        assert_ne!(
            fingerprint,
            store_forward_job_fingerprint(&changed_due).expect("changed due fingerprint")
        );
    }

    #[test]
    fn persisted_job_rejects_attempt_linkage_mismatch() {
        let mut job = StoreForwardJob {
            store_forward_id: StoreForwardId::from_opaque(oid("sf-job")),
            scope: scope(None),
            intent_id: IntentId::from_opaque(oid("sf-intent")),
            message_id: MessageId::from_opaque(oid("sf-message")),
            encrypted_envelope: vec![1],
            policy: policy(),
            attempts_used: 0,
            next_attempt_at_unix_ms: 10,
            last_delivery_id: None,
        };
        assert_eq!(validate_store_forward_job(&job), Ok(()));
        job.attempts_used = 1;
        assert_eq!(
            validate_store_forward_job(&job),
            Err(StoreForwardError::InvalidAttemptState)
        );
    }
}

#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::{
    IntentId, MessageId, NamespaceId, OpaqueId, StoreForwardId, StoreForwardJob,
    StoreForwardPolicy, TenantId, TenantScope,
};
use ucr_protocol::{
    store_forward_delivery_id, store_forward_job_fingerprint, store_forward_next_attempt_at,
    store_forward_retry_delay_ms, validate_store_forward_job, validate_store_forward_page_size,
};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static fuzz id")
}

fuzz_target!(|data: &[u8]| {
    let attempts = u16::from(data.first().copied().unwrap_or(1)).max(1);
    let base = u64::from(data.get(1).copied().unwrap_or(1)).max(1);
    let max = base.saturating_add(u64::from(data.get(2).copied().unwrap_or_default()) * 10);
    let lease = u64::from(data.get(3).copied().unwrap_or(1)).max(1);
    let now = i64::from(data.get(4).copied().unwrap_or_default());
    let expires = data
        .get(5)
        .copied()
        .filter(|value| value & 1 == 1)
        .map(|_| now.saturating_add(10_000));
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(oid("fuzz-store-forward-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(oid("fuzz-store-forward-ns"))),
    };
    let policy = StoreForwardPolicy {
        max_delivery_attempts: attempts,
        base_retry_delay_ms: base,
        max_retry_delay_ms: max,
        lease_duration_ms: lease,
        expires_at_unix_ms: expires,
    };
    let job = StoreForwardJob {
        store_forward_id: StoreForwardId::from_opaque(oid("fuzz-store-forward-job")),
        scope: scope.clone(),
        intent_id: IntentId::from_opaque(oid("fuzz-store-forward-intent")),
        message_id: MessageId::from_opaque(oid("fuzz-store-forward-message")),
        encrypted_envelope: data.iter().skip(6).take(2048).copied().collect(),
        policy,
        attempts_used: 0,
        next_attempt_at_unix_ms: now,
        last_delivery_id: None,
    };
    let validation = validate_store_forward_job(&job);
    if validation.is_ok() {
        let fingerprint = store_forward_job_fingerprint(&job).expect("validated job fingerprints");
        assert_eq!(
            fingerprint,
            store_forward_job_fingerprint(&job).expect("stable fingerprint")
        );
        let first = store_forward_delivery_id(&scope, &job.store_forward_id, 1);
        let second = store_forward_delivery_id(&scope, &job.store_forward_id, 2);
        assert_ne!(first, second);
        let delay = store_forward_retry_delay_ms(&policy, 1);
        assert!(delay <= policy.max_retry_delay_ms);
        let _ = store_forward_next_attempt_at(now, &policy, 1);
    }
    let requested = usize::from(data.get(7).copied().unwrap_or_default());
    let _ = validate_store_forward_page_size(requested);
});

use core::fmt;

use crate::{DeliveryId, IntentId, MessageId, StoreForwardId, StoreForwardLeaseId, TenantScope};

/// Bounded durable scheduling policy for one Store-and-Forward job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreForwardPolicy {
    pub max_delivery_attempts: u16,
    pub base_retry_delay_ms: u64,
    pub max_retry_delay_ms: u64,
    pub lease_duration_ms: u64,
    pub expires_at_unix_ms: Option<i64>,
}

/// Durable scheduling sidecar over canonical Message, Intent and Delivery owners.
///
/// The encrypted envelope is transport input, not a second canonical Message body. Its Debug
/// representation is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreForwardJob {
    pub store_forward_id: StoreForwardId,
    pub scope: TenantScope,
    pub intent_id: IntentId,
    pub message_id: MessageId,
    pub encrypted_envelope: Vec<u8>,
    pub policy: StoreForwardPolicy,
    pub attempts_used: u16,
    pub next_attempt_at_unix_ms: i64,
    pub last_delivery_id: Option<DeliveryId>,
}

impl fmt::Debug for StoreForwardJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreForwardJob")
            .field("store_forward_id", &self.store_forward_id)
            .field("scope", &self.scope)
            .field("intent_id", &self.intent_id)
            .field("message_id", &self.message_id)
            .field("encrypted_envelope", &"<redacted>")
            .field("encrypted_envelope_len", &self.encrypted_envelope.len())
            .field("policy", &self.policy)
            .field("attempts_used", &self.attempts_used)
            .field("next_attempt_at_unix_ms", &self.next_attempt_at_unix_ms)
            .field("last_delivery_id", &self.last_delivery_id)
            .finish()
    }
}

/// Exclusive restart-safe processing lease. The persisted job remains the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreForwardLease {
    pub job: StoreForwardJob,
    pub lease_id: StoreForwardLeaseId,
    pub lease_until_unix_ms: i64,
}

/// Public, payload-free result of one Store-and-Forward scheduler iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreForwardOutcome {
    AcceptedByTransport,
    RescheduledNoRoute,
    RescheduledAfterFailure,
    AcceptanceUnknown,
    AttemptsExhausted,
    Expired,
    NotDue,
    Busy,
}

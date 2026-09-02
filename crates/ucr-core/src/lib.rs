#![forbid(unsafe_code)]

use ucr_model::{
    AuthorizationRequest, CapabilityDescriptor, CommandEnvelope, CommandId, CommunicationIntent,
    ConversationId, ConversationRecord, DeliveryAttempt, DeliveryEvidence, DeliveryId,
    DeliveryState, EndpointAddress, EndpointId, EventEnvelope, EventId, IdentityId,
    MessageEnvelope, MessageId, RecoveryPlan, RecoveryPlanId, TenantScope,
};
use ucr_protocol::{CanonicalError, CommandReceipt};

/// A route candidate is transient runtime state, never canonical identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub endpoint_id: EndpointId,
    pub transport_capability: String,
    pub address: EndpointAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalTransportError {
    Unavailable,
    Timeout,
    Rejected,
    PolicyDenied,
    UnsupportedCapability,
    ResourceExhausted,
    MalformedResponse,
    Internal,
}

/// Boundary implemented by a concrete communication transport.
///
/// It intentionally does not expose provider-specific canonical message or
/// identity types.
pub trait TransportProvider: core::fmt::Debug + Send + Sync {
    fn capabilities(&self) -> Vec<CapabilityDescriptor>;
    fn health(&self) -> TransportHealth;

    /// Attempts transport of an already-canonical encrypted envelope.
    ///
    /// # Errors
    /// Returns a canonical transport error. Provider-specific diagnostics must
    /// not replace canonical failure semantics.
    fn transmit(
        &self,
        scope: &TenantScope,
        route: &RouteCandidate,
        encrypted_envelope: &[u8],
    ) -> Result<(), CanonicalTransportError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    PendingNoAllowedRoute,
}

/// Policy is evaluated above transport selection and therefore survives route
/// changes.
pub trait PolicyEvaluator: core::fmt::Debug + Send + Sync {
    fn evaluate_intent(&self, intent: &CommunicationIntent) -> PolicyDecision;
}

/// Authorization is a separate runtime boundary from communication policy.
/// Implementations must preserve deny-by-default permission semantics.
pub trait AuthorizationEvaluator: core::fmt::Debug + Send + Sync {
    /// Evaluates one scoped permission request.
    ///
    /// # Errors
    /// Returns a canonical error; lack of authority is `PermissionDenied`.
    fn authorize(&self, request: &AuthorizationRequest) -> Result<(), CanonicalError>;
}

/// Storage health is explicit and never inferred from successful construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageHealth {
    Healthy,
    ReadOnly,
    Unavailable,
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStoreError {
    InvalidRecord,
    Conflict,
    Full,
    Corrupt,
    Unavailable,
    PermissionDenied,
    UnsupportedSchemaVersion,
    ForeignStore,
    Internal,
}

/// Base boundary shared by local, memory-test, server, and future embedded stores.
pub trait StorageProvider: core::fmt::Debug + Send + Sync {
    /// Returns the schema generation understood by this store.
    ///
    /// # Errors
    /// Returns an explicit storage failure when metadata cannot be read safely.
    fn schema_version(&self) -> Result<u32, DurableStoreError>;

    /// Performs a non-mutating health check.
    ///
    /// # Errors
    /// Returns an explicit storage failure if health cannot be established.
    fn health(&self) -> Result<StorageHealth, DurableStoreError>;
}

/// Durable recovery-plan capability. Recovery secrets are not part of this store.
pub trait RecoveryPlanStore: StorageProvider {
    /// Installs the first active plan for an identity.
    ///
    /// # Errors
    /// Fails on invalid plan or when another active plan already exists.
    fn install_recovery_plan(&self, plan: &RecoveryPlan) -> Result<(), DurableStoreError>;

    /// Atomically replaces one expected active plan.
    ///
    /// # Errors
    /// Fails if the expected plan is not active or scope/identity changes.
    fn rotate_recovery_plan(
        &self,
        expected_current: &RecoveryPlanId,
        replacement: &RecoveryPlan,
    ) -> Result<(), DurableStoreError>;

    /// Revokes the expected active recovery plan. Repeating the same revocation is idempotent.
    ///
    /// # Errors
    /// Fails when a different active plan exists or storage cannot commit safely.
    fn revoke_recovery_plan(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
        expected_current: &RecoveryPlanId,
    ) -> Result<(), DurableStoreError>;

    /// Returns the currently active recovery plan for one scoped identity.
    ///
    /// # Errors
    /// Returns explicit storage/corruption failures; absence is not an error.
    fn active_recovery_plan(
        &self,
        scope: &TenantScope,
        identity_id: &IdentityId,
    ) -> Result<Option<RecoveryPlan>, DurableStoreError>;
}

/// Durable command-acceptance capability.
///
/// The implementation must atomically persist acceptance before returning an
/// Accepted receipt and must preserve deduplication across restart.
pub trait CommandAcceptanceStore: StorageProvider {
    /// Atomically accepts or deduplicates one command.
    ///
    /// # Errors
    /// Returns explicit invalid/conflict/storage failures; failures never mean
    /// that a new command was accepted.
    fn accept_command(
        &self,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, DurableStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRecordStatus {
    Persisted,
    Duplicate,
}

/// Durable provider-independent Conversation capability.
pub trait ConversationStore: StorageProvider {
    /// Persists or deduplicates one canonical Conversation.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, or storage failures.
    fn persist_conversation(
        &self,
        conversation: &ConversationRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one scoped Conversation when present.
    ///
    /// # Errors
    /// Returns explicit storage or corrupt-state failures.
    fn conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<ConversationRecord>, DurableStoreError>;
}

/// Durable canonical Message capability. Delivery transitions after Persisted
/// belong to the Delivery Engine, not this storage boundary.
pub trait MessageStore: ConversationStore {
    /// Persists or deduplicates one canonical Message as local durable state.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, or storage failures.
    fn persist_message(
        &self,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one scoped Message when present.
    ///
    /// # Errors
    /// Returns explicit storage or corrupt-state failures.
    fn message(
        &self,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError>;
}

/// Durable Delivery Engine state/evidence capability.
pub trait DeliveryStore: MessageStore {
    /// Creates one `DeliveryAttempt` from already-persisted Message state.
    ///
    /// # Errors
    /// Returns validation, conflict, or storage failures.
    fn create_delivery_attempt(
        &self,
        attempt: &DeliveryAttempt,
        persisted_evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Atomically validates and advances one attempt.
    ///
    /// # Errors
    /// Returns conflict for stale expected state and explicit validation/storage failures otherwise.
    fn transition_delivery(
        &self,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
        expected_state: DeliveryState,
        next_state: DeliveryState,
        evidence: Option<&DeliveryEvidence>,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Appends delivery evidence without changing state.
    ///
    /// # Errors
    /// Returns conflict for reused logical order with different evidence and explicit storage failures.
    fn record_delivery_evidence(
        &self,
        evidence: &DeliveryEvidence,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one scoped `DeliveryAttempt` when present.
    ///
    /// # Errors
    /// Returns explicit storage or corrupt-state failures.
    fn delivery_attempt(
        &self,
        scope: &TenantScope,
        delivery_id: &DeliveryId,
    ) -> Result<Option<DeliveryAttempt>, DurableStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAppendStatus {
    Appended,
    Duplicate,
}

/// Durable canonical event journal capability.
pub trait EventJournalStore: StorageProvider {
    /// Appends or deduplicates a canonical event.
    ///
    /// # Errors
    /// Returns explicit validation/conflict/storage failures. Reusing one
    /// scoped event ID with different semantics is a conflict.
    fn append_event(&self, event: &EventEnvelope) -> Result<EventAppendStatus, DurableStoreError>;
}

/// Durable terminal-outcome linkage for accepted commands.
pub trait CommandOutcomeStore: EventJournalStore {
    /// Atomically appends/deduplicates a terminal Event and links it to one
    /// previously accepted Command. This records UCR processing state only; it
    /// does not prove an arbitrary external side effect happened exactly once.
    ///
    /// # Errors
    /// Fails if the command was not accepted in the same scope, causation does
    /// not reference that command, or a different terminal event already won.
    fn record_terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError>;

    /// Returns the terminal event linked to a command, if any.
    ///
    /// # Errors
    /// Returns explicit storage failures; absence is not an error.
    fn terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
    ) -> Result<Option<EventId>, DurableStoreError>;
}

#[cfg(test)]
mod tests {
    use ucr_model::{EndpointAddress, EndpointId, OpaqueId};

    use super::RouteCandidate;

    #[test]
    fn route_debug_does_not_disclose_address_material() {
        let route = RouteCandidate {
            endpoint_id: EndpointId::from_opaque(OpaqueId::new("endpoint-a").expect("endpoint id")),
            transport_capability: "ucr.transport.test".to_owned(),
            address: EndpointAddress {
                scheme: "ucr.address.test".to_owned(),
                value: b"route-secret-address".to_vec(),
            },
        };

        let debug = format!("{route:?}");
        assert!(!debug.contains("route-secret-address"));
        assert!(debug.contains("<opaque>"));
    }
}

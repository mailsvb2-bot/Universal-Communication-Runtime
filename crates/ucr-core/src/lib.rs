#![forbid(unsafe_code)]

mod authorized_runtime;
mod id;
mod service_auth;

use ucr_model::{
    AntiEntropyCursor, AntiEntropyPage, AuthorizationRequest, CapabilityDescriptor,
    CommandEnvelope, CommandId, CommunicationIntent, ConversationId, ConversationRecord,
    DeliveryAttempt, DeliveryEvidence, DeliveryId, DeliveryState, DeviceId, EndpointAddress,
    EndpointId, EventEnvelope, EventId, EventReconciliation, EventSummary, IdentityId, KeyId,
    MessageEnvelope, MessageId, PermissionGrant, PublicKeyDescriptor, RecoveryPlan, RecoveryPlanId,
    ScopedPrincipal, ServiceCredentialId, ServiceCredentialRecord, SessionId, SyncCheckpoint,
    SyncSession, SyncState, TenantScope, TrustedSigningKeyRecord,
};
use ucr_protocol::{CanonicalError, CommandReceipt};

pub use authorized_runtime::AuthorizedDurableRuntime;
pub use id::{IdGenerationError, generate_opaque_id};
pub use service_auth::{
    ServiceAuthenticationError, ServiceCredentialIssueError, ServiceCredentialSecret,
    authenticate_service_principal, issue_service_credential,
};

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

/// Durable owner for explicit permission grants. Authentication credentials and
/// audit history deliberately remain separate capabilities.
pub trait PermissionGrantStore: StorageProvider {
    /// Adds one canonical grant. Repeating the identical grant is idempotent.
    ///
    /// # Errors
    /// Rejects malformed grants and explicit storage failures.
    fn grant_permission(&self, grant: &PermissionGrant) -> Result<(), DurableStoreError>;

    /// Removes one exact canonical grant. Repeating removal is idempotent.
    ///
    /// # Errors
    /// Rejects malformed grants and explicit storage failures.
    fn revoke_permission(&self, grant: &PermissionGrant) -> Result<(), DurableStoreError>;

    /// Returns all persisted grants for one exact scoped principal.
    ///
    /// # Errors
    /// Returns explicit storage/corruption failures.
    fn permission_grants_for(
        &self,
        subject: &ScopedPrincipal,
    ) -> Result<Vec<PermissionGrant>, DurableStoreError>;
}

/// Durable authentication-credential lifecycle for canonical Service Account principals.
///
/// This capability stores only credential metadata and a one-way digest. Plaintext
/// authentication secrets are never persisted here and permission grants remain a
/// separate authorization capability.
pub trait ServiceCredentialStore: StorageProvider {
    /// Persists the first active credential record. Identical retries are idempotent.
    ///
    /// # Errors
    /// Rejects malformed records, ID reuse, or storage failures.
    fn provision_service_credential(
        &self,
        record: &ServiceCredentialRecord,
    ) -> Result<(), DurableStoreError>;

    /// Irreversibly revokes one expected credential. Repeating revocation is idempotent.
    ///
    /// # Errors
    /// Rejects scope mismatches or explicit storage failures.
    fn revoke_service_credential(
        &self,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<(), DurableStoreError>;

    /// Resolves credential metadata for one exact scope. Absence is not an error.
    ///
    /// # Errors
    /// Returns explicit storage/corruption failures.
    fn service_credential(
        &self,
        scope: &TenantScope,
        credential_id: &ServiceCredentialId,
    ) -> Result<Option<ServiceCredentialRecord>, DurableStoreError>;
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
/// Durable trust/lifecycle owner for public Ed25519 device signing keys.
///
/// This store owns key trust state only. Device lifecycle remains a separate
/// canonical owner and must not be duplicated here.
pub trait TrustedSigningKeyStore: StorageProvider {
    /// Provisions the first active trusted signing key for one exact scope/device.
    /// Repeating the identical active record is idempotent; a conflicting or
    /// previously revoked key cannot be silently adopted or reactivated.
    ///
    /// # Errors
    /// Returns validation, conflict, or storage failures.
    fn provision_trusted_signing_key(
        &self,
        scope: &TenantScope,
        descriptor: &PublicKeyDescriptor,
    ) -> Result<(), DurableStoreError>;

    /// Atomically revokes the expected active key and installs its replacement
    /// for the same exact scope/device.
    ///
    /// # Errors
    /// Returns conflict for stale expected state, scope/device/key reuse, or storage failures.
    fn rotate_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
        replacement: &PublicKeyDescriptor,
    ) -> Result<(), DurableStoreError>;

    /// Revokes the expected active key. Repeating the same revocation is idempotent.
    /// Revocation never reactivates an earlier key.
    ///
    /// # Errors
    /// Returns conflict for a different active key or explicit storage failures.
    fn revoke_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
    ) -> Result<(), DurableStoreError>;

    /// Loads one trusted key record, including revoked historical records.
    ///
    /// # Errors
    /// Returns explicit storage/corruption failures; absence is not an error.
    fn trusted_signing_key(
        &self,
        scope: &TenantScope,
        key_id: &KeyId,
    ) -> Result<Option<TrustedSigningKeyRecord>, DurableStoreError>;

    /// Loads the currently active trusted signing key for one exact scope/device.
    ///
    /// # Errors
    /// Returns explicit storage/corruption failures; absence is not an error.
    fn active_trusted_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<Option<PublicKeyDescriptor>, DurableStoreError>;
}

/// Authorization-enforcing façade for trusted signing-key mutations.
///
/// Raw key storage remains an internal persistence capability. External/runtime
/// callers use this boundary with an already authenticated [`ScopedPrincipal`].
#[derive(Debug)]
pub struct AuthorizedTrustedSigningKeyMutations<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> AuthorizedTrustedSigningKeyMutations<'a, A, S>
where
    A: AuthorizationEvaluator,
    S: TrustedSigningKeyStore,
{
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }

    /// Authorizes and provisions the first trusted signing key for the scope.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures; denied calls never reach storage.
    pub fn provision(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        descriptor: &PublicKeyDescriptor,
    ) -> Result<(), AuthorizedMutationError> {
        AuthorizedDurableRuntime::new(self.authorization, self.store)
            .provision_trusted_signing_key(subject, scope, descriptor)
    }

    /// Authorizes and atomically rotates the expected trusted signing key.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures; denied calls never reach storage.
    pub fn rotate(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
        replacement: &PublicKeyDescriptor,
    ) -> Result<(), AuthorizedMutationError> {
        AuthorizedDurableRuntime::new(self.authorization, self.store).rotate_trusted_signing_key(
            subject,
            scope,
            device_id,
            expected_current,
            replacement,
        )
    }

    /// Authorizes and revokes the expected trusted signing key.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures; denied calls never reach storage.
    pub fn revoke(
        &self,
        subject: &ScopedPrincipal,
        scope: &TenantScope,
        device_id: &DeviceId,
        expected_current: &KeyId,
    ) -> Result<(), AuthorizedMutationError> {
        AuthorizedDurableRuntime::new(self.authorization, self.store).revoke_trusted_signing_key(
            subject,
            scope,
            device_id,
            expected_current,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedMutationError {
    Authorization(CanonicalError),
    Store(DurableStoreError),
}

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

/// Durable provider-independent Sync session/checkpoint capability.
pub trait SyncStore: StorageProvider {
    /// Persists or deduplicates one canonical sync session in Prepared state.
    ///
    /// # Errors
    /// Returns explicit validation, conflict, or storage failures.
    fn create_sync_session(
        &self,
        session: &SyncSession,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Atomically advances one sync session by expected-state compare-and-swap.
    ///
    /// # Errors
    /// Returns conflict for stale expected state and explicit storage failures.
    fn transition_sync(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        expected_state: SyncState,
        next_state: SyncState,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Appends one monotonic durable resume checkpoint.
    ///
    /// # Errors
    /// Returns conflict for stale/reused generation or explicit storage failures.
    fn record_sync_checkpoint(
        &self,
        checkpoint: &SyncCheckpoint,
    ) -> Result<DurableRecordStatus, DurableStoreError>;

    /// Loads one scoped sync session when present.
    ///
    /// # Errors
    /// Returns explicit storage or corrupt-state failures.
    fn sync_session(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncSession>, DurableStoreError>;

    /// Loads the latest checkpoint for one scoped sync session.
    ///
    /// # Errors
    /// Returns explicit storage or corrupt-state failures.
    fn latest_sync_checkpoint(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<SyncCheckpoint>, DurableStoreError>;
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

/// Event-level Anti-Entropy capability bound to durable Sync sessions.
///
/// Implementations may use private local ordering to resume snapshots, but no
/// storage sequence is canonical or exposed through this interface.
pub trait AntiEntropyStore: EventJournalStore + SyncStore {
    /// Returns one snapshot-bound page of source Event summaries.
    ///
    /// # Errors
    /// Fails closed for invalid session state/selection, cursor binding, or storage errors.
    fn anti_entropy_summary_page(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        cursor: Option<&AntiEntropyCursor>,
        max_items: usize,
    ) -> Result<AntiEntropyPage, DurableStoreError>;

    /// Classifies remote Event summaries as missing, matching, or damaged locally.
    ///
    /// # Errors
    /// Fails closed for invalid session binding or corrupt local Event state.
    fn classify_event_summaries(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        summaries: &[EventSummary],
    ) -> Result<Vec<EventReconciliation>, DurableStoreError>;

    /// Applies one missing Event, suppresses an exact duplicate, and refuses to
    /// overwrite a damaged Event that reuses the same scoped `EventId`.
    ///
    /// # Errors
    /// Returns conflict for damaged state and explicit validation/storage failures otherwise.
    fn reconcile_event(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError>;
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

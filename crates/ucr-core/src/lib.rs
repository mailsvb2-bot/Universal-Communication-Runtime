#![forbid(unsafe_code)]

use ucr_model::{CapabilityDescriptor, CommunicationIntent, TenantScope};

/// A route candidate is transient runtime state, never canonical identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub transport_capability: String,
    pub endpoint_address: Vec<u8>,
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

/// Durable persistence boundary. The concrete local/server stores arrive in a
/// later roadmap phase; the canonical runtime must depend on this boundary,
/// not on direct external-consumer database access.
pub trait DurableStore: core::fmt::Debug + Send + Sync {
    /// Persists an opaque canonical record before a transport attempt.
    ///
    /// # Errors
    /// Must return an explicit failure; silent message loss is forbidden.
    fn persist(&self, scope: &TenantScope, record: &[u8]) -> Result<(), DurableStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableStoreError {
    Full,
    Corrupt,
    Unavailable,
    PermissionDenied,
    Internal,
}

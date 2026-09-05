use std::collections::BTreeSet;

use ucr_model::CommunicationIntent;

use crate::{
    DEFAULT_MAX_PAYLOAD_LEN, ExtensionError, canonical_protocol_extensions,
    validate_namespaced_identifier,
};

pub const MAX_INTENT_TRANSPORT_CONSTRAINTS: usize = 256;
pub const MAX_INTENT_POLICY_VALUE_LEN: usize = 1024;
pub const MAX_INTENT_IDEMPOTENCY_KEY_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    PayloadTooLarge,
    PolicyValueTooLong,
    IdempotencyKeyTooLong,
    TooManyTransportConstraints,
    InvalidTransportCapability,
    DuplicateTransportCapability,
    ConflictingTransportCapability,
    InvalidExtension,
    DuplicateExtension,
    TooManyExtensions,
    ExtensionPayloadTooLarge,
}

/// Validates a provider-independent Communication Intent before policy evaluation.
///
/// # Errors
/// Rejects unsafe payload sizes, malformed or contradictory transport constraints,
/// and malformed or over-budget protocol extensions.
pub fn validate_communication_intent(intent: &CommunicationIntent) -> Result<(), IntentError> {
    let payload_len =
        u32::try_from(intent.payload.len()).map_err(|_| IntentError::PayloadTooLarge)?;
    if payload_len > DEFAULT_MAX_PAYLOAD_LEN {
        return Err(IntentError::PayloadTooLarge);
    }
    for value in [
        intent.constraints.privacy_profile.as_deref(),
        intent.constraints.region_constraint.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > MAX_INTENT_POLICY_VALUE_LEN {
            return Err(IntentError::PolicyValueTooLong);
        }
    }
    if intent
        .correlation
        .idempotency_key
        .as_deref()
        .is_some_and(|value| value.len() > MAX_INTENT_IDEMPOTENCY_KEY_LEN)
    {
        return Err(IntentError::IdempotencyKeyTooLong);
    }
    let total_constraints = intent
        .constraints
        .allowed_transport_capabilities
        .len()
        .checked_add(intent.constraints.forbidden_transport_capabilities.len())
        .ok_or(IntentError::TooManyTransportConstraints)?;
    if total_constraints > MAX_INTENT_TRANSPORT_CONSTRAINTS {
        return Err(IntentError::TooManyTransportConstraints);
    }
    let allowed =
        validate_transport_capabilities(&intent.constraints.allowed_transport_capabilities)?;
    let forbidden =
        validate_transport_capabilities(&intent.constraints.forbidden_transport_capabilities)?;
    if allowed.iter().any(|value| forbidden.contains(value)) {
        return Err(IntentError::ConflictingTransportCapability);
    }
    canonical_protocol_extensions(&intent.extensions).map_err(map_extension_error)?;
    Ok(())
}

/// Returns the deterministic semantic form used before policy evaluation.
///
/// Transport allow/forbid ordering and extension ordering are not semantic.
///
/// # Errors
/// Returns the same fail-closed errors as [`validate_communication_intent`].
pub fn canonical_communication_intent(
    intent: &CommunicationIntent,
) -> Result<CommunicationIntent, IntentError> {
    validate_communication_intent(intent)?;
    let mut canonical = intent.clone();
    canonical.constraints.allowed_transport_capabilities.sort();
    canonical
        .constraints
        .forbidden_transport_capabilities
        .sort();
    canonical.extensions =
        canonical_protocol_extensions(&intent.extensions).map_err(map_extension_error)?;
    Ok(canonical)
}

fn validate_transport_capabilities(values: &[String]) -> Result<BTreeSet<&str>, IntentError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_namespaced_identifier(value)
            .map_err(|_| IntentError::InvalidTransportCapability)?;
        if !seen.insert(value.as_str()) {
            return Err(IntentError::DuplicateTransportCapability);
        }
    }
    Ok(seen)
}

const fn map_extension_error(error: ExtensionError) -> IntentError {
    match error {
        ExtensionError::InvalidNamespace | ExtensionError::UnsupportedCritical => {
            IntentError::InvalidExtension
        }
        ExtensionError::DuplicateExtension => IntentError::DuplicateExtension,
        ExtensionError::TooManyExtensions => IntentError::TooManyExtensions,
        ExtensionError::PayloadTooLarge => IntentError::ExtensionPayloadTooLarge,
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        CommunicationIntent, CorrelationContext, IdentityId, IntentConstraints, IntentId, OpaqueId,
        ProtocolExtension, TenantId, TenantScope,
    };

    use super::{IntentError, canonical_communication_intent, validate_communication_intent};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn intent() -> CommunicationIntent {
        CommunicationIntent {
            intent_id: IntentId::from_opaque(oid("intent-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: None,
            },
            target_identity_id: IdentityId::from_opaque(oid("identity-a")),
            payload: b"hello".to_vec(),
            constraints: IntentConstraints {
                allowed_transport_capabilities: vec!["ucr.transport.direct".to_owned()],
                forbidden_transport_capabilities: vec!["ucr.transport.relay".to_owned()],
                privacy_profile: Some("ucr.privacy.private".to_owned()),
                region_constraint: None,
                max_cost_microunits: None,
                priority_class: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: None,
                idempotency_key: None,
            },
            extensions: Vec::new(),
        }
    }

    #[test]
    fn intent_preserves_correlation_and_canonical_extension_payloads() {
        let mut value = intent();
        value.extensions = vec![
            ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: false,
                payload: b"a".to_vec(),
            },
        ];
        let canonical = canonical_communication_intent(&value).expect("canonical intent");
        assert_eq!(canonical.correlation, value.correlation);
        assert_eq!(canonical.extensions[0].name, "ucr.example.a");
    }

    #[test]
    fn durable_policy_and_idempotency_budgets_fail_closed() {
        let mut privacy = intent();
        privacy.constraints.privacy_profile =
            Some("x".repeat(super::MAX_INTENT_POLICY_VALUE_LEN + 1));
        assert_eq!(
            validate_communication_intent(&privacy),
            Err(IntentError::PolicyValueTooLong)
        );

        let mut region = intent();
        region.constraints.region_constraint =
            Some("x".repeat(super::MAX_INTENT_POLICY_VALUE_LEN + 1));
        assert_eq!(
            validate_communication_intent(&region),
            Err(IntentError::PolicyValueTooLong)
        );

        let mut idempotency = intent();
        idempotency.correlation.idempotency_key =
            Some("x".repeat(super::MAX_INTENT_IDEMPOTENCY_KEY_LEN + 1));
        assert_eq!(
            validate_communication_intent(&idempotency),
            Err(IntentError::IdempotencyKeyTooLong)
        );
    }

    #[test]
    fn contradictory_or_duplicate_transport_constraints_fail_closed() {
        let mut value = intent();
        value
            .constraints
            .forbidden_transport_capabilities
            .push("ucr.transport.direct".to_owned());
        assert_eq!(
            validate_communication_intent(&value),
            Err(IntentError::ConflictingTransportCapability)
        );

        let mut duplicate = intent();
        duplicate
            .constraints
            .allowed_transport_capabilities
            .push("ucr.transport.direct".to_owned());
        assert_eq!(
            validate_communication_intent(&duplicate),
            Err(IntentError::DuplicateTransportCapability)
        );
    }
}

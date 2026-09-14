use ucr_model::{EndpointKind, FederationPeerRecord, FederationTrustState};

use crate::validate_namespaced_identifier;

pub const FEDERATION_CAPABILITY: &str = "ucr.federation";
pub const FEDERATION_SYNC_CAPABILITY: &str = "ucr.sync";
pub const MAX_FEDERATION_ALLOWED_CAPABILITIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationProtocolError {
    InvalidEndpointKind,
    InvalidGeneration,
    InvalidCapability,
    TooManyCapabilities,
    DuplicateCapability,
    InvalidTransition,
    CredentialUnchanged,
}

/// Validates one durable peer-policy record without granting federation authority.
///
/// # Errors
/// Rejects non-node endpoints, malformed capabilities, duplicate capabilities and generation zero.
pub fn validate_federation_peer(
    record: &FederationPeerRecord,
) -> Result<(), FederationProtocolError> {
    if !matches!(
        record.remote_endpoint_kind,
        EndpointKind::PersonalNode | EndpointKind::OrganizationNode
    ) {
        return Err(FederationProtocolError::InvalidEndpointKind);
    }
    if record.generation == 0 {
        return Err(FederationProtocolError::InvalidGeneration);
    }
    if record.allowed_capabilities.len() > MAX_FEDERATION_ALLOWED_CAPABILITIES {
        return Err(FederationProtocolError::TooManyCapabilities);
    }
    let mut canonical = record.allowed_capabilities.clone();
    for capability in &canonical {
        validate_namespaced_identifier(capability)
            .map_err(|_| FederationProtocolError::InvalidCapability)?;
    }
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(FederationProtocolError::DuplicateCapability);
    }
    Ok(())
}

/// Returns a deterministic capability ordering for durable equality/idempotency.
///
/// # Errors
/// Returns the same validation failures as [`validate_federation_peer`].
pub fn canonical_federation_peer(
    record: &FederationPeerRecord,
) -> Result<FederationPeerRecord, FederationProtocolError> {
    validate_federation_peer(record)?;
    let mut canonical = record.clone();
    canonical.allowed_capabilities.sort();
    Ok(canonical)
}
/// Validates a state-only trust transition. Credential rotation is a separate explicit operation.
///
/// # Errors
/// Rejects skipped trust elevation, silent unblocking and resurrection of revoked credentials.
pub const fn validate_federation_transition(
    current: FederationTrustState,
    next: FederationTrustState,
) -> Result<(), FederationProtocolError> {
    use FederationTrustState::{Authenticated, Authorized, Blocked, Known, Revoked, Trusted};
    if matches!(
        (current, next),
        (Known, Authenticated)
            | (Authenticated | Trusted, Authorized)
            | (Authorized, Trusted)
            | (
                Known | Authenticated | Authorized | Trusted,
                Revoked | Blocked
            )
    ) {
        Ok(())
    } else {
        Err(FederationProtocolError::InvalidTransition)
    }
}

/// Validates explicit credential rotation/recovery. Rotation always returns trust to `Known`.
///
/// # Errors
/// Rejects unchanged credentials and replacement records that alter the federation relationship.
pub fn validate_federation_credential_rotation(
    current: &FederationPeerRecord,
    replacement: &FederationPeerRecord,
) -> Result<(), FederationProtocolError> {
    validate_federation_peer(current)?;
    validate_federation_peer(replacement)?;
    if current.local_scope != replacement.local_scope
        || current.remote_scope != replacement.remote_scope
        || current.local_endpoint_id != replacement.local_endpoint_id
        || current.remote_endpoint_id != replacement.remote_endpoint_id
        || current.remote_endpoint_kind != replacement.remote_endpoint_kind
        || current.allowed_capabilities != replacement.allowed_capabilities
        || replacement.state != FederationTrustState::Known
        || replacement.generation != current.generation.saturating_add(1)
    {
        return Err(FederationProtocolError::InvalidTransition);
    }
    if current.expected_device_id == replacement.expected_device_id
        && current.expected_signing_key_id == replacement.expected_signing_key_id
    {
        return Err(FederationProtocolError::CredentialUnchanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        DeviceId, EndpointId, EndpointKind, FederationPeerRecord, FederationTrustState, KeyId,
        OpaqueId, TenantId, TenantScope,
    };

    use super::{
        FederationProtocolError, canonical_federation_peer,
        validate_federation_credential_rotation, validate_federation_transition,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn record() -> FederationPeerRecord {
        FederationPeerRecord {
            local_scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("local")),
                namespace_id: None,
            },
            remote_scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("remote")),
                namespace_id: None,
            },
            local_endpoint_id: EndpointId::from_opaque(oid("local-node")),
            remote_endpoint_id: EndpointId::from_opaque(oid("remote-node")),
            remote_endpoint_kind: EndpointKind::PersonalNode,
            expected_device_id: DeviceId::from_opaque(oid("device")),
            expected_signing_key_id: KeyId::from_opaque(oid("key")),
            allowed_capabilities: vec!["ucr.sync".to_owned(), "ucr.message.text".to_owned()],
            state: FederationTrustState::Known,
            generation: 1,
        }
    }

    #[test]
    fn canonical_peer_sorts_capabilities_and_rejects_duplicates() {
        let canonical = canonical_federation_peer(&record()).expect("canonical");
        assert_eq!(
            canonical.allowed_capabilities,
            ["ucr.message.text", "ucr.sync"]
        );
        let mut duplicate = record();
        duplicate.allowed_capabilities = vec!["ucr.sync".to_owned(), "ucr.sync".to_owned()];
        assert_eq!(
            canonical_federation_peer(&duplicate),
            Err(FederationProtocolError::DuplicateCapability)
        );
    }

    #[test]
    fn trust_state_cannot_skip_authentication_or_resurrect_terminal_state() {
        assert_eq!(
            validate_federation_transition(
                FederationTrustState::Known,
                FederationTrustState::Authorized,
            ),
            Err(FederationProtocolError::InvalidTransition)
        );
        assert_eq!(
            validate_federation_transition(
                FederationTrustState::Blocked,
                FederationTrustState::Trusted,
            ),
            Err(FederationProtocolError::InvalidTransition)
        );
    }
    #[test]
    fn credential_rotation_requires_change_and_resets_trust_to_known() {
        let mut current = canonical_federation_peer(&record()).expect("current");
        current.state = FederationTrustState::Trusted;
        current.generation = 4;
        let mut replacement = current.clone();
        replacement.expected_signing_key_id = KeyId::from_opaque(oid("new-key"));
        replacement.state = FederationTrustState::Known;
        replacement.generation = 5;
        assert_eq!(
            validate_federation_credential_rotation(&current, &replacement),
            Ok(())
        );
        replacement.expected_signing_key_id = current.expected_signing_key_id.clone();
        assert_eq!(
            validate_federation_credential_rotation(&current, &replacement),
            Err(FederationProtocolError::CredentialUnchanged)
        );
    }
}

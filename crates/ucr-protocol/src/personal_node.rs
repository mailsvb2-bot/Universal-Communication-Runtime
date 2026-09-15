use sha2::{Digest, Sha256};
use ucr_model::{
    EndpointKind, PersonalNodeObject, PersonalNodeProfile, PersonalNodeService, PersonalNodeState,
};

use crate::{DEFAULT_MAX_PAYLOAD_LEN, validate_namespaced_identifier};

pub const PERSONAL_NODE_SYNC_CAPABILITY: &str = "ucr.personal_node.sync";
pub const PERSONAL_NODE_MAILBOX_CAPABILITY: &str = "ucr.personal_node.mailbox";
pub const PERSONAL_NODE_RELAY_CAPABILITY: &str = "ucr.personal_node.relay";
pub const PERSONAL_NODE_CACHE_CAPABILITY: &str = "ucr.personal_node.cache";
pub const PERSONAL_NODE_BRIDGE_CAPABILITY: &str = "ucr.personal_node.bridge";
pub const MAX_PERSONAL_NODE_OBJECTS_PER_LIST: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonalNodeProtocolError {
    InvalidEndpointKind,
    InvalidGeneration,
    NoServices,
    DuplicateService,
    InvalidCapacity,
    InvalidTransition,
    InvalidEncryptionScheme,
    InvalidCiphertext,
    InvalidDigest,
    InvalidTimestamp,
    InvalidExpiry,
}

/// Canonicalizes one validated Personal Node profile.
///
/// # Errors
/// Returns a [`PersonalNodeProtocolError`] when the endpoint kind, generation,
/// service set, or service-bound capacities violate the Phase-37 contract.
pub fn canonical_personal_node_profile(
    profile: &PersonalNodeProfile,
) -> Result<PersonalNodeProfile, PersonalNodeProtocolError> {
    validate_personal_node_profile(profile)?;
    let mut canonical = profile.clone();
    canonical.services.sort_unstable();
    Ok(canonical)
}

/// Validates one Personal Node profile without mutating it.
///
/// # Errors
/// Returns a [`PersonalNodeProtocolError`] for non-PersonalNode endpoints,
/// zero generations, invalid/duplicate services, or inconsistent capacities.
pub fn validate_personal_node_profile(
    profile: &PersonalNodeProfile,
) -> Result<(), PersonalNodeProtocolError> {
    if profile.endpoint_kind != EndpointKind::PersonalNode {
        return Err(PersonalNodeProtocolError::InvalidEndpointKind);
    }
    if profile.generation == 0 {
        return Err(PersonalNodeProtocolError::InvalidGeneration);
    }
    if profile.services.is_empty() {
        return Err(PersonalNodeProtocolError::NoServices);
    }
    let mut services = profile.services.clone();
    services.sort_unstable();
    if services.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PersonalNodeProtocolError::DuplicateService);
    }
    validate_service_capacity(
        &services,
        PersonalNodeService::EncryptedMailbox,
        profile.mailbox_capacity_bytes,
    )?;
    validate_service_capacity(
        &services,
        PersonalNodeService::Cache,
        profile.cache_capacity_bytes,
    )
}
/// Validates one explicit Personal Node lifecycle transition.
///
/// # Errors
/// Returns [`PersonalNodeProtocolError::InvalidTransition`] for same-state or
/// otherwise unsupported transitions.
pub fn validate_personal_node_transition(
    current: PersonalNodeState,
    next: PersonalNodeState,
) -> Result<(), PersonalNodeProtocolError> {
    match (current, next) {
        (PersonalNodeState::Active, PersonalNodeState::Disabled)
        | (PersonalNodeState::Disabled, PersonalNodeState::Active) => Ok(()),
        _ => Err(PersonalNodeProtocolError::InvalidTransition),
    }
}

/// Canonicalizes one validated encrypted Personal Node object.
///
/// # Errors
/// Returns a [`PersonalNodeProtocolError`] when encryption metadata, ciphertext,
/// integrity digest, or temporal bounds violate the object contract.
pub fn canonical_personal_node_object(
    object: &PersonalNodeObject,
) -> Result<PersonalNodeObject, PersonalNodeProtocolError> {
    validate_personal_node_object(object)?;
    Ok(object.clone())
}

/// Validates one opaque encrypted mailbox/cache object.
///
/// # Errors
/// Returns a [`PersonalNodeProtocolError`] for malformed encryption identifiers,
/// empty/oversized ciphertext, digest mismatch, or invalid creation/expiry time.
pub fn validate_personal_node_object(
    object: &PersonalNodeObject,
) -> Result<(), PersonalNodeProtocolError> {
    validate_namespaced_identifier(&object.encryption_scheme)
        .map_err(|_| PersonalNodeProtocolError::InvalidEncryptionScheme)?;
    if object.ciphertext.is_empty() || object.ciphertext.len() > DEFAULT_MAX_PAYLOAD_LEN as usize {
        return Err(PersonalNodeProtocolError::InvalidCiphertext);
    }
    if object.created_at_unix_ms < 0 {
        return Err(PersonalNodeProtocolError::InvalidTimestamp);
    }
    if object
        .expires_at_unix_ms
        .is_some_and(|expires| expires <= object.created_at_unix_ms)
    {
        return Err(PersonalNodeProtocolError::InvalidExpiry);
    }
    let digest: [u8; 32] = Sha256::digest(&object.ciphertext).into();
    if digest != object.ciphertext_sha256 {
        return Err(PersonalNodeProtocolError::InvalidDigest);
    }
    Ok(())
}

fn validate_service_capacity(
    services: &[PersonalNodeService],
    service: PersonalNodeService,
    capacity: u64,
) -> Result<(), PersonalNodeProtocolError> {
    let enabled = services.binary_search(&service).is_ok();
    if (enabled && capacity == 0) || (!enabled && capacity != 0) {
        return Err(PersonalNodeProtocolError::InvalidCapacity);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use ucr_model::{
        EndpointId, EndpointKind, OpaqueId, PersonalNodeObject, PersonalNodeObjectId,
        PersonalNodeObjectKind, PersonalNodeProfile, PersonalNodeService, PersonalNodeState,
        TenantId, TenantScope,
    };

    use super::{
        PersonalNodeProtocolError, canonical_personal_node_object, canonical_personal_node_profile,
        validate_personal_node_transition,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(id("tenant-a")),
            namespace_id: None,
        }
    }
    #[test]
    fn profile_is_canonical_and_capacity_is_service_bound() {
        let profile = PersonalNodeProfile {
            scope: scope(),
            endpoint_id: EndpointId::from_opaque(id("node-a")),
            endpoint_kind: EndpointKind::PersonalNode,
            services: vec![
                PersonalNodeService::Relay,
                PersonalNodeService::EncryptedMailbox,
            ],
            state: PersonalNodeState::Active,
            generation: 1,
            mailbox_capacity_bytes: 1024,
            cache_capacity_bytes: 0,
        };
        let canonical = canonical_personal_node_profile(&profile).expect("canonical");
        assert_eq!(
            canonical.services,
            vec![
                PersonalNodeService::EncryptedMailbox,
                PersonalNodeService::Relay,
            ]
        );
        let mut invalid = profile;
        invalid.cache_capacity_bytes = 1;
        assert_eq!(
            canonical_personal_node_profile(&invalid),
            Err(PersonalNodeProtocolError::InvalidCapacity)
        );
    }
    #[test]
    fn encrypted_object_requires_exact_digest_and_future_expiry() {
        let ciphertext = b"encrypted".to_vec();
        let object = PersonalNodeObject {
            object_id: PersonalNodeObjectId::from_opaque(id("object-a")),
            scope: scope(),
            endpoint_id: EndpointId::from_opaque(id("node-a")),
            kind: PersonalNodeObjectKind::Mailbox,
            encryption_scheme: "ucr.crypto.xchacha20poly1305.v1".to_owned(),
            ciphertext_sha256: Sha256::digest(&ciphertext).into(),
            ciphertext,
            created_at_unix_ms: 10,
            expires_at_unix_ms: Some(20),
        };
        canonical_personal_node_object(&object).expect("valid");
        let mut invalid = object;
        invalid.ciphertext_sha256 = [0; 32];
        assert_eq!(
            canonical_personal_node_object(&invalid),
            Err(PersonalNodeProtocolError::InvalidDigest)
        );
    }

    #[test]
    fn lifecycle_has_no_implicit_same_state_generation_bump() {
        validate_personal_node_transition(PersonalNodeState::Active, PersonalNodeState::Disabled)
            .expect("disable");
        assert_eq!(
            validate_personal_node_transition(PersonalNodeState::Active, PersonalNodeState::Active),
            Err(PersonalNodeProtocolError::InvalidTransition)
        );
    }
}

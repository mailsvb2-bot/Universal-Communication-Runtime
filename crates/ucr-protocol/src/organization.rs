use ucr_model::{
    EndpointKind, OrganizationManagedDeviceBinding, OrganizationManagedIdentityBinding,
    OrganizationModeProfile, OrganizationModeState, PrincipalKind,
};

pub const ORGANIZATION_PRIVATE_DISCOVERY_CAPABILITY: &str = "ucr.organization.discovery.private";
pub const ORGANIZATION_PRIVATE_RELAY_CAPABILITY: &str = "ucr.organization.relay.private";
pub const ORGANIZATION_PRIVATE_SFU_CAPABILITY: &str = "ucr.organization.sfu.private";
pub const ORGANIZATION_PRIVATE_BRIDGE_CAPABILITY: &str = "ucr.organization.bridge.private";
pub const ORGANIZATION_MANAGED_IDENTITIES_CAPABILITY: &str = "ucr.organization.identities.managed";
pub const ORGANIZATION_MANAGED_DEVICES_CAPABILITY: &str = "ucr.organization.devices.managed";
pub const MAX_ORGANIZATION_DIRECTORY_ITEMS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationProtocolError {
    NamespaceRequired,
    InvalidOrganizationPrincipal,
    InvalidEndpointKind,
    InvalidGeneration,
    NoServices,
    DuplicateService,
    InvalidTransition,
}
/// Canonicalizes one validated Organization Mode profile.
///
/// # Errors
/// Returns an explicit protocol error for invalid namespace, principal, endpoint, generation or services.
pub fn canonical_organization_mode_profile(
    profile: &OrganizationModeProfile,
) -> Result<OrganizationModeProfile, OrganizationProtocolError> {
    validate_organization_mode_profile(profile)?;
    let mut canonical = profile.clone();
    canonical.services.sort_unstable();
    Ok(canonical)
}

/// Validates one Organization Mode profile without mutating it.
///
/// # Errors
/// Returns an explicit protocol error when the profile violates the Phase-38 contract.
pub fn validate_organization_mode_profile(
    profile: &OrganizationModeProfile,
) -> Result<(), OrganizationProtocolError> {
    if profile.scope.namespace_id.is_none() {
        return Err(OrganizationProtocolError::NamespaceRequired);
    }
    if profile.organization.kind != PrincipalKind::Organization {
        return Err(OrganizationProtocolError::InvalidOrganizationPrincipal);
    }
    if profile.endpoint_kind != EndpointKind::OrganizationNode {
        return Err(OrganizationProtocolError::InvalidEndpointKind);
    }
    if profile.generation == 0 {
        return Err(OrganizationProtocolError::InvalidGeneration);
    }
    if profile.services.is_empty() {
        return Err(OrganizationProtocolError::NoServices);
    }
    let mut services = profile.services.clone();
    services.sort_unstable();
    if services.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(OrganizationProtocolError::DuplicateService);
    }
    Ok(())
}

/// Validates one explicit Organization Mode lifecycle transition.
///
/// # Errors
/// Rejects same-state and unsupported transitions.
pub fn validate_organization_mode_transition(
    current: OrganizationModeState,
    next: OrganizationModeState,
) -> Result<(), OrganizationProtocolError> {
    match (current, next) {
        (OrganizationModeState::Active, OrganizationModeState::Disabled)
        | (OrganizationModeState::Disabled, OrganizationModeState::Active) => Ok(()),
        _ => Err(OrganizationProtocolError::InvalidTransition),
    }
}
/// Validates one organization-to-canonical-Identity association.
///
/// # Errors
/// Requires an exact namespace scope and an Organization principal.
pub fn validate_organization_managed_identity_binding(
    binding: &OrganizationManagedIdentityBinding,
) -> Result<(), OrganizationProtocolError> {
    validate_binding_scope_and_principal(&binding.scope, binding.organization.kind)
}

/// Validates one organization-to-canonical-Device association.
///
/// # Errors
/// Requires an exact namespace scope and an Organization principal.
pub fn validate_organization_managed_device_binding(
    binding: &OrganizationManagedDeviceBinding,
) -> Result<(), OrganizationProtocolError> {
    validate_binding_scope_and_principal(&binding.scope, binding.organization.kind)
}

fn validate_binding_scope_and_principal(
    scope: &ucr_model::TenantScope,
    kind: PrincipalKind,
) -> Result<(), OrganizationProtocolError> {
    if scope.namespace_id.is_none() {
        return Err(OrganizationProtocolError::NamespaceRequired);
    }
    if kind != PrincipalKind::Organization {
        return Err(OrganizationProtocolError::InvalidOrganizationPrincipal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        EndpointId, EndpointKind, NamespaceId, OpaqueId, OrganizationModeProfile,
        OrganizationModeState, OrganizationService, PrincipalId, PrincipalKind, PrincipalRef,
        TenantId, TenantScope,
    };

    use super::{
        OrganizationProtocolError, canonical_organization_mode_profile,
        validate_organization_mode_transition,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-a")),
            namespace_id: Some(NamespaceId::from_opaque(oid("org-a"))),
        }
    }
    fn organization(kind: PrincipalKind) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid("organization-a")),
            kind,
        }
    }

    fn profile() -> OrganizationModeProfile {
        OrganizationModeProfile {
            scope: scope(),
            organization: organization(PrincipalKind::Organization),
            endpoint_id: EndpointId::from_opaque(oid("organization-node-a")),
            endpoint_kind: EndpointKind::OrganizationNode,
            services: vec![
                OrganizationService::ManagedDevices,
                OrganizationService::PrivateDiscovery,
                OrganizationService::ManagedIdentities,
            ],
            state: OrganizationModeState::Active,
            generation: 1,
        }
    }

    #[test]
    fn profile_is_exact_namespace_organization_node_and_canonical() {
        let canonical = canonical_organization_mode_profile(&profile()).expect("canonical");
        assert_eq!(
            canonical.services,
            vec![
                OrganizationService::PrivateDiscovery,
                OrganizationService::ManagedIdentities,
                OrganizationService::ManagedDevices,
            ]
        );
        let mut no_namespace = profile();
        no_namespace.scope.namespace_id = None;
        assert_eq!(
            canonical_organization_mode_profile(&no_namespace),
            Err(OrganizationProtocolError::NamespaceRequired)
        );
        let mut wrong_principal = profile();
        wrong_principal.organization = organization(PrincipalKind::Person);
        assert_eq!(
            canonical_organization_mode_profile(&wrong_principal),
            Err(OrganizationProtocolError::InvalidOrganizationPrincipal)
        );
        let mut wrong_endpoint = profile();
        wrong_endpoint.endpoint_kind = EndpointKind::PersonalNode;
        assert_eq!(
            canonical_organization_mode_profile(&wrong_endpoint),
            Err(OrganizationProtocolError::InvalidEndpointKind)
        );
    }

    #[test]
    fn lifecycle_has_no_implicit_same_state_generation_bump() {
        validate_organization_mode_transition(
            OrganizationModeState::Active,
            OrganizationModeState::Disabled,
        )
        .expect("disable");
        assert_eq!(
            validate_organization_mode_transition(
                OrganizationModeState::Active,
                OrganizationModeState::Active,
            ),
            Err(OrganizationProtocolError::InvalidTransition)
        );
    }
}

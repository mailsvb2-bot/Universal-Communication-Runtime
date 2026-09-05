use std::collections::BTreeSet;

use ucr_model::{EndpointAddress, EndpointDescriptor, EndpointKind, ExternalIdentityBinding};

use crate::{CapabilityError, canonical_capability_descriptor, validate_namespaced_identifier};

pub const MAX_ADDRESS_VALUE_LEN: usize = 2 * 1024;
pub const MAX_EXTERNAL_ENTITY_ID_LEN: usize = 2 * 1024;
pub const MAX_ENDPOINT_ADDRESSES: usize = 64;
pub const MAX_ENDPOINT_CAPABILITIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressingError {
    InvalidScheme,
    EmptyAddressValue,
    AddressValueTooLong,
    TooManyAddresses,
    DuplicateAddress,
    TooManyCapabilities,
    DuplicateCapability,
    InvalidCapability,
    InvalidCapabilityExtension,
    CapabilityExtensionBudgetExceeded,
    DeviceEndpointMissingDevice,
    DeviceEndpointMissingIdentity,
    DeviceBindingWithoutIdentity,
    InvalidExternalNamespace,
    EmptyExternalEntityId,
    ExternalEntityIdTooLong,
}
/// Validates one endpoint address without interpreting its opaque value.
///
/// # Errors
/// Rejects invalid schemes and unsafe value sizes.
pub fn validate_endpoint_address(address: &EndpointAddress) -> Result<(), AddressingError> {
    validate_namespaced_identifier(&address.scheme).map_err(|_| AddressingError::InvalidScheme)?;
    if address.value.is_empty() {
        return Err(AddressingError::EmptyAddressValue);
    }
    if address.value.len() > MAX_ADDRESS_VALUE_LEN {
        return Err(AddressingError::AddressValueTooLong);
    }
    Ok(())
}

/// Validates structural invariants of a canonical endpoint descriptor.
///
/// Endpoint addresses are locators only. This function never promotes address
/// material into Identity and never derives Identity from an address.
///
/// # Errors
/// Rejects unsafe address/capability sets and inconsistent device bindings.
pub fn validate_endpoint_descriptor(endpoint: &EndpointDescriptor) -> Result<(), AddressingError> {
    if endpoint.addresses.len() > MAX_ENDPOINT_ADDRESSES {
        return Err(AddressingError::TooManyAddresses);
    }
    if endpoint.capabilities.len() > MAX_ENDPOINT_CAPABILITIES {
        return Err(AddressingError::TooManyCapabilities);
    }
    if endpoint.kind == EndpointKind::Device {
        if endpoint.device_id.is_none() {
            return Err(AddressingError::DeviceEndpointMissingDevice);
        }
        if endpoint.identity_id.is_none() {
            return Err(AddressingError::DeviceEndpointMissingIdentity);
        }
    } else if endpoint.device_id.is_some() && endpoint.identity_id.is_none() {
        return Err(AddressingError::DeviceBindingWithoutIdentity);
    }

    let mut addresses = BTreeSet::new();
    for address in &endpoint.addresses {
        validate_endpoint_address(address)?;
        if !addresses.insert((address.scheme.as_str(), address.value.as_slice())) {
            return Err(AddressingError::DuplicateAddress);
        }
    }

    let mut capabilities = BTreeSet::new();
    for capability in &endpoint.capabilities {
        canonical_capability_descriptor(capability).map_err(map_capability_error)?;
        if !capabilities.insert(capability.id.as_str()) {
            return Err(AddressingError::DuplicateCapability);
        }
    }
    Ok(())
}
const fn map_capability_error(error: CapabilityError) -> AddressingError {
    match error {
        CapabilityError::InvalidIdentifier => AddressingError::InvalidCapability,
        CapabilityError::InvalidExtension | CapabilityError::DuplicateExtension => {
            AddressingError::InvalidCapabilityExtension
        }
        CapabilityError::TooManyExtensions | CapabilityError::ExtensionPayloadTooLarge => {
            AddressingError::CapabilityExtensionBudgetExceeded
        }
        CapabilityError::DuplicateAdvertisement
        | CapabilityError::InvalidRequirement
        | CapabilityError::MissingRequired
        | CapabilityError::RequiredBelowMaturity
        | CapabilityError::CriticalExtensionRequiresExplicitNegotiation => {
            AddressingError::InvalidCapability
        }
    }
}

/// Validates an external-entity to canonical-Identity binding.
///
/// The external namespace and opaque entity ID are locators in an integration
/// namespace. They are never promoted to canonical Identity.
///
/// # Errors
/// Rejects malformed namespaces and unsafe external identifier sizes.
pub fn validate_external_identity_binding(
    binding: &ExternalIdentityBinding,
) -> Result<(), AddressingError> {
    validate_external_identity_binding_key(&binding.external_namespace, &binding.external_entity_id)
}

/// Validates the integration-local external identity key used for durable lookup.
///
/// The key preserves opaque entity bytes exactly. No Unicode, case, provider, or business-domain
/// normalization is applied by Core.
///
/// # Errors
/// Rejects malformed namespaces plus empty or oversized opaque external identifiers.
pub fn validate_external_identity_binding_key(
    external_namespace: &str,
    external_entity_id: &[u8],
) -> Result<(), AddressingError> {
    validate_namespaced_identifier(external_namespace)
        .map_err(|_| AddressingError::InvalidExternalNamespace)?;
    if external_entity_id.is_empty() {
        return Err(AddressingError::EmptyExternalEntityId);
    }
    if external_entity_id.len() > MAX_EXTERNAL_ENTITY_ID_LEN {
        return Err(AddressingError::ExternalEntityIdTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        CapabilityDescriptor, CapabilityMaturity, DeviceId, EndpointAddress, EndpointDescriptor,
        EndpointId, EndpointKind, ExternalIdentityBinding, IdentityId, IntegrationId, OpaqueId,
        TenantId, TenantScope,
    };

    use super::{
        AddressingError, MAX_ADDRESS_VALUE_LEN, validate_endpoint_address,
        validate_endpoint_descriptor, validate_external_identity_binding,
    };
    fn endpoint_id(value: &str) -> EndpointId {
        EndpointId::from_opaque(OpaqueId::new(value).expect("endpoint id"))
    }

    fn identity_id(value: &str) -> IdentityId {
        IdentityId::from_opaque(OpaqueId::new(value).expect("identity id"))
    }

    fn device_id(value: &str) -> DeviceId {
        DeviceId::from_opaque(OpaqueId::new(value).expect("device id"))
    }

    fn integration_id(value: &str) -> IntegrationId {
        IntegrationId::from_opaque(OpaqueId::new(value).expect("integration id"))
    }

    fn tenant_scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant id")),
            namespace_id: None,
        }
    }

    fn address(value: &[u8]) -> EndpointAddress {
        EndpointAddress {
            scheme: "ucr.address.test".to_owned(),
            value: value.to_vec(),
        }
    }
    fn device_endpoint() -> EndpointDescriptor {
        EndpointDescriptor {
            endpoint_id: endpoint_id("endpoint-a"),
            kind: EndpointKind::Device,
            identity_id: Some(identity_id("identity-a")),
            device_id: Some(device_id("device-a")),
            capabilities: vec![CapabilityDescriptor {
                id: "ucr.message.text".to_owned(),
                maturity: CapabilityMaturity::Production,
                extensions: Vec::new(),
            }],
            addresses: vec![address(b"opaque-address")],
        }
    }

    #[test]
    fn valid_device_endpoint_is_accepted() {
        assert_eq!(validate_endpoint_descriptor(&device_endpoint()), Ok(()));
    }

    #[test]
    fn device_endpoint_requires_device_and_identity() {
        let mut endpoint = device_endpoint();
        endpoint.device_id = None;
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::DeviceEndpointMissingDevice)
        );

        endpoint.device_id = Some(device_id("device-a"));
        endpoint.identity_id = None;
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::DeviceEndpointMissingIdentity)
        );
    }

    #[test]
    fn duplicate_addresses_are_rejected() {
        let mut endpoint = device_endpoint();
        endpoint.addresses.push(address(b"opaque-address"));
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::DuplicateAddress)
        );
    }

    #[test]
    fn duplicate_capabilities_are_rejected() {
        let mut endpoint = device_endpoint();
        endpoint.capabilities.push(endpoint.capabilities[0].clone());
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::DuplicateCapability)
        );
    }

    #[test]
    fn address_scheme_must_be_namespaced() {
        let bad = EndpointAddress {
            scheme: "phone".to_owned(),
            value: b"secret".to_vec(),
        };
        assert_eq!(
            validate_endpoint_address(&bad),
            Err(AddressingError::InvalidScheme)
        );
    }
    #[test]
    fn address_size_is_bounded_before_transport_use() {
        let oversized = EndpointAddress {
            scheme: "ucr.address.test".to_owned(),
            value: vec![0; MAX_ADDRESS_VALUE_LEN + 1],
        };
        assert_eq!(
            validate_endpoint_address(&oversized),
            Err(AddressingError::AddressValueTooLong)
        );
    }

    #[test]
    fn endpoint_debug_redacts_address_material() {
        let endpoint = device_endpoint();
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("opaque-address"));
        assert!(debug.contains("<opaque>"));
    }

    #[test]
    fn external_binding_is_validated_without_promoting_external_id() {
        let binding = ExternalIdentityBinding {
            scope: tenant_scope(),
            integration_id: integration_id("integration-a"),
            external_namespace: "vendor.example.account".to_owned(),
            external_entity_id: b"external-secret-id".to_vec(),
            identity_id: identity_id("identity-a"),
        };
        assert_eq!(validate_external_identity_binding(&binding), Ok(()));
        let debug = format!("{binding:?}");
        assert!(!debug.contains("external-secret-id"));
        assert!(debug.contains("<opaque>"));
    }
    #[test]
    fn external_binding_requires_namespaced_nonempty_external_id() {
        let mut binding = ExternalIdentityBinding {
            scope: tenant_scope(),
            integration_id: integration_id("integration-a"),
            external_namespace: "account".to_owned(),
            external_entity_id: b"id".to_vec(),
            identity_id: identity_id("identity-a"),
        };
        assert_eq!(
            validate_external_identity_binding(&binding),
            Err(AddressingError::InvalidExternalNamespace)
        );

        binding.external_namespace = "vendor.example.account".to_owned();
        binding.external_entity_id.clear();
        assert_eq!(
            validate_external_identity_binding(&binding),
            Err(AddressingError::EmptyExternalEntityId)
        );
    }
}

#[cfg(test)]
mod additional_tests {
    use ucr_model::{
        CapabilityDescriptor, CapabilityMaturity, DeviceId, EndpointAddress, EndpointDescriptor,
        EndpointId, EndpointKind, IdentityId, OpaqueId, ProtocolExtension,
    };

    use super::{
        AddressingError, MAX_ENDPOINT_ADDRESSES, MAX_ENDPOINT_CAPABILITIES,
        validate_endpoint_descriptor,
    };

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn base_endpoint() -> EndpointDescriptor {
        EndpointDescriptor {
            endpoint_id: EndpointId::from_opaque(opaque("endpoint-extra")),
            kind: EndpointKind::WebSession,
            identity_id: Some(IdentityId::from_opaque(opaque("identity-extra"))),
            device_id: None,
            capabilities: Vec::new(),
            addresses: Vec::new(),
        }
    }
    #[test]
    fn non_device_device_binding_still_requires_identity() {
        let mut endpoint = base_endpoint();
        endpoint.identity_id = None;
        endpoint.device_id = Some(DeviceId::from_opaque(opaque("device-extra")));
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::DeviceBindingWithoutIdentity)
        );
    }

    #[test]
    fn invalid_capability_identifier_is_rejected() {
        let mut endpoint = base_endpoint();
        endpoint.capabilities.push(CapabilityDescriptor {
            id: "text".to_owned(),
            maturity: CapabilityMaturity::Production,
            extensions: Vec::new(),
        });
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::InvalidCapability)
        );
    }

    #[test]
    fn endpoint_capability_extension_shape_is_validated() {
        let mut endpoint = base_endpoint();
        endpoint.capabilities.push(CapabilityDescriptor {
            id: "ucr.message.rich".to_owned(),
            maturity: CapabilityMaturity::Production,
            extensions: vec![
                ProtocolExtension {
                    name: "vendor.example.same".to_owned(),
                    critical: false,
                    payload: b"a".to_vec(),
                },
                ProtocolExtension {
                    name: "vendor.example.same".to_owned(),
                    critical: false,
                    payload: b"b".to_vec(),
                },
            ],
        });
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::InvalidCapabilityExtension)
        );
    }

    #[test]
    fn endpoint_collection_limits_are_enforced() {
        let mut endpoint = base_endpoint();
        endpoint.addresses = (0..=MAX_ENDPOINT_ADDRESSES)
            .map(|index| EndpointAddress {
                scheme: "ucr.address.test".to_owned(),
                value: index.to_be_bytes().to_vec(),
            })
            .collect();
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::TooManyAddresses)
        );

        endpoint.addresses.clear();
        endpoint.capabilities = (0..=MAX_ENDPOINT_CAPABILITIES)
            .map(|index| CapabilityDescriptor {
                id: format!("ucr.test.capability-{index}"),
                maturity: CapabilityMaturity::Experimental,
                extensions: Vec::new(),
            })
            .collect();
        assert_eq!(
            validate_endpoint_descriptor(&endpoint),
            Err(AddressingError::TooManyCapabilities)
        );
    }
}

#[cfg(test)]
mod boundary_tests {
    use ucr_model::{
        EndpointAddress, ExternalIdentityBinding, IdentityId, IntegrationId, OpaqueId, TenantId,
        TenantScope,
    };

    use super::{
        AddressingError, MAX_EXTERNAL_ENTITY_ID_LEN, validate_endpoint_address,
        validate_external_identity_binding,
    };

    #[test]
    fn empty_address_value_is_rejected() {
        let address = EndpointAddress {
            scheme: "ucr.address.test".to_owned(),
            value: Vec::new(),
        };
        assert_eq!(
            validate_endpoint_address(&address),
            Err(AddressingError::EmptyAddressValue)
        );
    }
    #[test]
    fn external_entity_id_size_is_bounded() {
        let binding = ExternalIdentityBinding {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-b").expect("tenant id")),
                namespace_id: None,
            },
            integration_id: IntegrationId::from_opaque(
                OpaqueId::new("integration-b").expect("integration id"),
            ),
            external_namespace: "vendor.example.account".to_owned(),
            external_entity_id: vec![0; MAX_EXTERNAL_ENTITY_ID_LEN + 1],
            identity_id: IdentityId::from_opaque(OpaqueId::new("identity-b").expect("identity id")),
        };
        assert_eq!(
            validate_external_identity_binding(&binding),
            Err(AddressingError::ExternalEntityIdTooLong)
        );
    }
}

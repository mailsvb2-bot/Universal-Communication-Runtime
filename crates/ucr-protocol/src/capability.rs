use std::collections::{BTreeMap, BTreeSet};

pub use ucr_model::{CapabilityDescriptor, CapabilityMaturity};

use crate::{ExtensionError, canonical_protocol_extensions, validate_namespaced_identifier};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequirement {
    pub id: String,
    pub minimum: CapabilityMaturity,
    pub allow_deprecated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidIdentifier,
    DuplicateAdvertisement,
    InvalidRequirement,
    MissingRequired,
    RequiredBelowMaturity,
    InvalidExtension,
    DuplicateExtension,
    TooManyExtensions,
    ExtensionPayloadTooLarge,
    CriticalExtensionRequiresExplicitNegotiation,
}

/// Validates and canonically orders one public Capability descriptor.
///
/// # Errors
/// Rejects malformed capability identifiers and invalid/over-budget extensions.
pub fn canonical_capability_descriptor(
    capability: &CapabilityDescriptor,
) -> Result<CapabilityDescriptor, CapabilityError> {
    validate_namespaced_identifier(&capability.id)
        .map_err(|_| CapabilityError::InvalidIdentifier)?;
    let mut canonical = capability.clone();
    canonical.extensions =
        canonical_protocol_extensions(&capability.extensions).map_err(map_extension_error)?;
    Ok(canonical)
}

/// Validates, deduplicates, and canonically orders a capability set by ID.
///
/// # Errors
/// Rejects malformed descriptors or duplicate capability IDs.
pub fn canonical_capabilities(
    capabilities: &[CapabilityDescriptor],
) -> Result<Vec<CapabilityDescriptor>, CapabilityError> {
    let mut canonical = capabilities
        .iter()
        .map(canonical_capability_descriptor)
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort_by(|left, right| left.id.cmp(&right.id));
    if canonical.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(CapabilityError::DuplicateAdvertisement);
    }
    Ok(canonical)
}

const fn map_extension_error(error: ExtensionError) -> CapabilityError {
    match error {
        ExtensionError::InvalidNamespace | ExtensionError::UnsupportedCritical => {
            CapabilityError::InvalidExtension
        }
        ExtensionError::TooManyExtensions => CapabilityError::TooManyExtensions,
        ExtensionError::DuplicateExtension => CapabilityError::DuplicateExtension,
        ExtensionError::PayloadTooLarge => CapabilityError::ExtensionPayloadTooLarge,
    }
}

const fn stability_rank(maturity: CapabilityMaturity) -> Option<u8> {
    match maturity {
        CapabilityMaturity::Experimental => Some(1),
        CapabilityMaturity::Prepared => Some(2),
        CapabilityMaturity::Beta => Some(3),
        CapabilityMaturity::Production => Some(4),
        CapabilityMaturity::Deprecated | CapabilityMaturity::Disabled => None,
    }
}

const fn maturity_from_rank(rank: u8) -> CapabilityMaturity {
    match rank {
        1 => CapabilityMaturity::Experimental,
        2 => CapabilityMaturity::Prepared,
        3 => CapabilityMaturity::Beta,
        4 => CapabilityMaturity::Production,
        _ => CapabilityMaturity::Disabled,
    }
}

/// Negotiates only capabilities actually advertised by both peers.
///
/// Disabled capabilities are absent. Deprecated capabilities remain explicitly
/// deprecated and never silently satisfy a stable requirement.
///
/// # Errors
/// Returns an explicit error for malformed or duplicate advertisements, or an
/// unsatisfied required capability.
pub fn negotiate_capabilities(
    local: &[CapabilityDescriptor],
    remote: &[CapabilityDescriptor],
    requirements: &[CapabilityRequirement],
) -> Result<Vec<CapabilityDescriptor>, CapabilityError> {
    let local = canonical_capabilities(local)?;
    let remote = canonical_capabilities(remote)?;
    if local
        .iter()
        .chain(&remote)
        .flat_map(|capability| &capability.extensions)
        .any(|extension| extension.critical)
    {
        return Err(CapabilityError::CriticalExtensionRequiresExplicitNegotiation);
    }
    let local = index_capabilities(&local)?;
    let remote = index_capabilities(&remote)?;
    let mut negotiated = BTreeMap::new();

    for (id, local_maturity) in &local {
        let Some(remote_maturity) = remote.get(id) else {
            continue;
        };
        if let Some(maturity) = combine_maturity(*local_maturity, *remote_maturity) {
            negotiated.insert((*id).to_owned(), maturity);
        }
    }

    for requirement in requirements {
        validate_namespaced_identifier(&requirement.id)
            .map_err(|_| CapabilityError::InvalidIdentifier)?;
        let Some(minimum_rank) = stability_rank(requirement.minimum) else {
            return Err(CapabilityError::InvalidRequirement);
        };
        let Some(actual) = negotiated.get(&requirement.id) else {
            return Err(CapabilityError::MissingRequired);
        };
        if *actual == CapabilityMaturity::Deprecated {
            if requirement.allow_deprecated {
                continue;
            }
            return Err(CapabilityError::RequiredBelowMaturity);
        }
        if stability_rank(*actual).is_none_or(|rank| rank < minimum_rank) {
            return Err(CapabilityError::RequiredBelowMaturity);
        }
    }

    Ok(negotiated
        .into_iter()
        .map(|(id, maturity)| CapabilityDescriptor {
            id,
            maturity,
            extensions: Vec::new(),
        })
        .collect())
}

fn index_capabilities(
    capabilities: &[CapabilityDescriptor],
) -> Result<BTreeMap<&str, CapabilityMaturity>, CapabilityError> {
    let mut seen = BTreeSet::new();
    let mut result = BTreeMap::new();
    for capability in capabilities {
        validate_namespaced_identifier(&capability.id)
            .map_err(|_| CapabilityError::InvalidIdentifier)?;
        if !seen.insert(capability.id.as_str()) {
            return Err(CapabilityError::DuplicateAdvertisement);
        }
        result.insert(capability.id.as_str(), capability.maturity);
    }
    Ok(result)
}

const fn combine_maturity(
    left: CapabilityMaturity,
    right: CapabilityMaturity,
) -> Option<CapabilityMaturity> {
    if matches!(left, CapabilityMaturity::Disabled) || matches!(right, CapabilityMaturity::Disabled)
    {
        return None;
    }
    if matches!(left, CapabilityMaturity::Deprecated)
        || matches!(right, CapabilityMaturity::Deprecated)
    {
        return Some(CapabilityMaturity::Deprecated);
    }
    let Some(left_rank) = stability_rank(left) else {
        return None;
    };
    let Some(right_rank) = stability_rank(right) else {
        return None;
    };
    Some(maturity_from_rank(if left_rank < right_rank {
        left_rank
    } else {
        right_rank
    }))
}

#[cfg(test)]
mod tests {
    use ucr_model::ProtocolExtension;

    use super::{
        CapabilityDescriptor, CapabilityError, CapabilityMaturity, CapabilityRequirement,
        canonical_capability_descriptor, negotiate_capabilities,
    };

    fn cap(id: &str, maturity: CapabilityMaturity) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: id.to_owned(),
            maturity,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn intersection_uses_weaker_declared_maturity() {
        let result = negotiate_capabilities(
            &[cap("ucr.message.text", CapabilityMaturity::Production)],
            &[cap("ucr.message.text", CapabilityMaturity::Beta)],
            &[],
        )
        .expect("capabilities");
        assert_eq!(
            result,
            vec![cap("ucr.message.text", CapabilityMaturity::Beta)]
        );
    }

    #[test]
    fn capability_extensions_are_wire_faithful_and_canonical() {
        let mut value = cap("ucr.message.text", CapabilityMaturity::Production);
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
        let canonical = canonical_capability_descriptor(&value).expect("canonical capability");
        assert_eq!(canonical.extensions[0].name, "ucr.example.a");

        value.extensions[1].name = "vendor.example.z".to_owned();
        assert_eq!(
            canonical_capability_descriptor(&value),
            Err(CapabilityError::DuplicateExtension)
        );
    }

    #[test]
    fn critical_capability_extension_fails_closed_until_negotiation_is_defined() {
        let local = cap("ucr.message.text", CapabilityMaturity::Production);
        let mut remote = cap("ucr.message.text", CapabilityMaturity::Production);
        remote.extensions.push(ProtocolExtension {
            name: "vendor.example.required".to_owned(),
            critical: true,
            payload: b"parameter".to_vec(),
        });
        assert_eq!(
            negotiate_capabilities(&[local], &[remote], &[]),
            Err(CapabilityError::CriticalExtensionRequiresExplicitNegotiation)
        );
    }

    #[test]
    fn disabled_capability_is_not_negotiated() {
        let result = negotiate_capabilities(
            &[cap("ucr.call.video", CapabilityMaturity::Production)],
            &[cap("ucr.call.video", CapabilityMaturity::Disabled)],
            &[],
        )
        .expect("capabilities");
        assert!(result.is_empty());
    }

    #[test]
    fn required_capability_enforces_maturity() {
        let requirement = CapabilityRequirement {
            id: "ucr.transport.direct".to_owned(),
            minimum: CapabilityMaturity::Production,
            allow_deprecated: false,
        };
        assert_eq!(
            negotiate_capabilities(
                &[cap("ucr.transport.direct", CapabilityMaturity::Production)],
                &[cap("ucr.transport.direct", CapabilityMaturity::Prepared)],
                &[requirement],
            ),
            Err(CapabilityError::RequiredBelowMaturity)
        );
    }

    #[test]
    fn duplicate_advertisement_is_rejected() {
        let local = [
            cap("ucr.message.text", CapabilityMaturity::Beta),
            cap("ucr.message.text", CapabilityMaturity::Production),
        ];
        assert_eq!(
            negotiate_capabilities(&local, &[], &[]),
            Err(CapabilityError::DuplicateAdvertisement)
        );
    }
}

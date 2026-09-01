use std::collections::{BTreeMap, BTreeSet};

pub use ucr_model::{CapabilityDescriptor, CapabilityMaturity};

use crate::validate_namespaced_identifier;

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
    let local = index_capabilities(local)?;
    let remote = index_capabilities(remote)?;
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
        .map(|(id, maturity)| CapabilityDescriptor { id, maturity })
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
    use super::{
        CapabilityDescriptor, CapabilityError, CapabilityMaturity, CapabilityRequirement,
        negotiate_capabilities,
    };

    fn cap(id: &str, maturity: CapabilityMaturity) -> CapabilityDescriptor {
        CapabilityDescriptor {
            id: id.to_owned(),
            maturity,
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

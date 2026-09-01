#![forbid(unsafe_code)]

use core::cmp::{max, min};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    pub min: ProtocolVersion,
    pub max: ProtocolVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationError {
    InvalidRange,
    NoMutualVersion,
    BelowLocalMinimum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPolicy {
    pub minimum: ProtocolVersion,
}

impl VersionRange {
    /// Creates an inclusive protocol version range.
    ///
    /// # Errors
    /// Returns [`NegotiationError::InvalidRange`] if `min > max`.
    pub const fn new(min: ProtocolVersion, max: ProtocolVersion) -> Result<Self, NegotiationError> {
        if min.major > max.major || (min.major == max.major && min.minor > max.minor) {
            return Err(NegotiationError::InvalidRange);
        }
        Ok(Self { min, max })
    }
}

/// Selects the highest mutually supported version that satisfies local policy.
///
/// Phase 0 assumes contiguous version ranges. The authenticated handshake must
/// later integrity-bind the advertised ranges and selected result.
///
/// # Errors
/// Returns an explicit error when ranges are invalid, have no overlap, or the
/// overlap is below the configured local minimum.
pub fn negotiate_version(
    local: VersionRange,
    remote: VersionRange,
    policy: VersionPolicy,
) -> Result<ProtocolVersion, NegotiationError> {
    if local.min > local.max || remote.min > remote.max {
        return Err(NegotiationError::InvalidRange);
    }

    let overlap_min = max(local.min, remote.min);
    let overlap_max = min(local.max, remote.max);
    if overlap_min > overlap_max {
        return Err(NegotiationError::NoMutualVersion);
    }
    if overlap_max < policy.minimum {
        return Err(NegotiationError::BelowLocalMinimum);
    }

    let selected = overlap_max;
    if selected < max(overlap_min, policy.minimum) {
        return Err(NegotiationError::BelowLocalMinimum);
    }
    Ok(selected)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionDescriptor {
    pub name: String,
    pub critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionError {
    InvalidNamespace,
    UnsupportedCritical,
}

/// Validates a canonical extension namespace.
///
/// # Errors
/// Returns [`ExtensionError::InvalidNamespace`] if the name is not in a
/// canonical UCR extension namespace.
pub fn validate_extension_name(name: &str) -> Result<(), ExtensionError> {
    let valid = name.starts_with("ucr.")
        || name.starts_with("experimental.")
        || name.starts_with("vendor.")
        || name.starts_with("organization.");
    if valid && !name.ends_with('.') && !name.contains("..") {
        Ok(())
    } else {
        Err(ExtensionError::InvalidNamespace)
    }
}

/// Rejects unsupported critical extensions while allowing unknown optional
/// extensions to remain forward-compatible.
///
/// # Errors
/// Returns [`ExtensionError::UnsupportedCritical`] for an unsupported critical
/// extension.
pub fn require_supported_extensions<'a>(
    advertised: impl IntoIterator<Item = &'a ExtensionDescriptor>,
    supported: impl IntoIterator<Item = &'a str>,
) -> Result<(), ExtensionError> {
    let supported: Vec<&str> = supported.into_iter().collect();
    for extension in advertised {
        validate_extension_name(&extension.name)?;
        if extension.critical && !supported.contains(&extension.name.as_str()) {
            return Err(ExtensionError::UnsupportedCritical);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ExtensionDescriptor, ExtensionError, NegotiationError, ProtocolVersion, VersionPolicy,
        VersionRange, negotiate_version, require_supported_extensions, validate_extension_name,
    };

    const fn version(major: u16, minor: u16) -> ProtocolVersion {
        ProtocolVersion::new(major, minor)
    }

    #[test]
    fn negotiation_selects_highest_mutual_version() {
        let local = VersionRange::new(version(1, 0), version(2, 4)).expect("local range");
        let remote = VersionRange::new(version(1, 3), version(2, 1)).expect("remote range");
        let selected = negotiate_version(
            local,
            remote,
            VersionPolicy {
                minimum: version(1, 0),
            },
        )
        .expect("mutual version");
        assert_eq!(selected, version(2, 1));
    }

    #[test]
    fn negotiation_refuses_policy_downgrade() {
        let local = VersionRange::new(version(1, 0), version(2, 0)).expect("local range");
        let remote = VersionRange::new(version(1, 0), version(1, 9)).expect("remote range");
        assert_eq!(
            negotiate_version(
                local,
                remote,
                VersionPolicy {
                    minimum: version(2, 0),
                },
            ),
            Err(NegotiationError::BelowLocalMinimum)
        );
    }

    #[test]
    fn negotiation_fails_without_overlap() {
        let local = VersionRange::new(version(2, 0), version(2, 5)).expect("local range");
        let remote = VersionRange::new(version(1, 0), version(1, 9)).expect("remote range");
        assert_eq!(
            negotiate_version(
                local,
                remote,
                VersionPolicy {
                    minimum: version(1, 0),
                },
            ),
            Err(NegotiationError::NoMutualVersion)
        );
    }

    #[test]
    fn extension_namespace_is_explicit() {
        assert!(validate_extension_name("ucr.message.edit").is_ok());
        assert!(validate_extension_name("vendor.example.feature").is_ok());
        assert_eq!(
            validate_extension_name("provider-specific-shortcut"),
            Err(ExtensionError::InvalidNamespace)
        );
    }

    #[test]
    fn unsupported_optional_extension_is_tolerated() {
        let advertised = [ExtensionDescriptor {
            name: "vendor.example.future".to_owned(),
            critical: false,
        }];
        assert!(require_supported_extensions(&advertised, []).is_ok());
    }

    #[test]
    fn unsupported_critical_extension_fails_explicitly() {
        let advertised = [ExtensionDescriptor {
            name: "vendor.example.required".to_owned(),
            critical: true,
        }];
        assert_eq!(
            require_supported_extensions(&advertised, []),
            Err(ExtensionError::UnsupportedCritical)
        );
    }
}

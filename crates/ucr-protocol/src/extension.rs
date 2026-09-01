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

/// Validates a namespaced UCR identifier.
///
/// # Errors
/// Returns [`ExtensionError::InvalidNamespace`] for malformed or unscoped names.
pub fn validate_namespaced_identifier(name: &str) -> Result<(), ExtensionError> {
    let valid_prefix = name.starts_with("ucr.")
        || name.starts_with("experimental.")
        || name.starts_with("vendor.")
        || name.starts_with("organization.");
    let segments_valid = name
        .split('.')
        .all(|segment| !segment.is_empty() && segment.bytes().all(is_identifier_byte));
    if valid_prefix && segments_valid {
        Ok(())
    } else {
        Err(ExtensionError::InvalidNamespace)
    }
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// Validates a canonical extension namespace.
///
/// # Errors
/// Returns [`ExtensionError::InvalidNamespace`] if the name is invalid.
pub fn validate_extension_name(name: &str) -> Result<(), ExtensionError> {
    validate_namespaced_identifier(name)
}

/// Rejects unsupported critical extensions while tolerating unknown optional ones.
///
/// # Errors
/// Returns [`ExtensionError::UnsupportedCritical`] for an unsupported critical extension.
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
        ExtensionDescriptor, ExtensionError, require_supported_extensions, validate_extension_name,
    };

    #[test]
    fn namespace_is_explicit() {
        assert!(validate_extension_name("ucr.message.edit").is_ok());
        assert!(validate_extension_name("vendor.example.feature").is_ok());
        assert_eq!(
            validate_extension_name("provider-specific-shortcut"),
            Err(ExtensionError::InvalidNamespace)
        );
        assert_eq!(
            validate_extension_name("ucr.message..edit"),
            Err(ExtensionError::InvalidNamespace)
        );
    }

    #[test]
    fn optional_extension_is_tolerated() {
        let advertised = [ExtensionDescriptor {
            name: "vendor.example.future".to_owned(),
            critical: false,
        }];
        assert!(require_supported_extensions(&advertised, []).is_ok());
    }

    #[test]
    fn critical_extension_fails_explicitly() {
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

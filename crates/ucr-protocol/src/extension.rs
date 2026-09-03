use ucr_model::ProtocolExtension;

pub const MAX_PROTOCOL_EXTENSIONS: usize = 64;
pub const MAX_EXTENSION_PAYLOAD_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionError {
    InvalidNamespace,
    UnsupportedCritical,
    TooManyExtensions,
    DuplicateExtension,
    PayloadTooLarge,
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

/// Validates and canonically orders protocol extensions.
///
/// Extension order is not semantic. Duplicate names are rejected.
///
/// # Errors
/// Returns an explicit namespace, count, duplicate, or payload budget error.
pub fn canonical_protocol_extensions(
    extensions: &[ProtocolExtension],
) -> Result<Vec<ProtocolExtension>, ExtensionError> {
    if extensions.len() > MAX_PROTOCOL_EXTENSIONS {
        return Err(ExtensionError::TooManyExtensions);
    }
    let mut canonical = extensions.to_vec();
    for extension in &canonical {
        validate_extension_name(&extension.name)?;
        if extension.payload.len() > MAX_EXTENSION_PAYLOAD_LEN {
            return Err(ExtensionError::PayloadTooLarge);
        }
    }
    canonical.sort_by(|left, right| left.name.cmp(&right.name));
    if canonical
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(ExtensionError::DuplicateExtension);
    }
    Ok(canonical)
}

/// Rejects unsupported critical extensions while tolerating unknown optional ones.
///
/// # Errors
/// Returns [`ExtensionError::UnsupportedCritical`] for an unsupported critical extension.
pub fn require_supported_extensions<'a>(
    advertised: impl IntoIterator<Item = &'a ProtocolExtension>,
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
    use super::{ExtensionError, require_supported_extensions, validate_extension_name};

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
        let advertised = [ucr_model::ProtocolExtension {
            name: "vendor.example.future".to_owned(),
            critical: false,
            payload: Vec::new(),
        }];
        assert!(require_supported_extensions(&advertised, []).is_ok());
    }

    #[test]
    fn critical_extension_fails_explicitly() {
        let advertised = [ucr_model::ProtocolExtension {
            name: "vendor.example.required".to_owned(),
            critical: true,
            payload: Vec::new(),
        }];
        assert_eq!(
            require_supported_extensions(&advertised, []),
            Err(ExtensionError::UnsupportedCritical)
        );
    }
}

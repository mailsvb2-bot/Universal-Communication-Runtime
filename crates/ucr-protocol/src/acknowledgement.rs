use ucr_model::{OpaqueId, ProtocolExtension, ProtocolVersion};

use crate::{ExtensionError, RUNTIME_ENVELOPE_SCHEMA_V1, canonical_protocol_extensions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgementEnvelope {
    pub acknowledged_id: OpaqueId,
    pub schema_version: ProtocolVersion,
    pub extensions: Vec<ProtocolExtension>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcknowledgementError {
    InvalidSchemaVersion,
    InvalidExtension,
    DuplicateExtension,
    TooManyExtensions,
    ExtensionPayloadTooLarge,
}

/// Validates a generic protocol acknowledgement.
///
/// A generic ACK confirms only the protocol object identified by
/// `acknowledged_id`; it is not delivery, read, provider-acceptance, or effect
/// evidence.
///
/// # Errors
/// Rejects zero-major schema versions and malformed/over-budget extensions.
pub fn validate_acknowledgement(
    acknowledgement: &AcknowledgementEnvelope,
) -> Result<(), AcknowledgementError> {
    if acknowledgement.schema_version.major == 0 {
        return Err(AcknowledgementError::InvalidSchemaVersion);
    }
    canonical_protocol_extensions(&acknowledgement.extensions).map_err(map_extension_error)?;
    Ok(())
}

/// Validates and canonically orders one acknowledgement for wire use.
///
/// # Errors
/// Returns the same fail-closed errors as [`validate_acknowledgement`].
pub fn canonical_acknowledgement(
    acknowledgement: &AcknowledgementEnvelope,
) -> Result<AcknowledgementEnvelope, AcknowledgementError> {
    validate_acknowledgement(acknowledgement)?;
    let mut canonical = acknowledgement.clone();
    canonical.extensions =
        canonical_protocol_extensions(&acknowledgement.extensions).map_err(map_extension_error)?;
    Ok(canonical)
}

/// Creates the base v1 generic acknowledgement with no response extensions.
#[must_use]
pub fn acknowledgement_for(acknowledged_id: OpaqueId) -> AcknowledgementEnvelope {
    AcknowledgementEnvelope {
        acknowledged_id,
        schema_version: RUNTIME_ENVELOPE_SCHEMA_V1,
        extensions: Vec::new(),
    }
}

const fn map_extension_error(error: ExtensionError) -> AcknowledgementError {
    match error {
        ExtensionError::InvalidNamespace | ExtensionError::UnsupportedCritical => {
            AcknowledgementError::InvalidExtension
        }
        ExtensionError::TooManyExtensions => AcknowledgementError::TooManyExtensions,
        ExtensionError::DuplicateExtension => AcknowledgementError::DuplicateExtension,
        ExtensionError::PayloadTooLarge => AcknowledgementError::ExtensionPayloadTooLarge,
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::{OpaqueId, ProtocolExtension, ProtocolVersion};

    use super::{
        AcknowledgementEnvelope, AcknowledgementError, acknowledgement_for,
        canonical_acknowledgement, validate_acknowledgement,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    #[test]
    fn base_acknowledgement_is_explicit_v1_and_empty_extension_set() {
        let value = acknowledgement_for(id("event-a"));
        assert_eq!(value.schema_version, ProtocolVersion::new(1, 0));
        assert!(value.extensions.is_empty());
        assert_eq!(validate_acknowledgement(&value), Ok(()));
    }

    #[test]
    fn extension_order_is_non_semantic_but_duplicates_fail_closed() {
        let mut value = acknowledgement_for(id("event-a"));
        value.extensions = vec![
            ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: true,
                payload: b"a".to_vec(),
            },
        ];
        let canonical = canonical_acknowledgement(&value).expect("canonical");
        assert_eq!(canonical.extensions[0].name, "ucr.example.a");

        value.extensions[1].name = "vendor.example.z".to_owned();
        assert_eq!(
            validate_acknowledgement(&value),
            Err(AcknowledgementError::DuplicateExtension)
        );
    }

    #[test]
    fn zero_major_schema_fails_closed() {
        let value = AcknowledgementEnvelope {
            acknowledged_id: id("event-a"),
            schema_version: ProtocolVersion::new(0, 0),
            extensions: Vec::new(),
        };
        assert_eq!(
            validate_acknowledgement(&value),
            Err(AcknowledgementError::InvalidSchemaVersion)
        );
    }
}

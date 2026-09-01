use ucr_model::OriginRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceError {
    EmptyOrigin,
}

/// Validates generic message provenance.
///
/// Origin is intentionally expressed only through canonical UCR references.
/// Product/provider-specific source fields belong outside the canonical model.
///
/// # Errors
/// Returns [`ProvenanceError::EmptyOrigin`] when an `OriginRef` carries no source.
pub const fn validate_origin_ref(origin: &OriginRef) -> Result<(), ProvenanceError> {
    if origin.principal_id.is_none()
        && origin.endpoint_id.is_none()
        && origin.integration_id.is_none()
    {
        return Err(ProvenanceError::EmptyOrigin);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{EndpointId, OpaqueId, OriginRef};

    use super::{ProvenanceError, validate_origin_ref};
    #[test]
    fn empty_origin_is_rejected() {
        let origin = OriginRef {
            principal_id: None,
            endpoint_id: None,
            integration_id: None,
        };
        assert_eq!(
            validate_origin_ref(&origin),
            Err(ProvenanceError::EmptyOrigin)
        );
    }

    #[test]
    fn endpoint_origin_is_accepted() {
        let origin = OriginRef {
            principal_id: None,
            endpoint_id: Some(EndpointId::from_opaque(
                OpaqueId::new("endpoint-origin").expect("endpoint id"),
            )),
            integration_id: None,
        };
        assert_eq!(validate_origin_ref(&origin), Ok(()));
    }
}

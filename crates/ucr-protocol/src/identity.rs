use ucr_model::IdentityRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidExpiry,
}

/// Validates the minimal canonical Root Identity record.
///
/// Identity IDs and scope IDs are already validated opaque IDs. Expiry is lifecycle metadata;
/// when present it must be a positive Unix-millisecond instant. Expiry enforcement/deletion is
/// deliberately not performed by this structural validator.
///
/// # Errors
/// Rejects non-positive expiry values.
pub const fn validate_identity_record(identity: &IdentityRecord) -> Result<(), IdentityError> {
    if let Some(expires_at) = identity.expires_at_unix_ms
        && expires_at <= 0
    {
        return Err(IdentityError::InvalidExpiry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        IdentityEvidence, IdentityId, IdentityOwnership, IdentityRecord, NamespaceId, OpaqueId,
        TenantId, TenantScope,
    };

    use super::{IdentityError, validate_identity_record};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn identity(ownership: IdentityOwnership, expiry: Option<i64>) -> IdentityRecord {
        IdentityRecord {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-identity")),
                namespace_id: Some(NamespaceId::from_opaque(oid("namespace-identity"))),
            },
            identity_id: IdentityId::from_opaque(oid("identity-a")),
            ownership,
            evidence: IdentityEvidence::Unverified,
            expires_at_unix_ms: expiry,
        }
    }

    #[test]
    fn accountless_identity_has_no_locator_requirements() {
        assert_eq!(
            validate_identity_record(&identity(IdentityOwnership::UcrNative, None)),
            Ok(())
        );
    }

    #[test]
    fn temporary_identity_can_carry_expiry_but_nonpositive_expiry_fails() {
        assert_eq!(
            validate_identity_record(&identity(IdentityOwnership::Temporary, Some(86_400_000))),
            Ok(())
        );
        assert_eq!(
            validate_identity_record(&identity(IdentityOwnership::Temporary, Some(0))),
            Err(IdentityError::InvalidExpiry)
        );
    }
}

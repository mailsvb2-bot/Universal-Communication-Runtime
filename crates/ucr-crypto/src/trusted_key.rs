use ucr_model::{DeviceId, IdentityId, KeyId, PublicKeyDescriptor, TenantScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeyResolutionError {
    NotTrusted,
    Unavailable,
    Corrupt,
    PermissionDenied,
    Internal,
}

/// Read-only trust boundary used by cryptographic verification/session setup.
///
/// Implementations must return only an active descriptor that exactly matches
/// the requested scope/device/key. Absence, revocation, or mismatch is the
/// deliberately non-disclosing `NotTrusted` result.
pub trait TrustedSigningKeyResolver: core::fmt::Debug + Send + Sync {
    /// Resolves one active trusted signing descriptor.
    ///
    /// # Errors
    /// Returns `NotTrusted` for absence/revocation/mismatch or an explicit
    /// availability/corruption/permission failure.
    fn resolve_active_signing_key(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
        identity_id: Option<&IdentityId>,
        key_id: &KeyId,
    ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError>;
}

use ucr_model::{PrincipalIdentityBinding, PrincipalKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalIdentityBindingError {
    DevicePrincipalUsesDeviceOwner,
}

/// Validates an explicit Principal→Root Identity association.
///
/// The binding is association evidence only. It never grants authorization, Group membership,
/// Call participation or Device trust. Device principals are intentionally excluded because the
/// canonical `DeviceDescriptor` already owns Device→Identity association.
///
/// # Errors
/// Rejects Device principals so there cannot be two owners for the same relationship.
pub fn validate_principal_identity_binding(
    binding: &PrincipalIdentityBinding,
) -> Result<(), PrincipalIdentityBindingError> {
    if binding.principal.kind == PrincipalKind::Device {
        return Err(PrincipalIdentityBindingError::DevicePrincipalUsesDeviceOwner);
    }
    Ok(())
}

use ucr_model::{DeviceDescriptor, DeviceLifecycleState};

/// Returns whether a canonical Device may participate in new protected-access
/// operations such as trusted-key provision/rotation or key-backed authentication.
///
/// The reference security policy is deliberately fail-closed: only `Active`
/// permits new protected access. Stale, re-verification-required, expired, and
/// revoked states remain distinct canonical states; this helper does not define
/// how those non-Active states return to service.
#[must_use]
pub const fn device_allows_protected_access(device: &DeviceDescriptor) -> bool {
    matches!(device.state, DeviceLifecycleState::Active)
}

#[cfg(test)]
mod tests {
    use ucr_model::{DeviceId, IdentityId, OpaqueId};

    use super::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn descriptor(state: DeviceLifecycleState) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: DeviceId::from_opaque(oid("device-a")),
            identity_id: IdentityId::from_opaque(oid("identity-a")),
            state,
        }
    }

    #[test]
    fn only_active_device_allows_new_protected_access() {
        assert!(device_allows_protected_access(&descriptor(
            DeviceLifecycleState::Active
        )));
        for state in [
            DeviceLifecycleState::Stale,
            DeviceLifecycleState::ReverificationRequired,
            DeviceLifecycleState::Expired,
            DeviceLifecycleState::Revoked,
        ] {
            assert!(!device_allows_protected_access(&descriptor(state)));
        }
    }
}

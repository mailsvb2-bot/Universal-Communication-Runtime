#![forbid(unsafe_code)]

use core::fmt;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use ucr_model::OpaqueId;
use zeroize::Zeroize;

pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_SECRET_VERSIONS_PER_HANDLE: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretPurpose {
    JoinSigning,
    WebhookSigning,
    TlsCertificate,
    TlsPrivateKey,
    MediaCrypto,
    TurnCredentials,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretHandle {
    pub secret_id: OpaqueId,
    pub purpose: SecretPurpose,
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretHandle")
            .field("secret_id", &self.secret_id)
            .field("purpose", &self.purpose)
            .finish()
    }
}

pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    /// Creates bounded secret material from provider bytes.
    ///
    /// # Errors
    /// Rejects empty and oversized material.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecretProviderError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretProviderError::InvalidMaterial);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for SecretMaterial {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("bytes", &"<redacted>")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVersion {
    pub version_id: OpaqueId,
    pub material: SecretMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSecretSet {
    pub handle: SecretHandle,
    pub current: SecretVersion,
    pub previous: Option<SecretVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretProviderHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretProviderError {
    InvalidMaterial,
    NotFound,
    Conflict,
    CapacityExceeded,
    Unavailable,
    Internal,
}

pub trait SecretProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn health(&self) -> SecretProviderHealth;

    /// Resolves the active overlap-safe keyset for one opaque handle.
    ///
    /// # Errors
    /// Returns explicit provider failures. Callers must fail closed on missing/unavailable secrets.
    fn active_secret_set(
        &self,
        handle: &SecretHandle,
    ) -> Result<ActiveSecretSet, SecretProviderError>;

    /// Rotates one handle to a new current version while retaining the previous current version
    /// for overlap verification.
    ///
    /// Exact retries of the same version/material are idempotent; changed reuse conflicts.
    ///
    /// # Errors
    /// Returns explicit validation/conflict/provider failures.
    fn rotate(
        &self,
        handle: &SecretHandle,
        new_version: SecretVersion,
    ) -> Result<ActiveSecretSet, SecretProviderError>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemorySecretProvider {
    state: Arc<RwLock<HashMap<SecretHandle, ActiveSecretSet>>>,
}

impl InMemorySecretProvider {
    /// Provisions one initial current version.
    ///
    /// # Errors
    /// Exact retry is idempotent; changed reuse conflicts.
    pub fn provision(
        &self,
        handle: SecretHandle,
        version: SecretVersion,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        let mut state = self.state.write().map_err(|_| SecretProviderError::Internal)?;
        if let Some(existing) = state.get(&handle) {
            if existing.current == version && existing.previous.is_none() {
                return Ok(existing.clone());
            }
            return Err(SecretProviderError::Conflict);
        }
        let set = ActiveSecretSet {
            handle: handle.clone(),
            current: version,
            previous: None,
        };
        state.insert(handle, set.clone());
        Ok(set)
    }
}

impl SecretProvider for InMemorySecretProvider {
    fn provider_id(&self) -> &'static str {
        "memory"
    }

    fn health(&self) -> SecretProviderHealth {
        SecretProviderHealth::Healthy
    }

    fn active_secret_set(
        &self,
        handle: &SecretHandle,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        self.state
            .read()
            .map_err(|_| SecretProviderError::Internal)?
            .get(handle)
            .cloned()
            .ok_or(SecretProviderError::NotFound)
    }

    fn rotate(
        &self,
        handle: &SecretHandle,
        new_version: SecretVersion,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        let mut state = self.state.write().map_err(|_| SecretProviderError::Internal)?;
        let existing = state.get(handle).cloned().ok_or(SecretProviderError::NotFound)?;

        if existing.current == new_version {
            return Ok(existing);
        }
        if existing.current.version_id == new_version.version_id {
            return Err(SecretProviderError::Conflict);
        }

        let rotated = ActiveSecretSet {
            handle: handle.clone(),
            current: new_version,
            previous: Some(existing.current),
        };
        state.insert(handle.clone(), rotated.clone());
        Ok(rotated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn material(value: &[u8]) -> SecretMaterial {
        SecretMaterial::new(value.to_vec()).expect("material")
    }

    #[test]
    fn rotation_keeps_exactly_current_and_previous_for_zero_downtime_overlap() {
        let provider = InMemorySecretProvider::default();
        let handle = SecretHandle {
            secret_id: oid("join-signing"),
            purpose: SecretPurpose::JoinSigning,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: oid("v1"),
                    material: material(b"first-secret"),
                },
            )
            .expect("provision");
        let rotated = provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v2"),
                    material: material(b"second-secret"),
                },
            )
            .expect("rotate");
        assert_eq!(rotated.current.version_id, oid("v2"));
        assert_eq!(
            rotated.previous.as_ref().map(|value| &value.version_id),
            Some(&oid("v1"))
        );

        let second = provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v3"),
                    material: material(b"third-secret"),
                },
            )
            .expect("second rotate");
        assert_eq!(second.current.version_id, oid("v3"));
        assert_eq!(
            second.previous.as_ref().map(|value| &value.version_id),
            Some(&oid("v2"))
        );
    }

    #[test]
    fn exact_rotation_retry_is_idempotent_and_changed_version_reuse_conflicts() {
        let provider = InMemorySecretProvider::default();
        let handle = SecretHandle {
            secret_id: oid("webhook-signing"),
            purpose: SecretPurpose::WebhookSigning,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: oid("v1"),
                    material: material(b"first-secret"),
                },
            )
            .expect("provision");
        let v2 = SecretVersion {
            version_id: oid("v2"),
            material: material(b"second-secret"),
        };
        let first = provider.rotate(&handle, v2.clone()).expect("rotate");
        let retry = provider.rotate(&handle, v2).expect("retry");
        assert_eq!(first, retry);

        assert_eq!(
            provider.rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v2"),
                    material: material(b"different-secret"),
                },
            ),
            Err(SecretProviderError::Conflict)
        );
    }

    #[test]
    fn secret_material_debug_never_exposes_bytes() {
        let secret = material(b"do-not-print");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("do-not-print"));
    }
}

#![forbid(unsafe_code)]

use core::fmt;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use ucr_model::OpaqueId;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SECRET_BYTES: usize = 64 * 1024;
pub const MAX_SECRET_VERSIONS_PER_HANDLE: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretPurpose {
    MachineTokenSigning,
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

#[derive(PartialEq, Eq)]
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

pub const MAX_TLS_CERTIFICATE_BYTES: u64 = MAX_SECRET_BYTES as u64;
pub const MAX_TLS_PRIVATE_KEY_BYTES: u64 = MAX_SECRET_BYTES as u64;

#[derive(Debug, Clone)]
pub struct ReloadingFileTlsSecretProvider {
    certificate_path: Arc<str>,
    private_key_path: Arc<str>,
    previous_certificate_path: Option<Arc<str>>,
    previous_private_key_path: Option<Arc<str>>,
    certificate_handle: SecretHandle,
    private_key_handle: SecretHandle,
}

impl ReloadingFileTlsSecretProvider {
    /// Creates a reloadable file-backed TLS adapter over the shared secret-provider boundary.
    ///
    /// Files are re-read on every lookup so atomic replacement is visible to new connections.
    /// Certificate and private-key rotation can overlap by exposing one bounded previous pair.
    ///
    /// # Errors
    /// Rejects empty paths, malformed handle identifiers, or incomplete previous-pair config.
    pub fn new(
        certificate_path: impl Into<String>,
        private_key_path: impl Into<String>,
        previous_certificate_path: Option<String>,
        previous_private_key_path: Option<String>,
        certificate_secret_id: &str,
        private_key_secret_id: &str,
    ) -> Result<Self, String> {
        let certificate_path = certificate_path.into();
        let private_key_path = private_key_path.into();
        if certificate_path.is_empty() || private_key_path.is_empty() {
            return Err("TLS secret provider paths must not be empty".to_owned());
        }
        if previous_certificate_path.is_some() != previous_private_key_path.is_some() {
            return Err(
                "previous TLS certificate and private-key paths must be configured together"
                    .to_owned(),
            );
        }
        Ok(Self {
            certificate_path: Arc::from(certificate_path),
            private_key_path: Arc::from(private_key_path),
            previous_certificate_path: previous_certificate_path.map(Arc::from),
            previous_private_key_path: previous_private_key_path.map(Arc::from),
            certificate_handle: SecretHandle {
                secret_id: OpaqueId::new(certificate_secret_id)
                    .map_err(|_| "invalid TLS certificate secret id".to_owned())?,
                purpose: SecretPurpose::TlsCertificate,
            },
            private_key_handle: SecretHandle {
                secret_id: OpaqueId::new(private_key_secret_id)
                    .map_err(|_| "invalid TLS private-key secret id".to_owned())?,
                purpose: SecretPurpose::TlsPrivateKey,
            },
        })
    }

    #[must_use]
    pub fn certificate_handle(&self) -> SecretHandle {
        self.certificate_handle.clone()
    }

    #[must_use]
    pub fn private_key_handle(&self) -> SecretHandle {
        self.private_key_handle.clone()
    }

    fn read_material(
        path: &str,
        limit: u64,
        require_private_permissions: bool,
    ) -> Result<SecretMaterial, SecretProviderError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| SecretProviderError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
            return Err(SecretProviderError::InvalidMaterial);
        }
        #[cfg(unix)]
        if require_private_permissions {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(SecretProviderError::InvalidMaterial);
            }
        }
        let bytes = fs::read(path).map_err(|_| SecretProviderError::Unavailable)?;
        SecretMaterial::new(bytes)
    }

    fn set_for(
        handle: &SecretHandle,
        current_path: &str,
        previous_path: Option<&str>,
        limit: u64,
        require_private_permissions: bool,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        let current = SecretVersion {
            version_id: OpaqueId::new("file-current").map_err(|_| SecretProviderError::Internal)?,
            material: Self::read_material(current_path, limit, require_private_permissions)?,
        };
        let previous = previous_path
            .map(|path| {
                Ok(SecretVersion {
                    version_id: OpaqueId::new("file-previous")
                        .map_err(|_| SecretProviderError::Internal)?,
                    material: Self::read_material(path, limit, require_private_permissions)?,
                })
            })
            .transpose()?;
        Ok(ActiveSecretSet {
            handle: handle.clone(),
            current,
            previous,
        })
    }
}

impl SecretProvider for ReloadingFileTlsSecretProvider {
    fn provider_id(&self) -> &'static str {
        "tls-file-reload"
    }

    fn health(&self) -> SecretProviderHealth {
        if self
            .active_secret_set(&self.certificate_handle)
            .and_then(|_| self.active_secret_set(&self.private_key_handle))
            .is_ok()
        {
            SecretProviderHealth::Healthy
        } else {
            SecretProviderHealth::Unavailable
        }
    }

    fn active_secret_set(
        &self,
        handle: &SecretHandle,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        if handle == &self.certificate_handle {
            Self::set_for(
                handle,
                &self.certificate_path,
                self.previous_certificate_path.as_deref(),
                MAX_TLS_CERTIFICATE_BYTES,
                false,
            )
        } else if handle == &self.private_key_handle {
            Self::set_for(
                handle,
                &self.private_key_path,
                self.previous_private_key_path.as_deref(),
                MAX_TLS_PRIVATE_KEY_BYTES,
                true,
            )
        } else {
            Err(SecretProviderError::NotFound)
        }
    }

    fn rotate(
        &self,
        _handle: &SecretHandle,
        _new_version: SecretVersion,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        Err(SecretProviderError::Unavailable)
    }
}

pub const MAX_RELOADABLE_SECRET_MANIFEST_BYTES: u64 = 1024;

#[derive(Debug, Clone)]
pub struct ReloadingFileSecretProvider {
    handle: SecretHandle,
    manifest_file: PathBuf,
}

impl ReloadingFileSecretProvider {
    /// Opens one read-only file-backed provider snapshot source.
    ///
    /// The manifest is re-read on every lookup so an atomic file replacement becomes visible
    /// without rebuilding consumers. This adapter owns no durable secret history and therefore
    /// does not implement mutation through the provider rotate method.
    ///
    /// # Errors
    /// Rejects unavailable, unsafe, malformed, or duplicate-version manifests.
    pub fn new(
        handle: SecretHandle,
        manifest_file: impl Into<PathBuf>,
    ) -> Result<Self, SecretProviderError> {
        let provider = Self {
            handle,
            manifest_file: manifest_file.into(),
        };
        provider.active_secret_set(&provider.handle)?;
        Ok(provider)
    }

    fn read_manifest(
        path: &Path,
        handle: &SecretHandle,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| SecretProviderError::Unavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_RELOADABLE_SECRET_MANIFEST_BYTES
        {
            return Err(SecretProviderError::InvalidMaterial);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(SecretProviderError::InvalidMaterial);
            }
        }

        let encoded =
            Zeroizing::new(fs::read_to_string(path).map_err(|_| SecretProviderError::Unavailable)?);
        let mut current_version_id = None;
        let mut current_secret_hex = None;
        let mut previous_version_id = None;
        let mut previous_secret_hex = None;
        for line in encoded
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let Some((name, value)) = line.split_once('=') else {
                return Err(SecretProviderError::InvalidMaterial);
            };
            let value = value.trim();
            match name.trim() {
                "current_key_id" | "current_version_id" if current_version_id.is_none() => {
                    current_version_id = Some(value);
                }
                "current_seed_hex" | "current_secret_hex" if current_secret_hex.is_none() => {
                    current_secret_hex = Some(value);
                }
                "previous_key_id" | "previous_version_id" if previous_version_id.is_none() => {
                    previous_version_id = Some(value);
                }
                "previous_seed_hex" | "previous_secret_hex" if previous_secret_hex.is_none() => {
                    previous_secret_hex = Some(value);
                }
                _ => return Err(SecretProviderError::InvalidMaterial),
            }
        }

        let current = Self::decode_version(
            current_version_id.ok_or(SecretProviderError::InvalidMaterial)?,
            current_secret_hex.ok_or(SecretProviderError::InvalidMaterial)?,
        )?;
        let previous = match (previous_version_id, previous_secret_hex) {
            (Some(version_id), Some(secret_hex)) => {
                Some(Self::decode_version(version_id, secret_hex)?)
            }
            (None, None) => None,
            _ => return Err(SecretProviderError::InvalidMaterial),
        };
        if previous
            .as_ref()
            .is_some_and(|version| version.version_id == current.version_id)
        {
            return Err(SecretProviderError::Conflict);
        }

        Ok(ActiveSecretSet {
            handle: handle.clone(),
            current,
            previous,
        })
    }

    fn decode_version(
        version_id: &str,
        secret_hex: &str,
    ) -> Result<SecretVersion, SecretProviderError> {
        let bytes = Zeroizing::new(decode_hex_32(secret_hex)?);
        Ok(SecretVersion {
            version_id: OpaqueId::new(version_id)
                .map_err(|_| SecretProviderError::InvalidMaterial)?,
            material: SecretMaterial::new(bytes.as_ref().to_vec())?,
        })
    }
}

impl SecretProvider for ReloadingFileSecretProvider {
    fn provider_id(&self) -> &'static str {
        "file-reload"
    }

    fn health(&self) -> SecretProviderHealth {
        if self.active_secret_set(&self.handle).is_ok() {
            SecretProviderHealth::Healthy
        } else {
            SecretProviderHealth::Unavailable
        }
    }

    fn active_secret_set(
        &self,
        handle: &SecretHandle,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        if handle != &self.handle {
            return Err(SecretProviderError::NotFound);
        }
        Self::read_manifest(self.manifest_file.as_path(), handle)
    }

    fn rotate(
        &self,
        _handle: &SecretHandle,
        _new_version: SecretVersion,
    ) -> Result<ActiveSecretSet, SecretProviderError> {
        Err(SecretProviderError::Unavailable)
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], SecretProviderError> {
    if value.len() != 64 {
        return Err(SecretProviderError::InvalidMaterial);
    }
    let mut output = [0_u8; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Result<u8, SecretProviderError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SecretProviderError::InvalidMaterial),
    }
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
        let mut state = self
            .state
            .write()
            .map_err(|_| SecretProviderError::Internal)?;
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
        let mut state = self
            .state
            .write()
            .map_err(|_| SecretProviderError::Internal)?;
        let existing = state
            .get(handle)
            .cloned()
            .ok_or(SecretProviderError::NotFound)?;

        if existing.current == new_version {
            return Ok(existing);
        }
        if existing.current.version_id == new_version.version_id {
            return Err(SecretProviderError::Conflict);
        }
        if let Some(previous) = &existing.previous {
            if *previous == new_version {
                return Ok(existing);
            }
            if previous.version_id == new_version.version_id {
                return Err(SecretProviderError::Conflict);
            }
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

    fn manifest_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ucr-secret-manifest-{name}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        path
    }

    fn write_manifest(path: &Path, body: &str) {
        fs::write(path, body).expect("write manifest");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod manifest");
        }
    }

    #[test]
    fn reloadable_tls_provider_reads_bounded_certificate_and_private_key() {
        let certificate_path = manifest_path("tls-cert");
        let private_key_path = manifest_path("tls-key");
        fs::write(&certificate_path, b"certificate-pem").expect("write certificate");
        fs::write(&private_key_path, b"private-key-pem").expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
                .expect("chmod private key");
        }

        let provider = ReloadingFileTlsSecretProvider::new(
            certificate_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            None,
            None,
            "tls-cert",
            "tls-key",
        )
        .expect("TLS provider");
        let certificate = provider
            .active_secret_set(&provider.certificate_handle())
            .expect("certificate");
        let private_key = provider
            .active_secret_set(&provider.private_key_handle())
            .expect("private key");
        assert_eq!(certificate.current.material.as_bytes(), b"certificate-pem");
        assert_eq!(private_key.current.material.as_bytes(), b"private-key-pem");
        fs::remove_file(certificate_path).expect("cleanup certificate");
        fs::remove_file(private_key_path).expect("cleanup key");
    }

    #[cfg(unix)]
    #[test]
    fn reloadable_tls_provider_rejects_group_readable_private_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let certificate_path = manifest_path("tls-public-cert");
        let private_key_path = manifest_path("tls-public-key");
        fs::write(&certificate_path, b"certificate-pem").expect("write certificate");
        fs::write(&private_key_path, b"private-key-pem").expect("write key");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o640))
            .expect("chmod private key");

        let provider = ReloadingFileTlsSecretProvider::new(
            certificate_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            None,
            None,
            "tls-public-cert",
            "tls-public-key",
        )
        .expect("TLS provider");
        assert_eq!(
            provider.active_secret_set(&provider.private_key_handle()),
            Err(SecretProviderError::InvalidMaterial)
        );
        fs::remove_file(certificate_path).expect("cleanup certificate");
        fs::remove_file(private_key_path).expect("cleanup key");
    }

    #[test]
    fn reloadable_file_provider_observes_atomic_overlap_replacement() {
        let path = manifest_path("rotation");
        write_manifest(
            &path,
            "current_version_id=v1\ncurrent_secret_hex=4141414141414141414141414141414141414141414141414141414141414141\n",
        );
        let handle = SecretHandle {
            secret_id: oid("file-provider"),
            purpose: SecretPurpose::JoinSigning,
        };
        let provider =
            ReloadingFileSecretProvider::new(handle.clone(), path.clone()).expect("provider");
        let first = provider.active_secret_set(&handle).expect("first");
        assert_eq!(first.current.version_id, oid("v1"));
        assert!(first.previous.is_none());

        let replacement = path.with_extension("next");
        write_manifest(
            &replacement,
            "current_version_id=v2\ncurrent_secret_hex=4242424242424242424242424242424242424242424242424242424242424242\nprevious_version_id=v1\nprevious_secret_hex=4141414141414141414141414141414141414141414141414141414141414141\n",
        );
        fs::rename(&replacement, &path).expect("atomic replace");

        let rotated = provider.active_secret_set(&handle).expect("rotated");
        assert_eq!(rotated.current.version_id, oid("v2"));
        assert_eq!(
            rotated.previous.as_ref().map(|value| &value.version_id),
            Some(&oid("v1"))
        );
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn reloadable_file_provider_rejects_duplicate_version_ids() {
        let path = manifest_path("duplicate");
        write_manifest(
            &path,
            "current_version_id=v1\ncurrent_secret_hex=4141414141414141414141414141414141414141414141414141414141414141\nprevious_version_id=v1\nprevious_secret_hex=4242424242424242424242424242424242424242424242424242424242424242\n",
        );
        let handle = SecretHandle {
            secret_id: oid("file-provider-duplicate"),
            purpose: SecretPurpose::WebhookSigning,
        };
        assert_eq!(
            ReloadingFileSecretProvider::new(handle, path.clone()).map(|_| ()),
            Err(SecretProviderError::Conflict)
        );
        fs::remove_file(path).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn reloadable_file_provider_rejects_group_readable_manifest() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = manifest_path("permissions");
        fs::write(
            &path,
            "current_version_id=v1\ncurrent_secret_hex=4141414141414141414141414141414141414141414141414141414141414141\n",
        )
        .expect("write manifest");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod manifest");
        let handle = SecretHandle {
            secret_id: oid("file-provider-permissions"),
            purpose: SecretPurpose::MachineTokenSigning,
        };
        assert_eq!(
            ReloadingFileSecretProvider::new(handle, path.clone()).map(|_| ()),
            Err(SecretProviderError::InvalidMaterial)
        );
        fs::remove_file(path).expect("cleanup");
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
    fn delayed_retry_of_previous_rotation_never_rolls_current_back() {
        let provider = InMemorySecretProvider::default();
        let handle = SecretHandle {
            secret_id: oid("join-delayed-retry"),
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
        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v2"),
                    material: material(b"second-secret"),
                },
            )
            .expect("v2");
        let current = provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v3"),
                    material: material(b"third-secret"),
                },
            )
            .expect("v3");

        let delayed = provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v2"),
                    material: material(b"second-secret"),
                },
            )
            .expect("delayed exact retry");
        assert_eq!(delayed, current);
        assert_eq!(delayed.current.version_id, oid("v3"));

        assert_eq!(
            provider.rotate(
                &handle,
                SecretVersion {
                    version_id: oid("v2"),
                    material: material(b"changed-second-secret"),
                },
            ),
            Err(SecretProviderError::Conflict)
        );
        assert_eq!(
            provider
                .active_secret_set(&handle)
                .expect("state")
                .current
                .version_id,
            oid("v3")
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

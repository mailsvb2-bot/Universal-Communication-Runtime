use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use ucr_model::{EncryptedRecoveryPackage, RecoveryPackageAlgorithm, RecoveryPlan};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, DEFAULT_MAX_PAYLOAD_LEN, RecoveryError, recovery_plan_aad,
};

const RECOVERY_KDF_DOMAIN: &[u8] = b"UCR-RECOVERY-PACKAGE-KDF-V1\0";
pub const RECOVERY_PACKAGE_FORMAT_VERSION: u32 = 1;
pub const RECOVERY_SECRET_LEN: usize = 32;
pub const RECOVERY_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
pub const MAX_RECOVERY_MATERIAL_LEN: usize = DEFAULT_MAX_PAYLOAD_LEN as usize - AEAD_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPackageError {
    OsRandomUnavailable,
    InvalidRecoverySecret,
    InvalidPlan(RecoveryError),
    MaterialTooLarge,
    UnsupportedAlgorithm,
    UnsupportedFormatVersion,
    EncryptionFailed,
    DecryptionFailed,
}

impl From<RecoveryPackageError> for CanonicalError {
    fn from(error: RecoveryPackageError) -> Self {
        match error {
            RecoveryPackageError::InvalidPlan(error) => error.into(),
            RecoveryPackageError::MaterialTooLarge => {
                Self::new(CanonicalErrorCode::ResourceExhausted)
            }
            RecoveryPackageError::DecryptionFailed => {
                Self::new(CanonicalErrorCode::IntegrityFailure)
            }
            RecoveryPackageError::InvalidRecoverySecret
            | RecoveryPackageError::UnsupportedAlgorithm
            | RecoveryPackageError::UnsupportedFormatVersion => {
                Self::new(CanonicalErrorCode::InvalidArgument)
            }
            RecoveryPackageError::OsRandomUnavailable | RecoveryPackageError::EncryptionFailed => {
                Self::new(CanonicalErrorCode::Internal)
            }
        }
    }
}

pub struct RecoverySecret(Zeroizing<[u8; RECOVERY_SECRET_LEN]>);
impl core::fmt::Debug for RecoverySecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("RecoverySecret")
            .field(&"<secret>")
            .finish()
    }
}

impl RecoverySecret {
    /// Generates user-controlled recovery key material from the OS CSPRNG.
    ///
    /// # Errors
    /// Returns an explicit failure if OS randomness is unavailable.
    pub fn generate() -> Result<Self, RecoveryPackageError> {
        let mut bytes = Zeroizing::new([0_u8; RECOVERY_SECRET_LEN]);
        getrandom::fill(bytes.as_mut()).map_err(|_| RecoveryPackageError::OsRandomUnavailable)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RecoveryPackageError::InvalidRecoverySecret);
        }
        Ok(Self(bytes))
    }

    /// Imports an explicitly user-backed-up recovery key.
    ///
    /// # Errors
    /// The all-zero value is rejected fail-closed.
    pub fn import_user_backup(
        bytes: [u8; RECOVERY_SECRET_LEN],
    ) -> Result<Self, RecoveryPackageError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RecoveryPackageError::InvalidRecoverySecret);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Exports a temporary zeroizing copy for explicit user-controlled backup.
    #[must_use]
    pub fn export_user_backup(&self) -> Zeroizing<[u8; RECOVERY_SECRET_LEN]> {
        Zeroizing::new(*self.0)
    }
}
/// Encrypts explicit recovery material and binds it to one canonical plan.
///
/// # Errors
/// Fails for an invalid plan, oversized material, randomness failure, or AEAD failure.
pub fn seal_recovery_material(
    secret: &RecoverySecret,
    plan: &RecoveryPlan,
    material: &[u8],
) -> Result<EncryptedRecoveryPackage, RecoveryPackageError> {
    if material.len() > MAX_RECOVERY_MATERIAL_LEN {
        return Err(RecoveryPackageError::MaterialTooLarge);
    }
    let aad = recovery_plan_aad(plan).map_err(RecoveryPackageError::InvalidPlan)?;
    let mut nonce = [0_u8; RECOVERY_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| RecoveryPackageError::OsRandomUnavailable)?;
    let key = derive_recovery_key(secret, &aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| RecoveryPackageError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).map_err(|_| RecoveryPackageError::EncryptionFailed)?,
            Payload {
                msg: material,
                aad: &aad,
            },
        )
        .map_err(|_| RecoveryPackageError::EncryptionFailed)?;
    Ok(EncryptedRecoveryPackage {
        algorithm: RecoveryPackageAlgorithm::UcrV1,
        format_version: RECOVERY_PACKAGE_FORMAT_VERSION,
        nonce,
        ciphertext,
    })
}

/// Decrypts recovery material only under the exact plan used when sealing.
///
/// # Errors
/// Unsupported metadata, a changed plan, wrong key, or tampering fail closed.
pub fn open_recovery_material(
    secret: &RecoverySecret,
    plan: &RecoveryPlan,
    package: &EncryptedRecoveryPackage,
) -> Result<Zeroizing<Vec<u8>>, RecoveryPackageError> {
    if package.algorithm != RecoveryPackageAlgorithm::UcrV1 {
        return Err(RecoveryPackageError::UnsupportedAlgorithm);
    }
    if package.format_version != RECOVERY_PACKAGE_FORMAT_VERSION {
        return Err(RecoveryPackageError::UnsupportedFormatVersion);
    }
    if package.ciphertext.len() > DEFAULT_MAX_PAYLOAD_LEN as usize {
        return Err(RecoveryPackageError::MaterialTooLarge);
    }
    let aad = recovery_plan_aad(plan).map_err(RecoveryPackageError::InvalidPlan)?;
    let key = derive_recovery_key(secret, &aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| RecoveryPackageError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(
            &XNonce::try_from(&package.nonce[..])
                .map_err(|_| RecoveryPackageError::DecryptionFailed)?,
            Payload {
                msg: &package.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RecoveryPackageError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

fn derive_recovery_key(
    secret: &RecoverySecret,
    plan_binding: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RecoveryPackageError> {
    let hkdf = Hkdf::<Sha256>::new(Some(plan_binding), secret.0.as_ref());
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(RECOVERY_KDF_DOMAIN, output.as_mut())
        .map_err(|_| RecoveryPackageError::EncryptionFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        DeviceId, DeviceLifecycleState, HistoricalMessageAccess, IdentityId, NamespaceId, OpaqueId,
        RecoveryAuthority, RecoveryPlan, RecoveryPlanId, RecoveryTrustModel, TenantId, TenantScope,
    };

    use super::{
        CanonicalError, CanonicalErrorCode, MAX_RECOVERY_MATERIAL_LEN, RecoveryPackageError,
        RecoverySecret, open_recovery_material, seal_recovery_material,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn plan(identity: &str) -> RecoveryPlan {
        RecoveryPlan {
            plan_id: RecoveryPlanId::from_opaque(id("plan-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(id("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(id("namespace-a"))),
            },
            identity_id: IdentityId::from_opaque(id(identity)),
            authorities: vec![
                RecoveryAuthority::RecoveryKey,
                RecoveryAuthority::TrustedDevice(DeviceId::from_opaque(id("device-trusted"))),
            ],
            historical_message_access: HistoricalMessageAccess::ExplicitEncryptedRecovery,
            trust_model: RecoveryTrustModel::UserControlled,
            recovered_device_state: DeviceLifecycleState::ReverificationRequired,
        }
    }

    #[test]
    fn recovery_package_round_trip_is_bound_to_plan() {
        let secret = RecoverySecret::generate().expect("recovery secret");
        let recovery_plan = plan("identity-a");
        let package = seal_recovery_material(&secret, &recovery_plan, b"wrapped-key-material")
            .expect("seal recovery material");
        let opened =
            open_recovery_material(&secret, &recovery_plan, &package).expect("open package");
        assert_eq!(opened.as_slice(), b"wrapped-key-material");

        let different_identity = plan("identity-b");
        assert_eq!(
            open_recovery_material(&secret, &different_identity, &package),
            Err(RecoveryPackageError::DecryptionFailed)
        );
    }

    #[test]
    fn wrong_secret_and_tampering_fail_closed() {
        let secret = RecoverySecret::generate().expect("recovery secret");
        let other = RecoverySecret::generate().expect("other recovery secret");
        let plan = plan("identity-a");
        let package =
            seal_recovery_material(&secret, &plan, b"secret-history-key").expect("seal package");
        assert_eq!(
            open_recovery_material(&other, &plan, &package),
            Err(RecoveryPackageError::DecryptionFailed)
        );

        let mut tampered = package.clone();
        tampered.ciphertext[0] ^= 1;
        assert_eq!(
            open_recovery_material(&secret, &plan, &tampered),
            Err(RecoveryPackageError::DecryptionFailed)
        );

        let mut tampered_nonce = package.clone();
        tampered_nonce.nonce[0] ^= 1;
        assert_eq!(
            open_recovery_material(&secret, &plan, &tampered_nonce),
            Err(RecoveryPackageError::DecryptionFailed)
        );
    }

    #[test]
    fn recovery_secret_is_explicitly_exportable_but_redacted() {
        let secret = RecoverySecret::generate().expect("recovery secret");
        let exported = secret.export_user_backup();
        assert!(!exported.iter().all(|byte| *byte == 0));
        assert_eq!(format!("{secret:?}"), r#"RecoverySecret("<secret>")"#);

        let imported = RecoverySecret::import_user_backup(*exported).expect("import backup");
        let package =
            seal_recovery_material(&secret, &plan("identity-a"), b"material").expect("seal");
        assert_eq!(
            open_recovery_material(&imported, &plan("identity-a"), &package)
                .expect("open imported")
                .as_slice(),
            b"material"
        );
        assert!(matches!(
            RecoverySecret::import_user_backup([0_u8; 32]),
            Err(RecoveryPackageError::InvalidRecoverySecret)
        ));
    }

    #[test]
    fn recovery_package_failures_map_to_stable_canonical_categories() {
        assert_eq!(
            CanonicalError::from(RecoveryPackageError::DecryptionFailed).code,
            CanonicalErrorCode::IntegrityFailure
        );
        assert_eq!(
            CanonicalError::from(RecoveryPackageError::MaterialTooLarge).code,
            CanonicalErrorCode::ResourceExhausted
        );
        assert_eq!(
            CanonicalError::from(RecoveryPackageError::UnsupportedFormatVersion).code,
            CanonicalErrorCode::InvalidArgument
        );
    }

    #[test]
    fn recovery_material_budget_is_enforced_before_encryption() {
        let secret = RecoverySecret::generate().expect("recovery secret");
        let oversized = vec![0_u8; MAX_RECOVERY_MATERIAL_LEN + 1];
        assert_eq!(
            seal_recovery_material(&secret, &plan("identity-a"), &oversized),
            Err(RecoveryPackageError::MaterialTooLarge)
        );
    }
}

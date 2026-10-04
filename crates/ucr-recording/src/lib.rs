#![forbid(unsafe_code)]

use core::fmt::Write as _;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use ucr_core::{
    MAX_RECORDING_PROVIDER_EXPORT_BYTES, RecordingMediaProvider, RecordingProviderCaptureContext,
    RecordingProviderError, RecordingProviderExport, RecordingProviderHealth,
    RecordingProviderOperation, RecordingProviderRequest,
};
use ucr_model::{
    CryptoSuite, EncryptedGroupMediaFrame, MediaKind, PrincipalKind, PrincipalRef, TenantScope,
    VideoSourceKind,
};
use ucr_secrets::{ActiveSecretSet, SecretHandle, SecretProvider, SecretPurpose, SecretVersion};
use zeroize::Zeroizing;

const ARCHIVE_FORMAT_MAGIC: &[u8; 8] = b"UCRRAE01";
const OPERATION_RECORD_MAGIC: &[u8] = b"ucr.recording.operation.v1";
const FRAME_RECORD_MAGIC: &[u8] = b"ucr.recording.frame.v1";
const EXPORT_FORMAT_MAGIC: &[u8; 8] = b"UCRREX01";
const EXPORT_MEDIA_TYPE: &str = "application/vnd.ucr.recording-encrypted-archive.v1";
const ARCHIVE_AAD_DOMAIN: &[u8] = b"ucr.recording.archive.at-rest.v1";
const RECORDING_PATH_DOMAIN: &[u8] = b"ucr.recording.archive.path.v1";
const OPERATION_PATH_DOMAIN: &[u8] = b"ucr.recording.archive.operation.path.v1";
const FRAME_PATH_DOMAIN: &[u8] = b"ucr.recording.archive.frame.path.v1";
const MAX_ARCHIVE_OBJECT_BYTES: u64 = 20 * 1024 * 1024;
const MAX_ARCHIVE_PLAINTEXT_BYTES: usize = 19 * 1024 * 1024;
const AT_REST_KEY_BYTES: usize = 32;

#[derive(Clone)]
pub struct EncryptedArchiveRecordingProvider {
    root: Arc<PathBuf>,
    secret_provider: Arc<dyn SecretProvider>,
    secret_handle: SecretHandle,
}

impl core::fmt::Debug for EncryptedArchiveRecordingProvider {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncryptedArchiveRecordingProvider")
            .field("root", &"<private-recording-root>")
            .field("secret_provider", &self.secret_provider.provider_id())
            .field("secret_handle", &self.secret_handle)
            .finish()
    }
}

impl EncryptedArchiveRecordingProvider {
    /// Creates a local encrypted-at-rest archive provider.
    ///
    /// The configured secret handle must use `SecretPurpose::RecordingAtRest`. Provider-owned paths
    /// are private on Unix and symlinks/non-directories at those paths are rejected.
    ///
    /// # Errors
    /// Fails closed on unsafe paths, unavailable/invalid secret material, or filesystem failures.
    pub fn new(
        root: impl Into<PathBuf>,
        secret_provider: Arc<dyn SecretProvider>,
        secret_handle: SecretHandle,
    ) -> Result<Self, RecordingProviderError> {
        let root = root.into();
        if root.as_os_str().is_empty() || secret_handle.purpose != SecretPurpose::RecordingAtRest {
            return Err(RecordingProviderError::PolicyDenied);
        }
        let provider = Self {
            root: Arc::new(root),
            secret_provider,
            secret_handle,
        };
        provider.ensure_layout()?;
        provider.validate_secret_set(&provider.active_secret_set()?)?;
        Ok(provider)
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn operations_dir(&self) -> PathBuf {
        self.root.join("operations")
    }

    fn ensure_layout(&self) -> Result<(), RecordingProviderError> {
        ensure_private_directory(self.root.as_path())?;
        ensure_private_directory(&self.objects_dir())?;
        ensure_private_directory(&self.operations_dir())
    }

    fn active_secret_set(&self) -> Result<ActiveSecretSet, RecordingProviderError> {
        self.secret_provider
            .active_secret_set(&self.secret_handle)
            .map_err(|_| RecordingProviderError::TemporarilyUnavailable)
    }

    fn validate_secret_set(&self, set: &ActiveSecretSet) -> Result<(), RecordingProviderError> {
        if set.handle != self.secret_handle {
            return Err(RecordingProviderError::Internal);
        }
        validate_secret_version(&set.current)?;
        if let Some(previous) = &set.previous {
            validate_secret_version(previous)?;
            if previous.version_id == set.current.version_id {
                return Err(RecordingProviderError::Conflict);
            }
        }
        Ok(())
    }

    fn recording_digest(scope: &TenantScope, recording_id: &ucr_model::RecordingId) -> [u8; 32] {
        let mut encoded = CanonicalWriter::new(RECORDING_PATH_DOMAIN);
        encoded.scope(scope);
        encoded.bytes(recording_id.as_opaque().as_wire_bytes());
        sha256(encoded.as_slice())
    }

    fn recording_dir(&self, scope: &TenantScope, recording_id: &ucr_model::RecordingId) -> PathBuf {
        self.objects_dir()
            .join(hex_digest(&Self::recording_digest(scope, recording_id)))
    }

    fn operation_binding(request: &RecordingProviderRequest) -> [u8; 32] {
        let mut encoded = CanonicalWriter::new(OPERATION_PATH_DOMAIN);
        encoded.scope(&request.scope);
        encoded.bytes(request.recording_id.as_opaque().as_wire_bytes());
        encoded.u64(request.lifecycle_revision);
        encoded.u8(operation_code(request.operation));
        sha256(encoded.as_slice())
    }

    fn operation_path(&self, request: &RecordingProviderRequest) -> PathBuf {
        self.operations_dir().join(format!(
            "{}.uar",
            hex_digest(&Self::operation_binding(request))
        ))
    }

    fn frame_binding(
        context: &RecordingProviderCaptureContext,
        frame: &EncryptedGroupMediaFrame,
    ) -> [u8; 32] {
        let identity = context.capture_identity(frame);
        let mut encoded = CanonicalWriter::new(FRAME_PATH_DOMAIN);
        encoded.scope(&identity.scope);
        encoded.bytes(identity.recording_id.as_opaque().as_wire_bytes());
        encoded.bytes(identity.call_id.as_opaque().as_wire_bytes());
        encoded.u64(identity.lifecycle_revision);
        encoded.bytes(identity.group_id.as_opaque().as_wire_bytes());
        encoded.principal(&identity.source);
        encoded.bytes(identity.source_device_id.as_opaque().as_wire_bytes());
        encoded.u8(media_kind_code(identity.media_kind));
        encoded.u8(video_source_kind_code(identity.video_source_kind));
        encoded.bytes(identity.stream_id.as_wire_bytes());
        encoded.bytes(identity.negotiation_ref.as_wire_bytes());
        encoded.u64(identity.negotiation_generation);
        encoded.u64(identity.crypto_epoch);
        encoded.bytes(identity.crypto_state_ref.as_wire_bytes());
        encoded.u64(identity.sequence);
        sha256(encoded.as_slice())
    }

    fn frame_path(
        &self,
        context: &RecordingProviderCaptureContext,
        frame: &EncryptedGroupMediaFrame,
    ) -> PathBuf {
        self.recording_dir(&context.scope, &context.recording_id)
            .join(format!(
                "{}.uar",
                hex_digest(&Self::frame_binding(context, frame))
            ))
    }

    fn encode_operation(
        request: &RecordingProviderRequest,
    ) -> Result<Vec<u8>, RecordingProviderError> {
        let mut encoded = CanonicalWriter::new(OPERATION_RECORD_MAGIC);
        encoded.scope(&request.scope);
        encoded.bytes(request.recording_id.as_opaque().as_wire_bytes());
        encoded.bytes(request.call_id.as_opaque().as_wire_bytes());
        encoded.u64(request.lifecycle_revision);
        encoded.u8(operation_code(request.operation));
        encoded.i64(request.expires_at_unix_ms);
        encoded.finish()
    }

    fn encode_frame(
        context: &RecordingProviderCaptureContext,
        frame: &EncryptedGroupMediaFrame,
    ) -> Result<Vec<u8>, RecordingProviderError> {
        if context.scope != frame.header.scope || context.call_id != frame.header.call_id {
            return Err(RecordingProviderError::PolicyDenied);
        }

        let mut encoded = CanonicalWriter::new(FRAME_RECORD_MAGIC);
        encoded.scope(&context.scope);
        encoded.bytes(context.recording_id.as_opaque().as_wire_bytes());
        encoded.bytes(context.call_id.as_opaque().as_wire_bytes());
        encoded.u64(context.lifecycle_revision);
        encoded.i64(context.expires_at_unix_ms);

        encoded.scope(&frame.header.scope);
        encoded.bytes(frame.header.call_id.as_opaque().as_wire_bytes());
        encoded.bytes(frame.header.group_id.as_opaque().as_wire_bytes());
        encoded.bytes(frame.header.stream_id.as_wire_bytes());
        encoded.principal(&frame.header.source);
        encoded.bytes(frame.header.source_device_id.as_opaque().as_wire_bytes());
        encoded.bytes(frame.header.negotiation_ref.as_wire_bytes());
        encoded.u64(frame.header.negotiation_generation);
        encoded.u64(frame.header.crypto_epoch);
        encoded.bytes(frame.header.crypto_state_ref.as_wire_bytes());
        encoded.u8(crypto_suite_code(frame.header.crypto_suite));
        encoded.u8(frame.header.header_version);
        encoded.u8(media_kind_code(frame.header.media_kind));
        encoded.u8(video_source_kind_code(frame.header.video_source_kind));
        encoded.u64(frame.header.sequence);
        encoded.u64(frame.header.media_timestamp);
        encoded.bool(frame.header.keyframe);
        encoded.bytes(&frame.nonce);
        encoded.bytes(&frame.ciphertext);
        encoded.bytes(frame.source_signature.key_id.as_opaque().as_wire_bytes());
        encoded.string(&frame.source_signature.algorithm_id);
        encoded.u32(frame.source_signature.algorithm_version);
        encoded.bytes(&frame.source_signature.signature);
        encoded.finish()
    }

    fn seal(
        &self,
        plaintext: &[u8],
        binding: &[u8; 32],
    ) -> Result<Vec<u8>, RecordingProviderError> {
        if plaintext.len() > MAX_ARCHIVE_PLAINTEXT_BYTES {
            return Err(RecordingProviderError::CapacityExceeded);
        }
        let set = self.active_secret_set()?;
        self.validate_secret_set(&set)?;
        seal_with_version(&set.current, plaintext, binding)
    }

    fn open(&self, encoded: &[u8], binding: &[u8; 32]) -> Result<Vec<u8>, RecordingProviderError> {
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_OBJECT_BYTES {
            return Err(RecordingProviderError::CapacityExceeded);
        }
        let envelope = SealedEnvelope::parse(encoded)?;
        let set = self.active_secret_set()?;
        self.validate_secret_set(&set)?;
        let version = matching_secret_version(&set, envelope.version_id)
            .ok_or(RecordingProviderError::TemporarilyUnavailable)?;
        open_with_version(version, &envelope, binding)
    }

    fn write_idempotent(
        &self,
        path: &Path,
        plaintext: &[u8],
        binding: &[u8; 32],
    ) -> Result<(), RecordingProviderError> {
        if let Some(existing) = read_regular_file_if_present(path)? {
            let decoded = self.open(&existing, binding)?;
            return if decoded == plaintext {
                Ok(())
            } else {
                Err(RecordingProviderError::Conflict)
            };
        }

        let sealed = self.seal(plaintext, binding)?;
        let parent = path.parent().ok_or(RecordingProviderError::Internal)?;
        ensure_private_directory(parent)?;
        let (temporary_path, mut temporary_file) = create_private_temporary_file(parent)?;
        let write_result = (|| {
            temporary_file
                .write_all(&sealed)
                .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            temporary_file
                .sync_all()
                .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            drop(temporary_file);

            if fs::hard_link(&temporary_path, path).is_ok() {
                fs::remove_file(&temporary_path)
                    .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
                sync_directory(parent);
                Ok(())
            } else {
                let _ = fs::remove_file(&temporary_path);
                let existing = read_regular_file_if_present(path)?
                    .ok_or(RecordingProviderError::TemporarilyUnavailable)?;
                let decoded = self.open(&existing, binding)?;
                if decoded == plaintext {
                    Ok(())
                } else {
                    Err(RecordingProviderError::Conflict)
                }
            }
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result
    }

    fn ensure_started_recording_dir(
        &self,
        scope: &TenantScope,
        recording_id: &ucr_model::RecordingId,
    ) -> Result<PathBuf, RecordingProviderError> {
        let path = self.recording_dir(scope, recording_id);
        ensure_private_directory(&path)?;
        Ok(path)
    }

    fn require_started_recording_dir(
        &self,
        scope: &TenantScope,
        recording_id: &ucr_model::RecordingId,
    ) -> Result<PathBuf, RecordingProviderError> {
        let path = self.recording_dir(scope, recording_id);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RecordingProviderError::PolicyDenied);
        }
        require_private_permissions(&metadata)?;
        Ok(path)
    }

    fn delete_recording_objects(
        &self,
        scope: &TenantScope,
        recording_id: &ucr_model::RecordingId,
    ) -> Result<(), RecordingProviderError> {
        let path = self.recording_dir(scope, recording_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(RecordingProviderError::TemporarilyUnavailable),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RecordingProviderError::PolicyDenied);
        }
        require_private_permissions(&metadata)?;

        let entries =
            fs::read_dir(&path).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            let entry_path = entry.path();
            let entry_metadata = fs::symlink_metadata(&entry_path)
                .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            if entry_metadata.file_type().is_symlink() || !entry_metadata.is_file() {
                return Err(RecordingProviderError::PolicyDenied);
            }
            require_private_file_permissions(&entry_metadata)?;
            fs::remove_file(entry_path)
                .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
        }
        fs::remove_dir(&path).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
        sync_directory(&self.objects_dir());
        Ok(())
    }

    fn export_recording_objects(
        &self,
        scope: &TenantScope,
        recording_id: &ucr_model::RecordingId,
    ) -> Result<RecordingProviderExport, RecordingProviderError> {
        self.ensure_layout()?;
        let directory = self.require_started_recording_dir(scope, recording_id)?;
        let mut entries = Vec::new();
        for entry in
            fs::read_dir(&directory).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?
        {
            let entry = entry.map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(RecordingProviderError::PolicyDenied);
            }
            require_private_file_permissions(&metadata)?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| RecordingProviderError::PolicyDenied)?;
            let binding = binding_from_frame_file_name(&file_name)?;
            entries.push((file_name, entry.path(), binding));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let count =
            u32::try_from(entries.len()).map_err(|_| RecordingProviderError::CapacityExceeded)?;
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(EXPORT_FORMAT_MAGIC);
        bytes.extend_from_slice(&count.to_be_bytes());

        for (_, path, binding) in entries {
            let sealed = read_regular_file_if_present(&path)?
                .ok_or(RecordingProviderError::TemporarilyUnavailable)?;
            let plaintext = self.open(&sealed, &binding)?;
            let plaintext_len = u32::try_from(plaintext.len())
                .map_err(|_| RecordingProviderError::CapacityExceeded)?;
            let next_len = bytes
                .len()
                .checked_add(binding.len())
                .and_then(|value| value.checked_add(4))
                .and_then(|value| value.checked_add(plaintext.len()))
                .ok_or(RecordingProviderError::CapacityExceeded)?;
            if next_len > MAX_RECORDING_PROVIDER_EXPORT_BYTES {
                return Err(RecordingProviderError::CapacityExceeded);
            }
            bytes.extend_from_slice(&binding);
            bytes.extend_from_slice(&plaintext_len.to_be_bytes());
            bytes.extend_from_slice(&plaintext);
        }

        Ok(RecordingProviderExport {
            media_type: EXPORT_MEDIA_TYPE.to_owned(),
            bytes,
        })
    }
}

impl RecordingMediaProvider for EncryptedArchiveRecordingProvider {
    fn provider_id(&self) -> &'static str {
        "encrypted-archive-v1"
    }

    fn health(&self) -> RecordingProviderHealth {
        if self.ensure_layout().is_ok()
            && self
                .active_secret_set()
                .and_then(|set| self.validate_secret_set(&set))
                .is_ok()
        {
            RecordingProviderHealth::Healthy
        } else {
            RecordingProviderHealth::Unavailable
        }
    }

    fn apply(&self, request: &RecordingProviderRequest) -> Result<(), RecordingProviderError> {
        self.ensure_layout()?;
        let plaintext = Self::encode_operation(request)?;
        let binding = Self::operation_binding(request);

        match request.operation {
            RecordingProviderOperation::Start => {
                self.write_idempotent(&self.operation_path(request), &plaintext, &binding)?;
                self.ensure_started_recording_dir(&request.scope, &request.recording_id)?;
            }
            RecordingProviderOperation::Stop => {
                self.require_started_recording_dir(&request.scope, &request.recording_id)?;
                self.write_idempotent(&self.operation_path(request), &plaintext, &binding)?;
            }
            RecordingProviderOperation::Delete => {
                self.write_idempotent(&self.operation_path(request), &plaintext, &binding)?;
                self.delete_recording_objects(&request.scope, &request.recording_id)?;
            }
        }
        Ok(())
    }

    fn capture_encrypted_frame(
        &self,
        context: &RecordingProviderCaptureContext,
        frame: &EncryptedGroupMediaFrame,
    ) -> Result<(), RecordingProviderError> {
        self.ensure_layout()?;
        self.require_started_recording_dir(&context.scope, &context.recording_id)?;
        let plaintext = Self::encode_frame(context, frame)?;
        let binding = Self::frame_binding(context, frame);
        self.write_idempotent(&self.frame_path(context, frame), &plaintext, &binding)
    }

    fn export_encrypted_recording(
        &self,
        scope: &TenantScope,
        recording_id: &ucr_model::RecordingId,
    ) -> Result<RecordingProviderExport, RecordingProviderError> {
        self.export_recording_objects(scope, recording_id)
    }
}

fn validate_secret_version(version: &SecretVersion) -> Result<(), RecordingProviderError> {
    if version.material.as_bytes().len() == AT_REST_KEY_BYTES {
        Ok(())
    } else {
        Err(RecordingProviderError::PolicyDenied)
    }
}

fn matching_secret_version<'a>(
    set: &'a ActiveSecretSet,
    version_id: &[u8],
) -> Option<&'a SecretVersion> {
    if set.current.version_id.as_wire_bytes() == version_id {
        Some(&set.current)
    } else {
        set.previous
            .as_ref()
            .filter(|previous| previous.version_id.as_wire_bytes() == version_id)
    }
}

fn seal_with_version(
    version: &SecretVersion,
    plaintext: &[u8],
    binding: &[u8; 32],
) -> Result<Vec<u8>, RecordingProviderError> {
    validate_secret_version(version)?;
    let key_bytes: [u8; AT_REST_KEY_BYTES] = version
        .material
        .as_bytes()
        .try_into()
        .map_err(|_| RecordingProviderError::PolicyDenied)?;
    let key = Zeroizing::new(key_bytes);
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
    let aad = archive_aad(version.version_id.as_wire_bytes(), binding)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| RecordingProviderError::Internal)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).map_err(|_| RecordingProviderError::Internal)?,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| RecordingProviderError::Internal)?;

    let version_len = u16::try_from(version.version_id.as_wire_bytes().len())
        .map_err(|_| RecordingProviderError::CapacityExceeded)?;
    let ciphertext_len =
        u64::try_from(ciphertext.len()).map_err(|_| RecordingProviderError::CapacityExceeded)?;
    let mut encoded = Vec::with_capacity(
        ARCHIVE_FORMAT_MAGIC.len()
            + 2
            + usize::from(version_len)
            + nonce.len()
            + 8
            + ciphertext.len(),
    );
    encoded.extend_from_slice(ARCHIVE_FORMAT_MAGIC);
    encoded.extend_from_slice(&version_len.to_be_bytes());
    encoded.extend_from_slice(version.version_id.as_wire_bytes());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext_len.to_be_bytes());
    encoded.extend_from_slice(&ciphertext);
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_OBJECT_BYTES {
        return Err(RecordingProviderError::CapacityExceeded);
    }
    Ok(encoded)
}

fn open_with_version(
    version: &SecretVersion,
    envelope: &SealedEnvelope<'_>,
    binding: &[u8; 32],
) -> Result<Vec<u8>, RecordingProviderError> {
    validate_secret_version(version)?;
    let key_bytes: [u8; AT_REST_KEY_BYTES] = version
        .material
        .as_bytes()
        .try_into()
        .map_err(|_| RecordingProviderError::PolicyDenied)?;
    let key = Zeroizing::new(key_bytes);
    let aad = archive_aad(version.version_id.as_wire_bytes(), binding)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| RecordingProviderError::Internal)?;
    cipher
        .decrypt(
            &XNonce::try_from(&envelope.nonce[..]).map_err(|_| RecordingProviderError::Internal)?,
            Payload {
                msg: envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| RecordingProviderError::Internal)
}

fn archive_aad(version_id: &[u8], binding: &[u8; 32]) -> Result<Vec<u8>, RecordingProviderError> {
    let version_len =
        u16::try_from(version_id.len()).map_err(|_| RecordingProviderError::CapacityExceeded)?;
    let mut aad =
        Vec::with_capacity(ARCHIVE_AAD_DOMAIN.len() + 2 + version_id.len() + binding.len());
    aad.extend_from_slice(ARCHIVE_AAD_DOMAIN);
    aad.extend_from_slice(&version_len.to_be_bytes());
    aad.extend_from_slice(version_id);
    aad.extend_from_slice(binding);
    Ok(aad)
}

struct SealedEnvelope<'a> {
    version_id: &'a [u8],
    nonce: [u8; 24],
    ciphertext: &'a [u8],
}

impl<'a> SealedEnvelope<'a> {
    fn parse(encoded: &'a [u8]) -> Result<Self, RecordingProviderError> {
        if encoded.len() < ARCHIVE_FORMAT_MAGIC.len() + 2 + 24 + 8
            || !encoded.starts_with(ARCHIVE_FORMAT_MAGIC)
        {
            return Err(RecordingProviderError::Internal);
        }
        let mut offset = ARCHIVE_FORMAT_MAGIC.len();
        let version_len = usize::from(read_u16(encoded, &mut offset)?);
        let version_id = take(encoded, &mut offset, version_len)?;
        if version_id.is_empty() || version_id.len() > ucr_model::OpaqueId::MAX_LEN {
            return Err(RecordingProviderError::Internal);
        }
        let nonce_slice = take(encoded, &mut offset, 24)?;
        let nonce: [u8; 24] = nonce_slice
            .try_into()
            .map_err(|_| RecordingProviderError::Internal)?;
        let ciphertext_len = read_u64(encoded, &mut offset)?;
        let ciphertext_len = usize::try_from(ciphertext_len)
            .map_err(|_| RecordingProviderError::CapacityExceeded)?;
        let ciphertext = take(encoded, &mut offset, ciphertext_len)?;
        if offset != encoded.len() {
            return Err(RecordingProviderError::Internal);
        }
        Ok(Self {
            version_id,
            nonce,
            ciphertext,
        })
    }
}

fn read_u16(encoded: &[u8], offset: &mut usize) -> Result<u16, RecordingProviderError> {
    let bytes: [u8; 2] = take(encoded, offset, 2)?
        .try_into()
        .map_err(|_| RecordingProviderError::Internal)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(encoded: &[u8], offset: &mut usize) -> Result<u64, RecordingProviderError> {
    let bytes: [u8; 8] = take(encoded, offset, 8)?
        .try_into()
        .map_err(|_| RecordingProviderError::Internal)?;
    Ok(u64::from_be_bytes(bytes))
}

fn take<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], RecordingProviderError> {
    let end = offset
        .checked_add(len)
        .ok_or(RecordingProviderError::CapacityExceeded)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(RecordingProviderError::Internal)?;
    *offset = end;
    Ok(value)
}

fn ensure_private_directory(path: &Path) -> Result<(), RecordingProviderError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RecordingProviderError::PolicyDenied);
            }
            require_private_permissions(&metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            set_private_directory_permissions(path)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RecordingProviderError::PolicyDenied);
            }
            require_private_permissions(&metadata)
        }
        Err(_) => Err(RecordingProviderError::TemporarilyUnavailable),
    }
}

fn set_private_directory_permissions(path: &Path) -> Result<(), RecordingProviderError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
    }
    Ok(())
}

fn require_private_permissions(metadata: &fs::Metadata) -> Result<(), RecordingProviderError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
            return Err(RecordingProviderError::PolicyDenied);
        }
    }
    Ok(())
}

fn require_private_file_permissions(metadata: &fs::Metadata) -> Result<(), RecordingProviderError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
            return Err(RecordingProviderError::PolicyDenied);
        }
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<(), RecordingProviderError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
    }
    Ok(())
}

fn read_regular_file_if_present(path: &Path) -> Result<Option<Vec<u8>>, RecordingProviderError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RecordingProviderError::TemporarilyUnavailable),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ARCHIVE_OBJECT_BYTES
    {
        return Err(RecordingProviderError::PolicyDenied);
    }
    require_private_file_permissions(&metadata)?;
    let mut file = File::open(path).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| RecordingProviderError::CapacityExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_OBJECT_BYTES {
        return Err(RecordingProviderError::CapacityExceeded);
    }
    Ok(Some(bytes))
}

fn binding_from_frame_file_name(file_name: &str) -> Result<[u8; 32], RecordingProviderError> {
    let hex = file_name
        .strip_suffix(".uar")
        .ok_or(RecordingProviderError::PolicyDenied)?;
    if hex.len() != 64 {
        return Err(RecordingProviderError::PolicyDenied);
    }
    let mut binding = [0_u8; 32];
    let bytes = hex.as_bytes();
    for (index, output) in binding.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2]).ok_or(RecordingProviderError::PolicyDenied)?;
        let low = hex_nibble(bytes[index * 2 + 1]).ok_or(RecordingProviderError::PolicyDenied)?;
        *output = (high << 4) | low;
    }
    Ok(binding)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn create_private_temporary_file(parent: &Path) -> Result<(PathBuf, File), RecordingProviderError> {
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| RecordingProviderError::TemporarilyUnavailable)?;
        let path = parent.join(format!(".tmp-{}", hex_digest(&random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                set_private_file_permissions(&path)?;
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RecordingProviderError::TemporarilyUnavailable),
        }
    }
    Err(RecordingProviderError::TemporarilyUnavailable)
}

fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = File::open(path) {
        let _ = directory.sync_all();
    }
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn hex_digest(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

const fn operation_code(operation: RecordingProviderOperation) -> u8 {
    match operation {
        RecordingProviderOperation::Start => 1,
        RecordingProviderOperation::Stop => 2,
        RecordingProviderOperation::Delete => 3,
    }
}

const fn media_kind_code(kind: MediaKind) -> u8 {
    match kind {
        MediaKind::Audio => 1,
        MediaKind::Video => 2,
    }
}

const fn video_source_kind_code(kind: Option<VideoSourceKind>) -> u8 {
    match kind {
        None => 0,
        Some(VideoSourceKind::Camera) => 1,
        Some(VideoSourceKind::ScreenShare) => 2,
    }
}

const fn crypto_suite_code(suite: CryptoSuite) -> u8 {
    match suite {
        CryptoSuite::UcrV1 => 1,
    }
}

const fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Person => 1,
        PrincipalKind::Device => 2,
        PrincipalKind::ServiceAccount => 3,
        PrincipalKind::AiAgent => 4,
        PrincipalKind::Bot => 5,
        PrincipalKind::Organization => 6,
        PrincipalKind::Automation => 7,
        PrincipalKind::ExternalPlatform => 8,
    }
}

struct CanonicalWriter {
    bytes: Vec<u8>,
    oversized: bool,
}

impl CanonicalWriter {
    fn new(domain: &[u8]) -> Self {
        let mut writer = Self {
            bytes: Vec::with_capacity(512),
            oversized: false,
        };
        writer.bytes(domain);
        writer
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn finish(self) -> Result<Vec<u8>, RecordingProviderError> {
        if self.oversized || self.bytes.len() > MAX_ARCHIVE_PLAINTEXT_BYTES {
            Err(RecordingProviderError::CapacityExceeded)
        } else {
            Ok(self.bytes)
        }
    }

    fn bytes(&mut self, value: &[u8]) {
        let Ok(len) = u32::try_from(value.len()) else {
            self.oversized = true;
            return;
        };
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn scope(&mut self, scope: &TenantScope) {
        self.bytes(scope.tenant_id.as_opaque().as_wire_bytes());
        match &scope.namespace_id {
            Some(namespace) => {
                self.bool(true);
                self.bytes(namespace.as_opaque().as_wire_bytes());
            }
            None => self.bool(false),
        }
    }

    fn principal(&mut self, principal: &PrincipalRef) {
        self.bytes(principal.principal_id.as_opaque().as_wire_bytes());
        self.u8(principal_kind_code(principal.kind));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use ucr_model::{
        CallId, DeviceId, GroupId, GroupMediaFrameHeader, GroupMediaSourceSignature, KeyId,
        NamespaceId, OpaqueId, PrincipalId, RecordingId, TenantId,
    };
    use ucr_secrets::{InMemorySecretProvider, SecretMaterial, SecretVersion};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-a")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-a"))),
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ucr-recording-{name}-{}-{stamp}",
            std::process::id()
        ))
    }

    fn secret_handle() -> SecretHandle {
        SecretHandle {
            secret_id: oid("recording-at-rest"),
            purpose: SecretPurpose::RecordingAtRest,
        }
    }

    fn secret_version(id: &str, byte: u8) -> SecretVersion {
        SecretVersion {
            version_id: oid(id),
            material: SecretMaterial::new(vec![byte; 32]).expect("secret"),
        }
    }

    fn provider(
        root: &Path,
    ) -> (
        EncryptedArchiveRecordingProvider,
        Arc<InMemorySecretProvider>,
        SecretHandle,
    ) {
        let secrets = Arc::new(InMemorySecretProvider::default());
        let handle = secret_handle();
        secrets
            .provision(handle.clone(), secret_version("key-v1", 7))
            .expect("provision");
        let secret_provider: Arc<dyn SecretProvider> = secrets.clone();
        let provider =
            EncryptedArchiveRecordingProvider::new(root, secret_provider, handle.clone())
                .expect("provider");
        (provider, secrets, handle)
    }

    fn request(operation: RecordingProviderOperation, revision: u64) -> RecordingProviderRequest {
        RecordingProviderRequest {
            scope: scope(),
            recording_id: RecordingId::from_opaque(oid("recording-a")),
            call_id: CallId::from_opaque(oid("call-a")),
            lifecycle_revision: revision,
            operation,
            expires_at_unix_ms: 9_999_999,
        }
    }

    fn context() -> RecordingProviderCaptureContext {
        RecordingProviderCaptureContext {
            scope: scope(),
            recording_id: RecordingId::from_opaque(oid("recording-a")),
            call_id: CallId::from_opaque(oid("call-a")),
            lifecycle_revision: 2,
            expires_at_unix_ms: 9_999_999,
        }
    }

    fn frame(sequence: u64, fill: u8) -> EncryptedGroupMediaFrame {
        EncryptedGroupMediaFrame {
            header: GroupMediaFrameHeader {
                scope: scope(),
                call_id: CallId::from_opaque(oid("call-a")),
                group_id: GroupId::from_opaque(oid("group-a")),
                stream_id: oid("stream-a"),
                source: PrincipalRef {
                    principal_id: PrincipalId::from_opaque(oid("person-a")),
                    kind: PrincipalKind::Person,
                },
                source_device_id: DeviceId::from_opaque(oid("device-a")),
                negotiation_ref: oid("negotiation-a"),
                negotiation_generation: 3,
                crypto_epoch: 4,
                crypto_state_ref: oid("crypto-state-a"),
                crypto_suite: CryptoSuite::UcrV1,
                header_version: 1,
                media_kind: MediaKind::Video,
                video_source_kind: Some(VideoSourceKind::Camera),
                sequence,
                media_timestamp: 55,
                keyframe: true,
            },
            nonce: [9_u8; 24],
            ciphertext: vec![fill; 256],
            source_signature: GroupMediaSourceSignature {
                key_id: KeyId::from_opaque(oid("signing-a")),
                algorithm_id: "ed25519".to_owned(),
                algorithm_version: 1,
                signature: vec![5_u8; 64],
            },
        }
    }

    #[test]
    fn archive_uses_outer_encryption_and_exact_frame_retry_is_idempotent() {
        let root = temp_root("outer-encryption");
        let (provider, _, _) = provider(&root);
        let start = request(RecordingProviderOperation::Start, 2);
        provider.apply(&start).expect("start");

        let context = context();
        let frame = frame(10, 0xA7);
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("capture");
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("idempotent retry");

        let path = provider.frame_path(&context, &frame);
        let stored = fs::read(&path).expect("stored object");
        assert!(stored.starts_with(ARCHIVE_FORMAT_MAGIC));
        assert!(
            !stored
                .windows(frame.ciphertext.len())
                .any(|window| window == frame.ciphertext),
            "inner media ciphertext must still be encrypted by the at-rest layer"
        );
        let binding = EncryptedArchiveRecordingProvider::frame_binding(&context, &frame);
        let opened = provider.open(&stored, &binding).expect("decrypt at rest");
        assert_eq!(
            opened,
            EncryptedArchiveRecordingProvider::encode_frame(&context, &frame)
                .expect("frame record")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn changed_payload_reusing_capture_identity_conflicts() {
        let root = temp_root("collision");
        let (provider, _, _) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let first = frame(10, 1);
        let changed = frame(10, 2);
        provider
            .capture_encrypted_frame(&context, &first)
            .expect("capture");
        assert_eq!(
            provider.capture_encrypted_frame(&context, &changed),
            Err(RecordingProviderError::Conflict)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn current_and_previous_storage_keys_support_rotation_overlap() {
        let root = temp_root("rotation");
        let (provider, secrets, handle) = provider(&root);
        let start = request(RecordingProviderOperation::Start, 2);
        provider.apply(&start).expect("start under v1");
        let old_object = fs::read(provider.operation_path(&start)).expect("v1 object");

        secrets
            .rotate(&handle, secret_version("key-v2", 8))
            .expect("rotate");
        provider.apply(&start).expect("retry can read previous key");
        assert_eq!(
            provider
                .open(
                    &old_object,
                    &EncryptedArchiveRecordingProvider::operation_binding(&start),
                )
                .expect("old object decrypts through overlap"),
            EncryptedArchiveRecordingProvider::encode_operation(&start).expect("operation")
        );

        let context = context();
        let frame = frame(11, 3);
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("capture under v2");
        let new_object = fs::read(provider.frame_path(&context, &frame)).expect("v2 object");
        let envelope = SealedEnvelope::parse(&new_object).expect("envelope");
        assert_eq!(envelope.version_id, b"key-v2");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn export_removes_only_at_rest_layer_and_is_deterministic() {
        let root = temp_root("export");
        let (provider, _, _) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let first = frame(20, 8);
        let second = frame(21, 9);
        provider
            .capture_encrypted_frame(&context, &second)
            .expect("capture second");
        provider
            .capture_encrypted_frame(&context, &first)
            .expect("capture first");

        let export = provider
            .export_encrypted_recording(&context.scope, &context.recording_id)
            .expect("export");
        assert_eq!(export.media_type, EXPORT_MEDIA_TYPE);
        assert!(export.bytes.starts_with(EXPORT_FORMAT_MAGIC));
        assert!(
            !export
                .bytes
                .windows(ARCHIVE_FORMAT_MAGIC.len())
                .any(|window| window == ARCHIVE_FORMAT_MAGIC),
            "provider at-rest envelope must not leak into the exported artifact"
        );

        let repeat = provider
            .export_encrypted_recording(&context.scope, &context.recording_id)
            .expect("repeat export");
        assert_eq!(repeat, export);

        let first_record = EncryptedArchiveRecordingProvider::encode_frame(&context, &first)
            .expect("first frame record");
        let second_record = EncryptedArchiveRecordingProvider::encode_frame(&context, &second)
            .expect("second frame record");
        assert!(
            export
                .bytes
                .windows(first_record.len())
                .any(|window| window == first_record)
        );
        assert!(
            export
                .bytes
                .windows(second_record.len())
                .any(|window| window == second_record)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn export_rejects_unexpected_archive_entry_names() {
        let root = temp_root("export-unexpected-entry");
        let (provider, _, _) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let directory = provider.recording_dir(&context.scope, &context.recording_id);
        let unexpected = directory.join("not-a-frame.uar");
        fs::write(&unexpected, b"invalid").expect("unexpected entry");
        set_private_file_permissions(&unexpected).expect("permissions");

        assert_eq!(
            provider.export_encrypted_recording(&context.scope, &context.recording_id),
            Err(RecordingProviderError::PolicyDenied)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn delete_removes_recording_objects_but_keeps_encrypted_operation_receipt() {
        let root = temp_root("delete");
        let (provider, _, _) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let frame = frame(12, 4);
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("capture");

        let delete = request(RecordingProviderOperation::Delete, 4);
        provider.apply(&delete).expect("delete");
        assert!(
            !provider
                .recording_dir(&delete.scope, &delete.recording_id)
                .exists()
        );
        assert!(provider.operation_path(&delete).is_file());
        provider.apply(&delete).expect("delete retry");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn delete_recovers_after_restart_when_receipt_was_committed_before_object_cleanup() {
        let root = temp_root("delete-restart-recovery");
        let (provider, secrets, handle) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let frame = frame(15, 7);
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("capture");

        let delete = request(RecordingProviderOperation::Delete, 4);
        let receipt =
            EncryptedArchiveRecordingProvider::encode_operation(&delete).expect("delete receipt");
        let binding = EncryptedArchiveRecordingProvider::operation_binding(&delete);
        provider
            .write_idempotent(&provider.operation_path(&delete), &receipt, &binding)
            .expect("commit delete receipt before simulated crash");
        assert!(
            provider
                .recording_dir(&delete.scope, &delete.recording_id)
                .is_dir(),
            "media objects must still exist at the simulated crash point"
        );
        drop(provider);

        let secret_provider: Arc<dyn SecretProvider> = secrets;
        let restarted = EncryptedArchiveRecordingProvider::new(&root, secret_provider, handle)
            .expect("restart provider");
        restarted
            .apply(&delete)
            .expect("restart retry completes controlled deletion");
        assert!(
            !restarted
                .recording_dir(&delete.scope, &delete.recording_id)
                .exists(),
            "restart retry must remove the controlled recording objects"
        );
        assert!(
            restarted.operation_path(&delete).is_file(),
            "encrypted delete receipt must survive media cleanup for exact retry evidence"
        );
        restarted
            .apply(&delete)
            .expect("post-recovery exact retry remains idempotent");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_archive_fails_closed() {
        let root = temp_root("tamper");
        let (provider, _, _) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let frame = frame(13, 5);
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("capture");

        let path = provider.frame_path(&context, &frame);
        let mut stored = fs::read(&path).expect("stored");
        let last = stored.len() - 1;
        stored[last] ^= 0x80;
        fs::write(&path, stored).expect("tamper");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        }
        assert_eq!(
            provider.capture_encrypted_frame(&context, &frame),
            Err(RecordingProviderError::Internal)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_secret_purpose_is_rejected() {
        let root = temp_root("purpose");
        let secrets = Arc::new(InMemorySecretProvider::default());
        let handle = SecretHandle {
            secret_id: oid("wrong-purpose"),
            purpose: SecretPurpose::MediaCrypto,
        };
        secrets
            .provision(handle.clone(), secret_version("key-v1", 7))
            .expect("provision");
        let secret_provider: Arc<dyn SecretProvider> = secrets;
        let result = EncryptedArchiveRecordingProvider::new(&root, secret_provider, handle);
        assert_eq!(result.err(), Some(RecordingProviderError::PolicyDenied));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn provider_rejects_insecure_and_symlink_roots() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let insecure = temp_root("insecure-root");
        fs::create_dir_all(&insecure).expect("create insecure root");
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755))
            .expect("set insecure permissions");
        let secrets = Arc::new(InMemorySecretProvider::default());
        let handle = secret_handle();
        secrets
            .provision(handle.clone(), secret_version("key-v1", 7))
            .expect("provision");
        let secret_provider: Arc<dyn SecretProvider> = secrets.clone();
        assert_eq!(
            EncryptedArchiveRecordingProvider::new(&insecure, secret_provider, handle.clone())
                .err(),
            Some(RecordingProviderError::PolicyDenied)
        );

        let target = temp_root("symlink-target");
        fs::create_dir_all(&target).expect("create symlink target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("secure target");
        let link = temp_root("symlink-root");
        symlink(&target, &link).expect("create symlink");
        let secret_provider: Arc<dyn SecretProvider> = secrets;
        assert_eq!(
            EncryptedArchiveRecordingProvider::new(&link, secret_provider, handle).err(),
            Some(RecordingProviderError::PolicyDenied)
        );

        let _ = fs::remove_file(link);
        let _ = fs::remove_dir_all(target);
        let _ = fs::remove_dir_all(insecure);
    }

    #[cfg(unix)]
    #[test]
    fn archive_retry_rejects_weakened_file_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp_root("object-permissions");
        let (provider, _, _) = provider(&root);
        provider
            .apply(&request(RecordingProviderOperation::Start, 2))
            .expect("start");
        let context = context();
        let frame = frame(14, 6);
        provider
            .capture_encrypted_frame(&context, &frame)
            .expect("capture");
        let path = provider.frame_path(&context, &frame);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("weaken permissions");
        assert_eq!(
            provider.capture_encrypted_frame(&context, &frame),
            Err(RecordingProviderError::PolicyDenied)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore permissions");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stop_requires_a_started_archive() {
        let root = temp_root("stop");
        let (provider, _, _) = provider(&root);
        assert_eq!(
            provider.apply(&request(RecordingProviderOperation::Stop, 3)),
            Err(RecordingProviderError::TemporarilyUnavailable)
        );
        let _ = fs::remove_dir_all(root);
    }
}

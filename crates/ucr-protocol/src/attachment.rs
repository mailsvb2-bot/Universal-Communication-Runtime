use sha2::{Digest, Sha256};
use ucr_model::{AttachmentChunk, AttachmentContentId, AttachmentDescriptor, AttachmentId};

pub const ATTACHMENT_CONTENT_HASH_ALGORITHM: &str = "sha256";
pub const ATTACHMENT_CONTENT_HASH_LEN: usize = 32;
pub const MAX_ATTACHMENT_CHUNK_BYTES: u32 = 1_048_576;
pub const MAX_ATTACHMENT_CHUNKS: u32 = 65_536;
pub const MAX_ATTACHMENT_BYTES: u64 = 68_719_476_736;
pub const MAX_ATTACHMENT_MEDIA_TYPE_BYTES: usize = 255;
pub const MAX_ATTACHMENT_FILE_NAME_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentProtocolError {
    AttachmentTooLarge,
    InvalidChunkSize,
    InvalidChunkCount,
    InvalidMediaType,
    InvalidFileName,
    WrongAttachment,
    InvalidChunkIndex,
    InvalidChunkOffset,
    InvalidChunkLength,
    ChunkIntegrityMismatch,
    MissingOrDuplicateChunk,
    ContentIntegrityMismatch,
}

#[must_use]
pub fn attachment_content_id(bytes: &[u8]) -> AttachmentContentId {
    AttachmentContentId {
        sha256: Sha256::digest(bytes).into(),
    }
}

#[must_use]
pub fn canonical_attachment_chunk(
    attachment_id: AttachmentId,
    index: u32,
    offset_bytes: u64,
    bytes: Vec<u8>,
) -> AttachmentChunk {
    let sha256 = Sha256::digest(&bytes).into();
    AttachmentChunk {
        attachment_id,
        index,
        offset_bytes,
        bytes,
        sha256,
    }
}

/// Validates immutable attachment metadata and its bounded chunk layout.
///
/// # Errors
/// Rejects an attachment that exceeds the v1 size/chunk ceilings, has an inconsistent chunk
/// count, or carries invalid optional metadata.
pub fn validate_attachment_descriptor(
    descriptor: &AttachmentDescriptor,
) -> Result<(), AttachmentProtocolError> {
    if descriptor.size_bytes > MAX_ATTACHMENT_BYTES {
        return Err(AttachmentProtocolError::AttachmentTooLarge);
    }
    if descriptor.chunk_size_bytes == 0 || descriptor.chunk_size_bytes > MAX_ATTACHMENT_CHUNK_BYTES
    {
        return Err(AttachmentProtocolError::InvalidChunkSize);
    }

    let expected_chunk_count = if descriptor.size_bytes == 0 {
        0
    } else {
        descriptor
            .size_bytes
            .div_ceil(u64::from(descriptor.chunk_size_bytes))
    };
    if expected_chunk_count > u64::from(MAX_ATTACHMENT_CHUNKS)
        || u64::from(descriptor.chunk_count) != expected_chunk_count
    {
        return Err(AttachmentProtocolError::InvalidChunkCount);
    }

    validate_optional_text(
        descriptor.media_type.as_deref(),
        MAX_ATTACHMENT_MEDIA_TYPE_BYTES,
        AttachmentProtocolError::InvalidMediaType,
    )?;
    validate_optional_text(
        descriptor.file_name.as_deref(),
        MAX_ATTACHMENT_FILE_NAME_BYTES,
        AttachmentProtocolError::InvalidFileName,
    )?;
    Ok(())
}

/// Verifies one chunk against its immutable Attachment descriptor.
///
/// # Errors
/// Rejects wrong attachment identity, index/offset/length drift, or any byte-integrity mismatch.
pub fn verify_attachment_chunk(
    descriptor: &AttachmentDescriptor,
    chunk: &AttachmentChunk,
) -> Result<(), AttachmentProtocolError> {
    validate_attachment_descriptor(descriptor)?;
    if chunk.attachment_id != descriptor.attachment_id {
        return Err(AttachmentProtocolError::WrongAttachment);
    }
    if chunk.index >= descriptor.chunk_count {
        return Err(AttachmentProtocolError::InvalidChunkIndex);
    }

    let expected_offset = u64::from(chunk.index) * u64::from(descriptor.chunk_size_bytes);
    if chunk.offset_bytes != expected_offset {
        return Err(AttachmentProtocolError::InvalidChunkOffset);
    }

    let remaining = descriptor
        .size_bytes
        .checked_sub(expected_offset)
        .ok_or(AttachmentProtocolError::InvalidChunkOffset)?;
    let expected_len_u64 = remaining.min(u64::from(descriptor.chunk_size_bytes));
    let expected_len = usize::try_from(expected_len_u64)
        .map_err(|_| AttachmentProtocolError::InvalidChunkLength)?;
    if chunk.bytes.len() != expected_len {
        return Err(AttachmentProtocolError::InvalidChunkLength);
    }

    let actual_hash: [u8; 32] = Sha256::digest(&chunk.bytes).into();
    if actual_hash != chunk.sha256 {
        return Err(AttachmentProtocolError::ChunkIntegrityMismatch);
    }
    Ok(())
}

/// Verifies a complete attachment from a canonical-order chunk stream.
///
/// Transfer/persistence layers may receive chunks out of order for retry/resume, but they must
/// expose complete verification in canonical index order. The verifier consumes owned chunks one
/// at a time, so a storage-backed iterator can release each payload after hashing instead of
/// retaining the complete attachment in memory.
///
/// # Errors
/// Rejects invalid descriptors/chunks, missing, duplicate or out-of-order indices, or a
/// full-content hash mismatch.
pub fn verify_complete_attachment<I>(
    descriptor: &AttachmentDescriptor,
    chunks: I,
) -> Result<(), AttachmentProtocolError>
where
    I: IntoIterator<Item = AttachmentChunk>,
{
    validate_attachment_descriptor(descriptor)?;

    let mut content_hasher = Sha256::new();
    let mut expected_index = 0_u32;

    for chunk in chunks {
        if expected_index >= descriptor.chunk_count || chunk.index != expected_index {
            return Err(AttachmentProtocolError::MissingOrDuplicateChunk);
        }
        verify_attachment_chunk(descriptor, &chunk)?;
        content_hasher.update(&chunk.bytes);
        expected_index = expected_index
            .checked_add(1)
            .ok_or(AttachmentProtocolError::InvalidChunkCount)?;
    }

    if expected_index != descriptor.chunk_count {
        return Err(AttachmentProtocolError::MissingOrDuplicateChunk);
    }

    let actual_content_id = AttachmentContentId {
        sha256: content_hasher.finalize().into(),
    };
    if actual_content_id != descriptor.content_id {
        return Err(AttachmentProtocolError::ContentIntegrityMismatch);
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    max_bytes: usize,
    error: AttachmentProtocolError,
) -> Result<(), AttachmentProtocolError> {
    if let Some(value) = value
        && (value.is_empty() || value.len() > max_bytes)
    {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{OpaqueId, TenantId, TenantScope};

    fn attachment_id(value: &str) -> AttachmentId {
        AttachmentId::from_opaque(OpaqueId::new(value).expect("attachment id"))
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant id")),
            namespace_id: None,
        }
    }

    fn descriptor_for(bytes: &[u8], chunk_size_bytes: u32) -> AttachmentDescriptor {
        let chunk_count = if bytes.is_empty() {
            0
        } else {
            u32::try_from(
                u64::try_from(bytes.len())
                    .expect("fixture length")
                    .div_ceil(u64::from(chunk_size_bytes)),
            )
            .expect("fixture chunk count")
        };
        AttachmentDescriptor {
            attachment_id: attachment_id("attachment-a"),
            scope: scope(),
            content_id: attachment_content_id(bytes),
            size_bytes: u64::try_from(bytes.len()).expect("fixture length"),
            chunk_size_bytes,
            chunk_count,
            media_type: Some("application/octet-stream".to_owned()),
            file_name: Some("example.bin".to_owned()),
        }
    }

    fn chunks_for(descriptor: &AttachmentDescriptor, bytes: &[u8]) -> Vec<AttachmentChunk> {
        bytes
            .chunks(usize::try_from(descriptor.chunk_size_bytes).expect("chunk size"))
            .enumerate()
            .map(|(index, bytes)| {
                let index = u32::try_from(index).expect("fixture chunk index");
                canonical_attachment_chunk(
                    descriptor.attachment_id.clone(),
                    index,
                    u64::from(index) * u64::from(descriptor.chunk_size_bytes),
                    bytes.to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn complete_attachment_verifies_canonical_stream_after_resume() {
        let bytes = b"0123456789abcdef";
        let descriptor = descriptor_for(bytes, 4);
        let chunks = chunks_for(&descriptor, bytes);

        assert_eq!(verify_complete_attachment(&descriptor, chunks), Ok(()));
    }

    #[test]
    fn out_of_order_complete_stream_is_rejected() {
        let bytes = b"0123456789abcdef";
        let descriptor = descriptor_for(bytes, 4);
        let mut chunks = chunks_for(&descriptor, bytes);
        chunks.swap(0, 3);

        assert_eq!(
            verify_complete_attachment(&descriptor, chunks),
            Err(AttachmentProtocolError::MissingOrDuplicateChunk)
        );
    }

    #[test]
    fn tampered_chunk_is_rejected_before_full_content_acceptance() {
        let bytes = b"0123456789abcdef";
        let descriptor = descriptor_for(bytes, 4);
        let mut chunks = chunks_for(&descriptor, bytes);
        chunks[1].bytes[0] ^= 0xff;

        assert_eq!(
            verify_complete_attachment(&descriptor, chunks),
            Err(AttachmentProtocolError::ChunkIntegrityMismatch)
        );
    }

    #[test]
    fn forged_chunk_hash_cannot_hide_full_content_tampering() {
        let bytes = b"0123456789abcdef";
        let descriptor = descriptor_for(bytes, 4);
        let mut chunks = chunks_for(&descriptor, bytes);
        chunks[1].bytes[0] ^= 0xff;
        chunks[1].sha256 = Sha256::digest(&chunks[1].bytes).into();

        assert_eq!(
            verify_complete_attachment(&descriptor, &chunks),
            Err(AttachmentProtocolError::ContentIntegrityMismatch)
        );
    }

    #[test]
    fn missing_or_duplicate_chunk_is_rejected() {
        let bytes = b"0123456789abcdef";
        let descriptor = descriptor_for(bytes, 4);
        let mut chunks = chunks_for(&descriptor, bytes);
        chunks[3] = chunks[2].clone();

        assert_eq!(
            verify_complete_attachment(&descriptor, &chunks),
            Err(AttachmentProtocolError::MissingOrDuplicateChunk)
        );
    }

    #[test]
    fn empty_attachment_has_stable_content_identity_and_zero_chunks() {
        let descriptor = descriptor_for(b"", 1024);
        assert_eq!(descriptor.chunk_count, 0);
        assert_eq!(verify_complete_attachment(&descriptor, Vec::<AttachmentChunk>::new()), Ok(()));
        assert_eq!(
            descriptor.content_id.sha256,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn descriptor_rejects_unbounded_or_inconsistent_layout() {
        let mut descriptor = descriptor_for(b"abc", 2);
        descriptor.chunk_size_bytes = MAX_ATTACHMENT_CHUNK_BYTES + 1;
        assert_eq!(
            validate_attachment_descriptor(&descriptor),
            Err(AttachmentProtocolError::InvalidChunkSize)
        );

        let mut descriptor = descriptor_for(b"abc", 2);
        descriptor.chunk_count = 99;
        assert_eq!(
            validate_attachment_descriptor(&descriptor),
            Err(AttachmentProtocolError::InvalidChunkCount)
        );
    }
}

use core::fmt;

use super::{AttachmentId, TenantScope};

/// Stable content identity for one attachment payload.
///
/// The v1 algorithm is SHA-256 over the exact attachment bytes. The algorithm itself is
/// specified by the protocol layer; the model only carries the fixed-size digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttachmentContentId {
    pub sha256: [u8; 32],
}

impl fmt::Debug for AttachmentContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentContentId")
            .field("sha256", &"<opaque>")
            .finish()
    }
}

/// Canonical immutable attachment metadata.
///
/// Message owns only ordered Attachment IDs. Attachment bytes and integrity metadata remain a
/// separate canonical object so a large payload never becomes a Message/Event body.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentDescriptor {
    pub attachment_id: AttachmentId,
    pub scope: TenantScope,
    pub content_id: AttachmentContentId,
    pub size_bytes: u64,
    pub chunk_size_bytes: u32,
    pub chunk_count: u32,
    pub media_type: Option<String>,
    pub file_name: Option<String>,
}

impl fmt::Debug for AttachmentDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentDescriptor")
            .field("attachment_id", &self.attachment_id)
            .field("scope", &self.scope)
            .field("content_id", &self.content_id)
            .field("size_bytes", &self.size_bytes)
            .field("chunk_size_bytes", &self.chunk_size_bytes)
            .field("chunk_count", &self.chunk_count)
            .field(
                "media_type",
                &self.media_type.as_ref().map(|_| "<redacted>"),
            )
            .field("file_name", &self.file_name.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One independently verifiable attachment chunk.
///
/// Chunks are transient transfer objects. Their bytes are intentionally redacted from Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentChunk {
    pub attachment_id: AttachmentId,
    pub index: u32,
    pub offset_bytes: u64,
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

impl fmt::Debug for AttachmentChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentChunk")
            .field("attachment_id", &self.attachment_id)
            .field("index", &self.index)
            .field("offset_bytes", &self.offset_bytes)
            .field("bytes", &"<redacted>")
            .field("bytes_len", &self.bytes.len())
            .field("sha256", &"<opaque>")
            .finish()
    }
}

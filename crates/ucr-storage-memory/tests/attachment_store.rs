use ucr_core::{AttachmentStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{AttachmentDescriptor, AttachmentId, OpaqueId, TenantId, TenantScope};
use ucr_protocol::{attachment_content_id, canonical_attachment_chunk};
use ucr_storage_memory::MemoryLocalStore;

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant id")),
        namespace_id: None,
    }
}

fn descriptor(bytes: &[u8]) -> AttachmentDescriptor {
    AttachmentDescriptor {
        attachment_id: AttachmentId::from_opaque(
            OpaqueId::new("attachment-a").expect("attachment id"),
        ),
        scope: scope(),
        content_id: attachment_content_id(bytes),
        size_bytes: u64::try_from(bytes.len()).expect("fixture length"),
        chunk_size_bytes: 4,
        chunk_count: 2,
        media_type: Some("application/octet-stream".to_owned()),
        file_name: Some("resume.bin".to_owned()),
    }
}

#[test]
fn memory_attachment_store_deduplicates_and_rejects_conflicting_resume_chunk() {
    let store = MemoryLocalStore::default();
    let bytes = b"abcdefgh";
    let descriptor = descriptor(bytes);
    let chunk =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 0, 0, bytes[..4].to_vec());

    assert_eq!(
        store.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Duplicate)
    );
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk),
        Ok(DurableRecordStatus::Duplicate)
    );
    assert_eq!(
        store.attachment_chunk(&descriptor.scope, &descriptor.attachment_id, 0),
        Ok(Some(chunk.clone()))
    );

    let mut conflict = chunk;
    conflict.bytes[0] ^= 0xff;
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &conflict),
        Err(DurableStoreError::InvalidRecord)
    );
}

use ucr_core::{AttachmentStore, DurableRecordStatus, DurableStoreError, StorageProvider};
use ucr_model::{AttachmentDescriptor, AttachmentId, NamespaceId, OpaqueId, TenantId, TenantScope};
use ucr_protocol::{attachment_content_id, canonical_attachment_chunk};
use ucr_storage_memory::MemoryLocalStore;

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-attachment")),
        namespace_id: Some(NamespaceId::from_opaque(oid("namespace-attachment"))),
    }
}

fn descriptor(bytes: &[u8], chunk_size_bytes: u32) -> AttachmentDescriptor {
    let chunk_count = if bytes.is_empty() {
        0
    } else {
        u32::try_from(
            u64::try_from(bytes.len())
                .expect("fixture len")
                .div_ceil(u64::from(chunk_size_bytes)),
        )
        .expect("fixture chunk count")
    };
    AttachmentDescriptor {
        attachment_id: AttachmentId::from_opaque(oid("attachment-a")),
        scope: scope(),
        content_id: attachment_content_id(bytes),
        size_bytes: u64::try_from(bytes.len()).expect("fixture len"),
        chunk_size_bytes,
        chunk_count,
        media_type: Some("application/octet-stream".to_owned()),
        file_name: Some("resume.bin".to_owned()),
    }
}

#[test]
fn memory_attachment_chunks_are_idempotent_and_resume_from_first_gap() {
    let bytes = b"abcdefghijkl";
    let descriptor = descriptor(bytes, 4);
    let store = MemoryLocalStore::default();

    assert_eq!(store.schema_version(), Ok(13));
    assert_eq!(
        store.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Duplicate)
    );

    let chunk0 =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 0, 0, bytes[0..4].to_vec());
    let chunk1 =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 1, 4, bytes[4..8].to_vec());
    let chunk2 = canonical_attachment_chunk(
        descriptor.attachment_id.clone(),
        2,
        8,
        bytes[8..12].to_vec(),
    );

    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk1),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
        Ok(0)
    );
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk0),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
        Ok(2)
    );
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk2),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
        Ok(descriptor.chunk_count)
    );
    assert_eq!(
        store.attachment_chunk(&descriptor.scope, &descriptor.attachment_id, 1),
        Ok(Some(chunk1.clone()))
    );
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk1),
        Ok(DurableRecordStatus::Duplicate)
    );
}

#[test]
fn memory_attachment_store_rejects_missing_descriptor_and_semantic_conflicts() {
    let bytes = b"abcdefgh";
    let descriptor = descriptor(bytes, 4);
    let store = MemoryLocalStore::default();
    let chunk0 =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 0, 0, bytes[0..4].to_vec());

    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunk0),
        Err(DurableStoreError::InvalidRecord)
    );
    store
        .persist_attachment_descriptor(&descriptor)
        .expect("persist descriptor");

    let mut conflicting_descriptor = descriptor.clone();
    conflicting_descriptor.file_name = Some("different.bin".to_owned());
    assert_eq!(
        store.persist_attachment_descriptor(&conflicting_descriptor),
        Err(DurableStoreError::Conflict)
    );

    store
        .persist_attachment_chunk(&descriptor.scope, &chunk0)
        .expect("persist chunk");
    let conflicting_chunk =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 0, 0, b"WXYZ".to_vec());
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &conflicting_chunk),
        Err(DurableStoreError::Conflict)
    );
}

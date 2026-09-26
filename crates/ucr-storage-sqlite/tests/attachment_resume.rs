use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use ucr_core::{AttachmentStore, DurableRecordStatus, StorageProvider};
use ucr_model::{AttachmentDescriptor, AttachmentId, OpaqueId, TenantId, TenantScope};
use ucr_protocol::{attachment_content_id, canonical_attachment_chunk};
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TestDb(PathBuf);

impl TestDb {
    fn new() -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ucr-attachment-resume-{}-{sequence}.sqlite3",
            std::process::id()
        )))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

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
        file_name: Some("restart.bin".to_owned()),
    }
}

#[test]
fn sqlite_attachment_resume_state_survives_restart() {
    let db = TestDb::new();
    let bytes = b"abcdefgh";
    let descriptor = descriptor(bytes);
    let first = canonical_attachment_chunk(
        descriptor.attachment_id.clone(),
        0,
        0,
        bytes[..4].to_vec(),
    );
    let second = canonical_attachment_chunk(
        descriptor.attachment_id.clone(),
        1,
        4,
        bytes[4..].to_vec(),
    );

    {
        let store = SqliteLocalStore::open(&db.0).expect("open store");
        assert_eq!(
            store.schema_version(),
            Ok(SQLITE_SCHEMA_VERSION),
            "new store must initialize current schema"
        );
        assert_eq!(
            store.persist_attachment_descriptor(&descriptor),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_attachment_chunk(&descriptor.scope, &first),
            Ok(DurableRecordStatus::Persisted)
        );
    }

    {
        let store = SqliteLocalStore::open(&db.0).expect("reopen store");
        assert_eq!(
            store.attachment_descriptor(&descriptor.scope, &descriptor.attachment_id),
            Ok(Some(descriptor.clone()))
        );
        assert_eq!(
            store.attachment_chunk(&descriptor.scope, &descriptor.attachment_id, 0),
            Ok(Some(first.clone()))
        );
        assert_eq!(
            store.attachment_chunk(&descriptor.scope, &descriptor.attachment_id, 1),
            Ok(None)
        );
        assert_eq!(
            store.persist_attachment_chunk(&descriptor.scope, &first),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert_eq!(
            store.persist_attachment_chunk(&descriptor.scope, &second),
            Ok(DurableRecordStatus::Persisted)
        );
    }

    {
        let store = SqliteLocalStore::open(&db.0).expect("reopen completed store");
        assert_eq!(
            store.attachment_chunk(&descriptor.scope, &descriptor.attachment_id, 1),
            Ok(Some(second))
        );
    }
}

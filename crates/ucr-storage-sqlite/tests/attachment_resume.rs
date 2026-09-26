use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use ucr_core::{AttachmentStore, DurableRecordStatus, StorageProvider};
use ucr_model::{AttachmentDescriptor, AttachmentId, OpaqueId, TenantId, TenantScope};
use ucr_protocol::{attachment_content_id, canonical_attachment_chunk};
use rusqlite::Connection;
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore, UCR_SQLITE_APPLICATION_ID};

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
    let first =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 0, 0, bytes[..4].to_vec());
    let second =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 1, 4, bytes[4..].to_vec());

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


#[test]
fn sqlite_v44_migrates_to_v45_without_inventing_attachment_state() {
    let db = TestDb::new();

    {
        let store = SqliteLocalStore::open(&db.0).expect("initialize current store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
    }

    {
        let connection = Connection::open(&db.0).expect("open raw store");
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DROP TABLE IF EXISTS attachment_chunks;
                 DROP TABLE IF EXISTS attachments;
                 PRAGMA foreign_keys=ON;",
            )
            .expect("remove v45 attachment objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("preserve UCR store ownership");
        connection
            .pragma_update(None, "user_version", 44_u32)
            .expect("simulate exact v44 store");
    }

    let migrated = SqliteLocalStore::open(&db.0).expect("migrate v44 to v45");
    assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
    let descriptor = descriptor(b"abcdefgh");
    assert_eq!(
        migrated.attachment_descriptor(&descriptor.scope, &descriptor.attachment_id),
        Ok(None)
    );
    assert_eq!(
        migrated.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Persisted)
    );
}

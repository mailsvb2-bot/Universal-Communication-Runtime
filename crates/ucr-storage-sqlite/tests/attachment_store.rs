use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::Connection;
use ucr_core::{AttachmentStore, DurableRecordStatus, DurableStoreError, StorageProvider};
use ucr_model::{
    AttachmentChunk, AttachmentDescriptor, AttachmentId, NamespaceId, OpaqueId, TenantId,
    TenantScope,
};
use ucr_protocol::{attachment_content_id, canonical_attachment_chunk, verify_complete_attachment};
use ucr_storage_sqlite::{SQLITE_SCHEMA_VERSION, SqliteLocalStore};

static DB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TestDb(PathBuf);

impl TestDb {
    fn new() -> Self {
        let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ucr-attachment-store-{}-{sequence}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(oid("tenant-attachment-sqlite")),
        namespace_id: Some(NamespaceId::from_opaque(oid("namespace-attachment-sqlite"))),
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
        attachment_id: AttachmentId::from_opaque(oid("attachment-sqlite-a")),
        scope: scope(),
        content_id: attachment_content_id(bytes),
        size_bytes: u64::try_from(bytes.len()).expect("fixture len"),
        chunk_size_bytes,
        chunk_count,
        media_type: Some("application/octet-stream".to_owned()),
        file_name: Some("restart.bin".to_owned()),
    }
}

fn chunks(descriptor: &AttachmentDescriptor, bytes: &[u8]) -> Vec<AttachmentChunk> {
    bytes
        .chunks(usize::try_from(descriptor.chunk_size_bytes).expect("chunk size"))
        .enumerate()
        .map(|(index, bytes)| {
            let index = u32::try_from(index).expect("chunk index");
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
fn sqlite_attachment_resume_survives_restart_and_final_stream_verifies() {
    let db = TestDb::new();
    let bytes = b"abcdefghijkl";
    let descriptor = descriptor(bytes, 4);
    let chunks = chunks(&descriptor, bytes);

    {
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        assert_eq!(
            store.persist_attachment_descriptor(&descriptor),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_attachment_chunk(&descriptor.scope, &chunks[1]),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
            Ok(0)
        );
    }

    {
        let store = SqliteLocalStore::open(db.path()).expect("reopen after out-of-order chunk");
        assert_eq!(
            store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
            Ok(0)
        );
        store
            .persist_attachment_chunk(&descriptor.scope, &chunks[0])
            .expect("persist first chunk");
        assert_eq!(
            store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
            Ok(2)
        );
    }

    {
        let store = SqliteLocalStore::open(db.path()).expect("reopen after resume");
        store
            .persist_attachment_chunk(&descriptor.scope, &chunks[2])
            .expect("persist final chunk");
        assert_eq!(
            store.attachment_resume_index(&descriptor.scope, &descriptor.attachment_id),
            Ok(descriptor.chunk_count)
        );

        let persisted = (0..descriptor.chunk_count)
            .map(|index| {
                store
                    .attachment_chunk(&descriptor.scope, &descriptor.attachment_id, index)
                    .expect("load chunk")
                    .expect("chunk present")
            })
            .collect::<Vec<_>>();
        assert_eq!(verify_complete_attachment(&descriptor, persisted), Ok(()));
    }
}

#[test]
fn sqlite_attachment_descriptor_and_chunks_are_idempotent_and_conflict_safe() {
    let db = TestDb::new();
    let bytes = b"abcdefgh";
    let descriptor = descriptor(bytes, 4);
    let chunks = chunks(&descriptor, bytes);
    let store = SqliteLocalStore::open(db.path()).expect("open store");

    assert_eq!(
        store.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Duplicate)
    );

    let mut changed = descriptor.clone();
    changed.file_name = Some("changed.bin".to_owned());
    assert_eq!(
        store.persist_attachment_descriptor(&changed),
        Err(DurableStoreError::Conflict)
    );

    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunks[0]),
        Ok(DurableRecordStatus::Persisted)
    );
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &chunks[0]),
        Ok(DurableRecordStatus::Duplicate)
    );

    let conflicting =
        canonical_attachment_chunk(descriptor.attachment_id.clone(), 0, 0, b"WXYZ".to_vec());
    assert_eq!(
        store.persist_attachment_chunk(&descriptor.scope, &conflicting),
        Err(DurableStoreError::Conflict)
    );
}

#[test]
fn sqlite_v44_store_migrates_to_v45_without_losing_existing_database() {
    let db = TestDb::new();
    {
        let store = SqliteLocalStore::open(db.path()).expect("initialize current store");
        assert_eq!(store.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
    }

    {
        let connection = Connection::open(db.path()).expect("open raw sqlite");
        connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DROP TABLE attachment_chunks;
                 DROP TABLE attachments;
                 PRAGMA user_version=44;",
            )
            .expect("simulate exact v44 store");
    }

    let migrated = SqliteLocalStore::open(db.path()).expect("migrate v44");
    assert_eq!(migrated.schema_version(), Ok(45));

    let bytes = b"abcd";
    let descriptor = descriptor(bytes, 4);
    assert_eq!(
        migrated.persist_attachment_descriptor(&descriptor),
        Ok(DurableRecordStatus::Persisted)
    );
}

#[test]
fn sqlite_corrupt_attachment_chunk_fails_closed_after_restart() {
    let db = TestDb::new();
    let bytes = b"abcdefgh";
    let descriptor = descriptor(bytes, 4);
    let chunks = chunks(&descriptor, bytes);

    {
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        store
            .persist_attachment_descriptor(&descriptor)
            .expect("persist descriptor");
        store
            .persist_attachment_chunk(&descriptor.scope, &chunks[0])
            .expect("persist chunk");
    }

    {
        let connection = Connection::open(db.path()).expect("open raw sqlite");
        connection
            .execute(
                "UPDATE attachment_chunks SET payload=?1
                 WHERE tenant_id=?2 AND namespace_present=1 AND namespace_id=?3
                   AND attachment_id=?4 AND chunk_index=0",
                rusqlite::params![
                    b"WXYZ".as_slice(),
                    descriptor.scope.tenant_id.as_opaque().as_str(),
                    descriptor
                        .scope
                        .namespace_id
                        .as_ref()
                        .expect("namespace")
                        .as_opaque()
                        .as_str(),
                    descriptor.attachment_id.as_opaque().as_str(),
                ],
            )
            .expect("corrupt payload");
    }

    let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
    assert_eq!(
        reopened.attachment_chunk(&descriptor.scope, &descriptor.attachment_id, 0),
        Err(DurableStoreError::Corrupt)
    );
}

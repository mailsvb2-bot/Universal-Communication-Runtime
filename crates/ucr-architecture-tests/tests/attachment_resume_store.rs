use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn attachment_resume_reuses_canonical_storage_provider_and_sqlite_owner() {
    let core = read("crates/ucr-core/src/lib.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/lib.rs");
    let sqlite_store = read("crates/ucr-storage-sqlite/src/attachment_store.rs");
    let adr = read("docs/adr/0111-attachment-resume-state-reuses-canonical-storage-provider.md");

    assert!(core.contains("pub trait AttachmentStore: StorageProvider"));
    assert!(core.contains("fn persist_attachment_descriptor"));
    assert!(core.contains("fn persist_attachment_chunk"));
    assert!(core.contains("fn attachment_chunk"));

    assert!(memory.contains("impl AttachmentStore for MemoryLocalStore"));
    assert!(sqlite.contains("const SQLITE_SCHEMA_V45: u32 = 45;"));
    assert!(sqlite.contains("const SQLITE_SCHEMA_V46: u32 = 46;"));
    assert!(sqlite.contains("const SQLITE_SCHEMA_V47: u32 = 47;"));
    assert!(sqlite.contains("const SQLITE_SCHEMA_V48: u32 = 48;"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 49;"));
    assert!(sqlite.contains("attachment_store::create_v45_objects"));
    assert!(sqlite.contains("migrate_v44_to_v45"));
    assert!(sqlite.contains("migrate_v45_to_v46"));
    assert!(sqlite.contains("migrate_v46_to_v47"));
    assert!(sqlite.contains("migrate_v47_to_v48"));
    assert!(sqlite.contains("migrate_v48_to_v49"));
    assert!(sqlite_store.contains("impl AttachmentStore for SqliteLocalStore"));
    assert!(sqlite_store.contains("verify_attachment_chunk(&descriptor, chunk)"));
    assert!(sqlite_store.contains("ON DELETE CASCADE"));

    assert!(adr.contains("does not create a second database"));
    assert!(adr.contains("survives close/reopen"));
}

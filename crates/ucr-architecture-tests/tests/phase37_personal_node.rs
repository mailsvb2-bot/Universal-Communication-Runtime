use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase37_personal_node_reuses_existing_communication_owners() {
    let model = read("crates/ucr-model/src/personal_node.rs");
    let protocol = read("crates/ucr-protocol/src/personal_node.rs");
    let runtime = read("crates/ucr-personal-node/src/lib.rs");
    let spec = read("spec/personal-node.md");

    assert!(model.contains("pub struct PersonalNodeProfile"));
    assert!(model.contains("EndpointKind"));
    for service in ["Sync", "EncryptedMailbox", "Relay", "Cache", "Bridge"] {
        assert!(model.contains(service));
    }
    assert!(protocol.contains("EndpointKind::PersonalNode"));
    assert!(
        runtime.contains(
            "PersonalNodeStore + SyncStore + StoreForwardStore + BridgeRegistrationStore"
        )
    );
    assert!(runtime.contains("pub fn admit_sync"));
    assert!(runtime.contains("pub fn admit_relay"));
    assert!(runtime.contains("pub fn admit_bridge"));
    assert!(!runtime.contains("struct Message"));
    assert!(!runtime.contains("struct DeliveryAttempt"));
    assert!(
        spec.contains(
            "not a second Identity, Message, Conversation, Delivery, Sync, Relay, Bridge"
        )
    );
}

#[test]
fn phase37_restart_storage_and_public_contract_are_locked() {
    let core = read("crates/ucr-core/src/personal_node.rs");
    let memory_root = read("crates/ucr-storage-memory/src/lib.rs");
    let memory = read("crates/ucr-storage-memory/src/personal_node_store.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/personal_node_store.rs");
    let sqlite_root = read("crates/ucr-storage-sqlite/src/lib.rs");
    let sqlite_tests = read("crates/ucr-storage-sqlite/tests/personal_node.rs");
    let proto = read("proto/ucr/v1/personal_node.proto");

    assert!(core.contains("pub trait PersonalNodeStore"));
    assert!(memory_root.contains("mod personal_node_store;"));
    assert!(memory.contains("impl PersonalNodeStore for MemoryLocalStore"));
    assert!(sqlite.contains("impl PersonalNodeStore for SqliteLocalStore"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V30: u32 = 30"));
    assert!(sqlite_root.contains("fn migrate_v29_to_v30"));
    assert!(sqlite_root.contains("personal_node_store::create_v30_objects"));
    assert!(sqlite_tests.contains("profile_mailbox_cache_and_disable_survive_restart"));
    assert!(
        sqlite_tests.contains("v29_migration_adds_empty_personal_node_state_without_inference")
    );
    assert!(proto.contains("message PersonalNodeProfile"));
    assert!(proto.contains("message PersonalNodeObject"));
    assert!(proto.contains("PERSONAL_NODE_SERVICE_ENCRYPTED_MAILBOX"));
    assert!(proto.contains("PERSONAL_NODE_STATE_DISABLED"));
}

#[test]
fn phase37_docs_permissions_privacy_security_and_ci_are_machine_locked() {
    let authorization = read("crates/ucr-protocol/src/authorization.rs");
    let runtime_tests = read("crates/ucr-personal-node/tests/reference.rs");
    let readme = read("README.md");
    let spec_index = read("spec/README.md");
    let metadata_tsv = read("spec/metadata-visibility.tsv");
    let metadata = read("spec/metadata-visibility.md");
    let adr = read("docs/adr/0075-phase37-personal-node-composes-existing-communication-owners.md");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/personal_node_threat.rs");
    let ci = read(".github/workflows/ci.yml");

    for permission in [
        "PERSONAL_NODE_READ_PERMISSION",
        "PERSONAL_NODE_MANAGE_PERMISSION",
        "PERSONAL_NODE_OBJECT_READ_PERMISSION",
        "PERSONAL_NODE_OBJECT_WRITE_PERMISSION",
        "PERSONAL_NODE_USE_PERMISSION",
    ] {
        assert!(authorization.contains(permission));
    }
    assert!(runtime_tests.contains("sync_relay_and_bridge_admission_reuse_canonical_owners"));
    assert!(runtime_tests.contains("cross_scope_actor_cannot_manage_personal_node"));
    assert!(readme.contains("Phase 37 adds a Prepared Personal Node boundary"));
    assert!(spec_index.contains("Phase 37 adds `personal-node.md`"));
    assert!(metadata_tsv.contains("personal_node\tPersonal Node\tprepared\t"));
    assert!(metadata.contains("Phase 37 promotes the Personal Node inventory row to `prepared`"));
    assert!(adr.contains("Phase 37 introduces a durable `PersonalNodeProfile`"));
    assert!(threat.contains(
        "Phase 37 Personal Node treats the owner-controlled node as a distinct compromised boundary"
    ));
    assert!(matrix.contains("Compromised Personal Node"));
    assert!(
        security
            .contains("fn compromised_personal_node_cannot_self_authorize_or_survive_disable()")
    );
    assert!(ci.contains("test -s spec/personal-node.md"));
    assert!(ci.contains("0075-phase37-personal-node-composes-existing-communication-owners.md"));
}

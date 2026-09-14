use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase36_federation_reuses_endpoint_crypto_sync_and_authorization_owners() {
    let model = read("crates/ucr-model/src/federation.rs");
    let protocol = read("crates/ucr-protocol/src/federation.rs");
    let runtime = read("crates/ucr-federation/src/lib.rs");
    let manifest = read("crates/ucr-federation/Cargo.toml");
    let spec = read("spec/federation.md");

    assert!(model.contains("pub struct FederationPeerRecord"));
    for state in [
        "Known",
        "Authenticated",
        "Authorized",
        "Trusted",
        "Revoked",
        "Blocked",
    ] {
        assert!(model.contains(state));
    }
    assert!(protocol.contains("validate_federation_transition"));
    assert!(protocol.contains("validate_federation_credential_rotation"));
    assert!(runtime.contains(
        "FederationPeerStore + SyncStore + DeviceLifecycleStore + TrustedSigningKeyResolver"
    ));
    assert!(runtime.contains("pub fn admit_sync"));
    assert!(!runtime.contains("MessageStore"));
    assert!(!runtime.contains("DeliveryStore"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
    assert!(spec.contains("not a second communication brain"));
}
#[test]
fn phase36_restart_lifecycle_and_public_contract_are_locked() {
    let core = read("crates/ucr-core/src/lib.rs");
    let memory = read("crates/ucr-storage-memory/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/federation_store.rs");
    let sqlite_root = read("crates/ucr-storage-sqlite/src/lib.rs");
    let sqlite_tests = read("crates/ucr-storage-sqlite/tests/federation.rs");
    let proto = read("proto/ucr/v1/federation.proto");

    assert!(core.contains("pub trait FederationPeerStore"));
    assert!(memory.contains("impl FederationPeerStore for MemoryLocalStore"));
    assert!(sqlite.contains("impl FederationPeerStore for SqliteLocalStore"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 29"));
    assert!(sqlite_root.contains("fn migrate_v28_to_v29"));
    assert!(sqlite_root.contains("federation_store::create_v29_objects"));
    assert!(sqlite_tests.contains("federation_trust_lifecycle_and_rotation_survive_restart"));
    assert!(sqlite_tests.contains("v28_migration_adds_empty_federation_state_without_inference"));
    assert!(proto.contains("message FederationPeer"));
    assert!(proto.contains("FEDERATION_TRUST_STATE_KNOWN"));
    assert!(proto.contains("FEDERATION_TRUST_STATE_AUTHENTICATED"));
    assert!(proto.contains("FEDERATION_TRUST_STATE_AUTHORIZED"));
    assert!(proto.contains("FEDERATION_TRUST_STATE_TRUSTED"));
    assert!(proto.contains("FEDERATION_TRUST_STATE_REVOKED"));
    assert!(proto.contains("FEDERATION_TRUST_STATE_BLOCKED"));
}
#[test]
fn phase36_docs_permissions_privacy_security_and_ci_are_machine_locked() {
    let authorization = read("crates/ucr-protocol/src/authorization.rs");
    let runtime_tests = read("crates/ucr-federation/tests/reference.rs");
    let readme = read("README.md");
    let spec_index = read("spec/README.md");
    let spec = read("spec/federation.md");
    let metadata = read("spec/metadata-visibility.md");
    let adr = read(
        "docs/adr/0074-phase36-federation-is-explicit-local-trust-over-endpoint-crypto-and-sync-owners.md",
    );
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/federation_threat.rs");
    let ci = read(".github/workflows/ci.yml");

    for permission in [
        "FEDERATION_PEER_READ_PERMISSION",
        "FEDERATION_PEER_MANAGE_PERMISSION",
        "FEDERATION_SYNC_PERMISSION",
    ] {
        assert!(authorization.contains(permission));
    }
    assert!(
        runtime_tests
            .contains("known_peer_requires_authentication_and_explicit_authorization_before_sync")
    );
    assert!(
        runtime_tests.contains("revoked_remote_device_invalidates_an_existing_authorized_session")
    );
    assert!(readme.contains(
        "**Phase 36 — Federation (Prepared explicit independent-node trust and sync admission).**"
    ));
    assert!(spec_index.contains("Phase 36 adds `federation.md`"));
    assert!(spec.contains("Cross-tenant federation is explicit local policy"));
    assert!(adr.contains(
        "Cross-tenant federation is therefore an explicit local authorization relationship"
    ));
    assert!(metadata.contains("Phase 36 Federation adds no new infrastructure trust-boundary row"));
    assert!(threat.contains("Phase 36 Federation treats an independent node as untrusted"));
    assert!(matrix.contains("Compromised federated node"));
    assert!(
        security.contains(
            "fn compromised_federated_node_cannot_self_authorize_or_survive_revocation()"
        )
    );
    assert!(ci.contains("test -s spec/federation.md"));
    assert!(ci.contains(
        "0074-phase36-federation-is-explicit-local-trust-over-endpoint-crypto-and-sync-owners.md"
    ));
}

use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase38_organization_mode_reuses_existing_canonical_owners() {
    let model = read("crates/ucr-model/src/organization.rs");
    let runtime = read("crates/ucr-organization-mode/src/lib.rs");
    let spec = read("spec/organization-mode.md");

    assert!(model.contains("pub struct OrganizationModeProfile"));
    assert!(model.contains("OrganizationManagedIdentityBinding"));
    assert!(model.contains("OrganizationManagedDeviceBinding"));
    assert!(runtime.contains("OrganizationModeStore"));
    assert!(runtime.contains("+ IdentityStore"));
    assert!(runtime.contains("+ DeviceLifecycleStore"));
    assert!(runtime.contains("+ StoreForwardStore"));
    assert!(runtime.contains("+ BridgeRegistrationStore"));
    for method in [
        "private_directory",
        "admit_relay",
        "admit_sfu",
        "admit_bridge",
    ] {
        assert!(runtime.contains(&format!("pub fn {method}")));
    }
    assert!(!runtime.contains("struct MessageEnvelope"));
    assert!(!runtime.contains("struct DeviceDescriptor"));
    assert!(!runtime.contains("struct IdentityRecord"));
    assert!(
        spec.contains(
            "not a second Identity, Device, Message, Conversation, Delivery, relay, SFU, Bridge or authorization brain"
        )
    );
    assert!(spec.contains("same UCR Protocol and canonical model as managed deployment"));
}

#[test]
fn phase38_sqlite_restart_migration_and_public_contract_are_locked() {
    let core = read("crates/ucr-core/src/organization.rs");
    let memory = read("crates/ucr-storage-memory/src/organization_store.rs");
    let sqlite_root = read("crates/ucr-storage-sqlite/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/organization_store.rs");
    let sqlite_tests = read("crates/ucr-storage-sqlite/tests/organization_mode.rs");
    let proto = read("proto/ucr/v1/organization_mode.proto");

    assert!(core.contains("pub trait OrganizationModeStore"));
    assert!(memory.contains("impl OrganizationModeStore for MemoryLocalStore"));
    assert!(sqlite.contains("impl OrganizationModeStore for SqliteLocalStore"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 32"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V30: u32 = 30"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V31: u32 = 31"));
    assert!(sqlite_root.contains("fn migrate_v30_to_v31"));
    assert!(sqlite_root.contains("organization_store::create_v31_objects"));
    assert!(sqlite_root.contains("fn migrate_v31_to_v32"));
    assert!(sqlite_tests.contains("profile_bindings_and_disable_survive_restart"));
    assert!(sqlite_tests.contains("v30_migration_adds_empty_organization_state_without_inference"));
    assert!(proto.contains("message OrganizationModeProfile"));
    assert!(proto.contains("message OrganizationManagedIdentityBinding"));
    assert!(proto.contains("message OrganizationManagedDeviceBinding"));
    assert!(proto.contains("ORGANIZATION_SERVICE_PRIVATE_SFU"));
    assert!(proto.contains("ORGANIZATION_MODE_STATE_DISABLED"));
}

#[test]
fn phase38_permissions_privacy_security_and_release_truth_are_locked() {
    let authorization = read("crates/ucr-protocol/src/authorization.rs");
    let reference = read("crates/ucr-organization-mode/tests/reference.rs");
    let metadata = read("spec/metadata-visibility.md");
    let metadata_tsv = read("spec/metadata-visibility.tsv");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let simulations = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/organization_mode_threat.rs");
    let adr = read(
        "docs/adr/0076-phase38-organization-mode-composes-existing-identity-device-and-infrastructure-owners.md",
    );
    let readme = read("README.md");
    let ci = read(".github/workflows/ci.yml");
    for permission in [
        "ORGANIZATION_READ_PERMISSION",
        "ORGANIZATION_MANAGE_PERMISSION",
        "ORGANIZATION_DISCOVERY_READ_PERMISSION",
        "ORGANIZATION_IDENTITY_MANAGE_PERMISSION",
        "ORGANIZATION_DEVICE_MANAGE_PERMISSION",
        "ORGANIZATION_RELAY_USE_PERMISSION",
        "ORGANIZATION_SFU_USE_PERMISSION",
        "ORGANIZATION_BRIDGE_USE_PERMISSION",
    ] {
        assert!(authorization.contains(permission));
    }
    assert!(
        reference.contains("managed_identity_device_and_private_directory_reuse_canonical_owners")
    );
    assert!(reference.contains("unmanaged_identity_and_ineligible_device_fail_closed"));
    assert!(metadata_tsv.contains("organization_node\tOrganization Node\tprepared\t"));
    assert!(
        metadata.contains("Phase 38 promotes the Organization Node inventory row to `prepared`")
    );
    assert!(threat.contains("Phase 38 Organization Mode treats an Organization Node"));
    assert!(simulations.contains("Compromised Organization Node"));
    assert!(
        security.contains("compromised_organization_node_cannot_self_authorize_or_survive_disable")
    );
    assert!(adr.contains("Phase 38 introduces one durable `OrganizationModeProfile`"));
    assert!(
        readme
            .contains("Phase 38 adds Prepared Organization Mode over exact tenant/namespace scope")
    );
    assert!(ci.contains("test -s spec/organization-mode.md"));
    assert!(ci.contains("0076-phase38-organization-mode-composes-existing-identity-device-and-infrastructure-owners.md"));
}

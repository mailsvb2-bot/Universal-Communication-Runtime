use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn protected_delivery_reuses_canonical_device_lifecycle_owner() {
    let orchestrator = read("crates/ucr-transport-orchestrator/src/lib.rs");
    let store_forward = read("crates/ucr-store-forward/src/lib.rs");
    let device_store = read("crates/ucr-storage-sqlite/src/device_store.rs");
    let adr = read("docs/adr/0112-protected-device-delivery-reuses-canonical-device-lifecycle.md");

    assert!(orchestrator.contains("pub fn plan_protected"));
    assert!(orchestrator.contains("S: DeviceLifecycleStore + ?Sized"));
    assert!(orchestrator.contains("device_allows_protected_access"));
    assert!(store_forward.contains("pub fn new_protected_origin"));
    assert!(store_forward.contains("protected_devices: Option<&'a dyn DeviceLifecycleStore>"));
    assert!(store_forward.contains(".plan_protected(intent, resources, hints, options, devices)"));
    assert!(
        store_forward.contains("None => self.orchestrator.plan(intent, resources, hints, options)")
    );
    assert!(device_store.contains("impl DeviceLifecycleStore for SqliteLocalStore"));
    assert!(adr.contains("Status: Accepted"));
    assert!(adr.contains("opaque relay"));
    assert!(adr.contains("minimum disclosure"));
}

#[test]
fn canon_e2e_proves_revoked_device_gets_no_new_protected_provider_call() {
    let e2e = read("crates/ucr-system-tests/tests/main_end_to_end.rs");
    let spec = read("spec/main-end-to-end.md");

    assert!(e2e.contains("e2e-post-revoke-protected-intent"));
    assert!(e2e.contains(".plan_protected("));
    assert!(e2e.contains("revoked device must not receive new protected content"));
    assert!(e2e.contains("provider.captured().is_empty()"));
    assert!(spec.contains("Revoked Device is rejected by protected route planning"));
}

use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn canon_main_e2e_remains_executable_and_traceable() {
    let workspace_manifest = read("Cargo.toml");
    let manifest = read("crates/ucr-system-tests/Cargo.toml");
    let test = read("crates/ucr-system-tests/tests/main_end_to_end.rs");
    let spec = read("spec/main-end-to-end.md");

    assert!(workspace_manifest.contains("\"crates/ucr-system-tests\""));
    assert!(manifest.contains("publish = false"));
    assert!(test.contains("fn canon_main_end_to_end()"));
    assert!(spec.contains("Canon §263"));
    assert!(spec.contains("22. A Device is revoked"));
    assert!(spec.contains("not a claim of live public-Internet/LAN hardware"));
}

#[test]
fn main_e2e_uses_canonical_owners_instead_of_a_second_brain() {
    let manifest = read("crates/ucr-system-tests/Cargo.toml");
    for owner in [
        "ucr-chat",
        "ucr-core",
        "ucr-protocol",
        "ucr-storage-sqlite",
        "ucr-store-forward",
        "ucr-transport-orchestrator",
        "ucr-video",
    ] {
        assert!(
            manifest.contains(owner),
            "main E2E lost canonical owner dependency {owner}"
        );
    }

    let test = read("crates/ucr-system-tests/tests/main_end_to_end.rs");
    for owner in [
        "ChatRuntime::new",
        "VideoRuntime::new",
        "TransportOrchestrator::new",
        "StoreForwardRuntime::new",
        "anti_entropy_summary_page",
        "negotiate_version",
        "revoke_device",
    ] {
        assert!(test.contains(owner), "main E2E no longer exercises {owner}");
    }
}

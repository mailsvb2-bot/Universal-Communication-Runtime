use std::{fs, path::PathBuf, process::Command};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn integration_conformance_profile_covers_universal_connector_requirements() {
    let matrix = read("sdk/conformance/matrix.json");
    let spec = read("spec/conformance-suite.md");
    for category in [
        "auth",
        "create",
        "join",
        "leave",
        "webhook",
        "idempotency",
        "expiry",
        "permissions",
        "tenant_isolation",
    ] {
        assert!(
            matrix.contains(&format!("\"{category}\"")),
            "missing integration conformance category {category}"
        );
    }
    assert!(spec.contains("## Integration profile"));
    assert!(spec.contains("tenant isolation"));
    assert!(spec.contains("contract + runtime-binding"));
}

#[test]
fn integration_conformance_validator_is_executable_and_fail_closed() {
    let status = Command::new("python3")
        .arg("sdk/conformance/validate.py")
        .current_dir(workspace())
        .status()
        .expect("run integration conformance validator");
    assert!(status.success(), "integration conformance validator failed");
}

use std::{fs, path::PathBuf, process::Command};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase41_conformance_artifacts_lock_the_canonical_eight_axis_sdk_matrix() {
    let spec = read("spec/conformance-suite.md");
    let adr =
        read("docs/adr/0087-phase41-conformance-suite-is-language-independent-and-fail-closed.md");
    let matrix = read("sdk/conformance/matrix.json");
    let workflow = read(".github/workflows/conformance.yml");

    for category in [
        "auth",
        "commands",
        "events",
        "retries",
        "permissions",
        "version_negotiation",
        "errors",
        "idempotency",
    ] {
        assert!(
            matrix.contains(&format!("\"{category}\"")),
            "missing {category}"
        );
    }
    for language in ["rust", "python", "typescript", "kotlin", "swift"] {
        assert!(
            matrix.contains(&format!("\"{language}\"")),
            "missing {language}"
        );
    }
    assert!(spec.contains("Phase 41 defines the **Prepared** UCR Conformance Suite"));
    assert!(spec.contains("not a new runtime"));
    assert!(adr.contains("Missing probes"));
    assert!(workflow.contains("fail-fast: false"));
    assert!(!workflow.contains("continue-on-error"));
    assert!(!workflow.contains("|| true"));
}

#[test]
fn phase41_language_probes_use_public_sdk_helpers_without_a_second_brain() {
    let probes = [
        "crates/ucr-sdk/tests/phase41_conformance.rs",
        "sdk/python/phase41_conformance.py",
        "sdk/typescript/phase41_conformance.ts",
        "sdk/kotlin/src/test/kotlin/org/ucr/sdk/Phase41Conformance.kt",
        "sdk/swift/Tests/main.swift",
    ];
    for path in probes {
        let source = read(path);
        assert!(source.contains("UCR_PHASE41_") || path.contains("ucr-sdk/tests"));
        let lowered = source.to_ascii_lowercase();
        for forbidden in ["ucr-storage", "ucr_core", "ucr-core", "sqlite"] {
            assert!(
                !lowered.contains(forbidden),
                "{path} imports forbidden owner {forbidden}"
            );
        }
    }

    let validator = read("sdk/conformance/validate.py");
    assert!(validator.contains("automatic_application_retry"));
    assert!(validator.contains("event_cursor"));
    assert!(validator.contains("canonical_errors_preserved"));
    assert!(validator.contains("direct_database_access"));
}

#[test]
fn phase41_fail_closed_validator_is_executable_release_evidence() {
    let status = Command::new("python3")
        .arg("sdk/conformance/validate.py")
        .current_dir(workspace())
        .status()
        .expect("run Phase-41 conformance validator");
    assert!(status.success(), "Phase-41 conformance validator failed");
}

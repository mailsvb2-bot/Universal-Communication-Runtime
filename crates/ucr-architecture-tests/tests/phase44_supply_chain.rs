use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase44_covers_canonical_supply_chain_controls() {
    let helper = read("tools/supply_chain.py");
    let spec = read("spec/supply-chain.md");
    let adr = read("docs/adr/0090-phase44-supply-chain-evidence-and-sigstore-attestation.md");
    let workflow = read(".github/workflows/phase44-supply-chain.yml");

    for marker in [
        "scan-secrets",
        "scan-actions",
        "SPDX-2.3",
        "manifest-create",
        "manifest-verify",
        "minimum-release-sequence",
        "expected-commit",
        "platform-binary-status",
    ] {
        assert!(
            helper.contains(marker),
            "missing Phase 44 helper control: {marker}"
        );
    }

    for marker in [
        "Dependency audit",
        "committed lockfiles",
        "secret scan",
        "SPDX 2.3",
        "build provenance",
        "Sigstore",
        "tamper",
        "rollback",
        "partial-update",
        "not-claimed-phase44",
    ] {
        assert!(
            spec.contains(marker),
            "missing Phase 44 spec marker: {marker}"
        );
    }

    assert!(adr.contains("Sigstore provenance is not Authenticode"));
    assert!(workflow.contains("cargo audit --file Cargo.lock"));
    assert!(workflow.contains("tools/supply_chain.py scan-secrets"));
    assert!(workflow.contains("tools/supply_chain.py scan-actions"));
    assert!(workflow.contains("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"));
    assert!(workflow.contains("gh attestation verify"));
    assert!(workflow.contains("--source-digest \"$GITHUB_SHA\""));
    assert!(!workflow.contains("continue-on-error"));
    assert!(!workflow.contains("|| true"));
}

#[test]
fn phase44_has_committed_lock_state_for_every_current_rust_surface() {
    for path in [
        "Cargo.lock",
        "fuzz/Cargo.lock",
        "crates/ucr-sdk/Cargo.lock",
        "crates/ucr-reference-messenger/Cargo.lock",
        "crates/ucr-ai-actor/Cargo.lock",
        "crates/ucr-chaos-lab/Cargo.lock",
    ] {
        let full = workspace().join(path);
        assert!(full.is_file(), "missing committed lockfile: {path}");
        assert!(
            fs::metadata(&full).map_or(0, |metadata| metadata.len()) > 0,
            "empty committed lockfile: {path}"
        );
    }
}

#[test]
fn every_external_action_is_pinned_to_a_full_commit_sha() {
    let workflows = workspace().join(".github/workflows");
    for entry in fs::read_dir(workflows).expect("workflow directory") {
        let path = entry.expect("workflow entry").path();
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let text = fs::read_to_string(&path).expect("workflow text");
        for line in text.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("uses:")
                .or_else(|| trimmed.strip_prefix("- uses:"))
            else {
                continue;
            };
            let use_value = rest.trim().trim_matches(|ch| ch == '\'' || ch == '"');
            if use_value.starts_with("./") {
                continue;
            }
            let (_, reference) = use_value.rsplit_once('@').unwrap_or_else(|| {
                panic!(
                    "external action has no ref in {}: {use_value}",
                    path.display()
                )
            });
            assert_eq!(
                reference.len(),
                40,
                "external action ref is not a full SHA in {}: {use_value}",
                path.display()
            );
            assert!(
                reference.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "external action ref is not hex in {}: {use_value}",
                path.display()
            );
        }
    }
}

#[test]
fn phase44_does_not_claim_platform_production_signing() {
    let spec = read("spec/supply-chain.md");
    let workflow = read(".github/workflows/phase44-supply-chain.yml");
    let helper = read("tools/supply_chain.py");

    assert!(spec.contains("Prepared ≠ Production"));
    assert!(spec.contains("does not satisfy the platform executable signature requirement"));
    assert!(workflow.contains("not-claimed-phase44"));
    assert!(!workflow.contains("platform-binary-status signed"));
    assert!(!workflow.contains("platform_binary_status=signed"));
    assert!(!helper.contains("platform_binary_status = \"signed\""));
}

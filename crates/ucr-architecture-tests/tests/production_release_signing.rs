use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn production_release_is_manual_main_only_and_environment_protected() {
    let workflow = read(".github/workflows/production-release-linux.yml");

    for marker in [
        "workflow_dispatch:",
        "environment: production",
        "source_commit:",
        "GITHUB_REF",
        "refs/heads/main",
        "GITHUB_SHA",
        "origin/main",
        "Production signing only accepts the exact current main head",
        "UCR_LINUX_GPG_PRIVATE_KEY_BASE64",
        "UCR_LINUX_GPG_FINGERPRINT",
    ] {
        assert!(
            workflow.contains(marker),
            "missing protected Production release marker: {marker}"
        );
    }

    assert!(!workflow.contains("contents: write"));
    assert!(!workflow.contains("pull_request_target"));
}

#[test]
fn production_release_requires_exact_main_push_proof() {
    let helper = read("tools/production_release.py");
    let workflow = read(".github/workflows/production-release-linux.yml");

    for marker in [
        "REQUIRED_MAIN_WORKFLOWS",
        r#""CI""#,
        r#""Conformance""#,
        r#""Phase 42 AI Actor""#,
        r#""Phase 43 Chaos Lab""#,
        r#""Phase 44 Supply Chain""#,
        r#""Phase 45 Production Hardening""#,
        r#"item.get("event") != "push""#,
        r#"item.get("headSha") != source_commit"#,
        r#"item.get("conclusion") != "success""#,
        "required exact-main workflows are not proven successful",
    ] {
        assert!(
            helper.contains(marker),
            "missing exact-main release proof marker: {marker}"
        );
    }

    assert!(workflow.contains("gh run list"));
    assert!(workflow.contains(r#"--commit "$SOURCE_COMMIT""#));
    assert!(workflow.contains("tools/production_release.py emit-readiness"));
}

#[test]
fn signed_binary_is_verified_live_before_production_claim() {
    let workflow = read(".github/workflows/production-release-linux.yml");
    let signing = read("tools/platform_signing.py");
    let readiness = read("tools/production_readiness.py");

    for marker in [
        "gpg --batch --yes",
        "--armor --detach-sign",
        "tools/platform_signing.py verify",
        "--platform linux-openpgp",
        "tools/production_readiness.py validate",
        "--mode production",
        r#"--signing-identity "$UCR_LINUX_GPG_FINGERPRINT_NORMALIZED""#,
    ] {
        assert!(
            workflow.contains(marker),
            "missing live Production signing marker: {marker}"
        );
    }

    assert!(signing.contains("expected exactly one OpenPGP VALIDSIG identity"));
    assert!(readiness.contains("Production requires live platform signature verification"));
    assert!(readiness.contains("_validate_live_signing_binding"));
}

#[test]
fn production_bundle_is_complete_and_supply_chain_attested() {
    let workflow = read(".github/workflows/production-release-linux.yml");

    for marker in [
        "cargo build --locked --profile production -p ucr-runtime",
        "cargo test --locked -p ucr-runtime",
        "tools/supply_chain.py sbom",
        "tools/supply_chain.py manifest-create",
        "tools/supply_chain.py manifest-verify",
        "ucr-runtime-linux-x86_64.asc",
        "ucr-platform-signing.json",
        "ucr-production-readiness.json",
        "ucr.spdx.json",
        "main-proof.json",
        "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
        "gh attestation verify",
        "--source-ref refs/heads/main",
        r#"--source-digest "$SOURCE_COMMIT""#,
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    ] {
        assert!(
            workflow.contains(marker),
            "missing signed release bundle marker: {marker}"
        );
    }
}

#[test]
fn canon_boundary_is_documented_without_false_production_claim() {
    let spec = read("spec/production-release.md");
    let adr = read("docs/adr/0094-production-release-requires-publisher-owned-platform-signing.md");

    for marker in [
        "Production artifact signing is proven only by a successful protected workflow execution",
        "GitHub/Sigstore attestation remains supply-chain provenance",
        "does **not** satisfy Canon Definition of Done item 31",
    ] {
        assert!(
            spec.contains(marker),
            "missing Production release honesty marker: {marker}"
        );
    }

    assert!(adr.contains("publisher-owned platform signing"));
    assert!(adr.contains("an actual successful publisher-signed release execution is required"));
    assert!(adr.contains("GitHub Environment secrets"));
}

#[test]
fn repository_never_contains_publisher_private_key_material() {
    let workflow = read(".github/workflows/production-release-linux.yml");
    let helper = read("tools/production_release.py");
    let adr = read("docs/adr/0094-production-release-requires-publisher-owned-platform-signing.md");

    let generic_private_key_marker = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
    let pgp_private_key_marker = ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].concat();

    for text in [workflow, helper, adr] {
        assert!(!text.contains(&generic_private_key_marker));
        assert!(!text.contains(&pgp_private_key_marker));
    }
}

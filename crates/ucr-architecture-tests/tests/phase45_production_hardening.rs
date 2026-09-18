use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn canonical_build_profiles_are_explicit() {
    let cargo = read("Cargo.toml");
    for profile in [
        "[profile.development]",
        "[profile.test]",
        "[profile.staging]",
        "[profile.production]",
    ] {
        assert!(
            cargo.contains(profile),
            "missing canonical build profile: {profile}"
        );
    }
    assert!(cargo.contains("[profile.production]\n"));
    assert!(cargo.contains("lto = \"thin\""));
    assert!(cargo.contains("codegen-units = 1"));
}

#[test]
fn production_claim_is_machine_fail_closed() {
    let helper = read("tools/production_readiness.py");
    let spec = read("spec/production-hardening.md");
    let adr = read("docs/adr/0091-phase45-production-maturity-requires-exact-release-evidence.md");

    for marker in [
        "ucr.production-readiness.v1",
        "CANDIDATE_REQUIRED",
        "PRODUCTION_REQUIRED",
        "platform_signing",
        "production_runtime",
        "telemetry_privacy",
        "candidate validation forbids a Production maturity claim",
        "Production requires the production build profile",
        "supply-chain attestation is not platform artifact signing",
    ] {
        assert!(
            helper.contains(marker),
            "missing readiness control: {marker}"
        );
    }

    for marker in [
        "Candidate ≠ Production",
        "Security release gate",
        "Data-safety release gate",
        "Compatibility release gate",
        "Performance release gate",
        "Observability and telemetry privacy",
        "Platform signing boundary",
    ] {
        assert!(
            spec.contains(marker),
            "missing Phase 45 spec marker: {marker}"
        );
    }

    assert!(adr.contains("Production maturity requires exact release evidence"));
    assert!(adr.contains("Sigstore/GitHub attestations cannot satisfy `platform_signing`"));
}

#[test]
fn development_environment_cannot_be_presented_as_production_runtime() {
    let dev = read("crates/ucr-dev/src/lib.rs");
    let dev_main = read("crates/ucr-dev/src/main.rs");
    let spec = read("spec/production-hardening.md");

    assert!(dev.contains("MemoryLocalStore"));
    assert!(dev.contains("TestTransport"));
    assert!(dev.contains("CapabilityMaturity::Experimental"));
    assert!(dev_main.contains("ucr dev"));
    assert!(dev_main.contains("ucr dev refuses non-loopback bind addresses"));
    assert!(spec.contains("`ucr dev` remains development-only"));
    assert!(spec.contains("must not depend on `TestTransport`, `MemoryLocalStore`"));
}

#[test]
fn production_runtime_is_durable_distinct_and_redaction_safe() {
    let cargo = read("Cargo.toml");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let main = read("crates/ucr-runtime/src/main.rs");

    assert!(cargo.contains("\"crates/ucr-runtime\""));
    assert!(runtime.contains("SqliteLocalStore"));
    assert!(runtime.contains("production runtime requires an explicitly initialized database"));
    assert!(runtime.contains("production local-daemon API requires a loopback bind"));
    assert!(runtime.contains("ucr_runtime_up"));
    assert!(runtime.contains("ucr_storage_schema_version"));
    assert!(!runtime.contains("MemoryLocalStore"));
    assert!(!runtime.contains("TestTransport"));
    assert!(!runtime.contains("credential_secret_hex"));
    assert!(!runtime.contains("UCR_DEV_CREDENTIAL_SECRET_HEX"));

    for command in ["\"init\"", "\"check\"", "\"metrics\"", "\"serve\""] {
        assert!(
            main.contains(command),
            "missing production runtime command: {command}"
        );
    }
}

#[test]
fn performance_budget_is_fixed_in_source_and_governed_by_adr() {
    let gate = read("tools/performance_gate.py");
    let adr = read("docs/adr/0092-phase45-performance-budget-is-a-release-contract.md");
    let spec = read("spec/production-hardening.md");

    for marker in [
        "WORKLOAD = \"1000-person-sfu-conference-lifecycle\"",
        "SAMPLES = 3",
        "MAX_SAMPLE_SECONDS = 10.0",
        "--profile",
        "production",
        "thousand_person_sfu_conference_fits_bounded_call_ceiling",
    ] {
        assert!(
            gate.contains(marker),
            "missing fixed performance marker: {marker}"
        );
    }
    assert!(!gate.contains("--max-sample-seconds"));
    assert!(adr.contains("**10.0 seconds per sample**"));
    assert!(adr.contains("A red build by itself is not sufficient justification"));
    assert!(spec.contains("10.0 seconds maximum per sample"));
    assert!(spec.contains("intentionally not a workflow parameter"));
}

#[test]
fn phase45_does_not_relabel_supply_chain_provenance_as_platform_signing() {
    let phase44 = read("spec/supply-chain.md");
    let phase45 = read("spec/production-hardening.md");
    let helper = read("tools/production_readiness.py");

    assert!(phase44.contains("does not satisfy the platform executable signature requirement"));
    assert!(phase45.contains("Sigstore-only evidence is rejected"));
    assert!(helper.contains("sigstore-only"));
    assert!(helper.contains("not-claimed-phase44"));
}

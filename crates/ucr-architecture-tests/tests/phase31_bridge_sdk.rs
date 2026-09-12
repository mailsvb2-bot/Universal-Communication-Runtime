use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase31_bridge_is_provider_boundary_without_second_communication_brain() {
    let runtime = read("crates/ucr-bridge/src/lib.rs");
    let model = read("crates/ucr-model/src/bridge.rs");
    let core = read("crates/ucr-core/src/lib.rs");
    let manifest = read("crates/ucr-bridge/Cargo.toml");
    assert!(runtime.contains("BridgeProvider"));
    assert!(runtime.contains("MessageStore"));
    assert!(runtime.contains("BridgeRegistrationStore"));
    assert!(runtime.contains("BridgeActionStore"));
    assert!(model.contains("BridgeProviderManifest"));
    assert!(core.contains("pub trait BridgeRegistrationStore"));
    assert!(core.contains("pub trait BridgeActionStore"));
    assert!(!runtime.contains("DeliveryStore"));
    assert!(!runtime.contains("persist_message"));
    assert!(!runtime.contains("BridgeMessageStore"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
}

#[test]
fn phase31_restart_safety_policy_and_provider_acceptance_are_machine_locked() {
    let runtime = read("crates/ucr-bridge/src/lib.rs");
    let tests = read("crates/ucr-bridge/tests/reference.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/bridge_store.rs");
    let sqlite_root = read("crates/ucr-storage-sqlite/src/lib.rs");
    let spec = read("spec/bridge-sdk.md");
    assert!(runtime.contains("DeliveryPolicy::NoExternalBridge"));
    assert!(runtime.contains("BridgeActionState::AcceptanceUnknown"));
    assert!(runtime.contains("validate_bridge_provider_acceptance"));
    assert!(tests.contains("accepted_action_deduplicates_without_second_provider_side_effect"));
    assert!(
        tests.contains(
            "crash_left_inflight_requires_explicit_unknown_recovery_without_provider_call"
        )
    );
    assert!(tests.contains("policy_and_payload_tampering_fail_before_provider_side_effect"));
    assert!(sqlite.contains("CREATE TABLE bridge_registrations"));
    assert!(sqlite.contains("CREATE TABLE bridge_actions"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 27"));
    assert!(spec.contains(
        "Provider acceptance/degradation is **not** canonical Delivery/Delivered/Read evidence"
    ));
    assert!(spec.contains("never provider plaintext"));
}

#[test]
fn phase31_public_contract_security_privacy_and_fuzz_are_machine_locked() {
    let proto = read("proto/ucr/v1/bridge.proto");
    let spec = read("spec/bridge-sdk.md");
    let adr = read(
        "docs/adr/0069-phase31-bridge-sdk-is-a-provider-extension-boundary-not-a-second-communication-brain.md",
    );
    let readme = read("README.md");
    let ci = read(".github/workflows/ci.yml");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let inventory = read("spec/metadata-visibility.tsv");
    let fuzz = read("fuzz/fuzz_targets/bridge_contract.rs");
    let smoke = read("fuzz/run-smoke.sh");
    assert!(proto.contains("service BridgeProviderService"));
    assert!(proto.contains("message BridgeProviderManifest"));
    assert!(proto.contains("message BridgeAction"));
    assert!(proto.contains("message BridgeEventPage"));
    assert!(spec.contains("text, edit, delete, reaction, files, audio, video, group, presence, typing, calls, threads and reply"));
    assert!(adr.contains("not a second communication brain"));
    assert!(threat.contains("Phase 31 adds compromised-Bridge evidence"));
    assert!(matrix.contains(
        "compromised_bridge_simulation_enforces_policy_and_scope_before_canonicalization"
    ));
    assert!(inventory.contains("bridge\tBridge\tprepared\t"));
    assert!(readme.contains(
        "**Phase 31 — Bridge SDK (Prepared/reference candidate; Telegram bridge not started).**"
    ));
    let protocol_guard = ci
        .split("- name: Protocol specification exists")
        .nth(1)
        .expect("protocol guard")
        .split("- name: Public contract exists")
        .next()
        .expect("protocol guard body");
    let public_guard = ci
        .split("- name: Public contract exists")
        .nth(1)
        .expect("public guard")
        .split("- name: ADR governance exists")
        .next()
        .expect("public guard body");
    let adr_guard = ci
        .split("- name: ADR governance exists")
        .nth(1)
        .expect("adr guard");
    assert!(protocol_guard.contains("test -s spec/bridge-sdk.md"));
    assert!(public_guard.contains("test -s proto/ucr/v1/bridge.proto"));
    assert!(adr_guard.contains("0069-phase31-bridge-sdk-is-a-provider-extension-boundary-not-a-second-communication-brain.md"));
    assert!(fuzz.contains("canonical_bridge_manifest"));
    assert!(fuzz.contains("validate_bridge_event_page"));
    assert!(smoke.contains("run_target bridge_contract"));
}

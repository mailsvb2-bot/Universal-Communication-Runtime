use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase33_vk_is_thin_text_bridge_without_second_brain() {
    let source = read("crates/ucr-bridge-vk/src/lib.rs");
    let manifest = read("crates/ucr-bridge-vk/Cargo.toml");
    let spec = read("spec/vk-bridge.md");
    assert!(source.contains("pub const VK_PROVIDER_ID: &str = \"vendor.vk.api\""));
    assert!(source.contains("pub const VK_API_VERSION: &str = \"5.199\""));
    assert!(source.contains("capabilities: vec![BridgeCapability::Text]"));
    assert!(source.contains("BridgeDataPermission::MessageContent"));
    assert!(source.contains("BridgeDataPermission::ExternalIdentityReferences"));
    assert!(source.contains("BridgeDataPermission::InboundEvents"));
    assert!(!source.contains("persist_message"));
    assert!(!source.contains("DeliveryStore"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
    assert!(spec.contains(
        "It introduces no VK Message store, Delivery store, Identity store or Conversation store"
    ));
    assert!(spec.contains("Overlay Conversation normalization remains Phase 35"));
}

#[test]
fn phase33_vk_https_idempotency_and_acceptance_semantics_are_locked() {
    let source = read("crates/ucr-bridge-vk/src/lib.rs");
    let manifest = read("crates/ucr-bridge-vk/Cargo.toml");
    let tests = read("crates/ucr-bridge-vk/tests/reference.rs");
    assert!(source.contains("https://api.vk.com/method"));
    assert!(source.contains("groups.getLongPollServer"));
    assert!(source.contains("messages.send"));
    assert!(source.contains("with_follow_redirects(false)"));
    assert!(source.contains("VK_MAX_RESPONSE_BODY_BYTES + 1"));
    assert!(source.contains("VkAccessToken(<redacted>)"));
    assert!(source.contains("stable_random_id"));
    assert!(source.contains("Sha256"));
    assert!(source.contains("ucr-vk-random-id-v1"));
    assert!(source.contains("action.scope.tenant_id.as_opaque().as_wire_bytes()"));
    assert!(source.contains("action.integration_id.as_opaque().as_wire_bytes()"));
    assert!(source.contains("action.action_id.as_opaque().as_wire_bytes()"));
    assert!(manifest.contains("sha2 = \"=0.11.0\""));
    assert!(source.contains("host.ends_with(\".vk.com\")"));
    assert!(source.contains("BridgeProviderFailure::AcceptanceUnknown"));
    assert!(source.contains("classify_vk_api_error"));
    assert!(source.contains("message.text.is_empty()"));
    assert!(source.contains("page_long_poll_events"));
    assert!(source.contains("format!(\"{}:{end}\", cursor.ts)"));
    assert!(manifest.contains("minreq = { version = \"=3.0.0\", default-features = false, features = [\"https-native-tls\"] }"));
    for name in [
        "vk_runtime_reuses_core_policy_and_phase31_dedup_ledger",
        "vk_failure_classification_prevents_blind_duplicate_retry",
        "vk_send_uses_stable_random_id_and_returns_no_delivery_claim",
        "vk_poll_maps_text_and_opaque_ts_cursor",
    ] {
        assert!(tests.contains(name));
    }
}

#[test]
fn phase33_security_spec_ci_and_fuzz_evidence_are_machine_locked() {
    let source = read("crates/ucr-bridge-vk/src/lib.rs");
    let readme = read("README.md");
    let spec_index = read("spec/README.md");
    let spec = read("spec/vk-bridge.md");
    let adr = read("docs/adr/0071-phase33-vk-is-a-thin-api-bridge-over-canonical-ucr.md");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/vk_bridge_threat.rs");
    let ci = read(".github/workflows/ci.yml");
    let fuzz = read("fuzz/fuzz_targets/vk_bridge_boundary.rs");
    let smoke = read("fuzz/run-smoke.sh");
    assert!(readme.contains("**Phase 33 — VK (Prepared text bridge; MAX bridge not started).**"));
    assert!(spec_index.contains("Phase 33 adds `vk-bridge.md`"));
    assert!(spec.contains("VK API 5.199"));
    assert!(adr.contains("thin API bridge over canonical UCR"));
    assert!(
        security
            .contains("fn compromised_vk_boundary_cannot_bypass_core_policy_or_choose_ucr_scope()")
    );
    assert!(
        matrix.contains("compromised_vk_boundary_cannot_bypass_core_policy_or_choose_ucr_scope")
    );
    assert!(threat.contains("Phase 33 adds concrete VK-adapter evidence"));
    assert!(ci.contains("test -s spec/vk-bridge.md"));
    assert!(ci.contains("0071-phase33-vk-is-a-thin-api-bridge-over-canonical-ucr.md"));
    assert!(fuzz.contains("fuzz_vk_wire_boundary(data)"));
    assert!(source.contains("pub fn fuzz_vk_wire_boundary(bytes: &[u8])"));
    assert!(source.contains("decode_api_envelope::<VkLongPollServerWire>"));
    assert!(source.contains("decode_long_poll_wire(bytes)"));
    assert!(fuzz.contains("VkAccessToken::new"));
    assert!(fuzz.contains("VkPeerTarget::parse"));
    assert!(smoke.contains("run_target vk_bridge_boundary"));
}

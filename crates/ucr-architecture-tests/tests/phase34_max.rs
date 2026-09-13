use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase34_max_is_thin_text_bridge_without_second_brain() {
    let source = read("crates/ucr-bridge-max/src/lib.rs");
    let manifest = read("crates/ucr-bridge-max/Cargo.toml");
    let spec = read("spec/max-bridge.md");
    assert!(source.contains("pub const MAX_PROVIDER_ID: &str = \"vendor.max.bot_api\""));
    assert!(source.contains("pub const MAX_BOT_API_SCHEMA_VERSION: &str = \"0.0.32\""));
    assert!(source.contains("capabilities: vec![BridgeCapability::Text]"));
    assert!(source.contains("BridgeDataPermission::MessageContent"));
    assert!(source.contains("BridgeDataPermission::ExternalIdentityReferences"));
    assert!(source.contains("BridgeDataPermission::InboundEvents"));
    assert!(!source.contains("persist_message"));
    assert!(!source.contains("DeliveryStore"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
    assert!(spec.contains(
        "It introduces no MAX Message store, Delivery store, Identity store or Conversation store"
    ));
    assert!(spec.contains("Overlay Conversation normalization remains Phase 35"));
}

#[test]
fn phase34_max_https_auth_marker_and_acceptance_semantics_are_locked() {
    let source = read("crates/ucr-bridge-max/src/lib.rs");
    let manifest = read("crates/ucr-bridge-max/Cargo.toml");
    let tests = read("crates/ucr-bridge-max/tests/reference.rs");
    assert!(source.contains("https://platform-api2.max.ru"));
    assert!(source.contains("with_header(\"authorization\", self.token.expose())"));
    assert!(source.contains("with_follow_redirects(false)"));
    assert!(source.contains("MAX_RESPONSE_BODY_BYTES + 1"));
    assert!(source.contains("MaxBotToken(<redacted>)"));
    assert!(source.contains("user:<positive-id>"));
    assert!(source.contains("chat:<non-zero-id>"));
    assert!(source.contains("types=message_created&v={MAX_BOT_API_SCHEMA_VERSION}"));
    assert!(source.contains("{kind}={id}&v={MAX_BOT_API_SCHEMA_VERSION}"));
    assert!(source.contains("!response.updates.is_empty() && marker == previous"));
    assert!(source.contains("400 | 401 | 403 | 404 | 405"));
    assert!(source.contains("BridgeProviderFailure::AcceptanceUnknown"));
    assert!(manifest.contains(
        "minreq = { version = \"=3.0.0\", default-features = false, features = [\"https-native-tls\"] }"
    ));
    for name in [
        "max_runtime_reuses_core_policy_and_phase31_dedup_ledger",
        "max_failure_classification_prevents_blind_duplicate_retry",
        "max_text_send_returns_acceptance_without_delivery_claim",
        "max_poll_maps_text_and_advances_opaque_cursor",
    ] {
        assert!(tests.contains(name));
    }
}

#[test]
fn phase34_security_spec_ci_and_fuzz_evidence_are_machine_locked() {
    let source = read("crates/ucr-bridge-max/src/lib.rs");
    let readme = read("README.md");
    let spec_index = read("spec/README.md");
    let spec = read("spec/max-bridge.md");
    let metadata = read("spec/metadata-visibility.tsv");
    let adr = read("docs/adr/0072-phase34-max-is-a-thin-bot-api-bridge-over-canonical-ucr.md");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/max_bridge_threat.rs");
    let ci = read(".github/workflows/ci.yml");
    let fuzz = read("fuzz/fuzz_targets/max_bridge_boundary.rs");
    let smoke = read("fuzz/run-smoke.sh");
    assert!(
        readme.contains(
            "**Phase 34 — MAX (Prepared text bridge; Overlay Conversations not started).**"
        )
    );
    assert!(spec_index.contains("Phase 34 adds `max-bridge.md`"));
    assert!(spec.contains("MAX Bot API"));
    assert!(spec.contains("Production Webhook ownership"));
    assert!(adr.contains("thin Bot API bridge over canonical UCR"));
    assert!(
        security.contains(
            "fn compromised_max_boundary_cannot_bypass_core_policy_or_choose_ucr_scope()"
        )
    );
    assert!(
        matrix.contains("compromised_max_boundary_cannot_bypass_core_policy_or_choose_ucr_scope")
    );
    assert!(threat.contains("Phase 34 adds concrete MAX-adapter evidence"));
    assert!(metadata.contains("Phase-34 MAX"));
    assert!(metadata.contains("MAX bot token"));
    assert!(ci.contains("test -s spec/max-bridge.md"));
    assert!(ci.contains("0072-phase34-max-is-a-thin-bot-api-bridge-over-canonical-ucr.md"));
    assert!(fuzz.contains("fuzz_max_wire_boundary(data)"));
    assert!(source.contains("pub fn fuzz_max_wire_boundary(bytes: &[u8])"));
    assert!(fuzz.contains("MaxBotToken::new"));
    assert!(fuzz.contains("MaxTarget::parse"));
    assert!(smoke.contains("run_target max_bridge_boundary"));
}

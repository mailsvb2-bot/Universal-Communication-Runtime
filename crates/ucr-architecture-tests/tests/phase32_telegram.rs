use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase32_telegram_is_thin_text_bridge_without_second_brain() {
    let source = read("crates/ucr-bridge-telegram/src/lib.rs");
    let manifest = read("crates/ucr-bridge-telegram/Cargo.toml");
    let spec = read("spec/telegram-bridge.md");
    assert!(source.contains("pub const TELEGRAM_PROVIDER_ID: &str = \"vendor.telegram.bot_api\""));
    assert!(source.contains("capabilities: vec![BridgeCapability::Text]"));
    assert!(source.contains("BridgeDataPermission::MessageContent"));
    assert!(source.contains("BridgeDataPermission::ExternalIdentityReferences"));
    assert!(source.contains("BridgeDataPermission::InboundEvents"));
    for forbidden in [
        "BridgeCapability::Edit",
        "BridgeCapability::Delete",
        "BridgeCapability::Files",
        "BridgeCapability::Calls",
    ] {
        assert!(!source.contains(&format!("capabilities: vec![{forbidden}")));
    }
    assert!(!source.contains("persist_message"));
    assert!(!source.contains("DeliveryStore"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
    assert!(spec.contains("It introduces no Telegram Message store, Delivery store, Identity store or Conversation store"));
    assert!(spec.contains("Overlay Conversation normalization remains Phase 35"));
}

#[test]
fn phase32_telegram_https_secret_bounds_and_acceptance_semantics_are_locked() {
    let source = read("crates/ucr-bridge-telegram/src/lib.rs");
    let manifest = read("crates/ucr-bridge-telegram/Cargo.toml");
    let tests = read("crates/ucr-bridge-telegram/tests/reference.rs");
    assert!(source.contains("https://api.telegram.org"));
    assert!(source.contains("with_follow_redirects(false)"));
    assert!(source.contains("TELEGRAM_MAX_RESPONSE_BODY_BYTES + 1"));
    assert!(source.contains("TELEGRAM_MAX_RESPONSE_HEADER_BYTES"));
    assert!(source.contains("TelegramBotToken(<redacted>)"));
    assert!(source.contains("client_debug_never_contains_bot_token"));
    assert!(source.contains("update_mapping_rejects_zero_actor_identity"));
    assert!(source.contains("TelegramApiFailure::RateLimited"));
    assert!(source.contains("BridgeProviderFailure::AcceptanceUnknown"));
    assert!(manifest.contains("minreq = { version = \"=3.0.0\", default-features = false, features = [\"https-native-tls\"] }"));
    assert!(!manifest.contains("features = [\"log\""));
    for name in [
        "telegram_runtime_reuses_core_policy_and_phase31_dedup_ledger",
        "telegram_failure_classification_prevents_blind_duplicate_retry",
        "telegram_text_send_returns_acceptance_without_delivery_claim",
        "invalid_cursor_fails_before_telegram_poll",
    ] {
        assert!(tests.contains(name));
    }
}

#[test]
fn phase32_security_spec_ci_and_fuzz_evidence_are_machine_locked() {
    let readme = read("README.md");
    let spec_index = read("spec/README.md");
    let spec = read("spec/telegram-bridge.md");
    let adr = read("docs/adr/0070-phase32-telegram-is-a-thin-bot-api-bridge-over-canonical-ucr.md");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let matrix = read("docs/architecture/THREAT_SIMULATIONS.md");
    let security = read("crates/ucr-security-tests/tests/telegram_bridge_threat.rs");
    let ci = read(".github/workflows/ci.yml");
    let fuzz = read("fuzz/fuzz_targets/telegram_bridge_boundary.rs");
    let smoke = read("fuzz/run-smoke.sh");
    assert!(
        readme.contains(
            "**Phase 35 — Overlay Conversations (Prepared cross-network logical groups).**"
        )
    );
    assert!(spec_index.contains("Phase 32 adds `telegram-bridge.md`"));
    assert!(spec.contains("Telegram Bot API 10.3"));
    assert!(adr.contains("thin Bot API bridge over canonical UCR"));
    assert!(security.contains(
        "fn compromised_telegram_boundary_cannot_bypass_core_policy_or_choose_ucr_scope()"
    ));
    assert!(
        matrix.contains(
            "compromised_telegram_boundary_cannot_bypass_core_policy_or_choose_ucr_scope"
        )
    );
    assert!(threat.contains("Phase 32 adds concrete Telegram-adapter evidence"));
    assert!(ci.contains("test -s spec/telegram-bridge.md"));
    assert!(ci.contains("0070-phase32-telegram-is-a-thin-bot-api-bridge-over-canonical-ucr.md"));
    assert!(fuzz.contains("TelegramBotToken::new"));
    assert!(fuzz.contains("TelegramChatTarget::parse"));
    assert!(smoke.contains("run_target telegram_bridge_boundary"));
}

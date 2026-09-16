use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase40_reference_messenger_has_only_public_ucr_dependency() {
    let cargo = read("crates/ucr-reference-messenger/Cargo.toml");
    let workspace_cargo = read("Cargo.toml");
    let client = read("crates/ucr-reference-messenger/src/client.rs");

    assert!(cargo.contains("ucr-sdk = { path = \"../ucr-sdk\" }"));
    for forbidden in [
        "ucr-core",
        "ucr-storage-memory",
        "ucr-storage-sqlite",
        "ucr-chat",
        "ucr-offline-groups",
        "ucr-store-forward",
        "ucr-transport-internet",
        "ucr-organization-mode",
    ] {
        assert!(
            !cargo.contains(forbidden),
            "hidden Reference Messenger dependency: {forbidden}"
        );
    }
    assert!(workspace_cargo.contains("\"crates/ucr-reference-messenger\""));
    assert!(client.contains("use ucr_sdk::"));
    assert!(!client.contains("ucr_core"));
    assert!(!client.contains("ucr_storage"));
}

#[test]
fn phase40_calls_are_reachable_through_the_same_public_sdk_boundary() {
    let sdk = read("crates/ucr-sdk/src/lib.rs");
    let contract = read("sdk/contract.json");
    let call_proto = read("proto/ucr/v1/call.proto");

    assert!(contract.contains("\"CallService\""));
    assert!(call_proto.contains("service CallService"));
    for method in ["start_call", "get_call", "signal_call"] {
        assert!(sdk.contains(&format!("pub async fn {method}")));
    }
    assert!(sdk.contains("pb::call_service_client::CallServiceClient<Channel>"));
    assert!(sdk.contains("ucr-service-credential-id-bin"));
    assert!(sdk.contains("ucr-service-credential-secret-bin"));
}

#[test]
fn phase40_keeps_required_proof_gaps_visible_instead_of_using_hidden_apis() {
    let capability = read("crates/ucr-reference-messenger/src/capability.rs");
    let spec = read("spec/reference-messenger.md");
    let adr = read("docs/adr/0078-phase40-reference-messenger-is-a-public-api-consumer.md");

    for required in [
        "Chat",
        "Groups",
        "Calls",
        "MultiDevice",
        "Local",
        "Offline",
        "P2p",
        "Recovery",
        "Accessibility",
    ] {
        assert!(
            capability.contains(required),
            "missing Phase-40 proof area: {required}"
        );
    }
    assert!(capability.contains("PublicApiGap"));
    assert!(capability.contains("PresentationModelOnly"));
    assert!(spec.contains("Phase 40 is incomplete"));
    assert!(spec.contains(
        "must not close a gap by linking the Reference Messenger directly to an internal owner"
    ));
    assert!(adr.contains("only UCR dependency is `ucr-sdk`"));
}

#[test]
fn phase40_presentation_contract_is_accessibility_and_localization_ready() {
    let accessibility = read("crates/ucr-reference-messenger/src/accessibility.rs");
    let presentation = read("crates/ucr-reference-messenger/src/presentation.rs");

    for required in [
        "screen_reader_semantics",
        "keyboard_navigation",
        "text_scaling",
        "captions",
        "subtitles",
        "transcription_surfaces",
        "high_contrast",
        "rtl_layout",
    ] {
        assert!(
            accessibility.contains(required),
            "missing accessibility requirement: {required}"
        );
    }
    for concept in ["Person", "Group", "Message", "Call", "Result"] {
        assert!(
            presentation.contains(concept),
            "missing primary user concept: {concept}"
        );
    }
    for forbidden in ["Stun", "Turn", "Quic", "Relay", "ProviderApi"] {
        assert!(
            !presentation.contains(forbidden),
            "infrastructure leaked into primary UX: {forbidden}"
        );
    }
    assert!(presentation.contains("AwaitingDeliveryOpportunity"));
}

use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase39_rust_sdk_is_a_client_only_public_contract_binding() {
    let cargo = read("crates/ucr-sdk/Cargo.toml");
    let build = read("crates/ucr-sdk/build.rs");
    let sdk = read("crates/ucr-sdk/src/lib.rs");

    assert!(!cargo.contains("ucr-core"));
    assert!(!cargo.contains("ucr-storage-memory"));
    assert!(!cargo.contains("ucr-storage-sqlite"));
    let workspace_cargo = read("Cargo.toml");
    assert!(workspace_cargo.contains("\"crates/ucr-sdk\""));
    assert!(build.contains(".build_client(true)"));
    assert!(build.contains(".build_server(false)"));
    assert!(sdk.contains("tonic::include_proto!(\"ucr.v1\")"));
    assert!(sdk.contains("pub struct UcrSdkClient"));
    assert!(sdk.contains("ucr-service-credential-id-bin"));
    assert!(sdk.contains("ucr-service-credential-secret-bin"));
    assert!(sdk.contains("[REDACTED]"));
    assert!(sdk.contains(
        "pb::universal_conference_service_client::UniversalConferenceServiceClient<Channel>"
    ));
    for method in [
        "submit_command",
        "create_identity",
        "link_identity",
        "get_identity",
        "resolve_identity_binding",
        "create_conversation",
        "get_conversation",
        "send_message",
        "get_message",
        "create_communication_intent",
        "get_communication_intent",
        "publish_event",
        "create_subscription",
        "get_subscription",
        "poll_events",
        "acknowledge_events",
        "reject_events",
        "replay_subscription",
        "list_dead_letters",
        "create_conference",
        "resolve_conference",
        "get_conference",
        "transition_conference",
        "set_entry_open",
        "ensure_participant",
        "ensure_participant_device",
        "update_participant",
        "remove_participant",
        "list_participants",
        "set_subscriptions",
        "prepare_conference_runtime",
        "issue_join_grant",
        "revoke_join_grant",
        "get_participant_attendance",
        "get_conference_capabilities",
    ] {
        assert!(sdk.contains(&format!("pub async fn {method}")));
    }
}
#[test]
fn phase39_all_required_languages_share_one_auth_and_semantic_manifest() {
    let manifest = read("sdk/contract.json");
    let helpers = [
        "crates/ucr-sdk/src/lib.rs",
        "sdk/python/ucr_sdk/auth.py",
        "sdk/typescript/src/auth.ts",
        "sdk/kotlin/src/main/kotlin/org/ucr/sdk/ServiceCredential.kt",
        "sdk/swift/Sources/UCRSDK/ServiceCredential.swift",
    ];
    for language in ["rust", "python", "typescript", "kotlin", "swift"] {
        assert!(manifest.contains(&format!("\"{language}\"")));
    }
    assert!(manifest.contains("\"automatic_application_retry\": false"));
    assert!(manifest.contains("\"event_cursor\": \"opaque\""));
    assert!(manifest.contains("\"direct_database_access\": false"));
    assert!(manifest.contains("\"UniversalConferenceService\""));
    for path in helpers {
        let source = read(path);
        assert!(source.contains("ucr-service-credential-id-bin"));
        assert!(source.contains("ucr-service-credential-secret-bin"));
        assert!(source.contains("[REDACTED]"));
    }
}
#[test]
fn phase39_spec_adr_ci_and_release_truth_are_locked() {
    let spec = read("spec/public-sdks.md");
    let adr = read(
        "docs/adr/0077-phase39-public-sdks-are-thin-clients-of-one-versioned-public-contract.md",
    );
    let readme = read("README.md");
    let spec_readme = read("spec/README.md");
    let ci = read(".github/workflows/ci.yml");

    assert!(spec.contains("SDKs have no direct database API"));
    assert!(spec.contains("There is no hidden automatic application retry"));
    assert!(spec.contains("Phase 41 owns the complete SDK conformance matrix"));
    assert!(adr.contains("The checked-in `.proto` files remain the source of wire truth"));
    assert!(readme.contains(
        "Phase 39 adds Prepared Public SDKs for Rust, Python, TypeScript, Kotlin and Swift"
    ));
    assert!(spec_readme.contains("Phase 39 adds `public-sdks.md`"));
    assert!(ci.contains("python3 sdk/validate.py"));
    assert!(ci.contains("test -s spec/public-sdks.md"));
    assert!(
        ci.contains(
            "0077-phase39-public-sdks-are-thin-clients-of-one-versioned-public-contract.md"
        )
    );
}

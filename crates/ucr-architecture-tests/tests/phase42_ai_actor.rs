use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase42_ai_actor_is_optional_and_reuses_canonical_identity_and_authorization() {
    let implementation = read("crates/ucr-ai-actor/src/lib.rs");
    let manifest = read("crates/ucr-ai-actor/Cargo.toml");
    let model = read("crates/ucr-model/src/lib.rs");
    let protocol = read("crates/ucr-protocol/src/authorization.rs");
    let spec = read("spec/ai-actor-layer.md");

    assert!(model.contains("AiAgent"));
    assert!(implementation.contains("PrincipalKind::AiAgent"));
    assert!(implementation.contains("ActorKind::AiAgent"));
    assert!(implementation.contains("use ucr_protocol::authorize"));
    assert!(protocol.contains("pub fn authorize("));
    assert!(!manifest.contains("ucr-storage"));
    assert!(!manifest.contains("ucr-api-grpc"));
    assert!(spec.contains("Canonical communication continues to work when no AI system is available"));
}

#[test]
fn phase42_data_policy_and_attribution_fail_closed() {
    let implementation = read("crates/ucr-ai-actor/src/lib.rs");
    let spec = read("spec/ai-actor-layer.md");

    for marker in [
        "AiForbidden",
        "LocalAiOnly",
        "OrganizationAi",
        "ExternalAiAllowed",
        "DeniedAttribution",
        "DeniedDataPolicy",
        "DeniedPermission",
        "DeniedQuota",
    ] {
        assert!(implementation.contains(marker), "missing {marker}");
    }
    for policy in [
        "AI_FORBIDDEN",
        "LOCAL_AI_ONLY",
        "ORGANIZATION_AI",
        "EXTERNAL_AI_ALLOWED",
    ] {
        assert!(spec.contains(policy), "missing {policy}");
    }
    assert!(implementation.contains("profile.attribution_label.trim().is_empty()"));
    assert!(implementation.contains("profile.actor.kind != ActorKind::AiAgent"));
}

#[test]
fn phase42_does_not_create_a_second_communication_or_transport_brain() {
    let implementation = read("crates/ucr-ai-actor/src/lib.rs");
    let adr = read(
        "docs/adr/0088-phase42-ai-actor-layer-reuses-canonical-identity-policy-and-authorization.md",
    );

    for forbidden in [
        "struct MessageEnvelope",
        "struct ConversationRecord",
        "struct DeliveryAttempt",
        "struct RouteCandidate",
        "struct TransportOrchestrator",
        "trait MessageStore",
        "trait ConversationStore",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "Phase 42 introduced forbidden owner: {forbidden}"
        );
    }
    assert!(adr.contains("AI resource selection and communication transport routing are separate"));
    assert!(adr.contains("Ordinary UCR communication remains unchanged"));
}

#[test]
fn phase42_has_executable_security_and_privacy_evidence() {
    let implementation = read("crates/ucr-ai-actor/src/lib.rs");
    let workflow = read(".github/workflows/phase42-ai-actor.yml");

    for test in [
        "ai_forbidden_denies_even_an_authorized_ai_principal",
        "local_only_rejects_external_execution",
        "canonical_permission_and_quota_are_both_required",
        "human_actor_cannot_be_admitted_as_ai",
        "audit_evidence_contains_no_prompt_or_response_payload",
    ] {
        assert!(implementation.contains(test), "missing executable evidence {test}");
    }
    assert!(workflow.contains("cargo clippy"));
    assert!(workflow.contains("cargo test"));
    assert!(!workflow.contains("continue-on-error"));
    assert!(!workflow.contains("|| true"));
}

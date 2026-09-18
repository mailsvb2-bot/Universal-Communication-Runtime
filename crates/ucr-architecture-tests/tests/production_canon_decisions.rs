use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn all_twenty_canon_production_decisions_are_mapped_and_accepted() {
    let matrix = read("spec/production-1.0-decisions.md");
    for marker in [
        "Root Identity Model", "Device Identity Model", "Persona Model", "Account Recovery",
        "Group Cryptography", "Protocol Framing", "Version Negotiation", "Conversation Taxonomy",
        "Group History Policy", "Delivery Semantics", "Delete Semantics", "Federation Trust",
        "Public API Compatibility", "Codec Baseline", "Metadata Privacy", "Multi-Tenant Boundary",
        "Self-Hosted vs Managed Contract", "Licensing Boundary", "Public Extension Registry",
        "Data Lifecycle",
    ] {
        assert!(matrix.contains(marker), "missing Canon decision mapping: {marker}");
    }

    for path in [
        "docs/adr/0095-persona-model-preserves-explicit-separation.md",
        "docs/adr/0096-group-cryptography-uses-mls-and-epoch-isolation.md",
        "docs/adr/0097-conversation-taxonomy-is-canonical-and-extensible.md",
        "docs/adr/0098-group-history-policy-is-explicit-and-access-bounded.md",
        "docs/adr/0099-deletion-semantics-distinguish-local-remote-expiry-and-erasure.md",
        "docs/adr/0100-public-api-compatibility-is-versioned-and-conformance-gated.md",
        "docs/adr/0101-codec-baseline-is-opus-and-h264-baseline.md",
        "docs/adr/0102-metadata-privacy-is-minimum-disclosure.md",
        "docs/adr/0103-self-hosted-and-managed-use-one-protocol-contract.md",
        "docs/adr/0104-licensing-boundary-preserves-no-unintended-grant.md",
        "docs/adr/0105-public-extension-registry-is-namespaced-and-fail-closed.md",
        "docs/adr/0106-data-lifecycle-is-policy-explicit-and-non-destructive.md",
    ] {
        assert!(read(path).contains("Status: Accepted"), "decision is not accepted: {path}");
    }
}

#[test]
fn implemented_model_matches_persona_taxonomy_and_group_history_decisions() {
    let model = read("crates/ucr-model/src/lib.rs");
    let group = read("crates/ucr-model/src/group.rs");

    for marker in ["pub struct PersonRecord", "pub struct PersonaRecord", "pub enum PersonaKind",
                   "person_id: Option<PersonId>", "identity_id: IdentityId"] {
        assert!(model.contains(marker), "missing Persona model marker: {marker}");
    }
    for marker in ["Direct", "PrivateGroup", "PublicGroup", "Broadcast", "Community",
                   "Room", "Topic", "Thread", "System"] {
        assert!(model.contains(marker), "missing Conversation taxonomy marker: {marker}");
    }
    for marker in ["NoHistory", "FromJoin", "LastNMessages", "FromTimestamp",
                   "FullHistory", "CustomPolicy"] {
        assert!(group.contains(marker), "missing Group history marker: {marker}");
    }
}

#[test]
fn decision_closure_does_not_fake_production_or_a_public_license_grant() {
    let matrix = read("spec/production-1.0-decisions.md");
    let licensing = read("docs/adr/0104-licensing-boundary-preserves-no-unintended-grant.md");
    assert!(matrix.contains("necessary but not sufficient for Production"));
    assert!(matrix.contains("successful protected publisher-signed release execution"));
    assert!(licensing.contains("no general redistribution/relicensing grant"));
    assert!(licensing.contains("publisher-approved license text"));
}

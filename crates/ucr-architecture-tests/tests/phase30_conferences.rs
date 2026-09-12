use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn phase30_reuses_call_group_mls_and_sfu_without_second_conference_brain() {
    let runtime = read("crates/ucr-conference/src/lib.rs");
    let manifest = read("crates/ucr-conference/Cargo.toml");
    assert!(runtime.contains("CallStore"));
    assert!(runtime.contains("GroupStore"));
    assert!(runtime.contains("SfuRuntime"));
    assert!(runtime.contains("GROUP_MLS_CAPABILITY"));
    assert!(runtime.contains("CallSignalKind::ParticipantUpdate"));
    assert!(!runtime.contains("ConferenceStore"));
    assert!(!runtime.contains("persist_conference"));
    assert!(!manifest.contains("ucr-storage-sqlite"));
}

#[test]
fn phase30_supports_thousand_person_reference_with_one_bounded_ceiling() {
    let call = read("crates/ucr-protocol/src/call.rs");
    let conference = read("crates/ucr-conference/tests/reference.rs");
    let spec = read("spec/conference.md");
    assert!(call.contains("MAX_CALL_PARTICIPANTS: usize = 1024"));
    assert!(conference.contains("thousand_person_sfu_conference_fits_bounded_call_ceiling"));
    assert!(conference.contains("snapshot.call.participants.len(), 1000"));
    assert!(spec.contains("shared bounded Call/Audio/Video/SFU ceiling is **1024 participants**"));
}

fn runtime_contains_selective_forwarding() -> bool {
    let runtime = read("crates/ucr-conference/src/lib.rs");
    let sfu = read("crates/ucr-sfu/src/lib.rs");
    runtime.contains("forward_selected")
        && runtime.contains("prune_subscriptions")
        && sfu.contains("pub fn forward_selected")
}

#[test]
fn phase30_public_contract_docs_permissions_and_fuzz_are_machine_locked() {
    let proto = read("proto/ucr/v1/conference.proto");
    let spec = read("spec/conference.md");
    let adr = read("docs/adr/0068-phase30-conferences-reuse-call-group-mls-and-sfu-owners.md");
    let readme = read("README.md");
    let ci = read(".github/workflows/ci.yml");
    let architecture = read("docs/architecture/ARCHITECTURE.md");
    let threat = read("docs/architecture/THREAT_MODEL.md");
    let threat_simulations = read("docs/architecture/THREAT_SIMULATIONS.md");
    let chaos = read("docs/architecture/CHAOS_SCENARIOS.md");
    let spec_readme = read("spec/README.md");
    let adaptive_media = read("spec/adaptive-media.md");
    let media_e2ee = read("spec/media-e2ee.md");
    let fuzz = read("fuzz/fuzz_targets/conference_start.rs");
    let smoke = read("fuzz/run-smoke.sh");
    assert!(proto.contains("message ConferenceStart"));
    assert!(proto.contains("message ConferenceSnapshot"));
    assert!(proto.contains("message ConferenceSubscriptionSet"));
    assert!(!proto.contains("service ConferenceService"));
    assert!(spec.contains("start/signal/forward do not implicitly require observe permission"));
    assert!(spec.contains("Phase 30 does not add recording"));
    assert!(spec.contains("at most **32 source/media pairs**"));
    assert!(runtime_contains_selective_forwarding());
    assert!(adr.contains("no schema v27"));
    assert!(architecture.contains("Phase 30 adds Prepared Conference coordination"));
    assert!(
        threat.contains(
            "recipient-owned subscriptions are bounded ephemeral routing preference only"
        )
    );
    assert!(
        threat_simulations
            .contains("Phase-30 Conference coordination now reuses the same SFU boundary")
    );
    assert!(
        chaos.contains("Phase-30 Conference selective routing composes this same sink boundary")
    );
    assert!(spec_readme.contains("Phase 30 adds `conference.md`"));
    assert!(adaptive_media.contains("Phase 30 now composes that foundation"));
    assert!(media_e2ee.contains("Phase 30 now composes that boundary"));
    assert!(!adaptive_media.contains("Conference coordination remains Phase 30"));
    assert!(!media_e2ee.contains("Conference coordination remains Phase 30"));
    assert!(readme.contains(
        "**Phase 30 — Conferences (Prepared/reference candidate; Bridge SDK not started).**"
    ));
    assert!(ci.contains("test -s proto/ucr/v1/conference.proto"));
    assert!(ci.contains("test -s spec/conference.md"));
    assert!(fuzz.contains("canonical_conference_start"));
    assert!(smoke.contains("run_target conference_start 4096 512"));
}

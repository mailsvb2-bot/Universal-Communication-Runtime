use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase22_e2ee_reuses_call_crypto_media_and_negotiation_owners() {
    let root = workspace();
    let model = fs::read_to_string(root.join("crates/ucr-model/src/media_e2ee.rs")).expect("model");
    let protocol =
        fs::read_to_string(root.join("crates/ucr-protocol/src/media_e2ee.rs")).expect("protocol");
    let crypto =
        fs::read_to_string(root.join("crates/ucr-crypto/src/media_e2ee.rs")).expect("crypto");
    let runtime =
        fs::read_to_string(root.join("crates/ucr-media-e2ee/src/lib.rs")).expect("runtime");
    let session =
        fs::read_to_string(root.join("crates/ucr-crypto/src/session.rs")).expect("session");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/media_e2ee.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/media-e2ee.md")).expect("spec");
    let adr = fs::read_to_string(root.join(
        "docs/adr/0060-phase22-e2ee-media-reuses-canonical-call-crypto-and-capability-owners.md",
    ))
    .expect("adr");

    assert!(model.contains("pub struct MediaE2eeContext"));
    assert!(model.contains("pub struct EncryptedMediaFrame"));
    assert!(model.contains("<encrypted-media>"));
    assert!(protocol.contains("pub const MEDIA_E2EE_CAPABILITY: &str = \"ucr.media.e2ee\""));
    assert!(protocol.contains("MEDIA_E2EE_FRAME_AAD_V1_DOMAIN"));
    assert!(protocol.contains("MAX_MEDIA_STREAMS_PER_EPOCH: usize = 64"));
    assert!(crypto.contains("MEDIA_E2EE_HANDSHAKE_V1_DOMAIN"));
    assert!(runtime.contains("S: CallStore"));
    assert!(runtime.contains("EstablishedSession"));
    assert!(runtime.contains("authenticated_peer_device_id"));
    assert!(runtime.contains("validate_audio_frame_for_stream"));
    assert!(runtime.contains("validate_video_frame_for_stream"));
    assert!(runtime.contains("self.established.decrypt_inbound"));
    assert!(runtime.contains("self.inbound_sequences.insert(key, frame.header.sequence)"));
    assert!(runtime.contains("GroupCryptoUnavailable"));
    assert!(runtime.contains("AUDIO_SEND_PERMISSION"));
    assert!(runtime.contains("VIDEO_RECEIVE_PERMISSION"));
    assert!(session.contains("authenticated_peer_device_id: Option<DeviceId>"));
    assert!(proto.contains("message MediaE2eeContext"));
    assert!(proto.contains("message EncryptedMediaFrame"));
    assert!(proto.contains("message MediaE2eeNegotiationBinding"));
    assert!(!proto.contains("service MediaE2eeService"));
    assert!(spec.contains("There is no plaintext fallback API"));
    assert!(
        spec.contains("forged unauthenticated high sequence numbers cannot poison receiver state")
    );
    assert!(spec.contains("Group calls fail closed"));
    assert!(adr.contains("No SQLite migration is introduced; schema remains v22"));
}

#[test]
fn phase22_does_not_create_second_call_group_transport_adaptive_or_sfu_brain() {
    let root = workspace();
    let sources = [
        fs::read_to_string(root.join("crates/ucr-model/src/media_e2ee.rs")).expect("model"),
        fs::read_to_string(root.join("crates/ucr-protocol/src/media_e2ee.rs")).expect("protocol"),
        fs::read_to_string(root.join("crates/ucr-media-e2ee/src/lib.rs")).expect("runtime"),
    ];
    for forbidden in [
        "struct E2eeCall",
        "trait MediaE2eeStore",
        "CREATE TABLE",
        "TransportProvider",
        "RouteCandidate",
        "AdaptiveBitrate",
        "struct Sfu",
        "struct GroupKeyManager",
        "struct MlsEngine",
        "fn negotiate_session(",
    ] {
        assert!(
            sources.iter().all(|source| !source.contains(forbidden)),
            "future/second-brain leak: {forbidden}"
        );
    }
    let manifest =
        fs::read_to_string(root.join("crates/ucr-media-e2ee/Cargo.toml")).expect("manifest");
    assert!(!manifest.contains("webrtc"));
    assert!(!manifest.contains("srtp"));
    assert!(!manifest.contains("openssl"));
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 22"));
}

#[test]
fn phase22_release_truth_and_fuzz_gate_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let fuzz_manifest = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let fuzz_smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");
    assert!(readme.contains("**Phase 22 — E2EE Media (Prepared/reference complete; Phase 23 Adaptive Media not started).**"));
    assert!(ci.contains("test -s spec/media-e2ee.md"));
    assert!(ci.contains("test -s proto/ucr/v1/media_e2ee.proto"));
    assert!(
        ci.contains(
            "0060-phase22-e2ee-media-reuses-canonical-call-crypto-and-capability-owners.md"
        )
    );
    assert!(spec_readme.contains("Phase 22 adds `media-e2ee.md`"));
    assert!(fuzz_manifest.contains("media_e2ee_frame"));
    assert!(fuzz_smoke.contains("run_target media_e2ee_frame 131072 768"));
    assert!(threat.contains("Phase 22 direct-call E2EE media"));
}

use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase20_audio_reuses_call_capability_and_authorization_owners() {
    let root = workspace();
    let model = fs::read_to_string(root.join("crates/ucr-model/src/audio.rs")).expect("model");
    let protocol =
        fs::read_to_string(root.join("crates/ucr-protocol/src/audio.rs")).expect("protocol");
    let audio = fs::read_to_string(root.join("crates/ucr-audio/src/lib.rs")).expect("audio");
    let call = fs::read_to_string(root.join("crates/ucr-core/src/call.rs")).expect("call core");
    let authorization = fs::read_to_string(root.join("crates/ucr-protocol/src/authorization.rs"))
        .expect("authorization");
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/audio.proto")).expect("audio proto");
    let spec = fs::read_to_string(root.join("spec/audio.md")).expect("spec");
    let adr = fs::read_to_string(
        root.join("docs/adr/0058-phase20-audio-reuses-canonical-call-and-capability-owners.md"),
    )
    .expect("adr");

    assert!(model.contains("pub struct AudioStreamDescriptor"));
    assert!(model.contains("pub struct EncodedAudioFrame"));
    assert!(model.contains("<encoded-audio>"));
    assert!(protocol.contains("pub const OPUS_AUDIO_CODEC_CAPABILITY"));
    assert!(protocol.contains("pub const MANDATORY_AUDIO_SAMPLE_RATE_HZ: u32 = 48_000"));
    assert!(protocol.contains("CapabilityMaturity::Prepared"));
    assert!(audio.contains("S: CallStore"));
    assert!(audio.contains("call_for_participant"));
    assert!(audio.contains("AUDIO_SEND_PERMISSION"));
    assert!(audio.contains("AUDIO_RECEIVE_PERMISSION"));
    assert!(audio.contains("Encoder::new"));
    assert!(audio.contains("Decoder::new"));
    assert!(audio.contains("media_negotiation_generation != descriptor.negotiation_generation"));
    assert!(audio.contains("pub trait AudioNegotiationResolver"));
    assert!(audio.contains("canonical_negotiation_result"));
    assert!(audio.contains("call.media_negotiation_ref.as_ref()"));
    assert!(audio.contains("NegotiatedCodecMismatch"));
    assert!(audio.contains("NegotiatedParticipantSetMismatch"));
    assert!(audio.contains("require_exact_negotiated_participants"));
    assert!(call.contains("pub trait CallStore"));
    assert!(authorization.contains("ucr.call.audio.send"));
    assert!(authorization.contains("ucr.call.audio.receive"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 22"));
    assert!(proto.contains("message AudioStreamDescriptor"));
    assert!(proto.contains("message EncodedAudioFrame"));
    assert!(proto.contains("message AudioNegotiationBinding"));
    assert!(proto.contains("NegotiationResult result = 5"));
    assert!(proto.contains("repeated PrincipalRef negotiated_participants = 7"));
    assert!(spec.contains("Status: **Prepared reference implementation**, not Production."));
    assert!(spec.contains("mandatory Phase-20 interoperable audio codec is **Opus**"));
    assert!(spec.contains("Audio MUST NOT start when that reference is absent"));
    assert!(spec.contains("current `Accepted` participant set"));
    assert!(adr.contains("owns no durable state"));
}

#[test]
fn phase20_audio_creates_no_second_call_transport_video_or_e2ee_brain() {
    let root = workspace();
    let sources = [
        fs::read_to_string(root.join("crates/ucr-model/src/audio.rs")).expect("model"),
        fs::read_to_string(root.join("crates/ucr-protocol/src/audio.rs")).expect("protocol"),
        fs::read_to_string(root.join("crates/ucr-audio/src/lib.rs")).expect("audio"),
    ];
    for forbidden in [
        "struct AudioCall",
        "trait AudioStore",
        "struct AudioGroup",
        "struct AudioIdentity",
        "CREATE TABLE",
        "TransportProvider",
        "RouteCandidate",
        "struct VideoFrame",
        "struct Srtp",
        "struct IceCandidate",
        "struct MediaKey",
        "fn negotiate_session(",
    ] {
        assert!(
            sources.iter().all(|content| !content.contains(forbidden)),
            "Phase 20 second-brain/future-phase leak: {forbidden}"
        );
    }
    let proto = fs::read_to_string(root.join("proto/ucr/v1/audio.proto")).expect("proto");
    assert!(!proto.contains("service AudioService"));
    assert!(!proto.contains("VideoFrame"));
    let manifest = fs::read_to_string(root.join("crates/ucr-audio/Cargo.toml")).expect("manifest");
    assert!(manifest.contains("opus = \"0.4.0\""));
    assert!(!manifest.contains("webrtc"));
}

#[test]
fn phase20_release_truth_and_repository_guards_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    assert!(readme.contains("Phase 20 now adds Prepared realtime Audio"));
    assert!(ci.contains("test -s spec/audio.md"));
    assert_eq!(ci.matches("cmake build-essential").count(), 2);
    assert!(ci.contains("test -s proto/ucr/v1/audio.proto"));
    assert!(ci.contains("0058-phase20-audio-reuses-canonical-call-and-capability-owners.md"));
    assert!(spec_readme.contains("Phase 20 adds `audio.md`"));
}

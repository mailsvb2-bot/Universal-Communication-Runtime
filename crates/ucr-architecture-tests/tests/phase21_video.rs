use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase21_video_reuses_call_capability_and_authorization_owners() {
    let root = workspace();
    let model = fs::read_to_string(root.join("crates/ucr-model/src/video.rs")).expect("model");
    let protocol =
        fs::read_to_string(root.join("crates/ucr-protocol/src/video.rs")).expect("protocol");
    let video = fs::read_to_string(root.join("crates/ucr-video/src/lib.rs")).expect("video");
    let authorization =
        fs::read_to_string(root.join("crates/ucr-protocol/src/authorization.rs")).expect("auth");
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/video.proto")).expect("proto");
    let spec = fs::read_to_string(root.join("spec/video.md")).expect("spec");
    let adr = fs::read_to_string(
        root.join("docs/adr/0059-phase21-video-reuses-canonical-call-and-capability-owners.md"),
    )
    .expect("adr");

    assert!(model.contains("pub struct VideoStreamDescriptor"));
    assert!(model.contains("pub struct EncodedVideoFrame"));
    assert!(model.contains("pub enum VideoSourceKind"));
    assert!(model.contains("<encoded-video>"));
    assert!(protocol.contains("pub const H264_VIDEO_CODEC_CAPABILITY"));
    assert!(protocol.contains("H264_LEVEL_4_0_MAX_DPB_MACROBLOCKS"));
    assert!(protocol.contains("h264_reference_max_dpb_frames"));
    assert!(protocol.contains("pub const SCREEN_SHARE_VIDEO_CAPABILITY"));
    assert!(protocol.contains("H264_LEVEL_4_0_MAX_FRAME_MACROBLOCKS: u32 = 8_192"));
    assert!(protocol.contains("H264_LEVEL_4_0_MAX_MACROBLOCKS_PER_SECOND: u32 = 245_760"));
    assert!(protocol.contains("h264_reference_coded_dimensions"));
    assert!(protocol.contains("CapabilityMaturity::Prepared"));
    assert!(video.contains("S: CallStore"));
    assert!(video.contains("call_for_participant"));
    assert!(video.contains("VIDEO_SEND_PERMISSION"));
    assert!(video.contains("VIDEO_RECEIVE_PERMISSION"));
    assert!(video.contains("Encoder::with_api_config"));
    assert!(video.contains("Decoder::new"));
    assert!(video.contains("SeqParameterSet::from_bits"));
    assert!(video.contains("FrameMbsFlags::Frames"));
    assert!(video.contains("reset_decoder_after_rejected_frame"));
    assert!(video.contains("self.validated_parameter_set = next_validated_parameter_set"));
    assert!(video.contains("MissingValidatedParameterSet"));
    assert!(video.contains("DecodedPictureBufferTooLarge"));
    assert!(video.contains("ParsedH264Level::L4"));
    assert!(video.contains("restrictions.max_dec_frame_buffering"));
    assert!(video.contains("recover_encoder()?"));
    assert!(video.contains("self.encoder_usable = false"));
    assert!(video.contains("pub trait VideoNegotiationResolver"));
    assert!(video.contains("canonical_negotiation_result"));
    assert!(video.contains("NegotiatedParticipantSetMismatch"));
    assert!(video.contains("required_video_capability_for_source"));
    assert!(authorization.contains("ucr.call.video.send"));
    assert!(authorization.contains("ucr.call.video.receive"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 ="));
    assert!(proto.contains("message VideoStreamDescriptor"));
    assert!(proto.contains("message EncodedVideoFrame"));
    assert!(proto.contains("message VideoNegotiationBinding"));
    assert!(proto.contains("VIDEO_SOURCE_KIND_SCREEN_SHARE"));
    assert!(spec.contains("Status: **Prepared reference implementation**, not Production."));
    assert!(spec.contains("real H.264"));
    assert!(spec.contains("decoded-picture-buffer"));
    assert!(spec.contains("encoder is reconstructed"));
    assert!(spec.contains("245,760 coded macroblocks/second"));
    assert!(spec.contains("uncropped coded macroblock canvas"));
    assert!(spec.contains("reconstructs the decoder"));
    assert!(spec.contains("does **not** claim WebRTC/RFC-7742 conformance"));
    assert!(adr.contains("No SQLite migration is introduced; schema remains v22"));
    assert!(adr.contains("uncropped coded macroblock canvas"));
    assert!(adr.contains("reconstructs the decoder"));
}

#[test]
fn phase21_video_creates_no_second_call_transport_e2ee_adaptive_or_sfu_brain() {
    let root = workspace();
    let sources = [
        fs::read_to_string(root.join("crates/ucr-model/src/video.rs")).expect("model"),
        fs::read_to_string(root.join("crates/ucr-protocol/src/video.rs")).expect("protocol"),
        fs::read_to_string(root.join("crates/ucr-video/src/lib.rs")).expect("video"),
    ];
    for forbidden in [
        "struct VideoCall",
        "trait VideoStore",
        "struct VideoGroup",
        "struct VideoIdentity",
        "CREATE TABLE",
        "TransportProvider",
        "RouteCandidate",
        "struct Srtp",
        "struct IceCandidate",
        "struct MediaKey",
        "AdaptiveBitrate",
        "struct Sfu",
        "fn negotiate_session(",
    ] {
        assert!(
            sources.iter().all(|content| !content.contains(forbidden)),
            "future/second-brain leak: {forbidden}"
        );
    }
    let proto = fs::read_to_string(root.join("proto/ucr/v1/video.proto")).expect("proto");
    assert!(!proto.contains("service VideoService"));
    assert!(!proto.contains("Srtp"));
    let manifest = fs::read_to_string(root.join("crates/ucr-video/Cargo.toml")).expect("manifest");
    assert!(manifest.contains("openh264 = \"0.9.8\""));
    assert!(manifest.contains("h264-reader = \"0.8.0\""));
    assert!(!manifest.contains("webrtc"));
}

#[test]
fn phase21_release_truth_and_repository_guards_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let fuzz_manifest = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let fuzz_smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    assert!(readme.contains("Phase 21 now adds Prepared realtime Video"));
    assert!(readme.contains(
        "**Phase 28 — Mesh (Prepared/reference complete; Relay/NAT traversal and multipath not started).**"
    ));
    assert!(ci.contains("test -s spec/video.md"));
    assert!(ci.contains("test -s proto/ucr/v1/video.proto"));
    assert!(ci.contains("0059-phase21-video-reuses-canonical-call-and-capability-owners.md"));
    assert_eq!(ci.matches("cmake build-essential").count(), 2);
    assert!(spec_readme.contains("Phase 21 adds `video.md`"));
    assert!(fuzz_manifest.contains("h264_sps_preflight"));
    assert!(fuzz_manifest.contains("ucr-video"));
    assert!(fuzz_smoke.contains("run_target h264_sps_preflight 131072 768"));
}

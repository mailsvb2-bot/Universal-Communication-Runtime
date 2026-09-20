use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).expect("architecture source")
}

#[test]
fn webrtc_provider_boundary_is_universal_ephemeral_and_truthful() {
    let workspace = read("Cargo.toml");
    let model = read("crates/ucr-model/src/webrtc.rs");
    let protocol = read("crates/ucr-protocol/src/webrtc.rs");
    let provider = read("crates/ucr-webrtc/src/lib.rs");
    let realtime_spec = read("spec/realtime.md");

    assert!(workspace.contains("\"crates/ucr-webrtc\""));
    assert!(model.contains("pub struct IceServerConfig"));
    assert!(model.contains("field(\"has_credential\""));
    assert!(protocol.contains("WEBRTC_BROWSER_CAPABILITY"));
    assert!(protocol.contains("WEBRTC_ICE_CAPABILITY"));
    assert!(protocol.contains("WEBRTC_TURN_CAPABILITY"));
    assert!(protocol.contains("CapabilityMaturity::Prepared"));
    assert!(provider.contains("pub trait WebRtcProvider"));
    assert!(provider.contains("pub struct PreparedWebRtcProvider"));
    assert!(provider.contains("Err(WebRtcProviderError::TemporarilyUnavailable)"));
    assert!(provider.contains("pub struct TurnRestCredentialIssuer"));
    assert!(provider.contains("TurnRestSecret([u8; 32])"));
    assert!(provider.contains("ZeroizeOnDrop"));
    assert!(provider.contains("MessageDigest::sha1()"));
    assert!(provider.contains("STANDARD.encode(mac)"));
    assert!(provider.contains("MAX_TURN_CREDENTIAL_TTL_SECONDS"));
    assert!(!provider.contains("UniversalConferenceStore"));
    assert!(!provider.contains("CallStore"));
    assert!(realtime_spec.contains("PreparedWebRtcProvider"));
    assert!(realtime_spec.contains("does not end the canonical Call"));
}

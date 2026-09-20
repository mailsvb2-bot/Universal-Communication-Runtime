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
    let realtime_proto = read("proto/ucr/v1/realtime.proto");
    let realtime_service = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let runtime_main = read("crates/ucr-runtime/src/main.rs");
    let browser = read("crates/ucr-realtime-web/static/client.html");
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
    assert!(provider.contains("pub struct LiveWebRtcProvider"));
    assert!(provider.contains("LIVE_WEBRTC_COMMAND_QUEUE_CAPACITY"));
    assert!(provider.contains("LIVE_WEBRTC_MAX_SESSIONS"));
    assert!(provider.contains("deadline: Instant"));
    assert!(provider.contains("command_expired(deadline)"));
    assert!(provider.contains("shutdown: Arc<AtomicBool>"));
    assert!(provider.contains("shutdown.store(true, Ordering::Release)"));
    assert!(provider.contains("api.new_peer_connection(engine_config)"));
    assert!(provider.contains("add_transceiver_from_kind(RTPCodecType::Audio, None)"));
    assert!(provider.contains("add_transceiver_from_kind(RTPCodecType::Video, None)"));
    assert!(provider.contains("gathering_complete_promise()"));
    assert!(provider.contains("add_ice_candidate(RTCIceCandidateInit"));
    assert!(provider.contains("TurnRestSecret([u8; 32])"));
    assert!(provider.contains("ZeroizeOnDrop"));
    assert!(provider.contains("MessageDigest::sha1()"));
    assert!(provider.contains("STANDARD.encode(mac)"));
    assert!(provider.contains("MAX_TURN_CREDENTIAL_TTL_SECONDS"));
    assert!(provider.contains("pub struct WebRtcSessionConfigFactory"));
    assert!(realtime_proto.contains("rpc StartWebRtc"));
    assert!(realtime_proto.contains("rpc SetWebRtcRemoteDescription"));
    assert!(realtime_proto.contains("rpc AddWebRtcIceCandidate"));
    assert!(realtime_proto.contains("rpc CloseWebRtc"));
    assert!(realtime_service.contains("authenticated_webrtc_claims"));
    assert!(realtime_service.contains("spawn_blocking"));
    assert!(runtime.contains("LiveWebRtcProvider::new()"));
    assert!(runtime.contains("GrpcRealtimeService::with_webrtc"));
    assert!(runtime_main.contains("UCR_WEBRTC_STUN_URLS"));
    assert!(runtime_main.contains("UCR_WEBRTC_TURN_URLS"));
    assert!(runtime_main.contains("UCR_WEBRTC_TURN_SECRET_HEX"));
    assert!(browser.contains("navigator.mediaDevices.getUserMedia"));
    assert!(browser.contains("new RTCPeerConnection"));
    assert!(browser.contains("/v1/realtime/webrtc/start"));
    assert!(browser.contains("/v1/realtime/webrtc/remote-description"));
    assert!(browser.contains("/v1/realtime/webrtc/ice"));
    assert!(browser.contains("/v1/realtime/webrtc/close"));
    assert!(!browser.contains("UCR_WEBRTC_TURN_SECRET"));
    assert!(provider.contains(".field(\"username\", &\"<redacted>\")"));
    assert!(!provider.contains(".field(\"username\", &self.username)"));
    assert!(!provider.contains("UniversalConferenceStore"));
    assert!(!provider.contains("CallStore"));
    assert!(realtime_spec.contains("PreparedWebRtcProvider"));
    assert!(realtime_spec.contains("LiveWebRtcProvider"));
    assert!(realtime_spec.contains("bounded worker"));
    assert!(realtime_spec.contains("Cache-Control: no-store"));
    assert!(realtime_spec.contains("UCR_WEBRTC_RELAY_ONLY"));
    assert!(realtime_spec.contains("does not end the canonical Call"));
}

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
    let e2ee_bridge = read("crates/ucr-webrtc/src/e2ee_bridge.rs");
    let realtime_proto = read("proto/ucr/v1/realtime.proto");
    let realtime_service = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let runtime_main = read("crates/ucr-runtime/src/main.rs");
    let browser = read("crates/ucr-realtime-web/static/client.html");
    let realtime_spec = read("spec/realtime.md");
    let typescript_e2ee = read("sdk/typescript/src/webrtc_e2ee.ts");

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
    assert!(provider.contains("session_config_until"));
    assert!(provider.contains("session_expires_at_unix_seconds"));
    assert!(realtime_proto.contains("rpc StartWebRtc"));
    assert!(realtime_proto.contains("rpc SetWebRtcRemoteDescription"));
    assert!(realtime_proto.contains("rpc AddWebRtcIceCandidate"));
    assert!(realtime_proto.contains("rpc CloseWebRtc"));
    assert!(realtime_service.contains("authenticated_webrtc_claims"));
    assert!(realtime_service.contains("spawn_blocking"));
    assert!(runtime.contains("LiveWebRtcProvider::with_e2ee_ingress"));
    assert!(runtime.contains("run_webrtc_e2ee_bridge"));
    assert!(runtime.contains("forward_authenticated_e2ee_media"));
    assert!(runtime.contains("spawn_blocking"));
    assert!(e2ee_bridge.contains("WEBRTC_E2EE_DATA_CHANNEL_LABEL"));
    assert!(e2ee_bridge.contains("ucr.e2ee.media.v1"));
    assert!(e2ee_bridge.contains("MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES"));
    assert!(e2ee_bridge.contains("WebRtcE2eeReassembler"));
    assert!(!e2ee_bridge.contains("exporter_secret"));
    assert!(!e2ee_bridge.contains("plaintext"));
    assert!(runtime.contains("GrpcRealtimeService::with_webrtc"));
    assert!(runtime_main.contains("UCR_WEBRTC_STUN_URLS"));
    assert!(runtime_main.contains("UCR_WEBRTC_TURN_URLS"));
    assert!(runtime_main.contains("UCR_WEBRTC_TURN_SECRET_HEX"));
    assert!(browser.contains("navigator.mediaDevices.getUserMedia"));
    assert!(browser.contains("navigator.mediaDevices.getDisplayMedia"));
    assert!(browser.contains("screen-toggle"));
    assert!(browser.contains("screenStream"));
    assert!(browser.contains("screenShareBusy"));
    assert!(browser.contains("updateSources"));
    assert!(browser.contains("e2eeChannel.readyState!==\"open\""));
    assert!(browser.contains("track.addEventListener(\"ended\""));
    assert!(browser.contains("if(screenStream){"));
    assert!(browser.contains("current.getTracks().forEach(track=>track.stop())"));
    let leave = browser
        .split_once("async function leave(){")
        .expect("leave function")
        .1
        .split_once("function scheduleWaitingRoom(){")
        .expect("leave function close")
        .0;
    let local_screen_stop = leave
        .find("await stopScreenShare(false)")
        .expect("leave stops local screen capture");
    let server_close = leave
        .find("await closeServerPeer()")
        .expect("leave requests server peer close");
    assert!(local_screen_stop < server_close);
    assert!(browser.contains("new RTCPeerConnection"));
    assert!(browser.contains("pc.ondatachannel"));
    assert!(browser.contains("ucr.e2ee.media.v1"));
    assert!(browser.contains("window.ucrE2eeEndpoint"));
    assert!(browser.contains("sendE2eeEnvelope"));
    assert!(browser.contains("receiveE2eeChunk"));
    assert!(!browser.contains("pc.addTrack("));
    assert!(browser.contains("Unexpected RTP track rejected"));
    assert!(realtime_spec.contains("endpoint-only screen capture"));
    assert!(realtime_spec.contains("getDisplayMedia"));
    assert!(typescript_e2ee.contains("export class UcrWebRtcE2eeTransport"));
    assert!(typescript_e2ee.contains("ucr.e2ee.media.v1"));
    assert!(typescript_e2ee.contains("encrypted media envelope exceeds transport bounds"));
    assert!(!typescript_e2ee.contains("CryptoKey"));
    assert!(!typescript_e2ee.contains("exporter_secret"));
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

#[test]
fn webrtc_e2ee_uses_protocol_owned_sfu_wire_codec() {
    let sfu_protocol = read("crates/ucr-protocol/src/sfu.rs");
    let e2ee_bridge = read("crates/ucr-webrtc/src/e2ee_bridge.rs");
    let typescript_e2ee = read("sdk/typescript/src/webrtc_e2ee.ts");
    let typescript_sfu_wire = read("sdk/typescript/src/sfu_forward_wire.ts");
    let conformance_workflow = read(".github/workflows/conformance.yml");

    assert!(sfu_protocol.contains("SFU_FORWARD_WIRE_MAGIC"));
    assert!(sfu_protocol.contains("encode_sfu_forward_envelope"));
    assert!(sfu_protocol.contains("decode_sfu_forward_envelope"));
    assert!(sfu_protocol.contains("WIRE_V1_VECTOR_HEX"));
    assert!(e2ee_bridge.contains("encode_sfu_forward_envelope"));
    assert!(e2ee_bridge.contains("decode_sfu_forward_envelope"));
    assert!(!e2ee_bridge.contains("UCRE2EE1"));
    assert!(typescript_e2ee.contains("sendCanonicalEnvelope"));
    assert!(typescript_sfu_wire.contains("SFU_FORWARD_WIRE_MAGIC"));
    assert!(typescript_sfu_wire.contains("encodeSfuForwardEnvelopeWire"));
    assert!(typescript_sfu_wire.contains("decodeSfuForwardEnvelopeWire"));
    assert!(conformance_workflow.contains("sfu_forward_wire_conformance.ts"));
}

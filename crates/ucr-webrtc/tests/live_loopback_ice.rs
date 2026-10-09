use std::{sync::Arc, time::Duration};

use ucr_model::{IceTransportPolicy, OpaqueId, SessionId, WebRtcSessionDescription, WebRtcSdpType};
use ucr_webrtc::{LiveWebRtcProvider, WebRtcProvider, WebRtcSessionConfig};
use webrtc::{
    api::{APIBuilder, interceptor_registry::register_default_interceptors, media_engine::MediaEngine},
    interceptor::registry::Registry,
    peer_connection::{
        RTCPeerConnection,
        configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription,
    },
};

fn session_id() -> SessionId {
    SessionId::from_opaque(OpaqueId::new("phase43-loopback-session").expect("session id"))
}

fn config() -> WebRtcSessionConfig {
    WebRtcSessionConfig {
        session_id: session_id(),
        ice_servers: Vec::new(),
        ice_transport_policy: IceTransportPolicy::All,
    }
}

async fn client_peer() -> Arc<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("register default codecs");
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)
        .expect("register default interceptors");
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .expect("create loopback peer"),
    )
}

async fn answer_offer(
    peer: &RTCPeerConnection,
    offer: &WebRtcSessionDescription,
) -> WebRtcSessionDescription {
    assert_eq!(offer.sdp_type, WebRtcSdpType::Offer);
    peer.set_remote_description(
        RTCSessionDescription::offer(offer.sdp.clone()).expect("valid offer"),
    )
    .await
    .expect("set remote offer");

    let answer = peer.create_answer(None).await.expect("create answer");
    let mut gathering_complete = peer.gathering_complete_promise().await;
    peer.set_local_description(answer)
        .await
        .expect("set local answer");
    tokio::time::timeout(Duration::from_secs(12), gathering_complete.recv())
        .await
        .expect("client ICE gathering timeout");

    let local = peer.local_description().await.expect("local answer");
    WebRtcSessionDescription {
        session_id: offer.session_id.clone(),
        sdp_type: WebRtcSdpType::Answer,
        sdp: local.sdp,
    }
}

async fn wait_connected(peer: &RTCPeerConnection) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match peer.connection_state() {
                RTCPeerConnectionState::Connected => break,
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    panic!("loopback peer entered terminal state: {:?}", peer.connection_state())
                }
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .expect("loopback WebRTC connection did not reach Connected");
}

fn ice_ufrag(sdp: &str) -> Option<&str> {
    sdp.lines()
        .find_map(|line| line.strip_prefix("a=ice-ufrag:"))
}

#[test]
fn live_loopback_negotiates_and_ice_restart_preserves_session() {
    let provider = LiveWebRtcProvider::new().expect("live provider");
    let config = config();
    let initial = provider.create_session(&config).expect("initial server offer");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime");
    let peer = runtime.block_on(client_peer());
    let answer = runtime.block_on(answer_offer(&peer, &initial));
    provider
        .set_remote_description(&answer)
        .expect("apply initial client answer");
    runtime.block_on(wait_connected(&peer));

    let restarted = provider
        .restart_session(&config)
        .expect("server ICE restart offer");
    assert_eq!(restarted.session_id, initial.session_id);
    assert_ne!(restarted.sdp, initial.sdp);
    assert_ne!(
        ice_ufrag(&initial.sdp),
        ice_ufrag(&restarted.sdp),
        "ICE restart must issue a new generation"
    );

    let restarted_answer = runtime.block_on(answer_offer(&peer, &restarted));
    provider
        .set_remote_description(&restarted_answer)
        .expect("apply restarted client answer");
    runtime.block_on(wait_connected(&peer));

    assert_eq!(provider.close_session(&config.session_id), Ok(()));
    runtime.block_on(peer.close()).expect("close client peer");
}

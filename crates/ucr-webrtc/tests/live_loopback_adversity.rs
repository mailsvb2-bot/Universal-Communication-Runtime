use std::{collections::BTreeSet, sync::Arc, time::Duration};

use ucr_model::{IceTransportPolicy, OpaqueId, SessionId, WebRtcSdpType, WebRtcSessionDescription};
use ucr_webrtc::{LiveWebRtcProvider, WebRtcProvider, WebRtcProviderError, WebRtcSessionConfig};
use webrtc::{
    api::{
        APIBuilder, interceptor_registry::register_default_interceptors, media_engine::MediaEngine,
    },
    interceptor::registry::Registry,
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription as EngineSessionDescription,
    },
};

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn ice_ufrags(sdp: &str) -> BTreeSet<&str> {
    sdp.lines()
        .filter_map(|line| line.trim_end_matches('\r').strip_prefix("a=ice-ufrag:"))
        .filter(|value| !value.is_empty())
        .collect()
}

async fn independent_remote_peer() -> Arc<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("register remote codecs");
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)
        .expect("register remote interceptors");
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .expect("create independent remote peer"),
    )
}

async fn answer_offer(
    remote: &RTCPeerConnection,
    session_id: &SessionId,
    offer: &WebRtcSessionDescription,
) -> WebRtcSessionDescription {
    assert_eq!(offer.session_id, *session_id);
    assert_eq!(offer.sdp_type, WebRtcSdpType::Offer);

    remote
        .set_remote_description(
            EngineSessionDescription::offer(offer.sdp.clone()).expect("parse UCR offer"),
        )
        .await
        .expect("apply UCR offer");

    let answer = remote
        .create_answer(None)
        .await
        .expect("create remote answer");
    let mut gathering_complete = remote.gathering_complete_promise().await;
    remote
        .set_local_description(answer)
        .await
        .expect("apply remote answer");
    tokio::time::timeout(Duration::from_secs(12), gathering_complete.recv())
        .await
        .expect("remote ICE gathering must finish inside the bounded evidence window");

    let local = remote
        .local_description()
        .await
        .expect("remote local description after gathering");
    WebRtcSessionDescription {
        session_id: session_id.clone(),
        sdp_type: WebRtcSdpType::Answer,
        sdp: local.sdp,
    }
}

async fn wait_connected(remote: &RTCPeerConnection) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match remote.connection_state() {
                RTCPeerConnectionState::Connected => return,
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    panic!(
                        "loopback peer entered terminal state {:?}",
                        remote.connection_state()
                    );
                }
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("loopback peer must establish ICE/DTLS connectivity");
}

#[test]
fn live_loopback_connects_and_renegotiates_fresh_ice_generation_on_same_session() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("loopback runtime");

    // rustls sees both crypto backends in the workspace; choose explicitly before DTLS.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install deterministic rustls crypto provider for loopback DTLS");

    runtime.block_on(async {
        let provider = LiveWebRtcProvider::new().expect("live UCR WebRTC provider");
        let session_id = SessionId::from_opaque(id("live-loopback-ice-session"));
        let config = WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        };
        let remote = independent_remote_peer().await;
        let unknown_config = WebRtcSessionConfig {
            session_id: SessionId::from_opaque(id("unknown-loopback-session")),
            ..config.clone()
        };
        assert_eq!(
            provider.restart_session(&unknown_config),
            Err(WebRtcProviderError::SessionUnavailable),
            "unknown session cannot acquire a peer through ICE restart"
        );

        let initial_offer = provider.create_session(&config).expect("initial UCR offer");
        assert_eq!(
            provider.create_session(&config),
            Err(WebRtcProviderError::Conflict),
            "a duplicate create must not replace the active peer"
        );
        let initial_ufrags = ice_ufrags(&initial_offer.sdp);
        assert!(
            !initial_ufrags.is_empty(),
            "initial fully-gathered UCR offer must carry an ICE generation"
        );
        let initial_answer = answer_offer(&remote, &session_id, &initial_offer).await;
        provider
            .set_remote_description(&initial_answer)
            .expect("apply initial remote answer");
        wait_connected(&remote).await;

        let restarted_offer = provider
            .restart_session(&config)
            .expect("restart ICE on the existing UCR session");
        assert_eq!(restarted_offer.session_id, session_id);
        let restarted_ufrags = ice_ufrags(&restarted_offer.sdp);
        assert!(
            !restarted_ufrags.is_empty(),
            "restarted UCR offer must carry an ICE generation"
        );
        assert_ne!(
            initial_ufrags, restarted_ufrags,
            "restart_ice must issue a fresh ICE username fragment"
        );

        let restarted_answer = answer_offer(&remote, &session_id, &restarted_offer).await;
        provider
            .set_remote_description(&restarted_answer)
            .expect("apply restarted remote answer");
        wait_connected(&remote).await;
        assert_eq!(
            remote.connection_state(),
            RTCPeerConnectionState::Connected,
            "same independent peer must remain connected after ICE restart negotiation"
        );

        remote.close().await.expect("close remote loopback peer");
        assert_eq!(provider.close_session(&session_id), Ok(()));
        assert_eq!(
            provider.restart_session(&config),
            Err(WebRtcProviderError::SessionUnavailable),
            "closed session cannot be resurrected through ICE restart"
        );
    });
}

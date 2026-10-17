//! Separate process: nothing else has installed a rustls provider yet.

/// Regression: with ring AND aws-lc-rs unified into one build, rustls could
/// not auto-select a provider and the DTLS worker panicked, leaving every
/// browser at ICE "connected" / DTLS "connecting" with no media.
#[test]
fn live_peer_engine_selects_a_process_rustls_provider_before_dtls() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let provider = ucr_webrtc::LiveWebRtcProvider::new().expect("live peer engine");
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "the peer engine must not rely on rustls crate-feature auto-detection"
    );
    drop(provider);
}

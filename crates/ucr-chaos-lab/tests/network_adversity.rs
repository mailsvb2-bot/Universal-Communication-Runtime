use ucr_chaos_lab::{ChaosTransport, Fault, LabPacket, PacketId, PeerId, RouteKind};
use ucr_model::{
    CallId, IceTransportPolicy, NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef,
    SessionId, TenantId, TenantScope,
};
use ucr_realtime::{
    AttendanceTransitionKind, JoinGrantUsePolicy, JoinTokenError, JoinTokenIssuer, JoinTokenKey,
    RealtimeSessionRegistry,
};
use ucr_webrtc::{LiveWebRtcProvider, WebRtcProvider, WebRtcSessionConfig};

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("valid opaque id")
}

fn scope() -> TenantScope {
    TenantScope {
        tenant_id: TenantId::from_opaque(id("network-adversity-tenant")),
        namespace_id: Some(NamespaceId::from_opaque(id("network-adversity-namespace"))),
    }
}

fn participant() -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(id("network-adversity-participant")),
        kind: PrincipalKind::Person,
    }
}

fn token_from_url(url: &str) -> &str {
    url.split_once("#ucr_join=").expect("join token fragment").1
}

#[test]
fn network_switch_recovers_single_use_realtime_downlink_without_second_redemption() {
    let issuer = JoinTokenIssuer::new(
        JoinTokenKey::from_bytes([11_u8; 32]),
        "https://join.example.test/network-adversity",
    )
    .expect("issuer");
    let grant = issuer
        .issue_with_policy(
            scope(),
            CallId::from_opaque(id("network-switch-call")),
            participant(),
            None,
            300,
            JoinGrantUsePolicy::SingleUse,
            None,
            None,
            100_000,
        )
        .expect("single-use grant");
    let token = token_from_url(&grant.join_url);
    let claims = issuer.redeem(token, 100_001).expect("first redemption");

    let registry = RealtimeSessionRegistry::new(8, 4);
    let joined = registry.join(claims.clone(), 100_002).expect("join");
    assert_eq!(joined.transition.kind, AttendanceTransitionKind::Joined);
    let first = registry
        .attach_downlink(&claims, 100_003)
        .expect("first downlink");
    assert!(first.transition.is_none());

    let mut network = ChaosTransport::with_peers(2);
    network
        .apply(Fault::SwitchNetwork(PeerId(1)))
        .expect("network switch");
    let delivery = network
        .send(LabPacket::new(
            PacketId(1),
            PeerId(0),
            PeerId(1),
            RouteKind::Sfu,
            b"connectivity-probe".to_vec(),
        ))
        .expect("post-switch probe")
        .pop()
        .expect("delivered probe");
    assert_eq!(delivery.destination_network_generation, 1);

    drop(first.receiver);
    assert_eq!(
        issuer.redeem(token, 100_004),
        Err(JoinTokenError::AlreadyUsed)
    );

    let resumed = registry
        .attach_downlink(&claims, 100_005)
        .expect("reconnected downlink");
    let transition = resumed.transition.expect("reconnect transition");
    assert_eq!(transition.kind, AttendanceTransitionKind::Reconnected);
    assert_eq!(transition.session_sequence, 2);
    assert_eq!(registry.active_session_count(), 1);
}

#[test]
fn packet_loss_recovery_restarts_ice_for_the_same_live_webrtc_session() {
    let provider = LiveWebRtcProvider::new().expect("live WebRTC provider");
    let session_id = SessionId::from_opaque(id("network-loss-webrtc-session"));
    let config = WebRtcSessionConfig {
        session_id: session_id.clone(),
        ice_servers: Vec::new(),
        ice_transport_policy: IceTransportPolicy::All,
    };
    let initial = provider.create_session(&config).expect("initial offer");

    let mut network = ChaosTransport::with_peers(2);
    network.apply(Fault::DropNext).expect("drop next");
    let lost = network
        .send(LabPacket::new(
            PacketId(2),
            PeerId(0),
            PeerId(1),
            RouteKind::Direct,
            b"ice-connectivity-check".to_vec(),
        ))
        .expect("loss injection");
    assert!(lost.is_empty());

    let restarted = provider
        .restart_session(&config)
        .expect("ICE restart offer after loss");
    assert_eq!(restarted.session_id, session_id);
    assert_ne!(initial.sdp, restarted.sdp);

    network
        .apply(Fault::SetLatency(PeerId(0), PeerId(1), 250))
        .expect("latency");
    let recovered = network
        .send(LabPacket::new(
            PacketId(3),
            PeerId(0),
            PeerId(1),
            RouteKind::Direct,
            b"post-restart-connectivity-check".to_vec(),
        ))
        .expect("post-restart delivery")
        .pop()
        .expect("recovered delivery");
    assert_eq!(recovered.latency_ms, 250);

    assert_eq!(provider.close_session(&session_id), Ok(()));
}

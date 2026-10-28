use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn realtime_mls_bootstrap_is_exact_device_and_uses_canonical_sqlite_owner() {
    let proto = read("proto/ucr/v1/realtime.proto");
    let service = read("crates/ucr-api-grpc/src/realtime_service.rs");
    let grpc = read("crates/ucr-api-grpc/src/lib.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let browser_gateway = read("crates/ucr-realtime-web/src/main.rs");
    let group_mls = read("crates/ucr-group-mls/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/group_mls_store.rs");

    assert!(proto.contains("rpc GetMlsBootstrap(RealtimeGetMlsBootstrapRequest)"));
    assert!(proto.contains("message RealtimeMlsBootstrap"));
    assert!(!proto.contains("RealtimeGetMlsBootstrapRequest {\n  TenantScope scope = 1;\n  OpaqueId call_id = 2;\n  OpaqueId session_id = 3;\n  OpaqueId device_id"));

    assert!(service.contains("authenticated_claims(&token, &scope, &call_id, &session_id)"));
    // MLS bootstrap must inspect the current Join without extending its lease.
    // The sole presence-renewing RPC is Heartbeat, with a generation fence for
    // first-party Calls. Keep this contract independent of rustfmt whitespace.
    let bootstrap_handler = service
        .split("async fn get_mls_bootstrap(")
        .nth(1)
        .expect("GetMlsBootstrap handler")
        .split("async fn ")
        .next()
        .expect("GetMlsBootstrap body");
    assert!(bootstrap_handler.contains(".require_active_session(&claims, self.now()?)"));
    assert!(!bootstrap_handler.contains(".heartbeat(&claims"));

    let heartbeat_handler = service
        .split("async fn heartbeat_realtime(")
        .nth(1)
        .expect("Heartbeat handler")
        .split("async fn ")
        .next()
        .expect("Heartbeat body");
    assert!(heartbeat_handler.contains(".heartbeat_if_join_generation("));
    assert!(heartbeat_handler.contains("if request.expected_session_sequence == 0"));
    assert!(heartbeat_handler.contains("starts_with(\"fp-m-\")"));
    assert!(
        !service
            .replace(heartbeat_handler, "")
            .contains(".heartbeat(&claims")
    );
    assert!(service.contains("self.device_bound_mls_bootstrap(&claims)"));
    assert!(service.contains(".device_id\n            .as_ref()"));
    assert!(
        service.contains("mls_bootstrap_for_device(&claims.scope, &snapshot.group_id, device_id)")
    );
    assert!(
        service.contains("bootstrap.current_crypto_state.epoch != snapshot.group_crypto_epoch")
    );
    assert!(service.contains("current_ref != &snapshot.group_crypto_state_ref"));

    assert!(group_mls.contains("pub const MAX_MLS_BOOTSTRAP_COMMITS: usize = 64;"));
    assert!(group_mls.contains("pub const MAX_MLS_BOOTSTRAP_BYTES: usize = 8 * 1024 * 1024;"));
    assert!(group_mls.contains("BootstrapTooLarge"));
    assert!(sqlite.contains("group_mls_transition_admissions"));
    assert!(sqlite.contains("LIMIT ?6"));
    assert!(sqlite.contains("commits.len() > MAX_MLS_BOOTSTRAP_COMMITS"));
    assert!(sqlite.contains("total_bytes > MAX_MLS_BOOTSTRAP_BYTES"));

    assert!(runtime.contains(".with_mls_bootstrap_store(Arc::clone(&store))"));
    assert!(browser_gateway.contains("\"/v1/realtime/mls-bootstrap\""));
    assert!(browser_gateway.contains("client.get_mls_bootstrap(request).await"));
    assert!(browser_gateway.contains("welcome_base64: STANDARD.encode(bootstrap.welcome)"));
    assert!(grpc.contains("REALTIME_MLS_BOOTSTRAP_RESPONSE_WIRE_MAX_BYTES"));
    assert!(grpc.contains(
        "GRPC_MAX_ENCODING_MESSAGE_SIZE >= REALTIME_MLS_BOOTSTRAP_RESPONSE_WIRE_MAX_BYTES"
    ));
}

#[test]
fn webrtc_provider_mutations_are_serialized_with_join_and_terminal_leave() {
    let service = read("crates/ucr-api-grpc/src/realtime_service.rs");
    // A slow SDP/ICE mutation must not race the canonical Leave path that
    // revokes the grant, retires the SFU downlink, and closes the peer.
    for name in [
        "start_web_rtc",
        "set_web_rtc_remote_description",
        "add_web_rtc_ice_candidate",
        "restart_web_rtc",
        "close_web_rtc",
    ] {
        let handler = service
            .split(&format!("async fn {name}("))
            .nth(1)
            .unwrap_or_else(|| panic!("missing {name} handler"))
            .split("\n    async fn ")
            .next()
            .expect("handler body");
        let guard = handler
            .find("self.sfu_placement_transition_guard().await")
            .unwrap_or_else(|| panic!("{name} bypasses the Join/Leave lifecycle guard"));
        let authentication = handler
            .find("self.authenticated_webrtc_claims(")
            .unwrap_or_else(|| panic!("{name} lacks canonical WebRTC admission"));
        let provider = handler
            .find("tokio::task::spawn_blocking(")
            .unwrap_or_else(|| panic!("{name} lacks provider operation"));
        assert!(
            guard < authentication && authentication < provider,
            "{name} must hold the lifecycle guard across admission and provider mutation"
        );
    }
}

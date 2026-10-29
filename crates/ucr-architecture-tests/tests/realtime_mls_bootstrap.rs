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
fn direct_media_requires_committed_endpoint_owned_epoch() {
    let media = read("crates/ucr-runtime/src/first_party_media.rs");
    let start = media
        .split("pub(crate) fn prepare_direct_call_media<S>(")
        .nth(1)
        .expect("canonical direct media preparation");
    let gate = start
        .split("let media = ensure_media_call(")
        .next()
        .expect("media admission boundary");
    assert!(gate.contains("group.crypto_state.epoch == 0"));
    assert!(gate.contains("server_possesses_mls_group("));
    assert!(gate.contains("GroupMemberState::Active"));
}

#[test]
fn first_party_bootstrap_rejects_server_custody_before_welcome() {
    let web = read("crates/ucr-runtime/src/first_party_web.rs");
    let handler = web
        .split("fn endpoint_mls_bootstrap(")
        .nth(1)
        .expect("first party endpoint bootstrap")
        .split("fn issue_join(")
        .next()
        .expect("bootstrap boundary");
    let custody_check = handler
        .find("server_possesses_mls_group(")
        .expect("server custody must fail closed");
    let welcome_load = handler
        .find(".mls_bootstrap_for_device(")
        .expect("canonical device-bound Welcome retrieval");
    assert!(custody_check < welcome_load);
    assert!(handler.contains("return Err(StatusCode::CONFLICT)"));
}

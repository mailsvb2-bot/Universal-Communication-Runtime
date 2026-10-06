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
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let group_mls = read("crates/ucr-group-mls/src/lib.rs");
    let sqlite = read("crates/ucr-storage-sqlite/src/group_mls_store.rs");

    assert!(proto.contains("rpc GetMlsBootstrap(RealtimeGetMlsBootstrapRequest)"));
    assert!(proto.contains("message RealtimeMlsBootstrap"));
    assert!(!proto.contains("RealtimeGetMlsBootstrapRequest {\n  TenantScope scope = 1;\n  OpaqueId call_id = 2;\n  OpaqueId session_id = 3;\n  OpaqueId device_id"));

    assert!(service.contains("authenticated_claims(&token, &scope, &call_id, &session_id)"));
    assert!(service.contains("self.registry\n                        .heartbeat(&claims"));
    assert!(service.contains("self.device_bound_mls_bootstrap(&claims)"));
    assert!(service.contains(".device_id\n            .as_ref()"));
    assert!(service.contains("mls_bootstrap_for_device(&claims.scope, &snapshot.group_id, device_id)"));
    assert!(service.contains("bootstrap.current_crypto_state.epoch != snapshot.group_crypto_epoch"));
    assert!(service.contains("current_ref != &snapshot.group_crypto_state_ref"));

    assert!(group_mls.contains("pub const MAX_MLS_BOOTSTRAP_COMMITS: usize = 64;"));
    assert!(group_mls.contains("pub const MAX_MLS_BOOTSTRAP_BYTES: usize = 8 * 1024 * 1024;"));
    assert!(group_mls.contains("BootstrapTooLarge"));
    assert!(sqlite.contains("group_mls_transition_admissions"));
    assert!(sqlite.contains("LIMIT ?6"));
    assert!(sqlite.contains("commits.len() > MAX_MLS_BOOTSTRAP_COMMITS"));
    assert!(sqlite.contains("total_bytes > MAX_MLS_BOOTSTRAP_BYTES"));

    assert!(runtime.contains(".with_mls_bootstrap_store(Arc::clone(&store))"));
}

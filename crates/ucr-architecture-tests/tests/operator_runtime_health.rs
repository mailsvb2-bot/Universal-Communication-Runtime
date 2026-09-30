use std::{fs, path::Path};

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"));
    let tail = &source[start..];
    let end = tail
        .find(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"));
    &tail[..end]
}

#[test]
fn operator_health_is_separate_from_integration_api() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let operator = fs::read_to_string(workspace.join("proto/ucr/v1/operator_runtime.proto"))
        .expect("operator proto");
    let universal = fs::read_to_string(workspace.join("proto/ucr/v1/universal_conference.proto"))
        .expect("universal proto");
    let api =
        fs::read_to_string(workspace.join("crates/ucr-api-grpc/src/operator_runtime_service.rs"))
            .expect("operator service");
    let runtime =
        fs::read_to_string(workspace.join("crates/ucr-runtime/src/lib.rs")).expect("runtime");
    let spec =
        fs::read_to_string(workspace.join("spec/operator-runtime.md")).expect("operator spec");

    assert!(operator.contains("service OperatorRuntimeService"));
    for field in [
        "OperatorComponentHealth api",
        "OperatorComponentHealth sfu",
        "OperatorComponentHealth turn",
        "OperatorComponentHealth storage",
        "OperatorComponentHealth webhook_worker",
        "OperatorComponentHealth recorder",
        "OperatorCapacityStatus capacity",
    ] {
        assert!(
            operator.contains(field),
            "missing operator health field {field}"
        );
    }
    assert!(!universal.contains("OperatorRuntimeService"));
    assert!(api.contains("OperatorRuntimeHealthSource"));
    assert!(api.contains("OperatorSfuClusterControl"));
    for rpc in ["HeartbeatSfuNode", "DrainSfuNode", "ListSfuNodes"] {
        assert!(operator.contains(rpc), "missing private operator RPC {rpc}");
        assert!(
            !universal.contains(rpc),
            "operator RPC leaked into integration API"
        );
    }
    assert!(runtime.contains("operator_runtime_service_server"));
    assert!(spec.contains("socket separation is"));
    assert!(spec.contains("the enforcement boundary"));
    assert!(spec.contains("MUST NOT point at or forward the operator"));
    assert!(spec.contains("valid TURN configuration is not equivalent to TURN network health"));
    assert!(spec.contains("Heartbeat TTL is bounded to 1–120 seconds"));
    assert!(spec.contains("do **not** make the"));
    assert!(spec.contains("public `horizontal_sfu` capability Production-ready"));
}

#[test]
fn operator_health_uses_durable_webhook_lease_and_does_not_claim_missing_providers() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime =
        fs::read_to_string(workspace.join("crates/ucr-runtime/src/lib.rs")).expect("runtime");

    assert!(runtime.contains("webhook delivery worker durable lease is active"));
    assert!(runtime.contains("webhook delivery worker durable lease has expired"));
    assert!(runtime.contains("webhook delivery worker has no durable lease"));
    assert!(runtime.contains("runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND)"));
    assert!(!runtime.contains("lease.holder_id"));
    assert!(runtime.contains("recording provider is not configured"));
    assert!(runtime.contains("TURN configured but network reachability is unverified"));
}

#[test]
fn operator_rpc_is_not_registered_on_public_runtime_listeners() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let runtime =
        fs::read_to_string(workspace.join("crates/ucr-runtime/src/lib.rs")).expect("runtime");
    let edge =
        fs::read_to_string(workspace.join("crates/ucr-https-edge/src/lib.rs")).expect("HTTPS edge");
    let runtime_main =
        fs::read_to_string(workspace.join("crates/ucr-runtime/src/main.rs")).expect("runtime main");

    assert!(edge.contains("copy_bidirectional"));
    for public in [
        section(
            &runtime,
            "async fn serve_api(",
            "/// Serves the canonical machine-auth gRPC service",
        ),
        section(
            &runtime,
            "async fn serve_api_public_services(",
            "struct RealtimeServerServices",
        ),
        section(
            &runtime,
            "async fn serve_machine_auth_inner(",
            "/// Serves the canonical API plus Conference join",
        ),
        section(
            &runtime,
            "async fn serve_realtime_services(",
            "async fn bind_private_operator_listener(",
        ),
    ] {
        assert!(!public.contains(".add_service(operator_runtime_service_server("));
        assert!(!public.contains(".add_service(sfu_placement_service_server("));
    }

    let private = section(
        &runtime,
        "async fn serve_basic_operator_services(",
        "fn configured_attachment_service(",
    );
    assert!(private.contains(".add_service(operator_runtime_service_server("));
    assert!(private.contains("async fn serve_realtime_operator_services("));
    assert!(private.contains(".add_service(sfu_placement_service_server("));
    assert!(runtime.contains("operator bind must be different from the public runtime bind"));
    assert!(runtime.contains("DEFAULT_OPERATOR_BIND: &str = \"127.0.0.1:50052\""));
    assert!(runtime_main.contains("\"--operator-bind\""));
    assert!(runtime_main.contains("serve_realtime_with_machine_bearer_and_operator"));
}

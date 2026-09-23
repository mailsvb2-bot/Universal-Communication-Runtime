use std::{fs, path::Path};

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
    assert!(runtime.contains("operator_runtime_service_server"));
    assert!(spec.contains("MUST NOT forward or expose this service"));
    assert!(spec.contains("valid TURN configuration is not equivalent to TURN network health"));
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

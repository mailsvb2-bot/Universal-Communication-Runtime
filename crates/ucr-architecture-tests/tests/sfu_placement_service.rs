use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn sfu_placement_is_private_infrastructure_not_integration_api() {
    let proto = read("proto/ucr/v1/sfu_placement.proto");
    let universal = read("proto/ucr/v1/universal_conference.proto");
    let web = read("crates/ucr-conference-web/src/main.rs");
    let binding = read("crates/ucr-api-grpc/src/sfu_placement_service.rs");
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let spec = read("spec/sfu.md");

    assert!(proto.contains("service SfuPlacementService"));
    assert!(proto.contains("rpc PlaceCall"));
    assert!(proto.contains("rpc ReleaseCall"));
    assert!(proto.contains("rpc ResolveNode"));
    assert!(proto.contains("endpoint_ip"));
    assert!(proto.contains("endpoint_port"));
    assert!(!universal.contains("SfuPlacementService"));
    assert!(!universal.contains("SfuResolveNodeRequest"));
    assert!(!web.contains("SfuPlacementService"));
    assert!(binding.contains("GrpcSfuPlacementService"));
    assert!(runtime.contains("sfu_placement_service_server(sfu_placement_service)"));
    assert!(spec.contains("private `SfuPlacementService`"));
    assert!(spec.contains("`ResolveNode` separately resolves"));
}

#[test]
fn placement_service_shares_operator_cluster_and_keeps_public_capability_fail_closed() {
    let runtime = read("crates/ucr-runtime/src/lib.rs");
    let universal = read("crates/ucr-api-grpc/src/universal_conference_service.rs");

    assert!(
        runtime.contains("let sfu_cluster = Arc::new(Mutex::new(SfuClusterDirectory::default()))")
    );
    assert!(runtime.contains("Arc::clone(&sfu_cluster)"));
    assert!(runtime.contains("GrpcSfuPlacementService::new"));
    assert!(universal.contains("horizontal_sfu: false"));
}

#[test]
fn placement_request_cannot_choose_an_sfu_node() {
    let proto = read("proto/ucr/v1/sfu_placement.proto");
    let request_start = proto
        .find("message SfuPlaceCallRequest")
        .expect("placement request");
    let request_end = proto[request_start..]
        .find("\n}")
        .map(|offset| request_start + offset)
        .expect("placement request end");
    let request = &proto[request_start..request_end];

    assert!(!request.contains("node_id"));
    assert!(request.contains("preferred_region"));
    assert!(request.contains("allow_cross_region_failover"));
}

#[test]
fn placement_contract_does_not_route_participants_or_media_payloads() {
    let proto = read("proto/ucr/v1/sfu_placement.proto");
    for forbidden in [
        "participant_id",
        "external_user_id",
        "join_token",
        "media_key",
        "payload",
        "ciphertext",
        "endpoint_url",
        "selected_node_id",
    ] {
        assert!(
            !proto.contains(forbidden),
            "private placement contract gained forbidden field {forbidden}"
        );
    }
}

use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn recording_rest_routes_remain_thin_grpc_adapters() {
    let web = read("crates/ucr-conference-web/src/main.rs");
    let openapi = read("crates/ucr-conference-web/openapi.yaml");

    assert!(web.contains("pb::recording_service_client::RecordingServiceClient"));
    assert!(web.contains("type RecordingClient"));
    assert!(web.contains("UCR_RECORDING_GRPC_UPSTREAM"));
    assert!(web.contains("recording gRPC upstream is not configured"));
    assert!(web.contains("state.recording_upstream.as_ref()"));
    for (route, rpc) in [
        ("/v1/recordings", "request_recording"),
        ("/v1/recordings/get", "get_recording"),
        ("/v1/recordings/consent", "set_recording_consent"),
        ("/v1/recordings/start", "start_recording"),
        ("/v1/recordings/stop", "stop_recording"),
        ("/v1/recordings/delete", "delete_recording"),
    ] {
        assert!(web.contains(route), "missing HTTP route {route}");
        assert!(web.contains(rpc), "missing gRPC forwarding call {rpc}");
        assert!(openapi.contains(route), "missing OpenAPI route {route}");
    }

    assert!(web.contains("attach_authorization"));
    assert!(web.contains("authorized(request, authorization)"));
    assert!(!web.contains("recording_admin"));
    assert!(!web.contains("recording_api_key"));
}

#[test]
fn recording_consent_http_path_does_not_create_a_second_auth_owner() {
    let web = read("crates/ucr-conference-web/src/main.rs");
    let service = read("crates/ucr-api-grpc/src/recording_service.rs");

    assert!(web.contains("forward_recording_consent"));
    assert!(web.contains("client.set_recording_consent(request)"));
    assert!(service.contains("decode_bearer_token(request.metadata())"));
    assert!(service.contains("authenticate_realtime_bearer_claims"));
    assert!(!web.contains("authenticate_realtime_bearer_claims"));
    assert!(!web.contains("MachineBearerRequestGate"));
}

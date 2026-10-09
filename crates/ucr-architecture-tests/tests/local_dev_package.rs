use std::{fs, path::Path};

#[test]
fn local_dev_package_reuses_loopback_ucr_dev_and_stays_host_local() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let compose = fs::read_to_string(workspace.join("compose.yaml")).expect("read compose.yaml");
    assert!(compose.contains("dockerfile: docker/dev/Dockerfile"));
    for mapping in [
        "127.0.0.1:50051:50052/tcp",
        "127.0.0.1:8080:8080/tcp",
        "127.0.0.1:8090:8090/tcp",
        "127.0.0.1:3478:3478/tcp",
        "127.0.0.1:3478:3478/udp",
    ] {
        assert!(
            compose.contains(mapping),
            "local dev package must keep published service {mapping} on host loopback"
        );
    }

    let dockerfile =
        fs::read_to_string(workspace.join("docker/dev/Dockerfile")).expect("read dev Dockerfile");
    assert!(dockerfile.contains("cargo build --locked --release -p ucr-dev --bin ucr"));
    assert!(dockerfile.contains("crates/ucr-realtime-web/static/client.html"));
    assert!(dockerfile.contains("cargo build --locked --release -p ucr-realtime-web --bin ucr-realtime-web"));
    assert!(dockerfile.contains("--manifest-path crates/ucr-endpoint-wasm/Cargo.toml"));
    assert!(dockerfile.contains("sdk/typescript/src/reference_browser_media_installer.ts"));
    assert!(dockerfile.contains("COPY --from=browser-sdk /out/endpoint-media/"));
    assert!(dockerfile.contains("COPY --from=builder /src/crates/ucr-realtime-web/static/endpoint-wasm/"));

    let entrypoint = fs::read_to_string(workspace.join("docker/dev/entrypoint.sh"))
        .expect("read dev entrypoint");
    assert!(entrypoint.contains("ucr dev --bind 127.0.0.1:50051"));
    assert!(
        entrypoint
            .contains("socat TCP-LISTEN:50052,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:50051")
    );
    // The browser must use real authenticated Rust realtime HTTP/gRPC bindings.
    // A static-only Python server previously returned 404 for all media/MLS RPCs
    // while allowing the conference page to appear deceptively functional.
    assert!(entrypoint.contains("UCR_REALTIME_WEB_BIND=127.0.0.1:8081"));
    assert!(entrypoint.contains("UCR_REALTIME_GRPC_UPSTREAM=http://127.0.0.1:50051"));
    assert!(entrypoint.contains("UCR_REALTIME_WEB_ASSET_DIR=/opt/ucr/browser"));
    assert!(entrypoint.contains("/usr/local/bin/ucr-realtime-web &"));
    assert!(entrypoint.contains("socat TCP-LISTEN:8080,bind=0.0.0.0,reuseaddr,fork TCP:127.0.0.1:8081"));
    assert!(!entrypoint.contains("python3 -m http.server"));
    assert!(entrypoint.contains("webhook_receiver.py"));
    assert!(entrypoint.contains("turnserver -n"));
    assert!(entrypoint.contains("--use-auth-secret"));

    let dev_main =
        fs::read_to_string(workspace.join("crates/ucr-dev/src/main.rs")).expect("read ucr dev CLI");
    assert!(
        dev_main.contains("if !bind.ip().is_loopback()"),
        "container package must not weaken the canonical dev CLI loopback guard"
    );

    let dev_runtime = fs::read_to_string(workspace.join("crates/ucr-dev/src/lib.rs"))
        .expect("read ucr dev runtime");
    for marker in [
        "universal_conference_service_server",
        "realtime_service_server",
        "GrpcUniversalConferenceService::with_state_and_join_issuer",
        "GrpcRealtimeService::new",
        "verify_universal_conference_round_trip",
        "CreateConference exact idempotent retry",
        "attendance Event projection",
    ] {
        assert!(
            dev_runtime.contains(marker),
            "local integration package must retain Universal Conference runtime evidence: {marker}"
        );
    }
}

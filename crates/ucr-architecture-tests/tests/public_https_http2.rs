use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn public_https_edge_upstreams_remain_dual_http_protocol() {
    for cargo in [
        "crates/ucr-conference-web/Cargo.toml",
        "crates/ucr-auth-web/Cargo.toml",
        "crates/ucr-realtime-web/Cargo.toml",
    ] {
        let manifest = read(cargo);
        // Check the server transport capabilities, not an incidental ordering
        // of Cargo features. The realtime gateway also needs Hyper's client
        // feature for forwarding first-party requests to its loopback BFF.
        let hyper_line = manifest
            .lines()
            .find(|line| line.trim_start().starts_with("hyper = {"))
            .unwrap_or_else(|| panic!("{cargo} must declare the Hyper server dependency"));
        let features = hyper_line
            .split_once("features = [")
            .and_then(|(_, rest)| rest.split_once(']'))
            .map_or_else(
                || panic!("{cargo} must specify Hyper transport features"),
                |(features, _)| {
                    features
                        .split(',')
                        .map(|feature| feature.trim().trim_matches('"'))
                        .collect::<Vec<_>>()
                },
            );
        for required in ["http1", "http2", "server"] {
            assert!(
                features.contains(&required),
                "{cargo} must keep Hyper {required} enabled"
            );
        }
        assert!(
            manifest.contains(r#"features = ["server-auto", "tokio"]"#),
            "{cargo} must keep Hyper auto protocol detection enabled"
        );
    }

    for source in [
        "crates/ucr-conference-web/src/main.rs",
        "crates/ucr-auth-web/src/main.rs",
        "crates/ucr-realtime-web/src/main.rs",
    ] {
        let source_text = read(source);
        assert!(
            source_text.contains("server::conn::auto"),
            "{source} must remain compatible with h2 ALPN from the shared HTTPS edge"
        );
        assert!(
            source_text.contains("auto::Builder::new(TokioExecutor::new())"),
            "{source} must serve both HTTP/1.1 and HTTP/2"
        );
        assert!(
            !source_text.contains("http1::Builder::new().serve_connection"),
            "{source} must not regress to an HTTP/1-only listener"
        );
    }

    let edge = read("crates/ucr-https-edge/src/lib.rs");
    assert!(edge.contains(r#"b"h2".to_vec(), b"http/1.1".to_vec()"#));
}

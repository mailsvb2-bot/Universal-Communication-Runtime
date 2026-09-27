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
        assert!(
            manifest.contains(r#"features = ["http1", "http2", "server"]"#),
            "{cargo} must keep Hyper HTTP/1.1 + HTTP/2 enabled"
        );
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

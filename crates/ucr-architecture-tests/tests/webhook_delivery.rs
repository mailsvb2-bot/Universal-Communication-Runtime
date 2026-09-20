use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).expect("architecture source")
}

#[test]
fn webhook_adapter_preserves_single_event_owner_and_fails_closed() {
    let workspace = read("Cargo.toml");
    let adapter = read("crates/ucr-webhook/src/lib.rs");
    let core = read("crates/ucr-core/src/event_api.rs");
    let runtime = read("crates/ucr-runtime/src/main.rs");
    let spec = read("spec/event-api.md");

    assert!(workspace.contains("\"crates/ucr-webhook\""));
    assert!(core.contains("pub trait EventWebhookSink"));
    assert!(core.contains("pub struct EventWebhookDispatcher"));
    assert!(adapter.contains("impl<R, X> EventWebhookSink for HardenedWebhookSink<R, X>"));
    assert!(adapter.contains("url.scheme() != \"https\""));
    assert!(adapter.contains("!url.username().is_empty()"));
    assert!(adapter.contains("url.query().is_some()"));
    assert!(adapter.contains("url.fragment().is_some()"));
    assert!(adapter.contains(".any(|address| !is_public_address(*address))"));
    assert!(adapter.contains("follow_redirects: false"));
    assert!(adapter.contains("HmacSha256::new_from_slice"));
    assert!(adapter.contains("WebhookSigningSecret([u8; 32])"));
    assert!(adapter.contains("ZeroizeOnDrop"));
    assert!(adapter.contains("408 | 425 | 429 | 500..=599"));
    assert!(adapter.contains("pub struct NativeTlsWebhookExecutor"));
    assert!(adapter.contains("TcpStream::connect_timeout"));
    assert!(adapter.contains("connector.connect(&request.host, stream)"));
    assert!(adapter.contains("SystemWebhookDnsResolver"));
    assert!(runtime.contains("\"dispatch-webhook-once\""));
    assert!(runtime.contains("UCR_WEBHOOK_SIGNING_KEY_HEX"));
    assert!(spec.contains("dispatch-webhook-once"));
}

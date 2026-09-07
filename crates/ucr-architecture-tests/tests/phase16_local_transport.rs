use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase16_local_transport_is_prepared_and_reuses_canonical_owners() {
    let workspace = workspace();
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let lib = fs::read_to_string(workspace.join("crates/ucr-transport-internet/src/lib.rs"))
        .expect("transport lib");
    let local = fs::read_to_string(workspace.join("crates/ucr-transport-internet/src/local.rs"))
        .expect("local transport");
    let handshake =
        fs::read_to_string(workspace.join("crates/ucr-transport-internet/src/local_handshake.rs"))
            .expect("local handshake");
    let route =
        fs::read_to_string(workspace.join("crates/ucr-transport-internet/src/local_route.rs"))
            .expect("local route");
    let spec = fs::read_to_string(workspace.join("spec/local-transport.md")).expect("local spec");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0054-phase16-local-direct-transport-reuses-canonical-transport-and-crypto-owners.md",
    ))
    .expect("ADR 0054");

    assert!(core.contains("pub trait TransportProvider"));
    assert!(local.contains("impl TransportProvider for LocalTransportProvider"));
    assert!(local.contains("CapabilityMaturity::Prepared"));
    assert!(lib.contains("LocalTransportProvider"));
    assert!(lib.contains("LocalTransportServer"));

    assert!(route.contains("ucr.transport.local.tcp"));
    assert!(route.contains("ucr.local.tcp"));
    assert!(route.contains("NonLocalDirectAddress"));
    assert!(route.contains("a == 10"));
    assert!(route.contains("a == 192 && b == 168"));
    assert!(route.contains("first & 0xfe00 == 0xfc00"));
    assert!(route.contains("first & 0xffc0 == 0xfe80"));

    assert!(handshake.contains("ucr.transport.local.context.v1"));
    assert!(handshake.contains("UCR-LOCAL-SCOPE-V1"));
    assert!(handshake.contains("begin_session_with_trusted_peer"));
    assert!(handshake.contains("TrustedSigningKeyResolver"));
    assert!(handshake.contains("ReplayProtector"));
    assert!(handshake.contains("LOCAL_TCP_CAPABILITY"));

    for domain in [
        "UCR-LOCAL-ATTEMPT-ID-V1",
        "UCR-LOCAL-TRANSPORT-V1",
        "UCR-LOCAL-RECEIPT-V1",
        "UCR-LOCAL-RETRY-JITTER-V1",
    ] {
        assert!(local.contains(domain), "missing local domain {domain}");
    }

    assert!(local.contains("local_socket_addr(route)"));
    assert!(local.contains("is_local_direct_ip(peer.ip())"));
    assert!(local.contains("encrypted_envelope.is_empty()"));
    assert!(local.contains("self.policy.max_attempts"));
    assert!(local.contains("self.policy.connect_timeout"));
    assert!(local.contains("self.policy.io_timeout"));
    assert!(local.contains("LocalAcceptStatus::Duplicate"));

    assert!(spec.contains("Status: **Prepared reference implementation**, not Production."));
    assert!(spec.contains("A transport receipt is not `DELIVERED`"));
    assert!(spec.contains("No failure path silently falls back to Internet Transport"));
    assert!(spec.contains("Chat or any Phase 17"));

    assert!(adr.contains("Rejected. That creates a second communication brain"));
    assert!(adr.contains("Phase 15 deliberately rejects local/private client routes"));
    assert!(adr.contains("Phase 17 Chat is explicitly outside this ADR"));
}

#[test]
fn phase16_does_not_create_a_second_canonical_delivery_or_identity_model() {
    let workspace = workspace();
    let local = fs::read_to_string(workspace.join("crates/ucr-transport-internet/src/local.rs"))
        .expect("local transport");
    let handshake =
        fs::read_to_string(workspace.join("crates/ucr-transport-internet/src/local_handshake.rs"))
            .expect("local handshake");

    for forbidden in [
        "struct Message",
        "struct Conversation",
        "struct Delivery",
        "struct Identity",
        "enum DeliveryState",
        "trait MessageStore",
        "trait ConversationStore",
    ] {
        assert!(
            !local.contains(forbidden),
            "local transport owns {forbidden}"
        );
        assert!(
            !handshake.contains(forbidden),
            "local handshake owns {forbidden}"
        );
    }

    assert!(local.contains("RouteCandidate"));
    assert!(local.contains("TenantScope"));
    assert!(handshake.contains("InternetPeerExpectationResolver"));
}

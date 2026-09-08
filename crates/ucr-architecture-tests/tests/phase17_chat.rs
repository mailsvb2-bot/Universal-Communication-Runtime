use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase17_chat_is_thin_prepared_layer_over_canonical_owners() {
    let workspace = workspace();
    let root = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace manifest");
    let chat = fs::read_to_string(workspace.join("crates/ucr-chat/src/lib.rs")).expect("chat");
    let manifest = fs::read_to_string(workspace.join("crates/ucr-chat/Cargo.toml"))
        .expect("chat manifest");
    let spec = fs::read_to_string(workspace.join("spec/chat.md")).expect("chat spec");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0055-phase17-chat-reuses-canonical-conversation-message-and-delivery-owners.md",
    ))
    .expect("ADR 0055");

    assert!(root.contains("\"crates/ucr-chat\""));
    assert!(manifest.contains("publish = false"));
    assert!(manifest.contains("ucr-core = { path = \"../ucr-core\" }"));
    assert!(chat.contains("pub struct ChatRuntime"));
    assert!(chat.contains("AuthorizedDurableRuntime::new"));
    assert!(chat.contains("S: DeliveryStore"));
    assert!(chat.contains("ConversationKind::Direct"));
    assert!(chat.contains("DeliveryEvidenceKind::ReadByUser"));
    assert!(chat.contains("DeliveryState::Delivered"));
    assert!(chat.contains("DeliveryState::Read"));
    assert!(chat.contains("pub trait EphemeralChatSink"));
    assert!(chat.contains("MAX_TYPING_TTL_MS"));
    assert!(chat.contains("MAX_TRANSCRIPT_BATCH_ITEMS"));
    assert!(chat.contains("PrincipalKind::ServiceAccount"));
    assert!(spec.contains("Status: **Prepared reference implementation**, not Production."));
    assert!(spec.contains("Typing is deliberately ephemeral"));
    assert!(spec.contains("Transport or Relay acknowledgement is never promoted to `READ`"));
    assert!(spec.contains("Phase 18"));
    assert!(adr.contains("second communication brain"));
    assert!(adr.contains("Phase 18 Groups remains outside this ADR"));
}

#[test]
fn phase17_chat_creates_no_second_message_conversation_delivery_or_route_brain() {
    let workspace = workspace();
    let chat = fs::read_to_string(workspace.join("crates/ucr-chat/src/lib.rs")).expect("chat");
    for forbidden in [
        "struct ChatMessage",
        "struct ChatConversation",
        "struct ChatDelivery",
        "trait ChatMessageStore",
        "trait ChatConversationStore",
        "HashMap<",
        "Sqlite",
        "rusqlite",
        "TcpStream",
        "RoutePlanner",
        "TransportOrchestrator",
    ] {
        assert!(!chat.contains(forbidden), "Phase 17 leaked second owner: {forbidden}");
    }
    assert!(chat.contains("load_transcript_batch"));
    assert!(chat.contains(".message(subject, scope"));
    assert!(chat.contains(".persist_message(subject, message)"));
    assert!(chat.contains(".transition_delivery("));
    assert!(!chat.contains("persist_typing"));
    assert!(!chat.contains("append_typing"));
}

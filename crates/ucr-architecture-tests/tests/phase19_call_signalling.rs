use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase19_call_signalling_reuses_canonical_owners_and_is_restart_safe() {
    let root = workspace();
    let model = fs::read_to_string(root.join("crates/ucr-model/src/call.rs")).expect("call model");
    let protocol =
        fs::read_to_string(root.join("crates/ucr-protocol/src/call.rs")).expect("call protocol");
    let core = fs::read_to_string(root.join("crates/ucr-core/src/call.rs")).expect("call core");
    let runtime = fs::read_to_string(root.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("runtime");
    let memory = fs::read_to_string(root.join("crates/ucr-storage-memory/src/call_store.rs"))
        .expect("memory");
    let sqlite = fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/call_store.rs"))
        .expect("sqlite");
    let sqlite_root =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite root");
    let proto = fs::read_to_string(root.join("proto/ucr/v1/call.proto")).expect("call proto");
    let grpc = fs::read_to_string(root.join("crates/ucr-api-grpc/src/lib.rs")).expect("grpc");
    let spec = fs::read_to_string(root.join("spec/call-signalling.md")).expect("spec");
    let adr = fs::read_to_string(root.join("docs/adr/0057-phase19-call-signalling-reuses-canonical-conversation-identity-and-authorization-owners.md")).expect("adr");

    assert!(model.contains("pub struct CallSession"));
    assert!(model.contains("pub reconnecting_participant: Option<PrincipalRef>"));
    assert!(model.contains("pub enum CallSignalKind"));
    assert!(protocol.contains("pub fn apply_call_signal("));
    assert!(protocol.contains("pub fn call_signal_fingerprint("));
    assert!(core.contains("pub trait CallStore: StorageProvider + ConversationStore + GroupStore"));
    assert!(core.contains("fn call_for_participant("));
    assert!(runtime.contains("CALL_START_PERMISSION"));
    assert!(runtime.contains("CALL_OBSERVE_PERMISSION"));
    assert!(runtime.contains("CALL_SIGNAL_PERMISSION"));
    assert!(memory.contains("state.call_signals"));
    assert!(memory.contains("session.signalling_state == CallSignallingState::Terminated"));
    assert!(memory.contains("group_actor_current_if_needed"));
    assert!(sqlite.contains("CREATE TABLE calls"));
    assert!(sqlite.contains("CREATE TABLE call_participants"));
    assert!(sqlite.contains("CREATE TABLE call_signals"));
    assert!(sqlite.contains("reconnecting_principal_id"));
    assert!(sqlite.contains("reconnecting_principal_kind"));
    assert!(sqlite.contains("call_signal_reserves_event_id"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 22"));
    assert!(sqlite_root.contains("migrate_v21_to_v22"));
    assert!(proto.contains("service CallService"));
    assert!(proto.contains("rpc StartCall"));
    assert!(proto.contains("rpc GetCall"));
    assert!(proto.contains("rpc SignalCall"));
    assert!(proto.contains("PrincipalRef reconnecting_participant = 12"));
    assert!(grpc.contains("ServicePrincipalRequestGate") || grpc.contains("IntegrationIngress"));
    assert!(
        grpc.contains("call_start_cancel_duplicate_get_and_non_disclosure_round_trip_over_grpc")
    );
    assert!(spec.contains("Status: **Prepared reference implementation**, not Production."));
    assert!(spec.contains("`Active` means only that signalling acceptance has completed"));
    assert!(spec.contains("same exact `PrincipalRef` that opened the reconnect cycle"));
    assert!(adr.contains("second communication brain"));
}

#[test]
fn phase19_creates_no_second_identity_conversation_delivery_event_or_media_brain() {
    let root = workspace();
    let files = [
        fs::read_to_string(root.join("crates/ucr-model/src/call.rs")).expect("model"),
        fs::read_to_string(root.join("crates/ucr-core/src/call.rs")).expect("core"),
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/call_store.rs"))
            .expect("sqlite"),
    ];
    for forbidden in [
        "struct CallIdentity",
        "struct CallConversation",
        "struct CallMessage",
        "struct CallDelivery",
        "trait CallIdentityStore",
        "trait CallConversationStore",
        "trait CallDeliveryStore",
        "CREATE TABLE call_identities",
        "CREATE TABLE call_conversations",
        "CREATE TABLE call_messages",
        "CREATE TABLE call_deliveries",
        "CREATE TABLE call_media",
        "struct Rtp",
        "struct Sdp",
        "struct IceCandidate",
    ] {
        assert!(
            files.iter().all(|content| !content.contains(forbidden)),
            "second owner/media leak: {forbidden}"
        );
    }
}

#[test]
fn phase19_release_truth_and_repository_guards_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    assert!(readme.contains(
        "**Phase 19 — Call Signalling (Prepared/reference complete; Phase 20 Audio not started).**"
    ));
    assert!(ci.contains("test -s spec/call-signalling.md"));
    assert!(ci.contains("test -s proto/ucr/v1/call.proto"));
    assert!(ci.contains("0057-phase19-call-signalling-reuses-canonical-conversation-identity-and-authorization-owners.md"));
}

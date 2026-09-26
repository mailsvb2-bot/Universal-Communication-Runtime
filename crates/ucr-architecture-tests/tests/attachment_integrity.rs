use std::{fs, path::PathBuf};

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(workspace().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"))
}

#[test]
fn attachment_integrity_contract_is_canonical_and_message_stays_reference_only() {
    let model = read("crates/ucr-model/src/attachment.rs");
    let protocol = read("crates/ucr-protocol/src/attachment.rs");
    let message_model = read("crates/ucr-model/src/lib.rs");
    let proto = read("proto/ucr/v1/attachment.proto");
    let message_proto = read("proto/ucr/v1/communication.proto");
    let spec = read("spec/attachments.md");
    let adr = read(
        "docs/adr/0110-attachment-integrity-is-content-addressed-and-separate-from-message-identity.md",
    );

    for marker in [
        "pub struct AttachmentContentId",
        "pub struct AttachmentDescriptor",
        "pub struct AttachmentChunk",
    ] {
        assert!(
            model.contains(marker),
            "missing canonical Attachment model: {marker}"
        );
    }

    for marker in [
        "ATTACHMENT_CONTENT_HASH_ALGORITHM",
        "MAX_ATTACHMENT_CHUNK_BYTES",
        "MAX_ATTACHMENT_CHUNKS",
        "verify_attachment_chunk",
        "verify_complete_attachment",
        "Sha256::digest",
    ] {
        assert!(
            protocol.contains(marker),
            "missing Attachment integrity rule: {marker}"
        );
    }

    assert!(message_model.contains("pub attachment_ids: Vec<AttachmentId>"));
    assert!(!message_model.contains("pub attachment_bytes"));
    assert!(!message_proto.contains("attachment_payload"));
    assert!(message_proto.contains("repeated OpaqueId attachment_ids = 13;"));

    for marker in [
        "message AttachmentContentId",
        "message AttachmentDescriptor",
        "message AttachmentChunk",
        "bytes sha256 = 1;",
    ] {
        assert!(
            proto.contains(marker),
            "missing public Attachment contract: {marker}"
        );
    }

    assert!(spec.contains("SHA-256(exact attachment bytes)"));
    assert!(spec.contains("does **not** claim that Canon file transfer is complete"));
    assert!(adr.contains("Message continues to carry only Attachment IDs"));
    assert!(adr.contains("No existing durable data migration is required"));
}

#[test]
fn attachment_integrity_contract_keeps_payload_and_hashes_out_of_debug() {
    let model = read("crates/ucr-model/src/attachment.rs");

    for redaction in [
        r#".field("bytes", &"<redacted>")"#,
        r#".field("sha256", &"<opaque>")"#,
        r#".field("file_name""#,
        r#".field("media_type""#,
        r#".map(|_| "<redacted>")"#,
    ] {
        assert!(
            model.contains(redaction),
            "Attachment Debug boundary lost redaction marker: {redaction}"
        );
    }
    assert!(
        model.matches(r#".map(|_| "<redacted>")"#).count() >= 2,
        "Attachment metadata Debug fields must remain redacted"
    );
}

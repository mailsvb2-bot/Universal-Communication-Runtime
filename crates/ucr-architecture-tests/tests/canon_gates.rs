use std::{fs, path::Path};

const FORBIDDEN_CORE_TERMS: &[&str] = &[
    "telegram",
    "vk_message",
    "max_message",
    "clientplatform",
    "businessaios",
    "send_via_telegram",
    "send_via_vk",
    "send_via_max",
];

fn collect_files(path: &Path, output: &mut Vec<std::path::PathBuf>) {
    let entries = fs::read_dir(path).unwrap_or_else(|error| {
        panic!(
            "failed to read architecture-test path {}: {error}",
            path.display()
        )
    });
    for entry in entries {
        let entry = entry.expect("valid directory entry");
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_files(&entry_path, output);
        } else if matches!(
            entry_path.extension().and_then(|value| value.to_str()),
            Some("rs" | "proto")
        ) {
            output.push(entry_path);
        }
    }
}

#[test]
fn canonical_core_and_protocol_do_not_contain_product_specific_brains() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let mut files = Vec::new();
    for relative in [
        "crates/ucr-model/src",
        "crates/ucr-protocol/src",
        "crates/ucr-core/src",
        "proto",
    ] {
        collect_files(&workspace.join(relative), &mut files);
    }

    assert!(!files.is_empty(), "architecture gate scanned no files");
    for file in files {
        let content = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        let lower = content.to_ascii_lowercase();
        for forbidden in FORBIDDEN_CORE_TERMS {
            assert!(
                !lower.contains(forbidden),
                "forbidden product/provider coupling `{forbidden}` found in {}",
                file.display()
            );
        }
    }
}

#[test]
fn protobuf_contract_is_versioned_and_language_independent() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto_root = workspace.join("proto/ucr/v1");
    let mut files = Vec::new();
    collect_files(&proto_root, &mut files);
    assert!(!files.is_empty(), "no protobuf contract files found");

    for file in files {
        let content = fs::read_to_string(&file).expect("read protobuf file");
        assert!(
            content.contains("package ucr.v1;"),
            "{} does not declare the versioned public package",
            file.display()
        );
    }
}

#[test]
fn canonical_error_codes_match_public_protobuf_contract() {
    use ucr_protocol::CanonicalErrorCode;

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/errors.proto")).expect("read errors.proto");

    let codes = [
        (
            CanonicalErrorCode::InvalidArgument,
            "ERROR_CODE_INVALID_ARGUMENT",
        ),
        (
            CanonicalErrorCode::MalformedFrame,
            "ERROR_CODE_MALFORMED_FRAME",
        ),
        (
            CanonicalErrorCode::UnsupportedProtocolVersion,
            "ERROR_CODE_UNSUPPORTED_PROTOCOL_VERSION",
        ),
        (
            CanonicalErrorCode::DowngradeRejected,
            "ERROR_CODE_DOWNGRADE_REJECTED",
        ),
        (
            CanonicalErrorCode::UnsupportedCriticalExtension,
            "ERROR_CODE_UNSUPPORTED_CRITICAL_EXTENSION",
        ),
        (
            CanonicalErrorCode::CapabilityMismatch,
            "ERROR_CODE_CAPABILITY_MISMATCH",
        ),
        (
            CanonicalErrorCode::Unauthenticated,
            "ERROR_CODE_UNAUTHENTICATED",
        ),
        (
            CanonicalErrorCode::PermissionDenied,
            "ERROR_CODE_PERMISSION_DENIED",
        ),
        (CanonicalErrorCode::PolicyDenied, "ERROR_CODE_POLICY_DENIED"),
        (CanonicalErrorCode::RateLimited, "ERROR_CODE_RATE_LIMITED"),
        (
            CanonicalErrorCode::ResourceExhausted,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
        ),
        (
            CanonicalErrorCode::DeadlineExceeded,
            "ERROR_CODE_DEADLINE_EXCEEDED",
        ),
        (CanonicalErrorCode::Cancelled, "ERROR_CODE_CANCELLED"),
        (
            CanonicalErrorCode::TemporarilyUnavailable,
            "ERROR_CODE_TEMPORARILY_UNAVAILABLE",
        ),
        (
            CanonicalErrorCode::IntegrityFailure,
            "ERROR_CODE_INTEGRITY_FAILURE",
        ),
        (CanonicalErrorCode::Conflict, "ERROR_CODE_CONFLICT"),
        (CanonicalErrorCode::NotFound, "ERROR_CODE_NOT_FOUND"),
        (CanonicalErrorCode::Internal, "ERROR_CODE_INTERNAL"),
    ];

    for (code, name) in codes {
        let declaration = format!("{name} = {};", code as u16);
        assert!(
            proto.contains(&declaration),
            "public protobuf contract is missing `{declaration}`"
        );
    }
}

#[test]
fn canonical_capability_vocabulary_has_single_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs"))
        .expect("read canonical model");
    assert!(model.contains("pub enum CapabilityMaturity"));
    assert!(model.contains("pub struct CapabilityDescriptor"));

    for path in [
        "crates/ucr-core/src/lib.rs",
        "crates/ucr-protocol/src/capability.rs",
    ] {
        let content = fs::read_to_string(workspace.join(path)).expect("read consumer layer");
        assert!(
            !content.contains("pub enum CapabilityMaturity"),
            "{path} must consume the canonical capability maturity instead of redefining it"
        );
        assert!(
            !content.contains("pub struct CapabilityDescriptor"),
            "{path} must consume the canonical capability descriptor instead of redefining it"
        );
    }
}

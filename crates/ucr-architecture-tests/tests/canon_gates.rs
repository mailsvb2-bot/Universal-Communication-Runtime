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

#[test]
fn identity_address_endpoint_and_route_remain_separate_layers() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs"))
        .expect("read canonical model");
    assert!(model.contains("pub struct EndpointAddress"));
    assert!(model.contains("pub struct EndpointDescriptor"));
    assert!(model.contains("pub struct ExternalIdentityBinding"));

    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs"))
        .expect("read core contract");
    assert!(core.contains("pub endpoint_id: EndpointId"));
    assert!(core.contains("pub address: EndpointAddress"));
    assert!(
        !core.contains("pub endpoint_address: Vec<u8>"),
        "RouteCandidate must not collapse endpoint identity and address bytes"
    );
}

#[test]
fn public_identity_contract_exposes_generic_addressing_primitives() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/identity.proto"))
        .expect("read identity proto");

    for declaration in [
        "enum EndpointKind",
        "message EndpointAddress",
        "message EndpointDescriptor",
        "message ExternalIdentityBinding",
    ] {
        assert!(
            proto.contains(declaration),
            "public identity contract is missing `{declaration}`"
        );
    }
    assert!(proto.contains("bytes external_entity_id = 4;"));
    assert!(proto.contains("OpaqueId identity_id = 5;"));
}

#[test]
fn actor_provenance_is_explicit_and_not_person_only() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let identity = fs::read_to_string(workspace.join("proto/ucr/v1/identity.proto"))
        .expect("read identity proto");
    let communication = fs::read_to_string(workspace.join("proto/ucr/v1/communication.proto"))
        .expect("read communication proto");

    assert!(identity.contains("ACTOR_KIND_AI_AGENT"));
    assert!(identity.contains("ACTOR_KIND_BOT"));
    assert!(communication.contains("message OriginRef"));
    assert!(communication.contains("ActorRef author = 4;"));
    assert!(communication.contains("OriginRef origin = 11;"));
    assert!(
        !communication.contains("PersonId author"),
        "canonical message author must remain Actor-based"
    );
}

#[test]
fn device_lifecycle_and_identity_evidence_match_canon_vocabulary() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/identity.proto"))
        .expect("read identity proto");

    for token in [
        "IDENTITY_EVIDENCE_UNVERIFIED",
        "IDENTITY_EVIDENCE_SELF_ASSERTED",
        "IDENTITY_EVIDENCE_DEVICE_VERIFIED",
        "IDENTITY_EVIDENCE_CONTACT_VERIFIED",
        "IDENTITY_EVIDENCE_ORGANIZATION_VERIFIED",
        "IDENTITY_EVIDENCE_EXTERNAL_PROVIDER_VERIFIED",
        "DEVICE_LIFECYCLE_STATE_ACTIVE",
        "DEVICE_LIFECYCLE_STATE_STALE",
        "DEVICE_LIFECYCLE_STATE_REVERIFICATION_REQUIRED",
        "DEVICE_LIFECYCLE_STATE_EXPIRED",
        "DEVICE_LIFECYCLE_STATE_REVOKED",
    ] {
        assert!(
            proto.contains(token),
            "public identity contract is missing `{token}`"
        );
    }
}

#[test]
fn threat_model_keeps_all_canon_trust_boundaries() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let threat_model = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("read threat model");

    for boundary in [
        "User Device",
        "External App",
        "SDK",
        "UCR Core",
        "Relay",
        "Bridge",
        "SFU",
        "Personal Node",
        "Organization Node",
        "Cloud Infrastructure",
    ] {
        assert!(
            threat_model.contains(boundary),
            "threat model is missing `{boundary}`"
        );
    }
}
#[test]
fn threat_model_keeps_required_canon_threat_classes() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let threat_model = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("read threat model");

    for threat in [
        "malicious peer",
        "compromised device",
        "stolen device",
        "malicious bridge",
        "compromised relay",
        "compromised SFU",
        "malicious tenant",
        "malicious service account",
        "MITM",
        "replay",
        "downgrade",
        "impersonation",
        "attachment bombs",
        "Sybil-like abuse",
    ] {
        assert!(
            threat_model.contains(threat),
            "threat model is missing `{threat}`"
        );
    }
}
#[test]
fn threat_model_keeps_production_blockers_visible() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let threat_model = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("read threat model");

    for blocker in [
        "authenticated handshake and key confirmation",
        "replay protection state",
        "cryptographic transcript/downgrade binding",
        "tenant-scoped authorization enforcement",
        "Service Principal authentication/least-privilege enforcement",
        "device revocation enforcement",
        "account/key recovery model and tests",
        "required threat simulations",
        "required fuzz targets",
        "secret/plaintext telemetry regression tests",
    ] {
        assert!(
            threat_model.contains(blocker),
            "production blocker disappeared without evidence: `{blocker}`"
        );
    }

    assert!(threat_model.contains("Documentation alone does not close it"));
}
#[test]
fn threat_model_keeps_minimum_disclosure_and_security_nonclaims() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let threat_model = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("read threat model");

    for invariant in [
        "minimum disclosure of metadata",
        "Relay receives only relay-required routing material",
        "Bridge receives only provider context required",
        "SFU receives only media-routing context required",
        "Successful version/capability negotiation alone is not proof",
        "cannot promise deletion of secrets or plaintext already extracted",
        "must not require central telemetry upload to function",
    ] {
        assert!(
            threat_model.contains(invariant),
            "security/privacy invariant is missing: `{invariant}`"
        );
    }
}

#[test]
fn tenant_scope_remains_explicit_and_non_wildcard() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec =
        fs::read_to_string(workspace.join("spec/tenant-scope.md")).expect("read tenant scope spec");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/identity.proto"))
        .expect("read identity proto");

    assert!(spec.contains("does **not** mean \"all namespaces\""));
    assert!(spec.contains("exact scope equality"));
    assert!(spec.contains("PERMISSION_DENIED"));
    assert!(proto.contains("message ScopedPrincipal"));
    assert!(proto.contains("TenantScope scope = 1;"));
    assert!(proto.contains("PrincipalRef principal = 2;"));
}

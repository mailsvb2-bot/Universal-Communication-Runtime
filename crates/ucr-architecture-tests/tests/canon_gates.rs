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
        "production OS/hardware-backed key providers for supported targets",
        "device-bound credential/content delivery",
        "end-to-end recovery workflow",
        "required threat simulations",
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

#[test]
fn authorization_contract_is_deny_by_default_and_explicitly_scoped() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec =
        fs::read_to_string(workspace.join("spec/permissions.md")).expect("read permissions spec");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/authorization.proto"))
        .expect("read authorization proto");

    assert!(spec.contains("Authorization is deny-by-default"));
    assert!(spec.contains("TenantWide"));
    assert!(spec.contains("namespace-bound principal cannot receive tenant-wide authority"));
    assert!(proto.contains("oneof scope"));
    assert!(proto.contains("ExactPermissionScope exact_scope = 3;"));
    assert!(proto.contains("TenantWidePermissionScope tenant_wide_scope = 4;"));
}

#[test]
fn service_accounts_reuse_canonical_principal_model() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let identity = fs::read_to_string(workspace.join("proto/ucr/v1/identity.proto"))
        .expect("read identity proto");
    let authz = fs::read_to_string(workspace.join("proto/ucr/v1/authorization.proto"))
        .expect("read authorization proto");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("read core");

    assert!(identity.contains("PRINCIPAL_KIND_SERVICE_ACCOUNT"));
    assert!(authz.contains("ScopedPrincipal subject = 1;"));
    assert!(!authz.contains("message ServicePrincipal"));
    assert!(core.contains("pub trait AuthorizationEvaluator"));
    assert!(core.contains("pub trait PolicyEvaluator"));
}

#[test]
fn authorization_contract_does_not_embed_credentials() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let authz = fs::read_to_string(workspace.join("proto/ucr/v1/authorization.proto"))
        .expect("read authorization proto");

    for forbidden in ["api_key =", "bearer_token =", "secret =", "credential ="] {
        assert!(
            !authz.contains(forbidden),
            "authorization contract must not embed credential field `{forbidden}`"
        );
    }
}

#[test]
fn command_receipt_is_not_event_or_effect_proof() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/commands-events.md"))
        .expect("read command/event spec");
    let runtime = fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto"))
        .expect("read runtime proto");

    assert!(spec.contains("An accepted command is not evidence"));
    assert!(spec.contains("Neither receipt is an Event"));
    assert!(runtime.contains("message CommandReceipt"));
    assert!(runtime.contains("COMMAND_RECEIPT_STATUS_ACCEPTED"));
    assert!(runtime.contains("COMMAND_RECEIPT_STATUS_DUPLICATE"));
    assert!(runtime.contains("not evidence that the requested real-world effect occurred"));
}

#[test]
fn runtime_response_envelopes_keep_wire_parity_and_ack_nonclaim() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let commands = fs::read_to_string(workspace.join("crates/ucr-protocol/src/commands.rs"))
        .expect("command protocol");
    let acknowledgement =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/acknowledgement.rs"))
            .expect("acknowledgement protocol");
    let framing = fs::read_to_string(workspace.join("crates/ucr-protocol/src/framing.rs"))
        .expect("framing protocol");
    let runtime =
        fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto")).expect("runtime proto");
    let framing_spec = fs::read_to_string(workspace.join("spec/framing.md")).expect("framing spec");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite store");

    let receipt = commands
        .split("pub struct CommandReceipt")
        .nth(1)
        .and_then(|tail| tail.split("/// Validates receipt shape").next())
        .expect("CommandReceipt Rust block");
    assert!(receipt.contains("pub schema_version: ProtocolVersion"));
    assert!(receipt.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(commands.contains("pub fn canonical_command_receipt"));
    assert!(commands.contains("RUNTIME_ENVELOPE_SCHEMA_V1"));

    assert!(acknowledgement.contains("pub struct AcknowledgementEnvelope"));
    assert!(acknowledgement.contains("pub acknowledged_id: OpaqueId"));
    assert!(acknowledgement.contains("pub schema_version: ProtocolVersion"));
    assert!(acknowledgement.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(acknowledgement.contains("pub fn canonical_acknowledgement"));

    assert!(runtime.contains("message CommandReceipt"));
    assert!(runtime.contains("ProtocolVersion schema_version = 4;"));
    assert!(runtime.contains("repeated Extension extensions = 5;"));
    assert!(runtime.contains("message AcknowledgementEnvelope"));
    assert!(runtime.contains("OpaqueId acknowledged_id = 1;"));
    assert!(runtime.contains("ProtocolVersion schema_version = 2;"));
    assert!(runtime.contains("repeated Extension extensions = 3;"));
    assert!(framing.contains("Acknowledgement = 6"));

    assert!(memory.contains("accepted_command_receipt"));
    assert!(memory.contains("duplicate_command_receipt"));
    assert!(sqlite.contains("accepted_command_receipt"));
    assert!(sqlite.contains("duplicate_command_receipt"));
    assert!(framing_spec.contains("not `DeliveryState::ACKNOWLEDGED`"));
    assert!(
        framing_spec
            .contains("cannot be promoted into provider/transport/device/user delivery evidence")
    );
}

#[test]
fn negotiation_and_capabilities_preserve_payload_bearing_extension_wire_semantics() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let capability = fs::read_to_string(workspace.join("crates/ucr-protocol/src/capability.rs"))
        .expect("capability protocol");
    let handshake = fs::read_to_string(workspace.join("crates/ucr-protocol/src/handshake.rs"))
        .expect("handshake protocol");
    let extension = fs::read_to_string(workspace.join("crates/ucr-protocol/src/extension.rs"))
        .expect("extension protocol");
    let common =
        fs::read_to_string(workspace.join("proto/ucr/v1/common.proto")).expect("common proto");
    let runtime =
        fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto")).expect("runtime proto");
    let negotiation_spec =
        fs::read_to_string(workspace.join("spec/negotiation.md")).expect("negotiation spec");

    let capability_model = model
        .split("pub struct CapabilityDescriptor")
        .nth(1)
        .and_then(|tail| tail.split("#[derive").next())
        .expect("CapabilityDescriptor model block");
    assert!(capability_model.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(common.contains("message Capability"));
    assert!(common.contains("repeated Extension extensions = 3;"));
    assert!(capability.contains("pub fn canonical_capability_descriptor"));
    assert!(capability.contains("CriticalExtensionRequiresExplicitNegotiation"));

    let hello = handshake
        .split("pub struct PeerHello")
        .nth(1)
        .and_then(|tail| tail.split("#[derive").next())
        .expect("PeerHello block");
    assert!(hello.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(runtime.contains("message NegotiationHello"));
    assert!(runtime.contains("repeated Extension extensions = 3;"));

    let result = handshake
        .split("pub struct NegotiationResultEnvelope")
        .nth(1)
        .and_then(|tail| tail.split("#[derive").next())
        .expect("NegotiationResultEnvelope block");
    assert!(result.contains("pub capabilities: Vec<CapabilityDescriptor>"));
    assert!(result.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(result.contains("pub transcript_binding: Vec<u8>"));
    assert!(runtime.contains("message NegotiationResult"));
    assert!(runtime.contains("bytes transcript_binding = 4 [deprecated = true];"));
    assert!(handshake.contains("DeprecatedTranscriptBindingNotEmpty"));
    assert!(handshake.contains("pub fn canonical_negotiation_result"));

    assert!(!extension.contains("pub struct ExtensionDescriptor"));
    assert!(negotiation_spec.contains("extension payload bytes are never discarded"));
    assert!(negotiation_spec.contains("critical capability-level extension fails negotiation"));
    assert!(negotiation_spec.contains("does not infer response extensions from either Hello"));
}

#[test]
fn command_idempotency_contract_keeps_restart_nonclaim_visible() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/commands-events.md"))
        .expect("read command/event spec");

    for invariant in [
        "Every accepted command requires a non-empty bounded idempotency key",
        "different type, payload, schema version, or canonical extension semantics is `CONFLICT`",
        "restart-safe command acceptance/deduplication",
        "does not prove an arbitrary external side effect happened exactly once",
        "different tenant/namespace scope means a different command domain",
    ] {
        assert!(
            spec.contains(invariant),
            "command invariant missing: `{invariant}`"
        );
    }
}

#[test]
fn command_envelope_keeps_wire_model_idempotency_and_storage_parity() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/commands.rs"))
        .expect("command protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let sqlite_command =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/command_store.rs"))
            .expect("sqlite command store");
    let runtime =
        fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto")).expect("runtime proto");

    let command_model = model
        .split("pub struct CommandEnvelope")
        .nth(1)
        .and_then(|tail| tail.split("impl fmt::Debug for CommandEnvelope").next())
        .expect("CommandEnvelope model block");
    assert!(command_model.contains("pub schema_version: ProtocolVersion"));
    assert!(command_model.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(runtime.contains("ProtocolVersion schema_version = 6;"));
    assert!(runtime.contains("repeated Extension extensions = 7;"));
    assert!(protocol.contains("pub fn canonical_command"));
    assert!(protocol.contains("original.schema_version == incoming.schema_version"));
    assert!(protocol.contains("original.extensions == incoming.extensions"));
    assert!(
        memory.contains("command_extensions_and_schema_are_semantic_but_extension_order_is_not")
    );
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V9: u32 = 9;"));
    assert!(sqlite_root.contains("fn migrate_v8_to_v9"));
    assert!(sqlite_root.contains("v8_to_v9_migration_backfills_legacy_command_protocol_semantics"));
    assert!(sqlite_root.contains("missing_command_protocol_metadata_is_rejected_on_reopen"));
    assert!(sqlite_command.contains("CREATE TABLE command_protocol_metadata"));
    assert!(sqlite_command.contains("CREATE TABLE command_extensions"));
}

#[test]
fn local_storage_keeps_sqlite_out_of_canonical_core() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    for relative in [
        "crates/ucr-model/src/lib.rs",
        "crates/ucr-protocol/src/lib.rs",
        "crates/ucr-core/src/lib.rs",
    ] {
        let content = fs::read_to_string(workspace.join(relative)).expect("read canonical crate");
        assert!(
            !content.contains("rusqlite"),
            "SQLite leaked into {relative}"
        );
        assert!(
            !content.contains("accepted_commands"),
            "SQL schema leaked into {relative}"
        );
    }

    let root = fs::read_to_string(workspace.join("Cargo.toml")).expect("read workspace manifest");
    let sqlite_manifest =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/Cargo.toml"))
            .expect("read sqlite manifest");
    assert!(root.contains("crates/ucr-storage-memory"));
    assert!(root.contains("crates/ucr-storage-sqlite"));
    assert!(sqlite_manifest.contains("version = \"=0.40.2\""));
    assert!(sqlite_manifest.contains("features = [\"bundled\"]"));
}

#[test]
fn local_storage_contract_keeps_restart_and_failure_invariants() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/local-storage.md"))
        .expect("read local storage spec");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("read sqlite store");

    for invariant in [
        "only then return Accepted",
        "process restart must preserve committed deduplication state",
        "silent downgrade is forbidden",
        "Storage exhaustion, corruption, unavailability",
        "preserve unsynced/durable state",
        "External consumers never receive direct database access",
    ] {
        assert!(
            spec.contains(invariant),
            "storage invariant missing: `{invariant}`"
        );
    }
    for evidence in [
        "accepted_command_is_deduplicated_after_restart",
        "concurrent_acceptance_has_single_winner",
        "uncommitted_acceptance_does_not_survive_reopen",
        "foreign_sqlite_database_is_not_adopted",
        "newer_schema_is_rejected_without_downgrade",
        "schema_shape_drift_is_rejected_even_at_known_version",
        "sqlite_sidecar_files_are_owner_only",
        "v1_store_migrates_and_preserves_command_deduplication",
        "v1_duplicate_scoped_command_ids_block_migration_without_version_bump",
        "event_append_survives_restart_and_is_idempotent",
        "terminal_event_survives_restart_and_retry",
        "concurrent_terminal_events_have_single_winner",
        "foreign_key_violation_is_rejected_on_reopen",
        "command_protocol_semantics_survive_restart_and_extension_order_is_canonical",
        "v8_to_v9_migration_backfills_legacy_command_protocol_semantics",
        "missing_command_protocol_metadata_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite.contains(evidence),
            "storage evidence test missing: `{evidence}`"
        );
    }
}

#[test]
fn protocol_version_value_type_has_one_rust_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let version = fs::read_to_string(workspace.join("crates/ucr-protocol/src/version.rs"))
        .expect("version module");

    assert!(model.contains("pub struct ProtocolVersion"));
    assert!(version.contains("pub use ucr_model::ProtocolVersion;"));
    assert!(!version.contains("pub struct ProtocolVersion"));
}

#[test]
fn canonical_event_contract_keeps_provenance_and_wire_compatibility() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let runtime =
        fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto")).expect("runtime");

    for field in [
        "pub actor: ActorRef",
        "pub source_device: DeviceRef",
        "pub wall_time_unix_ms: i64",
        "pub logical_order: u64",
        "pub schema_version: ProtocolVersion",
        "pub integrity_metadata: Vec<u8>",
    ] {
        assert!(
            model.contains(field),
            "missing canonical Event field: {field}"
        );
    }
    for wire in [
        "uint64 logical_order = 5;",
        "Correlation correlation = 6;",
        "ProtocolVersion schema_version = 7;",
        "bytes integrity_metadata = 8;",
        "repeated Extension extensions = 9;",
        "ActorRef actor = 10;",
        "DeviceRef source_device = 11;",
        "int64 wall_time_unix_ms = 12;",
    ] {
        assert!(
            runtime.contains(wire),
            "Event wire invariant missing: {wire}"
        );
    }
}

#[test]
fn event_journal_keeps_append_only_and_exactly_once_nonclaim() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/local-storage.md")).expect("storage spec");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");

    for invariant in [
        "Canonical Events are append-only",
        "same scoped Event ID with identical semantics is a Duplicate",
        "second different terminal Event for the same Command is a Conflict",
        "not universal exactly-once evidence for an external side effect",
        "migration fails and the database remains at v1",
    ] {
        assert!(
            spec.contains(invariant),
            "event journal invariant missing: {invariant}"
        );
    }
    assert!(core.contains("pub trait EventJournalStore"));
    assert!(core.contains("pub trait CommandOutcomeStore"));
}

#[test]
fn crypto_suite_has_one_protocol_owner_and_non_exporting_key_boundary() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/crypto_contract.rs"))
        .expect("crypto contract");
    let crypto = fs::read_to_string(workspace.join("crates/ucr-crypto/src/lib.rs"))
        .expect("crypto implementation");
    let provider = fs::read_to_string(workspace.join("crates/ucr-crypto/src/key_provider.rs"))
        .expect("key provider");

    for identifier in ["ed25519", "x25519", "hkdf-sha256", "xchacha20-poly1305"] {
        assert!(protocol.contains(identifier));
    }
    assert!(crypto.contains("pub use ucr_protocol"));
    assert!(!crypto.contains("pub const SIGNATURE_ALGORITHM_ID"));
    assert!(provider.contains("pub trait SigningKeyHandle"));
    let agreement = fs::read_to_string(workspace.join("crates/ucr-crypto/src/agreement.rs"))
        .expect("agreement implementation");
    assert!(agreement.contains("pub fn agree(self, peer: AgreementPublicKey)"));
    assert!(!provider.contains("private_key"));

    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let negotiation =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/crypto_negotiation.rs"))
            .expect("crypto negotiation");
    assert!(!model.contains("PartialOrd, Ord, Hash)]\n#[repr(u32)]\npub enum CryptoSuite"));
    assert!(negotiation.contains("pub preferred_suites: Vec<CryptoSuite>"));
    assert!(!negotiation.contains(".max()"));
    assert!(!negotiation.contains("minimum: CryptoSuite"));
}

#[test]
fn crypto_foundation_keeps_handshake_replay_and_nonclaims_explicit() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/crypto.md")).expect("crypto spec");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/replay.rs"))
        .expect("replay store");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/crypto.proto")).expect("crypto proto");

    for invariant in [
        "insecure fallback is forbidden",
        "A session is `Pending`",
        "Traffic APIs are exposed only after",
        "Replay security does not depend on wall-clock expiry",
        "Private key bytes are never part of the public UCR protocol",
        "still do not claim complete credential re-issuance",
    ] {
        assert!(
            spec.contains(invariant),
            "crypto invariant missing: {invariant}"
        );
    }
    for evidence in [
        "replay_record_survives_restart",
        "concurrent_replay_record_has_single_winner",
        "v2_store_migrates_to_v3_without_losing_accepted_commands",
    ] {
        assert!(
            sqlite.contains(evidence),
            "replay evidence missing: {evidence}"
        );
    }
    assert!(proto.contains("message HandshakeKeyExchange"));
    assert!(proto.contains("bytes ephemeral_key = 1;"));
    let runtime =
        fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto")).expect("runtime proto");
    assert!(runtime.contains("bytes transcript_binding = 4 [deprecated = true];"));
    assert!(spec.contains("MUST be empty"));
    let session = fs::read_to_string(workspace.join("crates/ucr-crypto/src/session.rs"))
        .expect("crypto session");
    assert!(session.contains("pub suite: CryptoSuite"));
    assert!(session.contains("PeerAgreementKeyMismatch"));
}

#[test]
fn recovery_contract_keeps_explicit_authority_and_reverification_invariants() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/recovery.md")).expect("recovery spec");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/recovery.proto")).expect("recovery proto");

    for invariant in [
        "A method label alone does not authorize recovery",
        "at most **64** authorities",
        "used as the HKDF salt and as AEAD associated data",
        "only accepted recovered-device state is `REVERIFICATION_REQUIRED`",
        "Historical access defaults to `NONE`",
        "organization recovery authority is valid only with the explicit organization-managed trust model",
        "Recovery secret bytes are intentionally absent from protobuf",
        "SYNC != BACKUP",
    ] {
        assert!(
            spec.contains(invariant),
            "recovery invariant missing: {invariant}"
        );
    }
    assert!(proto.contains("message RecoveryAuthority"));
    assert!(proto.contains("RecoveryTrustModel trust_model = 7;"));
    assert!(proto.contains("message EncryptedRecoveryPackage"));
    assert!(!proto.contains("recovery_secret"));
    assert!(!proto.contains("private_key"));
}

#[test]
fn recovery_storage_keeps_restart_rotation_and_migration_evidence() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/recovery_plan.rs"))
            .expect("recovery sqlite store");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");

    for evidence in [
        "recovery_plan_survives_restart_and_is_canonicalized",
        "recovery_revoke_survives_restart",
        "concurrent_recovery_rotation_has_single_winner",
        "v3_store_migrates_through_v4_to_current_without_losing_existing_schema",
    ] {
        assert!(
            sqlite.contains(evidence),
            "recovery evidence missing: {evidence}"
        );
    }
    assert!(core.contains("pub trait RecoveryPlanStore"));
    assert!(!sqlite.contains("recovery_secret"));
}

#[test]
fn conversation_message_contract_keeps_canon_and_wire_compatibility() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/conversation-message.md"))
        .expect("conversation message spec");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/communication.proto"))
        .expect("communication proto");

    for invariant in [
        "A Conversation is a canonical UCR entity and outlives any provider",
        "A `TOPIC` requires one existing parent root Conversation",
        "A `THREAD` requires one existing `TOPIC` parent",
        "Relation order, external-mapping order, and protocol-extension order are not semantic",
        "reuse of one scoped Message ID with different semantics is a conflict",
    ] {
        assert!(
            spec.contains(invariant),
            "message invariant missing: {invariant}"
        );
    }
    for field in [
        "OpaqueId message_id = 1;",
        "TenantScope scope = 2;",
        "ConversationRef conversation = 3;",
        "ActorRef author = 4;",
        "optional DeviceRef author_device = 5;",
        "uint64 logical_order = 6;",
        "bytes content = 7;",
        "DeliveryPolicy delivery_policy = 8;",
        "Correlation correlation = 9;",
        "repeated Extension extensions = 10;",
        "OriginRef origin = 11;",
        "int64 created_at_unix_ms = 12;",
        "optional OpaqueId reply_to = 19;",
    ] {
        assert!(
            proto.contains(field),
            "wire field changed or missing: {field}"
        );
    }
    assert!(proto.contains("message ConversationRecord"));
    assert!(proto.contains("message MessageRelation"));
}

#[test]
fn message_storage_keeps_restart_migration_and_security_nonclaims() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/message_store.rs"))
            .expect("message sqlite store");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let spec = fs::read_to_string(workspace.join("spec/conversation-message.md"))
        .expect("conversation message spec");

    for evidence in [
        "message_round_trip_survives_restart_with_all_canonical_fields",
        "concurrent_conflicting_messages_have_single_winner",
        "v4_store_migrates_to_v5_without_losing_existing_durable_state",
        "conversation_hierarchy_requires_existing_parent_with_valid_kind",
    ] {
        assert!(
            sqlite.contains(evidence),
            "message evidence missing: {evidence}"
        );
    }
    assert!(core.contains("pub trait ConversationStore"));
    assert!(core.contains("pub trait MessageStore"));
    for nonclaim in [
        "The Phase-9 boundary intentionally stops at `PERSISTED`",
        "Merely storing signature metadata is not authenticity proof.",
        "does not claim message-content encryption at rest",
    ] {
        assert!(
            spec.contains(nonclaim),
            "message nonclaim missing: {nonclaim}"
        );
    }
    assert!(!sqlite.contains("telegram_message"));
    assert!(!sqlite.contains("vk_message"));
    assert!(!sqlite.contains("max_message"));
}

#[test]
fn message_intent_and_error_wire_parity_survives_v10_storage() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let message_protocol =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/message.rs")).expect("message");
    let intent_protocol =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/intent.rs")).expect("intent");
    let error_protocol =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/error.rs")).expect("error");
    let sqlite_root =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    let sqlite_message =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/message_store.rs"))
            .expect("message sqlite");
    let communication =
        fs::read_to_string(workspace.join("proto/ucr/v1/communication.proto")).expect("proto");
    let errors = fs::read_to_string(workspace.join("proto/ucr/v1/errors.proto")).expect("errors");
    let message_spec =
        fs::read_to_string(workspace.join("spec/conversation-message.md")).expect("message spec");
    let error_spec = fs::read_to_string(workspace.join("spec/errors.md")).expect("error spec");

    let message_model = model
        .split("pub struct MessageEnvelope")
        .nth(1)
        .and_then(|tail| tail.split("pub struct IntentConstraints").next())
        .expect("MessageEnvelope block");
    assert!(message_model.contains("pub author_device: DeviceRef"));
    assert!(!message_model.contains("pub author_device: Option<DeviceRef>"));
    assert!(message_model.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(message_protocol.contains("canonical_protocol_extensions(&message.extensions)"));

    let intent_constraints = model
        .split("pub struct IntentConstraints")
        .nth(1)
        .and_then(|tail| tail.split("pub struct CommunicationIntent").next())
        .expect("IntentConstraints block");
    assert!(intent_constraints.contains("pub privacy_profile: Option<String>"));
    assert!(intent_constraints.contains("pub priority_class: Option<u32>"));
    let intent_model = model
        .split("pub struct CommunicationIntent")
        .nth(1)
        .and_then(|tail| tail.split("#[cfg(test)]").next())
        .expect("CommunicationIntent block");
    assert!(intent_model.contains("pub correlation: CorrelationContext"));
    assert!(intent_model.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(intent_protocol.contains("pub fn canonical_communication_intent"));
    assert!(intent_protocol.contains("ConflictingTransportCapability"));

    assert!(communication.contains("optional string privacy_profile = 3;"));
    assert!(communication.contains("optional uint32 priority_class = 6;"));
    assert!(communication.contains("Correlation correlation = 6;"));
    assert!(communication.contains("repeated Extension extensions = 7;"));
    assert!(communication.contains("optional DeviceRef author_device = 5;"));
    assert!(communication.contains("repeated Extension extensions = 10;"));
    assert!(message_spec.contains("Canonical Message semantic decoding requires an author Device"));

    assert!(errors.contains("message ErrorEnvelope"));
    assert!(errors.contains("repeated Extension extensions = 5;"));
    assert!(error_protocol.contains("pub struct ErrorEnvelope"));
    assert!(error_protocol.contains("pub code: i32"));
    assert!(error_protocol.contains("pub extensions: Vec<ProtocolExtension>"));
    assert!(error_protocol.contains("pub fn canonical_error_envelope"));
    assert!(error_spec.contains("Unknown future non-zero numeric codes remain failures"));

    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V10: u32 = 10;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V11: u32 = 11;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V12: u32 = 12;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V13: u32 = 13;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v9_to_v10"));
    assert!(sqlite_root.contains("fn migrate_v10_to_v11"));
    assert!(sqlite_root.contains("fn migrate_v11_to_v12"));
    assert!(sqlite_root.contains("fn migrate_v12_to_v13"));
    assert!(sqlite_root.contains("fn migrate_v13_to_v14"));
    assert!(sqlite_message.contains("CREATE TABLE message_extensions"));
    let sqlite_command =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/command_store.rs"))
            .expect("command sqlite");
    let sqlite_event =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/event_journal.rs"))
            .expect("event sqlite");
    for loader in [&sqlite_command, &sqlite_event, &sqlite_message] {
        assert!(loader.contains("expected_position >= MAX_PROTOCOL_EXTENSIONS"));
    }
    for evidence in [
        "message_extensions_survive_restart_and_are_part_of_conflict_semantics",
        "v9_to_v10_migration_preserves_existing_messages_as_empty_extensions",
        "corrupt_message_extension_rows_are_rejected_on_reopen",
        "oversized_persisted_message_extension_set_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite_message.contains(evidence),
            "missing v10 evidence: {evidence}"
        );
    }
    assert!(
        sqlite_root.contains("oversized_persisted_command_extension_set_is_rejected_on_reopen")
    );
    assert!(sqlite_root.contains("oversized_persisted_event_extension_set_is_rejected_on_reopen"));
}

#[test]
fn delivery_contract_keeps_evidence_semantics_and_wire_shape() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/delivery.md")).expect("delivery spec");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/communication.proto"))
        .expect("communication proto");

    for invariant in [
        "A canonical Message outlives any route",
        "Retry and multi-path delivery create a new `DeliveryId`",
        "`REPLICATED_TO_RELAY` never proves `DELIVERED`",
        "`READ` requires `READ_BY_USER` evidence",
        "The Message row is not a second mutable delivery state machine",
    ] {
        assert!(
            spec.contains(invariant),
            "delivery invariant missing: {invariant}"
        );
    }
    assert!(proto.contains("enum DeliveryEvidenceKind"));
    assert!(proto.contains("message DeliveryAttempt"));
    assert!(proto.contains("message DeliveryEvidence"));
    assert!(proto.contains("DELIVERY_EVIDENCE_KIND_REPLICATED_TO_RELAY = 4;"));
    assert!(proto.contains("uint64 logical_order = 5;"));
}

#[test]
fn delivery_storage_keeps_restart_migration_and_nonclaims() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/delivery_store.rs"))
            .expect("delivery sqlite store");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let spec = fs::read_to_string(workspace.join("spec/delivery.md")).expect("delivery spec");

    for evidence in [
        "delivery_transition_chain_survives_restart_with_evidence",
        "concurrent_ack_transition_has_single_winner",
        "v5_store_migrates_to_v6_without_losing_message_state",
        "corrupt_delivery_evidence_binding_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite.contains(evidence),
            "delivery evidence missing: {evidence}"
        );
    }
    assert!(core.contains("pub trait DeliveryStore"));
    for nonclaim in [
        "does not claim network exactly-once delivery",
        "does not yet provide real transport adapters",
        "remote receipt authentication",
    ] {
        assert!(
            spec.contains(nonclaim),
            "delivery nonclaim missing: {nonclaim}"
        );
    }
    assert!(!sqlite.contains("telegram_delivery"));
    assert!(!sqlite.contains("vk_delivery"));
    assert!(!sqlite.contains("max_delivery"));
}

#[test]
fn sync_contract_keeps_scope_resume_and_phase_boundaries() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/sync.md")).expect("sync spec");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/sync.proto")).expect("sync proto");

    for invariant in [
        "SYNC != BACKUP",
        "A server, cloud, relay, provider, or external consumer is never the canonical source of truth",
        "`PAUSED` is durable state",
        "Bidirectional synchronization uses two independent sessions/checkpoint streams",
        "The resume token is opaque",
        "not proof that the remote peer possesses any particular Event or Message",
        "EventId is never a canonical ordering key",
        "Conversation-selected Partial Sync fails closed for Event-level reconciliation",
        "DAMAGED` is fail-closed",
    ] {
        assert!(
            spec.contains(invariant),
            "sync invariant missing: {invariant}"
        );
    }
    for declaration in [
        "enum SyncLinkKind",
        "enum SyncMode",
        "enum SyncState",
        "message SyncSession",
        "message SyncCheckpoint",
        "enum EventFingerprintAlgorithm",
        "message EventFingerprint",
        "message EventSummary",
        "message AntiEntropyCursor",
        "message AntiEntropyPage",
        "enum EventReplicaState",
        "message EventReconciliation",
    ] {
        assert!(
            proto.contains(declaration),
            "sync wire declaration missing: {declaration}"
        );
    }
}

#[test]
fn sync_storage_keeps_restart_migration_and_conflict_evidence() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/sync_store.rs"))
        .expect("sync sqlite store");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");

    for evidence in [
        "sync_session_checkpoint_pause_and_resume_survive_restart",
        "concurrent_sync_activation_has_single_winner",
        "concurrent_checkpoint_generation_has_single_winner",
        "checkpoint_generation_gap_is_rejected_on_reopen",
        "corrupt_partial_sync_selection_is_rejected_on_reopen",
        "v6_store_migrates_to_v7_without_losing_message_state",
    ] {
        assert!(
            sqlite.contains(evidence),
            "sync evidence missing: {evidence}"
        );
    }
    assert!(core.contains("pub trait SyncStore"));
    assert!(!sqlite.contains("telegram_sync"));
    assert!(!sqlite.contains("vk_sync"));
    assert!(!sqlite.contains("max_sync"));
}

#[test]
fn anti_entropy_keeps_fingerprint_snapshot_damage_and_storage_boundaries() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/anti_entropy.rs"))
        .expect("anti entropy protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/anti_entropy_store.rs"))
            .expect("sqlite anti entropy store");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let runtime_proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/runtime.proto")).expect("runtime proto");
    let sync_proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/sync.proto")).expect("sync proto");

    assert!(core.contains("pub trait AntiEntropyStore"));
    assert!(protocol.contains("EVENT_FINGERPRINT_SHA256_V1_DOMAIN"));
    assert!(protocol.contains("event_fingerprint_sha256_v1_matches_golden_vector"));
    assert!(runtime_proto.contains("repeated Extension extensions = 9;"));
    assert!(sync_proto.contains("EVENT_FINGERPRINT_ALGORITHM_SHA256_V1"));
    assert!(!core.contains("journal_seq"));
    assert!(!sync_proto.contains("journal_seq"));

    for evidence in [
        "snapshot_resume_does_not_lose_events_added_during_pass",
        "cursor_is_bound_to_exact_session_and_direction",
        "reconciliation_distinguishes_missing_matching_and_damaged_without_overwrite",
        "partial_event_reconciliation_and_extension_order_fail_or_deduplicate_canonically",
    ] {
        assert!(
            memory.contains(evidence),
            "memory evidence missing: {evidence}"
        );
    }
    for evidence in [
        "sqlite_snapshot_resume_excludes_mid_pass_event_until_next_pass",
        "sqlite_reconciliation_classifies_and_never_overwrites_damaged_event",
        "sqlite_cursor_binding_partial_fail_closed_and_extensions_round_trip",
        "v7_to_v8_migration_preserves_existing_events_as_empty_extensions",
    ] {
        assert!(
            sqlite.contains(evidence),
            "sqlite evidence missing: {evidence}"
        );
    }
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V8: u32 = 8;"));
    assert!(memory.contains("validate_anti_entropy_summary_count(summaries.len())"));
    assert!(sqlite.contains("validate_anti_entropy_summary_count(summaries.len())"));
}

#[test]
fn sensitive_model_debug_surfaces_redact_private_material_without_closing_telemetry_blocker() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let commands = fs::read_to_string(workspace.join("spec/commands-events.md"))
        .expect("commands/events spec");
    let message =
        fs::read_to_string(workspace.join("spec/conversation-message.md")).expect("message spec");
    let protocol = fs::read_to_string(workspace.join("spec/protocol.md")).expect("protocol spec");

    for owner in [
        "CorrelationContext",
        "EventEnvelope",
        "EventFingerprint",
        "ExternalMessageMapping",
        "MessageCryptoMetadata",
        "MessageSignature",
        "MessageEnvelope",
        "IntentConstraints",
        "CommunicationIntent",
    ] {
        assert!(
            model.contains(&format!("impl fmt::Debug for {owner}")),
            "sensitive Debug owner missing for {owner}"
        );
        assert!(
            !model.contains(&format!(
                "#[derive(Debug, Clone, PartialEq, Eq)]\npub struct {owner}"
            )),
            "derived Debug reintroduced for sensitive owner {owner}"
        );
    }

    for evidence in [
        "correlation_and_event_debug_do_not_disclose_sensitive_material",
        "message_nested_debug_does_not_disclose_sensitive_material",
        "message_envelope_debug_does_not_disclose_sensitive_material",
        "communication_intent_and_constraints_debug_redact_private_policy_and_payload",
    ] {
        assert!(
            model.contains(evidence),
            "redaction evidence missing: {evidence}"
        );
    }
    assert!(
        commands
            .contains("Ordinary Rust `Debug` output is not an authorized payload-inspection path")
    );
    assert!(message.contains("Ordinary Rust `Debug` output redacts Message plaintext"));
    assert!(protocol.contains("Ordinary Rust `Debug` output for a Communication Intent redacts"));
    assert!(threat.contains("- secret/plaintext telemetry regression tests."));
    assert!(threat.contains(
        "do **not** close the broader `secret/plaintext telemetry regression tests` blocker"
    ));
}

#[test]
fn opaque_id_bytes_have_one_explicit_utf8_semantic_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto =
        fs::read_to_string(workspace.join("proto/ucr/v1/common.proto")).expect("common proto");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let protocol = fs::read_to_string(workspace.join("spec/protocol.md")).expect("protocol spec");
    let sync = fs::read_to_string(workspace.join("spec/sync.md")).expect("sync spec");
    let anti_entropy =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/anti_entropy.rs"))
            .expect("anti entropy protocol");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite store");
    let local_storage =
        fs::read_to_string(workspace.join("spec/local-storage.md")).expect("local storage spec");

    assert!(proto.contains("message OpaqueId"));
    assert!(proto.contains("bytes value = 1;"));
    assert!(proto.contains("exact, non-empty UTF-8 token of at most 128 bytes"));
    assert!(model.contains("pub struct OpaqueId(String);"));
    assert!(model.contains("pub const MAX_LEN: usize = 128;"));
    assert!(model.contains("InvalidUtf8"));
    assert!(model.contains("pub fn from_wire_bytes(value: &[u8])"));
    assert!(model.contains("pub fn as_wire_bytes(&self) -> &[u8]"));
    assert!(model.contains("opaque_id_wire_bytes_have_explicit_utf8_and_byte_budget_semantics"));
    assert!(model.contains("opaque_id_does_not_normalize_distinct_utf8_tokens"));

    for invariant in [
        "an exact, non-empty UTF-8 token whose encoded length is at most 128 bytes",
        "MUST NOT normalize Unicode, case-fold, trim, transliterate, or otherwise rewrite an ID",
        "protobuf syntactic ability to carry arbitrary bytes is not by itself canonical validity",
    ] {
        assert!(
            protocol.contains(invariant),
            "OpaqueId invariant missing: {invariant}"
        );
    }
    assert!(sync.contains("canonical IDs as their exact `OpaqueId.value` semantic UTF-8 bytes"));
    assert!(anti_entropy.contains("value.as_wire_bytes()"));
    assert!(anti_entropy.contains("event_fingerprint_sha256_v1_matches_golden_vector"));
    assert!(sync.contains("The Phase-12 golden vector in the reference implementation hashes"));
    assert!(sqlite.contains("utf8_opaque_ids_survive_restart_without_normalization"));
    assert!(
        local_storage.contains("This OpaqueId clarification requires no SQLite schema migration.")
    );
}

#[test]
fn native_opaque_id_generation_is_offline_csprng_owned_and_non_authoritative() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let protocol_id = fs::read_to_string(workspace.join("crates/ucr-protocol/src/id.rs"))
        .expect("id generation protocol");
    let core_id = fs::read_to_string(workspace.join("crates/ucr-core/src/id.rs"))
        .expect("id generation runtime");
    let protocol = fs::read_to_string(workspace.join("spec/protocol.md")).expect("protocol spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let protocol_cargo = fs::read_to_string(workspace.join("crates/ucr-protocol/Cargo.toml"))
        .expect("protocol cargo manifest");
    let core_cargo = fs::read_to_string(workspace.join("crates/ucr-core/Cargo.toml"))
        .expect("core cargo manifest");

    assert!(protocol_id.contains("ucr.id.random_hex.v1"));
    assert!(protocol_id.contains("CANONICAL_ID_RANDOM_BYTES: usize = 16"));
    assert!(protocol_id.contains("generation_contract_has_stable_algorithm_and_golden_encoding"));
    assert!(protocol_id.contains("pub fn encode_native_opaque_id"));
    assert!(!protocol_id.contains("getrandom::"));
    assert!(!protocol_cargo.contains("getrandom"));

    assert!(core_id.contains("pub fn generate_opaque_id"));
    assert!(core_id.contains("getrandom::fill(bytes)"));
    assert!(core_id.contains("generator_fails_closed_when_os_randomness_is_unavailable"));
    assert!(core_id.contains("production_generator_emits_semantically_valid_lower_hex_tokens"));
    assert!(core_cargo.contains("getrandom = \"=0.4.3\""));

    for forbidden in [
        "std::time",
        "SystemTime",
        "Uuid",
        "Ulid",
        "rand::",
        "thread_rng",
    ] {
        assert!(
            !core_id.contains(forbidden),
            "native ID runtime must not depend on alternate/time-based source: {forbidden}"
        );
    }
    for invariant in [
        "exactly 16 bytes (128 bits) from the operating-system CSPRNG",
        "no clock, host, provider, server, database-sequence, or business-data input",
        "not a credential, authority proof, chronology value, or a narrower validation rule",
        "`ucr-protocol::encode_native_opaque_id` is the single deterministic algorithm/encoding owner",
        "`ucr-core::generate_opaque_id` is the Rust runtime owner",
    ] {
        assert!(
            protocol.contains(invariant),
            "native ID generation invariant missing: {invariant}"
        );
    }
    assert!(threat.contains("`ucr.id.random_hex.v1` uses 128 bits from the OS CSPRNG"));
}

#[test]
fn message_signature_verification_binds_authored_semantics_without_claiming_key_trust() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let binding =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/message_signature.rs"))
            .expect("message signing binding");
    let signing = fs::read_to_string(workspace.join("crates/ucr-crypto/src/signing.rs"))
        .expect("crypto signing");
    let verifier = fs::read_to_string(workspace.join("crates/ucr-crypto/src/message_signature.rs"))
        .expect("message signature verifier");
    let key_provider = fs::read_to_string(workspace.join("crates/ucr-crypto/src/key_provider.rs"))
        .expect("key provider");
    let spec =
        fs::read_to_string(workspace.join("spec/conversation-message.md")).expect("message spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");

    assert!(binding.contains("UCR-MESSAGE-SIGNING-BINDING-V1\\0"));
    assert!(binding.contains("signing_binding_has_stable_golden_vector"));
    assert!(binding.contains("authored_fields_change_binding_but_runtime_provider_fields_do_not"));
    assert!(!binding.contains("canonical.delivery_state"));
    assert!(!binding.contains("canonical.external_mappings"));
    assert!(signing.contains("UCR-MESSAGE-SIGNATURE-V1\\0"));
    assert!(signing.contains("sign_message_binding"));
    assert!(signing.contains("verify_message_binding_signature"));
    assert!(key_provider.contains("fn sign_message_binding"));
    assert!(verifier.contains("verify_message_signature"));
    assert!(verifier.contains("KeyIdMismatch"));
    assert!(verifier.contains("AuthorDeviceMismatch"));
    assert!(verifier.contains("InvalidTrustedKeyDescriptor"));
    assert!(verifier.contains("authored_tampering_and_wrong_crypto_key_fail_closed"));
    assert!(spec.contains("d71367107172322ca408610f8a1de9b00fff44383f33ee56e4316fd5043d09d2"));
    assert!(spec.contains("`delivery_state`, `external_mappings`, and `signature` are excluded"));
    assert!(spec.contains("`key_id` inside a Message never establishes trust by itself"));
    assert!(!threat.contains("- trusted peer signing-key provisioning and lifecycle integration;"));
    assert!(
        !threat.contains(
            "- cryptographic Message-signature verification over canonical signing bytes;"
        )
    );
}

#[test]
fn trusted_signing_key_lifecycle_is_scoped_restart_safe_and_runtime_integrated() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let resolver = fs::read_to_string(workspace.join("crates/ucr-crypto/src/trusted_key.rs"))
        .expect("trusted key resolver");
    let message = fs::read_to_string(workspace.join("crates/ucr-crypto/src/message_signature.rs"))
        .expect("message trust integration");
    let session = fs::read_to_string(workspace.join("crates/ucr-crypto/src/session.rs"))
        .expect("session trust integration");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/trusted_key_store.rs"))
            .expect("sqlite trust store");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory trust store");
    let crypto_spec = fs::read_to_string(workspace.join("spec/crypto.md")).expect("crypto spec");
    let storage_spec =
        fs::read_to_string(workspace.join("spec/local-storage.md")).expect("storage spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");

    for invariant in [
        "pub enum TrustedSigningKeyState",
        "pub struct TrustedSigningKeyRecord",
    ] {
        assert!(
            model.contains(invariant),
            "model trust invariant missing: {invariant}"
        );
    }
    assert!(core.contains("pub trait TrustedSigningKeyStore"));
    assert!(core.contains("rotate_trusted_signing_key"));
    assert!(core.contains("revoke_trusted_signing_key"));
    assert!(resolver.contains("pub trait TrustedSigningKeyResolver"));
    assert!(resolver.contains("NotTrusted"));
    assert!(message.contains("verify_message_signature_with_trust"));
    assert!(session.contains("begin_session_with_trusted_peer"));
    assert!(session.contains("if trusted != *claim"));

    for evidence in [
        "trusted_key_rotation_revocation_and_resolver_survive_restart",
        "concurrent_trusted_key_rotation_has_single_winner",
        "v10_to_v11_migration_preserves_existing_security_state_and_starts_empty_trust",
        "corrupt_trusted_key_row_is_rejected_on_reopen",
        "missing_active_key_unique_index_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite.contains(evidence),
            "sqlite trust evidence missing: {evidence}"
        );
    }
    assert!(sqlite.contains("trusted_signing_keys_one_active_per_device"));
    assert!(sqlite.contains("WHERE state = 'active'"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V10: u32 = 10"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V11: u32 = 11"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V12: u32 = 12"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V13: u32 = 13"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V14: u32 = 14"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18"));
    assert!(sqlite_root.contains("fn migrate_v10_to_v11"));
    assert!(sqlite_root.contains("fn migrate_v11_to_v12"));
    assert!(sqlite_root.contains("fn migrate_v12_to_v13"));
    assert!(sqlite_root.contains("fn migrate_v13_to_v14"));
    assert!(sqlite_root.contains("fn migrate_v14_to_v15"));

    for evidence in [
        "trusted_signing_key_lifecycle_is_atomic_idempotent_and_irreversible",
        "active_trust_controls_message_verification_and_revocation_denies_same_signature",
        "active_trust_controls_handshake_and_peer_claim_cannot_self_provision",
    ] {
        assert!(
            memory.contains(evidence),
            "memory trust evidence missing: {evidence}"
        );
    }
    assert!(crypto_spec.contains("peer or referenced by a Message remains a claim"));
    assert!(storage_spec.contains("Schema v11 migrates v10 transactionally"));
    assert!(!threat.contains("- trusted peer signing-key provisioning and lifecycle integration;"));
    for remaining in [
        "production OS/hardware-backed key providers for supported targets",
        "device-bound credential/content delivery enforcement beyond implemented trusted-key/authentication paths",
    ] {
        assert!(
            threat.contains(remaining),
            "neighboring blocker disappeared: {remaining}"
        );
    }
}

#[test]
fn implemented_untrusted_boundaries_have_bounded_required_fuzzing() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");
    let smoke = fs::read_to_string(workspace.join("fuzz/run-smoke.sh")).expect("fuzz smoke");
    let manifest = fs::read_to_string(workspace.join("fuzz/Cargo.toml")).expect("fuzz manifest");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");

    assert!(manifest.contains("[workspace]"));
    assert!(manifest.contains("libfuzzer-sys = \"=0.4.13\""));
    assert!(workspace.join("fuzz/Cargo.lock").is_file());

    for target in [
        "framing_parser",
        "opaque_id_wire",
        "message_envelope",
        "crypto_wrapper",
    ] {
        assert!(
            workspace
                .join(format!("fuzz/fuzz_targets/{target}.rs"))
                .is_file()
        );
        assert!(workspace.join(format!("fuzz/corpus/{target}")).is_dir());
        assert!(smoke.contains(&format!("run_target {target} ")));
    }

    for budget in [
        "-max_total_time=",
        "-timeout=",
        "-rss_limit_mb=",
        "-max_len=",
        "mktemp -d",
    ] {
        assert!(smoke.contains(budget), "fuzz budget missing: {budget}");
    }

    assert!(ci.contains("fuzz-smoke:"));
    assert!(ci.contains("nightly-2026-09-02"));
    assert!(ci.contains("cargo install cargo-fuzz --version 0.13.2 --locked"));
    assert!(ci.contains("./fuzz/run-smoke.sh"));
    assert!(ci.contains("cargo fmt --manifest-path fuzz/Cargo.toml -- --check"));
    assert!(ci.contains("cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked"));
    assert!(ci.contains(
        "cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings"
    ));
    assert!(ci.contains("cargo audit --file fuzz/Cargo.lock --deny warnings"));
    assert!(ci.contains("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"));

    let framing = fs::read_to_string(workspace.join("fuzz/fuzz_targets/framing_parser.rs"))
        .expect("framing fuzz target");
    let opaque = fs::read_to_string(workspace.join("fuzz/fuzz_targets/opaque_id_wire.rs"))
        .expect("opaque id fuzz target");
    let message = fs::read_to_string(workspace.join("fuzz/fuzz_targets/message_envelope.rs"))
        .expect("message fuzz target");
    let crypto = fs::read_to_string(workspace.join("fuzz/fuzz_targets/crypto_wrapper.rs"))
        .expect("crypto fuzz target");

    assert!(framing.contains("decode_frame_prefix"));
    assert!(framing.contains("payload.len()"));
    assert!(opaque.contains("OpaqueId::from_wire_bytes"));
    assert!(opaque.contains("assert_eq!(id.as_wire_bytes(), data)"));
    assert!(message.contains("canonical_message"));
    assert!(message.contains("message_signing_binding"));
    assert!(crypto.contains("verify_message_binding_signature"));
    assert!(crypto.contains("verify_transcript_signature"));
    assert!(crypto.contains("open_recovery_material"));

    assert!(
        threat.contains(
            "Current implemented untrusted boundaries have executable bounded fuzz targets"
        )
    );
    assert!(threat.contains("each requires a real fuzz target when its implementation appears"));
    assert!(
        !threat.contains("- required fuzz targets for implemented parsers/wrappers;"),
        "fuzz blocker must only be removed with the positive executable evidence above"
    );
}

#[test]
fn permission_grants_are_durable_and_enforce_trusted_key_mutations_without_overclaiming() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
        .expect("authorization protocol");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/permission_store.rs"))
            .expect("permission sqlite store");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let spec = fs::read_to_string(workspace.join("spec/permissions.md")).expect("permissions spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(
        workspace.join("docs/adr/0027-permission-grants-are-durable-and-runtime-enforced.md"),
    )
    .expect("adr 0027");

    assert!(core.contains("pub trait PermissionGrantStore"));
    assert!(core.contains("pub struct AuthorizedTrustedSigningKeyMutations"));
    assert!(runtime.contains("TRUSTED_SIGNING_KEY_PROVISION_PERMISSION"));
    assert!(runtime.contains("TRUSTED_SIGNING_KEY_ROTATE_PERMISSION"));
    assert!(runtime.contains("TRUSTED_SIGNING_KEY_REVOKE_PERMISSION"));
    assert!(protocol.contains("ucr.crypto.trusted_signing_key.provision"));
    assert!(protocol.contains("ucr.crypto.trusted_signing_key.rotate"));
    assert!(protocol.contains("ucr.crypto.trusted_signing_key.revoke"));
    assert!(memory.contains("impl PermissionGrantStore for MemoryLocalStore"));
    assert!(memory.contains("impl AuthorizationEvaluator for MemoryLocalStore"));
    assert!(memory.contains(
        "persisted_permission_is_deny_by_default_revocable_and_storage_is_not_reached_on_denial"
    ));
    assert!(sqlite.contains("CREATE TABLE permission_grants"));
    assert!(sqlite.contains("impl PermissionGrantStore for SqliteLocalStore"));
    assert!(sqlite.contains("impl AuthorizationEvaluator for SqliteLocalStore"));
    assert!(sqlite.contains("malformed_persisted_permission_is_rejected_on_reopen"));
    assert!(sqlite.contains("authorized_trusted_key_mutation_uses_persisted_grant_after_restart"));
    assert!(
        sqlite
            .contains("v11_to_v12_migration_preserves_trusted_key_state_and_starts_without_grants")
    );
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V12: u32 = 12;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V13: u32 = 13;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V14: u32 = 14;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v11_to_v12"));
    assert!(sqlite_root.contains("fn migrate_v12_to_v13"));
    assert!(sqlite_root.contains("fn migrate_v13_to_v14"));
    assert!(sqlite_root.contains("fn migrate_v14_to_v15"));
    assert!(spec.contains("SQLite schema v12"));
    assert!(adr.contains("does not claim every Command/Message/Sync/Delivery/runtime operation"));
    assert!(threat.contains("SQLite v12 state"));
}

const AUTHORIZED_DURABLE_METHODS: &[&str] = &[
    "provision_service_credential",
    "revoke_service_credential",
    "service_quota_policy",
    "set_service_quota_policy",
    "service_audit_records",
    "service_audit_records_for_operation",
    "register_device",
    "revoke_device",
    "device",
    "link_external_identity",
    "external_identity_binding",
    "grant_permission",
    "revoke_permission",
    "permission_grants_for",
    "provision_trusted_signing_key",
    "rotate_trusted_signing_key",
    "revoke_trusted_signing_key",
    "trusted_signing_key",
    "active_trusted_signing_key",
    "install_recovery_plan",
    "rotate_recovery_plan",
    "revoke_recovery_plan",
    "active_recovery_plan",
    "accept_command",
    "persist_conversation",
    "conversation",
    "persist_message",
    "message",
    "persist_communication_intent",
    "communication_intent",
    "create_delivery_attempt",
    "transition_delivery",
    "record_delivery_evidence",
    "delivery_attempt",
    "create_sync_session",
    "transition_sync",
    "record_sync_checkpoint",
    "sync_session",
    "latest_sync_checkpoint",
    "append_event",
    "anti_entropy_summary_page",
    "classify_event_summaries",
    "reconcile_event",
    "record_terminal_event",
    "terminal_event",
];

const AUTHORIZED_RUNTIME_PERMISSIONS: &[&str] = &[
    "SERVICE_CREDENTIAL_PROVISION_PERMISSION",
    "SERVICE_CREDENTIAL_REVOKE_PERMISSION",
    "SERVICE_QUOTA_READ_PERMISSION",
    "SERVICE_QUOTA_WRITE_PERMISSION",
    "SERVICE_AUDIT_READ_PERMISSION",
    "DEVICE_READ_PERMISSION",
    "DEVICE_REGISTER_PERMISSION",
    "DEVICE_REVOKE_PERMISSION",
    "EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION",
    "EXTERNAL_IDENTITY_BINDING_READ_PERMISSION",
    "PERMISSION_GRANT_READ_PERMISSION",
    "PERMISSION_GRANT_CREATE_PERMISSION",
    "PERMISSION_GRANT_REVOKE_PERMISSION",
    "TRUSTED_SIGNING_KEY_READ_PERMISSION",
    "TRUSTED_SIGNING_KEY_PROVISION_PERMISSION",
    "TRUSTED_SIGNING_KEY_ROTATE_PERMISSION",
    "TRUSTED_SIGNING_KEY_REVOKE_PERMISSION",
    "RECOVERY_PLAN_READ_PERMISSION",
    "RECOVERY_PLAN_INSTALL_PERMISSION",
    "RECOVERY_PLAN_ROTATE_PERMISSION",
    "RECOVERY_PLAN_REVOKE_PERMISSION",
    "COMMAND_ACCEPT_PERMISSION",
    "COMMAND_OUTCOME_READ_PERMISSION",
    "COMMAND_OUTCOME_WRITE_PERMISSION",
    "CONVERSATION_READ_PERMISSION",
    "CONVERSATION_WRITE_PERMISSION",
    "MESSAGE_READ_PERMISSION",
    "MESSAGE_WRITE_PERMISSION",
    "COMMUNICATION_INTENT_READ_PERMISSION",
    "COMMUNICATION_INTENT_WRITE_PERMISSION",
    "DELIVERY_READ_PERMISSION",
    "DELIVERY_WRITE_PERMISSION",
    "SYNC_READ_PERMISSION",
    "SYNC_WRITE_PERMISSION",
    "ANTI_ENTROPY_READ_PERMISSION",
    "ANTI_ENTROPY_RECONCILE_PERMISSION",
    "EVENT_APPEND_PERMISSION",
];

#[test]
fn tenant_scoped_durable_runtime_authorization_covers_every_current_method() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
        .expect("authorization protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let spec = fs::read_to_string(workspace.join("spec/permissions.md")).expect("permissions spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0028-tenant-scoped-durable-runtime-operations-require-explicit-permissions.md",
    ))
    .expect("adr 0028");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    for method in AUTHORIZED_DURABLE_METHODS {
        assert!(
            runtime.contains(&format!("pub fn {method}(")),
            "authorized runtime method missing: {method}"
        );
    }
    assert_eq!(
        runtime.matches("pub fn ").count(),
        AUTHORIZED_DURABLE_METHODS.len()
    );
    assert_eq!(
        runtime.matches("self.require(").count(),
        AUTHORIZED_DURABLE_METHODS.len()
    );

    for permission in AUTHORIZED_RUNTIME_PERMISSIONS {
        assert!(
            protocol.contains(permission),
            "permission owner missing: {permission}"
        );
        assert!(
            runtime.contains(permission),
            "runtime permission mapping missing: {permission}"
        );
    }
    assert!(protocol.contains("pub const RUNTIME_PERMISSION_IDS"));
    assert!(protocol.contains("runtime_permission_vocabulary_is_namespaced_and_unique"));
    assert!(
        memory
            .contains("runtime_permission_administration_cannot_self_bootstrap_and_is_scope_bound")
    );
    assert!(
        memory
            .contains("unified_runtime_enforces_independent_conversation_and_message_permissions")
    );
    assert!(core.contains("AuthorizedDurableRuntime::new(self.authorization, self.store)"));
    assert!(spec.contains(
        "every currently implemented **permission-authorized** tenant-scoped durable capability"
    ));
    assert!(adr.contains("mirrors all 32 methods"));
    assert!(adr.contains("cannot grant itself grant-management authority"));
    assert!(ci.contains(
        "docs/adr/0028-tenant-scoped-durable-runtime-operations-require-explicit-permissions.md"
    ));
    assert!(
        !threat.contains("- tenant-scoped authorization enforcement;"),
        "authorization blocker may be removed only with complete runtime evidence"
    );
    assert!(!threat.contains("- Service Principal authentication/least-privilege enforcement;"));
    assert!(!threat.contains("- Service Principal quota and audit enforcement;"));
}

#[test]
fn device_lifecycle_is_durable_and_gates_protected_key_access() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let protocol =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/device_lifecycle.rs"))
            .expect("device protocol");
    let authorization =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
            .expect("authorization protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let sqlite_device =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/device_store.rs"))
            .expect("sqlite device store");
    let sqlite_keys =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/trusted_key_store.rs"))
            .expect("sqlite key store");
    let memory_keys = &memory;
    let resolver = fs::read_to_string(workspace.join("crates/ucr-crypto/src/trusted_key.rs"))
        .expect("trusted key resolver");
    let message_signature =
        fs::read_to_string(workspace.join("crates/ucr-crypto/src/message_signature.rs"))
            .expect("message signature");
    let spec =
        fs::read_to_string(workspace.join("spec/principal-actor-device.md")).expect("device spec");
    let storage_spec =
        fs::read_to_string(workspace.join("spec/local-storage.md")).expect("storage spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(
        workspace
            .join("docs/adr/0032-device-lifecycle-is-durable-and-gates-protected-key-access.md"),
    )
    .expect("adr 0032");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(core.contains("pub trait DeviceLifecycleStore: StorageProvider"));
    for method in ["register_device", "revoke_device", "device"] {
        assert!(runtime.contains(&format!("pub fn {method}(")));
    }
    for permission in [
        "DEVICE_READ_PERMISSION",
        "DEVICE_REGISTER_PERMISSION",
        "DEVICE_REVOKE_PERMISSION",
    ] {
        assert!(authorization.contains(permission));
        assert!(runtime.contains(permission));
    }
    assert!(protocol.contains("only `Active`"));
    assert!(protocol.contains("DeviceLifecycleState::Active"));
    assert!(resolver.contains("identity_id: Option<&IdentityId>"));
    assert!(message_signature.contains("Some(&message.author_device.identity_id)"));
    assert!(sqlite_keys.contains("protected_device_allows"));
    assert!(memory_keys.contains("device_allows_protected_access"));

    for evidence in [
        "device_revocation_atomically_revokes_key_and_cannot_be_reactivated",
        "protected_key_access_requires_active_device_and_exact_identity_binding",
        "device_lifecycle_administration_uses_independent_permissions_and_cannot_reactivate",
    ] {
        assert!(
            memory.contains(evidence),
            "memory Device evidence missing: {evidence}"
        );
    }
    for evidence in [
        "device_revocation_and_key_invalidation_survive_restart",
        "concurrent_device_revoke_and_key_rotation_never_leave_active_key",
        "v14_to_v15_migration_preserves_key_but_does_not_invent_device_identity",
        "registering_non_active_device_after_v14_migration_revokes_residual_key",
        "non_active_device_with_active_key_is_rejected_on_reopen",
        "corrupt_device_state_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite_device.contains(evidence),
            "sqlite Device evidence missing: {evidence}"
        );
    }
    assert!(sqlite_device.contains("CREATE TABLE devices"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V14: u32 = 14;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v14_to_v15"));
    assert!(storage_spec.contains("migration does not invent an Identity binding"));
    assert!(spec.contains("one exact-scope durable `DeviceLifecycleStore`"));
    assert!(adr.contains("creates no Device rows"));
    assert!(adr.contains("does not claim a device-bound credential/content-delivery API"));
    assert!(
        ci.contains("docs/adr/0032-device-lifecycle-is-durable-and-gates-protected-key-access.md")
    );
    assert!(!threat.contains("- device revocation enforcement in credential/key delivery;"));
    assert!(threat.contains(
        "- device-bound credential/content delivery enforcement beyond implemented trusted-key/authentication paths;"
    ));
    assert!(threat.contains("- end-to-end recovery workflow:"));
}

#[test]
fn recovery_execution_requires_verified_authority_and_atomic_device_staging() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let workflow = fs::read_to_string(workspace.join("crates/ucr-core/src/recovery_workflow.rs"))
        .expect("recovery workflow");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite_recovery =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/recovery_plan.rs"))
            .expect("sqlite recovery");
    let sqlite_device =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/device_store.rs"))
            .expect("sqlite device");
    let spec = fs::read_to_string(workspace.join("spec/recovery.md")).expect("recovery spec");
    let permissions =
        fs::read_to_string(workspace.join("spec/permissions.md")).expect("permissions spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0033-recovery-device-staging-requires-verified-authority-and-active-plan.md",
    ))
    .expect("adr 0033");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(workflow.contains("pub trait RecoveryAuthorityVerifier"));
    assert!(workflow.contains("pub struct RecoveryAdmissionProof"));
    assert!(workflow.contains("plan_id: RecoveryPlanId"));
    assert!(!workflow.contains("pub plan_id: RecoveryPlanId"));
    assert!(workflow.contains("pub trait RecoveryDeviceStagingStore"));
    assert!(workflow.contains("proof: &RecoveryAdmissionProof"));
    let validate = workflow
        .find("validate_recovery_request(&plan, request)")
        .expect("validation");
    let verify = workflow
        .find(".verify_authority(&plan, request)")
        .expect("authority verifier");
    assert!(
        validate < verify,
        "authority verifier must run after canonical request binding"
    );
    assert!(workflow.contains("RecoveryError::PlanMismatch"));
    assert!(workflow.contains("CanonicalErrorCode::PermissionDenied"));

    for evidence in [
        "recovery_staging_requires_verified_authority_and_never_auto_trusts_device",
        "recovery_proof_is_invalidated_by_plan_revoke_and_cannot_overwrite_existing_device",
    ] {
        assert!(
            memory.contains(evidence),
            "memory recovery evidence missing: {evidence}"
        );
    }
    for evidence in [
        "verified_recovery_device_staging_survives_restart_and_stays_reverification_required",
        "revoked_plan_invalidates_previously_issued_recovery_proof",
        "concurrent_plan_revoke_and_device_stage_never_stage_after_revocation",
        "missing_or_mismatched_recovery_plan_is_non_disclosing",
    ] {
        assert!(
            sqlite_recovery.contains(evidence),
            "sqlite recovery evidence missing: {evidence}"
        );
    }
    assert!(sqlite_recovery.contains("TransactionBehavior::Immediate"));
    assert!(sqlite_recovery.contains("active_plan_id(&transaction, &identity)?"));
    assert!(sqlite_recovery.contains("revoke_active_device_key"));
    assert!(sqlite_device.contains("WHERE d.state<>'active' AND k.state='active'"));
    assert!(spec.contains("validate_recovery_request` proves only"));
    assert!(spec.contains("atomically re-check that the same plan is still active"));
    assert!(
        permissions
            .contains("Recovery execution is deliberately not another PermissionGrant operation")
    );
    assert!(adr.contains("rejected because revoke/rotation creates a TOCTOU race"));
    assert!(ci.contains(
        "docs/adr/0033-recovery-device-staging-requires-verified-authority-and-active-plan.md"
    ));
    assert!(threat.contains(
        "- end-to-end recovery workflow: concrete authority-verifier and re-verification-verifier providers, credential re-issuance"
    ));
    assert!(threat.contains(
        "- device-bound credential/content delivery enforcement beyond implemented trusted-key/authentication paths;"
    ));
}

#[test]
fn service_principal_authentication_resolves_canonical_identity_before_least_privilege() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/service_auth.rs"))
        .expect("service auth");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
        .expect("authorization protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite store");
    let sqlite_credentials = fs::read_to_string(
        workspace.join("crates/ucr-storage-sqlite/src/service_credential_store.rs"),
    )
    .expect("sqlite credential store");
    let spec = fs::read_to_string(workspace.join("spec/service-principal-authentication.md"))
        .expect("service auth spec");
    let permissions =
        fs::read_to_string(workspace.join("spec/permissions.md")).expect("permissions spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0030-service-principal-credentials-authenticate-canonical-scoped-principals.md",
    ))
    .expect("adr 0030");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(model.contains("pub struct ServiceCredentialRecord"));
    assert!(model.contains(".field(\"secret_digest\", &\"<redacted>\")"));
    assert!(core.contains("UCR-SERVICE-CREDENTIAL-DIGEST-V1\\0"));
    assert!(core.contains("getrandom::fill"));
    assert!(core.contains("self.0.zeroize()"));
    assert!(core.contains("expected.ct_eq(&record.secret_digest)"));
    assert!(core.contains("CanonicalErrorCode::Unauthenticated"));
    assert!(core.contains("record.subject.principal.kind != PrincipalKind::ServiceAccount"));
    assert!(runtime.contains("SERVICE_CREDENTIAL_PROVISION_PERMISSION"));
    assert!(runtime.contains("SERVICE_CREDENTIAL_REVOKE_PERMISSION"));
    assert!(protocol.contains("ucr.authentication.service_credential.provision"));
    assert!(protocol.contains("ucr.authentication.service_credential.revoke"));
    assert!(memory.contains(
        "credential_authentication_is_non_disclosing_revocable_and_raw_runtime_cannot_bypass_gate"
    ));
    assert!(sqlite.contains("const SQLITE_SCHEMA_V13: u32 = 13"));
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18"));
    assert!(sqlite.contains("SQLITE_SCHEMA_V12 => migrate_v12_to_v13(connection)?"));
    assert!(sqlite.contains("SQLITE_SCHEMA_V13 => migrate_v13_to_v14(connection)?"));
    assert!(sqlite.contains("SQLITE_SCHEMA_V14 => migrate_v14_to_v15(connection)?"));
    assert!(
        sqlite_credentials.contains("credential_survives_restart_and_revocation_remains_effective")
    );
    assert!(
        sqlite_credentials
            .contains("v12_to_v13_migration_preserves_permissions_and_starts_without_credentials")
    );
    assert!(
        spec.contains(
            "Successful authentication returns the persisted canonical `ScopedPrincipal`"
        )
    );
    assert!(permissions.contains(
        "Service Principal credential authentication feeds an authenticated `ScopedPrincipal`"
    ));
    assert!(adr.contains("credential-enumeration oracle"));
    assert!(ci.contains(
        "docs/adr/0030-service-principal-credentials-authenticate-canonical-scoped-principals.md"
    ));
    assert!(
        !threat.contains("- Service Principal authentication/least-privilege enforcement;"),
        "authentication/least-privilege blocker may disappear only with this executable evidence"
    );
    assert!(
        !threat.contains("- Service Principal quota and audit enforcement;"),
        "quota/audit blocker may disappear only with dedicated executable evidence"
    );
}

#[test]
fn service_principal_request_ingress_requires_unforgeable_single_use_quota_context() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let request = fs::read_to_string(workspace.join("crates/ucr-core/src/service_request.rs"))
        .expect("service request gate");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let authorization =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
            .expect("authorization protocol");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");

    assert!(core.contains("pub trait ServiceQuotaStore"));
    assert!(core.contains("pub trait ServiceAuditStore"));
    assert!(request.contains("pub struct ServicePrincipalRequestGate"));
    assert!(request.contains("pub struct ServicePrincipalRequestAuthorization"));
    assert!(request.contains("pub struct ServicePrincipalAdmissionProof"));
    assert!(core.contains("service_principal_admission_proof"));
    assert!(runtime.contains("PrincipalKind::ServiceAccount"));
    assert!(runtime.contains("service_principal_admission_proof()"));
    assert!(request.contains("AuthorizationEvaluator for ServicePrincipalRequestAuthorization"));
    assert!(request.contains("authenticate_service_principal"));
    assert!(request.contains("consume_service_request(&self.proof.subject, now)"));
    assert!(request.contains("self.authorization.authorize(request)"));
    assert!(request.contains("append_service_audit(&record)"));
    assert!(request.contains("self.used.swap(true"));
    assert!(request.contains("request.permission == self.permission"));
    assert!(request.contains("request.resource_scope == self.resource_scope"));
    assert!(request.contains("if !self.proof.matches(request)"));
    assert!(request.contains("ServiceQuotaConsumeError::NotConfigured"));
    assert!(request.contains("ServiceQuotaConsumeError::ClockRollback"));
    assert!(request.contains("CanonicalErrorCode::RateLimited"));
    assert!(request.contains("CanonicalErrorCode::TemporarilyUnavailable"));

    for permission in [
        "SERVICE_QUOTA_READ_PERMISSION",
        "SERVICE_QUOTA_WRITE_PERMISSION",
        "SERVICE_AUDIT_READ_PERMISSION",
    ] {
        assert!(authorization.contains(permission));
        assert!(runtime.contains(permission));
    }
    assert!(runtime.contains("pub fn service_quota_policy("));
    assert!(runtime.contains("pub fn set_service_quota_policy("));
    assert!(runtime.contains("pub fn service_audit_records("));
    assert!(!runtime.contains("pub fn consume_service_request("));
    assert!(!runtime.contains("pub fn append_service_audit("));

    for evidence in [
        "credential_authentication_is_non_disclosing_revocable_and_raw_runtime_cannot_bypass_gate",
        "service_request_gate_enforces_fixed_window_quota_and_audits_decisions",
        "service_request_gate_audits_bad_secret_clock_rollback_and_context_reuse",
        "quota_policy_and_audit_read_use_independent_admin_permissions",
    ] {
        assert!(
            memory.contains(evidence),
            "memory evidence missing: {evidence}"
        );
    }
}

#[test]
fn service_principal_audit_storage_and_governance_close_only_the_evidenced_blocker() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let control = fs::read_to_string(workspace.join("crates/ucr-protocol/src/service_control.rs"))
        .expect("service control protocol");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let sqlite = fs::read_to_string(
        workspace.join("crates/ucr-storage-sqlite/src/service_control_store.rs"),
    )
    .expect("sqlite service controls");
    let spec = fs::read_to_string(workspace.join("spec/service-principal-control.md"))
        .expect("service principal control spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr =
        fs::read_to_string(workspace.join(
            "docs/adr/0031-service-principal-requests-require-quota-and-append-only-audit.md",
        ))
        .expect("adr 0031");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(model.contains("pub struct ServiceQuotaPolicy"));
    assert!(model.contains("pub struct ServiceAuditRecord"));
    let audit_fields = model
        .split("pub struct ServiceAuditRecord")
        .nth(1)
        .and_then(|tail| tail.split('}').next())
        .expect("audit record fields");
    for forbidden in ["secret", "secret_digest", "payload", "message_content"] {
        assert!(
            !audit_fields.contains(forbidden),
            "audit record leaked: {forbidden}"
        );
    }
    assert!(control.contains("UCR-SERVICE-AUDIT-HASH-V1\\0"));
    assert!(control.contains("722e882fce879eb31f509d6deaedea36208817adac3bb99138e025907711efa4"));
    assert!(control.contains("MAX_SERVICE_REQUEST_PERMISSION_LEN"));
    for evidence in [
        "quota_accounting_survives_restart_and_identical_policy_does_not_reset_usage",
        "audit_is_append_only_and_offline_semantic_tampering_is_detected_on_reopen",
        "v13_to_v14_migration_preserves_credentials_and_permissions_and_starts_empty_controls",
    ] {
        assert!(
            sqlite.contains(evidence),
            "sqlite evidence missing: {evidence}"
        );
    }
    assert!(sqlite.contains("CREATE TRIGGER service_audit_no_update"));
    assert!(sqlite.contains("CREATE TRIGGER service_audit_no_delete"));
    assert!(sqlite.contains("verify_audit_chain"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V13: u32 = 13;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V14: u32 = 14;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v13_to_v14"));
    assert!(sqlite_root.contains("fn migrate_v14_to_v15"));
    assert!(spec.contains("single-use"));
    assert!(spec.contains("not a distributed global rate limiter"));
    assert!(spec.contains("not a claim that an attacker with privileged filesystem control"));
    assert!(
        adr.contains(
            "closes the production blocker `Service Principal quota and audit enforcement`"
        )
    );
    assert!(ci.contains("spec/service-principal-control.md"));
    assert!(ci.contains(
        "docs/adr/0031-service-principal-requests-require-quota-and-append-only-audit.md"
    ));
    assert!(!threat.contains("- Service Principal quota and audit enforcement;"));
    assert!(
        threat.contains("- production OS/hardware-backed key providers for supported targets;")
    );
    assert!(threat.contains("- device-bound credential/content delivery enforcement beyond implemented trusted-key/authentication paths;"));
}

fn canonical_threat_boundaries(threat: &str) -> std::collections::BTreeSet<String> {
    let boundary_block = threat
        .split("The canonical boundaries are:\n")
        .nth(1)
        .and_then(|tail| tail.split("\n\n").next())
        .expect("numbered trust-boundary block");
    let boundaries = boundary_block
        .lines()
        .filter_map(|line| line.split_once(". ").map(|(_, name)| name.to_owned()))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        boundaries.len() >= 10,
        "canonical trust-boundary baseline must not shrink silently"
    );
    boundaries
}

fn metadata_visibility_rows(inventory: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut lines = inventory.lines();
    assert_eq!(
        lines.next(),
        Some(
            "component_id\tboundary_name\timplementation_status\tmay_observe\tmust_not_observe\tretention\texport_rule"
        )
    );
    let mut component_ids = std::collections::BTreeSet::new();
    let mut rows = std::collections::BTreeMap::new();
    for line in lines {
        let columns = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            columns.len(),
            7,
            "metadata row must have exactly seven columns: {line}"
        );
        assert!(
            columns.iter().all(|value| !value.trim().is_empty()),
            "metadata row contains an empty required field: {line}"
        );
        assert!(
            matches!(
                columns[2].as_str(),
                "implemented" | "partial" | "not_implemented" | "cross_cutting"
            ),
            "unknown implementation status: {}",
            columns[2]
        );
        assert!(
            component_ids.insert(columns[0].clone()),
            "duplicate metadata component_id: {}",
            columns[0]
        );
        assert!(
            rows.insert(columns[1].clone(), columns).is_none(),
            "duplicate metadata boundary"
        );
    }
    rows
}

#[test]
fn every_infrastructure_boundary_has_machine_checked_metadata_visibility() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let spec = fs::read_to_string(workspace.join("spec/metadata-visibility.md"))
        .expect("metadata visibility spec");
    let inventory = fs::read_to_string(workspace.join("spec/metadata-visibility.tsv"))
        .expect("metadata visibility inventory");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0029-infrastructure-metadata-visibility-is-explicit-and-machine-checked.md",
    ))
    .expect("adr 0029");
    let boundaries = canonical_threat_boundaries(&threat);
    let rows = metadata_visibility_rows(&inventory);
    let inventory_boundaries = rows
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();

    for boundary in &boundaries {
        assert!(
            rows.contains_key(boundary),
            "missing metadata inventory row: {boundary}"
        );
    }
    assert_eq!(inventory_boundaries.len(), boundaries.len() + 1);
    assert!(inventory_boundaries.contains("Observability"));

    let relay = rows.get("Relay").expect("relay row");
    assert!(relay[3].contains("encrypted payload length and timing"));
    assert!(relay[4].contains("plaintext message or attachment content"));
    let bridge = rows.get("Bridge").expect("bridge row");
    assert!(bridge[3].contains(
        "only when the explicit bridge action and policy require provider-visible content"
    ));
    let sfu = rows.get("SFU").expect("sfu row");
    assert!(sfu[3].contains("encrypted media packet size/timing"));
    assert!(
        sfu[4].contains(
            "media plaintext unless an explicitly reviewed media architecture requires it"
        )
    );
    assert!(rows["Cloud Infrastructure"][6].contains("no cloud account"));
    for forbidden in [
        "plaintext messages",
        "authentication secrets",
        "KEY_MATERIAL",
    ] {
        assert!(rows["Observability"][4].contains(forbidden));
    }

    assert!(spec.contains("minimum-disclosure ceiling"));
    assert!(spec.contains(
        "does **not** close the separate `secret/plaintext telemetry regression tests` blocker"
    ));
    assert!(adr.contains("future privacy ceiling"));
    assert!(adr.contains("does not close telemetry leak testing"));
    assert!(
        !threat.contains("- metadata-visibility documentation for each infrastructure component;")
    );
    assert!(threat.contains("- secret/plaintext telemetry regression tests."));
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");
    assert!(ci.contains(
        "docs/adr/0029-infrastructure-metadata-visibility-is-explicit-and-machine-checked.md"
    ));
}

#[test]
fn implemented_trust_boundaries_have_cross_crate_threat_simulations() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let workspace_manifest = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace");
    let manifest = fs::read_to_string(workspace.join("crates/ucr-security-tests/Cargo.toml"))
        .expect("security test manifest");
    let lib = fs::read_to_string(workspace.join("crates/ucr-security-tests/src/lib.rs"))
        .expect("security test lib");
    let simulations =
        fs::read_to_string(workspace.join("crates/ucr-security-tests/tests/threat_simulations.rs"))
            .expect("threat simulations");
    let matrix = fs::read_to_string(workspace.join("docs/architecture/THREAT_SIMULATIONS.md"))
        .expect("threat simulation matrix");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0034-implemented-trust-boundaries-require-cross-crate-threat-simulations.md",
    ))
    .expect("adr 0034");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(workspace_manifest.contains("\"crates/ucr-security-tests\""));
    assert!(manifest.contains("publish = false"));
    for dependency in [
        "ucr-core",
        "ucr-crypto",
        "ucr-model",
        "ucr-protocol",
        "ucr-storage-memory",
        "ucr-storage-sqlite",
    ] {
        assert!(
            manifest.contains(dependency),
            "missing cross-crate dependency: {dependency}"
        );
    }
    assert!(lib.contains("Cross-crate executable threat simulations"));
    assert!(
        !lib.contains("pub fn "),
        "security evidence crate must not grow a second runtime brain"
    );

    let scenarios = [
        "replay_simulation_survives_process_restart_and_rejects_duplicate_binding",
        "mitm_simulation_cannot_replace_trusted_peer_signature_or_poison_replay_state",
        "forged_identity_simulation_fails_even_with_valid_device_private_key",
        "malicious_tenant_simulation_cannot_cross_scope_or_mutate_storage",
        "malicious_service_account_simulation_cannot_bypass_admission_proof",
        "malicious_peer_simulation_cannot_self_provision_claimed_key",
        "invalid_permission_simulation_denies_mutation_before_storage",
        "revoked_device_simulation_denies_existing_signature_and_future_key_access",
    ];
    for scenario in scenarios {
        assert!(
            simulations.contains(&format!("fn {scenario}()")),
            "missing executable threat scenario: {scenario}"
        );
        assert!(
            matrix.contains(scenario),
            "missing threat evidence index: {scenario}"
        );
    }
    let simulation_test_count = simulations
        .lines()
        .filter(|line| line.trim_start().starts_with("fn ") && line.contains("_simulation_"))
        .count();
    assert_eq!(simulation_test_count, scenarios.len());

    assert!(matrix.contains("Compromised Bridge"));
    assert!(matrix.contains(
        "**Not implemented: Bridge does not exist yet; a mock is not accepted as evidence**"
    ));
    assert!(threat.contains(
        "required threat simulations for not-yet-implemented Bridge/remote-transport boundaries"
    ));
    assert!(!threat.contains("- required threat simulations;"));
    assert!(
        adr.contains(
            "Create placeholder Bridge/transport implementations only for tests: rejected"
        )
    );
    assert!(ci.contains(
        "docs/adr/0034-implemented-trust-boundaries-require-cross-crate-threat-simulations.md"
    ));
}

fn assert_chaos_evidence(source: &str, matrix: &str, scenario: &str) {
    assert!(
        source.contains(&format!("fn {scenario}()")),
        "missing executable chaos scenario: {scenario}"
    );
    assert!(
        matrix.contains(scenario),
        "missing chaos evidence index: {scenario}"
    );
}

#[test]
fn applicable_chaos_scenarios_cross_real_boundaries_without_fake_infrastructure() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let chaos =
        fs::read_to_string(workspace.join("crates/ucr-security-tests/tests/chaos_scenarios.rs"))
            .expect("chaos scenarios");
    let sqlite_store = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite provider");
    let matrix = fs::read_to_string(workspace.join("docs/architecture/CHAOS_SCENARIOS.md"))
        .expect("chaos evidence matrix");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(
        workspace
            .join("docs/adr/0035-applicable-chaos-evidence-composes-real-runtime-boundaries.md"),
    )
    .expect("adr 0035");
    let storage_full_adr = fs::read_to_string(workspace.join(
        "docs/adr/0036-sqlite-storage-full-chaos-uses-provider-private-capacity-injection.md",
    ))
    .expect("adr 0036");
    let process_kill_adr = fs::read_to_string(
        workspace.join("docs/adr/0037-sqlite-process-kill-chaos-uses-test-only-precommit-pause.md"),
    )
    .expect("adr 0037");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    let scenarios = [
        "app_restart_chaos_preserves_command_deduplication",
        "duplicate_ingress_chaos_has_one_canonical_acceptance",
        "clock_rollback_chaos_fails_closed_and_is_audited",
        "local_partition_merge_chaos_recovers_missing_and_refuses_damaged_state",
        "old_client_chaos_cannot_force_policy_downgrade",
        "authenticated_message_corruption_chaos_fails_closed",
        "revoked_device_restart_chaos_never_resurrects_trust",
    ];
    for scenario in scenarios {
        assert_chaos_evidence(&chaos, &matrix, scenario);
    }
    let chaos_test_count = chaos
        .lines()
        .filter(|line| line.trim_start().starts_with("fn ") && line.contains("_chaos_"))
        .count();
    assert_eq!(chaos_test_count, scenarios.len());

    let storage_full = "sqlite_storage_full_rolls_back_command_acceptance_atomically";
    assert_chaos_evidence(&sqlite_store, &matrix, storage_full);
    let process_kill = "mid_operation_process_kill_rolls_back_command_acceptance_atomically";
    assert_chaos_evidence(&sqlite_store, &matrix, process_kill);
    assert!(sqlite_store.contains("#[cfg(test)]\nfn test_pause_command_acceptance_before_commit"));
    assert!(!sqlite_store.contains("pub fn test_pause_command_acceptance_before_commit"));

    for open_evidence in [
        "Not implemented: no production network transport exists",
        "Not implemented: Relay does not exist yet",
        "Not implemented: SFU does not exist yet",
        "Not implemented: no production packet receive/reorder boundary exists",
        "Not implemented: no production consumer/backpressure boundary exists",
    ] {
        assert!(
            matrix.contains(open_evidence),
            "chaos limitation disappeared without evidence: {open_evidence}"
        );
    }
    assert!(!threat.contains("- applicable chaos scenarios;"));
    assert!(
        !matrix.contains("OPEN: deterministic mid-operation process-kill injection does not exist")
    );
    assert!(!threat.contains("deterministic process-kill fault injection for durable stores"));
    assert!(threat.contains(
        "transport/infrastructure chaos evidence for network/DNS/Relay/SFU/peer-disappearance/transport-reorder/slow-consumer"
    ));
    assert!(!threat.contains("end-to-end storage-full fault injection remain open"));
    assert!(threat.contains("seven executable cross-crate chaos scenarios"));
    assert!(threat.contains("provider-owned end-to-end page-capacity exhaustion evidence"));
    assert!(adr.contains("An application restart is not claimed to be a process-kill test"));
    assert!(adr.contains(
        "Create fake Relay/SFU/network implementations only to satisfy the checklist: rejected"
    ));
    assert!(storage_full_adr.contains(
        "No public fault-injection API, alternate store, or second storage-policy owner is added"
    ));
    assert!(process_kill_adr.contains("separate instance of the actual SQLite crate test binary"));
    assert!(process_kill_adr.contains("immediately before the real transaction commit"));
    assert!(process_kill_adr.contains("No public fault-injection API"));
    assert!(
        ci.contains("docs/adr/0035-applicable-chaos-evidence-composes-real-runtime-boundaries.md")
    );
    assert!(ci.contains(
        "docs/adr/0036-sqlite-storage-full-chaos-uses-provider-private-capacity-injection.md"
    ));
    assert!(
        ci.contains("docs/adr/0037-sqlite-process-kill-chaos-uses-test-only-precommit-pause.md")
    );
}

#[test]
fn communication_intent_storage_is_durable_scoped_and_has_one_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/intent.rs"))
        .expect("intent protocol");
    let authorization =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
            .expect("authorization");
    let memory =
        fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs")).expect("memory");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/intent_store.rs"))
            .expect("intent sqlite");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("runtime");
    let storage = fs::read_to_string(workspace.join("spec/local-storage.md")).expect("storage");
    let architecture = fs::read_to_string(workspace.join("docs/architecture/ARCHITECTURE.md"))
        .expect("architecture");
    let adr = fs::read_to_string(
        workspace
            .join("docs/adr/0038-communication-intent-is-a-durable-scoped-runtime-primitive.md"),
    )
    .expect("adr 0038");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(core.contains("pub trait CommunicationIntentStore: StorageProvider"));
    assert!(memory.contains("impl CommunicationIntentStore for MemoryLocalStore"));
    assert!(sqlite.contains("impl CommunicationIntentStore for SqliteLocalStore"));
    assert!(sqlite.contains("CREATE TABLE communication_intents"));
    assert!(sqlite.contains("CREATE TABLE communication_intent_transports"));
    assert!(sqlite.contains("CREATE TABLE communication_intent_extensions"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V15: u32 = 15;"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V16: u32 = 16;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v15_to_v16"));

    for evidence in [
        "intent_survives_restart_and_canonical_retries_deduplicate",
        "scoped_intent_id_reuse_with_changed_semantics_conflicts",
        "concurrent_conflicting_intents_have_single_winner",
        "same_intent_id_is_isolated_by_exact_scope",
        "v15_to_v16_migration_starts_with_no_invented_intents",
        "malformed_persisted_transport_is_rejected_on_reopen",
        "orphan_intent_child_is_rejected_on_reopen",
        "oversized_persisted_root_fields_are_rejected_on_reopen",
        "oversized_persisted_extension_payload_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite.contains(evidence),
            "missing Intent durability evidence: {evidence}"
        );
    }
    assert!(protocol.contains("MAX_INTENT_POLICY_VALUE_LEN"));
    assert!(protocol.contains("MAX_INTENT_IDEMPOTENCY_KEY_LEN"));
    assert!(protocol.contains("canonical_communication_intent"));
    assert!(runtime.contains("pub fn persist_communication_intent("));
    assert!(runtime.contains("pub fn communication_intent("));
    assert!(authorization.contains("COMMUNICATION_INTENT_READ_PERMISSION"));
    assert!(authorization.contains("COMMUNICATION_INTENT_WRITE_PERMISSION"));
    assert!(
        memory.contains("unified_runtime_enforces_independent_communication_intent_permissions")
    );
    assert!(storage.contains("Schema v16 migrates v15 transactionally"));
    assert!(
        architecture
            .contains("`CommunicationIntent` is persisted independently from route availability")
    );
    assert!(adr.contains("Intent is neither Message nor Delivery"));
    assert!(adr.contains("does not claim remote-peer authentication"));
    assert!(
        ci.contains("docs/adr/0038-communication-intent-is-a-durable-scoped-runtime-primitive.md")
    );

    for forbidden in [
        "telegram_intent",
        "vk_intent",
        "max_messenger_intent",
        "whatsapp_intent",
        "provider_intent",
    ] {
        assert!(
            !sqlite.contains(forbidden),
            "provider-specific Intent owner leaked: {forbidden}"
        );
    }
}

#[test]
fn recovered_device_reverification_has_independent_proof_and_atomic_activation_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let workflow = fs::read_to_string(workspace.join("crates/ucr-core/src/recovery_workflow.rs"))
        .expect("recovery workflow");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite =
        fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/device_store.rs"))
            .expect("sqlite device store");
    let spec = fs::read_to_string(workspace.join("spec/recovery.md")).expect("recovery spec");
    let device_spec =
        fs::read_to_string(workspace.join("spec/principal-actor-device.md")).expect("device spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0039-recovered-device-activation-requires-independent-reverification-proof.md",
    ))
    .expect("adr 0039");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(workflow.contains("pub trait DeviceReverificationVerifier"));
    assert!(workflow.contains("pub struct DeviceReverificationProof"));
    assert!(workflow.contains("pub trait ReverifiedDeviceActivationStore"));
    assert!(workflow.contains("authorize_and_activate_reverified_device"));
    assert!(workflow.contains("DeviceLifecycleState::ReverificationRequired"));
    assert!(memory.contains("impl ReverifiedDeviceActivationStore for MemoryLocalStore"));
    assert!(sqlite.contains("impl ReverifiedDeviceActivationStore for SqliteLocalStore"));
    assert!(sqlite.contains("state='reverification_required'"));
    for evidence in [
        "recovered_device_requires_independent_reverification_before_active",
        "stale_reverification_proof_cannot_resurrect_revoked_device",
    ] {
        assert!(
            memory.contains(evidence),
            "memory re-verification evidence missing: {evidence}"
        );
    }
    for evidence in [
        "reverified_device_activation_survives_restart_and_enables_new_key_trust",
        "concurrent_reverify_and_revoke_never_resurrect_revoked_device",
    ] {
        assert!(
            sqlite.contains(evidence),
            "sqlite re-verification evidence missing: {evidence}"
        );
    }
    assert!(spec.contains(
        "Ordinary registration or PermissionGrant administration is not a re-verification bypass"
    ));
    assert!(
        device_spec.contains("Ordinary registration cannot perform the re-verification promotion")
    );
    assert!(adr.contains(
        "Re-verification authority is deliberately not represented as a `PermissionGrant`"
    ));
    assert!(threat.contains("private-field `DeviceReverificationProof`"));
    assert!(
        ci.contains(
            "0039-recovered-device-activation-requires-independent-reverification-proof.md"
        )
    );
    assert!(!threat.contains("re-verification transition/UX evidence"));
}

#[test]
fn integration_api_reuses_canonical_command_and_service_principal_owners() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let proto = fs::read_to_string(workspace.join("proto/ucr/v1/integration.proto"))
        .expect("integration proto");
    let ingress = fs::read_to_string(workspace.join("crates/ucr-core/src/integration_api.rs"))
        .expect("integration ingress");
    let spec =
        fs::read_to_string(workspace.join("spec/integration-api.md")).expect("integration spec");
    let architecture = fs::read_to_string(workspace.join("docs/architecture/ARCHITECTURE.md"))
        .expect("architecture");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let inventory = fs::read_to_string(workspace.join("spec/metadata-visibility.tsv"))
        .expect("metadata inventory");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");
    let sqlite = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite store");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0040-integration-api-reuses-canonical-command-and-service-principal-boundaries.md",
    ))
    .expect("adr 0040");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");
    let readme = fs::read_to_string(workspace.join("README.md")).expect("readme");

    assert!(proto.contains("service IntegrationService"));
    assert!(proto.contains("rpc SubmitCommand(IntegrationCommandRequest)"));
    assert!(proto.contains("CommandEnvelope command = 1;"));
    assert!(proto.contains("CommandReceipt receipt = 1;"));
    assert!(proto.contains("ErrorEnvelope error = 2;"));
    assert!(!proto.contains("SubscribeEvents"));

    assert!(ingress.contains("pub struct IntegrationCommandIngress"));
    assert!(ingress.contains("ServicePrincipalRequestGate::new"));
    assert!(ingress.contains("COMMAND_ACCEPT_PERMISSION"));
    assert!(ingress.contains("AuthorizedDurableRuntime::new"));
    assert!(ingress.contains(".accept_command(&subject, command)"));

    for forbidden in [
        "SqliteLocalStore",
        "MemoryLocalStore",
        "rusqlite",
        "telegram",
        "vk_",
        "max_messenger",
        "clientplatform",
        "businessaios",
    ] {
        assert!(
            !ingress
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase()),
            "Integration ingress leaked forbidden owner/provider: {forbidden}"
        );
    }

    assert!(spec.contains(
        "credential authentication -> quota consumption/audit -> permission evaluation -> durable command acceptance"
    ));
    assert!(spec.contains("Phase 14 owns Event API"));
    assert!(spec.contains("semantics; later phases own network transport"));
    assert!(architecture.contains("Phase 13 begins with `IntegrationService.SubmitCommand`"));
    assert!(threat.contains("Phase-13 `IntegrationCommandIngress`"));
    assert!(inventory.contains("external_app\tExternal App\tpartial\t"));
    for evidence in [
        "integration_ingress_authenticates_audits_authorizes_and_deduplicates",
        "integration_ingress_denials_never_create_ghost_acceptance",
        "integration_ingress_rate_limit_fails_before_command_acceptance",
    ] {
        assert!(
            memory.contains(evidence),
            "missing Integration API evidence: {evidence}"
        );
    }
    assert!(sqlite.contains("integration_command_ingress_deduplicates_after_sqlite_restart"));
    assert!(adr.contains("Direct database access was rejected"));
    assert!(adr.contains("does not implement Event API"));
    assert!(ci.contains("spec/integration-api.md"));
    assert!(ci.contains("proto/ucr/v1/integration.proto"));
    assert!(ci.contains(
        "docs/adr/0040-integration-api-reuses-canonical-command-and-service-principal-boundaries.md"
    ));
    assert!(readme.contains("**Phase 13 — Integration API (in progress"));
}

#[test]
fn service_principal_audit_operation_binding_reuses_existing_core_owner() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/service_control.rs"))
        .expect("service control protocol");
    let request = fs::read_to_string(workspace.join("crates/ucr-core/src/service_request.rs"))
        .expect("service request gate");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let ingress = fs::read_to_string(workspace.join("crates/ucr-core/src/integration_api.rs"))
        .expect("integration ingress");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");

    assert!(model.contains("pub struct ServiceAuditOperationRef"));
    assert!(model.contains("pub operation: Option<ServiceAuditOperationRef>"));
    assert!(protocol.contains("UCR-SERVICE-AUDIT-HASH-V1\\0"));
    assert!(protocol.contains("UCR-SERVICE-AUDIT-HASH-V2\\0"));
    assert!(protocol.contains("SERVICE_AUDIT_COMMAND_OPERATION_KIND"));
    assert!(protocol.contains("fn service_audit_hash_v1("));
    assert!(protocol.contains("fn service_audit_hash_v2("));
    assert!(!protocol.contains("pub fn service_audit_hash_v1("));
    assert!(!protocol.contains("pub fn service_audit_hash_v2("));
    assert!(protocol.contains("def3f98563a1590f6c6fe3f5901c179102c90aaea125729ed513d961a25f599a"));
    assert!(request.contains("pub fn authenticate_request_for_operation("));
    assert!(core.contains("fn service_audit_records_for_operation("));
    let lookup = runtime
        .split("pub fn service_audit_records_for_operation(")
        .nth(1)
        .and_then(|tail| tail.split("\n    }").next())
        .expect("authorized operation audit lookup");
    assert!(lookup.contains("SERVICE_AUDIT_READ_PERMISSION"));
    assert!(lookup.contains(".service_audit_records_for_operation("));
    assert!(ingress.contains("SERVICE_AUDIT_COMMAND_OPERATION_KIND"));
    assert!(ingress.contains("command.command_id.as_opaque().clone()"));
    assert!(ingress.contains(".authenticate_request_for_operation("));
    for evidence in [
        "integration_ingress_authenticates_audits_authorizes_and_deduplicates",
        "integration_ingress_denials_never_create_ghost_acceptance",
        "integration_ingress_rate_limit_fails_before_command_acceptance",
        "operation_audit_lookup_uses_existing_audit_read_permission",
    ] {
        assert!(
            memory.contains(evidence),
            "missing operation-binding evidence: {evidence}"
        );
    }
    for forbidden in [
        "service_command_audit",
        "command_audit_records",
        "integration_audit_store",
    ] {
        assert!(
            !request.contains(forbidden),
            "second audit owner leaked: {forbidden}"
        );
    }
}

#[test]
fn service_principal_audit_operation_binding_has_v17_migration_and_governance() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let sqlite = fs::read_to_string(
        workspace.join("crates/ucr-storage-sqlite/src/service_control_store.rs"),
    )
    .expect("sqlite service audit");
    let service_spec = fs::read_to_string(workspace.join("spec/service-principal-control.md"))
        .expect("service principal control spec");
    let integration_spec =
        fs::read_to_string(workspace.join("spec/integration-api.md")).expect("integration spec");
    let storage_spec =
        fs::read_to_string(workspace.join("spec/local-storage.md")).expect("storage spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0041-service-principal-audit-operation-reference-is-versioned-and-append-only.md",
    ))
    .expect("adr 0041");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(sqlite.contains("CREATE TABLE service_audit_operations"));
    assert!(sqlite.contains("CREATE INDEX service_audit_operation_lookup"));
    assert!(sqlite.contains("CREATE TRIGGER service_audit_operation_no_update"));
    assert!(sqlite.contains("CREATE TRIGGER service_audit_operation_no_delete"));
    assert!(sqlite.contains("LEFT JOIN service_audit_operations"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V16: u32 = 16;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v16_to_v17"));
    for evidence in [
        "operation_bound_audit_survives_restart_and_exact_lookup",
        "operation_audit_child_is_append_only_and_offline_tampering_is_detected",
        "offline_operation_addition_to_legacy_v1_row_is_detected_on_reopen",
        "offline_operation_deletion_from_v2_row_is_detected_on_reopen",
        "missing_v17_operation_owner_is_rejected_on_reopen",
        "v16_to_v17_migration_preserves_legacy_v1_hash_without_inventing_operations",
    ] {
        assert!(
            sqlite.contains(evidence),
            "missing v17 audit evidence: {evidence}"
        );
    }
    assert!(service_spec.contains("SQLite schema v17 migrates v16 transactionally"));
    assert!(service_spec.contains("UCR-SERVICE-AUDIT-HASH-V2"));
    assert!(integration_spec.contains("generic operation reference `ucr.command`"));
    assert!(storage_spec.contains("Schema v17 migrates v16 transactionally"));
    assert!(threat.contains("SQLite v17 extends the same Service Principal audit owner"));
    assert!(adr.contains("`service_audit_records` table is not rewritten"));
    assert!(adr.contains("not proof that Command validation"));
    assert!(ci.contains(
        "0041-service-principal-audit-operation-reference-is-versioned-and-append-only.md"
    ));
    for forbidden in [
        "service_command_audit",
        "command_audit_records",
        "integration_audit_store",
    ] {
        assert!(
            !sqlite.contains(forbidden),
            "second audit owner leaked: {forbidden}"
        );
    }
}

#[test]
fn external_identity_binding_reuses_one_canonical_owner_and_permissions() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model = fs::read_to_string(workspace.join("crates/ucr-model/src/lib.rs")).expect("model");
    let protocol = fs::read_to_string(workspace.join("crates/ucr-protocol/src/addressing.rs"))
        .expect("addressing protocol");
    let authorization =
        fs::read_to_string(workspace.join("crates/ucr-protocol/src/authorization.rs"))
            .expect("authorization protocol");
    let core = fs::read_to_string(workspace.join("crates/ucr-core/src/lib.rs")).expect("core");
    let runtime = fs::read_to_string(workspace.join("crates/ucr-core/src/authorized_runtime.rs"))
        .expect("authorized runtime");
    let memory = fs::read_to_string(workspace.join("crates/ucr-storage-memory/src/lib.rs"))
        .expect("memory store");

    assert!(model.contains("pub struct ExternalIdentityBinding"));
    assert!(protocol.contains("pub fn validate_external_identity_binding_key("));
    assert!(core.contains("pub trait ExternalIdentityBindingStore: StorageProvider"));
    assert!(core.contains("fn persist_external_identity_binding("));
    assert!(core.contains("fn external_identity_binding("));
    assert!(memory.contains("impl ExternalIdentityBindingStore for MemoryLocalStore"));
    assert!(authorization.contains("EXTERNAL_IDENTITY_BINDING_LINK_PERMISSION"));
    assert!(authorization.contains("ucr.identity.external_binding.link"));
    assert!(authorization.contains("EXTERNAL_IDENTITY_BINDING_READ_PERMISSION"));
    assert!(authorization.contains("ucr.identity.external_binding.read"));
    assert!(runtime.contains("pub fn link_external_identity("));
    assert!(runtime.contains("pub fn external_identity_binding("));

    for evidence in [
        "exact_external_identity_binding_is_deduplicated_and_never_relinked",
        "external_identity_key_preserves_namespace_and_opaque_bytes_exactly",
        "unified_runtime_enforces_external_identity_binding_permissions_without_relink_bypass",
    ] {
        assert!(
            memory.contains(evidence),
            "missing memory binding evidence: {evidence}"
        );
    }
    for forbidden in [
        "CustomerIdentityBindingStore",
        "PatientIdentityBindingStore",
        "ClientPlatformIdentityBindingStore",
        "ProviderIdentityBindingStore",
    ] {
        assert!(
            !core.contains(forbidden),
            "second identity owner leaked into Core: {forbidden}"
        );
        assert!(
            !memory.contains(forbidden),
            "second identity owner leaked into Memory: {forbidden}"
        );
    }
}

#[test]
fn external_identity_binding_v18_is_exact_scoped_migrated_and_governed() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let sqlite_root = fs::read_to_string(workspace.join("crates/ucr-storage-sqlite/src/lib.rs"))
        .expect("sqlite root");
    let sqlite = fs::read_to_string(
        workspace.join("crates/ucr-storage-sqlite/src/identity_binding_store.rs"),
    )
    .expect("sqlite identity binding store");
    let identity_spec =
        fs::read_to_string(workspace.join("spec/identity-addressing.md")).expect("identity spec");
    let storage_spec =
        fs::read_to_string(workspace.join("spec/local-storage.md")).expect("storage spec");
    let permission_spec =
        fs::read_to_string(workspace.join("spec/permissions.md")).expect("permission spec");
    let threat = fs::read_to_string(workspace.join("docs/architecture/THREAT_MODEL.md"))
        .expect("threat model");
    let adr = fs::read_to_string(workspace.join(
        "docs/adr/0042-external-identity-binding-is-a-durable-scoped-integration-primitive.md",
    ))
    .expect("adr 0042");
    let ci = fs::read_to_string(workspace.join(".github/workflows/ci.yml")).expect("ci");

    assert!(sqlite.contains("impl ExternalIdentityBindingStore for SqliteLocalStore"));
    for component in [
        "tenant_id",
        "namespace_present",
        "namespace_id",
        "integration_id",
        "external_namespace",
        "external_entity_id",
    ] {
        assert!(
            sqlite.contains(component),
            "binding key component missing: {component}"
        );
    }
    assert!(sqlite.contains("PRIMARY KEY("));
    assert!(sqlite.contains("external_namespace, external_entity_id"));
    assert!(sqlite_root.contains("const SQLITE_SCHEMA_V17: u32 = 17;"));
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 18;"));
    assert!(sqlite_root.contains("fn migrate_v17_to_v18("));
    assert!(sqlite_root.contains("identity_binding_store::create_v18_objects"));
    assert!(sqlite_root.contains("identity_binding_store::verify_schema_v18"));

    for evidence in [
        "external_identity_binding_survives_restart_and_relink_conflicts",
        "concurrent_conflicting_external_identity_links_have_one_winner",
        "v17_to_v18_migration_starts_with_no_inferred_identity_bindings",
        "missing_or_malformed_v18_identity_binding_owner_is_rejected_on_reopen",
    ] {
        assert!(
            sqlite.contains(evidence),
            "missing sqlite binding evidence: {evidence}"
        );
    }
    assert!(identity_spec.contains(
        "exact durable key is `TenantScope + IntegrationId + external_namespace + external_entity_id bytes`"
    ));
    assert!(identity_spec.contains("No relink/unlink lifecycle is defined yet"));
    assert!(storage_spec.contains("Schema v18 migrates v17 transactionally"));
    assert!(storage_spec.contains("External Identity Binding scope + integration namespace + opaque external entity ID + Identity target"));
    assert!(storage_spec.contains("identity-binding lifecycle retention"));
    assert!(storage_spec.contains("PRIVATE / identity and provider metadata"));
    assert!(permission_spec.contains("45 externally callable tenant-scoped durable methods"));
    assert!(permission_spec.contains("37 unique permission IDs"));
    assert!(threat.contains("SQLite v18 adds the single durable `ExternalIdentityBinding` owner"));
    assert!(adr.contains("No implicit relink or unlink operation is defined"));
    assert!(adr.contains("Direct integration database access was rejected"));
    assert!(
        ci.contains("0042-external-identity-binding-is-a-durable-scoped-integration-primitive.md")
    );
    assert!(!sqlite.contains("ProviderIdentityBindingStore"));
}

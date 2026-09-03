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
        "Service Principal authentication/least-privilege enforcement",
        "device revocation enforcement",
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
    let architecture = fs::read_to_string(workspace.join("docs/architecture/ARCHITECTURE.md"))
        .expect("architecture");

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
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 12;"));
    assert!(sqlite_root.contains("fn migrate_v9_to_v10"));
    assert!(sqlite_root.contains("fn migrate_v10_to_v11"));
    assert!(sqlite_root.contains("fn migrate_v11_to_v12"));
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
    assert!(architecture.contains("durable Intent storage is not yet implemented"));
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
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 12"));
    assert!(sqlite_root.contains("fn migrate_v10_to_v11"));
    assert!(sqlite_root.contains("fn migrate_v11_to_v12"));

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
        "device revocation enforcement in credential/key delivery",
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
    assert!(sqlite_root.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 12;"));
    assert!(sqlite_root.contains("fn migrate_v11_to_v12"));
    assert!(spec.contains("SQLite schema v12"));
    assert!(adr.contains("does not claim every Command/Message/Sync/Delivery/runtime operation"));
    assert!(threat.contains("SQLite v12 state"));
}

const AUTHORIZED_DURABLE_METHODS: &[&str] = &[
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
    assert!(spec.contains("every currently implemented tenant-scoped durable capability"));
    assert!(adr.contains("mirrors all 32 methods"));
    assert!(adr.contains("cannot grant itself grant-management authority"));
    assert!(ci.contains(
        "docs/adr/0028-tenant-scoped-durable-runtime-operations-require-explicit-permissions.md"
    ));
    assert!(
        !threat.contains("- tenant-scoped authorization enforcement;"),
        "authorization blocker may be removed only with complete runtime evidence"
    );
    assert!(threat.contains("- Service Principal authentication/least-privilege enforcement;"));
}

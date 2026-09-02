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
        "trusted peer signing-key provisioning and lifecycle integration",
        "production OS/hardware-backed key providers for supported targets",
        "tenant-scoped authorization enforcement",
        "Service Principal authentication/least-privilege enforcement",
        "device revocation enforcement",
        "end-to-end recovery workflow",
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
fn command_idempotency_contract_keeps_restart_nonclaim_visible() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let spec = fs::read_to_string(workspace.join("spec/commands-events.md"))
        .expect("read command/event spec");

    for invariant in [
        "Every accepted command requires a non-empty bounded idempotency key",
        "different command type or payload is `CONFLICT`",
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
        "Relation order and external-mapping order are not semantic",
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
        "does **not** claim that merely storing a signature proves Message authenticity",
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

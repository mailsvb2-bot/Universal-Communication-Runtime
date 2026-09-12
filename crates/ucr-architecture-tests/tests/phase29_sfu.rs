use std::{fs, path::Path};

fn workspace() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn phase29_reuses_group_call_device_crypto_and_permission_owners() {
    let root = workspace();
    let runtime = fs::read_to_string(root.join("crates/ucr-sfu/src/lib.rs")).expect("sfu runtime");
    let media = fs::read_to_string(root.join("crates/ucr-media-e2ee/src/group_media.rs"))
        .expect("group media");
    let mls = fs::read_to_string(root.join("crates/ucr-group-mls/src/lib.rs")).expect("group mls");
    assert!(runtime.contains("validate_group_media_source_frame"));
    assert!(runtime.contains("GroupStore"));
    assert!(runtime.contains("PrincipalIdentityBindingStore"));
    assert!(
        runtime.contains("AUDIO_SEND_PERMISSION") && runtime.contains("VIDEO_RECEIVE_PERMISSION")
    );
    assert!(runtime.contains("sink.forward_encrypted(target, &canonical)"));
    assert!(media.contains("verify_source_signature"));
    assert!(media.contains("PrincipalIdentityBindingStore"));
    assert!(mls.contains("openmls"));
    assert!(mls.contains("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"));
    assert!(!runtime.contains("fn decrypt_") && !runtime.contains("decrypt_payload("));
    assert!(!runtime.contains("DeliveryStore"));
    assert!(
        !runtime.contains("ConferenceStore")
            && !runtime.contains("ConferenceId")
            && !runtime.contains("ConferenceSession")
    );
}

#[test]
fn phase29_sqlite_public_privacy_and_atomicity_boundaries_are_machine_locked() {
    let root = workspace();
    let sqlite =
        fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/lib.rs")).expect("sqlite");
    let atomic = fs::read_to_string(root.join("crates/ucr-storage-sqlite/src/group_mls_store.rs"))
        .expect("atomic mls");
    let group_proto =
        fs::read_to_string(root.join("proto/ucr/v1/group_media_e2ee.proto")).expect("group proto");
    let sfu_proto = fs::read_to_string(root.join("proto/ucr/v1/sfu.proto")).expect("sfu proto");
    let identity_proto =
        fs::read_to_string(root.join("proto/ucr/v1/identity.proto")).expect("identity proto");
    let spec = fs::read_to_string(root.join("spec/sfu.md")).expect("spec");
    assert!(sqlite.contains("pub const SQLITE_SCHEMA_VERSION: u32 = 26"));
    assert!(sqlite.contains("migrate_v25_to_v26"));
    assert!(sqlite.contains("initialize_or_validate_group_mls_storage"));
    assert!(atomic.contains("transaction_with_behavior(TransactionBehavior::Immediate)"));
    assert!(atomic.contains("group_mls_transitions"));
    assert!(atomic.contains("merge_pending"));
    assert!(group_proto.contains("message EncryptedGroupMediaFrame"));
    assert!(group_proto.contains("message GroupMediaSourceSignature"));
    assert!(sfu_proto.contains("EncryptedGroupMediaFrame frame = 1"));
    assert!(identity_proto.contains("message PrincipalIdentityBinding"));
    assert!(!sfu_proto.contains("service Sfu"));
    assert!(!sfu_proto.contains("bytes plaintext ="));
    assert!(!sfu_proto.contains("bytes private_key ="));
    assert!(!sfu_proto.contains("message Conference"));
    assert!(spec.contains("OpenMLS (RFC 9420)"));
    assert!(spec.contains("one `BEGIN IMMEDIATE` transaction"));
    assert!(spec.contains(
        "does not infer that every Device owned by an Identity is automatically an MLS member"
    ));
}

#[test]
fn phase29_release_truth_security_and_fuzz_are_machine_locked() {
    let root = workspace();
    let readme = fs::read_to_string(root.join("README.md")).expect("readme");
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    let spec_readme = fs::read_to_string(root.join("spec/README.md")).expect("spec readme");
    let threat =
        fs::read_to_string(root.join("docs/architecture/THREAT_MODEL.md")).expect("threat");
    let threat_matrix = fs::read_to_string(root.join("docs/architecture/THREAT_SIMULATIONS.md"))
        .expect("threat matrix");
    let chaos =
        fs::read_to_string(root.join("docs/architecture/CHAOS_SCENARIOS.md")).expect("chaos");
    let fuzz = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz");
    let smoke = fs::read_to_string(root.join("fuzz/run-smoke.sh")).expect("smoke");
    let adr = fs::read_to_string(root.join(
        "docs/adr/0067-phase29-sfu-routes-encrypted-media-without-becoming-call-or-crypto-owner.md",
    ))
    .expect("ADR 0067");
    assert!(readme.contains("Phase 29 — SFU Routing + standardized Group Media E2EE"));
    assert!(ci.contains("test -s proto/ucr/v1/group_media_e2ee.proto"));
    assert!(ci.contains("test -s proto/ucr/v1/sfu.proto"));
    assert!(spec_readme.contains("RFC-9420/OpenMLS-backed group-media E2EE and SFU fan-out"));
    assert!(threat.contains("MLS-epoch-bound `EncryptedGroupMediaFrame`"));
    assert!(threat_matrix.contains("compromised_sfu_simulation_rejects_spoof_before_sink"));
    assert!(chaos.contains("sfu_sink_failure_chaos_preserves_call_authority"));
    assert!(fuzz.contains("sfu_forward_envelope"));
    assert!(smoke.contains("run_target sfu_forward_envelope 4096 768"));
    assert!(adr.contains("Phase 30 owns Conference coordination/lifecycle"));
}
#[test]
fn phase29_hpke_rustsec_patch_is_machine_locked() {
    let root = workspace();
    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    let lock = fs::read_to_string(root.join("Cargo.lock")).expect("root lock");
    let hpke_manifest =
        fs::read_to_string(root.join("third_party/hpke-rs/Cargo.toml")).expect("hpke manifest");
    let hpke_kem =
        fs::read_to_string(root.join("third_party/hpke-rs/src/kem.rs")).expect("hpke kem");
    let patch =
        fs::read_to_string(root.join("third_party/hpke-rs/UCR_PATCH.md")).expect("hpke patch note");
    let license = fs::read_to_string(root.join("third_party/hpke-rs/LICENSE-MPL-2.0"))
        .expect("hpke MPL-2.0 license text");

    assert!(root_manifest.contains("hpke-rs = { path = \"third_party/hpke-rs\" }"));
    assert!(hpke_manifest.contains("[dependencies.sha3]"));
    assert!(!hpke_manifest.contains("libcrux-sha3"));
    assert!(!hpke_manifest.contains("hpke-rs-libcrux"));
    assert!(hpke_kem.contains("use sha3::{"));
    assert!(hpke_kem.contains("shake256_seed::<32>(ikm)"));
    assert!(hpke_kem.contains("shake256_seed::<64>(ikm)"));
    for forbidden in [
        "name = \"proc-macro-error2\"",
        "name = \"libcrux-sha3\"",
        "name = \"hax-lib\"",
        "name = \"hpke-rs-libcrux\"",
    ] {
        assert!(
            !lock.contains(forbidden),
            "forbidden audited dependency returned: {forbidden}"
        );
    }
    assert!(patch.contains("RUSTSEC-2026-0173"));
    assert!(patch.contains("same SHAKE256 algorithm"));
    assert!(license.contains("Mozilla Public License Version 2.0"));
}

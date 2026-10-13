//! Full in-process BFF -> durable canonical SQLite acceptance.
//! Not a simulated HTTP transport and not a real public TLS deployment.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use ucr_core::{IdentityDeviceLookupStore, TrustedSigningKeyStore};
use ucr_realtime::JoinTokenKey;

static SEQUENCE: AtomicU64 = AtomicU64::new(600_000);

struct TestDb(PathBuf);

impl TestDb {
    fn new() -> Self {
        let n = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ucr-rt0-first-party-{}-{n}.sqlite3",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(self.0.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(self.0.with_extension("sqlite3-shm"));
    }
}

fn state(path: &PathBuf) -> State {
    State {
        store: Arc::new(SqliteLocalStore::open(path).expect("canonical SQLite")),
        issuer: Arc::new(
            JoinTokenIssuer::new(
                JoinTokenKey::from_bytes([9; 32]),
                "https://call.example.invalid/client.html",
            )
            .expect("test issuer"),
        ),
        origin: "https://call.example.invalid".to_owned(),
        registration_scope: Some(TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("public-self-service").unwrap()),
            namespace_id: None,
        }),
        pending: Mutex::new(Vec::new()),
        sessions: Mutex::new(Vec::new()),
    }
}

fn proof(
    binding: &Binding,
    key_id: &str,
    signer: &SigningKey,
    challenge: &Value,
    domain: &str,
) -> Value {
    let public_key_base64_url = URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes());
    let nonce = challenge["challengeBytesBase64Url"]
        .as_str()
        .expect("server challenge nonce");
    let challenge_id = challenge["challengeId"]
        .as_str()
        .expect("server challenge id");
    let signed = encoded_proof(
        domain,
        &json!([
            binding.tenant_id,
            binding.namespace_id,
            binding.participant_id,
            binding.device,
            key_id,
            public_key_base64_url,
            challenge_id,
            nonce
        ]),
    )
    .expect("domain-scoped proof");
    json!({
        "binding": binding,
        "keyId": key_id,
        "publicKeyBase64Url": public_key_base64_url,
        "challengeId": challenge_id,
        "signatureBase64Url": URL_SAFE_NO_PAD.encode(signer.sign(signed.as_bytes()).to_bytes())
    })
}

fn signup(state: &State, seed: u8) -> (Binding, SigningKey, String) {
    let (issued, _) = account_route(
        state,
        "/v1/first-party/signup/begin",
        b"{}",
    )
    .expect("independent public signup challenge");
    let binding: Binding = serde_json::from_value(issued["binding"].clone()).unwrap();
    let signer = SigningKey::from_bytes(&[seed; 32]);
    let finish = proof(
        &binding,
        &format!("key-{seed}"),
        &signer,
        &issued,
        "ucr-first-party-signup.v1",
    );
    let (response, cookie) = account_route(
        state,
        "/v1/first-party/signup/finish",
        &serde_json::to_vec(&finish).unwrap(),
    )
    .expect("atomic canonical signup");
    assert!(cookie.unwrap().contains("HttpOnly; SameSite=Strict"));
    assert_eq!(
        serde_json::from_value::<Binding>(response["binding"].clone()).unwrap(),
        binding
    );
    (
        binding,
        signer,
        response["recoveryCode"].as_str().unwrap().to_owned(),
    )
}

fn recover(
    state: &State,
    account: &Binding,
    recovery_code: &str,
    device_name: &str,
    seed: u8,
) -> Result<(Binding, SigningKey, String), StatusCode> {
    let binding = Binding {
        device: device_name.to_owned(),
        ..account.clone()
    };
    let (issued, _) = account_route(
        state,
        "/v1/first-party/recover/begin",
        &serde_json::to_vec(&binding).unwrap(),
    )?;
    let signer = SigningKey::from_bytes(&[seed; 32]);
    let mut finish = proof(
        &binding,
        &format!("key-{seed}"),
        &signer,
        &issued,
        "ucr-first-party-recover.v1",
    );
    finish["recoveryCode"] = json!(recovery_code);
    let (response, cookie) = account_route(
        state,
        "/v1/first-party/recover/finish",
        &serde_json::to_vec(&finish).unwrap(),
    )?;
    assert!(cookie.unwrap().contains("Secure; HttpOnly"));
    Ok((
        binding,
        signer,
        response["recoveryCode"].as_str().unwrap().to_owned(),
    ))
}

fn signed_login(state: &State, binding: &Binding, signer: &SigningKey) {
    let (issued, _) = login_route(
        state,
        "/v1/first-party/login/challenge",
        &serde_json::to_vec(binding).unwrap(),
    )
    .expect("login challenge");
    let signed = encoded_proof(
        "ucr-first-party-device-login.v1",
        &json!([
            binding.tenant_id,
            binding.namespace_id,
            binding.participant_id,
            binding.device,
            issued["challengeId"].as_str().unwrap(),
            issued["challengeBytesBase64Url"].as_str().unwrap(),
        ]),
    )
    .unwrap();
    let proof = json!({
        "binding": binding,
        "challengeId": issued["challengeId"],
        "signatureBase64Url": URL_SAFE_NO_PAD.encode(signer.sign(signed.as_bytes()).to_bytes())
    });
    let (response, cookie) = login_route(
        state,
        "/v1/first-party/login/verify",
        &serde_json::to_vec(&proof).unwrap(),
    )
    .expect("fresh independent canonical Device login");
    assert_eq!(
        serde_json::from_value::<Binding>(response).unwrap(),
        *binding
    );
    assert!(cookie.unwrap().contains("HttpOnly; SameSite=Strict"));
}

#[test]
fn two_real_sqlite_accounts_two_devices_and_signed_login_after_server_restart() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, alice_signer, alice_recovery) = signup(&server, 17);
    let (bob, bob_signer, bob_recovery) = signup(&server, 18);
    assert_ne!(alice.participant_id, bob.participant_id);
    assert_ne!(alice.device, bob.device);
    assert_ne!(alice_recovery, bob_recovery);

    let (alice_two, alice_second_signer, next_alice) =
        recover(&server, &alice, &alice_recovery, "alice-second-device", 19).unwrap();
    let (bob_two, bob_second_signer, _) =
        recover(&server, &bob, &bob_recovery, "bob-second-device", 20).unwrap();
    assert_eq!(
        recover(
            &server,
            &alice,
            &alice_recovery,
            "alice-replay-device",
            21,
        )
        .err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        recover(&server, &alice, &bob_recovery, "cross-user-device", 22).err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        recover(&server, &alice, &next_alice, &alice.device, 23).err(),
        Some(StatusCode::FORBIDDEN),
        "revoked or existing Device ID must never be silently rebound"
    );
    for binding in [&alice, &bob] {
        assert_eq!(
            server
                .store
                .active_devices_for_identity(
                    &scope(binding).unwrap(),
                    &identity(binding).unwrap(),
                    64
                )
                .unwrap()
                .len(),
            2
        );
    }

    // Both public Identity and ALL four trusted Device keys live in the same
    // SQLite file. No first-party session or other server memory is retained.
    drop(server);
    let restarted = state(&db.0);
    for (binding, signer) in [
        (&alice, &alice_signer),
        (&bob, &bob_signer),
        (&alice_two, &alice_second_signer),
        (&bob_two, &bob_second_signer),
    ] {
        signed_login(&restarted, binding, signer);
        assert!(
            restarted
                .store
                .active_trusted_signing_key(
                    &scope(binding).unwrap(),
                    &device(binding).unwrap()
                )
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(restarted.sessions.lock().unwrap().len(), 4);
    // Revoke B's recovered Device via the canonical owner, then verify that
    // its old signer is rejected even after another complete server restart.
    restarted
        .store
        .revoke_device(
            &scope(&bob_two).unwrap(),
            &device(&bob_two).unwrap(),
            &identity(&bob_two).unwrap(),
        )
        .unwrap();
    drop(restarted);
    let revoked = state(&db.0);
    assert!(
        login_route(
            &revoked,
            "/v1/first-party/login/verify",
            b"{}"
        )
        .is_err()
    );
    let (challenge, _) = login_route(
        &revoked,
        "/v1/first-party/login/challenge",
        &serde_json::to_vec(&bob_two).unwrap(),
    )
    .unwrap();
    let signed = encoded_proof(
        "ucr-first-party-device-login.v1",
        &json!([
            bob_two.tenant_id, bob_two.namespace_id, bob_two.participant_id,
            bob_two.device, challenge["challengeId"].as_str().unwrap(),
            challenge["challengeBytesBase64Url"].as_str().unwrap()
        ]),
    )
    .unwrap();
    let proof = json!({
        "binding": bob_two,
        "challengeId": challenge["challengeId"],
        "signatureBase64Url": URL_SAFE_NO_PAD.encode(
            bob_second_signer.sign(signed.as_bytes()).to_bytes())
    });
    assert_eq!(
        login_route(
            &revoked,
            "/v1/first-party/login/verify",
            &serde_json::to_vec(&proof).unwrap()
        )
        .err(),
        Some(StatusCode::UNAUTHORIZED)
    );
    signed_login(&revoked, &alice, &alice_signer);
}

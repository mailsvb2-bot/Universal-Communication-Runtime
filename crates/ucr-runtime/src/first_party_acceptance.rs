//! Full in-process BFF -> durable canonical `SQLite` acceptance.
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
        challenge_key: [7; 32],
        consumed: Mutex::new(Vec::new()),
        untrusted_consumed: Mutex::new(Vec::new()),
        recovery_consumed: Mutex::new(Vec::new()),
        signup_admissions: Mutex::new(Vec::new()),
        sessions: Mutex::new(SessionLedger::default()),
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
    let signed_payload = encoded_proof(
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
        "signatureBase64Url": URL_SAFE_NO_PAD.encode(signer.sign(signed_payload.as_bytes()).to_bytes())
    })
}

fn signup(state: &State, seed: u8) -> (Binding, SigningKey, String) {
    let (issued, _) = account_route(state, "/v1/first-party/signup/begin", b"{}")
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
    let signed_payload = encoded_proof(
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
        "signatureBase64Url": URL_SAFE_NO_PAD.encode(signer.sign(signed_payload.as_bytes()).to_bytes())
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
fn anonymous_signup_replay_and_write_limits_preserve_existing_device_login() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, alice_signer, recovery_code) = signup(&server, 61);

    // Even an attacker who can generate valid self-signed recovery/signup
    // proofs cannot consume the independently authenticated login replay pool.
    {
        let mut untrusted = server.untrusted_consumed.lock().unwrap();
        let expiry = Instant::now() + CHALLENGE_TTL;
        for n in 0..MAX_UNTRUSTED_CONSUMED {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&(n as u64).to_be_bytes());
            untrusted.push((tag, expiry));
        }
    }
    signed_login(&server, &alice, &alice_signer);

    let (issued, _) = account_route(&server, "/v1/first-party/signup/begin", b"{}").unwrap();
    let blocked_binding: Binding = serde_json::from_value(issued["binding"].clone()).unwrap();
    let blocked_signer = SigningKey::from_bytes(&[62; 32]);
    let finish = proof(
        &blocked_binding,
        "key-62",
        &blocked_signer,
        &issued,
        "ucr-first-party-signup.v1",
    );
    assert_eq!(
        account_route(
            &server,
            "/v1/first-party/signup/finish",
            &serde_json::to_vec(&finish).unwrap()
        )
        .err(),
        Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert!(
        server
            .store
            .identity(
                &scope(&blocked_binding).unwrap(),
                &identity(&blocked_binding).unwrap()
            )
            .unwrap()
            .is_none(),
        "a rejected anonymous signup must not persist an Identity"
    );

    server.untrusted_consumed.lock().unwrap().clear();
    {
        let mut admitted = server.signup_admissions.lock().unwrap();
        admitted.extend(std::iter::repeat_n(
            Instant::now(),
            MAX_SELF_SERVICE_SIGNUPS,
        ));
    }
    let (issued, _) = account_route(&server, "/v1/first-party/signup/begin", b"{}").unwrap();
    let denied_binding: Binding = serde_json::from_value(issued["binding"].clone()).unwrap();
    let denied_signer = SigningKey::from_bytes(&[63; 32]);
    let denied = proof(
        &denied_binding,
        "key-63",
        &denied_signer,
        &issued,
        "ucr-first-party-signup.v1",
    );
    assert_eq!(
        account_route(
            &server,
            "/v1/first-party/signup/finish",
            &serde_json::to_vec(&denied).unwrap()
        )
        .err(),
        Some(StatusCode::TOO_MANY_REQUESTS)
    );
    signed_login(&server, &alice, &alice_signer);
    recover(&server, &alice, &recovery_code, "alice-second-device", 64)
        .expect("a signup quota must not disable canonical recovery");

    // Expired quota entries are removed; the process-local gate is not a
    // permanent lockout after a burst.
    let after_window = Instant::now()
        .checked_add(SIGNUP_WINDOW + Duration::from_secs(1))
        .expect("bounded monotonic test clock advance");
    admit_signup_at(&server, after_window).expect("expired quota entries must be pruned");
    assert_eq!(server.signup_admissions.lock().unwrap().len(), 1);
    signup(&server, 65);
}

#[test]
fn guessed_recovery_credentials_cannot_exhaust_valid_recovery_capacity() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, alice_signer, recovery_code) = signup(&server, 81);

    // Leave exactly one slot. An invalid but correctly self-signed proof
    // must not take it from a holder of the real canonical recovery code.
    {
        let mut untrusted = server.recovery_consumed.lock().unwrap();
        untrusted.clear();
        let expiry = Instant::now() + CHALLENGE_TTL;
        for n in 0..(MAX_RECOVERY_CONSUMED - 1) {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&(n as u64).to_be_bytes());
            untrusted.push((tag, expiry));
        }
    }
    // Even a full anonymous signup replay pool must not disable recovery.
    {
        let mut signup = server.untrusted_consumed.lock().unwrap();
        let expiry = Instant::now() + CHALLENGE_TTL;
        for n in 0..MAX_UNTRUSTED_CONSUMED {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&(n as u64).to_be_bytes());
            signup.push((tag, expiry));
        }
    }
    let guessed = URL_SAFE_NO_PAD.encode([99u8; 32]);
    assert_eq!(
        recover(&server, &alice, &guessed, "attacker-device", 82).err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        server.recovery_consumed.lock().unwrap().len(),
        MAX_RECOVERY_CONSUMED - 1,
        "invalid recovery code must not spend a shared replay slot"
    );
    recover(&server, &alice, &recovery_code, "alice-recovered", 83)
        .expect("valid recovery must retain its replay capacity");
    assert_eq!(
        server.recovery_consumed.lock().unwrap().len(),
        MAX_RECOVERY_CONSUMED
    );
    signed_login(&server, &alice, &alice_signer);
}

#[test]
fn successful_recovery_challenge_cannot_be_replayed_with_rotated_code() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, _signer, recovery_code) = signup(&server, 84);
    let binding = Binding {
        device: "recovered-once".to_owned(),
        ..alice
    };
    let (issued, _) = account_route(
        &server,
        "/v1/first-party/recover/begin",
        &serde_json::to_vec(&binding).unwrap(),
    )
    .expect("recovery challenge");
    let signer = SigningKey::from_bytes(&[85; 32]);
    let mut finish = proof(
        &binding,
        "key-85",
        &signer,
        &issued,
        "ucr-first-party-recover.v1",
    );
    finish["recoveryCode"] = json!(recovery_code);
    let (first, _) = account_route(
        &server,
        "/v1/first-party/recover/finish",
        &serde_json::to_vec(&finish).unwrap(),
    )
    .expect("first credential rotation");
    finish["recoveryCode"] = first["recoveryCode"].clone();
    assert_eq!(
        account_route(
            &server,
            "/v1/first-party/recover/finish",
            &serde_json::to_vec(&finish).unwrap(),
        )
        .err(),
        Some(StatusCode::UNAUTHORIZED),
        "a consumed challenge must not authorize another credential rotation"
    );
}

#[test]
fn recovery_returns_rotated_code_even_when_browser_session_capacity_is_exhausted() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, _original_signer, old_code) = signup(&server, 90);

    // Fill the global session budget with other identities. The canonical
    // recovery CAS must not strand a rotated secret merely because an
    // unrelated identity consumed the last browser-session slot.
    {
        let mut sessions = server.sessions.lock().unwrap();
        let template = sessions.sessions[0].clone();
        sessions.sessions.clear();
        for n in 0..MAX_SESSIONS {
            let mut other = template.clone();
            other.binding.participant_id = format!("unrelated-{}", n / MAX_SESSIONS_PER_IDENTITY);
            sessions.sessions.push(other);
        }
    }
    let recovered = Binding {
        device: "new-recovery-device".to_owned(),
        ..alice.clone()
    };
    let (issued, _) = account_route(
        &server,
        "/v1/first-party/recover/begin",
        &serde_json::to_vec(&recovered).unwrap(),
    )
    .expect("recovery challenge");
    let signer = SigningKey::from_bytes(&[91; 32]);
    let mut finish = proof(
        &recovered,
        "key-91",
        &signer,
        &issued,
        "ucr-first-party-recover.v1",
    );
    finish["recoveryCode"] = json!(old_code);
    let (response, cookie) = account_route(
        &server,
        "/v1/first-party/recover/finish",
        &serde_json::to_vec(&finish).unwrap(),
    )
    .expect("committed recovery must still return the rotated secret");
    assert!(
        cookie.is_none(),
        "global session capacity must remain enforced"
    );
    let next_code = response["recoveryCode"]
        .as_str()
        .expect("the committed recovery code must be delivered")
        .to_owned();
    assert_ne!(next_code, old_code);

    // The endpoint owns the new signer; once session capacity is available it
    // can independently authenticate, and the returned code can recover again.
    server.sessions.lock().unwrap().sessions.clear();
    signed_login(&server, &recovered, &signer);
    recover(&server, &alice, &next_code, "subsequent-recovery", 92)
        .expect("returned recovery code remains usable");
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
        recover(&server, &alice, &alice_recovery, "alice-replay-device", 21).err(),
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
                .active_trusted_signing_key(&scope(binding).unwrap(), &device(binding).unwrap())
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(restarted.sessions.lock().unwrap().sessions.len(), 4);
    // Revoke B's recovered Device via the canonical owner, then verify that
    // its old signer is rejected even after another complete server restart.
    verify_revoked_device_stays_revoked(
        &db,
        restarted,
        &bob_two,
        &bob_second_signer,
        &alice,
        &alice_signer,
    );
}

fn verify_revoked_device_stays_revoked(
    db: &TestDb,
    restarted: State,
    bob_two: &Binding,
    bob_second_signer: &SigningKey,
    alice: &Binding,
    alice_signer: &SigningKey,
) {
    restarted
        .store
        .revoke_device(
            &scope(bob_two).unwrap(),
            &device(bob_two).unwrap(),
            &identity(bob_two).unwrap(),
        )
        .unwrap();
    drop(restarted);
    let revoked = state(&db.0);
    assert!(login_route(&revoked, "/v1/first-party/login/verify", b"{}").is_err());
    let (challenge, _) = login_route(
        &revoked,
        "/v1/first-party/login/challenge",
        &serde_json::to_vec(bob_two).unwrap(),
    )
    .unwrap();
    let signed_payload = encoded_proof(
        "ucr-first-party-device-login.v1",
        &json!([
            bob_two.tenant_id,
            bob_two.namespace_id,
            bob_two.participant_id,
            bob_two.device,
            challenge["challengeId"].as_str().unwrap(),
            challenge["challengeBytesBase64Url"].as_str().unwrap()
        ]),
    )
    .unwrap();
    let proof = json!({
        "binding": bob_two,
        "challengeId": challenge["challengeId"],
        "signatureBase64Url": URL_SAFE_NO_PAD.encode(
            bob_second_signer.sign(signed_payload.as_bytes()).to_bytes())
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
    signed_login(&revoked, alice, alice_signer);
}

fn session_of(state: &State, binding: &Binding) -> Session {
    state
        .sessions
        .lock()
        .unwrap()
        .sessions
        .iter()
        .rev()
        .find(|session| session.binding == *binding)
        .cloned()
        .expect("authenticated first-party session")
}

fn call(state: &State, binding: &Binding, path: &str, body: &Value) -> Result<Value, StatusCode> {
    let session = session_of(state, binding);
    call_route(state, &session, path, &serde_json::to_vec(body).unwrap())
}

fn join_accepted(
    state: &State,
    binding: &Binding,
    call_id: &str,
    revision: u64,
) -> Result<Value, StatusCode> {
    call(
        state,
        binding,
        "/v1/first-party/call/join-accepted",
        &json!({"binding": binding, "callId": call_id, "expectedRevision": revision}),
    )
}

fn signal(
    state: &State,
    binding: &Binding,
    call_id: &str,
    revision: u64,
    action: &str,
) -> Result<Value, StatusCode> {
    call(
        state,
        binding,
        "/v1/first-party/call/signal",
        &json!({"binding": binding, "callId": call_id, "expectedRevision": revision, "action": action}),
    )
}

fn realtime_join_request(
    claims: &ucr_realtime::RealtimeSessionClaims,
    token: &str,
) -> tonic::Request<ucr_api_grpc::pb::RealtimeJoinRequest> {
    use ucr_api_grpc::pb;
    let mut request = tonic::Request::new(pb::RealtimeJoinRequest {
        scope: Some(pb::TenantScope {
            tenant_id: Some(pb::OpaqueId {
                value: claims.scope.tenant_id.as_opaque().as_wire_bytes().to_vec(),
            }),
            namespace_id: claims
                .scope
                .namespace_id
                .as_ref()
                .map(|namespace| pb::OpaqueId {
                    value: namespace.as_opaque().as_wire_bytes().to_vec(),
                }),
        }),
        call_id: Some(pb::OpaqueId {
            value: claims.call_id.as_opaque().as_wire_bytes().to_vec(),
        }),
        session_id: Some(pb::OpaqueId {
            value: claims.session_id.as_opaque().as_wire_bytes().to_vec(),
        }),
    });
    request.metadata_mut().insert(
        ucr_api_grpc::REALTIME_AUTHORIZATION_METADATA_KEY,
        format!("Bearer {token}").parse().unwrap(),
    );
    request
}

/// Regression: a first-party direct Call started through `/start` was refused
/// by Realtime with 401 "realtime join rejected" because Realtime admits only
/// Group Calls. Both accepted participants must now be admitted to the derived
/// media Group Call through the SAME issuer and canonical `SQLite` owner, while
/// a third party, an unaccepted callee and a hung-up Call stay refused.
#[tokio::test]
#[allow(clippy::too_many_lines)] // One end-to-end acceptance narrative.
async fn first_party_direct_call_is_admitted_to_realtime_for_both_accepted_participants_only() {
    use ucr_api_grpc::{
        GrpcRealtimeService, pb, pb::realtime_service_server::RealtimeService as _,
    };
    use ucr_core::{CallStore, GroupStore};
    use ucr_model::{GroupMemberState, PrincipalRef};

    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, _, _) = signup(&server, 41);
    let (bob, _, _) = signup(&server, 42);
    let (carol, _, _) = signup(&server, 43);

    // The non-loginable media host is never a callable contact.
    assert_eq!(
        call(
            &server,
            &alice,
            "/v1/first-party/call/start",
            &json!({"binding": alice, "intent": {"peerIdentityId": "fp-media-host", "media": "video", "idempotencyKey": "host"}}),
        )
        .err(),
        Some(StatusCode::NOT_FOUND)
    );
    let started = call(
        &server,
        &alice,
        "/v1/first-party/call/start",
        &json!({"binding": alice, "intent": {"peerIdentityId": bob.participant_id, "media": "video", "idempotencyKey": "media-acceptance"}}),
    )
    .expect("canonical direct Call start");
    let call_id = started["callId"].as_str().unwrap().to_owned();
    let revision = started["revision"].as_u64().unwrap();

    // Before the callee accepted, nobody gets media authority.
    assert_eq!(
        join_accepted(&server, &alice, &call_id, revision).err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        join_accepted(&server, &bob, &call_id, revision).err(),
        Some(StatusCode::FORBIDDEN)
    );
    let accepted = signal(&server, &bob, &call_id, revision, "accept").expect("callee accepts");
    assert_eq!(accepted["state"], "active");
    let revision = accepted["revision"].as_u64().unwrap();
    // A third person never sees nor joins the Call.
    assert!(join_accepted(&server, &carol, &call_id, revision).is_err());

    let grants = [&alice, &bob].map(|binding| {
        join_accepted(&server, binding, &call_id, revision).expect("accepted participant Join")
    });
    let tokens = grants.clone().map(|grant| {
        // The SDK contract is unchanged: the response names the direct Call.
        assert_eq!(grant["callId"], call_id.as_str());
        grant["joinFragment"]
            .as_str()
            .unwrap()
            .strip_prefix("#ucr_join=")
            .unwrap()
            .to_owned()
    });
    let claims = tokens.clone().map(|token| {
        server
            .issuer
            .verify_signed_claims(&token, now_unix_ms().unwrap())
            .expect("first-party grant signed by the realtime issuer")
    });
    // Both grants name ONE derived media Group Call, bound to the exact Device.
    assert_eq!(claims[0].call_id, claims[1].call_id);
    assert!(claims[0].call_id.as_opaque().as_str().starts_with("fp-m-"));
    assert_ne!(claims[0].call_id.as_opaque().as_str(), call_id);
    assert_eq!(
        claims[0].device_id.as_ref().map(|d| d.as_opaque().as_str()),
        Some(alice.device.as_str())
    );
    assert_eq!(
        claims[1].device_id.as_ref().map(|d| d.as_opaque().as_str()),
        Some(bob.device.as_str())
    );

    // Repeating the Join is idempotent and keeps the media Group exact.
    join_accepted(&server, &alice, &call_id, revision).expect("idempotent re-prepare");
    let media = server
        .store
        .call(&claims[0].scope, &claims[0].call_id)
        .unwrap()
        .expect("media Call");
    assert_eq!(media.participants.len(), 2);
    let group_id = first_party_media::media_runtime_ids(
        &claims[0].scope,
        &CallId::from_opaque(opaque(&call_id).unwrap()),
    )
    .unwrap()
    .group_id;
    let members = server
        .store
        .group_memberships(&claims[0].scope, &group_id, 16)
        .unwrap()
        .into_iter()
        .filter(|membership| membership.state == GroupMemberState::Active)
        .map(|membership| membership.member)
        .collect::<Vec<PrincipalRef>>();
    assert_eq!(
        members.len(),
        3,
        "exactly host + both participants: {members:?}"
    );
    assert!(members.contains(&claims[0].participant));
    assert!(members.contains(&claims[1].participant));

    // The real gRPC Realtime owner over the SAME SQLite store and issuer.
    let realtime = GrpcRealtimeService::new(
        Arc::new(ucr_core::SystemServiceQuotaClock),
        Arc::clone(&server.store),
        Arc::clone(&server.store),
        Arc::clone(&server.issuer),
        Arc::new(ucr_realtime::RealtimeSessionRegistry::new(16, 4)),
        Arc::new(ucr_conference::ConferenceRuntimeState::new()),
    )
    .with_mls_admission_store(Arc::clone(&server.store));
    let mut generations = Vec::new();
    for (claim, token) in claims.iter().zip(&tokens) {
        let joined = realtime
            .join_realtime(realtime_join_request(claim, token))
            .await
            .unwrap()
            .into_inner();
        match joined.result {
            Some(pb::realtime_join_response::Result::Session(session)) => {
                assert_eq!(
                    session.admission_state,
                    pb::RealtimeAdmissionState::Admitted as i32
                );
                generations.push(session.session_sequence);
            }
            other => panic!("direct-call participant was not admitted: {other:?}"),
        }
    }
    // Heartbeat keeps the Join generation fence.
    for ((claim, token), generation) in claims.iter().zip(&tokens).zip(&generations) {
        let join = realtime_join_request(claim, token).into_inner();
        for (sequence, ok) in [(*generation, true), (generation + 1, false)] {
            let mut beat = tonic::Request::new(pb::RealtimeHeartbeatRequest {
                scope: join.scope.clone(),
                call_id: join.call_id.clone(),
                session_id: join.session_id.clone(),
                expected_session_sequence: sequence,
            });
            beat.metadata_mut().insert(
                ucr_api_grpc::REALTIME_AUTHORIZATION_METADATA_KEY,
                format!("Bearer {token}").parse().unwrap(),
            );
            let result = realtime
                .heartbeat_realtime(beat)
                .await
                .unwrap()
                .into_inner()
                .result;
            assert_eq!(
                matches!(
                    result,
                    Some(pb::realtime_heartbeat_response::Result::Acknowledgement(_))
                ),
                ok,
                "heartbeat sequence {sequence}: {result:?}"
            );
        }
    }

    // A plain media Group Call has no Universal mute policy: a speaking level
    // is accepted (regression: every level > 0 was refused with 409).
    let audio = |claim: &ucr_realtime::RealtimeSessionClaims, token: &str| {
        let join = realtime_join_request(claim, token).into_inner();
        let mut request = tonic::Request::new(pb::RealtimeReportAudioLevelRequest {
            scope: join.scope,
            call_id: join.call_id,
            session_id: join.session_id,
            level: 42,
        });
        request.metadata_mut().insert(
            ucr_api_grpc::REALTIME_AUTHORIZATION_METADATA_KEY,
            format!("Bearer {token}").parse().unwrap(),
        );
        request
    };
    let level = realtime
        .report_audio_level(audio(&claims[0], &tokens[0]))
        .await
        .unwrap()
        .into_inner();
    assert!(
        matches!(
            level.result,
            Some(pb::realtime_report_audio_level_response::Result::Acknowledgement(_))
        ),
        "{level:?}"
    );

    // Hang-up ends the media Call too; no new Join grant and no re-admission.
    let hung = signal(&server, &bob, &call_id, revision, "hangup").expect("hangup");
    assert_eq!(hung["state"], "terminated");
    let media = server
        .store
        .call(&claims[0].scope, &claims[0].call_id)
        .unwrap()
        .unwrap();
    assert_eq!(media.signalling_state, CallSignallingState::Terminated);
    assert!(
        join_accepted(
            &server,
            &alice,
            &call_id,
            hung["revision"].as_u64().unwrap()
        )
        .is_err()
    );
    let rejoin = realtime
        .join_realtime(realtime_join_request(&claims[0], &tokens[0]))
        .await
        .unwrap()
        .into_inner();
    assert!(
        matches!(
            rejoin.result,
            Some(pb::realtime_join_response::Result::Error(_))
        ),
        "ended direct Call must not be re-admitted: {rejoin:?}"
    );
    // An already-open session of the ended Call cannot keep heartbeating.
    let join = realtime_join_request(&claims[1], &tokens[1]).into_inner();
    let mut beat = tonic::Request::new(pb::RealtimeHeartbeatRequest {
        scope: join.scope,
        call_id: join.call_id,
        session_id: join.session_id,
        expected_session_sequence: generations[1],
    });
    beat.metadata_mut().insert(
        ucr_api_grpc::REALTIME_AUTHORIZATION_METADATA_KEY,
        format!("Bearer {}", tokens[1]).parse().unwrap(),
    );
    let after = realtime
        .heartbeat_realtime(beat)
        .await
        .unwrap()
        .into_inner();
    assert!(
        matches!(
            after.result,
            Some(pb::realtime_heartbeat_response::Result::Error(_))
        ),
        "{after:?}"
    );
}

/// Regression: 512 anonymous challenge requests used to fill ONE global pending
/// pool and answer 429 to every user for 90 s. Challenges are now stateless
/// (MAC-sealed, bound to binding/purpose/key) and only verified proofs are
/// remembered, so a flood cannot lock anybody out, while replay, tampering
/// and cross-purpose use stay rejected.
#[test]
fn anonymous_challenge_flood_cannot_lock_out_signup_or_login() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, alice_signer, _) = signup(&server, 51);
    for _ in 0..4096 {
        account_route(&server, "/v1/first-party/signup/begin", b"{}").expect("never 429");
        login_route(
            &server,
            "/v1/first-party/login/challenge",
            &serde_json::to_vec(&alice).unwrap(),
        )
        .expect("never 429");
    }
    assert!(server.consumed.lock().unwrap().len() <= 1);
    // Everybody can still sign up and log in.
    let (bob, _, _) = signup(&server, 52);
    signed_login(&server, &alice, &alice_signer);
    assert_ne!(alice.participant_id, bob.participant_id);

    let (issued, _) = login_route(
        &server,
        "/v1/first-party/login/challenge",
        &serde_json::to_vec(&alice).unwrap(),
    )
    .unwrap();
    let sign = |challenge_id: &str, nonce: &str| {
        let payload = encoded_proof(
            "ucr-first-party-device-login.v1",
            &json!([
                alice.tenant_id,
                alice.namespace_id,
                alice.participant_id,
                alice.device,
                challenge_id,
                nonce
            ]),
        )
        .unwrap();
        URL_SAFE_NO_PAD.encode(alice_signer.sign(payload.as_bytes()).to_bytes())
    };
    let id = issued["challengeId"].as_str().unwrap();
    let nonce = issued["challengeBytesBase64Url"].as_str().unwrap();
    let verify = |binding: &Binding, challenge_id: &str, signature: String| {
        login_route(
            &server,
            "/v1/first-party/login/verify",
            &serde_json::to_vec(&json!({"binding": binding, "challengeId": challenge_id, "signatureBase64Url": signature})).unwrap(),
        )
        .map(|_| ())
    };
    // A wrong signature does not spend the challenge...
    let mut bad = sign(id, nonce);
    bad.replace_range(0..2, if bad.starts_with("AA") { "BB" } else { "AA" });
    assert!(verify(&alice, id, bad).is_err());
    // ...a tampered id or another binding is refused...
    let mut tampered = URL_SAFE_NO_PAD.decode(id).unwrap();
    tampered[3] ^= 1;
    let tampered = URL_SAFE_NO_PAD.encode(tampered);
    assert_eq!(
        verify(&alice, &tampered, sign(&tampered, nonce)),
        Err(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        verify(&bob, id, sign(id, nonce)),
        Err(StatusCode::UNAUTHORIZED)
    );
    // ...a signup challenge never serves as a login challenge...
    let (signup_issued, _) = account_route(&server, "/v1/first-party/signup/begin", b"{}").unwrap();
    let signup_id = signup_issued["challengeId"].as_str().unwrap();
    assert_eq!(
        verify(
            &alice,
            signup_id,
            sign(
                signup_id,
                signup_issued["challengeBytesBase64Url"].as_str().unwrap()
            )
        ),
        Err(StatusCode::UNAUTHORIZED)
    );
    // ...the genuine proof succeeds exactly once.
    verify(&alice, id, sign(id, nonce)).expect("genuine login");
    assert_eq!(
        verify(&alice, id, sign(id, nonce)),
        Err(StatusCode::UNAUTHORIZED)
    );

    // Repeated logins of one Identity evict only its own oldest sessions.
    for _ in 0..(MAX_SESSIONS_PER_IDENTITY + 4) {
        signed_login(&server, &alice, &alice_signer);
    }
    let sessions = server.sessions.lock().unwrap();
    assert_eq!(
        sessions
            .sessions
            .iter()
            .filter(|s| s.binding.participant_id == alice.participant_id)
            .count(),
        MAX_SESSIONS_PER_IDENTITY
    );
    assert_eq!(
        sessions
            .sessions
            .iter()
            .filter(|s| s.binding.participant_id == bob.participant_id)
            .count(),
        1
    );
}

#[test]
fn logout_atomically_fences_old_login_verify_and_retires_all_device_cookies() {
    let db = TestDb::new();
    let server = state(&db.0);
    let (alice, alice_signer, _) = signup(&server, 101);
    let (bob, bob_signer, _) = signup(&server, 102);
    signed_login(&server, &alice, &alice_signer);
    let old_session = session_of(&server, &alice);
    assert!(
        server
            .sessions
            .lock()
            .unwrap()
            .sessions
            .iter()
            .filter(|session| session.binding == alice)
            .count()
            >= 2
    );

    // Both challenges are issued BEFORE Alice logs out. A Device logout must
    // invalidate Alice's pending signed proof without locking out Bob.
    let (alice_challenge, _) = login_route(
        &server,
        "/v1/first-party/login/challenge",
        &serde_json::to_vec(&alice).unwrap(),
    )
    .unwrap();
    let (bob_challenge, _) = login_route(
        &server,
        "/v1/first-party/login/challenge",
        &serde_json::to_vec(&bob).unwrap(),
    )
    .unwrap();
    let make_proof = |binding: &Binding, signer: &SigningKey, issued: &Value| {
        let signed = encoded_proof(
            "ucr-first-party-device-login.v1",
            &json!([
                binding.tenant_id,
                binding.namespace_id,
                binding.participant_id,
                binding.device,
                issued["challengeId"],
                issued["challengeBytesBase64Url"],
            ]),
        )
        .unwrap();
        serde_json::to_vec(&json!({
            "binding": binding,
            "challengeId": issued["challengeId"],
            "signatureBase64Url": URL_SAFE_NO_PAD.encode(
                signer.sign(signed.as_bytes()).to_bytes()
            ),
        }))
        .unwrap()
    };
    let alice_proof = make_proof(&alice, &alice_signer, &alice_challenge);
    let bob_proof = make_proof(&bob, &bob_signer, &bob_challenge);

    // Deterministic concurrency interleaving: signature was verified and its
    // challenge consumed, but the response/cookie has NOT been issued yet.
    let parsed: LoginProof = parse(&alice_proof).unwrap();
    let pending = consume(&server, &alice, &parsed.challenge_id, "login", None).unwrap();
    let subject = subject_for(&server, &alice).unwrap();
    let (key_id, public_key) = trusted_key(&server, &alice).unwrap();
    let signed = encoded_proof(
        "ucr-first-party-device-login.v1",
        &json!([
            alice.tenant_id,
            alice.namespace_id,
            alice.participant_id,
            alice.device,
            pending.id,
            pending.nonce,
        ]),
    )
    .unwrap();
    verify_ed25519(public_key, &signed, &parsed.signature_base64_url).unwrap();
    spend(&server, &pending).unwrap();

    let (response, clear_cookie) = dispatch_post(
        &server,
        "/v1/first-party/logout",
        &serde_json::to_vec(&json!({"binding": alice})).unwrap(),
        Some(&old_session),
    )
    .unwrap();
    assert_eq!(response["signedOut"], true);
    assert!(clear_cookie.unwrap().contains("Max-Age=0"));
    assert_eq!(
        server
            .sessions
            .lock()
            .unwrap()
            .sessions
            .iter()
            .filter(|session| session.binding == alice)
            .count(),
        0,
        "Logout must retire even a newer cookie issued before its completion"
    );

    assert_eq!(
        issue_session(
            &server,
            alice.clone(),
            subject,
            key_id,
            public_key,
            pending.login_generation,
        )
        .err(),
        Some(StatusCode::UNAUTHORIZED),
        "verified pre-Logout login must not issue a cookie after Logout"
    );
    assert_eq!(
        login_route(&server, "/v1/first-party/login/verify", &alice_proof).err(),
        Some(StatusCode::UNAUTHORIZED),
        "a signed pre-Logout challenge must fail even if verification starts late"
    );
    assert_eq!(
        dispatch_post(
            &server,
            "/v1/first-party/logout",
            &serde_json::to_vec(&json!({"binding": alice})).unwrap(),
            Some(&old_session),
        )
        .err(),
        Some(StatusCode::UNAUTHORIZED),
        "a retired cookie cannot execute a second Logout"
    );
    login_route(&server, "/v1/first-party/login/verify", &bob_proof)
        .expect("another Device's pre-Logout challenge must remain valid");
    signed_login(&server, &alice, &alice_signer);
}

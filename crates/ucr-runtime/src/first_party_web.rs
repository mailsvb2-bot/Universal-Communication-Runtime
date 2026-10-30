//! First-party same-origin BFF for independently proved canonical human Devices.
//! This module shares the production `SQLite` and `JoinTokenIssuer` with realtime.
//! It deliberately does not bootstrap Root Identities or silently trust a new Device.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signature, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use ucr_core::{
    AuthorizedDurableRuntime, DeviceLifecycleStore, IdentityDeviceLookupStore, IdentityStore,
    PrincipalIdentityBindingStore, PrincipalIdentityLookupStore, TrustedSigningKeyStore,
    generate_opaque_id,
};
use ucr_model::{
    CallId, CallParticipant, CallParticipantState, CallSession, CallSignal, CallSignalKind,
    CallSignallingState, CallTerminationReason, ConversationId, ConversationKind,
    ConversationRecord, ConversationRef, DeviceDescriptor, DeviceId, DeviceLifecycleState, EventId,
    IdentityId, KeyId, KeyPurpose, NamespaceId, OpaqueId, PrincipalKind, PublicKeyDescriptor,
    ScopedPrincipal, TenantId, TenantScope,
};
use ucr_realtime::{DEFAULT_JOIN_TTL_SECONDS, JoinTokenIssuer};
use ucr_storage_sqlite::SqliteLocalStore;

use crate::first_party_media;

const MAX_BODY: usize = 16 * 1024;
/// Successfully proven challenges remembered (only until expiry) to reject replay.
/// Unproven challenges consume NO server memory, so anonymous challenge
/// requests can never exhaust a shared pool and lock other users out.
const MAX_CONSUMED: usize = 1 << 16;
/// Anonymous self-service proofs cannot consume the replay capacity reserved
/// for independently authenticated login and Device operations.
const MAX_UNTRUSTED_CONSUMED: usize = 1024;
/// A successful recovery must not compete with unauthenticated signup traffic.
const MAX_RECOVERY_CONSUMED: usize = 1024;
/// Per-process signup budget; this is defense in depth, NOT a substitute for
/// ingress-wide abuse controls and independently approved enrollment policy.
const MAX_SELF_SERVICE_SIGNUPS: usize = 256;
const SIGNUP_WINDOW: Duration = Duration::from_mins(10);
/// Global memory bound on live sessions; each Identity keeps at most
/// `MAX_SESSIONS_PER_IDENTITY`, evicting only its OWN oldest session.
const MAX_SESSIONS: usize = 1 << 16;
const MAX_SESSIONS_PER_IDENTITY: usize = 16;
const CHALLENGE_VERSION: u8 = 1;
const CHALLENGE_TTL: Duration = Duration::from_secs(90);
const SESSION_TTL: Duration = Duration::from_mins(30);
const COOKIE_NAME: &str = "__Host-ucr_fp";
type HttpResponse = Response<Full<Bytes>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    tenant_id: String,
    namespace_id: Option<String>,
    participant_id: String,
    #[serde(rename = "deviceId")]
    device: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginProof {
    binding: Binding,
    challenge_id: String,
    signature_base64_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceChallenge {
    binding: Binding,
    key_id: String,
    public_key_base64_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceApproval {
    binding: Binding,
    key_id: String,
    public_key_base64_url: String,
    challenge_id: String,
    signature_base64_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoundRequest {
    binding: Binding,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountFinish {
    binding: Binding,
    challenge_id: String,
    key_id: String,
    public_key_base64_url: String,
    signature_base64_url: String,
    recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevokeRequest {
    binding: Binding,
    device_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartRequest {
    binding: Binding,
    intent: StartIntent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartIntent {
    peer_identity_id: String,
    media: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GetRequest {
    binding: Binding,
    call_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignalRequest {
    binding: Binding,
    call_id: String,
    expected_revision: u64,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JoinRequest {
    binding: Binding,
    call_id: String,
    expected_revision: u64,
}

#[derive(Debug, Clone)]
struct Pending {
    purpose: &'static str,
    /// Authenticated replay tag of the proven challenge.
    tag: [u8; 32],
    id: String,
    nonce: String,
    key_id: Option<String>,
    public_key: Option<[u8; 32]>,
    until: Instant,
    login_generation: Option<u64>,
}

#[derive(Debug, Clone)]
struct Session {
    token: String,
    binding: Binding,
    subject: ScopedPrincipal,
    signer_key_id: String,
    signer_public_key: [u8; 32],
    until: Instant,
}

// Login and Logout share ONE lock: a completed Logout revokes every session
// for that Device, and a pre-Logout challenge can never issue a later cookie.
// This is process-local, like the existing session pool; multi-process BFF
// authentication remains a separate release gate.
#[derive(Debug, Default)]
struct SessionLedger {
    sessions: Vec<Session>,
    // Short-lived Device-specific challenge fences, not a second Identity store.
    login_generations: HashMap<Binding, (u64, Instant)>,
    next_generation: u64,
    global_generation: u64,
}

impl SessionLedger {
    fn generation(&self, binding: &Binding) -> u64 {
        self.login_generations
            .get(binding)
            .filter(|(_, until)| *until > Instant::now())
            .map_or(self.global_generation, |(generation, _)| {
                (*generation).max(self.global_generation)
            })
    }

    fn revoke_device(&mut self, binding: &Binding) {
        self.sessions.retain(|session| &session.binding != binding);
        let now = Instant::now();
        self.login_generations.retain(|_, (_, until)| *until > now);
        self.next_generation = self.next_generation.saturating_add(1);
        if self.login_generations.len() >= MAX_SESSIONS
            && !self.login_generations.contains_key(binding)
        {
            // Never drop a live fence to admit an old challenge: conservatively
            // invalidate all pending logins on exceptional capacity pressure.
            self.global_generation = self.next_generation;
            self.login_generations.clear();
        }
        self.login_generations.insert(
            binding.clone(),
            (self.next_generation, now + CHALLENGE_TTL + CHALLENGE_TTL),
        );
    }
}

#[derive(Debug)]
struct State {
    store: Arc<SqliteLocalStore>,
    issuer: Arc<JoinTokenIssuer>,
    origin: String,
    registration_scope: Option<TenantScope>,
    /// Per-process MAC key sealing stateless challenges. A restart voids them.
    challenge_key: [u8; 32],
    consumed: Mutex<Vec<([u8; 32], Instant)>>,
    untrusted_consumed: Mutex<Vec<([u8; 32], Instant)>>,
    recovery_consumed: Mutex<Vec<([u8; 32], Instant)>>,
    signup_admissions: Mutex<Vec<Instant>>,
    sessions: Mutex<SessionLedger>,
    // One in-process serialization gate per canonical Device. Weak entries are
    // pruned so anonymous/retired Devices cannot grow this map without bound.
    protected_actions: Mutex<HashMap<Binding, Weak<Mutex<()>>>>,
}

#[derive(Debug)]
pub(super) struct Configuration {
    bind: SocketAddr,
    origin: String,
    registration_scope: Option<TenantScope>,
}

impl Configuration {
    pub(super) fn from_env() -> Result<Option<Self>, String> {
        let Ok(raw) = std::env::var("UCR_FIRST_PARTY_BIND") else {
            return Ok(None);
        };
        let bind: SocketAddr = raw.parse().map_err(|_| "invalid UCR_FIRST_PARTY_BIND")?;
        if !bind.ip().is_loopback() {
            return Err("first-party BFF must bind loopback behind a trusted HTTPS edge".into());
        }
        let origin = std::env::var("UCR_FIRST_PARTY_PUBLIC_ORIGIN")
            .map_err(|_| "UCR_FIRST_PARTY_PUBLIC_ORIGIN is required")?;
        if !origin.starts_with("https://")
            || origin.contains('/') && origin["https://".len()..].contains('/')
            || origin.contains('#')
            || origin.contains('?')
            || origin.chars().any(char::is_whitespace)
        {
            return Err("first-party public origin must be an exact HTTPS origin".into());
        }
        let registration_scope = std::env::var("UCR_FIRST_PARTY_SELF_SERVICE_TENANT")
            .ok()
            .map(|tenant| {
                opaque(&tenant)
                    .map(TenantId::from_opaque)
                    .map(|tenant_id| TenantScope {
                        tenant_id,
                        namespace_id: None,
                    })
                    .map_err(|_| "invalid self-service Tenant ID".to_owned())
            })
            .transpose()?;
        Ok(Some(Self {
            bind,
            origin,
            registration_scope,
        }))
    }
}

pub(super) async fn serve(
    config: Configuration,
    store: Arc<SqliteLocalStore>,
    issuer: Arc<JoinTokenIssuer>,
) -> Result<(), String> {
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("bind first-party BFF: {error}"))?;
    let state = Arc::new(State {
        store,
        issuer,
        origin: config.origin,
        registration_scope: config.registration_scope,
        challenge_key: random_key().map_err(|_| "first-party challenge key unavailable")?,
        consumed: Mutex::new(Vec::new()),
        untrusted_consumed: Mutex::new(Vec::new()),
        recovery_consumed: Mutex::new(Vec::new()),
        signup_admissions: Mutex::new(Vec::new()),
        sessions: Mutex::new(SessionLedger::default()),
        protected_actions: Mutex::new(HashMap::new()),
    });
    println!(
        "UCR_FIRST_PARTY_READY loopback={} https_edge=required",
        config.bind
    );
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("BFF accept: {e}"))?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |request| route(request, Arc::clone(&state)));
            let builder = auto::Builder::new(TokioExecutor::new());
            if let Err(error) = builder.serve_connection(io, service).await {
                eprintln!("ucr-first-party-web: connection closed: {error}");
            }
        });
    }
}

fn api_error(status: StatusCode) -> HttpResponse {
    reply(status, &json!({"error": status.as_str()}), None)
}

fn reply(status: StatusCode, body: &Value, cookie: Option<&str>) -> HttpResponse {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut result = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header(CACHE_CONTROL, "no-store, private")
        .header("Pragma", "no-cache")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Content-Security-Policy", "default-src 'none'")
        .body(Full::new(Bytes::from(bytes)))
        .expect("static response headers");
    if let Some(value) = cookie
        && let Ok(cookie) = hyper::header::HeaderValue::from_str(value)
    {
        result.headers_mut().insert(SET_COOKIE, cookie);
    }
    result
}

fn opaque(value: &str) -> Result<OpaqueId, StatusCode> {
    if value.is_empty()
        || value.len() > 120
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@'))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    OpaqueId::new(value).map_err(|_| StatusCode::BAD_REQUEST)
}

fn scope(binding: &Binding) -> Result<TenantScope, StatusCode> {
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(opaque(&binding.tenant_id)?),
        namespace_id: binding
            .namespace_id
            .as_deref()
            .map(opaque)
            .transpose()?
            .map(NamespaceId::from_opaque),
    })
}

fn identity(binding: &Binding) -> Result<IdentityId, StatusCode> {
    Ok(IdentityId::from_opaque(opaque(&binding.participant_id)?))
}

fn device(binding: &Binding) -> Result<DeviceId, StatusCode> {
    Ok(DeviceId::from_opaque(opaque(&binding.device)?))
}

fn now_unix_ms() -> Result<i64, StatusCode> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn subject_for(state: &State, binding: &Binding) -> Result<ScopedPrincipal, StatusCode> {
    let scope = scope(binding)?;
    let identity = identity(binding)?;
    let device_id = device(binding)?;
    let record = state
        .store
        .identity(&scope, &identity)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if record
        .expires_at_unix_ms
        .is_some_and(|expires| now_unix_ms().map_or(true, |now| now >= expires))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let candidates = state
        .store
        .principal_identity_bindings_for_identity_kind(&scope, &identity, PrincipalKind::Person, 2)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if candidates.len() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let descriptor = state
        .store
        .device(&scope, &device_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if descriptor.identity_id != identity || descriptor.state != DeviceLifecycleState::Active {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let active = state
        .store
        .active_trusted_signing_key(&scope, &device_id)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if active.device_id != device_id
        || active.purpose != ucr_model::KeyPurpose::Signing
        || active.public_key.len() != 32
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(ScopedPrincipal {
        scope,
        principal: candidates[0].principal.clone(),
    })
}

fn trusted_key(state: &State, binding: &Binding) -> Result<(String, [u8; 32]), StatusCode> {
    let key = state
        .store
        .active_trusted_signing_key(&scope(binding)?, &device(binding)?)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let raw: [u8; 32] = key
        .public_key
        .try_into()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok((key.key_id.as_opaque().as_str().to_owned(), raw))
}

fn verify_ed25519(pubkey: [u8; 32], proof: &str, signature: &str) -> Result<(), StatusCode> {
    let raw = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let raw: [u8; 64] = raw.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let verifier = VerifyingKey::from_bytes(&pubkey).map_err(|_| StatusCode::UNAUTHORIZED)?;
    verifier
        .verify_strict(proof.as_bytes(), &Signature::from_bytes(&raw))
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

fn nonce() -> Result<String, StatusCode> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn random_key() -> Result<[u8; 32], StatusCode> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(key)
}

type ChallengeMac = hmac::Hmac<Sha256>;

fn current_login_generation(state: &State, binding: &Binding) -> Result<u64, StatusCode> {
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(sessions.generation(binding))
}

// Explicitly bind the MAC to one purpose, signer descriptor and Logout epoch.
#[derive(Clone, Copy)]
struct ChallengeMacContext<'a> {
    purpose: &'a str,
    key_id: Option<&'a str>,
    public_key: Option<&'a [u8; 32]>,
    login_generation: Option<u64>,
}

/// MAC over the challenge core and EVERYTHING the challenge is bound to.
fn challenge_mac(
    state: &State,
    label: &[u8],
    core: &[u8],
    binding: &Binding,
    context: ChallengeMacContext<'_>,
) -> Result<[u8; 32], StatusCode> {
    use hmac::Mac as _;
    let ChallengeMacContext {
        purpose,
        key_id,
        public_key,
        login_generation,
    } = context;
    let mut mac = <ChallengeMac as hmac::KeyInit>::new_from_slice(&state.challenge_key)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let bound = serde_json::to_vec(&json!([
        purpose,
        binding.tenant_id,
        binding.namespace_id,
        binding.participant_id,
        binding.device,
        key_id,
        public_key.map(|key| URL_SAFE_NO_PAD.encode(key)),
    ]))
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for part in [label, core, &bound] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    if let Some(generation) = login_generation {
        mac.update(&8u64.to_be_bytes());
        mac.update(&generation.to_be_bytes());
    }
    Ok(mac.finalize().into_bytes().into())
}

fn now_ms() -> Result<u64, StatusCode> {
    u64::try_from(now_unix_ms()?).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn challenge(
    state: &State,
    binding: &Binding,
    purpose: &'static str,
    key_id: Option<&str>,
    public_key: Option<[u8; 32]>,
) -> Result<Value, StatusCode> {
    let login_generation = (purpose == "login")
        .then(|| current_login_generation(state, binding))
        .transpose()?;
    // Always one-time and short-lived, but STATELESS: the challenge is sealed
    // with a per-process MAC key, so issuing one allocates no server memory and
    // no anonymous actor can exhaust a shared pool to lock everyone else out.
    // The server does not trust the supplied Identity until signature
    // verification; challenge requests never reveal its existence.
    let expiry = now_ms()?.saturating_add(
        u64::try_from(CHALLENGE_TTL.as_millis()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    let mut core = Vec::with_capacity(25);
    core.push(CHALLENGE_VERSION);
    core.extend_from_slice(&expiry.to_be_bytes());
    core.extend_from_slice(&random_key()?[..16]);
    let context = ChallengeMacContext {
        purpose,
        key_id,
        public_key: public_key.as_ref(),
        login_generation,
    };
    let tag = challenge_mac(
        state,
        b"ucr-first-party-challenge-id.v1",
        &core,
        binding,
        context,
    )?;
    let nonce = challenge_mac(
        state,
        b"ucr-first-party-challenge-nonce.v1",
        &core,
        binding,
        context,
    )?;
    let mut id = core;
    id.extend_from_slice(&tag);
    Ok(json!({
        "challengeId": URL_SAFE_NO_PAD.encode(id),
        "challengeBytesBase64Url": URL_SAFE_NO_PAD.encode(nonce),
    }))
}

/// Opens a sealed challenge for exactly this binding, purpose and key. This
/// does NOT spend it: call [`spend`] only after the proof signature verified,
/// so failed attempts never consume replay memory.
fn consume(
    state: &State,
    binding: &Binding,
    id: &str,
    purpose: &'static str,
    key: Option<(&str, [u8; 32])>,
) -> Result<Pending, StatusCode> {
    use subtle::ConstantTimeEq as _;
    let raw = URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if raw.len() != 25 + 32 || raw[0] != CHALLENGE_VERSION || URL_SAFE_NO_PAD.encode(&raw) != id {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (core, tag) = raw.split_at(25);
    let key_id = key.map(|(key_id, _)| key_id);
    let public_key = key.map(|(_, public_key)| public_key);
    let login_generation = (purpose == "login")
        .then(|| current_login_generation(state, binding))
        .transpose()?;
    let context = ChallengeMacContext {
        purpose,
        key_id,
        public_key: public_key.as_ref(),
        login_generation,
    };
    let expected = challenge_mac(
        state,
        b"ucr-first-party-challenge-id.v1",
        core,
        binding,
        context,
    )?;
    if !bool::from(expected.ct_eq(tag)) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let expiry = u64::from_be_bytes(
        core[1..9]
            .try_into()
            .map_err(|_| StatusCode::UNAUTHORIZED)?,
    );
    let now = now_ms()?;
    if expiry <= now {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let nonce = challenge_mac(
        state,
        b"ucr-first-party-challenge-nonce.v1",
        core,
        binding,
        context,
    )?;
    Ok(Pending {
        purpose,
        tag: expected,
        id: id.to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        key_id: key_id.map(str::to_owned),
        public_key,
        until: Instant::now() + Duration::from_millis(expiry - now),
        login_generation,
    })
}

/// Atomically spends a VERIFIED challenge before any side effect: a replayed
/// or concurrently duplicated proof loses here.
fn spend(state: &State, pending: &Pending) -> Result<(), StatusCode> {
    // A self-signed signup proof is not independently authenticated.
    // Neither signup nor recovery may exhaust the login/Device replay pool.
    let (pool, capacity) = if pending.purpose == "signup" {
        (&state.untrusted_consumed, MAX_UNTRUSTED_CONSUMED)
    } else {
        (&state.consumed, MAX_CONSUMED)
    };
    let mut consumed = pool.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let now = Instant::now();
    consumed.retain(|(_, until)| *until > now);
    if consumed.iter().any(|(tag, _)| *tag == pending.tag) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if consumed.len() >= capacity {
        // A successfully verified but unauthenticated self-service proof may
        // exhaust only its own bounded pool, never existing Device logins.
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    consumed.push((pending.tag, pending.until));
    Ok(())
}

/// Serialize recovery replay admission with the canonical `SQLite` credential CAS.
/// A self-signed proof alone must not consume scarce shared recovery capacity.
/// The challenge is spent only after the existing recovery verifier has been
/// atomically checked and rotated; concurrent reuse of the same challenge
/// cannot rotate two credentials.
fn spend_verified_recovery<T>(
    state: &State,
    pending: &Pending,
    recover: impl FnOnce() -> Result<T, StatusCode>,
) -> Result<T, StatusCode> {
    if pending.purpose != "recover" {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut consumed = state
        .recovery_consumed
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let now = Instant::now();
    consumed.retain(|(_, until)| *until > now);
    if consumed.iter().any(|(tag, _)| *tag == pending.tag) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if consumed.len() >= MAX_RECOVERY_CONSUMED {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Hold the replay lock through the existing SQLite recovery transaction.
    // Failed/guessed credentials cannot spend a shared replay slot.
    let value = recover()?;
    consumed.push((pending.tag, pending.until));
    Ok(value)
}

/// Reserve a bounded anonymous signup slot before writing to canonical `SQLite`.
/// The quota is process-local; multi-instance/global anti-abuse admission is a
/// separate release gate and must not be represented as already enforced.
fn admit_signup(state: &State) -> Result<(), StatusCode> {
    admit_signup_at(state, Instant::now())
}

fn admit_signup_at(state: &State, now: Instant) -> Result<(), StatusCode> {
    let mut admitted = state
        .signup_admissions
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    admitted.retain(|at| now.saturating_duration_since(*at) < SIGNUP_WINDOW);
    if admitted.len() >= MAX_SELF_SERVICE_SIGNUPS {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    admitted.push(now);
    Ok(())
}

fn register_self_service_account(
    state: &State,
    public: &TenantScope,
    account: &IdentityId,
    descriptor: &DeviceDescriptor,
    signing_key: &PublicKeyDescriptor,
    verifier: [u8; 32],
) -> Result<(), StatusCode> {
    admit_signup(state)?;
    state
        .store
        .first_party_register_account(public, account, descriptor, signing_key, verifier)
        .map_err(|_| StatusCode::CONFLICT)
}

fn encoded_proof(prefix: &str, context: &Value) -> Result<String, StatusCode> {
    Ok(format!(
        "{prefix}\0{}",
        serde_json::to_string(context).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

// A delayed POST body must not resurrect a session after Logout. Every
// protected action, including Logout, acquires this same per-Device gate only
// AFTER its body has been read; no mutex is held across a network await.
fn protected_action_gate(state: &State, binding: &Binding) -> Result<Arc<Mutex<()>>, StatusCode> {
    let mut gates = state
        .protected_actions
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    gates.retain(|_, weak| weak.strong_count() > 0);
    if let Some(gate) = gates.get(binding).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(binding.clone(), Arc::downgrade(&gate));
    Ok(gate)
}

fn issue_session(
    state: &State,
    binding: Binding,
    subject: ScopedPrincipal,
    signer_key_id: String,
    signer_public_key: [u8; 32],
    login_generation: Option<u64>,
) -> Result<(Value, String), StatusCode> {
    let gate = protected_action_gate(state, &binding)?;
    let _action = gate.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let token = nonce()?;
    let mut ledger = state
        .sessions
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if login_generation.is_some_and(|expected| ledger.generation(&binding) != expected) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let sessions = &mut ledger.sessions;
    sessions.retain(|session| session.until > Instant::now());
    // A new login evicts only the SAME Identity's oldest session, so one
    // actor cannot push other people's sessions out or block their login.
    let same = |session: &Session| {
        session.binding.tenant_id == binding.tenant_id
            && session.binding.namespace_id == binding.namespace_id
            && session.binding.participant_id == binding.participant_id
    };
    if sessions.iter().filter(|session| same(session)).count() >= MAX_SESSIONS_PER_IDENTITY
        && let Some(oldest) = sessions.iter().position(same)
    {
        sessions.remove(oldest);
    }
    if sessions.len() >= MAX_SESSIONS {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    sessions.push(Session {
        token: token.clone(),
        binding: binding.clone(),
        subject,
        signer_key_id,
        signer_public_key,
        until: Instant::now() + SESSION_TTL,
    });
    let cookie =
        format!("{COOKIE_NAME}={token}; Path=/; Max-Age=1800; Secure; HttpOnly; SameSite=Strict");
    Ok((
        serde_json::to_value(binding).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        cookie,
    ))
}

fn authenticated(state: &State, request: &Request<Incoming>) -> Result<Session, StatusCode> {
    let raw = request
        .headers()
        .get(COOKIE)
        .and_then(|x| x.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if raw.len() > 4096 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = raw
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&format!("{COOKIE_NAME}=")))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if token.len() != 43
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let session = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        sessions
            .sessions
            .retain(|session| session.until > Instant::now());
        sessions
            .sessions
            .iter()
            .find(|s| s.token == token)
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?
    };
    let live_subject = subject_for(state, &session.binding)?;
    if live_subject != session.subject {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (current_id, current_key) = trusted_key(state, &session.binding)?;
    if session.signer_key_id != current_id || session.signer_public_key != current_key {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(session)
}

fn ensure_binding(requested: &Binding, session: &Session) -> Result<(), StatusCode> {
    if requested == &session.binding {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, StatusCode> {
    serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)
}

fn call_media(call: &CallSession) -> Result<&'static str, StatusCode> {
    let id = call.call_id.as_opaque().as_str();
    if id.starts_with("fp-a-") {
        Ok("audio")
    } else if id.starts_with("fp-v-") {
        Ok("video")
    } else {
        Err(StatusCode::CONFLICT)
    }
}

fn to_call(state: &State, call: &CallSession) -> Result<Value, StatusCode> {
    if call.conversation.kind != ConversationKind::Direct || call.participants.len() != 2 {
        return Err(StatusCode::FORBIDDEN);
    }
    let a = state
        .store
        .principal_identity_binding(&call.scope, &call.initiated_by)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    let other = call
        .participants
        .iter()
        .find(|p| p.principal != call.initiated_by)
        .ok_or(StatusCode::FORBIDDEN)?;
    let b = state
        .store
        .principal_identity_binding(&call.scope, &other.principal)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::FORBIDDEN)?;
    let state_name = match call.signalling_state {
        CallSignallingState::Inviting => "inviting",
        CallSignallingState::Ringing => "ringing",
        CallSignallingState::Active => "active",
        CallSignallingState::Reconnecting => "reconnecting",
        CallSignallingState::Terminated => "terminated",
    };
    Ok(json!({
        "tenantId": call.scope.tenant_id.as_opaque().as_str(),
        "namespaceId": call.scope.namespace_id.as_ref().map(|n| n.as_opaque().as_str()),
        "callId": call.call_id.as_opaque().as_str(),
        "callerIdentityId": a.identity_id.as_opaque().as_str(),
        "calleeIdentityId": b.identity_id.as_opaque().as_str(),
        "media": call_media(call)?,
        "state": state_name,
        "revision": call.revision,
    }))
}

fn get_call(state: &State, session: &Session, id: &str) -> Result<CallSession, StatusCode> {
    AuthorizedDurableRuntime::new(state.store.as_ref(), state.store.as_ref())
        .first_party_call_get(
            &session.subject,
            &device(&session.binding)?,
            &CallId::from_opaque(opaque(id)?),
        )
        .map_err(|_| StatusCode::FORBIDDEN)?
        .ok_or(StatusCode::NOT_FOUND)
}

fn start_call(state: &State, session: &Session, intent: &StartIntent) -> Result<Value, StatusCode> {
    if intent.peer_identity_id == session.binding.participant_id {
        return Err(StatusCode::BAD_REQUEST);
    }
    let peer_id = IdentityId::from_opaque(opaque(&intent.peer_identity_id)?);
    if first_party_media::is_media_host_identity(&peer_id) {
        // The media host is infrastructure, never a callable contact.
        return Err(StatusCode::NOT_FOUND);
    }
    let peer = state
        .store
        .principal_identity_bindings_for_identity_kind(
            &session.subject.scope,
            &peer_id,
            PrincipalKind::Person,
            2,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if peer.len() != 1 || peer[0].principal == session.subject.principal {
        return Err(StatusCode::NOT_FOUND);
    }
    // Media is an immutable, scoped creation convention in the opaque Call ID,
    // not a second Call table. The canonical owner still owns lifecycle and CAS.
    let media = match intent.media.as_str() {
        "audio" => "a",
        "video" => "v",
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let key = opaque(&intent.idempotency_key)?;
    if key.as_str().len() > 90 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = format!("fp-{media}-{}", key.as_str());
    let call_id = CallId::from_opaque(opaque(&id)?);
    let conversation = ConversationRef {
        conversation_id: ConversationId::from_opaque(opaque(&format!("fp-conv-{id}"))?),
        kind: ConversationKind::Direct,
    };
    let runtime = AuthorizedDurableRuntime::new(state.store.as_ref(), state.store.as_ref());
    runtime
        .persist_conversation(
            &session.subject,
            &ConversationRecord {
                scope: session.subject.scope.clone(),
                conversation: conversation.clone(),
                parent_conversation_id: None,
            },
        )
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let draft = CallSession {
        scope: session.subject.scope.clone(),
        call_id: call_id.clone(),
        conversation,
        initiated_by: session.subject.principal.clone(),
        participants: vec![
            CallParticipant {
                principal: session.subject.principal.clone(),
                state: CallParticipantState::Accepted,
                joined_revision: 0,
                left_revision: None,
            },
            CallParticipant {
                principal: peer[0].principal.clone(),
                state: CallParticipantState::Invited,
                joined_revision: 0,
                left_revision: None,
            },
        ],
        signalling_state: CallSignallingState::Inviting,
        reconnecting_participant: None,
        media_negotiation_ref: None,
        media_negotiation_generation: 0,
        replication_generation: 0,
        revision: 0,
        termination_reason: None,
    };
    runtime
        .first_party_call_start(&session.subject, &device(&session.binding)?, &draft)
        .map_err(|_| StatusCode::CONFLICT)?;
    // Return the current canonical persisted revision, not a synthetic Ringing.
    let current = get_call(state, session, &id)?;
    to_call(state, &current)
}

fn signal_call(state: &State, session: &Session, req: &SignalRequest) -> Result<Value, StatusCode> {
    let before = get_call(state, session, &req.call_id)?;
    if before.revision != req.expected_revision {
        return Err(StatusCode::CONFLICT);
    }
    let action = match req.action.as_str() {
        "accept" => CallSignalKind::Accept,
        "reject" => CallSignalKind::Reject,
        "busy" => CallSignalKind::Busy,
        "cancel" => CallSignalKind::Cancel,
        "hangup" => CallSignalKind::Terminate {
            reason: CallTerminationReason::Completed,
        },
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let ends_media = matches!(action, CallSignalKind::Terminate { .. });
    let signal = CallSignal {
        event_id: EventId::from_opaque(
            generate_opaque_id().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        scope: session.subject.scope.clone(),
        call_id: before.call_id.clone(),
        expected_revision: req.expected_revision,
        kind: action,
    };
    let runtime = AuthorizedDurableRuntime::new(state.store.as_ref(), state.store.as_ref());
    if ends_media {
        // `before` is a participant-scoped read at the expected revision. End
        // media FIRST: a failure leaves the direct Call active and the user can
        // retry, but media never keeps running after the direct Call ended.
        first_party_media::end_direct_call_media(state.store.as_ref(), &before)
            .map_err(|_| StatusCode::CONFLICT)?;
    }
    runtime
        .first_party_call_signal(&session.subject, &device(&session.binding)?, &signal)
        .map_err(|_| StatusCode::CONFLICT)?;
    let current = get_call(state, session, &req.call_id)?;
    if current.signalling_state == CallSignallingState::Terminated {
        first_party_media::end_direct_call_media(state.store.as_ref(), &current)
            .map_err(|_| StatusCode::CONFLICT)?;
    }
    to_call(state, &current)
}

fn issue_join(state: &State, session: &Session, req: &JoinRequest) -> Result<Value, StatusCode> {
    let call = AuthorizedDurableRuntime::new(state.store.as_ref(), state.store.as_ref())
        .first_party_call_join_admission(
            &session.subject,
            &device(&session.binding)?,
            &CallId::from_opaque(opaque(&req.call_id)?),
            req.expected_revision,
        )
        .map_err(|_| StatusCode::FORBIDDEN)?;
    // Realtime media is owned by the Conference/SFU + Group-MLS stack, which
    // admits only Group Calls. Bind this ACTIVE direct Call to its derived
    // two-member media Group Call and name THAT Call in the Join grant.
    let media =
        first_party_media::prepare_direct_call_media(state.store.as_ref(), &call, &session.subject)
            .map_err(|error| match error {
                first_party_media::MediaRuntimeError::NotAdmissible => StatusCode::FORBIDDEN,
                first_party_media::MediaRuntimeError::Conflict => StatusCode::CONFLICT,
                first_party_media::MediaRuntimeError::Unavailable => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            })?;
    // This is the SAME issuer instance used for gRPC Realtime admission.
    let grant = state
        .issuer
        .issue(
            media.scope,
            media.call_id,
            session.subject.principal.clone(),
            Some(device(&session.binding)?),
            DEFAULT_JOIN_TTL_SECONDS,
            now_unix_ms()?,
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let fragment = grant
        .join_url
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"))
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    if !fragment.starts_with("#ucr_join=") {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let binding = &session.binding;
    Ok(json!({
        "tenantId": binding.tenant_id,
        "namespaceId": binding.namespace_id,
        "participantId": binding.participant_id,
        "deviceId": binding.device,
        "callId": req.call_id,
        "sessionId": grant.claims.session_id.as_opaque().as_str(),
        "joinFragment": fragment,
    }))
}

async fn route(request: Request<Incoming>, state: Arc<State>) -> Result<HttpResponse, Infallible> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let result = dispatch(request, &state, &path, method).await;
    Ok(match result {
        Ok((value, cookie)) => reply(StatusCode::OK, &value, cookie.as_deref()),
        Err(status) => api_error(status),
    })
}

async fn dispatch(
    request: Request<Incoming>,
    state: &State,
    path: &str,
    method: Method,
) -> Result<(Value, Option<String>), StatusCode> {
    if method == Method::GET && path == "/healthz" {
        return Ok((json!({"ok": true}), None));
    }
    if !path.starts_with("/v1/first-party/") {
        return Err(StatusCode::NOT_FOUND);
    }
    if method != Method::GET && method != Method::POST {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if method == Method::POST {
        require_post_headers(&request, &state.origin)?;
    }
    if method == Method::GET && path == "/v1/first-party/bootstrap" {
        let public = state
            .registration_scope
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        return Ok((
            json!({"tenantId": public.tenant_id.as_opaque().as_str(),
            "namespaceId": null}),
            None,
        ));
    }
    let session = if matches!(
        path,
        "/v1/first-party/login/challenge"
            | "/v1/first-party/login/verify"
            | "/v1/first-party/signup/begin"
            | "/v1/first-party/signup/finish"
            | "/v1/first-party/recover/begin"
            | "/v1/first-party/recover/finish"
    ) {
        None
    } else {
        Some(authenticated(state, &request)?)
    };
    if method == Method::GET {
        if path == "/v1/first-party/session" {
            let binding = &session.ok_or(StatusCode::UNAUTHORIZED)?.binding;
            return Ok((
                serde_json::to_value(binding).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                None,
            ));
        }
        return Err(StatusCode::NOT_FOUND);
    }
    // Bound the stream before aggregating DATA frames. A Content-Length check
    // or collect().await would permit unbounded memory growth from chunked POST.
    let mut incoming = request.into_body();
    let mut body = Vec::with_capacity(1024);
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(data) = frame.data_ref() {
            if data.len() > MAX_BODY.saturating_sub(body.len()) {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            body.extend_from_slice(data);
        }
    }
    // Typed decoding rejects extraneous fields; account/scope is verified against
    // the independent server session on every route.
    let response = dispatch_post(state, path, &body, session.as_ref())?;
    body.clear();
    Ok(response)
}

fn require_post_headers(request: &Request<Incoming>, origin: &str) -> Result<(), StatusCode> {
    let headers = request.headers();
    if headers.get(ORIGIN).and_then(|v| v.to_str().ok()) == Some(origin)
        && headers
            .get("X-UCR-First-Party-Request")
            .and_then(|v| v.to_str().ok())
            == Some("v1")
        && headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) == Some("application/json")
    {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn dispatch_post(
    state: &State,
    path: &str,
    body: &[u8],
    session: Option<&Session>,
) -> Result<(Value, Option<String>), StatusCode> {
    if matches!(
        path,
        "/v1/first-party/login/challenge" | "/v1/first-party/login/verify"
    ) {
        return login_route(state, path, body);
    }
    if matches!(
        path,
        "/v1/first-party/signup/begin"
            | "/v1/first-party/signup/finish"
            | "/v1/first-party/recover/begin"
            | "/v1/first-party/recover/finish"
    ) {
        return account_route(state, path, body);
    }
    let auth = session.ok_or(StatusCode::UNAUTHORIZED)?;
    // Revalidate the cookie AFTER the possibly slow request body, and hold
    // the Device gate through the complete synchronous canonical operation.
    // Logout waits for an earlier operation to finish, then revokes it; an
    // operation queued behind Logout cannot mutate Call or issue signed Join.
    // Revoking another Device must also fence that Device's in-flight
    // protected actions. Lock both gates in a stable order so simultaneous
    // cross-Device revocations cannot deadlock.
    let target_binding = if path == "/v1/first-party/device/revoke" {
        let revoke: RevokeRequest = parse(body)?;
        ensure_binding(&revoke.binding, auth)?;
        opaque(&revoke.device_id)?;
        Some(Binding {
            device: revoke.device_id,
            ..auth.binding.clone()
        })
    } else {
        None
    };
    let own_gate = protected_action_gate(state, &auth.binding)?;
    let target_gate = target_binding
        .as_ref()
        .filter(|target| *target != &auth.binding)
        .map(|target| protected_action_gate(state, target))
        .transpose()?;
    let (first_gate, second_gate) = if target_binding
        .as_ref()
        .is_some_and(|target| target.device < auth.binding.device)
    {
        (
            target_gate
                .as_ref()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
            Some(&own_gate),
        )
    } else {
        (&own_gate, target_gate.as_ref())
    };
    let _first = first_gate
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let _second = second_gate
        .map(|gate| gate.lock().map_err(|_| StatusCode::SERVICE_UNAVAILABLE))
        .transpose()?;
    {
        let ledger = state
            .sessions
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !ledger.sessions.iter().any(|current| {
            current.token == auth.token
                && current.binding == auth.binding
                && current.until > Instant::now()
        }) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    if subject_for(state, &auth.binding)? != auth.subject {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (key_id, public_key) = trusted_key(state, &auth.binding)?;
    if key_id != auth.signer_key_id || public_key != auth.signer_public_key {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if path == "/v1/first-party/logout" {
        let input: BoundRequest = parse(body)?;
        ensure_binding(&input.binding, auth)?;
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !sessions
            .sessions
            .iter()
            .any(|item| item.token == auth.token)
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        sessions.revoke_device(&auth.binding);
        let cookie =
            format!("{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
        return Ok((json!({"signedOut": true}), Some(cookie)));
    }
    let response = if path.starts_with("/v1/first-party/device/") {
        device_route(state, auth, path, body)?
    } else if path.starts_with("/v1/first-party/call/") {
        call_route(state, auth, path, body)?
    } else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok((response, None))
}

fn recovery_verifier(secret: &str) -> Result<[u8; 32], StatusCode> {
    // A recovery code is NOT a password: require 32 CSPRNG bytes. SHA-256
    // is sufficient only because guessing a random 256-bit value is infeasible.
    let bytes = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| StatusCode::FORBIDDEN)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != secret {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ucr-first-party-recovery-verifier.v1\0");
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn account_route(
    state: &State,
    path: &str,
    body: &[u8],
) -> Result<(Value, Option<String>), StatusCode> {
    let public = state
        .registration_scope
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    match path {
        "/v1/first-party/signup/begin" => {
            let value: Value = parse(body)?;
            if value.as_object().is_none_or(|fields| !fields.is_empty()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            // Unforgeable fresh IDs and a one-time challenge are issued by
            // the BFF, not chosen by anonymous browsers.
            let binding = Binding {
                tenant_id: public.tenant_id.as_opaque().as_str().to_owned(),
                namespace_id: None,
                participant_id: format!("fp-id-{}", nonce()?),
                device: format!("fp-device-{}", nonce()?),
            };
            let mut result = challenge(state, &binding, "signup", None, None)?;
            result["binding"] =
                serde_json::to_value(binding).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok((result, None))
        }
        "/v1/first-party/recover/begin" => {
            // The user explicitly brings an unguessable recovery credential.
            // Challenge issuance does not disclose whether an Identity exists.
            let binding: Binding = parse(body)?;
            if &scope(&binding)? != public {
                return Err(StatusCode::FORBIDDEN);
            }
            identity(&binding)?;
            device(&binding)?;
            Ok((challenge(state, &binding, "recover", None, None)?, None))
        }
        "/v1/first-party/signup/finish" | "/v1/first-party/recover/finish" => {
            account_finish(state, public, path, body)
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

fn account_finish(
    state: &State,
    public: &TenantScope,
    path: &str,
    body: &[u8],
) -> Result<(Value, Option<String>), StatusCode> {
    let input: AccountFinish = parse(body)?;
    let registration = path.ends_with("/signup/finish");
    let purpose = if registration { "signup" } else { "recover" };
    if &scope(&input.binding)? != public {
        return Err(StatusCode::FORBIDDEN);
    }
    let pending = consume(state, &input.binding, &input.challenge_id, purpose, None)?;
    let key_id = KeyId::from_opaque(opaque(&input.key_id)?);
    let public_key = URL_SAFE_NO_PAD
        .decode(&input.public_key_base64_url)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if public_key.len() != 32 || URL_SAFE_NO_PAD.encode(&public_key) != input.public_key_base64_url
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let signed = encoded_proof(
        if registration {
            "ucr-first-party-signup.v1"
        } else {
            "ucr-first-party-recover.v1"
        },
        &json!([
            input.binding.tenant_id,
            input.binding.namespace_id,
            input.binding.participant_id,
            input.binding.device,
            input.key_id,
            input.public_key_base64_url,
            pending.id,
            pending.nonce,
        ]),
    )?;
    let verifier_key: [u8; 32] = public_key
        .clone()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_ed25519(verifier_key, &signed, &input.signature_base64_url)?;
    let account = identity(&input.binding)?;
    let device_id = device(&input.binding)?;
    let descriptor = DeviceDescriptor {
        device_id: device_id.clone(),
        identity_id: account.clone(),
        state: DeviceLifecycleState::Active,
    };
    let signing_key = PublicKeyDescriptor {
        key_id,
        device_id,
        purpose: KeyPurpose::Signing,
        algorithm_id: "ed25519".to_owned(),
        algorithm_version: 1,
        key_format_version: 1,
        public_key,
    };
    let next_code = nonce()?;
    let next_verifier = recovery_verifier(&next_code)?;
    if registration {
        if input.recovery_code.is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        spend(state, &pending)?;
        register_self_service_account(
            state,
            public,
            &account,
            &descriptor,
            &signing_key,
            next_verifier,
        )?;
    } else {
        let existing = input
            .recovery_code
            .as_deref()
            .ok_or(StatusCode::FORBIDDEN)?;
        let verifier = recovery_verifier(existing)?;
        spend_verified_recovery(state, &pending, || {
            state
                .store
                .first_party_recover_device(
                    public,
                    &account,
                    &descriptor,
                    &signing_key,
                    verifier,
                    next_verifier,
                )
                .map_err(|_| StatusCode::FORBIDDEN)
        })?;
    }
    // The canonical account/recovery transaction has already committed.
    // Neither a transient canonical subject lookup failure nor a full browser
    // session pool may suppress delivery of the freshly rotated recovery code.
    // The protected Device signer can authenticate again when capacity frees.
    let value = json!(&input.binding);
    let cookie = account_session_after_commit(state, input.binding, &signing_key, verifier_key);
    Ok((json!({"binding": value, "recoveryCode": next_code}), cookie))
}

/// Account registration/recovery is already committed in the canonical store.
/// Session admission is a separate best-effort operation: a full session pool
/// must not hide the newly rotated recovery credential from its owner.
fn account_session_after_commit(
    state: &State,
    binding: Binding,
    signing_key: &PublicKeyDescriptor,
    verifier_key: [u8; 32],
) -> Option<String> {
    let subject = subject_for(state, &binding).ok()?;
    issue_session(
        state,
        binding,
        subject,
        signing_key.key_id.as_opaque().as_str().to_owned(),
        verifier_key,
        None,
    )
    .ok()
    .map(|(_, cookie)| cookie)
}

fn login_route(
    state: &State,
    path: &str,
    body: &[u8],
) -> Result<(Value, Option<String>), StatusCode> {
    let response = match path {
        "/v1/first-party/login/challenge" => {
            let binding: Binding = parse(body)?;
            scope(&binding)?;
            identity(&binding)?;
            device(&binding)?;
            challenge(state, &binding, "login", None, None)?
        }
        "/v1/first-party/login/verify" => {
            let proof: LoginProof = parse(body)?;
            let pending = consume(state, &proof.binding, &proof.challenge_id, "login", None)?;
            let subject = subject_for(state, &proof.binding)?;
            let (key_id, public_key) = trusted_key(state, &proof.binding)?;
            let signed = encoded_proof(
                "ucr-first-party-device-login.v1",
                &json!([
                    proof.binding.tenant_id,
                    proof.binding.namespace_id,
                    proof.binding.participant_id,
                    proof.binding.device,
                    pending.id,
                    pending.nonce,
                ]),
            )?;
            verify_ed25519(public_key, &signed, &proof.signature_base64_url)?;
            spend(state, &pending)?;
            let (value, cookie) = issue_session(
                state,
                proof.binding,
                subject,
                key_id,
                public_key,
                pending.login_generation,
            )?;
            return Ok((value, Some(cookie)));
        }
        _ => return Err(StatusCode::NOT_FOUND),
    };
    Ok((response, None))
}

fn device_route(
    state: &State,
    auth: &Session,
    path: &str,
    body: &[u8],
) -> Result<Value, StatusCode> {
    let response = match path {
        "/v1/first-party/device/list" => {
            let input: BoundRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            let devices = state
                .store
                .devices_for_identity(&scope(&auth.binding)?, &identity(&auth.binding)?, 64)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            json!(devices.iter().map(|device| json!({
                "deviceId": device.device_id.as_opaque().as_str(),
                "state": match device.state {
                    DeviceLifecycleState::Active => "active",
                    DeviceLifecycleState::Revoked => "revoked",
                    DeviceLifecycleState::Stale => "stale",
                    DeviceLifecycleState::ReverificationRequired => "reverificationRequired",
                    DeviceLifecycleState::Expired => "expired",
                }
            })).collect::<Vec<_>>())
        }
        "/v1/first-party/device/revoke" => {
            let input: RevokeRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            let target = DeviceId::from_opaque(opaque(&input.device_id)?);
            state
                .store
                .revoke_device(&auth.subject.scope, &target, &identity(&auth.binding)?)
                .map_err(|_| StatusCode::FORBIDDEN)?;
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            sessions.revoke_device(&Binding {
                device: input.device_id,
                ..auth.binding.clone()
            });
            json!({"revoked": true})
        }
        "/v1/first-party/device/rotate-recovery" => {
            let input: BoundRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            let code = nonce()?;
            state
                .store
                .first_party_rotate_recovery(
                    &auth.subject.scope,
                    &identity(&auth.binding)?,
                    recovery_verifier(&code)?,
                )
                .map_err(|_| StatusCode::FORBIDDEN)?;
            json!({"recoveryCode": code})
        }
        "/v1/first-party/device/inspect" => {
            let input: BoundRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            let (key_id, public_key) = trusted_key(state, &auth.binding)?;
            json!({"deviceActive": true, "deviceRevoked": false,
                "activeKey": {"keyId": key_id,
                              "publicKeyBase64Url": URL_SAFE_NO_PAD.encode(public_key)}})
        }
        "/v1/first-party/device/challenge" => {
            let input: DeviceChallenge = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            opaque(&input.key_id)?;
            let public_key = URL_SAFE_NO_PAD
                .decode(&input.public_key_base64_url)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            let pubkey: [u8; 32] = public_key.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
            challenge(
                state,
                &input.binding,
                "device",
                Some(&input.key_id),
                Some(pubkey),
            )?
        }
        "/v1/first-party/device/approve" => device_approve(state, auth, body)?,
        _ => return Err(StatusCode::NOT_FOUND),
    };
    Ok(response)
}

fn device_approve(state: &State, auth: &Session, body: &[u8]) -> Result<Value, StatusCode> {
    let input: DeviceApproval = parse(body)?;
    ensure_binding(&input.binding, auth)?;
    let offered: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&input.public_key_base64_url)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let pending = consume(
        state,
        &input.binding,
        &input.challenge_id,
        "device",
        Some((&input.key_id, offered)),
    )?;
    if pending.key_id.as_deref() != Some(&input.key_id)
        || pending.public_key.map(|x| URL_SAFE_NO_PAD.encode(x))
            != Some(input.public_key_base64_url.clone())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let (key_id, key) = trusted_key(state, &input.binding)?;
    if key_id != input.key_id || pending.public_key != Some(key) {
        // New device enrollment requires independent, existing account
        // authority. Never let a logged-in device self-provision a new signer.
        return Err(StatusCode::FORBIDDEN);
    }
    let signed = encoded_proof(
        "ucr-first-party-device-enrollment.v1",
        &json!([
            input.binding.tenant_id,
            input.binding.namespace_id,
            input.binding.participant_id,
            input.binding.device,
            input.key_id,
            input.public_key_base64_url,
            pending.id,
            pending.nonce,
        ]),
    )?;
    verify_ed25519(key, &signed, &input.signature_base64_url)?;
    spend(state, &pending)?;
    Ok(json!({"approved": true}))
}

fn call_route(state: &State, auth: &Session, path: &str, body: &[u8]) -> Result<Value, StatusCode> {
    let response = match path {
        "/v1/first-party/call/start" => {
            let input: StartRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            start_call(state, auth, &input.intent)?
        }
        "/v1/first-party/call/get" => {
            let input: GetRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            to_call(state, &get_call(state, auth, &input.call_id)?)?
        }
        "/v1/first-party/call/incoming" => {
            let input: BoundRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            let calls = AuthorizedDurableRuntime::new(state.store.as_ref(), state.store.as_ref())
                .first_party_call_incoming(&auth.subject, &device(&auth.binding)?, 64)
                .map_err(|_| StatusCode::FORBIDDEN)?;
            let calls = calls
                .iter()
                .map(|call| to_call(state, call))
                .collect::<Result<Vec<_>, _>>()?;
            json!(calls)
        }
        "/v1/first-party/call/signal" => {
            let input: SignalRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            signal_call(state, auth, &input)?
        }
        "/v1/first-party/call/join-accepted" => {
            let input: JoinRequest = parse(body)?;
            ensure_binding(&input.binding, auth)?;
            issue_join(state, auth, &input)?
        }
        "/v1/first-party/call/join" => {
            // A bare device binding cannot establish accepted Call authority.
            return Err(StatusCode::FORBIDDEN);
        }
        _ => return Err(StatusCode::NOT_FOUND),
    };
    Ok(response)
}

#[cfg(test)]
#[path = "first_party_acceptance.rs"]
mod acceptance_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_must_be_explicit_https_and_listener_loopback() {
        assert_eq!(opaque(""), Err(StatusCode::BAD_REQUEST));
        assert!(opaque("ok.good-123").is_ok());
        assert!(opaque("../bad").is_err());
        assert!(opaque("bad\r\n").is_err());
    }

    #[test]
    fn device_inspect_and_incoming_require_canonical_bound_request_envelope() {
        let binding = json!({
            "tenantId": "tenant-one",
            "namespaceId": null,
            "participantId": "identity-one",
            "deviceId": "device-one"
        });
        let canonical = json!({"binding": binding.clone()});
        let parsed: BoundRequest = parse(&serde_json::to_vec(&canonical).unwrap()).unwrap();
        assert_eq!(parsed.binding.participant_id, "identity-one");

        // An SDK mock that accepts the bare binding would lie about live BFF interoperability.
        assert!(parse::<BoundRequest>(&serde_json::to_vec(&binding).unwrap()).is_err());
        assert!(
            parse::<BoundRequest>(
                &serde_json::to_vec(&json!({"binding": binding, "extra": true})).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn first_party_call_http_envelopes_match_the_single_browser_contract() {
        let binding = json!({
            "tenantId": "tenant-one",
            "namespaceId": null,
            "participantId": "identity-one",
            "deviceId": "device-one"
        });
        let start = json!({
            "binding": binding.clone(),
            "intent": {
                "peerIdentityId": "identity-two",
                "media": "video",
                "idempotencyKey": "first-call-42"
            }
        });
        let parsed: StartRequest = parse(&serde_json::to_vec(&start).unwrap()).unwrap();
        assert_eq!(parsed.intent.peer_identity_id, "identity-two");
        assert_eq!(parsed.intent.media, "video");
        assert_eq!(parsed.intent.idempotency_key, "first-call-42");
        assert_eq!(parsed.binding.device, "device-one");
        assert!(
            parse::<StartRequest>(
                &serde_json::to_vec(&json!({
                    "binding": binding.clone(),
                    "intent": {
                        "peerIdentityId": "identity-two",
                        "media": "video",
                        "idempotencyKey": "first-call-42",
                        "joinFragment": "#forged"
                    }
                }))
                .unwrap()
            )
            .is_err(),
            "Call start must not accept browser-supplied Join material"
        );

        let get = json!({"binding": binding.clone(), "callId": "fp-v-first-call-42"});
        let parsed: GetRequest = parse(&serde_json::to_vec(&get).unwrap()).unwrap();
        assert_eq!(parsed.call_id, "fp-v-first-call-42");
        let signal = json!({
            "binding": binding.clone(),
            "callId": "fp-v-first-call-42",
            "expectedRevision": 7,
            "action": "accept"
        });
        let parsed: SignalRequest = parse(&serde_json::to_vec(&signal).unwrap()).unwrap();
        assert_eq!(parsed.expected_revision, 7);
        assert_eq!(parsed.action, "accept");
        assert!(
            parse::<SignalRequest>(
                &serde_json::to_vec(&json!({
                    "binding": binding.clone(),
                    "callId": "fp-v-first-call-42",
                    "expectedRevision": -1,
                    "action": "hangup"
                }))
                .unwrap()
            )
            .is_err(),
            "CAS revisions must be unsigned canonical revision numbers"
        );
        let join = json!({
            "binding": binding.clone(),
            "callId": "fp-v-first-call-42",
            "expectedRevision": 8
        });
        let parsed: JoinRequest = parse(&serde_json::to_vec(&join).unwrap()).unwrap();
        assert_eq!(parsed.call_id, "fp-v-first-call-42");
        assert_eq!(parsed.expected_revision, 8);
        assert!(
            parse::<JoinRequest>(
                &serde_json::to_vec(&json!({
                    "binding": binding.clone(),
                    "callId": "fp-v-first-call-42"
                }))
                .unwrap()
            )
            .is_err(),
            "Join must not bypass the accepted Call's revision"
        );
        assert!(
            parse::<JoinRequest>(
                &serde_json::to_vec(&json!({
                    "binding": binding,
                    "callId": "fp-v-first-call-42",
                    "expectedRevision": 8,
                    "deviceJoin": true
                }))
                .unwrap()
            )
            .is_err(),
            "Device-only Join cannot be smuggled through accepted-Call admission"
        );
    }

    #[test]
    fn challenge_signature_proof_is_domain_separated_and_ordered() {
        let proof = encoded_proof(
            "ucr-first-party-device-login.v1",
            &json!(["tenant", null, "identity", "device", "id", "nonce"]),
        )
        .unwrap();
        assert!(proof.starts_with("ucr-first-party-device-login.v1\0["));
        assert!(proof.ends_with("[\"tenant\",null,\"identity\",\"device\",\"id\",\"nonce\"]"));
    }
}

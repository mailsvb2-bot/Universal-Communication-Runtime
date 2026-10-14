//! First-party same-origin BFF for independently proved canonical human Devices.
//! This module shares the production `SQLite` and `JoinTokenIssuer` with realtime.
//! It deliberately does not bootstrap Root Identities or silently trust a new Device.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
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

const MAX_BODY: usize = 16 * 1024;
const MAX_PENDING: usize = 512;
const MAX_SESSIONS: usize = 2048;
const CHALLENGE_TTL: Duration = Duration::from_secs(90);
const SESSION_TTL: Duration = Duration::from_mins(30);
const COOKIE_NAME: &str = "__Host-ucr_fp";
type HttpResponse = Response<Full<Bytes>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    id: String,
    binding: Binding,
    nonce: String,
    purpose: &'static str,
    key_id: Option<String>,
    public_key: Option<[u8; 32]>,
    until: Instant,
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

#[derive(Debug)]
struct State {
    store: Arc<SqliteLocalStore>,
    issuer: Arc<JoinTokenIssuer>,
    origin: String,
    registration_scope: Option<TenantScope>,
    pending: Mutex<Vec<Pending>>,
    sessions: Mutex<Vec<Session>>,
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
        pending: Mutex::new(Vec::new()),
        sessions: Mutex::new(Vec::new()),
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

fn challenge(
    state: &State,
    binding: Binding,
    purpose: &'static str,
    key_id: Option<String>,
    public_key: Option<[u8; 32]>,
) -> Result<Value, StatusCode> {
    // Always bounded and one-time. The server does not trust the supplied Identity
    // until signature verification; challenge requests never reveal its existence.
    let record = Pending {
        id: nonce()?,
        binding,
        nonce: nonce()?,
        purpose,
        key_id,
        public_key,
        until: Instant::now() + CHALLENGE_TTL,
    };
    let mut pending = state
        .pending
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    pending.retain(|c| c.until > Instant::now());
    if pending.len() >= MAX_PENDING {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let response = json!({
        "challengeId": record.id,
        "challengeBytesBase64Url": record.nonce,
    });
    pending.push(record);
    Ok(response)
}

fn consume(
    state: &State,
    binding: &Binding,
    id: &str,
    purpose: &str,
) -> Result<Pending, StatusCode> {
    let mut pending = state
        .pending
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let index = pending
        .iter()
        .position(|c| c.id == id && c.purpose == purpose)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let challenge = pending.swap_remove(index);
    if challenge.until <= Instant::now() || challenge.binding != *binding {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(challenge)
}

fn encoded_proof(prefix: &str, context: &Value) -> Result<String, StatusCode> {
    Ok(format!(
        "{prefix}\0{}",
        serde_json::to_string(context).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

fn issue_session(
    state: &State,
    binding: Binding,
    subject: ScopedPrincipal,
    signer_key_id: String,
    signer_public_key: [u8; 32],
) -> Result<(Value, String), StatusCode> {
    let token = nonce()?;
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    sessions.retain(|session| session.until > Instant::now());
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
        sessions.retain(|session| session.until > Instant::now());
        sessions
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
    let signal = CallSignal {
        event_id: EventId::from_opaque(
            generate_opaque_id().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        scope: session.subject.scope.clone(),
        call_id: before.call_id,
        expected_revision: req.expected_revision,
        kind: action,
    };
    AuthorizedDurableRuntime::new(state.store.as_ref(), state.store.as_ref())
        .first_party_call_signal(&session.subject, &device(&session.binding)?, &signal)
        .map_err(|_| StatusCode::CONFLICT)?;
    let current = get_call(state, session, &req.call_id)?;
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
    // This is the SAME issuer instance used for gRPC Realtime admission.
    let grant = state
        .issuer
        .issue(
            call.scope,
            call.call_id,
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
    if path == "/v1/first-party/logout" {
        let input: BoundRequest = parse(body)?;
        ensure_binding(&input.binding, auth)?;
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        sessions.retain(|item| item.token != auth.token);
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
            let mut result = challenge(state, binding.clone(), "signup", None, None)?;
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
            Ok((challenge(state, binding, "recover", None, None)?, None))
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
    let pending = consume(state, &input.binding, &input.challenge_id, purpose)?;
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
        state
            .store
            .first_party_register_account(
                public,
                &account,
                &descriptor,
                &signing_key,
                next_verifier,
            )
            .map_err(|_| StatusCode::CONFLICT)?;
    } else {
        let existing = input
            .recovery_code
            .as_deref()
            .ok_or(StatusCode::FORBIDDEN)?;
        let verifier = recovery_verifier(existing)?;
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
            .map_err(|_| StatusCode::FORBIDDEN)?;
    }
    let subject = subject_for(state, &input.binding)?;
    let (value, cookie) = issue_session(
        state,
        input.binding,
        subject,
        signing_key.key_id.as_opaque().as_str().to_owned(),
        verifier_key,
    )?;
    Ok((
        json!({"binding": value, "recoveryCode": next_code}),
        Some(cookie),
    ))
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
            challenge(state, binding, "login", None, None)?
        }
        "/v1/first-party/login/verify" => {
            let proof: LoginProof = parse(body)?;
            let pending = consume(state, &proof.binding, &proof.challenge_id, "login")?;
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
            let (value, cookie) = issue_session(state, proof.binding, subject, key_id, public_key)?;
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
            sessions.retain(|item| {
                !(item.binding.tenant_id == auth.binding.tenant_id
                    && item.binding.namespace_id == auth.binding.namespace_id
                    && item.binding.device == input.device_id)
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
                input.binding,
                "device",
                Some(input.key_id),
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
    let pending = consume(state, &input.binding, &input.challenge_id, "device")?;
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

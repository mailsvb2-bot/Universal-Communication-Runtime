#![forbid(unsafe_code)]

use std::{convert::Infallible, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tonic::{Request as GrpcRequest, metadata::MetadataValue, transport::Channel};
use ucr_api_grpc::pb;

const DEFAULT_BIND: &str = "127.0.0.1:8082";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:50051";
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 8_192 + 32;
const OPENAPI: &str = include_str!("../openapi.yaml");

type HttpBody = UnsyncBoxBody<Bytes, Infallible>;
type HttpResponse = Response<HttpBody>;

#[derive(Clone, Debug)]
struct AppState {
    upstream: Channel,
}

#[derive(Debug)]
struct TransportError {
    status: StatusCode,
    message: &'static str,
}

impl TransportError {
    const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }

    fn into_response(self) -> HttpResponse {
        json_response(
            self.status,
            &json!({ "error": { "code": "TRANSPORT", "message": self.message } }),
        )
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ucr-conference-web: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let bind: SocketAddr = std::env::var("UCR_CONFERENCE_WEB_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()
        .map_err(|error| format!("invalid UCR_CONFERENCE_WEB_BIND: {error}"))?;
    validate_loopback_bind(bind)?;
    let upstream = std::env::var("UCR_CONFERENCE_GRPC_UPSTREAM")
        .unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    let channel = Channel::from_shared(upstream)
        .map_err(|error| format!("invalid conference upstream URI: {error}"))?
        .connect()
        .await
        .map_err(|error| format!("connect conference upstream: {error}"))?;
    let state = AppState { upstream: channel };
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind conference HTTP adapter: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve conference HTTP adapter: {error}"))?;
    println!("UCR_CONFERENCE_WEB_READY endpoint=http://{address} tls_edge=required");
    serve(listener, state).await
}

async fn serve(listener: TcpListener, state: AppState) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept conference HTTP adapter connection: {error}"))?;
        let io = TokioIo::new(stream);
        let connection_state = state.clone();
        tokio::spawn(async move {
            let service =
                service_fn(move |request| handle_request(request, connection_state.clone()));
            if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("ucr-conference-web: connection closed: {error}");
            }
        });
    }
}

fn validate_loopback_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(
            "conference HTTP adapter requires a loopback bind; publish it only through a trusted HTTPS reverse proxy"
                .to_owned(),
        )
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: AppState,
) -> Result<HttpResponse, Infallible> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let response = match (method, path.as_str()) {
        (Method::GET, "/healthz") => text_response(StatusCode::OK, "ok"),
        (Method::GET, "/v1/openapi.yaml") => yaml_response(OPENAPI),
        (Method::GET, "/v1/capabilities") => dispatch_get_capabilities(request, &state).await,
        (Method::POST, path) => dispatch_post(path, request, &state).await,
        _ => TransportError::new(StatusCode::NOT_FOUND, "conference HTTP route not found")
            .into_response(),
    };
    Ok(response)
}

async fn dispatch_post(path: &str, request: Request<Incoming>, state: &AppState) -> HttpResponse {
    if request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.starts_with("application/json"))
    {
        return TransportError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "conference HTTP adapter requires application/json",
        )
        .into_response();
    }
    let authorization = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if authorization
        .as_ref()
        .is_some_and(|value| value.len() > MAX_AUTHORIZATION_HEADER_BYTES)
    {
        return TransportError::new(
            StatusCode::UNAUTHORIZED,
            "authorization header exceeds the bounded limit",
        )
        .into_response();
    }
    let body = match bounded_body(request.into_body()).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let mut client = pb::universal_conference_service_client::UniversalConferenceServiceClient::new(
        state.upstream.clone(),
    );
    match path {
        "/v1/conferences" => forward_create(&mut client, &body, authorization.as_deref()).await,
        "/v1/conferences/resolve" => {
            forward_resolve(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/conferences/get" => forward_get(&mut client, &body, authorization.as_deref()).await,
        "/v1/conferences/lifecycle" => {
            forward_lifecycle(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/conferences/entry" => {
            forward_entry(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/participants" => {
            forward_ensure_participant(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/participant-devices" => {
            forward_ensure_device(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/participants/update" => {
            forward_update_participant(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/participants/remove" => {
            forward_remove_participant(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/participants/list" => {
            forward_list_participants(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/subscriptions" => {
            forward_subscriptions(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/conferences/runtime" => {
            forward_runtime(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/join-grants" => forward_issue_join(&mut client, &body, authorization.as_deref()).await,
        "/v1/join-grants/revoke" => {
            forward_revoke_join(&mut client, &body, authorization.as_deref()).await
        }
        "/v1/attendance" => forward_attendance(&mut client, &body, authorization.as_deref()).await,
        "/v1/capabilities" => {
            forward_capabilities(&mut client, &body, authorization.as_deref()).await
        }
        _ => TransportError::new(StatusCode::NOT_FOUND, "conference HTTP route not found")
            .into_response(),
    }
}

async fn dispatch_get_capabilities(
    request: Request<Incoming>,
    state: &AppState,
) -> HttpResponse {
    let authorization = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if authorization
        .as_ref()
        .is_some_and(|value| value.len() > MAX_AUTHORIZATION_HEADER_BYTES)
    {
        return TransportError::new(
            StatusCode::UNAUTHORIZED,
            "authorization header exceeds the bounded limit",
        )
        .into_response();
    }
    let parsed = match capabilities_query(request.uri().query().unwrap_or_default()) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let mut client =
        pb::universal_conference_service_client::UniversalConferenceServiceClient::new(
            state.upstream.clone(),
        );
    forward_capabilities_input(&mut client, parsed, authorization.as_deref()).await
}

fn capabilities_query(query: &str) -> Result<CapabilitiesJson, TransportError> {
    const MAX_QUERY_BYTES: usize = 4 * 1024;
    if query.len() > MAX_QUERY_BYTES {
        return Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "capabilities query exceeds the bounded limit",
        ));
    }
    let mut tenant_id = None;
    let mut namespace_id = None;
    let mut integration_id = None;
    if !query.is_empty() {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or_else(|| {
                TransportError::new(StatusCode::BAD_REQUEST, "invalid capabilities query")
            })?;
            let name = decode_query_component(name)?;
            let value = decode_query_component(value)?;
            let slot = match name.as_str() {
                "tenant_id" => &mut tenant_id,
                "namespace_id" => &mut namespace_id,
                "integration_id" => &mut integration_id,
                _ => {
                    return Err(TransportError::new(
                        StatusCode::BAD_REQUEST,
                        "unknown capabilities query field",
                    ));
                }
            };
            if slot.replace(value).is_some() {
                return Err(TransportError::new(
                    StatusCode::BAD_REQUEST,
                    "duplicate capabilities query field",
                ));
            }
        }
    }
    Ok(CapabilitiesJson {
        scope: ScopeJson {
            tenant_id: tenant_id.ok_or_else(|| {
                TransportError::new(StatusCode::BAD_REQUEST, "tenant_id is required")
            })?,
            namespace_id,
        },
        integration_id: integration_id.ok_or_else(|| {
            TransportError::new(StatusCode::BAD_REQUEST, "integration_id is required")
        })?,
    })
}

fn decode_query_component(value: &str) -> Result<String, TransportError> {
    const MAX_COMPONENT_BYTES: usize = 512;
    if value.len() > MAX_COMPONENT_BYTES {
        return Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "capabilities query field exceeds the bounded limit",
        ));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(TransportError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid capabilities query encoding",
                    ));
                }
                let high = hex_nibble(bytes[index + 1])?;
                let low = hex_nibble(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| {
        TransportError::new(
            StatusCode::BAD_REQUEST,
            "capabilities query must be valid UTF-8",
        )
    })
}

fn hex_nibble(value: u8) -> Result<u8, TransportError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "invalid capabilities query encoding",
        )),
    }
}

type ConferenceClient =
    pb::universal_conference_service_client::UniversalConferenceServiceClient<Channel>;

fn attach_authorization<T>(
    request: &mut GrpcRequest<T>,
    authorization: Option<&str>,
) -> Result<(), TransportError> {
    let Some(authorization) = authorization else {
        return Ok(());
    };
    let value = MetadataValue::try_from(authorization).map_err(|_| {
        TransportError::new(
            StatusCode::UNAUTHORIZED,
            "authorization header is not grpc metadata",
        )
    })?;
    request.metadata_mut().insert("authorization", value);
    Ok(())
}

fn decode_json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, TransportError> {
    serde_json::from_slice(body).map_err(|_| {
        TransportError::new(
            StatusCode::BAD_REQUEST,
            "conference JSON body is not the typed request",
        )
    })
}

fn opaque(value: &str) -> Result<pb::OpaqueId, TransportError> {
    if value.is_empty() || value.len() > 128 {
        return Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "opaque id is outside the public byte budget",
        ));
    }
    Ok(pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    })
}

fn scope_of(scope: &ScopeJson) -> Result<pb::TenantScope, TransportError> {
    Ok(pb::TenantScope {
        tenant_id: Some(opaque(&scope.tenant_id)?),
        namespace_id: scope.namespace_id.as_deref().map(opaque).transpose()?,
    })
}

fn external_bytes(encoded: &str) -> Result<Vec<u8>, TransportError> {
    STANDARD.decode(encoded).map_err(|_| {
        TransportError::new(
            StatusCode::BAD_REQUEST,
            "external bytes must be standard base64",
        )
    })
}

fn mode_code(mode: &str) -> Result<i32, TransportError> {
    match mode {
        "unspecified" => Ok(pb::UniversalConferenceMode::Unspecified as i32),
        "meeting" => Ok(pb::UniversalConferenceMode::Meeting as i32),
        "webinar" => Ok(pb::UniversalConferenceMode::Webinar as i32),
        "broadcast" => Ok(pb::UniversalConferenceMode::Broadcast as i32),
        "audio_room" => Ok(pb::UniversalConferenceMode::AudioRoom as i32),
        _ => Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "unknown conference mode",
        )),
    }
}

fn lifecycle_code(lifecycle: &str) -> Result<i32, TransportError> {
    match lifecycle {
        "unspecified" => Ok(pb::UniversalConferenceLifecycle::Unspecified as i32),
        "scheduled" => Ok(pb::UniversalConferenceLifecycle::Scheduled as i32),
        "waiting" => Ok(pb::UniversalConferenceLifecycle::Waiting as i32),
        "live" => Ok(pb::UniversalConferenceLifecycle::Live as i32),
        "ending" => Ok(pb::UniversalConferenceLifecycle::Ending as i32),
        "ended" => Ok(pb::UniversalConferenceLifecycle::Ended as i32),
        _ => Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "unknown conference lifecycle",
        )),
    }
}

fn role_code(role: &str) -> Result<i32, TransportError> {
    match role {
        "unspecified" => Ok(pb::ConferenceParticipantRole::Unspecified as i32),
        "owner" => Ok(pb::ConferenceParticipantRole::Owner as i32),
        "host" => Ok(pb::ConferenceParticipantRole::Host as i32),
        "moderator" => Ok(pb::ConferenceParticipantRole::Moderator as i32),
        "speaker" => Ok(pb::ConferenceParticipantRole::Speaker as i32),
        "attendee" => Ok(pb::ConferenceParticipantRole::Attendee as i32),
        _ => Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "unknown participant role",
        )),
    }
}

fn use_policy_code(policy: &str) -> Result<i32, TransportError> {
    match policy {
        "unspecified" => Ok(pb::JoinGrantUsePolicy::Unspecified as i32),
        "single_use" => Ok(pb::JoinGrantUsePolicy::SingleUse as i32),
        "reusable" => Ok(pb::JoinGrantUsePolicy::Reusable as i32),
        _ => Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "unknown join grant use policy",
        )),
    }
}

fn media_kind_code(kind: &str) -> Result<i32, TransportError> {
    match kind {
        "unspecified" => Ok(pb::MediaKind::Unspecified as i32),
        "audio" => Ok(pb::MediaKind::Audio as i32),
        "video" => Ok(pb::MediaKind::Video as i32),
        _ => Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "unknown media kind",
        )),
    }
}

fn schedule_of(schedule: &ScheduleJson) -> Result<pb::ConferenceScheduleMetadata, TransportError> {
    if schedule
        .timezone
        .as_ref()
        .is_some_and(|value| value.len() > 128)
    {
        return Err(TransportError::new(
            StatusCode::BAD_REQUEST,
            "timezone exceeds the bounded limit",
        ));
    }
    Ok(pb::ConferenceScheduleMetadata {
        starts_at_unix_ms: schedule.starts_at_unix_ms,
        planned_end_unix_ms: schedule.planned_end_unix_ms,
        join_before_seconds: schedule.join_before_seconds,
        join_after_seconds: schedule.join_after_seconds,
        timezone: schedule.timezone.clone(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeJson {
    tenant_id: String,
    #[serde(default)]
    namespace_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleJson {
    starts_at_unix_ms: i64,
    #[serde(default)]
    planned_end_unix_ms: Option<i64>,
    #[serde(default)]
    join_before_seconds: u32,
    #[serde(default)]
    join_after_seconds: u32,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateJson {
    scope: ScopeJson,
    integration_id: String,
    external_conference_id_b64: String,
    idempotency_key: String,
    mode: String,
    schedule: ScheduleJson,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveJson {
    scope: ScopeJson,
    integration_id: String,
    external_conference_id_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    target: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    entry_open: bool,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnsureParticipantJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
    role: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnsureDeviceJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateParticipantJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    audio_muted: Option<bool>,
    #[serde(default)]
    camera_allowed: Option<bool>,
    #[serde(default)]
    publish_audio_allowed: Option<bool>,
    #[serde(default)]
    publish_video_allowed: Option<bool>,
    #[serde(default)]
    screen_share_allowed: Option<bool>,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveParticipantJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParticipantsJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    max_items: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionJson {
    source_external_user_id_b64: String,
    media_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionsJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
    subscriptions: Vec<SubscriptionJson>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueJoinJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
    ttl_seconds: u32,
    use_policy: String,
    #[serde(default)]
    not_before_unix_ms: Option<i64>,
    #[serde(default)]
    not_after_unix_ms: Option<i64>,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeJoinJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    session_id: String,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttendanceJson {
    scope: ScopeJson,
    conference_id: String,
    integration_id: String,
    external_user_id_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesJson {
    scope: ScopeJson,
    integration_id: String,
}

async fn forward_create(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<CreateJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match create_request(&parsed) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let mut request = GrpcRequest::new(request);
    if let Err(response) = attach_authorization(&mut request, authorization) {
        return response.into_response();
    }
    match client.create_conference(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::universal_create_conference_response::Result::Conference(conference)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "conference": conference_json(&conference) }),
                )
            }
            Some(pb::universal_create_conference_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
        Err(status) => grpc_status(&status),
    }
}

fn create_request(
    parsed: &CreateJson,
) -> Result<pb::UniversalCreateConferenceRequest, TransportError> {
    Ok(pb::UniversalCreateConferenceRequest {
        scope: Some(scope_of(&parsed.scope)?),
        integration_id: Some(opaque(&parsed.integration_id)?),
        external_conference_id: external_bytes(&parsed.external_conference_id_b64)?,
        idempotency_key: parsed.idempotency_key.clone(),
        mode: mode_code(&parsed.mode)?,
        schedule: Some(schedule_of(&parsed.schedule)?),
    })
}

async fn forward_resolve(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<ResolveJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalResolveConferenceRequest {
            scope: Some(scope_of(&parsed.scope)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
            external_conference_id: external_bytes(&parsed.external_conference_id_b64)?,
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.resolve_conference(request),
        |response| match response.result {
            Some(pb::universal_resolve_conference_response::Result::Conference(conference)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "conference": conference_json(&conference) }),
                )
            }
            Some(pb::universal_resolve_conference_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

fn authorized<T>(
    message: T,
    authorization: Option<&str>,
) -> Result<GrpcRequest<T>, TransportError> {
    let mut request = GrpcRequest::new(message);
    attach_authorization(&mut request, authorization)?;
    Ok(request)
}

async fn call<F, T>(
    pending: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    map: F,
) -> HttpResponse
where
    F: FnOnce(T) -> HttpResponse,
{
    match pending.await {
        Ok(response) => map(response.into_inner()),
        Err(status) => grpc_status(&status),
    }
}

async fn forward_get(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<GetJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalGetConferenceRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(client.get_conference(request), |response| {
        match response.result {
            Some(pb::universal_get_conference_response::Result::Conference(conference)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "conference": conference_json(&conference) }),
                )
            }
            Some(pb::universal_get_conference_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        }
    })
    .await
}

async fn forward_lifecycle(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<LifecycleJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match lifecycle_request(&parsed) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.transition_conference(request),
        |response| match response.result {
            Some(pb::universal_conference_lifecycle_response::Result::Conference(conference)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "conference": conference_json(&conference) }),
                )
            }
            Some(pb::universal_conference_lifecycle_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

fn lifecycle_request(
    parsed: &LifecycleJson,
) -> Result<pb::UniversalConferenceLifecycleRequest, TransportError> {
    Ok(pb::UniversalConferenceLifecycleRequest {
        scope: Some(scope_of(&parsed.scope)?),
        conference_id: Some(opaque(&parsed.conference_id)?),
        target: lifecycle_code(&parsed.target)?,
        idempotency_key: parsed.idempotency_key.clone(),
        integration_id: Some(opaque(&parsed.integration_id)?),
    })
}

async fn forward_entry(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<EntryJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalSetEntryOpenRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            entry_open: parsed.entry_open,
            idempotency_key: parsed.idempotency_key.clone(),
            integration_id: Some(opaque(&parsed.integration_id)?),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(client.set_entry_open(request), |response| {
        match response.result {
            Some(pb::universal_set_entry_open_response::Result::Conference(conference)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "conference": conference_json(&conference) }),
                )
            }
            Some(pb::universal_set_entry_open_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        }
    })
    .await
}

async fn forward_ensure_participant(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<EnsureParticipantJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalEnsureParticipantRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
            external_user_id: external_bytes(&parsed.external_user_id_b64)?,
            role: role_code(&parsed.role)?,
            idempotency_key: parsed.idempotency_key.clone(),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.ensure_participant(request),
        |response| match response.result {
            Some(pb::universal_ensure_participant_response::Result::Participant(participant)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "participant": participant_json(&participant) }),
                )
            }
            Some(pb::universal_ensure_participant_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

async fn forward_ensure_device(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<EnsureDeviceJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalEnsureParticipantDeviceRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
            external_user_id: external_bytes(&parsed.external_user_id_b64)?,
            idempotency_key: parsed.idempotency_key.clone(),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.ensure_participant_device(request),
        |response| match response.result {
            Some(pb::universal_ensure_participant_device_response::Result::Device(device)) => {
                json_response(
                    StatusCode::OK,
                    &json!({
                        "device": {
                            "external_user_id_b64": STANDARD.encode(&device.external_user_id),
                            "active": device.active,
                        }
                    }),
                )
            }
            Some(pb::universal_ensure_participant_device_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

async fn forward_update_participant(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<UpdateParticipantJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match update_request(&parsed) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.update_participant(request),
        |response| match response.result {
            Some(pb::universal_update_participant_response::Result::Participant(participant)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "participant": participant_json(&participant) }),
                )
            }
            Some(pb::universal_update_participant_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

fn update_request(
    parsed: &UpdateParticipantJson,
) -> Result<pb::UniversalUpdateParticipantRequest, TransportError> {
    Ok(pb::UniversalUpdateParticipantRequest {
        scope: Some(scope_of(&parsed.scope)?),
        conference_id: Some(opaque(&parsed.conference_id)?),
        external_user_id: external_bytes(&parsed.external_user_id_b64)?,
        role: parsed.role.as_deref().map(role_code).transpose()?,
        audio_muted: parsed.audio_muted,
        camera_allowed: parsed.camera_allowed,
        publish_audio_allowed: parsed.publish_audio_allowed,
        publish_video_allowed: parsed.publish_video_allowed,
        idempotency_key: parsed.idempotency_key.clone(),
        integration_id: Some(opaque(&parsed.integration_id)?),
        screen_share_allowed: parsed.screen_share_allowed,
    })
}

async fn forward_remove_participant(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<RemoveParticipantJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalRemoveParticipantRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            external_user_id: external_bytes(&parsed.external_user_id_b64)?,
            idempotency_key: parsed.idempotency_key.clone(),
            integration_id: Some(opaque(&parsed.integration_id)?),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.remove_participant(request),
        |response| match response.result {
            Some(pb::universal_remove_participant_response::Result::Acknowledgement(ack)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "acknowledgement": acknowledgement_json(&ack) }),
                )
            }
            Some(pb::universal_remove_participant_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

async fn forward_list_participants(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<ListParticipantsJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalListParticipantsRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            max_items: parsed.max_items,
            integration_id: Some(opaque(&parsed.integration_id)?),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(client.list_participants(request), |response| match response.result {
        Some(pb::universal_list_participants_response::Result::Participants(list)) => json_response(
            StatusCode::OK,
            &json!({
                "participants": list.participants.iter().map(participant_json).collect::<Vec<_>>()
            }),
        ),
        Some(pb::universal_list_participants_response::Result::Error(error)) => error_response(&error),
        None => empty_upstream(),
    })
    .await
}

async fn forward_subscriptions(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<SubscriptionsJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match subscriptions_request(&parsed) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.set_subscriptions(request),
        |response| match response.result {
            Some(pb::universal_set_subscriptions_response::Result::Acknowledgement(ack)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "acknowledgement": acknowledgement_json(&ack) }),
                )
            }
            Some(pb::universal_set_subscriptions_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

fn subscriptions_request(
    parsed: &SubscriptionsJson,
) -> Result<pb::UniversalSetSubscriptionsRequest, TransportError> {
    let mut subscriptions = Vec::with_capacity(parsed.subscriptions.len());
    for subscription in &parsed.subscriptions {
        subscriptions.push(pb::UniversalConferenceMediaSubscription {
            source_external_user_id: external_bytes(&subscription.source_external_user_id_b64)?,
            media_kind: media_kind_code(&subscription.media_kind)?,
        });
    }
    Ok(pb::UniversalSetSubscriptionsRequest {
        scope: Some(scope_of(&parsed.scope)?),
        conference_id: Some(opaque(&parsed.conference_id)?),
        integration_id: Some(opaque(&parsed.integration_id)?),
        external_user_id: external_bytes(&parsed.external_user_id_b64)?,
        subscriptions,
    })
}

async fn forward_runtime(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<RuntimeJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalPrepareConferenceRuntimeRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
            idempotency_key: parsed.idempotency_key.clone(),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.prepare_conference_runtime(request),
        |response| match response.result {
            Some(pb::universal_prepare_conference_runtime_response::Result::Runtime(runtime)) => {
                json_response(
                    StatusCode::OK,
                    &json!({
                        "runtime": {
                            "group_ready": runtime.group_ready,
                            "call_ready": runtime.call_ready,
                            "admitted_participant_count": runtime.admitted_participant_count,
                        }
                    }),
                )
            }
            Some(pb::universal_prepare_conference_runtime_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

async fn forward_issue_join(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<IssueJoinJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match issue_request(&parsed) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.issue_join_grant(request),
        |response| match response.result {
            Some(pb::universal_issue_join_grant_response::Result::Grant(grant)) => json_response(
                StatusCode::OK,
                &json!({
                    "grant": {
                        "session_id": opaque_str(grant.session_id.as_ref()),
                        "join_url": grant.join_url,
                        "expires_at_unix_ms": grant.expires_at_unix_ms,
                    }
                }),
            ),
            Some(pb::universal_issue_join_grant_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

fn issue_request(
    parsed: &IssueJoinJson,
) -> Result<pb::UniversalIssueJoinGrantRequest, TransportError> {
    Ok(pb::UniversalIssueJoinGrantRequest {
        scope: Some(scope_of(&parsed.scope)?),
        conference_id: Some(opaque(&parsed.conference_id)?),
        integration_id: Some(opaque(&parsed.integration_id)?),
        external_user_id: external_bytes(&parsed.external_user_id_b64)?,
        ttl_seconds: parsed.ttl_seconds,
        use_policy: use_policy_code(&parsed.use_policy)?,
        not_before_unix_ms: parsed.not_before_unix_ms,
        not_after_unix_ms: parsed.not_after_unix_ms,
        idempotency_key: parsed.idempotency_key.clone(),
    })
}

async fn forward_revoke_join(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<RevokeJoinJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalRevokeJoinGrantRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            session_id: Some(opaque(&parsed.session_id)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
            idempotency_key: parsed.idempotency_key.clone(),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.revoke_join_grant(request),
        |response| match response.result {
            Some(pb::universal_revoke_join_grant_response::Result::Acknowledgement(ack)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "acknowledgement": acknowledgement_json(&ack) }),
                )
            }
            Some(pb::universal_revoke_join_grant_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

async fn forward_attendance(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<AttendanceJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalGetParticipantAttendanceRequest {
            scope: Some(scope_of(&parsed.scope)?),
            conference_id: Some(opaque(&parsed.conference_id)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
            external_user_id: external_bytes(&parsed.external_user_id_b64)?,
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.get_participant_attendance(request),
        |response| match response.result {
            Some(pb::universal_get_participant_attendance_response::Result::Attendance(
                attendance,
            )) => json_response(
                StatusCode::OK,
                &json!({ "attendance": attendance_json(&attendance) }),
            ),
            Some(pb::universal_get_participant_attendance_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

async fn forward_capabilities(
    client: &mut ConferenceClient,
    body: &[u8],
    authorization: Option<&str>,
) -> HttpResponse {
    let parsed = match decode_json::<CapabilitiesJson>(body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    forward_capabilities_input(client, parsed, authorization).await
}

async fn forward_capabilities_input(
    client: &mut ConferenceClient,
    parsed: CapabilitiesJson,
    authorization: Option<&str>,
) -> HttpResponse {
    let request = match (|| -> Result<_, TransportError> {
        Ok(pb::UniversalGetCapabilitiesRequest {
            scope: Some(scope_of(&parsed.scope)?),
            integration_id: Some(opaque(&parsed.integration_id)?),
        })
    })() {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let request = match authorized(request, authorization) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    call(
        client.get_capabilities(request),
        |response| match response.result {
            Some(pb::universal_get_capabilities_response::Result::Capabilities(capabilities)) => {
                json_response(
                    StatusCode::OK,
                    &json!({ "capabilities": capabilities_json(&capabilities) }),
                )
            }
            Some(pb::universal_get_capabilities_response::Result::Error(error)) => {
                error_response(&error)
            }
            None => empty_upstream(),
        },
    )
    .await
}

fn conference_json(conference: &pb::UniversalConferenceDescriptor) -> Value {
    let schedule = conference.schedule.as_ref();
    json!({
        "scope": scope_json(conference.scope.as_ref()),
        "conference_id": opaque_str(conference.conference_id.as_ref()),
        "integration_id": opaque_str(conference.integration_id.as_ref()),
        "external_conference_id_b64": STANDARD.encode(&conference.external_conference_id),
        "mode": enum_name(conference.mode, &["unspecified", "meeting", "webinar", "broadcast", "audio_room"]),
        "lifecycle": enum_name(conference.lifecycle, &["unspecified", "scheduled", "waiting", "live", "ending", "ended"]),
        "schedule": schedule.map(|item| json!({
            "starts_at_unix_ms": item.starts_at_unix_ms,
            "planned_end_unix_ms": item.planned_end_unix_ms,
            "join_before_seconds": item.join_before_seconds,
            "join_after_seconds": item.join_after_seconds,
            "timezone": item.timezone,
        })),
        "entry_open": conference.entry_open,
        "revision": conference.revision,
    })
}

fn participant_json(participant: &pb::UniversalConferenceParticipant) -> Value {
    json!({
        "external_user_id_b64": STANDARD.encode(&participant.external_user_id),
        "role": enum_name(participant.role, &["unspecified", "owner", "host", "moderator", "speaker", "attendee"]),
        "audio_muted": participant.audio_muted,
        "camera_allowed": participant.camera_allowed,
        "publish_audio_allowed": participant.publish_audio_allowed,
        "publish_video_allowed": participant.publish_video_allowed,
        "active": participant.active,
        "screen_share_allowed": participant.screen_share_allowed,
    })
}

fn attendance_json(attendance: &pb::UniversalParticipantAttendance) -> Value {
    json!({
        "external_user_id_b64": STANDARD.encode(&attendance.external_user_id),
        "first_join_at_unix_ms": attendance.first_join_at_unix_ms,
        "last_leave_at_unix_ms": attendance.last_leave_at_unix_ms,
        "first_media_ready_at_unix_ms": attendance.first_media_ready_at_unix_ms,
        "total_connected_seconds": attendance.total_connected_seconds,
        "current_connected_seconds": attendance.current_connected_seconds,
        "join_count": attendance.join_count,
        "reconnect_count": attendance.reconnect_count,
        "media_ready_count": attendance.media_ready_count,
        "connected": attendance.connected,
    })
}

fn capabilities_json(capabilities: &pb::UniversalConferenceCapabilities) -> Value {
    json!({
        "capabilities": capabilities.capabilities.iter().map(|capability| json!({
            "id": capability.id,
            "maturity": capability.maturity,
        })).collect::<Vec<_>>(),
        "max_participants": capabilities.max_participants,
        "browser_realtime_gateway": capabilities.browser_realtime_gateway,
        "production_webrtc": capabilities.production_webrtc,
        "turn": capabilities.turn,
        "recording": capabilities.recording,
        "horizontal_sfu": capabilities.horizontal_sfu,
    })
}

fn acknowledgement_json(ack: &pb::AcknowledgementEnvelope) -> Value {
    let version = ack.schema_version.as_ref();
    json!({
        "acknowledged_id": opaque_str(ack.acknowledged_id.as_ref()),
        "schema_version": version.map(|item| json!({ "major": item.major, "minor": item.minor })),
    })
}

fn scope_json(scope: Option<&pb::TenantScope>) -> Value {
    let Some(scope) = scope else {
        return Value::Null;
    };
    json!({
        "tenant_id": opaque_str(scope.tenant_id.as_ref()),
        "namespace_id": scope.namespace_id.as_ref().map(|id| opaque_str(Some(id))),
    })
}

fn opaque_str(id: Option<&pb::OpaqueId>) -> String {
    id.and_then(|id| String::from_utf8(id.value.clone()).ok())
        .unwrap_or_default()
}

fn enum_name(code: i32, names: &[&str]) -> String {
    names
        .get(usize::try_from(code).unwrap_or(usize::MAX))
        .copied()
        .unwrap_or("unspecified")
        .to_owned()
}

fn error_response(error: &pb::ErrorEnvelope) -> HttpResponse {
    json_response(
        error_status(error.code),
        &json!({
            "error": {
                "code": error_name(error.code),
                "retryable": error.retryable,
                "retry_after_ms": error.retry_after_ms,
            }
        }),
    )
}

fn error_name(code: i32) -> &'static str {
    match code {
        1 => "INVALID_ARGUMENT",
        7 => "UNAUTHENTICATED",
        8 => "PERMISSION_DENIED",
        9 => "POLICY_DENIED",
        10 => "RATE_LIMITED",
        11 => "RESOURCE_EXHAUSTED",
        16 => "CONFLICT",
        17 => "NOT_FOUND",
        18 => "INTERNAL",
        _ => "ERROR",
    }
}

fn error_status(code: i32) -> StatusCode {
    match code {
        7 => StatusCode::UNAUTHORIZED,
        8 | 9 => StatusCode::FORBIDDEN,
        10 | 11 => StatusCode::TOO_MANY_REQUESTS,
        16 => StatusCode::CONFLICT,
        17 => StatusCode::NOT_FOUND,
        18 => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn empty_upstream() -> HttpResponse {
    TransportError::new(
        StatusCode::BAD_GATEWAY,
        "conference service returned an empty response",
    )
    .into_response()
}

fn grpc_status(status: &tonic::Status) -> HttpResponse {
    let http = match status.code() {
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    };
    json_response(
        http,
        &json!({ "error": { "code": "UPSTREAM", "grpc_code": status.code() as i32 } }),
    )
}

async fn bounded_body(mut body: Incoming) -> Result<Bytes, TransportError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            TransportError::new(
                StatusCode::BAD_REQUEST,
                "could not read conference request body",
            )
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let next_len = bytes
            .len()
            .checked_add(data.len())
            .ok_or(TransportError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "conference request body exceeds the bounded limit",
            ))?;
        if next_len > MAX_REQUEST_BODY_BYTES {
            return Err(TransportError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "conference request body exceeds the bounded limit",
            ));
        }
        bytes.extend_from_slice(&data);
    }
    Ok(Bytes::from(bytes))
}

fn json_response(status: StatusCode, payload: &Value) -> HttpResponse {
    let bytes = serde_json::to_vec(payload)
        .unwrap_or_else(|_| br#"{"error":{"code":"INTERNAL"}}"#.to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(PRAGMA, "no-cache")
        .body(Full::new(Bytes::from(bytes)).boxed_unsync())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed_unsync()))
}

fn text_response(status: StatusCode, text: &'static str) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from_static(text.as_bytes())).boxed_unsync())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed_unsync()))
}

fn yaml_response(text: &'static str) -> HttpResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/yaml")
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from_static(text.as_bytes())).boxed_unsync())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed_unsync()))
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use rustls::pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use ucr_api_grpc::{GrpcUniversalConferenceService, universal_conference_service_server};
    use ucr_core::{
        PermissionGrantStore, ServiceQuotaClock, ServiceQuotaClockError, ServiceQuotaStore,
    };
    use ucr_crypto::{
        AccessTokenIssueRequest, MachineTokenPolicy, MachineTokenPublicKeySet,
        MachineTokenSigningKey, issue_machine_access_token,
    };
    use ucr_model::{
        IntegrationId, KeyId, NamespaceId, OpaqueId, PermissionGrant, PermissionScope, PrincipalId,
        PrincipalKind, PrincipalRef, ScopedPrincipal, ServiceQuotaPolicy, TenantId, TenantScope,
    };
    use ucr_protocol::{
        CONFERENCE_CREATE_PERMISSION, CONFERENCE_JOIN_ISSUE_PERMISSION,
        CONFERENCE_MANAGE_PERMISSION, CONFERENCE_PARTICIPANT_ENSURE_PERMISSION,
        DEVICE_REGISTER_PERMISSION,
    };
    use ucr_realtime::{JoinTokenIssuer, JoinTokenKey};
    use ucr_storage_sqlite::SqliteLocalStore;

    use super::{AppState, create_request, serve, validate_loopback_bind};

    #[test]
    fn conference_http_adapter_refuses_non_loopback_bind() {
        let public: SocketAddr = "8.8.8.8:8082".parse().expect("address");
        assert!(validate_loopback_bind(public).is_err());
        let loopback: SocketAddr = "127.0.0.1:8082".parse().expect("address");
        assert!(validate_loopback_bind(loopback).is_ok());
    }

    #[test]
    fn create_json_preserves_external_bytes_and_mode() {
        let body = br#"{
            "scope": {"tenant_id": "tenant-a", "namespace_id": "ns-a"},
            "integration_id": "integration-a",
            "external_conference_id_b64": "ZXZlbnQtMQ==",
            "idempotency_key": "create-1",
            "mode": "webinar",
            "schedule": {"starts_at_unix_ms": 10, "join_before_seconds": 5}
        }"#;
        let parsed = serde_json::from_slice(body).expect("json");
        let request = create_request(&parsed).expect("request");
        assert_eq!(request.external_conference_id, b"event-1");
        assert_eq!(request.mode, 2);
        assert_eq!(request.idempotency_key, "create-1");
        assert_eq!(
            request
                .scope
                .expect("scope")
                .tenant_id
                .expect("tenant")
                .value,
            b"tenant-a"
        );
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedClock;

    impl ServiceQuotaClock for FixedClock {
        fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
            Ok(1_100_000)
        }
    }

    #[tokio::test]
    async fn conference_http_adapter_forwards_unauthenticated_capabilities() {
        let directory = std::env::temp_dir().join(format!(
            "ucr-conference-web-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let store =
            Arc::new(SqliteLocalStore::open(directory.join("ucr.sqlite")).expect("sqlite store"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("grpc listener");
        let grpc_address = listener.local_addr().expect("grpc address");
        let incoming = TcpListenerStream::new(listener);
        let service =
            GrpcUniversalConferenceService::new(Arc::new(FixedClock), Arc::clone(&store), store);
        tokio::spawn(async move {
            Server::builder()
                .add_service(universal_conference_service_server(service))
                .serve_with_incoming(incoming)
                .await
                .expect("grpc server");
        });

        let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_address}"))
            .expect("grpc uri")
            .connect()
            .await
            .expect("grpc channel");
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("http listener");
        let http_address = http_listener.local_addr().expect("http address");
        tokio::spawn(async move {
            serve(http_listener, AppState { upstream: channel })
                .await
                .expect("http adapter");
        });

        let body = br#"{"scope":{"tenant_id":"tenant-a"},"integration_id":"integration-a"}"#;
        let mut request = format!(
            "POST /v1/capabilities HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let mut stream = tokio::net::TcpStream::connect(http_address)
            .await
            .expect("connect http");
        stream.write_all(&request).await.expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response = String::from_utf8(response).expect("utf-8 response");
        assert!(
            response.starts_with("HTTP/1.1 401"),
            "unauthenticated capabilities must fail closed: {response}"
        );
        assert!(
            response.contains("UNAUTHENTICATED"),
            "canonical error must cross the HTTP adapter: {response}"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn conference_http_adapter_is_reachable_through_the_tls_edge() {
        let directory = std::env::temp_dir().join(format!(
            "ucr-conference-edge-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let certificate = directory.join("cert.pem");
        let private_key = directory.join("key.pem");
        let status = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
            .arg(&private_key)
            .arg("-out")
            .arg(&certificate)
            .args([
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                "subjectAltName=DNS:localhost",
            ])
            .status()
            .expect("openssl");
        assert!(status.success());

        let store =
            Arc::new(SqliteLocalStore::open(directory.join("ucr.sqlite")).expect("sqlite store"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("grpc listener");
        let grpc_address = listener.local_addr().expect("grpc address");
        let incoming = TcpListenerStream::new(listener);
        let service =
            GrpcUniversalConferenceService::new(Arc::new(FixedClock), Arc::clone(&store), store);
        tokio::spawn(async move {
            Server::builder()
                .add_service(universal_conference_service_server(service))
                .serve_with_incoming(incoming)
                .await
                .expect("grpc server");
        });
        let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_address}"))
            .expect("grpc uri")
            .connect()
            .await
            .expect("grpc channel");
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("http listener");
        let http_address = http_listener.local_addr().expect("http address");
        tokio::spawn(async move {
            serve(http_listener, AppState { upstream: channel })
                .await
                .expect("http adapter");
        });

        let edge_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("edge listener");
        let edge_address = edge_listener.local_addr().expect("edge address");
        let acceptor = ucr_https_edge::tls_acceptor(
            certificate.to_str().expect("cert path"),
            private_key.to_str().expect("key path"),
        )
        .expect("tls acceptor");
        tokio::spawn(async move {
            let (stream, _) = edge_listener.accept().await.expect("edge accept");
            ucr_https_edge::proxy_connection(acceptor, stream, http_address)
                .await
                .expect("proxy");
        });

        let mut certificates =
            std::io::BufReader::new(std::fs::File::open(&certificate).expect("cert"));
        let certificate = rustls::pki_types::CertificateDer::pem_reader_iter(&mut certificates)
            .next()
            .expect("certificate")
            .expect("parse certificate");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust certificate");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = tokio::net::TcpStream::connect(edge_address)
            .await
            .expect("connect edge");
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").expect("name"),
                tcp,
            )
            .await
            .expect("handshake");
        let body = br#"{"scope":{"tenant_id":"tenant-a"},"integration_id":"integration-a"}"#;
        let mut request = format!(
            "POST /v1/capabilities HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        tls.write_all(&request).await.expect("write");
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.expect("read");
        let response = String::from_utf8(response).expect("utf-8");
        assert!(
            response.starts_with("HTTP/1.1 401"),
            "edge must forward the unauthenticated capabilities call: {response}"
        );
        assert!(response.contains("UNAUTHENTICATED"));
        let _ = std::fs::remove_dir_all(directory);
    }

    fn bearer_for_scopes(
        scopes: &[&str],
    ) -> (String, Arc<MachineTokenPublicKeySet>, MachineTokenPolicy) {
        let key = MachineTokenSigningKey::from_seed(
            KeyId::from_opaque(OpaqueId::new("conference-create-key").expect("key id")),
            [0x46_u8; 32],
        );
        let policy = MachineTokenPolicy {
            issuer: "https://auth.ucr.example.test".to_owned(),
            audience: "ucr-api".to_owned(),
            max_ttl_seconds: 900,
        };
        let subject = ScopedPrincipal {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant")),
                namespace_id: Some(NamespaceId::from_opaque(
                    OpaqueId::new("ns-a").expect("namespace"),
                )),
            },
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(
                    IntegrationId::from_opaque(
                        OpaqueId::new("integration-a").expect("integration"),
                    )
                    .as_opaque()
                    .clone(),
                ),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        let scopes = scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect::<Vec<_>>();
        let token = issue_machine_access_token(
            &key,
            &policy,
            AccessTokenIssueRequest {
                subject: &subject,
                token_id: &OpaqueId::new("conference-create-jti").expect("jti"),
                requested_scopes: &scopes,
                allowed_scopes: &scopes,
                issued_at_unix_s: 1_000,
                requested_ttl_seconds: Some(300),
            },
        )
        .expect("issue bearer");
        let keys = Arc::new(
            MachineTokenPublicKeySet::new(vec![key.public_key()]).expect("verification keys"),
        );
        (token.as_str().to_owned(), keys, policy)
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn bearer_create_conference_is_idempotent_over_http() {
        let directory = std::env::temp_dir().join(format!(
            "ucr-conference-create-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let store =
            Arc::new(SqliteLocalStore::open(directory.join("ucr.sqlite")).expect("sqlite store"));
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant")),
            namespace_id: Some(NamespaceId::from_opaque(
                OpaqueId::new("ns-a").expect("namespace"),
            )),
        };
        let subject = ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(
                    IntegrationId::from_opaque(
                        OpaqueId::new("integration-a").expect("integration"),
                    )
                    .as_opaque()
                    .clone(),
                ),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        store
            .grant_permission(&PermissionGrant {
                grantee: subject.clone(),
                permission: CONFERENCE_CREATE_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope),
            })
            .expect("grant create");
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject,
                max_requests: 4,
                window_ms: 60_000,
            })
            .expect("quota");
        let (token, keys, policy) =
            bearer_for_scopes(&[ucr_machine_auth::MACHINE_SCOPE_CONFERENCE_CREATE]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("grpc listener");
        let grpc_address = listener.local_addr().expect("grpc address");
        let incoming = TcpListenerStream::new(listener);
        let service = GrpcUniversalConferenceService::new(
            Arc::new(FixedClock),
            Arc::clone(&store),
            Arc::clone(&store),
        )
        .with_machine_bearer_auth(keys, policy);
        tokio::spawn(async move {
            Server::builder()
                .add_service(universal_conference_service_server(service))
                .serve_with_incoming(incoming)
                .await
                .expect("grpc server");
        });
        let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_address}"))
            .expect("grpc uri")
            .connect()
            .await
            .expect("grpc channel");
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("http listener");
        let http_address = http_listener.local_addr().expect("http address");
        tokio::spawn(async move {
            serve(http_listener, AppState { upstream: channel })
                .await
                .expect("http adapter");
        });

        let body = br#"{"scope":{"tenant_id":"tenant-a","namespace_id":"ns-a"},"integration_id":"integration-a","external_conference_id_b64":"ZXZlbnQtMQ==","idempotency_key":"create-1","mode":"webinar","schedule":{"starts_at_unix_ms":10,"join_before_seconds":5}}"#;
        let first = post_json(http_address, "/v1/conferences", body, &token).await;
        let second = post_json(http_address, "/v1/conferences", body, &token).await;
        assert!(
            first.starts_with("HTTP/1.1 200"),
            "bearer create must succeed: {first}"
        );
        assert!(
            second.starts_with("HTTP/1.1 200"),
            "exact retry must succeed: {second}"
        );
        let first_id = conference_id_from(&first);
        let second_id = conference_id_from(&second);
        assert_eq!(first_id, second_id);
        assert!(!first_id.is_empty());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn bearer_ensure_participant_is_idempotent_over_http() {
        let directory = std::env::temp_dir().join(format!(
            "ucr-conference-participant-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let store =
            Arc::new(SqliteLocalStore::open(directory.join("ucr.sqlite")).expect("sqlite store"));
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant")),
            namespace_id: Some(NamespaceId::from_opaque(
                OpaqueId::new("ns-a").expect("namespace"),
            )),
        };
        let subject = ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(
                    IntegrationId::from_opaque(
                        OpaqueId::new("integration-a").expect("integration"),
                    )
                    .as_opaque()
                    .clone(),
                ),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        for permission in [
            CONFERENCE_CREATE_PERMISSION,
            CONFERENCE_PARTICIPANT_ENSURE_PERMISSION,
        ] {
            store
                .grant_permission(&PermissionGrant {
                    grantee: subject.clone(),
                    permission: permission.to_owned(),
                    scope: PermissionScope::Exact(scope.clone()),
                })
                .expect("grant");
        }
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject,
                max_requests: 8,
                window_ms: 60_000,
            })
            .expect("quota");
        let (token, keys, policy) = bearer_for_scopes(&[
            ucr_machine_auth::MACHINE_SCOPE_CONFERENCE_CREATE,
            ucr_machine_auth::MACHINE_SCOPE_CONFERENCE_MANAGE,
        ]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("grpc listener");
        let grpc_address = listener.local_addr().expect("grpc address");
        let incoming = TcpListenerStream::new(listener);
        let service = GrpcUniversalConferenceService::new(
            Arc::new(FixedClock),
            Arc::clone(&store),
            Arc::clone(&store),
        )
        .with_machine_bearer_auth(keys, policy);
        tokio::spawn(async move {
            Server::builder()
                .add_service(universal_conference_service_server(service))
                .serve_with_incoming(incoming)
                .await
                .expect("grpc server");
        });
        let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_address}"))
            .expect("grpc uri")
            .connect()
            .await
            .expect("grpc channel");
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("http listener");
        let http_address = http_listener.local_addr().expect("http address");
        tokio::spawn(async move {
            serve(http_listener, AppState { upstream: channel })
                .await
                .expect("http adapter");
        });

        let created = post_json(
            http_address,
            "/v1/conferences",
            br#"{"scope":{"tenant_id":"tenant-a","namespace_id":"ns-a"},"integration_id":"integration-a","external_conference_id_b64":"ZXZlbnQtMQ==","idempotency_key":"create-1","mode":"meeting","schedule":{"starts_at_unix_ms":10}}"#,
            &token,
        )
        .await;
        assert!(
            created.starts_with("HTTP/1.1 200"),
            "create must succeed before participant ensure: {created}"
        );
        let conference_id = conference_id_from(&created);
        let participant_body = format!(
            r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","external_user_id_b64":"dXNlci0x","role":"host","idempotency_key":"ensure-1"}}"#
        );
        let first = post_json(
            http_address,
            "/v1/participants",
            participant_body.as_bytes(),
            &token,
        )
        .await;
        let second = post_json(
            http_address,
            "/v1/participants",
            participant_body.as_bytes(),
            &token,
        )
        .await;
        assert!(
            first.starts_with("HTTP/1.1 200"),
            "ensure participant must succeed: {first}"
        );
        assert!(
            second.starts_with("HTTP/1.1 200"),
            "exact participant retry must succeed: {second}"
        );
        assert!(first.contains("dXNlci0x"));
        assert!(second.contains("\"role\":\"host\""));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn bearer_issue_join_grant_is_idempotent_over_http() {
        let directory = std::env::temp_dir().join(format!(
            "ucr-conference-join-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let store =
            Arc::new(SqliteLocalStore::open(directory.join("ucr.sqlite")).expect("sqlite store"));
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant")),
            namespace_id: Some(NamespaceId::from_opaque(
                OpaqueId::new("ns-a").expect("namespace"),
            )),
        };
        let subject = ScopedPrincipal {
            scope: scope.clone(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(
                    IntegrationId::from_opaque(
                        OpaqueId::new("integration-a").expect("integration"),
                    )
                    .as_opaque()
                    .clone(),
                ),
                kind: PrincipalKind::ServiceAccount,
            },
        };
        for permission in [
            CONFERENCE_CREATE_PERMISSION,
            CONFERENCE_MANAGE_PERMISSION,
            CONFERENCE_PARTICIPANT_ENSURE_PERMISSION,
            DEVICE_REGISTER_PERMISSION,
            CONFERENCE_JOIN_ISSUE_PERMISSION,
        ] {
            store
                .grant_permission(&PermissionGrant {
                    grantee: subject.clone(),
                    permission: permission.to_owned(),
                    scope: PermissionScope::Exact(scope.clone()),
                })
                .expect("grant");
        }
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject,
                max_requests: 16,
                window_ms: 60_000,
            })
            .expect("quota");
        let (token, keys, policy) = bearer_for_scopes(&[
            ucr_machine_auth::MACHINE_SCOPE_CONFERENCE_CREATE,
            ucr_machine_auth::MACHINE_SCOPE_CONFERENCE_MANAGE,
            ucr_machine_auth::MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE,
        ]);
        let issuer = Arc::new(
            JoinTokenIssuer::new(
                JoinTokenKey::from_bytes([7_u8; 32]),
                "https://join.example.test/join",
            )
            .expect("join issuer"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("grpc listener");
        let grpc_address = listener.local_addr().expect("grpc address");
        let incoming = TcpListenerStream::new(listener);
        let service = GrpcUniversalConferenceService::with_join_issuer(
            Arc::new(FixedClock),
            Arc::clone(&store),
            Arc::clone(&store),
            issuer,
        )
        .with_machine_bearer_auth(keys, policy);
        tokio::spawn(async move {
            Server::builder()
                .add_service(universal_conference_service_server(service))
                .serve_with_incoming(incoming)
                .await
                .expect("grpc server");
        });
        let channel = tonic::transport::Channel::from_shared(format!("http://{grpc_address}"))
            .expect("grpc uri")
            .connect()
            .await
            .expect("grpc channel");
        let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("http listener");
        let http_address = http_listener.local_addr().expect("http address");
        tokio::spawn(async move {
            serve(http_listener, AppState { upstream: channel })
                .await
                .expect("http adapter");
        });

        let created = post_json(
            http_address,
            "/v1/conferences",
            br#"{"scope":{"tenant_id":"tenant-a","namespace_id":"ns-a"},"integration_id":"integration-a","external_conference_id_b64":"ZXZlbnQtMQ==","idempotency_key":"create-1","mode":"meeting","schedule":{"starts_at_unix_ms":1000000}}"#,
            &token,
        )
        .await;
        assert!(
            created.starts_with("HTTP/1.1 200"),
            "create must succeed before a join grant: {created}"
        );
        let conference_id = conference_id_from(&created);
        let owner = format!(
            r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","external_user_id_b64":"dXNlci0x","role":"owner","idempotency_key":"ensure-owner"}}"#
        );
        let ensured_owner =
            post_json(http_address, "/v1/participants", owner.as_bytes(), &token).await;
        assert!(
            ensured_owner.starts_with("HTTP/1.1 200"),
            "owner ensure must succeed before a join grant: {ensured_owner}"
        );
        let attendee = format!(
            r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","external_user_id_b64":"dXNlci0y","role":"attendee","idempotency_key":"ensure-attendee"}}"#
        );
        let ensured_attendee = post_json(
            http_address,
            "/v1/participants",
            attendee.as_bytes(),
            &token,
        )
        .await;
        assert!(
            ensured_attendee.starts_with("HTTP/1.1 200"),
            "attendee ensure must succeed before a join grant: {ensured_attendee}"
        );
        for (external_user_id_b64, idempotency_key) in [
            ("dXNlci0x", "device-owner"),
            ("dXNlci0y", "device-attendee"),
        ] {
            let device = format!(
                r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","external_user_id_b64":"{external_user_id_b64}","idempotency_key":"{idempotency_key}"}}"#
            );
            let enrolled = post_json(
                http_address,
                "/v1/participant-devices",
                device.as_bytes(),
                &token,
            )
            .await;
            assert!(
                enrolled.starts_with("HTTP/1.1 200"),
                "device enrollment must succeed before a join grant: {enrolled}"
            );
        }
        let runtime = format!(
            r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","idempotency_key":"runtime-1"}}"#
        );
        let prepared = post_json(
            http_address,
            "/v1/conferences/runtime",
            runtime.as_bytes(),
            &token,
        )
        .await;
        assert!(
            prepared.starts_with("HTTP/1.1 200"),
            "runtime preparation must succeed before a join grant: {prepared}"
        );
        assert!(
            prepared.contains("\"call_ready\":true"),
            "runtime must admit a call before a join grant: {prepared}"
        );
        let lifecycle = format!(
            r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","target":"waiting","idempotency_key":"lifecycle-1"}}"#
        );
        let waiting = post_json(
            http_address,
            "/v1/conferences/lifecycle",
            lifecycle.as_bytes(),
            &token,
        )
        .await;
        assert!(
            waiting.starts_with("HTTP/1.1 200"),
            "waiting lifecycle must succeed before a join grant: {waiting}"
        );
        assert!(waiting.contains("\"lifecycle\":\"waiting\""));
        let grant_body = format!(
            r#"{{"scope":{{"tenant_id":"tenant-a","namespace_id":"ns-a"}},"conference_id":"{conference_id}","integration_id":"integration-a","external_user_id_b64":"dXNlci0y","ttl_seconds":300,"use_policy":"single_use","idempotency_key":"join-1"}}"#
        );
        let first = post_json(
            http_address,
            "/v1/join-grants",
            grant_body.as_bytes(),
            &token,
        )
        .await;
        let second = post_json(
            http_address,
            "/v1/join-grants",
            grant_body.as_bytes(),
            &token,
        )
        .await;
        assert!(
            first.starts_with("HTTP/1.1 200"),
            "join grant must succeed: {first}"
        );
        assert!(
            second.starts_with("HTTP/1.1 200"),
            "exact join retry must succeed: {second}"
        );
        let first_grant = json_body(&first);
        let second_grant = json_body(&second);
        let session_id = first_grant["grant"]["session_id"]
            .as_str()
            .expect("session id");
        let join_url = first_grant["grant"]["join_url"].as_str().expect("join url");
        assert!(!session_id.is_empty());
        assert!(join_url.starts_with("https://join.example.test/join#ucr_join="));
        assert_eq!(first_grant["grant"]["expires_at_unix_ms"], 1_400_000);
        assert_eq!(first_grant["grant"], second_grant["grant"]);
        let _ = std::fs::remove_dir_all(directory);
    }

    async fn post_json(
        address: std::net::SocketAddr,
        path: &str,
        body: &[u8],
        token: &str,
    ) -> String {
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect http");
        stream.write_all(&request).await.expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        String::from_utf8(response).expect("utf-8 response")
    }

    fn conference_id_from(response: &str) -> String {
        json_body(response)["conference"]["conference_id"]
            .as_str()
            .expect("conference id")
            .to_owned()
    }

    fn json_body(response: &str) -> serde_json::Value {
        let json = response.split("\r\n\r\n").nth(1).expect("http body");
        serde_json::from_str(json).expect("json body")
    }
}

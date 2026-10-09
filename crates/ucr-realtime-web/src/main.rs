#![forbid(unsafe_code)]

use std::{convert::Infallible, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HOST, ORIGIN, VARY,
    },
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{Request as GrpcRequest, metadata::MetadataValue, transport::Channel};
use ucr_api_grpc::pb;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:50051";
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_BEARER_BYTES: usize = 4096;
const MAX_SIGNALING_SDP_BYTES: usize = 256 * 1024;
const MAX_SIGNALING_ICE_CANDIDATE_BYTES: usize = 4096;
const MAX_SIGNALING_ICE_MID_BYTES: usize = 256;
const CLIENT_HTML: &str = include_str!("../static/client.html");

// Generated endpoint-only public code: no secrets, grants or MLS state in these
// artifacts. The gateway serves only an explicit allowlist, never a directory.
const REFERENCE_MEDIA_ASSETS: [(&str, &str, &str); 3] = [
    (
        "/endpoint-media/reference_browser_media_installer.js",
        "endpoint-media/reference_browser_media_installer.js",
        "text/javascript; charset=utf-8",
    ),
    (
        "/endpoint-wasm/ucr_endpoint_wasm.js",
        "endpoint-wasm/ucr_endpoint_wasm.js",
        "text/javascript; charset=utf-8",
    ),
    (
        "/endpoint-wasm/ucr_endpoint_wasm_bg.wasm",
        "endpoint-wasm/ucr_endpoint_wasm_bg.wasm",
        "application/wasm",
    ),
];

type HttpBody = UnsyncBoxBody<Bytes, Infallible>;
type HttpResponse = Response<HttpBody>;

#[derive(Debug, Clone, Copy)]
struct GatewayFailure {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl GatewayFailure {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    fn into_response(self) -> HttpResponse {
        api_error(self.status, self.code, self.message)
    }
}

#[derive(Clone, Debug)]
struct AppState {
    upstream: Channel,
    allowed_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    #[serde(rename = "tenant_id")]
    tenant: String,
    #[serde(rename = "namespace_id")]
    namespace: Option<String>,
    #[serde(rename = "call_id")]
    call: String,
    #[serde(rename = "session_id")]
    session: String,
}

#[derive(Debug, Deserialize)]
struct HeartbeatRequest {
    #[serde(flatten)]
    session: SessionRequest,
    expected_session_sequence: u64,
}

#[derive(Debug, Deserialize)]
struct RaisedHandRequest {
    #[serde(flatten)]
    session: SessionRequest,
    raised: bool,
}

#[derive(Debug, Deserialize)]
struct PublishReactionRequest {
    #[serde(flatten)]
    session: SessionRequest,
    reaction: String,
}

#[derive(Debug, Deserialize)]
struct ListReactionsRequest {
    #[serde(flatten)]
    session: SessionRequest,
    after_sequence: u64,
    max_items: u32,
}

#[derive(Debug, Serialize)]
struct ReactionResponse {
    sequence: u64,
    participant_id_b64: String,
    reaction: String,
}

#[derive(Debug, Serialize)]
struct ReactionListResponse {
    ok: bool,
    reactions: Vec<ReactionResponse>,
}

#[derive(Debug, Serialize)]
struct ReactionReceiptResponse {
    ok: bool,
    sequence: u64,
}

#[derive(Debug, Serialize)]
struct ReceiveRosterSourceResponse {
    source_id: String,
    source_kind: i32,
}

#[derive(Debug, Serialize)]
struct ReceiveRosterResponse {
    ok: bool,
    call_revision: u64,
    sources: Vec<ReceiveRosterSourceResponse>,
}

#[derive(Debug, Deserialize)]
struct BrowserMediaSubscription {
    source_id: String,
    source_kind: i32,
    media_kind: i32,
    stream_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetMediaSubscriptionsRequest {
    #[serde(flatten)]
    session: SessionRequest,
    subscriptions: Vec<BrowserMediaSubscription>,
}

#[derive(Debug, Deserialize)]
struct AdaptiveMediaRequest {
    #[serde(flatten)]
    session: SessionRequest,
    estimated_bandwidth_bps: u64,
    packet_loss_basis_points: u32,
    jitter_ms: u32,
    rtt_ms: u32,
    cpu_utilization_percent: u32,
    gpu_utilization_percent: Option<u32>,
    battery_percent: u32,
    external_power: bool,
    thermal_state: String,
}

#[derive(Debug, Serialize)]
struct AdaptiveVideoResponse {
    codec_capability_id: String,
    width: u32,
    height: u32,
    frame_rate: u32,
    target_bitrate_bps: u32,
}

#[derive(Debug, Serialize)]
struct AdaptiveMediaResponse {
    ok: bool,
    stage: String,
    changed: bool,
    requires_media_renegotiation: bool,
    video: Option<AdaptiveVideoResponse>,
    opus_target_bitrate_bps: Option<u32>,
    deferred_fallbacks: Vec<String>,
    pressures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AudioLevelRequest {
    #[serde(flatten)]
    session: SessionRequest,
    level: u32,
}

#[derive(Debug, Serialize)]
struct ActiveSpeakerResponse {
    ok: bool,
    participant_id_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SendChatMessageRequest {
    #[serde(flatten)]
    session: SessionRequest,
    message_id: String,
    created_at_unix_ms: i64,
    correlation_id: String,
    idempotency_key: Option<String>,
    content: String,
}

#[derive(Debug, Deserialize)]
struct GetChatMessageRequest {
    #[serde(flatten)]
    session: SessionRequest,
    message_id: String,
}

#[derive(Debug, Serialize)]
struct ChatMessageReceiptResponse {
    ok: bool,
    message_id: String,
}

#[derive(Debug, Serialize)]
struct ChatMessageResponse {
    ok: bool,
    message_id: String,
    author_id_b64: String,
    author_kind: i32,
    created_at_unix_ms: i64,
    logical_order: u64,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ListChatMessagesRequest {
    #[serde(flatten)]
    session: SessionRequest,
    after_sequence: u64,
    max_items: u32,
}

#[derive(Debug, Serialize)]
struct SequencedChatMessageResponse {
    sequence: u64,
    message_id: String,
    author_id_b64: String,
    author_kind: i32,
    created_at_unix_ms: i64,
    logical_order: u64,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatMessageListResponse {
    ok: bool,
    messages: Vec<SequencedChatMessageResponse>,
    next_sequence: u64,
}

#[derive(Debug, Deserialize)]
struct PublishRequest {
    #[serde(flatten)]
    session: SessionRequest,
    envelope_base64: String,
}

#[derive(Debug, Deserialize)]
struct WebRtcRemoteDescriptionRequest {
    #[serde(flatten)]
    session: SessionRequest,
    sdp_type: String,
    sdp: String,
}

#[derive(Debug, Deserialize)]
struct WebRtcIceCandidateRequest {
    #[serde(flatten)]
    session: SessionRequest,
    candidate: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct MlsKeyPackageRequest {
    tenant_id: String,
    namespace_id: Option<String>,
    call_id: String,
    session_id: String,
    key_package_base64: String,
}

#[derive(Debug, Serialize)]
struct MlsAdmissionContextResponse {
    ok: bool,
    group_id: String,
    endpoint_state_mode: &'static str,
}

#[derive(Debug, Serialize)]
struct MlsCryptoStateResponse {
    crypto_epoch: u64,
    crypto_state_ref: String,
}

#[derive(Debug, Serialize)]
struct MlsBootstrapCommitResponse {
    commit_base64: String,
    next_crypto_state: MlsCryptoStateResponse,
}

#[derive(Debug, Serialize)]
struct MlsBootstrapResponse {
    ok: bool,
    group_id: String,
    welcome_base64: String,
    welcome_crypto_state: MlsCryptoStateResponse,
    subsequent_commits: Vec<MlsBootstrapCommitResponse>,
    current_crypto_state: MlsCryptoStateResponse,
}

#[derive(Debug, Serialize)]
struct WebRtcIceServerResponse {
    urls: Vec<String>,
    username: Option<String>,
    credential: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebRtcOfferResponse {
    ok: bool,
    code: &'static str,
    message: &'static str,
    sdp_type: &'static str,
    sdp: String,
    ice_servers: Vec<WebRtcIceServerResponse>,
}

#[derive(Debug, Serialize)]
struct BrowserMediaPolicyResponse {
    #[serde(rename = "publish_audio_allowed")]
    audio: Option<bool>,
    #[serde(rename = "publish_camera_allowed")]
    camera: Option<bool>,
    #[serde(rename = "screen_share_allowed")]
    screen_share: Option<bool>,
}

impl From<pb::RealtimeMediaPolicy> for BrowserMediaPolicyResponse {
    fn from(value: pb::RealtimeMediaPolicy) -> Self {
        Self {
            audio: value.publish_audio_allowed,
            camera: value.publish_camera_allowed,
            screen_share: value.screen_share_allowed,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiResponse {
    ok: bool,
    code: &'static str,
    message: String,
    expires_at_unix_ms: Option<i64>,
    heartbeat_interval_ms: Option<u64>,
    accepted_recipient_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    admission_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    media_policy: Option<BrowserMediaPolicyResponse>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ucr-realtime-web: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let bind: SocketAddr = std::env::var("UCR_REALTIME_WEB_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()
        .map_err(|error| format!("invalid UCR_REALTIME_WEB_BIND: {error}"))?;
    validate_loopback_bind(bind)?;

    let upstream =
        std::env::var("UCR_REALTIME_GRPC_UPSTREAM").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    let channel = Channel::from_shared(upstream)
        .map_err(|error| format!("invalid realtime upstream URI: {error}"))?
        .connect()
        .await
        .map_err(|error| format!("connect realtime upstream: {error}"))?;
    let allowed_origins_raw = std::env::var("UCR_REALTIME_ALLOWED_ORIGINS").unwrap_or_default();
    let allowed_origins = parse_allowed_origins(&allowed_origins_raw)?;
    let state = AppState {
        upstream: channel,
        allowed_origins,
    };

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind browser gateway: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve browser gateway: {error}"))?;
    println!("UCR_REALTIME_WEB_READY endpoint=http://{address} tls_edge=required");

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept browser gateway connection: {error}"))?;
        let io = TokioIo::new(stream);
        let connection_state = state.clone();
        tokio::spawn(async move {
            let service =
                service_fn(move |request| handle_request(request, connection_state.clone()));
            let builder = auto::Builder::new(TokioExecutor::new());
            if let Err(error) = builder.serve_connection(io, service).await {
                eprintln!("ucr-realtime-web: connection closed: {error}");
            }
        });
    }
}

fn validate_loopback_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(
            "browser gateway requires a loopback bind; publish it only through a trusted HTTPS reverse proxy"
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
    let origin = match request_origin(request.headers(), &state.allowed_origins) {
        Ok(origin) => origin,
        Err(error) => return Ok(error.into_response()),
    };

    if method == Method::OPTIONS {
        return Ok(cors_preflight(origin.as_deref()));
    }

    if method == Method::GET && path == "/healthz" {
        return Ok(text_response(StatusCode::OK, "ok"));
    }
    if method == Method::GET && matches!(path.as_str(), "/" | "/join" | "/conference") {
        return Ok(html_response(StatusCode::OK, CLIENT_HTML));
    }
    if method == Method::GET && reference_media_asset(&path).is_some() {
        return Ok(serve_reference_media_asset(&path));
    }

    if method != Method::POST {
        return Ok(api_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "only POST is supported for realtime operations",
        ));
    }

    let token = match bearer_from_headers(request.headers()) {
        Ok(token) => token,
        Err(error) => return Ok(error.into_response()),
    };
    let body = match bounded_body(request.into_body()).await {
        Ok(body) => body,
        Err(error) => return Ok(error.into_response()),
    };

    let response = handle_post_route(&state, &token, &path, &body).await;

    Ok(with_cors(response, origin.as_deref()))
}

async fn handle_post_route(state: &AppState, token: &str, path: &str, body: &[u8]) -> HttpResponse {
    match path {
        "/v1/realtime/join" => match decode_json::<SessionRequest>(body) {
            Ok(input) => join(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/heartbeat" => match decode_json::<HeartbeatRequest>(body) {
            Ok(input) => heartbeat(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/leave" => match decode_json::<SessionRequest>(body) {
            Ok(input) => leave(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/mls-context" => match decode_json::<SessionRequest>(body) {
            Ok(input) => get_mls_admission_context(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/mls-key-package" => match decode_json::<MlsKeyPackageRequest>(body) {
            Ok(input) => register_mls_key_package(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/mls-bootstrap" => match decode_json::<SessionRequest>(body) {
            Ok(input) => get_mls_bootstrap(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/raised-hand" => match decode_json::<RaisedHandRequest>(body) {
            Ok(input) => set_raised_hand(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/reactions/publish" => match decode_json::<PublishReactionRequest>(body) {
            Ok(input) => publish_reaction(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/reactions/list" => match decode_json::<ListReactionsRequest>(body) {
            Ok(input) => list_reactions(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/receive-roster" => match decode_json::<SessionRequest>(body) {
            Ok(input) => get_receive_roster(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/subscriptions" => match decode_json::<SetMediaSubscriptionsRequest>(body) {
            Ok(input) => set_media_subscriptions(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/adaptive-media" => match decode_json::<AdaptiveMediaRequest>(body) {
            Ok(input) => report_adaptive_media(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/audio-level" | "/v1/realtime/active-speaker" => {
            handle_active_speaker_route(state, token, path, body).await
        }
        "/v1/realtime/chat/send" | "/v1/realtime/chat/get" | "/v1/realtime/chat/list" => {
            handle_chat_route(state, token, path, body).await
        }
        "/v1/realtime/media/publish" => match decode_json::<PublishRequest>(body) {
            Ok(input) => publish_media(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/media/stream" => match decode_json::<SessionRequest>(body) {
            Ok(input) => subscribe_media(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/start" => match decode_json::<SessionRequest>(body) {
            Ok(input) => start_webrtc(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/remote-description" => {
            match decode_json::<WebRtcRemoteDescriptionRequest>(body) {
                Ok(input) => set_webrtc_remote_description(state, token, input).await,
                Err(error) => error.into_response(),
            }
        }
        "/v1/realtime/webrtc/ice" => match decode_json::<WebRtcIceCandidateRequest>(body) {
            Ok(input) => add_webrtc_ice_candidate(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/restart" => match decode_json::<SessionRequest>(body) {
            Ok(input) => restart_webrtc(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/close" => match decode_json::<SessionRequest>(body) {
            Ok(input) => close_webrtc(state, token, input).await,
            Err(error) => error.into_response(),
        },
        _ => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "realtime route not found",
        ),
    }
}

fn parse_allowed_origins(raw: &str) -> Result<Vec<String>, String> {
    let mut origins = Vec::new();
    for candidate in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if candidate == "*" {
            return Err(
                "UCR_REALTIME_ALLOWED_ORIGINS must not contain wildcard origins".to_owned(),
            );
        }
        let valid_scheme = candidate.starts_with("https://")
            || candidate.starts_with("http://127.0.0.1:")
            || candidate.starts_with("http://localhost:");
        if !valid_scheme
            || candidate.contains(char::is_whitespace)
            || candidate.ends_with('/')
            || candidate.contains('#')
            || candidate.contains('?')
        {
            return Err(format!("invalid allowed realtime origin: {candidate}"));
        }
        if !origins.iter().any(|origin| origin == candidate) {
            origins.push(candidate.to_owned());
        }
    }
    Ok(origins)
}

fn request_origin(
    headers: &hyper::HeaderMap,
    allowed_origins: &[String],
) -> Result<Option<String>, GatewayFailure> {
    let Some(value) = headers.get(ORIGIN) else {
        return Ok(None);
    };
    let origin = value.to_str().map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_origin",
            "invalid browser Origin header",
        )
    })?;
    let same_origin = headers
        .get(HOST)
        .and_then(|host| host.to_str().ok())
        .is_some_and(|host| {
            origin == format!("https://{host}") || origin == format!("http://{host}")
        });
    if same_origin || allowed_origins.iter().any(|allowed| allowed == origin) {
        Ok(Some(origin.to_owned()))
    } else {
        Err(GatewayFailure::new(
            StatusCode::FORBIDDEN,
            "origin_denied",
            "browser origin is not allowed for this realtime gateway",
        ))
    }
}

fn with_cors(mut response: HttpResponse, origin: Option<&str>) -> HttpResponse {
    if let Some(origin) = origin
        && let Ok(value) = hyper::header::HeaderValue::from_str(origin)
    {
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
        response
            .headers_mut()
            .insert(VARY, hyper::header::HeaderValue::from_static("Origin"));
    }
    response
}

fn cors_preflight(origin: Option<&str>) -> HttpResponse {
    let mut response = empty_response(StatusCode::NO_CONTENT);
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        hyper::header::HeaderValue::from_static("POST, OPTIONS"),
    );
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        hyper::header::HeaderValue::from_static("Authorization, Content-Type"),
    );
    with_cors(response, origin)
}

async fn join(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeJoinRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.join_realtime(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_join_response::Result::Session(session)) => {
                let media_policy = session.media_policy.map(BrowserMediaPolicyResponse::from);
                api_ok_with_realtime_state(
                    "joined",
                    "realtime session joined",
                    Some(session.expires_at_unix_ms),
                    Some(session.heartbeat_interval_ms),
                    None,
                    admission_state_name(session.admission_state),
                    media_policy,
                )
            }
            Some(pb::realtime_join_response::Result::Error(error)) => join_error(&error),
            None => api_error(
                StatusCode::UNAUTHORIZED,
                "join_rejected",
                "realtime join rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

fn join_error(error: &pb::ErrorEnvelope) -> HttpResponse {
    if error.code == pb::ErrorCode::PolicyDenied as i32 && error.retryable {
        return api_error(
            StatusCode::TOO_EARLY,
            "waiting_room",
            "conference entry is not open yet",
        );
    }
    api_error(
        StatusCode::UNAUTHORIZED,
        "join_rejected",
        "realtime join rejected",
    )
}

async fn heartbeat(state: &AppState, token: &str, input: HeartbeatRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeHeartbeatRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        expected_session_sequence: input.expected_session_sequence,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.heartbeat_realtime(request).await {
        Ok(response) => {
            let response = response.into_inner();
            match response.result {
                Some(pb::realtime_heartbeat_response::Result::Acknowledgement(_)) => {
                    let media_policy = response.media_policy.map(BrowserMediaPolicyResponse::from);
                    api_ok_with_realtime_state(
                        "alive",
                        "realtime heartbeat accepted",
                        None,
                        None,
                        None,
                        admission_state_name(response.admission_state),
                        media_policy,
                    )
                }
                Some(pb::realtime_heartbeat_response::Result::Error(_)) | None => api_error(
                    StatusCode::CONFLICT,
                    "heartbeat_rejected",
                    "realtime heartbeat rejected",
                ),
            }
        }
        Err(status) => grpc_error(&status),
    }
}

async fn get_mls_admission_context(
    state: &AppState,
    token: &str,
    input: SessionRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeGetMlsAdmissionContextRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    match client.get_mls_admission_context(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_get_mls_admission_context_response::Result::Context(context)) => {
                let Some(group_id) = context.group_id else {
                    return GatewayFailure::new(
                        StatusCode::BAD_GATEWAY,
                        "invalid_mls_context",
                        "realtime upstream returned an MLS context without Group ID",
                    )
                    .into_response();
                };
                let mode =
                    match pb::RealtimeMlsEndpointStateMode::try_from(context.endpoint_state_mode) {
                        Ok(pb::RealtimeMlsEndpointStateMode::Register) => "register",
                        Ok(pb::RealtimeMlsEndpointStateMode::Restore) => "restore",
                        Ok(pb::RealtimeMlsEndpointStateMode::LegacyServerOwned) => {
                            "legacy_server_owned"
                        }
                        _ => {
                            return GatewayFailure::new(
                                StatusCode::BAD_GATEWAY,
                                "invalid_mls_context",
                                "realtime upstream returned an unspecified MLS endpoint state mode",
                            )
                            .into_response();
                        }
                    };
                match String::from_utf8(group_id.value) {
                    Ok(group_id) => json_response(
                        StatusCode::OK,
                        &MlsAdmissionContextResponse {
                            ok: true,
                            group_id,
                            endpoint_state_mode: mode,
                        },
                    ),
                    Err(_) => GatewayFailure::new(
                        StatusCode::BAD_GATEWAY,
                        "invalid_mls_context",
                        "realtime upstream returned a non-text MLS Group ID",
                    )
                    .into_response(),
                }
            }
            Some(pb::realtime_get_mls_admission_context_response::Result::Error(error)) => {
                canonical_error_response(
                    &error,
                    "mls_context_rejected",
                    "device-bound MLS admission context rejected",
                )
            }
            None => empty_upstream(),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn register_mls_key_package(
    state: &AppState,
    token: &str,
    input: MlsKeyPackageRequest,
) -> HttpResponse {
    let key_package = match STANDARD.decode(input.key_package_base64.as_bytes()) {
        Ok(bytes)
            if !bytes.is_empty()
                && bytes.len() <= ucr_api_grpc::REALTIME_MLS_KEY_PACKAGE_MAX_BYTES =>
        {
            bytes
        }
        _ => {
            return GatewayFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_mls_key_package",
                "MLS KeyPackage is invalid or exceeds the wire bound",
            )
            .into_response();
        }
    };
    let session = SessionRequest {
        tenant: input.tenant_id,
        namespace: input.namespace_id,
        call: input.call_id,
        session: input.session_id,
    };
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeRegisterMlsKeyPackageRequest {
        scope: Some(pb_scope(&session)),
        call_id: Some(pb_id(&session.call)),
        session_id: Some(pb_id(&session.session)),
        key_package,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    match client.register_mls_key_package(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_register_mls_key_package_response::Result::Acknowledgement(_)) => {
                json_response(StatusCode::OK, &serde_json::json!({"ok": true}))
            }
            Some(pb::realtime_register_mls_key_package_response::Result::Error(error)) => {
                canonical_error_response(
                    &error,
                    "mls_key_package_rejected",
                    "device-bound MLS KeyPackage rejected",
                )
            }
            None => empty_upstream(),
        },
        Err(status) => grpc_error(&status),
    }
}

fn decode_mls_crypto_state(
    state: pb::RealtimeMlsCryptoState,
) -> Result<MlsCryptoStateResponse, GatewayFailure> {
    let state_ref = state.crypto_state_ref.ok_or_else(|| {
        GatewayFailure::new(
            StatusCode::BAD_GATEWAY,
            "invalid_mls_bootstrap",
            "realtime upstream returned an invalid MLS crypto state",
        )
    })?;
    let crypto_state_ref = String::from_utf8(state_ref.value).map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_GATEWAY,
            "invalid_mls_bootstrap",
            "realtime upstream returned a non-text MLS state reference",
        )
    })?;
    Ok(MlsCryptoStateResponse {
        crypto_epoch: state.crypto_epoch,
        crypto_state_ref,
    })
}

fn decode_mls_bootstrap(
    bootstrap: pb::RealtimeMlsBootstrap,
) -> Result<MlsBootstrapResponse, GatewayFailure> {
    let group_id = bootstrap.group_id.ok_or_else(|| {
        GatewayFailure::new(
            StatusCode::BAD_GATEWAY,
            "invalid_mls_bootstrap",
            "realtime upstream returned an MLS bootstrap without a Group ID",
        )
    })?;
    let group_id = String::from_utf8(group_id.value).map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_GATEWAY,
            "invalid_mls_bootstrap",
            "realtime upstream returned a non-text MLS Group ID",
        )
    })?;
    let welcome_crypto_state =
        decode_mls_crypto_state(bootstrap.welcome_crypto_state.ok_or_else(|| {
            GatewayFailure::new(
                StatusCode::BAD_GATEWAY,
                "invalid_mls_bootstrap",
                "realtime upstream returned an MLS bootstrap without Welcome state",
            )
        })?)?;
    let current_crypto_state =
        decode_mls_crypto_state(bootstrap.current_crypto_state.ok_or_else(|| {
            GatewayFailure::new(
                StatusCode::BAD_GATEWAY,
                "invalid_mls_bootstrap",
                "realtime upstream returned an MLS bootstrap without current state",
            )
        })?)?;
    let mut subsequent_commits = Vec::with_capacity(bootstrap.subsequent_commits.len());
    for commit in bootstrap.subsequent_commits {
        let next_crypto_state =
            decode_mls_crypto_state(commit.next_crypto_state.ok_or_else(|| {
                GatewayFailure::new(
                    StatusCode::BAD_GATEWAY,
                    "invalid_mls_bootstrap",
                    "realtime upstream returned an MLS commit without next state",
                )
            })?)?;
        subsequent_commits.push(MlsBootstrapCommitResponse {
            commit_base64: STANDARD.encode(commit.commit),
            next_crypto_state,
        });
    }
    Ok(MlsBootstrapResponse {
        ok: true,
        group_id,
        welcome_base64: STANDARD.encode(bootstrap.welcome),
        welcome_crypto_state,
        subsequent_commits,
        current_crypto_state,
    })
}

async fn get_mls_bootstrap(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeGetMlsBootstrapRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.get_mls_bootstrap(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_get_mls_bootstrap_response::Result::Bootstrap(bootstrap)) => {
                match decode_mls_bootstrap(bootstrap) {
                    Ok(bootstrap) => json_response(StatusCode::OK, &bootstrap),
                    Err(error) => error.into_response(),
                }
            }
            Some(pb::realtime_get_mls_bootstrap_response::Result::Error(error)) => {
                canonical_error_response(
                    &error,
                    "mls_bootstrap_rejected",
                    "device-bound MLS bootstrap rejected",
                )
            }
            None => empty_upstream(),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn leave(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeLeaveRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.leave_realtime(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_leave_response::Result::Acknowledgement(_)) => {
                api_ok("left", "realtime session left", None, None, None)
            }
            Some(pb::realtime_leave_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "leave_rejected",
                "realtime leave rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn set_raised_hand(state: &AppState, token: &str, input: RaisedHandRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeSetRaisedHandRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        raised: input.raised,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.set_raised_hand(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_set_raised_hand_response::Result::Acknowledgement(_)) => api_ok(
                if input.raised {
                    "hand_raised"
                } else {
                    "hand_lowered"
                },
                if input.raised {
                    "raised hand set"
                } else {
                    "raised hand cleared"
                },
                None,
                None,
                None,
            ),
            Some(pb::realtime_set_raised_hand_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "raised_hand_rejected",
                "raised hand update rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn publish_reaction(
    state: &AppState,
    token: &str,
    input: PublishReactionRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimePublishReactionRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        reaction: input.reaction,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.publish_reaction(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_publish_reaction_response::Result::Receipt(receipt)) => {
                json_response(
                    StatusCode::OK,
                    &ReactionReceiptResponse {
                        ok: true,
                        sequence: receipt.sequence,
                    },
                )
            }
            Some(pb::realtime_publish_reaction_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "reaction_rejected",
                "conference reaction rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn list_reactions(
    state: &AppState,
    token: &str,
    input: ListReactionsRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeListReactionsRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        after_sequence: input.after_sequence,
        max_items: input.max_items,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.list_reactions(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_list_reactions_response::Result::Reactions(list)) => {
                let reactions = list
                    .reactions
                    .into_iter()
                    .map(|reaction| {
                        let participant_id_b64 = reaction
                            .participant
                            .and_then(|participant| participant.principal_id)
                            .map(|id| STANDARD.encode(id.value))
                            .unwrap_or_default();
                        ReactionResponse {
                            sequence: reaction.sequence,
                            participant_id_b64,
                            reaction: reaction.reaction,
                        }
                    })
                    .collect();
                json_response(
                    StatusCode::OK,
                    &ReactionListResponse {
                        ok: true,
                        reactions,
                    },
                )
            }
            Some(pb::realtime_list_reactions_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "reactions_rejected",
                "conference reaction list rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn handle_chat_route(state: &AppState, token: &str, path: &str, body: &[u8]) -> HttpResponse {
    match path {
        "/v1/realtime/chat/send" => match decode_json::<SendChatMessageRequest>(body) {
            Ok(input) => send_chat_message(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/chat/get" => match decode_json::<GetChatMessageRequest>(body) {
            Ok(input) => get_chat_message(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/chat/list" => match decode_json::<ListChatMessagesRequest>(body) {
            Ok(input) => list_chat_messages(state, token, input).await,
            Err(error) => error.into_response(),
        },
        _ => api_error(
            StatusCode::NOT_FOUND,
            "route_not_found",
            "realtime route not found",
        ),
    }
}

async fn send_chat_message(
    state: &AppState,
    token: &str,
    input: SendChatMessageRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeSendChatMessageRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        message_id: Some(pb_id(&input.message_id)),
        created_at_unix_ms: input.created_at_unix_ms,
        correlation_id: Some(pb_id(&input.correlation_id)),
        idempotency_key: input.idempotency_key,
        content: input.content.into_bytes(),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.send_chat_message(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_send_chat_message_response::Result::Receipt(receipt)) => {
                let Some(message_id) = receipt.message_id else {
                    return empty_upstream();
                };
                match String::from_utf8(message_id.value) {
                    Ok(message_id) => json_response(
                        StatusCode::OK,
                        &ChatMessageReceiptResponse {
                            ok: true,
                            message_id,
                        },
                    ),
                    Err(_) => empty_upstream(),
                }
            }
            Some(pb::realtime_send_chat_message_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "chat_message_rejected",
                "conference chat message rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn list_chat_messages(
    state: &AppState,
    token: &str,
    input: ListChatMessagesRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeListChatMessagesRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        after_sequence: input.after_sequence,
        max_items: input.max_items,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.list_chat_messages(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_list_chat_messages_response::Result::Messages(list)) => {
                let mut messages = Vec::with_capacity(list.messages.len());
                for entry in list.messages {
                    let Some(message) = entry.message else {
                        continue;
                    };
                    let Some(message_id) = message.message_id else {
                        continue;
                    };
                    let Some(author) = message.author else {
                        continue;
                    };
                    let Some(actor_id) = author.actor_id else {
                        continue;
                    };
                    let Ok(message_id) = String::from_utf8(message_id.value) else {
                        continue;
                    };
                    let Ok(content) = String::from_utf8(message.content) else {
                        continue;
                    };
                    messages.push(SequencedChatMessageResponse {
                        sequence: entry.sequence,
                        message_id,
                        author_id_b64: STANDARD.encode(actor_id.value),
                        author_kind: author.kind,
                        created_at_unix_ms: message.created_at_unix_ms,
                        logical_order: message.logical_order,
                        content,
                    });
                }
                json_response(
                    StatusCode::OK,
                    &ChatMessageListResponse {
                        ok: true,
                        messages,
                        next_sequence: list.next_sequence,
                    },
                )
            }
            Some(pb::realtime_list_chat_messages_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "chat_list_rejected",
                "conference chat list rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn get_chat_message(
    state: &AppState,
    token: &str,
    input: GetChatMessageRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeGetChatMessageRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        message_id: Some(pb_id(&input.message_id)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.get_chat_message(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_get_chat_message_response::Result::Message(message)) => {
                let Some(message_id) = message.message_id else {
                    return empty_upstream();
                };
                let Some(author) = message.author else {
                    return empty_upstream();
                };
                let Some(actor_id) = author.actor_id else {
                    return empty_upstream();
                };
                let Ok(message_id) = String::from_utf8(message_id.value) else {
                    return empty_upstream();
                };
                let Ok(content) = String::from_utf8(message.content) else {
                    return api_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "chat_content_not_text",
                        "conference chat content is not UTF-8 text",
                    );
                };
                json_response(
                    StatusCode::OK,
                    &ChatMessageResponse {
                        ok: true,
                        message_id,
                        author_id_b64: STANDARD.encode(actor_id.value),
                        author_kind: author.kind,
                        created_at_unix_ms: message.created_at_unix_ms,
                        logical_order: message.logical_order,
                        content,
                    },
                )
            }
            Some(pb::realtime_get_chat_message_response::Result::Error(_)) | None => api_error(
                StatusCode::NOT_FOUND,
                "chat_message_not_found",
                "conference chat message not found",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

/// The current accepted sender candidates are projected from the canonical
/// `CallSession`, after validating this same bearer/session and active admission.
/// These identities cannot be invented or changed by an untrusted browser.
async fn get_receive_roster(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut request = GrpcRequest::new(pb::RealtimeGetReceiveRosterRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    let mut client = client(state);
    match client.get_receive_roster(request).await {
        Ok(reply) => match reply.into_inner().result {
            Some(pb::realtime_get_receive_roster_response::Result::Roster(roster)) => {
                let mut sources = Vec::with_capacity(roster.accepted_sources.len());
                for principal in roster.accepted_sources {
                    let Some(id) = principal.principal_id else {
                        return api_error(
                            StatusCode::BAD_GATEWAY,
                            "invalid_roster",
                            "canonical source identity unavailable",
                        );
                    };
                    let Ok(source_id) = String::from_utf8(id.value) else {
                        return api_error(
                            StatusCode::BAD_GATEWAY,
                            "unsupported_roster_id",
                            "canonical source identity cannot be represented in browser",
                        );
                    };
                    if !valid_subscription_id(&source_id) {
                        return api_error(
                            StatusCode::BAD_GATEWAY,
                            "invalid_roster_id",
                            "canonical source identity exceeds browser bounds",
                        );
                    }
                    sources.push(ReceiveRosterSourceResponse {
                        source_id,
                        source_kind: principal.kind,
                    });
                }
                json_response(
                    StatusCode::OK,
                    &ReceiveRosterResponse {
                        ok: true,
                        call_revision: roster.call_revision,
                        sources,
                    },
                )
            }
            Some(pb::realtime_get_receive_roster_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "receive_roster_rejected",
                "canonical receive roster unavailable or access revoked",
            ),
        },
        Err(error) => grpc_error(&error),
    }
}

/// Replace only this authenticated viewer's ephemeral receive set. Exact stream IDs
/// allow the current canonical SFU to forward a selected ciphertext layer without
/// decoding frames or changing any publisher's shared encoder.
async fn set_media_subscriptions(
    state: &AppState,
    token: &str,
    input: SetMediaSubscriptionsRequest,
) -> HttpResponse {
    if input.subscriptions.len() > 32 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "too_many_subscriptions",
            "subscriber stream selection exceeds capacity",
        );
    }
    let mut layers = Vec::with_capacity(input.subscriptions.len());
    for item in input.subscriptions {
        if !valid_subscription_id(&item.source_id)
            || item
                .stream_id
                .as_ref()
                .is_some_and(|id| !valid_subscription_id(id))
            || item.media_kind != pb::MediaKind::Audio as i32
                && item.media_kind != pb::MediaKind::Video as i32
            || item.media_kind == pb::MediaKind::Audio as i32 && item.stream_id.is_some()
        {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_stream_selection",
                "invalid subscriber source or encrypted video stream",
            );
        }
        layers.push(pb::ConferenceMediaSubscription {
            source: Some(pb::PrincipalRef {
                principal_id: Some(pb_id(&item.source_id)),
                kind: item.source_kind,
            }),
            media_kind: item.media_kind,
            stream_id: item.stream_id.as_deref().map(pb_id),
        });
    }
    let mut request = GrpcRequest::new(pb::RealtimeSetSubscriptionsRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        subscriptions: layers,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    let mut client = client(state);
    match client.set_subscriptions(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_set_subscriptions_response::Result::Acknowledgement(_)) => {
                json_response(StatusCode::OK, &serde_json::json!({"ok": true}))
            }
            Some(pb::realtime_set_subscriptions_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "subscription_rejected",
                "canonical subscriber selection denied",
            ),
        },
        Err(error) => grpc_error(&error),
    }
}

fn valid_subscription_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

async fn report_adaptive_media(
    state: &AppState,
    token: &str,
    input: AdaptiveMediaRequest,
) -> HttpResponse {
    let thermal_state = match input.thermal_state.as_str() {
        "nominal" => pb::MediaThermalState::Nominal,
        "elevated" => pb::MediaThermalState::Elevated,
        "serious" => pb::MediaThermalState::Serious,
        "critical" => pb::MediaThermalState::Critical,
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_thermal_state",
                "thermal_state must be nominal, elevated, serious, or critical",
            );
        }
    };
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeReportAdaptiveMediaRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        telemetry: Some(pb::AdaptiveMediaTelemetry {
            estimated_bandwidth_bps: input.estimated_bandwidth_bps,
            packet_loss_basis_points: input.packet_loss_basis_points,
            jitter_ms: input.jitter_ms,
            rtt_ms: input.rtt_ms,
            cpu_utilization_percent: input.cpu_utilization_percent,
            gpu_utilization_percent: input.gpu_utilization_percent,
            battery_percent: input.battery_percent,
            external_power: input.external_power,
            thermal_state: thermal_state as i32,
        }),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.report_adaptive_media(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_report_adaptive_media_response::Result::Decision(value)) => {
                json_response(
                    StatusCode::OK,
                    &AdaptiveMediaResponse {
                        ok: true,
                        stage: adaptive_stage_name(value.stage).to_owned(),
                        changed: value.changed,
                        requires_media_renegotiation: value.requires_media_renegotiation,
                        video: value.video.map(|video| AdaptiveVideoResponse {
                            codec_capability_id: video.codec_capability_id,
                            width: video.width,
                            height: video.height,
                            frame_rate: video.frame_rate,
                            target_bitrate_bps: video.target_bitrate_bps,
                        }),
                        opus_target_bitrate_bps: value.opus_target_bitrate_bps,
                        deferred_fallbacks: value
                            .deferred_fallbacks
                            .into_iter()
                            .map(deferred_fallback_name)
                            .map(str::to_owned)
                            .collect(),
                        pressures: value
                            .pressures
                            .into_iter()
                            .map(adaptive_pressure_name)
                            .map(str::to_owned)
                            .collect(),
                    },
                )
            }
            Some(pb::realtime_report_adaptive_media_response::Result::Error(_)) | None => {
                api_error(
                    StatusCode::CONFLICT,
                    "adaptive_media_rejected",
                    "adaptive media telemetry rejected",
                )
            }
        },
        Err(status) => grpc_error(&status),
    }
}

fn adaptive_stage_name(value: i32) -> &'static str {
    match pb::AdaptiveMediaStage::try_from(value) {
        Ok(pb::AdaptiveMediaStage::Video1080p) => "video_1080p",
        Ok(pb::AdaptiveMediaStage::Video720p) => "video_720p",
        Ok(pb::AdaptiveMediaStage::Video480p) => "video_480p",
        Ok(pb::AdaptiveMediaStage::VideoLowFps) => "video_low_fps",
        Ok(pb::AdaptiveMediaStage::Audio) => "audio",
        Ok(pb::AdaptiveMediaStage::AudioLowBitrate) => "audio_low_bitrate",
        Ok(pb::AdaptiveMediaStage::EventualFallbackRequired) => "eventual_fallback_required",
        Ok(pb::AdaptiveMediaStage::Unspecified) | Err(_) => "unspecified",
    }
}

fn deferred_fallback_name(value: i32) -> &'static str {
    match pb::DeferredMediaFallback::try_from(value) {
        Ok(pb::DeferredMediaFallback::VoiceMessage) => "voice_message",
        Ok(pb::DeferredMediaFallback::Text) => "text",
        Ok(pb::DeferredMediaFallback::StoreAndForward) => "store_and_forward",
        Ok(pb::DeferredMediaFallback::Unspecified) | Err(_) => "unspecified",
    }
}

fn adaptive_pressure_name(value: i32) -> &'static str {
    match pb::AdaptiveMediaPressure::try_from(value) {
        Ok(pb::AdaptiveMediaPressure::Bandwidth) => "bandwidth",
        Ok(pb::AdaptiveMediaPressure::PacketLoss) => "packet_loss",
        Ok(pb::AdaptiveMediaPressure::Jitter) => "jitter",
        Ok(pb::AdaptiveMediaPressure::Rtt) => "rtt",
        Ok(pb::AdaptiveMediaPressure::Cpu) => "cpu",
        Ok(pb::AdaptiveMediaPressure::Gpu) => "gpu",
        Ok(pb::AdaptiveMediaPressure::Battery) => "battery",
        Ok(pb::AdaptiveMediaPressure::Thermal) => "thermal",
        Ok(pb::AdaptiveMediaPressure::Unspecified) | Err(_) => "unspecified",
    }
}

async fn handle_active_speaker_route(
    state: &AppState,
    token: &str,
    path: &str,
    body: &[u8],
) -> HttpResponse {
    match path {
        "/v1/realtime/audio-level" => match decode_json::<AudioLevelRequest>(body) {
            Ok(input) => report_audio_level(state, token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/active-speaker" => match decode_json::<SessionRequest>(body) {
            Ok(input) => get_active_speaker(state, token, input).await,
            Err(error) => error.into_response(),
        },
        _ => api_error(
            StatusCode::NOT_FOUND,
            "route_not_found",
            "realtime route not found",
        ),
    }
}

async fn report_audio_level(
    state: &AppState,
    token: &str,
    input: AudioLevelRequest,
) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeReportAudioLevelRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        level: input.level,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.report_audio_level(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_report_audio_level_response::Result::Acknowledgement(_)) => api_ok(
                "audio_level_reported",
                "audio level reported",
                None,
                None,
                None,
            ),
            Some(pb::realtime_report_audio_level_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "audio_level_rejected",
                "audio level report rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn get_active_speaker(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeGetActiveSpeakerRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.get_active_speaker(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_get_active_speaker_response::Result::ActiveSpeaker(value)) => {
                let participant_id_b64 = value
                    .participant
                    .and_then(|participant| participant.principal_id)
                    .map(|id| STANDARD.encode(id.value));
                json_response(
                    StatusCode::OK,
                    &ActiveSpeakerResponse {
                        ok: true,
                        participant_id_b64,
                    },
                )
            }
            Some(pb::realtime_get_active_speaker_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "active_speaker_rejected",
                "active speaker projection rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn publish_media(state: &AppState, token: &str, input: PublishRequest) -> HttpResponse {
    let Ok(bytes) = STANDARD.decode(input.envelope_base64.as_bytes()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_media",
            "invalid base64 media envelope",
        );
    };
    let Ok(envelope) = pb::SfuForwardEnvelope::decode(bytes.as_slice()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_media",
            "invalid protobuf media envelope",
        );
    };

    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimePublishMediaRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        envelope: Some(envelope),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.publish_media(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_publish_media_response::Result::Receipt(receipt)) => api_ok(
                "published",
                "encrypted media accepted for SFU routing",
                None,
                None,
                Some(receipt.accepted_recipient_count),
            ),
            Some(pb::realtime_publish_media_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "publish_rejected",
                "encrypted media publish rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn subscribe_media(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeSubscribeMediaRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    let response = match client.subscribe_media(request).await {
        Ok(response) => response,
        Err(status) => return grpc_error(&status),
    };
    let mut stream = response.into_inner();
    let (sender, receiver) = mpsc::channel::<Bytes>(32);
    tokio::spawn(async move {
        loop {
            match stream.message().await {
                Ok(Some(message)) => {
                    let payload = STANDARD.encode(message.encode_to_vec());
                    let event = Bytes::from(format!("event: media\ndata: {payload}\n\n"));
                    if sender.send(event).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = sender
                        .send(Bytes::from_static(
                            b"event: error\ndata: realtime stream closed\n\n",
                        ))
                        .await;
                    break;
                }
            }
        }
    });

    let frames = ReceiverStream::new(receiver)
        .map(|bytes| Ok::<Frame<Bytes>, Infallible>(Frame::data(bytes)));
    let body = StreamBody::new(frames).boxed_unsync();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/event-stream")
        .header(CACHE_CONTROL, "no-cache, no-store")
        .body(body)
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

async fn start_webrtc(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeStartWebRtcRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.start_web_rtc(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_start_web_rtc_response::Result::Offer(offer)) => {
                let Some(description) = offer.description else {
                    return api_error(
                        StatusCode::BAD_GATEWAY,
                        "invalid_webrtc_offer",
                        "realtime upstream returned an invalid WebRTC offer",
                    );
                };
                let sdp_type = match pb::WebRtcSdpType::try_from(description.sdp_type) {
                    Ok(pb::WebRtcSdpType::Offer) => "offer",
                    _ => {
                        return api_error(
                            StatusCode::BAD_GATEWAY,
                            "invalid_webrtc_offer",
                            "realtime upstream returned an invalid WebRTC offer",
                        );
                    }
                };
                json_response(
                    StatusCode::OK,
                    &WebRtcOfferResponse {
                        ok: true,
                        code: "webrtc_offer",
                        message: "WebRTC offer ready",
                        sdp_type,
                        sdp: description.sdp,
                        ice_servers: offer
                            .ice_servers
                            .into_iter()
                            .map(|server| WebRtcIceServerResponse {
                                urls: server.urls,
                                username: server.username,
                                credential: server.credential,
                            })
                            .collect(),
                    },
                )
            }
            Some(pb::realtime_start_web_rtc_response::Result::Error(error)) => webrtc_error(
                &error,
                "webrtc_start_rejected",
                "WebRTC session start rejected",
            ),
            None => api_error(
                StatusCode::BAD_GATEWAY,
                "invalid_webrtc_response",
                "realtime upstream returned an invalid WebRTC response",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn set_webrtc_remote_description(
    state: &AppState,
    token: &str,
    input: WebRtcRemoteDescriptionRequest,
) -> HttpResponse {
    if !valid_sdp(&input.sdp) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_sdp",
            "WebRTC SDP exceeds bounds or has invalid content",
        );
    }
    let sdp_type = match input.sdp_type.as_str() {
        "offer" => pb::WebRtcSdpType::Offer as i32,
        "answer" => pb::WebRtcSdpType::Answer as i32,
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_sdp_type",
                "WebRTC SDP type must be offer or answer",
            );
        }
    };
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeSetWebRtcRemoteDescriptionRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        description: Some(pb::WebRtcDescription {
            sdp_type,
            sdp: input.sdp,
        }),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    match client.set_web_rtc_remote_description(request).await {
        Ok(response) => match response.into_inner().result {
            Some(
                pb::realtime_set_web_rtc_remote_description_response::Result::Acknowledgement(_),
            ) => api_ok(
                "webrtc_remote_set",
                "WebRTC remote description accepted",
                None,
                None,
                None,
            ),
            Some(pb::realtime_set_web_rtc_remote_description_response::Result::Error(error)) => {
                webrtc_error(
                    &error,
                    "webrtc_remote_rejected",
                    "WebRTC remote description rejected",
                )
            }
            None => api_error(
                StatusCode::BAD_GATEWAY,
                "invalid_webrtc_response",
                "realtime upstream returned an invalid WebRTC response",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn add_webrtc_ice_candidate(
    state: &AppState,
    token: &str,
    input: WebRtcIceCandidateRequest,
) -> HttpResponse {
    if !valid_ice_candidate(&input.candidate, input.sdp_mid.as_deref()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_ice_candidate",
            "WebRTC ICE candidate exceeds bounds or has invalid content",
        );
    }
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeAddWebRtcIceCandidateRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call)),
        session_id: Some(pb_id(&input.session.session)),
        candidate: input.candidate,
        sdp_mid: input.sdp_mid,
        sdp_mline_index: input.sdp_mline_index,
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    match client.add_web_rtc_ice_candidate(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_add_web_rtc_ice_candidate_response::Result::Acknowledgement(_)) => {
                api_ok(
                    "webrtc_ice_added",
                    "WebRTC ICE candidate accepted",
                    None,
                    None,
                    None,
                )
            }
            Some(pb::realtime_add_web_rtc_ice_candidate_response::Result::Error(error)) => {
                webrtc_error(
                    &error,
                    "webrtc_ice_rejected",
                    "WebRTC ICE candidate rejected",
                )
            }
            None => api_error(
                StatusCode::BAD_GATEWAY,
                "invalid_webrtc_response",
                "realtime upstream returned an invalid WebRTC response",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn restart_webrtc(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeRestartWebRtcRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }

    match client.restart_web_rtc(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_restart_web_rtc_response::Result::Offer(offer)) => {
                webrtc_offer_response("webrtc_restarted", "WebRTC ICE restart offer ready", offer)
            }
            Some(pb::realtime_restart_web_rtc_response::Result::Error(error)) => webrtc_error(
                &error,
                "webrtc_restart_rejected",
                "WebRTC ICE restart rejected",
            ),
            None => api_error(
                StatusCode::BAD_GATEWAY,
                "webrtc_restart_rejected",
                "WebRTC ICE restart rejected",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn close_webrtc(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeCloseWebRtcRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call)),
        session_id: Some(pb_id(&input.session)),
    });
    if let Err(error) = attach_bearer(&mut request, token) {
        return error.into_response();
    }
    match client.close_web_rtc(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_close_web_rtc_response::Result::Acknowledgement(_)) => {
                api_ok("webrtc_closed", "WebRTC session closed", None, None, None)
            }
            Some(pb::realtime_close_web_rtc_response::Result::Error(error)) => webrtc_error(
                &error,
                "webrtc_close_rejected",
                "WebRTC session close rejected",
            ),
            None => api_error(
                StatusCode::BAD_GATEWAY,
                "invalid_webrtc_response",
                "realtime upstream returned an invalid WebRTC response",
            ),
        },
        Err(status) => grpc_error(&status),
    }
}

async fn bounded_body(body: Incoming) -> Result<Bytes, GatewayFailure> {
    let collected = body.collect().await.map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "could not read request body",
        )
    })?;
    let bytes = collected.to_bytes();
    if bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(GatewayFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "realtime request body exceeds the bounded limit",
        ));
    }
    Ok(bytes)
}

fn valid_sdp(sdp: &str) -> bool {
    !sdp.is_empty() && sdp.len() <= MAX_SIGNALING_SDP_BYTES && !sdp.bytes().any(|byte| byte == 0)
}

fn valid_ice_candidate(candidate: &str, mid: Option<&str>) -> bool {
    !candidate.is_empty()
        && candidate.len() <= MAX_SIGNALING_ICE_CANDIDATE_BYTES
        && !candidate
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        && mid.is_none_or(|value| {
            value.len() <= MAX_SIGNALING_ICE_MID_BYTES
                && !value
                    .bytes()
                    .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        })
}

fn decode_json<T>(body: &[u8]) -> Result<T, GatewayFailure>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(body).map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "invalid realtime request JSON",
        )
    })
}

fn bearer_from_headers(headers: &hyper::HeaderMap) -> Result<String, GatewayFailure> {
    let value = headers.get(AUTHORIZATION).ok_or_else(|| {
        GatewayFailure::new(
            StatusCode::UNAUTHORIZED,
            "missing_token",
            "missing realtime bearer token",
        )
    })?;
    let value = value.to_str().map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        )
    })?;
    let token = value.strip_prefix("Bearer ").ok_or_else(|| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        )
    })?;
    if token.is_empty() || token.len() > MAX_BEARER_BYTES || token.chars().any(char::is_whitespace)
    {
        return Err(GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        ));
    }
    Ok(token.to_owned())
}

fn client(state: &AppState) -> pb::realtime_service_client::RealtimeServiceClient<Channel> {
    pb::realtime_service_client::RealtimeServiceClient::new(state.upstream.clone())
}

fn attach_bearer<T>(request: &mut GrpcRequest<T>, token: &str) -> Result<(), GatewayFailure> {
    let bearer = format!("Bearer {token}");
    let value = MetadataValue::try_from(bearer.as_str()).map_err(|_| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        )
    })?;
    request.metadata_mut().insert("authorization", value);
    Ok(())
}

fn pb_scope(input: &SessionRequest) -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb_id(&input.tenant)),
        namespace_id: input.namespace.as_deref().map(pb_id),
    }
}

fn pb_id(value: &str) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    }
}

fn webrtc_offer_response(
    code: &'static str,
    message: &'static str,
    offer: pb::RealtimeWebRtcOffer,
) -> HttpResponse {
    let Some(description) = offer.description else {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "invalid_webrtc_offer",
            "realtime upstream returned an invalid WebRTC offer",
        );
    };
    let sdp_type = match pb::WebRtcSdpType::try_from(description.sdp_type) {
        Ok(pb::WebRtcSdpType::Offer) => "offer",
        _ => {
            return api_error(
                StatusCode::BAD_GATEWAY,
                "invalid_webrtc_offer",
                "realtime upstream returned an invalid WebRTC offer",
            );
        }
    };
    json_response(
        StatusCode::OK,
        &WebRtcOfferResponse {
            ok: true,
            code,
            message,
            sdp_type,
            sdp: description.sdp,
            ice_servers: offer
                .ice_servers
                .into_iter()
                .map(|server| WebRtcIceServerResponse {
                    urls: server.urls,
                    username: server.username,
                    credential: server.credential,
                })
                .collect(),
        },
    )
}

fn canonical_error_response(
    error: &pb::ErrorEnvelope,
    code: &'static str,
    message: &'static str,
) -> HttpResponse {
    let status = match pb::ErrorCode::try_from(error.code) {
        Ok(pb::ErrorCode::InvalidArgument | pb::ErrorCode::MalformedFrame) => {
            StatusCode::BAD_REQUEST
        }
        Ok(pb::ErrorCode::Unauthenticated) => StatusCode::UNAUTHORIZED,
        Ok(pb::ErrorCode::PermissionDenied | pb::ErrorCode::PolicyDenied) => StatusCode::FORBIDDEN,
        Ok(pb::ErrorCode::RateLimited | pb::ErrorCode::ResourceExhausted) => {
            StatusCode::TOO_MANY_REQUESTS
        }
        Ok(pb::ErrorCode::DeadlineExceeded | pb::ErrorCode::Cancelled) => {
            StatusCode::REQUEST_TIMEOUT
        }
        Ok(pb::ErrorCode::TemporarilyUnavailable) => StatusCode::SERVICE_UNAVAILABLE,
        Ok(pb::ErrorCode::Conflict) => StatusCode::CONFLICT,
        Ok(pb::ErrorCode::NotFound) => StatusCode::NOT_FOUND,
        Ok(
            pb::ErrorCode::UnsupportedProtocolVersion
            | pb::ErrorCode::DowngradeRejected
            | pb::ErrorCode::UnsupportedCriticalExtension
            | pb::ErrorCode::CapabilityMismatch,
        ) => StatusCode::BAD_REQUEST,
        Ok(
            pb::ErrorCode::IntegrityFailure | pb::ErrorCode::Internal | pb::ErrorCode::Unspecified,
        )
        | Err(_) => StatusCode::BAD_GATEWAY,
    };
    api_error(status, code, message)
}

fn webrtc_error(
    error: &pb::ErrorEnvelope,
    code: &'static str,
    message: &'static str,
) -> HttpResponse {
    canonical_error_response(error, code, message)
}

fn grpc_error(status: &tonic::Status) -> HttpResponse {
    let http = match status.code() {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    };
    api_error(
        http,
        "upstream_rejected",
        "realtime upstream rejected the request",
    )
}

fn api_ok(
    code: &'static str,
    message: impl Into<String>,
    expires_at_unix_ms: Option<i64>,
    heartbeat_interval_ms: Option<u64>,
    accepted_recipient_count: Option<u32>,
) -> HttpResponse {
    api_ok_with_realtime_state(
        code,
        message,
        expires_at_unix_ms,
        heartbeat_interval_ms,
        accepted_recipient_count,
        None,
        None,
    )
}

fn api_ok_with_realtime_state(
    code: &'static str,
    message: impl Into<String>,
    expires_at_unix_ms: Option<i64>,
    heartbeat_interval_ms: Option<u64>,
    accepted_recipient_count: Option<u32>,
    admission_state: Option<&'static str>,
    media_policy: Option<BrowserMediaPolicyResponse>,
) -> HttpResponse {
    json_response(
        StatusCode::OK,
        &ApiResponse {
            ok: true,
            code,
            message: message.into(),
            expires_at_unix_ms,
            heartbeat_interval_ms,
            accepted_recipient_count,
            admission_state,
            media_policy,
        },
    )
}

fn admission_state_name(value: i32) -> Option<&'static str> {
    match pb::RealtimeAdmissionState::try_from(value).ok()? {
        pb::RealtimeAdmissionState::WaitingRoom => Some("waiting_room"),
        pb::RealtimeAdmissionState::Admitted => Some("admitted"),
        pb::RealtimeAdmissionState::Closed => Some("closed"),
        pb::RealtimeAdmissionState::Unspecified => None,
    }
}

fn empty_upstream() -> HttpResponse {
    api_error(
        StatusCode::BAD_GATEWAY,
        "invalid_upstream_response",
        "realtime upstream returned an incomplete response",
    )
}

fn api_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> HttpResponse {
    json_response(
        status,
        &ApiResponse {
            ok: false,
            code,
            message: message.into(),
            expires_at_unix_ms: None,
            heartbeat_interval_ms: None,
            accepted_recipient_count: None,
            admission_state: None,
            media_policy: None,
        },
    )
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> HttpResponse {
    let bytes = serde_json::to_vec(payload).unwrap_or_else(|_| {
        b"{\"ok\":false,\"code\":\"internal\",\"message\":\"response encoding failed\",\"expires_at_unix_ms\":null,\"heartbeat_interval_ms\":null,\"accepted_recipient_count\":null}".to_vec()
    });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::from(bytes)))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn reference_media_asset(path: &str) -> Option<(&'static str, &'static str)> {
    REFERENCE_MEDIA_ASSETS
        .iter()
        .find(|(route, _, _)| *route == path)
        .map(|(_, file, mime)| (*file, *mime))
}

fn serve_reference_media_asset(path: &str) -> HttpResponse {
    let Some((file, mime)) = reference_media_asset(path) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    // A deployment must provide the exact WASM and SDK bundles built for its
    // source revision. Never generate an adapter dynamically or load a remote
    // untrusted CDN script. Missing assets fail closed, not to plaintext media.
    let directory = std::env::var_os("UCR_REALTIME_WEB_ASSET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/static")));
    match std::fs::read(directory.join(file)) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= 16 * 1024 * 1024 => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, mime)
            .header(CACHE_CONTROL, "no-store")
            .header("X-Content-Type-Options", "nosniff")
            .body(full_body(Bytes::from(bytes)))
            .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
        _ => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "endpoint_media_asset_missing",
            "Authorized endpoint E2EE package not installed on the gateway",
        ),
    }
}

fn html_response(status: StatusCode, html: &'static str) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::from_static(html.as_bytes())))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn text_response(status: StatusCode, text: &'static str) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::from_static(text.as_bytes())))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn full_body(bytes: Bytes) -> HttpBody {
    Full::new(bytes).boxed_unsync()
}

fn empty_response(status: StatusCode) -> HttpResponse {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::new()))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_webrtc_signaling_rejects_malformed_or_oversized_inputs() {
        assert!(valid_sdp("v=0\r\n"));
        assert!(!valid_sdp(""));
        assert!(!valid_sdp(&"a".repeat(MAX_SIGNALING_SDP_BYTES + 1)));
        assert!(!valid_sdp("v=0\0"));
        assert!(valid_ice_candidate(
            "candidate:1 1 udp 1 127.0.0.1 1234 typ host",
            Some("0")
        ));
        assert!(!valid_ice_candidate("", None));
        assert!(!valid_ice_candidate(
            &"x".repeat(MAX_SIGNALING_ICE_CANDIDATE_BYTES + 1),
            None
        ));
        assert!(!valid_ice_candidate("candidate:1\nspoof", None));
        assert!(!valid_ice_candidate("candidate:1", Some("x\rspoof")));
        assert!(!valid_ice_candidate(
            "candidate:1",
            Some(&"x".repeat(MAX_SIGNALING_ICE_MID_BYTES + 1))
        ));
    }

    #[test]
    fn browser_privacy_modes_restrict_network_and_preserve_fragment_grant() {
        assert!(CLIENT_HTML.contains("id=\"privacy-mode\""));
        assert!(CLIENT_HTML.contains("iceTransportPolicy:mode===\"private\"?\"relay\":\"all\""));
        assert!(CLIENT_HTML.contains("Higher privacy requires configured TURN relay"));
        assert!(CLIENT_HTML.contains("ui.privacyMode.disabled=true"));
        assert!(CLIENT_HTML.contains("ui.privacyMode.disabled=false"));
        assert!(CLIENT_HTML.contains("token=params.get(\"ucr_join\")"));
        assert!(CLIENT_HTML.contains("window.history.replaceState("));
        assert!(CLIENT_HTML.contains("location.pathname+location.search"));
        assert!(CLIENT_HTML.contains("claims=readGrant(token);if(Date.now()>=claims.expires)"));

        assert!(CLIENT_HTML.contains("Independent privacy relay is not configured"));
        assert!(CLIENT_HTML.contains("adapter===e2eeManagedAdapter"));
        assert!(CLIENT_HTML.contains("delete window.ucrE2eeEndpoint"));
        assert!(CLIENT_HTML.contains("e2eeManagedAdapter=installed"));
        assert!(CLIENT_HTML.contains("pc.setConfiguration(rtcNetworkConfiguration("));
        assert!(CLIENT_HTML.contains("Endpoint E2EE adapter failed; encrypted transport closed"));
        assert!(CLIENT_HTML.contains("if(e2eeChannel===channel){closeE2eeTransport()"));
    }

    #[test]
    fn browser_e2ee_activation_rejects_stale_channels() {
        assert!(CLIENT_HTML.contains("e2eeActivationGeneration"));
        assert!(
            CLIENT_HTML.contains("Encrypted media session changed during adapter installation")
        );
        assert!(CLIENT_HTML.contains("Encrypted media session changed during startup"));
        assert!(CLIENT_HTML.contains("if(e2eeChannel!==channel)return;"));
    }

    #[test]
    fn browser_client_exposes_live_webrtc_media_and_reconnect_flow() {
        for required in [
            "navigator.mediaDevices.getUserMedia",
            "new RTCPeerConnection",
            "/v1/realtime/raised-hand",
            "id=\"hand-toggle\"",
            "toggleRaisedHand",
            "/v1/realtime/reactions/publish",
            "/v1/realtime/reactions/list",
            "id=\"reaction-send\"",
            "publishReaction",
            "pollReactions",
            "/v1/realtime/adaptive-media",
            "/v1/realtime/audio-level",
            "/v1/realtime/active-speaker",
            "startActiveSpeakerMonitoring",
            "createAnalyser",
            "id=\"active-speaker\"",
            "/v1/realtime/chat/send",
            "/v1/realtime/chat/list",
            "id=\"chat-input\"",
            "sendChat",
            "pollChat",
            "pendingChatPayload",
            "new Uint8Array(16)",
            "window.crypto.getRandomValues(bytes)",
            "/v1/realtime/webrtc/start",
            "/v1/realtime/webrtc/remote-description",
            "/v1/realtime/webrtc/ice",
            "/v1/realtime/webrtc/close",
            "scheduleWebRtcRetry",
            "remoteDescriptionAccepted",
            "pendingCandidates",
            "id=\"microphone\"",
            "id=\"camera\"",
            "id=\"mic-toggle\"",
            "id=\"camera-toggle\"",
            "devicechange",
            "handleMediaDeviceChange",
            "readyState===\"ended\"",
            "applyMediaPolicy",
            "policyAllows(\"audio\")",
            "policyAllows(\"camera\")",
            "policyAllows(\"screen\")",
            "Viewing mode does not request camera or microphone access.",
            "Conference access ended by host or server policy.",
        ] {
            assert!(
                CLIENT_HTML.contains(required),
                "missing browser WebRTC proof: {required}"
            );
        }
        assert!(!CLIENT_HTML.contains("UCR_WEBRTC_TURN_SECRET"));
        assert!(!CLIENT_HTML.contains("randomUUID"));
    }

    #[test]
    fn webrtc_domain_errors_preserve_http_semantics() {
        let cases = [
            (pb::ErrorCode::Unauthenticated, StatusCode::UNAUTHORIZED),
            (pb::ErrorCode::PermissionDenied, StatusCode::FORBIDDEN),
            (pb::ErrorCode::RateLimited, StatusCode::TOO_MANY_REQUESTS),
            (
                pb::ErrorCode::TemporarilyUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (pb::ErrorCode::NotFound, StatusCode::NOT_FOUND),
            (pb::ErrorCode::Conflict, StatusCode::CONFLICT),
        ];
        for (code, expected) in cases {
            let response = webrtc_error(
                &pb::ErrorEnvelope {
                    code: code as i32,
                    retryable: false,
                    retry_after_ms: None,
                    diagnostic_domain: "ucr.grpc.binding".to_owned(),
                    extensions: Vec::new(),
                },
                "webrtc_rejected",
                "WebRTC request rejected",
            );
            assert_eq!(response.status(), expected);
        }
    }

    #[test]
    fn webrtc_offer_response_is_no_store() {
        let response = json_response(
            StatusCode::OK,
            &WebRtcOfferResponse {
                ok: true,
                code: "webrtc_offer",
                message: "WebRTC offer ready",
                sdp_type: "offer",
                sdp: "v=0\r\n".to_owned(),
                ice_servers: vec![WebRtcIceServerResponse {
                    urls: vec!["turns:turn.example.test:5349?transport=tcp".to_owned()],
                    username: Some("ephemeral".to_owned()),
                    credential: Some("secret".to_owned()),
                }],
            },
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&hyper::header::HeaderValue::from_static("no-store"))
        );
    }

    #[test]
    fn browser_media_assets_use_only_fixed_local_paths_and_correct_mime() {
        assert_eq!(
            reference_media_asset("/endpoint-wasm/ucr_endpoint_wasm_bg.wasm"),
            Some(("endpoint-wasm/ucr_endpoint_wasm_bg.wasm", "application/wasm")),
        );
        assert_eq!(
            reference_media_asset("/endpoint-media/reference_browser_media_installer.js"),
            Some((
                "endpoint-media/reference_browser_media_installer.js",
                "text/javascript; charset=utf-8",
            )),
        );
        assert!(reference_media_asset("/endpoint-wasm/../private.key").is_none());
        assert!(reference_media_asset("/endpoint-media/signing-seed").is_none());
        assert!(reference_media_asset("/client.html").is_none());
    }

    #[test]
    fn browser_gateway_refuses_non_loopback_bind() {
        let local: SocketAddr = "127.0.0.1:8080".parse().expect("loopback");
        let remote: SocketAddr = "0.0.0.0:8080".parse().expect("remote");
        assert!(validate_loopback_bind(local).is_ok());
        assert!(validate_loopback_bind(remote).is_err());
    }

    #[test]
    fn allowed_origins_are_exact_and_wildcards_fail_closed() {
        let origins = parse_allowed_origins(
            "https://app.example.test, http://localhost:5173,https://app.example.test",
        )
        .expect("valid origins");
        assert_eq!(
            origins,
            vec![
                "https://app.example.test".to_owned(),
                "http://localhost:5173".to_owned()
            ]
        );
        assert!(parse_allowed_origins("*").is_err());
        assert!(parse_allowed_origins("http://example.test").is_err());
    }

    #[test]
    fn retryable_unavailable_join_maps_to_waiting_room() {
        let response = join_error(&pb::ErrorEnvelope {
            code: pb::ErrorCode::PolicyDenied as i32,
            retryable: true,
            retry_after_ms: Some(2_000),
            diagnostic_domain: "ucr.grpc.binding".to_owned(),
            extensions: Vec::new(),
        });
        assert_eq!(response.status(), StatusCode::TOO_EARLY);
    }

    #[test]
    fn browser_origin_must_match_allowlist_exactly() {
        let allowed = vec!["https://app.example.test".to_owned()];
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            ORIGIN,
            hyper::header::HeaderValue::from_static("https://app.example.test"),
        );
        assert_eq!(
            request_origin(&headers, &allowed).expect("allowed"),
            Some("https://app.example.test".to_owned())
        );
        headers.insert(
            ORIGIN,
            hyper::header::HeaderValue::from_static("https://evil.example.test"),
        );
        assert!(request_origin(&headers, &allowed).is_err());

        let mut same_origin = hyper::HeaderMap::new();
        same_origin.insert(
            ORIGIN,
            hyper::header::HeaderValue::from_static("http://127.0.0.1:8080"),
        );
        same_origin.insert(
            HOST,
            hyper::header::HeaderValue::from_static("127.0.0.1:8080"),
        );
        assert_eq!(
            request_origin(&same_origin, &[]).expect("same origin"),
            Some("http://127.0.0.1:8080".to_owned())
        );
        assert!(
            request_origin(&hyper::HeaderMap::new(), &allowed)
                .expect("non-browser request")
                .is_none()
        );
    }
}

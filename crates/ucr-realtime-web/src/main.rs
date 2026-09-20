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
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
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
const CLIENT_HTML: &str = include_str!("../static/client.html");

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
struct ApiResponse {
    ok: bool,
    code: &'static str,
    message: String,
    expires_at_unix_ms: Option<i64>,
    heartbeat_interval_ms: Option<u64>,
    accepted_recipient_count: Option<u32>,
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
            if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
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

    let response = match path.as_str() {
        "/v1/realtime/join" => match decode_json::<SessionRequest>(&body) {
            Ok(input) => join(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/heartbeat" => match decode_json::<HeartbeatRequest>(&body) {
            Ok(input) => heartbeat(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/leave" => match decode_json::<SessionRequest>(&body) {
            Ok(input) => leave(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/media/publish" => match decode_json::<PublishRequest>(&body) {
            Ok(input) => publish_media(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/media/stream" => match decode_json::<SessionRequest>(&body) {
            Ok(input) => subscribe_media(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/start" => match decode_json::<SessionRequest>(&body) {
            Ok(input) => start_webrtc(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/remote-description" => {
            match decode_json::<WebRtcRemoteDescriptionRequest>(&body) {
                Ok(input) => set_webrtc_remote_description(&state, &token, input).await,
                Err(error) => error.into_response(),
            }
        }
        "/v1/realtime/webrtc/ice" => match decode_json::<WebRtcIceCandidateRequest>(&body) {
            Ok(input) => add_webrtc_ice_candidate(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        "/v1/realtime/webrtc/close" => match decode_json::<SessionRequest>(&body) {
            Ok(input) => close_webrtc(&state, &token, input).await,
            Err(error) => error.into_response(),
        },
        _ => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "realtime route not found",
        ),
    };

    Ok(with_cors(response, origin.as_deref()))
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
            Some(pb::realtime_join_response::Result::Session(session)) => api_ok(
                "joined",
                "realtime session joined",
                Some(session.expires_at_unix_ms),
                Some(session.heartbeat_interval_ms),
                None,
            ),
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
        Ok(response) => match response.into_inner().result {
            Some(pb::realtime_heartbeat_response::Result::Acknowledgement(_)) => {
                api_ok("alive", "realtime heartbeat accepted", None, None, None)
            }
            Some(pb::realtime_heartbeat_response::Result::Error(_)) | None => api_error(
                StatusCode::CONFLICT,
                "heartbeat_rejected",
                "realtime heartbeat rejected",
            ),
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

fn webrtc_error(
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
    json_response(
        StatusCode::OK,
        &ApiResponse {
            ok: true,
            code,
            message: message.into(),
            expires_at_unix_ms,
            heartbeat_interval_ms,
            accepted_recipient_count,
        },
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
    fn browser_client_exposes_live_webrtc_media_and_reconnect_flow() {
        for required in [
            "navigator.mediaDevices.getUserMedia",
            "new RTCPeerConnection",
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
        ] {
            assert!(
                CLIENT_HTML.contains(required),
                "missing browser WebRTC proof: {required}"
            );
        }
        assert!(!CLIENT_HTML.contains("UCR_WEBRTC_TURN_SECRET"));
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

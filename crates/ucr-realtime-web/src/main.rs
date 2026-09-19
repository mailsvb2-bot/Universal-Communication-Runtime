#![forbid(unsafe_code)]

use std::{convert::Infallible, net::SocketAddr};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, metadata::MetadataValue, transport::Channel};
use ucr_api_grpc::pb;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:50051";

#[derive(Clone, Debug)]
struct AppState {
    upstream: Channel,
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    tenant_id: String,
    namespace_id: Option<String>,
    call_id: String,
    session_id: String,
    token: String,
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
    if !bind.ip().is_loopback() {
        return Err(
            "browser gateway requires a loopback bind; publish it only through a trusted HTTPS reverse proxy"
                .to_owned(),
        );
    }

    let upstream =
        std::env::var("UCR_REALTIME_GRPC_UPSTREAM").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    let channel = Channel::from_shared(upstream)
        .map_err(|error| format!("invalid realtime upstream URI: {error}"))?
        .connect()
        .await
        .map_err(|error| format!("connect realtime upstream: {error}"))?;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/realtime/join", post(join))
        .route("/v1/realtime/heartbeat", post(heartbeat))
        .route("/v1/realtime/leave", post(leave))
        .route("/v1/realtime/media/publish", post(publish_media))
        .route("/v1/realtime/media/stream", post(subscribe_media))
        .with_state(AppState { upstream: channel });

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind browser gateway: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve browser gateway: {error}"))?;
    println!("UCR_REALTIME_WEB_READY endpoint=http://{address} tls_edge=required");

    axum::serve(listener, app)
        .await
        .map_err(|error| format!("serve browser gateway: {error}"))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn join(State(state): State<AppState>, Json(input): Json<SessionRequest>) -> Response {
    let mut client = client(&state);
    let mut request = Request::new(pb::RealtimeJoinRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call_id)),
        session_id: Some(pb_id(&input.session_id)),
    });
    if let Err(response) = attach_bearer(&mut request, &input.token) {
        return response;
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
            Some(pb::realtime_join_response::Result::Error(_)) | None => api_error(
                StatusCode::UNAUTHORIZED,
                "join_rejected",
                "realtime join rejected",
            ),
        },
        Err(status) => grpc_error(status),
    }
}

async fn heartbeat(State(state): State<AppState>, Json(input): Json<HeartbeatRequest>) -> Response {
    let mut client = client(&state);
    let mut request = Request::new(pb::RealtimeHeartbeatRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call_id)),
        session_id: Some(pb_id(&input.session.session_id)),
        expected_session_sequence: input.expected_session_sequence,
    });
    if let Err(response) = attach_bearer(&mut request, &input.session.token) {
        return response;
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
        Err(status) => grpc_error(status),
    }
}

async fn leave(State(state): State<AppState>, Json(input): Json<SessionRequest>) -> Response {
    let mut client = client(&state);
    let mut request = Request::new(pb::RealtimeLeaveRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call_id)),
        session_id: Some(pb_id(&input.session_id)),
    });
    if let Err(response) = attach_bearer(&mut request, &input.token) {
        return response;
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
        Err(status) => grpc_error(status),
    }
}

async fn publish_media(
    State(state): State<AppState>,
    Json(input): Json<PublishRequest>,
) -> Response {
    let bytes = match STANDARD.decode(input.envelope_base64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_media",
                "invalid base64 media envelope",
            );
        }
    };
    let envelope = match pb::SfuForwardEnvelope::decode(bytes.as_slice()) {
        Ok(envelope) => envelope,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_media",
                "invalid protobuf media envelope",
            );
        }
    };

    let mut client = client(&state);
    let mut request = Request::new(pb::RealtimePublishMediaRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call_id)),
        session_id: Some(pb_id(&input.session.session_id)),
        envelope: Some(envelope),
    });
    if let Err(response) = attach_bearer(&mut request, &input.session.token) {
        return response;
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
        Err(status) => grpc_error(status),
    }
}

async fn subscribe_media(
    State(state): State<AppState>,
    Json(input): Json<SessionRequest>,
) -> Response {
    let mut client = client(&state);
    let mut request = Request::new(pb::RealtimeSubscribeMediaRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call_id)),
        session_id: Some(pb_id(&input.session_id)),
    });
    if let Err(response) = attach_bearer(&mut request, &input.token) {
        return response;
    }

    let response = match client.subscribe_media(request).await {
        Ok(response) => response,
        Err(status) => return grpc_error(status),
    };
    let mut stream = response.into_inner();
    let (sender, receiver) = mpsc::channel::<Result<Event, Infallible>>(32);
    tokio::spawn(async move {
        loop {
            match stream.message().await {
                Ok(Some(message)) => {
                    let payload = STANDARD.encode(message.encode_to_vec());
                    if sender
                        .send(Ok(Event::default().event("media").data(payload)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = sender
                        .send(Ok(Event::default()
                            .event("error")
                            .data("realtime stream closed")))
                        .await;
                    break;
                }
            }
        }
    });

    Sse::new(ReceiverStream::new(receiver))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn client(state: &AppState) -> pb::realtime_service_client::RealtimeServiceClient<Channel> {
    pb::realtime_service_client::RealtimeServiceClient::new(state.upstream.clone())
}

fn attach_bearer<T>(request: &mut Request<T>, token: &str) -> Result<(), Response> {
    if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_whitespace) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        ));
    }

    let value = MetadataValue::try_from(format!("Bearer {token}")).map_err(|_| {
        api_error(
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
        tenant_id: Some(pb_id(&input.tenant_id)),
        namespace_id: input.namespace_id.as_deref().map(pb_id),
    }
}

fn pb_id(value: &str) -> pb::OpaqueId {
    pb::OpaqueId {
        value: value.as_bytes().to_vec(),
    }
}

fn grpc_error(status: tonic::Status) -> Response {
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
) -> Response {
    (
        StatusCode::OK,
        Json(ApiResponse {
            ok: true,
            code,
            message: message.into(),
            expires_at_unix_ms,
            heartbeat_interval_ms,
            accepted_recipient_count,
        }),
    )
        .into_response()
}

fn api_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiResponse {
            ok: false,
            code,
            message: message.into(),
            expires_at_unix_ms: None,
            heartbeat_interval_ms: None,
            accepted_recipient_count: None,
        }),
    )
        .into_response()
}

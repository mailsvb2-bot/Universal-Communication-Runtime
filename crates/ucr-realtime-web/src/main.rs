#![forbid(unsafe_code)]

use std::{convert::Infallible, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE},
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

type HttpBody = UnsyncBoxBody<Bytes, Infallible>;
type HttpResponse = Response<HttpBody>;

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
    validate_loopback_bind(bind)?;

    let upstream =
        std::env::var("UCR_REALTIME_GRPC_UPSTREAM").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    let channel = Channel::from_shared(upstream)
        .map_err(|error| format!("invalid realtime upstream URI: {error}"))?
        .connect()
        .await
        .map_err(|error| format!("connect realtime upstream: {error}"))?;
    let state = AppState { upstream: channel };

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

    if method == Method::GET && path == "/healthz" {
        return Ok(text_response(StatusCode::OK, "ok"));
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
        Err(response) => return Ok(response),
    };
    let body = match bounded_body(request.into_body()).await {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };

    let response = match path.as_str() {
        "/v1/realtime/join" => decode_json::<SessionRequest>(&body)
            .map_or_else(|response| response, |input| join(&state, &token, input)),
        "/v1/realtime/heartbeat" => decode_json::<HeartbeatRequest>(&body).map_or_else(
            |response| response,
            |input| heartbeat(&state, &token, input),
        ),
        "/v1/realtime/leave" => decode_json::<SessionRequest>(&body)
            .map_or_else(|response| response, |input| leave(&state, &token, input)),
        "/v1/realtime/media/publish" => decode_json::<PublishRequest>(&body).map_or_else(
            |response| response,
            |input| publish_media(&state, &token, input),
        ),
        "/v1/realtime/media/stream" => match decode_json::<SessionRequest>(&body) {
            Ok(input) => return Ok(subscribe_media(&state, &token, input).await),
            Err(response) => response,
        }
        _ => api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "realtime route not found",
        ),
    };

    Ok(response.await)
}

async fn join(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeJoinRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call_id)),
        session_id: Some(pb_id(&input.session_id)),
    });
    if let Err(response) = attach_bearer(&mut request, token) {
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

async fn heartbeat(state: &AppState, token: &str, input: HeartbeatRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeHeartbeatRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call_id)),
        session_id: Some(pb_id(&input.session.session_id)),
        expected_session_sequence: input.expected_session_sequence,
    });
    if let Err(response) = attach_bearer(&mut request, token) {
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

async fn leave(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeLeaveRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call_id)),
        session_id: Some(pb_id(&input.session_id)),
    });
    if let Err(response) = attach_bearer(&mut request, token) {
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

async fn publish_media(state: &AppState, token: &str, input: PublishRequest) -> HttpResponse {
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

    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimePublishMediaRequest {
        scope: Some(pb_scope(&input.session)),
        call_id: Some(pb_id(&input.session.call_id)),
        session_id: Some(pb_id(&input.session.session_id)),
        envelope: Some(envelope),
    });
    if let Err(response) = attach_bearer(&mut request, token) {
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

async fn subscribe_media(state: &AppState, token: &str, input: SessionRequest) -> HttpResponse {
    let mut client = client(state);
    let mut request = GrpcRequest::new(pb::RealtimeSubscribeMediaRequest {
        scope: Some(pb_scope(&input)),
        call_id: Some(pb_id(&input.call_id)),
        session_id: Some(pb_id(&input.session_id)),
    });
    if let Err(response) = attach_bearer(&mut request, token) {
        return response;
    }

    let response = match client.subscribe_media(request).await {
        Ok(response) => response,
        Err(status) => return grpc_error(status),
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

async fn bounded_body(body: Incoming) -> Result<Bytes, HttpResponse> {
    let collected = body.collect().await.map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "could not read request body",
        )
    })?;
    let bytes = collected.to_bytes();
    if bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "realtime request body exceeds the bounded limit",
        ));
    }
    Ok(bytes)
}

fn decode_json<T>(body: &[u8]) -> Result<T, HttpResponse>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(body).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "invalid realtime request JSON",
        )
    })
}

fn bearer_from_headers(headers: &hyper::HeaderMap) -> Result<String, HttpResponse> {
    let value = headers.get(AUTHORIZATION).ok_or_else(|| {
        api_error(
            StatusCode::UNAUTHORIZED,
            "missing_token",
            "missing realtime bearer token",
        )
    })?;
    let value = value.to_str().map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        )
    })?;
    let token = value.strip_prefix("Bearer ").ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid_token",
            "invalid realtime bearer token",
        )
    })?;
    if token.is_empty() || token.len() > MAX_BEARER_BYTES || token.chars().any(char::is_whitespace)
    {
        return Err(api_error(
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

fn attach_bearer<T>(request: &mut GrpcRequest<T>, token: &str) -> Result<(), HttpResponse> {
    let bearer = format!("Bearer {token}");
    let value = MetadataValue::try_from(bearer.as_str()).map_err(|_| {
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

fn grpc_error(status: tonic::Status) -> HttpResponse {
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
        ApiResponse {
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
        ApiResponse {
            ok: false,
            code,
            message: message.into(),
            expires_at_unix_ms: None,
            heartbeat_interval_ms: None,
            accepted_recipient_count: None,
        },
    )
}

fn json_response(status: StatusCode, payload: ApiResponse) -> HttpResponse {
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| {
        b"{\"ok\":false,\"code\":\"internal\",\"message\":\"response encoding failed\",\"expires_at_unix_ms\":null,\"heartbeat_interval_ms\":null,\"accepted_recipient_count\":null}".to_vec()
    });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::from(bytes)))
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
    fn browser_gateway_refuses_non_loopback_bind() {
        let local: SocketAddr = "127.0.0.1:8080".parse().expect("loopback");
        let remote: SocketAddr = "0.0.0.0:8080".parse().expect("remote");
        assert!(validate_loopback_bind(local).is_ok());
        assert!(validate_loopback_bind(remote).is_err());
    }
}

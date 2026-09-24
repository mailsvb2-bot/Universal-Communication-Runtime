#![forbid(unsafe_code)]

use std::{convert::Infallible, net::SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tonic::{Request as GrpcRequest, metadata::BinaryMetadataValue, transport::Channel};
use ucr_api_grpc::{
    SERVICE_CREDENTIAL_ID_METADATA_KEY, SERVICE_CREDENTIAL_SECRET_METADATA_KEY, pb,
};
use ucr_machine_auth::{OAuthClientSecretBinding, decode_oauth_client_secret};
use ucr_model::{OpaqueId, TenantScope};
use zeroize::Zeroize;

const DEFAULT_BIND: &str = "127.0.0.1:8081";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:50051";
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;
const MAX_BASIC_DECODED_BYTES: usize = 2048;
const MAX_CLIENT_SECRET_BYTES: usize = 1024;

type HttpBody = UnsyncBoxBody<Bytes, Infallible>;
type HttpResponse = Response<HttpBody>;

#[derive(Debug, Clone, Copy)]
struct GatewayFailure {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
    challenge_basic: bool,
}

impl GatewayFailure {
    const fn new(status: StatusCode, error: &'static str, description: &'static str) -> Self {
        Self {
            status,
            error,
            description,
            challenge_basic: false,
        }
    }

    const fn invalid_client(description: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description,
            challenge_basic: true,
        }
    }

    fn into_response(self) -> HttpResponse {
        oauth_error_response(
            self.status,
            self.error,
            self.description,
            self.challenge_basic,
        )
    }
}

#[derive(Clone, Debug)]
struct AppState {
    upstream: Channel,
}

struct BasicCredentials {
    client_id: OpaqueId,
    client_secret: String,
}

impl Drop for BasicCredentials {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}

impl core::fmt::Debug for BasicCredentials {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BasicCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TokenForm {
    requested_scopes: Vec<String>,
    audience: String,
    requested_ttl_seconds: Option<u32>,
}

struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u32,
    scope: String,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

impl Serialize for TokenResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("TokenResponse", 4)?;
        state.serialize_field("access_token", &self.access_token)?;
        state.serialize_field("token_type", &self.token_type)?;
        state.serialize_field("expires_in", &self.expires_in)?;
        state.serialize_field("scope", &self.scope)?;
        state.end()
    }
}

#[derive(Debug, Serialize)]
struct OAuthErrorResponse {
    error: &'static str,
    error_description: &'static str,
}

#[derive(Debug, Serialize)]
struct OAuthMetadataResponse {
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
    grant_types_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JwksResponse {
    keys: Vec<JwkResponse>,
}

#[derive(Debug, Serialize)]
struct JwkResponse {
    kty: String,
    crv: String,
    #[serde(rename = "use")]
    key_use: String,
    alg: String,
    kid: String,
    x: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ucr-auth-web: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let bind: SocketAddr = std::env::var("UCR_AUTH_WEB_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
        .parse()
        .map_err(|error| format!("invalid UCR_AUTH_WEB_BIND: {error}"))?;
    validate_loopback_bind(bind)?;

    let upstream =
        std::env::var("UCR_AUTH_GRPC_UPSTREAM").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    let channel = Channel::from_shared(upstream)
        .map_err(|error| format!("invalid auth upstream URI: {error}"))?
        .connect()
        .await
        .map_err(|error| format!("connect auth upstream: {error}"))?;
    let state = AppState { upstream: channel };

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind OAuth gateway: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve OAuth gateway: {error}"))?;
    println!("UCR_AUTH_WEB_READY endpoint=http://{address} tls_edge=required");

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept OAuth gateway connection: {error}"))?;
        let io = TokioIo::new(stream);
        let connection_state = state.clone();
        tokio::spawn(async move {
            let service =
                service_fn(move |request| handle_request(request, connection_state.clone()));
            if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("ucr-auth-web: connection closed: {error}");
            }
        });
    }
}

fn validate_loopback_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(
            "OAuth gateway requires a loopback bind; publish it only through a trusted HTTPS reverse proxy"
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
        (Method::GET, "/.well-known/oauth-authorization-server") => {
            authorization_server_metadata(&state).await
        }
        (Method::GET, "/oauth2/jwks") => jwks(&state).await,
        (Method::POST, "/oauth2/token") => token(request, &state).await,
        _ => oauth_error_response(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "OAuth route not found",
            false,
        ),
    };

    Ok(response)
}

async fn token(request: Request<Incoming>, state: &AppState) -> HttpResponse {
    if !is_form_urlencoded(request.headers()) {
        return GatewayFailure::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
            "token endpoint requires application/x-www-form-urlencoded",
        )
        .into_response();
    }

    let credentials = match basic_credentials(request.headers()) {
        Ok(credentials) => credentials,
        Err(error) => return error.into_response(),
    };
    let Ok(binding) = decode_oauth_client_secret(&credentials.client_secret) else {
        return GatewayFailure::invalid_client("invalid client credentials").into_response();
    };
    let body = match bounded_body(request.into_body()).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let form = match parse_token_form(&body) {
        Ok(form) => form,
        Err(error) => return error.into_response(),
    };

    let mut client = machine_auth_client(state);
    let mut grpc_request = GrpcRequest::new(pb::MachineTokenRequest {
        scope: Some(pb_scope(binding.scope())),
        client_id: Some(pb_id(&credentials.client_id)),
        requested_scopes: form.requested_scopes,
        audience: form.audience,
        requested_ttl_seconds: form.requested_ttl_seconds.unwrap_or_default(),
    });
    attach_service_credential(&mut grpc_request, &binding);

    match client.exchange_client_credentials(grpc_request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::machine_token_response::Result::Token(token)) => token_response(token),
            Some(pb::machine_token_response::Result::Error(error)) => {
                machine_auth_error(&error).into_response()
            }
            None => GatewayFailure::new(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "machine auth returned an empty response",
            )
            .into_response(),
        },
        Err(status) => grpc_failure(&status).into_response(),
    }
}

async fn authorization_server_metadata(state: &AppState) -> HttpResponse {
    let mut client = machine_auth_client(state);
    let request = GrpcRequest::new(pb::MachineAuthMetadataRequest {});
    match client.get_metadata(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::machine_auth_metadata_response::Result::Metadata(metadata)) => json_response(
                StatusCode::OK,
                &OAuthMetadataResponse {
                    issuer: metadata.issuer,
                    token_endpoint: metadata.token_endpoint,
                    jwks_uri: metadata.jwks_uri,
                    grant_types_supported: metadata.supported_grant_types,
                    scopes_supported: metadata.supported_scopes,
                    token_endpoint_auth_methods_supported: metadata
                        .supported_token_endpoint_auth_methods,
                },
            ),
            Some(pb::machine_auth_metadata_response::Result::Error(error)) => {
                machine_auth_error(&error).into_response()
            }
            None => GatewayFailure::new(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "machine auth returned empty metadata",
            )
            .into_response(),
        },
        Err(status) => grpc_failure(&status).into_response(),
    }
}

async fn jwks(state: &AppState) -> HttpResponse {
    let mut client = machine_auth_client(state);
    let request = GrpcRequest::new(pb::MachineAuthJwksRequest {});
    match client.get_jwks(request).await {
        Ok(response) => match response.into_inner().result {
            Some(pb::machine_auth_jwks_response::Result::Jwks(jwks)) => json_response(
                StatusCode::OK,
                &JwksResponse {
                    keys: jwks
                        .keys
                        .into_iter()
                        .map(|key| JwkResponse {
                            kty: key.kty,
                            crv: key.crv,
                            key_use: key.r#use,
                            alg: key.alg,
                            kid: key.kid,
                            x: key.x,
                        })
                        .collect(),
                },
            ),
            Some(pb::machine_auth_jwks_response::Result::Error(error)) => {
                machine_auth_error(&error).into_response()
            }
            None => GatewayFailure::new(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "machine auth returned empty JWKS",
            )
            .into_response(),
        },
        Err(status) => grpc_failure(&status).into_response(),
    }
}

fn machine_auth_client(
    state: &AppState,
) -> pb::machine_auth_service_client::MachineAuthServiceClient<Channel> {
    pb::machine_auth_service_client::MachineAuthServiceClient::new(state.upstream.clone())
}

fn attach_service_credential<T>(request: &mut GrpcRequest<T>, binding: &OAuthClientSecretBinding) {
    let mut credential_id =
        BinaryMetadataValue::from_bytes(binding.credential_id().as_opaque().as_wire_bytes());
    credential_id.set_sensitive(true);
    let mut secret = BinaryMetadataValue::from_bytes(binding.secret().as_bytes());
    secret.set_sensitive(true);
    request
        .metadata_mut()
        .insert_bin(SERVICE_CREDENTIAL_ID_METADATA_KEY, credential_id);
    request
        .metadata_mut()
        .insert_bin(SERVICE_CREDENTIAL_SECRET_METADATA_KEY, secret);
}

fn basic_credentials(headers: &hyper::HeaderMap) -> Result<BasicCredentials, GatewayFailure> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| GatewayFailure::invalid_client("missing HTTP Basic client credentials"))?;
    let value = value
        .to_str()
        .map_err(|_| GatewayFailure::invalid_client("invalid HTTP Basic client credentials"))?;
    if value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(GatewayFailure::invalid_client(
            "HTTP Basic client credentials exceed the bounded limit",
        ));
    }
    let bytes = value.as_bytes();
    if bytes.len() < 6 || !bytes[..6].eq_ignore_ascii_case(b"Basic ") {
        return Err(GatewayFailure::invalid_client(
            "client_secret_basic is required",
        ));
    }
    let encoded = &value[6..];

    let mut decoded = STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| GatewayFailure::invalid_client("invalid HTTP Basic client credentials"))?;
    if decoded.len() > MAX_BASIC_DECODED_BYTES {
        decoded.zeroize();
        return Err(GatewayFailure::invalid_client(
            "HTTP Basic client credentials exceed the bounded limit",
        ));
    }

    let result = decode_basic_pair(&decoded);
    decoded.zeroize();
    result
}

fn decode_basic_pair(decoded: &[u8]) -> Result<BasicCredentials, GatewayFailure> {
    let separator = decoded
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| GatewayFailure::invalid_client("invalid HTTP Basic client credentials"))?;
    let client_id = decode_form_component(&decoded[..separator])?;
    let mut client_secret = decode_form_component(&decoded[separator + 1..])?;
    if client_secret.is_empty() || client_secret.len() > MAX_CLIENT_SECRET_BYTES {
        client_secret.zeroize();
        return Err(GatewayFailure::invalid_client("invalid client credentials"));
    }
    let Ok(client_id) = OpaqueId::new(client_id) else {
        client_secret.zeroize();
        return Err(GatewayFailure::invalid_client("invalid client credentials"));
    };
    Ok(BasicCredentials {
        client_id,
        client_secret,
    })
}

fn decode_form_component(value: &[u8]) -> Result<String, GatewayFailure> {
    let mut input = Vec::with_capacity(value.len() + 2);
    input.extend_from_slice(b"v=");
    input.extend_from_slice(value);

    let decoded = {
        let mut pairs = form_urlencoded::parse(&input);
        match (pairs.next(), pairs.next()) {
            (Some((key, value)), None) if key == "v" => value.into_owned(),
            _ => {
                input.zeroize();
                return Err(GatewayFailure::invalid_client(
                    "invalid HTTP Basic client credentials",
                ));
            }
        }
    };
    input.zeroize();
    if decoded.contains('�') {
        return Err(GatewayFailure::invalid_client(
            "invalid HTTP Basic client credentials",
        ));
    }
    Ok(decoded)
}

fn parse_token_form(body: &[u8]) -> Result<TokenForm, GatewayFailure> {
    let mut grant_type = None;
    let mut scope = None;
    let mut audience = None;
    let mut requested_ttl_seconds = None;

    for (key, value) in form_urlencoded::parse(body) {
        if key.contains('�') || value.contains('�') {
            return Err(GatewayFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token request contains invalid UTF-8",
            ));
        }
        match key.as_ref() {
            "grant_type" => set_once(&mut grant_type, value.into_owned())?,
            "scope" => set_once(&mut scope, value.into_owned())?,
            "audience" => set_once(&mut audience, value.into_owned())?,
            "requested_ttl_seconds" => {
                let parsed = value.parse::<u32>().map_err(|_| {
                    GatewayFailure::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "requested_ttl_seconds must be an unsigned integer",
                    )
                })?;
                if requested_ttl_seconds.replace(parsed).is_some() {
                    return Err(GatewayFailure::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "duplicate requested_ttl_seconds",
                    ));
                }
            }
            _ => {}
        }
    }

    if grant_type.as_deref() != Some("client_credentials") {
        return Err(GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be client_credentials",
        ));
    }

    let scope = scope.ok_or_else(|| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope is required",
        )
    })?;
    let requested_scopes = parse_scopes(&scope)?;
    let audience = audience.ok_or_else(|| {
        GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience is required",
        )
    })?;
    if audience.is_empty() {
        return Err(GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "audience must not be empty",
        ));
    }

    Ok(TokenForm {
        requested_scopes,
        audience,
        requested_ttl_seconds,
    })
}

fn set_once(target: &mut Option<String>, value: String) -> Result<(), GatewayFailure> {
    if target.replace(value).is_some() {
        Err(GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "duplicate OAuth request parameter",
        ))
    } else {
        Ok(())
    }
}

fn parse_scopes(scope: &str) -> Result<Vec<String>, GatewayFailure> {
    if scope.is_empty() {
        return Err(GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must not be empty",
        ));
    }
    let parts = scope.split(' ').collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must use single spaces between values",
        ));
    }
    Ok(parts.into_iter().map(str::to_owned).collect())
}

fn is_form_urlencoded(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

async fn bounded_body(mut body: Incoming) -> Result<Bytes, GatewayFailure> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            GatewayFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "could not read token request body",
            )
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let next_len = bytes
            .len()
            .checked_add(data.len())
            .ok_or(GatewayFailure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "token request body exceeds the bounded limit",
            ))?;
        if next_len > MAX_REQUEST_BODY_BYTES {
            bytes.zeroize();
            return Err(GatewayFailure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "token request body exceeds the bounded limit",
            ));
        }
        bytes.extend_from_slice(&data);
    }
    Ok(Bytes::from(bytes))
}

fn pb_scope(scope: &TenantScope) -> pb::TenantScope {
    pb::TenantScope {
        tenant_id: Some(pb_id(scope.tenant_id.as_opaque())),
        namespace_id: scope.namespace_id.as_ref().map(|id| pb_id(id.as_opaque())),
    }
}

fn pb_id(id: &OpaqueId) -> pb::OpaqueId {
    pb::OpaqueId {
        value: id.as_wire_bytes().to_vec(),
    }
}

fn token_response(token: pb::MachineAccessToken) -> HttpResponse {
    let access_token = match String::from_utf8(token.access_token) {
        Ok(access_token) => access_token,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return GatewayFailure::new(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "machine auth returned a malformed access token",
            )
            .into_response();
        }
    };
    let response = TokenResponse {
        access_token,
        token_type: token.token_type,
        expires_in: token.expires_in_seconds,
        scope: token.granted_scopes.join(" "),
    };
    json_response(StatusCode::OK, &response)
}

fn machine_auth_error(error: &pb::ErrorEnvelope) -> GatewayFailure {
    match pb::ErrorCode::try_from(error.code) {
        Ok(pb::ErrorCode::Unauthenticated) => {
            GatewayFailure::invalid_client("invalid client credentials")
        }
        Ok(pb::ErrorCode::PermissionDenied) => GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "client is not authorized for the requested operation",
        ),
        Ok(pb::ErrorCode::InvalidArgument | pb::ErrorCode::MalformedFrame) => GatewayFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid token request",
        ),
        Ok(pb::ErrorCode::RateLimited | pb::ErrorCode::TemporarilyUnavailable) => {
            GatewayFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token service is temporarily unavailable",
            )
        }
        Ok(pb::ErrorCode::ResourceExhausted) => GatewayFailure::new(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "token service capacity is exhausted",
        ),
        _ => GatewayFailure::new(
            StatusCode::BAD_GATEWAY,
            "server_error",
            "machine auth rejected the request",
        ),
    }
}

fn grpc_failure(status: &tonic::Status) -> GatewayFailure {
    if status.code() == tonic::Code::Unavailable {
        GatewayFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "machine auth upstream is unavailable",
        )
    } else {
        GatewayFailure::new(
            StatusCode::BAD_GATEWAY,
            "server_error",
            "machine auth upstream failed",
        )
    }
}

fn oauth_error_response(
    status: StatusCode,
    error: &'static str,
    description: &'static str,
    challenge_basic: bool,
) -> HttpResponse {
    let mut response = json_response(
        status,
        &OAuthErrorResponse {
            error,
            error_description: description,
        },
    );
    if challenge_basic {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            hyper::header::HeaderValue::from_static(r#"Basic realm="ucr-oauth", charset="UTF-8""#),
        );
    }
    response
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> HttpResponse {
    let bytes =
        serde_json::to_vec(payload).unwrap_or_else(|_| br#"{"error":"server_error"}"#.to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(PRAGMA, "no-cache")
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
    use hyper::header::HeaderValue;
    use ucr_core::ServiceCredentialSecret;
    use ucr_machine_auth::encode_oauth_client_secret;
    use ucr_model::{ServiceCredentialId, TenantId};

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test opaque ID")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque("tenant-auth-web")),
            namespace_id: None,
        }
    }

    #[test]
    fn oauth_gateway_refuses_non_loopback_bind() {
        let local: SocketAddr = "127.0.0.1:8081".parse().expect("loopback");
        let remote: SocketAddr = "0.0.0.0:8081".parse().expect("remote");
        assert!(validate_loopback_bind(local).is_ok());
        assert!(validate_loopback_bind(remote).is_err());
    }

    #[test]
    fn client_secret_basic_decodes_external_client_and_opaque_secret() {
        let credential_id = ServiceCredentialId::from_opaque(opaque("credential-auth-web"));
        let secret = ServiceCredentialSecret::from_bytes([7_u8; 32]);
        let oauth_secret = encode_oauth_client_secret(&scope(), &credential_id, &secret);
        let client_id = "integration%3Aauth-web";
        let basic = STANDARD.encode(format!("{client_id}:{}", oauth_secret.expose_secret()));
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {basic}")).expect("authorization"),
        );

        let credentials = basic_credentials(&headers).expect("Basic credentials");
        assert_eq!(credentials.client_id.as_str(), "integration:auth-web");
        assert_eq!(credentials.client_secret, oauth_secret.expose_secret());
        assert!(!format!("{credentials:?}").contains(oauth_secret.expose_secret()));
    }

    #[test]
    fn token_form_requires_client_credentials_scope_and_audience() {
        let form = parse_token_form(
            b"grant_type=client_credentials&scope=conference%3Aread+attendance%3Aread&audience=ucr-api&requested_ttl_seconds=300",
        )
        .expect("token form");
        assert_eq!(
            form,
            TokenForm {
                requested_scopes: vec!["conference:read".to_owned(), "attendance:read".to_owned(),],
                audience: "ucr-api".to_owned(),
                requested_ttl_seconds: Some(300),
            }
        );

        assert!(
            parse_token_form(b"grant_type=password&scope=conference%3Aread&audience=ucr-api")
                .is_err()
        );
        assert!(parse_token_form(b"grant_type=client_credentials&audience=ucr-api").is_err());
        assert!(
            parse_token_form(b"grant_type=client_credentials&scope=conference%3Aread").is_err()
        );
    }

    #[test]
    fn oauth_responses_are_not_cached() {
        let response = json_response(
            StatusCode::OK,
            &OAuthMetadataResponse {
                issuer: "https://auth.example.test".to_owned(),
                token_endpoint: "https://auth.example.test/oauth2/token".to_owned(),
                jwks_uri: "https://auth.example.test/oauth2/jwks".to_owned(),
                grant_types_supported: vec!["client_credentials".to_owned()],
                scopes_supported: vec!["conference:read".to_owned()],
                token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_owned()],
            },
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&hyper::header::HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(PRAGMA),
            Some(&hyper::header::HeaderValue::from_static("no-cache"))
        );
    }
}

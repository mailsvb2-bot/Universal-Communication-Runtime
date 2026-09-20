#![forbid(unsafe_code)]

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use ucr_core::{EventWebhookDeliveryError, EventWebhookSink};
use ucr_model::{EventEnvelope, EventSubscription, EventSubscriptionMode};
use url::{Host, Url};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

const WEBHOOK_SCHEMA: &str = "ucr.webhook.event.v1";
const USER_AGENT: &str = "UCR-Webhook/1";
const SIGNATURE_HEADER: &str = "x-ucr-webhook-signature";
const EVENT_ID_HEADER: &str = "x-ucr-webhook-id";
const EVENT_TIME_HEADER: &str = "x-ucr-webhook-timestamp";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WebhookSigningSecret([u8; 32]);

impl WebhookSigningSecret {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for WebhookSigningSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebhookSigningSecret(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardenedWebhookRequest {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub resolved_ips: Vec<IpAddr>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookHttpResponse {
    pub status: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookResolveError {
    Unavailable,
    Empty,
}

pub trait WebhookDnsResolver: fmt::Debug + Send + Sync {
    /// Resolves one hostname for a single delivery attempt.
    ///
    /// # Errors
    /// Must fail closed when DNS is unavailable or returns no usable addresses.
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, WebhookResolveError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookTransportError {
    Retryable,
    Permanent,
}

/// Deployment-owned HTTPS executor.
///
/// Implementations MUST connect to one of `request.resolved_ips`, preserve `request.host` as
/// TLS SNI/HTTP Host, validate the peer certificate for that host, and MUST NOT follow redirects.
pub trait WebhookHttpsExecutor: fmt::Debug + Send + Sync {
    /// Sends one already validated HTTPS request.
    ///
    /// # Errors
    /// Classifies network/TLS/provider failures without exposing credentials.
    fn post(
        &self,
        request: &HardenedWebhookRequest,
    ) -> Result<WebhookHttpResponse, WebhookTransportError>;
}

pub struct HardenedWebhookSink<R, X> {
    resolver: R,
    executor: X,
    signing_secret: WebhookSigningSecret,
}

impl<R, X> HardenedWebhookSink<R, X> {
    #[must_use]
    pub const fn new(
        resolver: R,
        executor: X,
        signing_secret: WebhookSigningSecret,
    ) -> Self {
        Self {
            resolver,
            executor,
            signing_secret,
        }
    }
}

impl<R: fmt::Debug, X: fmt::Debug> fmt::Debug for HardenedWebhookSink<R, X> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardenedWebhookSink")
            .field("resolver", &self.resolver)
            .field("executor", &self.executor)
            .field("signing_secret", &"<redacted>")
            .finish()
    }
}

impl<R, X> EventWebhookSink for HardenedWebhookSink<R, X>
where
    R: WebhookDnsResolver,
    X: WebhookHttpsExecutor,
{
    fn deliver(
        &self,
        subscription: &EventSubscription,
        event: &EventEnvelope,
    ) -> Result<(), EventWebhookDeliveryError> {
        let request = self
            .prepare_request(subscription, event)
            .map_err(|error| error.delivery_error())?;
        let response = self
            .executor
            .post(&request)
            .map_err(map_transport_error)?;
        classify_status(response.status)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookPolicyError {
    InvalidSubscription,
    InvalidEndpoint,
    PrivateEndpoint,
    ResolutionUnavailable,
}

impl WebhookPolicyError {
    const fn delivery_error(self) -> EventWebhookDeliveryError {
        match self {
            Self::ResolutionUnavailable => EventWebhookDeliveryError::Retryable,
            Self::InvalidSubscription | Self::InvalidEndpoint | Self::PrivateEndpoint => {
                EventWebhookDeliveryError::Permanent
            }
        }
    }
}

impl<R, X> HardenedWebhookSink<R, X>
where
    R: WebhookDnsResolver,
    X: WebhookHttpsExecutor,
{
    fn prepare_request(
        &self,
        subscription: &EventSubscription,
        event: &EventEnvelope,
    ) -> Result<HardenedWebhookRequest, WebhookPolicyError> {
        if subscription.mode != EventSubscriptionMode::Webhook
            || subscription.scope != event.scope
            || subscription.max_in_flight != 1
        {
            return Err(WebhookPolicyError::InvalidSubscription);
        }
        let endpoint = subscription
            .webhook_uri
            .as_deref()
            .ok_or(WebhookPolicyError::InvalidSubscription)?;
        let url = Url::parse(endpoint).map_err(|_| WebhookPolicyError::InvalidEndpoint)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(WebhookPolicyError::InvalidEndpoint);
        }
        let host = url.host().ok_or(WebhookPolicyError::InvalidEndpoint)?;
        let host_text = url
            .host_str()
            .ok_or(WebhookPolicyError::InvalidEndpoint)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(WebhookPolicyError::InvalidEndpoint)?;
        if port == 0 {
            return Err(WebhookPolicyError::InvalidEndpoint);
        }
        let resolved_ips = match host {
            Host::Ipv4(address) => vec![IpAddr::V4(address)],
            Host::Ipv6(address) => vec![IpAddr::V6(address)],
            Host::Domain(domain) => self
                .resolver
                .resolve(domain)
                .map_err(|_| WebhookPolicyError::ResolutionUnavailable)?,
        };
        if resolved_ips.is_empty() {
            return Err(WebhookPolicyError::ResolutionUnavailable);
        }
        if resolved_ips.iter().any(|address| !is_public_address(*address)) {
            return Err(WebhookPolicyError::PrivateEndpoint);
        }

        let body = webhook_body(subscription, event);
        let body_hash = Sha256::digest(&body);
        let timestamp = event.wall_time_unix_ms.to_string();
        let event_id = event.event_id.as_opaque().as_str();
        let subscription_id = subscription.subscription_id.as_opaque().as_str();
        let mut mac = HmacSha256::new_from_slice(&self.signing_secret.0)
            .map_err(|_| WebhookPolicyError::InvalidSubscription)?;
        mac.update(timestamp.as_bytes());
        mac.update(b"\n");
        mac.update(subscription_id.as_bytes());
        mac.update(b"\n");
        mac.update(event_id.as_bytes());
        mac.update(b"\n");
        mac.update(&body_hash);
        let signature = hex_lower(&mac.finalize().into_bytes());

        Ok(HardenedWebhookRequest {
            host: host_text,
            port,
            path: if url.path().is_empty() {
                "/".to_owned()
            } else {
                url.path().to_owned()
            },
            resolved_ips,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("user-agent".to_owned(), USER_AGENT.to_owned()),
                (EVENT_ID_HEADER.to_owned(), event_id.to_owned()),
                (EVENT_TIME_HEADER.to_owned(), timestamp),
                (
                    SIGNATURE_HEADER.to_owned(),
                    format!("sha256={signature}"),
                ),
            ],
            body,
            follow_redirects: false,
        })
    }
}

fn webhook_body(subscription: &EventSubscription, event: &EventEnvelope) -> Vec<u8> {
    let namespace = event
        .scope
        .namespace_id
        .as_ref()
        .map(|value| value.as_opaque().as_str());
    serde_json::to_vec(&json!({
        "schema": WEBHOOK_SCHEMA,
        "subscription_id": subscription.subscription_id.as_opaque().as_str(),
        "event_id": event.event_id.as_opaque().as_str(),
        "tenant_id": event.scope.tenant_id.as_opaque().as_str(),
        "namespace_id": namespace,
        "event_type": event.event_type,
        "wall_time_unix_ms": event.wall_time_unix_ms,
        "logical_order": event.logical_order,
        "schema_major": event.schema_version.major,
        "schema_minor": event.schema_version.minor,
        "payload_base64": BASE64.encode(&event.payload),
    }))
    .expect("JSON serialization of bounded canonical webhook envelope cannot fail")
}

const fn map_transport_error(error: WebhookTransportError) -> EventWebhookDeliveryError {
    match error {
        WebhookTransportError::Retryable => EventWebhookDeliveryError::Retryable,
        WebhookTransportError::Permanent => EventWebhookDeliveryError::Permanent,
    }
}

fn classify_status(status: u16) -> Result<(), EventWebhookDeliveryError> {
    match status {
        200..=299 => Ok(()),
        408 | 425 | 429 | 500..=599 => Err(EventWebhookDeliveryError::Retryable),
        _ => Err(EventWebhookDeliveryError::Permanent),
    }
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || octets[0] == 0
        || octets[0] == 100 && (64..=127).contains(&octets[1])
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 0
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 2
        || octets[0] == 198 && matches!(octets[1], 18 | 19)
        || octets[0] == 198 && octets[1] == 51 && octets[2] == 100
        || octets[0] == 203 && octets[1] == 0 && octets[2] == 113
        || octets[0] >= 240)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let unique_local = segments[0] & 0xfe00 == 0xfc00;
    let link_local = segments[0] & 0xffc0 == 0xfe80;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let ipv4_mapped = segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff;
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || unique_local
        || link_local
        || documentation
        || ipv4_mapped)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, sync::Mutex};

    use super::*;
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EventId,
        EventSubscriptionId, EventSubscriptionStart, OpaqueId, ProtocolVersion, TenantId,
        TenantScope,
    };

    #[derive(Debug)]
    struct StaticResolver {
        addresses: Vec<IpAddr>,
    }

    impl WebhookDnsResolver for StaticResolver {
        fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, WebhookResolveError> {
            Ok(self.addresses.clone())
        }
    }

    #[derive(Debug)]
    struct RecordingExecutor {
        status: u16,
        request: Mutex<Option<HardenedWebhookRequest>>,
    }

    impl WebhookHttpsExecutor for RecordingExecutor {
        fn post(
            &self,
            request: &HardenedWebhookRequest,
        ) -> Result<WebhookHttpResponse, WebhookTransportError> {
            *self.request.lock().expect("request lock") = Some(request.clone());
            Ok(WebhookHttpResponse {
                status: self.status,
            })
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-webhook")),
            namespace_id: None,
        }
    }

    fn subscription(uri: &str) -> EventSubscription {
        EventSubscription {
            subscription_id: EventSubscriptionId::from_opaque(oid("subscription-webhook")),
            scope: scope(),
            mode: EventSubscriptionMode::Webhook,
            webhook_uri: Some(uri.to_owned()),
            event_types: vec!["ucr.conference.attendance.joined.v1".to_owned()],
            max_in_flight: 1,
            max_attempts: 5,
            start: EventSubscriptionStart::Latest,
        }
    }

    fn event() -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid("event-webhook")),
            scope: scope(),
            event_type: "ucr.conference.attendance.joined.v1".to_owned(),
            payload: b"payload".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-webhook")),
                kind: ActorKind::Service,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-webhook")),
                identity_id: None,
            },
            wall_time_unix_ms: 1_000,
            logical_order: 7,
            correlation: CorrelationContext {
                correlation_id: oid("correlation-webhook"),
                causation_id: None,
                idempotency_key: None,
            },
            schema_version: ProtocolVersion { major: 1, minor: 0 },
            integrity_metadata: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn public_https_delivery_is_signed_and_redirects_are_disabled() {
        let sink = HardenedWebhookSink::new(
            StaticResolver {
                addresses: vec![IpAddr::from_str("93.184.216.34").expect("public ip")],
            },
            RecordingExecutor {
                status: 204,
                request: Mutex::new(None),
            },
            WebhookSigningSecret::from_bytes([7_u8; 32]),
        );
        sink.deliver(&subscription("https://example.com/events"), &event())
            .expect("deliver");
        let request = sink
            .executor
            .request
            .lock()
            .expect("request lock")
            .clone()
            .expect("request");
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 443);
        assert_eq!(request.path, "/events");
        assert!(!request.follow_redirects);
        assert!(request.headers.iter().any(|(name, value)| {
            name == SIGNATURE_HEADER && value.starts_with("sha256=") && value.len() == 71
        }));
    }

    #[test]
    fn private_or_credentialed_endpoints_fail_closed() {
        let private = HardenedWebhookSink::new(
            StaticResolver {
                addresses: vec![IpAddr::from_str("127.0.0.1").expect("loopback")],
            },
            RecordingExecutor {
                status: 204,
                request: Mutex::new(None),
            },
            WebhookSigningSecret::from_bytes([1_u8; 32]),
        );
        assert_eq!(
            private.deliver(&subscription("https://example.com/events"), &event()),
            Err(EventWebhookDeliveryError::Permanent)
        );
        assert_eq!(
            private.deliver(
                &subscription("https://user:pass@example.com/events"),
                &event()
            ),
            Err(EventWebhookDeliveryError::Permanent)
        );
        assert_eq!(
            private.deliver(&subscription("https://example.com/events?token=x"), &event()),
            Err(EventWebhookDeliveryError::Permanent)
        );
    }

    #[test]
    fn retryable_provider_statuses_preserve_dispatcher_retry_semantics() {
        let sink = HardenedWebhookSink::new(
            StaticResolver {
                addresses: vec![IpAddr::from_str("93.184.216.34").expect("public ip")],
            },
            RecordingExecutor {
                status: 429,
                request: Mutex::new(None),
            },
            WebhookSigningSecret::from_bytes([9_u8; 32]),
        );
        assert_eq!(
            sink.deliver(&subscription("https://example.com/events"), &event()),
            Err(EventWebhookDeliveryError::Retryable)
        );
    }
}

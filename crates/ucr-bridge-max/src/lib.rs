#![forbid(unsafe_code)]

use core::fmt;
use std::{collections::BTreeSet, io::Read};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ucr_bridge::{BridgeProvider, BridgeProviderFailure, BridgeProviderFailureKind};
use ucr_model::{
    BridgeAction, BridgeCapability, BridgeDataPermission, BridgeEventCursor, BridgeEventPage,
    BridgeInboundEvent, BridgeProviderAcceptance, BridgeProviderManifest, IntegrationId,
    ProtocolVersion, TenantScope,
};
use ucr_protocol::{BRIDGE_SDK_VERSION, MAX_BRIDGE_EVENT_PAGE_ITEMS, validate_bridge_event_page};

pub const MAX_PROVIDER_ID: &str = "vendor.max.bot_api";
pub const MAX_BOT_API_SCHEMA_VERSION: &str = "0.0.33";
pub const MAX_TEXT_CHARS: usize = 4_000;
pub const MAX_UPDATES_PER_POLL: usize = 1_000;
const MAX_API_ROOT: &str = "https://platform-api2.max.ru";
const MAX_HTTP_TIMEOUT_SECS: u64 = 35;
const MAX_LONG_POLL_TIMEOUT_SECS: u8 = 25;
const MAX_RESPONSE_BODY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
const MAX_MESSAGE_ID_BYTES: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub struct MaxBotToken(String);

impl MaxBotToken {
    /// Creates bounded MAX bot-token material without logging or normalization.
    ///
    /// # Errors
    /// Rejects empty, oversized, whitespace/control-containing or non-ASCII credentials.
    pub fn new(value: impl Into<String>) -> Result<Self, MaxConfigError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > 4_096 || !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(MaxConfigError::InvalidBotToken);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MaxBotToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaxBotToken(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxConfigError {
    InvalidBotToken,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MaxTarget {
    User(i64),
    Chat(i64),
}

impl MaxTarget {
    /// Parses an explicit MAX target from the opaque Bridge target.
    ///
    /// Canonical external targets use `user:<positive-id>` or `chat:<non-zero-id>`. The adapter
    /// never guesses whether one numeric identifier is a user or a chat/channel.
    ///
    /// # Errors
    /// Rejects malformed UTF-8, unknown prefixes, zero IDs and non-positive user IDs.
    pub fn parse(value: &[u8]) -> Result<Self, MaxBoundaryError> {
        let value = std::str::from_utf8(value).map_err(|_| MaxBoundaryError::InvalidTarget)?;
        if let Some(raw) = value.strip_prefix("user:") {
            let id = raw
                .parse::<i64>()
                .map_err(|_| MaxBoundaryError::InvalidTarget)?;
            return (id > 0)
                .then_some(Self::User(id))
                .ok_or(MaxBoundaryError::InvalidTarget);
        }
        if let Some(raw) = value.strip_prefix("chat:") {
            let id = raw
                .parse::<i64>()
                .map_err(|_| MaxBoundaryError::InvalidTarget)?;
            return (id != 0)
                .then_some(Self::Chat(id))
                .ok_or(MaxBoundaryError::InvalidTarget);
        }
        Err(MaxBoundaryError::InvalidTarget)
    }

    const fn query(self) -> (&'static str, i64) {
        match self {
            Self::User(id) => ("user_id", id),
            Self::Chat(id) => ("chat_id", id),
        }
    }
}

impl fmt::Debug for MaxTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaxTarget(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxBoundaryError {
    InvalidTarget,
    InvalidText,
    InvalidCursor,
    InvalidProviderResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxApiFailure {
    Rejected,
    RateLimited,
    Ambiguous,
    MalformedResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxSentMessage {
    pub message_id: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MaxTextUpdate {
    pub event_id: String,
    pub chat_id: i64,
    pub actor_id: Option<i64>,
    pub text: String,
    pub occurred_at_unix_ms: i64,
}

impl fmt::Debug for MaxTextUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaxTextUpdate")
            .field("event_id", &"<opaque>")
            .field("chat_id", &"<opaque>")
            .field("has_actor_id", &self.actor_id.is_some())
            .field("text", &"<redacted>")
            .field("text_len", &self.text.len())
            .field("occurred_at_unix_ms", &self.occurred_at_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxUpdateBatch {
    pub updates: Vec<MaxTextUpdate>,
    pub next_marker: Option<i64>,
}

pub trait MaxApiClient: fmt::Debug + Send + Sync {
    /// Sends plain text through MAX `POST /messages` semantics.
    ///
    /// # Errors
    /// Returns a classified provider failure without exposing credentials or plaintext.
    fn send_text(&self, target: MaxTarget, text: &str) -> Result<MaxSentMessage, MaxApiFailure>;

    /// Polls one bounded development/test page of MAX `message_created` events.
    ///
    /// # Errors
    /// Returns explicit provider/network/response failure.
    fn poll_text_updates(
        &self,
        marker: Option<i64>,
        limit: usize,
    ) -> Result<MaxUpdateBatch, MaxApiFailure>;
}

pub struct MaxBotApiClient {
    token: MaxBotToken,
}

impl fmt::Debug for MaxBotApiClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaxBotApiClient")
            .field("token", &self.token)
            .field("api_root", &MAX_API_ROOT)
            .field("authorization", &"<redacted-header>")
            .field("redirects", &0)
            .finish_non_exhaustive()
    }
}

impl MaxBotApiClient {
    #[must_use]
    pub fn new(token: MaxBotToken) -> Self {
        Self { token }
    }

    fn post_json<B, R>(&self, url: &str, body: &B) -> Result<R, MaxApiFailure>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let encoded = serde_json::to_vec(body).map_err(|_| MaxApiFailure::MalformedResponse)?;
        let mut response = minreq::post(url)
            .with_header("authorization", self.token.expose())
            .with_header("content-type", "application/json")
            .with_timeout(MAX_HTTP_TIMEOUT_SECS)
            .with_follow_redirects(false)
            .with_max_headers_size(MAX_RESPONSE_HEADER_BYTES)
            .with_body(encoded)
            .send_lazy()
            .map_err(|_| MaxApiFailure::Ambiguous)?;
        classify_http_status(response.status_code)?;
        let bytes = read_bounded_body(&mut response)?;
        decode_json(&bytes)
    }

    fn get_json<R>(&self, url: &str) -> Result<R, MaxApiFailure>
    where
        R: DeserializeOwned,
    {
        let mut response = minreq::get(url)
            .with_header("authorization", self.token.expose())
            .with_timeout(MAX_HTTP_TIMEOUT_SECS)
            .with_follow_redirects(false)
            .with_max_headers_size(MAX_RESPONSE_HEADER_BYTES)
            .send_lazy()
            .map_err(|_| MaxApiFailure::Ambiguous)?;
        classify_http_status(response.status_code)?;
        let bytes = read_bounded_body(&mut response)?;
        decode_json(&bytes)
    }
}

impl MaxApiClient for MaxBotApiClient {
    fn send_text(&self, target: MaxTarget, text: &str) -> Result<MaxSentMessage, MaxApiFailure> {
        let (kind, id) = target.query();
        let url = format!("{MAX_API_ROOT}/messages?{kind}={id}");
        let response: MaxSendMessageResultWire = self.post_json(
            &url,
            &MaxSendMessageRequest {
                text,
                attachments: Vec::new(),
            },
        )?;
        let body = response
            .message
            .body
            .ok_or(MaxApiFailure::MalformedResponse)?;
        validate_message_id(&body.mid).map_err(|_| MaxApiFailure::MalformedResponse)?;
        Ok(MaxSentMessage {
            message_id: body.mid,
        })
    }

    fn poll_text_updates(
        &self,
        marker: Option<i64>,
        limit: usize,
    ) -> Result<MaxUpdateBatch, MaxApiFailure> {
        if limit == 0 || limit > MAX_UPDATES_PER_POLL {
            return Err(MaxApiFailure::Rejected);
        }
        let mut url = format!(
            "{MAX_API_ROOT}/updates?limit={limit}&timeout={MAX_LONG_POLL_TIMEOUT_SECS}&types=message_created"
        );
        if let Some(marker) = marker {
            if marker <= 0 {
                return Err(MaxApiFailure::Rejected);
            }
            url.push_str("&marker=");
            url.push_str(&marker.to_string());
        }
        let response: MaxUpdateListWire = self.get_json(&url)?;
        map_update_batch(response, marker, limit).map_err(|_| MaxApiFailure::MalformedResponse)
    }
}

pub struct MaxProvider<C> {
    client: C,
}

impl<C> fmt::Debug for MaxProvider<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaxProvider")
            .field("provider_id", &MAX_PROVIDER_ID)
            .finish_non_exhaustive()
    }
}

impl<C> MaxProvider<C> {
    #[must_use]
    pub const fn new(client: C) -> Self {
        Self { client }
    }

    #[must_use]
    pub const fn client(&self) -> &C {
        &self.client
    }
}

impl<C> BridgeProvider for MaxProvider<C>
where
    C: MaxApiClient,
{
    fn manifest(&self) -> BridgeProviderManifest {
        BridgeProviderManifest {
            provider_id: MAX_PROVIDER_ID.to_owned(),
            sdk_min: BRIDGE_SDK_VERSION,
            sdk_max: BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities: vec![BridgeCapability::Text],
            permissions: vec![
                BridgeDataPermission::MessageContent,
                BridgeDataPermission::ExternalIdentityReferences,
                BridgeDataPermission::InboundEvents,
            ],
            extensions: vec![],
        }
    }

    fn execute(
        &self,
        action: &BridgeAction,
    ) -> Result<BridgeProviderAcceptance, BridgeProviderFailure> {
        if action.capability != BridgeCapability::Text
            || action.canonical_message_id.is_none()
            || !action.attachment_ids.is_empty()
        {
            return Err(not_accepted(BridgeProviderFailureKind::Rejected));
        }
        let target = MaxTarget::parse(&action.external_target)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let text = validate_text(&action.provider_payload)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let result = self
            .client
            .send_text(target, text)
            .map_err(map_send_failure)?;
        Ok(BridgeProviderAcceptance {
            external_message_id: Some(result.message_id.into_bytes()),
            degradation: None,
        })
    }

    fn poll_events(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        cursor: Option<&BridgeEventCursor>,
        limit: usize,
    ) -> Result<BridgeEventPage, BridgeProviderFailure> {
        if limit == 0 || limit > MAX_BRIDGE_EVENT_PAGE_ITEMS {
            return Err(not_accepted(BridgeProviderFailureKind::Rejected));
        }
        let marker =
            parse_cursor(cursor).map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let batch = self
            .client
            .poll_text_updates(marker, limit)
            .map_err(map_poll_failure)?;
        let next_cursor = batch.next_marker.map(|value| BridgeEventCursor {
            token: value.to_string().into_bytes(),
        });
        let mut events = Vec::with_capacity(batch.updates.len());
        for update in batch.updates {
            events.push(BridgeInboundEvent {
                scope: scope.clone(),
                integration_id: integration_id.clone(),
                external_event_id: format!("message_created:{}", update.event_id).into_bytes(),
                external_conversation_id: format!("chat:{}", update.chat_id).into_bytes(),
                external_actor_id: update
                    .actor_id
                    .map(|value| format!("user:{value}").into_bytes()),
                capability: BridgeCapability::Text,
                payload: update.text.into_bytes(),
                occurred_at_unix_ms: update.occurred_at_unix_ms,
            });
        }
        let page = BridgeEventPage {
            events,
            next_cursor,
        };
        validate_bridge_event_page(&page)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        Ok(page)
    }
}

fn validate_text(payload: &[u8]) -> Result<&str, MaxBoundaryError> {
    let text = std::str::from_utf8(payload).map_err(|_| MaxBoundaryError::InvalidText)?;
    let count = text.chars().count();
    if count == 0 || count > MAX_TEXT_CHARS {
        return Err(MaxBoundaryError::InvalidText);
    }
    Ok(text)
}

fn parse_cursor(cursor: Option<&BridgeEventCursor>) -> Result<Option<i64>, MaxBoundaryError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&cursor.token).map_err(|_| MaxBoundaryError::InvalidCursor)?;
    let value = text
        .parse::<i64>()
        .map_err(|_| MaxBoundaryError::InvalidCursor)?;
    if value <= 0 {
        return Err(MaxBoundaryError::InvalidCursor);
    }
    Ok(Some(value))
}

fn validate_message_id(value: &str) -> Result<(), MaxBoundaryError> {
    if value.is_empty()
        || value.len() > MAX_MESSAGE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(MaxBoundaryError::InvalidProviderResponse);
    }
    Ok(())
}

fn map_update_batch(
    response: MaxUpdateListWire,
    requested_marker: Option<i64>,
    requested_limit: usize,
) -> Result<MaxUpdateBatch, MaxBoundaryError> {
    if response.updates.len() > requested_limit {
        return Err(MaxBoundaryError::InvalidProviderResponse);
    }
    if let Some(marker) = response.marker {
        if marker <= 0
            || requested_marker.is_some_and(|previous| {
                marker < previous || (!response.updates.is_empty() && marker == previous)
            })
        {
            return Err(MaxBoundaryError::InvalidProviderResponse);
        }
    } else if !response.updates.is_empty() {
        return Err(MaxBoundaryError::InvalidProviderResponse);
    }

    let next_marker = response.marker.or(requested_marker);
    let mut seen = BTreeSet::new();
    let mut mapped = Vec::new();
    for update in response.updates {
        if update.update_type != "message_created" {
            continue;
        }
        if update.timestamp <= 0 {
            return Err(MaxBoundaryError::InvalidProviderResponse);
        }
        let message = update
            .message
            .ok_or(MaxBoundaryError::InvalidProviderResponse)?;
        if message.timestamp <= 0 {
            return Err(MaxBoundaryError::InvalidProviderResponse);
        }
        let chat_id = message
            .recipient
            .chat_id
            .filter(|value| *value != 0)
            .ok_or(MaxBoundaryError::InvalidProviderResponse)?;
        let actor_id = match message.sender {
            Some(sender) if sender.user_id > 0 => Some(sender.user_id),
            Some(_) => return Err(MaxBoundaryError::InvalidProviderResponse),
            None => None,
        };
        let Some(body) = message.body else {
            continue;
        };
        validate_message_id(&body.mid)?;
        if !seen.insert(body.mid.clone()) {
            return Err(MaxBoundaryError::InvalidProviderResponse);
        }
        let Some(text) = body.text else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        if text.chars().count() > MAX_TEXT_CHARS {
            return Err(MaxBoundaryError::InvalidProviderResponse);
        }
        mapped.push(MaxTextUpdate {
            event_id: body.mid,
            chat_id,
            actor_id,
            text,
            occurred_at_unix_ms: message.timestamp,
        });
    }
    Ok(MaxUpdateBatch {
        updates: mapped,
        next_marker,
    })
}

const fn map_send_failure(error: MaxApiFailure) -> BridgeProviderFailure {
    match error {
        MaxApiFailure::Rejected => not_accepted(BridgeProviderFailureKind::Rejected),
        MaxApiFailure::RateLimited => not_accepted(BridgeProviderFailureKind::RateLimited),
        MaxApiFailure::Ambiguous | MaxApiFailure::MalformedResponse => {
            BridgeProviderFailure::AcceptanceUnknown(BridgeProviderFailureKind::Unavailable)
        }
    }
}

const fn map_poll_failure(error: MaxApiFailure) -> BridgeProviderFailure {
    match error {
        MaxApiFailure::RateLimited => not_accepted(BridgeProviderFailureKind::RateLimited),
        MaxApiFailure::Rejected | MaxApiFailure::MalformedResponse => {
            not_accepted(BridgeProviderFailureKind::Rejected)
        }
        MaxApiFailure::Ambiguous => not_accepted(BridgeProviderFailureKind::Unavailable),
    }
}

const fn not_accepted(kind: BridgeProviderFailureKind) -> BridgeProviderFailure {
    BridgeProviderFailure::NotAccepted(kind)
}

fn classify_http_status(status: u16) -> Result<(), MaxApiFailure> {
    match status {
        200..=299 => Ok(()),
        429 => Err(MaxApiFailure::RateLimited),
        400 | 401 | 403 | 404 | 405 => Err(MaxApiFailure::Rejected),
        _ => Err(MaxApiFailure::Ambiguous),
    }
}

fn read_bounded_body(reader: &mut impl Read) -> Result<Vec<u8>, MaxApiFailure> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_RESPONSE_BODY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MaxApiFailure::Ambiguous)?;
    if bytes.len() as u64 > MAX_RESPONSE_BODY_BYTES {
        return Err(MaxApiFailure::MalformedResponse);
    }
    Ok(bytes)
}

fn decode_json<R: DeserializeOwned>(bytes: &[u8]) -> Result<R, MaxApiFailure> {
    serde_json::from_slice(bytes).map_err(|_| MaxApiFailure::MalformedResponse)
}

#[derive(Debug, Serialize)]
struct MaxSendMessageRequest<'a> {
    text: &'a str,
    attachments: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct MaxSendMessageResultWire {
    message: MaxMessageWire,
}

#[derive(Debug, Deserialize)]
struct MaxUpdateListWire {
    updates: Vec<MaxUpdateWire>,
    marker: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct MaxUpdateWire {
    update_type: String,
    timestamp: i64,
    #[serde(default)]
    message: Option<MaxMessageWire>,
}

#[derive(Debug, Deserialize)]
struct MaxMessageWire {
    #[serde(default)]
    sender: Option<MaxSenderWire>,
    recipient: MaxRecipientWire,
    timestamp: i64,
    #[serde(default)]
    body: Option<MaxMessageBodyWire>,
}

#[derive(Debug, Deserialize)]
struct MaxSenderWire {
    user_id: i64,
}

#[derive(Debug, Deserialize)]
struct MaxRecipientWire {
    chat_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct MaxMessageBodyWire {
    mid: String,
    #[serde(default)]
    text: Option<String>,
}

/// Exercises the actual untrusted MAX response parsers used by the HTTP client.
///
/// This is side-effect free so the fuzz workspace can feed arbitrary bytes through the send
/// response, update-list, marker, message and target boundaries without network access.
fn fuzz_prior_marker(bytes: &[u8]) -> i64 {
    let mut value = 0_u64;
    for byte in bytes.iter().take(8) {
        value = value.wrapping_mul(257).wrapping_add(u64::from(*byte) + 1);
    }
    let positive_range = (i64::MAX as u64) - 1;
    i64::try_from((value % positive_range) + 1).unwrap_or(i64::MAX)
}

#[doc(hidden)]
pub fn fuzz_max_wire_boundary(bytes: &[u8]) {
    let _ = decode_json::<MaxSendMessageResultWire>(bytes);
    if let Ok(response) = decode_json::<MaxUpdateListWire>(bytes) {
        let _ = map_update_batch(response, None, MAX_BRIDGE_EVENT_PAGE_ITEMS);
    }
    if let Ok(response) = decode_json::<MaxUpdateListWire>(bytes) {
        let prior_marker = fuzz_prior_marker(bytes);
        let _ = map_update_batch(response, Some(prior_marker), MAX_BRIDGE_EVENT_PAGE_ITEMS);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = MaxBotToken::new(text.to_owned());
        let _ = MaxTarget::parse(text.as_bytes());
        let _ = validate_message_id(text);
        let _ = text.parse::<i64>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(
        mid: &str,
        text: Option<&str>,
        chat_id: i64,
        sender_id: Option<i64>,
    ) -> MaxMessageWire {
        MaxMessageWire {
            sender: sender_id.map(|user_id| MaxSenderWire { user_id }),
            recipient: MaxRecipientWire {
                chat_id: Some(chat_id),
            },
            timestamp: 1_700_000_000_123,
            body: Some(MaxMessageBodyWire {
                mid: mid.to_owned(),
                text: text.map(str::to_owned),
            }),
        }
    }

    fn created(message: MaxMessageWire) -> MaxUpdateWire {
        MaxUpdateWire {
            update_type: "message_created".to_owned(),
            timestamp: 1_700_000_000_100,
            message: Some(message),
        }
    }

    #[test]
    fn token_debug_never_contains_secret() {
        let token = MaxBotToken::new("max-secret-token_123").expect("token");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "MaxBotToken(<redacted>)");
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn client_debug_never_contains_bot_token() {
        let token = MaxBotToken::new("max-secret-token_123").expect("token");
        let client = MaxBotApiClient::new(token);
        let rendered = format!("{client:?}");
        assert!(rendered.contains("MaxBotToken(<redacted>)"));
        assert!(!rendered.contains("max-secret-token_123"));
    }

    #[test]
    fn target_parser_requires_explicit_user_or_chat_kind() {
        assert_eq!(
            MaxTarget::parse(b"user:123").expect("user"),
            MaxTarget::User(123)
        );
        assert_eq!(
            MaxTarget::parse(b"chat:-456").expect("chat"),
            MaxTarget::Chat(-456)
        );
        assert!(MaxTarget::parse(b"123").is_err());
        assert!(MaxTarget::parse(b"user:-1").is_err());
        assert!(MaxTarget::parse(b"chat:0").is_err());
        assert!(MaxTarget::parse(b"channel:1").is_err());
    }

    #[test]
    fn token_parser_rejects_whitespace_and_control_material() {
        assert!(MaxBotToken::new("bad token").is_err());
        assert!(MaxBotToken::new("bad\ntoken").is_err());
        assert!(MaxBotToken::new("").is_err());
    }

    #[test]
    fn attachment_only_message_advances_marker_without_inventing_text_event() {
        let batch = map_update_batch(
            MaxUpdateListWire {
                updates: vec![created(message("mid.abc", None, -10, Some(7)))],
                marker: Some(52),
            },
            Some(50),
            10,
        )
        .expect("batch");
        assert!(batch.updates.is_empty());
        assert_eq!(batch.next_marker, Some(52));
    }

    #[test]
    fn empty_null_marker_preserves_requested_cursor() {
        let batch = map_update_batch(
            MaxUpdateListWire {
                updates: vec![],
                marker: None,
            },
            Some(50),
            10,
        )
        .expect("empty page");
        assert!(batch.updates.is_empty());
        assert_eq!(batch.next_marker, Some(50));

        let initial = map_update_batch(
            MaxUpdateListWire {
                updates: vec![],
                marker: None,
            },
            None,
            10,
        )
        .expect("initial empty page");
        assert_eq!(initial.next_marker, None);
    }

    #[test]
    fn update_mapping_rejects_marker_rollback_or_provider_overflow() {
        assert_eq!(
            map_update_batch(
                MaxUpdateListWire {
                    updates: vec![],
                    marker: Some(49),
                },
                Some(50),
                10,
            ),
            Err(MaxBoundaryError::InvalidProviderResponse)
        );
        let updates = (0..3)
            .map(|index| created(message(&format!("mid.{index}"), Some("x"), -10, Some(7))))
            .collect();
        assert_eq!(
            map_update_batch(
                MaxUpdateListWire {
                    updates,
                    marker: Some(60),
                },
                Some(50),
                2,
            ),
            Err(MaxBoundaryError::InvalidProviderResponse)
        );
    }

    #[test]
    fn update_mapping_preserves_message_id_scope_and_millisecond_time() {
        let batch = map_update_batch(
            MaxUpdateListWire {
                updates: vec![created(message("mid.abc_123", Some("hello"), -10, Some(7)))],
                marker: Some(52),
            },
            Some(50),
            10,
        )
        .expect("batch");
        assert_eq!(batch.updates.len(), 1);
        assert_eq!(batch.updates[0].event_id, "mid.abc_123");
        assert_eq!(batch.updates[0].chat_id, -10);
        assert_eq!(batch.updates[0].actor_id, Some(7));
        assert_eq!(batch.updates[0].occurred_at_unix_ms, 1_700_000_000_123);
        assert_eq!(batch.updates[0].text, "hello");
    }

    #[test]
    fn text_send_wire_includes_empty_attachments_array() {
        let encoded = serde_json::to_value(MaxSendMessageRequest {
            text: "hello",
            attachments: Vec::new(),
        })
        .expect("encode request");
        assert_eq!(encoded["text"], "hello");
        assert_eq!(encoded["attachments"], serde_json::json!([]));
    }

    #[test]
    fn update_wire_requires_updates_field() {
        assert!(matches!(
            decode_json::<MaxUpdateListWire>(br#"{"marker":52}"#),
            Err(MaxApiFailure::MalformedResponse)
        ));
    }

    #[test]
    fn http_status_classification_separates_rejection_rate_limit_and_ambiguity() {
        assert_eq!(classify_http_status(200), Ok(()));
        assert_eq!(classify_http_status(401), Err(MaxApiFailure::Rejected));
        assert_eq!(classify_http_status(408), Err(MaxApiFailure::Ambiguous));
        assert_eq!(classify_http_status(429), Err(MaxApiFailure::RateLimited));
        assert_eq!(classify_http_status(500), Err(MaxApiFailure::Ambiguous));
        assert_eq!(classify_http_status(302), Err(MaxApiFailure::Ambiguous));
    }

    #[test]
    fn bounded_body_rejects_provider_response_bombs() {
        let limit = usize::try_from(MAX_RESPONSE_BODY_BYTES).expect("body limit");
        let data = vec![b'x'; limit + 1];
        assert_eq!(
            read_bounded_body(&mut data.as_slice()),
            Err(MaxApiFailure::MalformedResponse)
        );
    }
}

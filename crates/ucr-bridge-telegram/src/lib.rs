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

pub const TELEGRAM_PROVIDER_ID: &str = "vendor.telegram.bot_api";
pub const TELEGRAM_BOT_API_VERSION: &str = "10.3";
pub const TELEGRAM_MAX_TEXT_CHARS: usize = 4_096;
pub const TELEGRAM_MAX_UPDATES_PER_POLL: usize = 100;
const TELEGRAM_API_ROOT: &str = "https://api.telegram.org";
const TELEGRAM_HTTP_TIMEOUT_SECS: u64 = 35;
const TELEGRAM_LONG_POLL_TIMEOUT_SECS: u8 = 25;
const TELEGRAM_MAX_RESPONSE_BODY_BYTES: u64 = 4 * 1024 * 1024;
const TELEGRAM_MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct TelegramBotToken(String);

impl TelegramBotToken {
    /// Creates one bounded Bot API token without logging or normalizing it.
    ///
    /// # Errors
    /// Returns `TelegramConfigError::InvalidBotToken` for empty, oversized, non-ASCII, control,
    /// whitespace-containing, or structurally invalid token material.
    pub fn new(value: impl Into<String>) -> Result<Self, TelegramConfigError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let Some((bot_id, secret)) = value.split_once(':') else {
            return Err(TelegramConfigError::InvalidBotToken);
        };
        if bytes.len() > 256
            || bot_id.is_empty()
            || secret.is_empty()
            || !bot_id.bytes().all(|byte| byte.is_ascii_digit())
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !bytes.iter().all(u8::is_ascii_graphic)
        {
            return Err(TelegramConfigError::InvalidBotToken);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TelegramBotToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TelegramBotToken(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramConfigError {
    InvalidBotToken,
}

#[derive(Clone, PartialEq, Eq)]
pub enum TelegramChatTarget {
    Numeric(i64),
    Username(String),
}

impl TelegramChatTarget {
    /// Parses one Telegram Bot API `chat_id` from the opaque Bridge target.
    ///
    /// # Errors
    /// Returns `TelegramBoundaryError::InvalidTarget` for malformed UTF-8, zero numeric IDs,
    /// unsupported strings, or names outside Telegram's username shape.
    pub fn parse(value: &[u8]) -> Result<Self, TelegramBoundaryError> {
        let value = std::str::from_utf8(value).map_err(|_| TelegramBoundaryError::InvalidTarget)?;
        if let Ok(id) = value.parse::<i64>() {
            return (id != 0)
                .then_some(Self::Numeric(id))
                .ok_or(TelegramBoundaryError::InvalidTarget);
        }
        let Some(username) = value.strip_prefix('@') else {
            return Err(TelegramBoundaryError::InvalidTarget);
        };
        if !(5..=32).contains(&username.len())
            || !username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(TelegramBoundaryError::InvalidTarget);
        }
        Ok(Self::Username(value.to_owned()))
    }
}

impl fmt::Debug for TelegramChatTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TelegramChatTarget(<opaque>)")
    }
}

impl Serialize for TelegramChatTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Numeric(value) => serializer.serialize_i64(*value),
            Self::Username(value) => serializer.serialize_str(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramBoundaryError {
    InvalidTarget,
    InvalidText,
    InvalidCursor,
    InvalidProviderResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramApiFailure {
    Rejected,
    RateLimited,
    Ambiguous,
    MalformedResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramSentMessage {
    pub message_id: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TelegramTextUpdate {
    pub update_id: i64,
    pub chat_id: i64,
    pub actor_id: Option<i64>,
    pub text: String,
    pub occurred_at_unix_seconds: i64,
}

impl fmt::Debug for TelegramTextUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramTextUpdate")
            .field("update_id", &self.update_id)
            .field("chat_id", &"<opaque>")
            .field("has_actor_id", &self.actor_id.is_some())
            .field("text", &"<redacted>")
            .field("text_len", &self.text.len())
            .field("occurred_at_unix_seconds", &self.occurred_at_unix_seconds)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramUpdateBatch {
    pub updates: Vec<TelegramTextUpdate>,
    pub next_offset: Option<i64>,
}

pub trait TelegramApiClient: fmt::Debug + Send + Sync {
    /// Sends plain text through Telegram Bot API semantics.
    ///
    /// # Errors
    /// Returns a classified provider failure. Implementations must not expose token/plaintext in
    /// their error value or logs.
    fn send_text(
        &self,
        target: &TelegramChatTarget,
        text: &str,
    ) -> Result<TelegramSentMessage, TelegramApiFailure>;

    /// Polls a bounded batch of text updates, advancing over non-text updates as well.
    ///
    /// # Errors
    /// Returns a classified provider/network/response failure.
    fn poll_text_updates(
        &self,
        offset: Option<i64>,
        limit: usize,
    ) -> Result<TelegramUpdateBatch, TelegramApiFailure>;
}

pub struct TelegramBotApiClient {
    token: TelegramBotToken,
}

impl fmt::Debug for TelegramBotApiClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramBotApiClient")
            .field("token", &self.token)
            .field("api_root", &TELEGRAM_API_ROOT)
            .field("redirects", &0)
            .finish_non_exhaustive()
    }
}

impl TelegramBotApiClient {
    #[must_use]
    pub fn new(token: TelegramBotToken) -> Self {
        Self { token }
    }

    fn method_url(&self, method: &str) -> String {
        format!("{TELEGRAM_API_ROOT}/bot{}/{method}", self.token.expose())
    }

    fn post_json<B, R>(&self, method: &str, body: &B) -> Result<R, TelegramApiFailure>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let encoded =
            serde_json::to_vec(body).map_err(|_| TelegramApiFailure::MalformedResponse)?;
        let mut response = minreq::post(self.method_url(method))
            .with_header("content-type", "application/json")
            .with_timeout(TELEGRAM_HTTP_TIMEOUT_SECS)
            .with_follow_redirects(false)
            .with_max_headers_size(TELEGRAM_MAX_RESPONSE_HEADER_BYTES)
            .with_body(encoded)
            .send_lazy()
            .map_err(|_| TelegramApiFailure::Ambiguous)?;
        classify_http_status(response.status_code)?;
        let bytes = read_bounded_body(&mut response)?;
        decode_api_envelope(&bytes)
    }
}

fn classify_http_status(status: u16) -> Result<(), TelegramApiFailure> {
    match status {
        200..=299 => Ok(()),
        429 => Err(TelegramApiFailure::RateLimited),
        400..=499 => Err(TelegramApiFailure::Rejected),
        _ => Err(TelegramApiFailure::Ambiguous),
    }
}

fn read_bounded_body(reader: &mut impl Read) -> Result<Vec<u8>, TelegramApiFailure> {
    let mut bytes = Vec::new();
    reader
        .take(TELEGRAM_MAX_RESPONSE_BODY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TelegramApiFailure::Ambiguous)?;
    if bytes.len() as u64 > TELEGRAM_MAX_RESPONSE_BODY_BYTES {
        return Err(TelegramApiFailure::MalformedResponse);
    }
    Ok(bytes)
}

fn decode_api_envelope<R: DeserializeOwned>(bytes: &[u8]) -> Result<R, TelegramApiFailure> {
    let envelope = serde_json::from_slice::<TelegramApiEnvelope<R>>(bytes)
        .map_err(|_| TelegramApiFailure::MalformedResponse)?;
    if !envelope.ok {
        return Err(match envelope.error_code {
            Some(429) => TelegramApiFailure::RateLimited,
            Some(400..=499) => TelegramApiFailure::Rejected,
            _ => TelegramApiFailure::Ambiguous,
        });
    }
    envelope.result.ok_or(TelegramApiFailure::MalformedResponse)
}

impl TelegramApiClient for TelegramBotApiClient {
    fn send_text(
        &self,
        target: &TelegramChatTarget,
        text: &str,
    ) -> Result<TelegramSentMessage, TelegramApiFailure> {
        let response: TelegramSendMessageResult = self.post_json(
            "sendMessage",
            &TelegramSendMessageRequest {
                chat_id: target,
                text,
            },
        )?;
        if response.message_id <= 0 {
            return Err(TelegramApiFailure::MalformedResponse);
        }
        Ok(TelegramSentMessage {
            message_id: response.message_id,
        })
    }

    fn poll_text_updates(
        &self,
        offset: Option<i64>,
        limit: usize,
    ) -> Result<TelegramUpdateBatch, TelegramApiFailure> {
        let limit = limit.clamp(1, TELEGRAM_MAX_UPDATES_PER_POLL);
        let response: Vec<TelegramUpdateWire> = self.post_json(
            "getUpdates",
            &TelegramGetUpdatesRequest {
                offset,
                limit,
                timeout: TELEGRAM_LONG_POLL_TIMEOUT_SECS,
                allowed_updates: ["message"],
            },
        )?;
        map_update_batch(response, offset).map_err(|_| TelegramApiFailure::MalformedResponse)
    }
}

pub struct TelegramProvider<C> {
    client: C,
}

impl<C> fmt::Debug for TelegramProvider<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramProvider")
            .field("provider_id", &TELEGRAM_PROVIDER_ID)
            .finish_non_exhaustive()
    }
}

impl<C> TelegramProvider<C> {
    #[must_use]
    pub const fn new(client: C) -> Self {
        Self { client }
    }

    #[must_use]
    pub const fn client(&self) -> &C {
        &self.client
    }
}

impl<C> BridgeProvider for TelegramProvider<C>
where
    C: TelegramApiClient,
{
    fn manifest(&self) -> BridgeProviderManifest {
        BridgeProviderManifest {
            provider_id: TELEGRAM_PROVIDER_ID.to_owned(),
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
        let target = TelegramChatTarget::parse(&action.external_target)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let text = validate_text(&action.provider_payload)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let result = self
            .client
            .send_text(&target, text)
            .map_err(map_send_failure)?;
        Ok(BridgeProviderAcceptance {
            external_message_id: Some(result.message_id.to_string().into_bytes()),
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
        let offset =
            parse_cursor(cursor).map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let batch = self
            .client
            .poll_text_updates(offset, limit)
            .map_err(map_poll_failure)?;
        let next_cursor = batch.next_offset.map(|value| BridgeEventCursor {
            token: value.to_string().into_bytes(),
        });
        let mut events = Vec::with_capacity(batch.updates.len());
        for update in batch.updates {
            let occurred_at_unix_ms = update
                .occurred_at_unix_seconds
                .checked_mul(1_000)
                .ok_or_else(|| not_accepted(BridgeProviderFailureKind::Rejected))?;
            events.push(BridgeInboundEvent {
                scope: scope.clone(),
                integration_id: integration_id.clone(),
                external_event_id: update.update_id.to_string().into_bytes(),
                external_conversation_id: update.chat_id.to_string().into_bytes(),
                external_actor_id: update.actor_id.map(|value| value.to_string().into_bytes()),
                capability: BridgeCapability::Text,
                payload: update.text.into_bytes(),
                occurred_at_unix_ms,
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

fn validate_text(payload: &[u8]) -> Result<&str, TelegramBoundaryError> {
    let text = std::str::from_utf8(payload).map_err(|_| TelegramBoundaryError::InvalidText)?;
    let count = text.chars().count();
    if count == 0 || count > TELEGRAM_MAX_TEXT_CHARS {
        return Err(TelegramBoundaryError::InvalidText);
    }
    Ok(text)
}

fn parse_cursor(cursor: Option<&BridgeEventCursor>) -> Result<Option<i64>, TelegramBoundaryError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let text =
        std::str::from_utf8(&cursor.token).map_err(|_| TelegramBoundaryError::InvalidCursor)?;
    let value = text
        .parse::<i64>()
        .map_err(|_| TelegramBoundaryError::InvalidCursor)?;
    if value <= 0 {
        return Err(TelegramBoundaryError::InvalidCursor);
    }
    Ok(Some(value))
}

fn map_update_batch(
    updates: Vec<TelegramUpdateWire>,
    requested_offset: Option<i64>,
) -> Result<TelegramUpdateBatch, TelegramBoundaryError> {
    let mut seen = BTreeSet::new();
    let mut next_offset = requested_offset;
    let mut mapped = Vec::new();
    for update in updates {
        if update.update_id <= 0
            || requested_offset.is_some_and(|offset| update.update_id < offset)
            || !seen.insert(update.update_id)
        {
            return Err(TelegramBoundaryError::InvalidProviderResponse);
        }
        let candidate = update
            .update_id
            .checked_add(1)
            .ok_or(TelegramBoundaryError::InvalidProviderResponse)?;
        next_offset = Some(next_offset.map_or(candidate, |current| current.max(candidate)));
        let Some(message) = update.message else {
            continue;
        };
        let Some(text) = message.text else {
            continue;
        };
        if message.chat.id == 0
            || message.date <= 0
            || message.from.as_ref().is_some_and(|actor| actor.id == 0)
            || text.chars().count() == 0
            || text.chars().count() > TELEGRAM_MAX_TEXT_CHARS
        {
            return Err(TelegramBoundaryError::InvalidProviderResponse);
        }
        mapped.push(TelegramTextUpdate {
            update_id: update.update_id,
            chat_id: message.chat.id,
            actor_id: message.from.map(|actor| actor.id),
            text,
            occurred_at_unix_seconds: message.date,
        });
    }
    Ok(TelegramUpdateBatch {
        updates: mapped,
        next_offset,
    })
}

const fn map_send_failure(error: TelegramApiFailure) -> BridgeProviderFailure {
    match error {
        TelegramApiFailure::Rejected => not_accepted(BridgeProviderFailureKind::Rejected),
        TelegramApiFailure::RateLimited => not_accepted(BridgeProviderFailureKind::RateLimited),
        TelegramApiFailure::Ambiguous | TelegramApiFailure::MalformedResponse => {
            BridgeProviderFailure::AcceptanceUnknown(BridgeProviderFailureKind::Unavailable)
        }
    }
}

const fn map_poll_failure(error: TelegramApiFailure) -> BridgeProviderFailure {
    match error {
        TelegramApiFailure::RateLimited => not_accepted(BridgeProviderFailureKind::RateLimited),
        TelegramApiFailure::Rejected | TelegramApiFailure::MalformedResponse => {
            not_accepted(BridgeProviderFailureKind::Rejected)
        }
        TelegramApiFailure::Ambiguous => not_accepted(BridgeProviderFailureKind::Unavailable),
    }
}

const fn not_accepted(kind: BridgeProviderFailureKind) -> BridgeProviderFailure {
    BridgeProviderFailure::NotAccepted(kind)
}

#[derive(Debug, Deserialize)]
struct TelegramApiEnvelope<T> {
    ok: bool,
    result: Option<T>,
    error_code: Option<u16>,
}

#[derive(Debug, Serialize)]
struct TelegramSendMessageRequest<'a> {
    chat_id: &'a TelegramChatTarget,
    text: &'a str,
}

#[derive(Debug, Deserialize)]
struct TelegramSendMessageResult {
    message_id: i64,
}

#[derive(Debug, Serialize)]
struct TelegramGetUpdatesRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
    limit: usize,
    timeout: u8,
    allowed_updates: [&'static str; 1],
}

#[derive(Debug, Deserialize)]
struct TelegramUpdateWire {
    update_id: i64,
    message: Option<TelegramMessageWire>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessageWire {
    date: i64,
    chat: TelegramChatWire,
    from: Option<TelegramActorWire>,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChatWire {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TelegramActorWire {
    id: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_debug_never_contains_secret() {
        let token = TelegramBotToken::new("123456:ABC_def-SECRET").expect("token");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "TelegramBotToken(<redacted>)");
        assert!(!rendered.contains("SECRET"));
    }

    #[test]
    fn client_debug_never_contains_bot_token() {
        let token = TelegramBotToken::new("123456:ABC_def-SECRET").expect("token");
        let client = TelegramBotApiClient::new(token);
        let rendered = format!("{client:?}");
        assert!(rendered.contains("TelegramBotToken(<redacted>)"));
        assert!(!rendered.contains("ABC_def-SECRET"));
    }

    #[test]
    fn target_parser_accepts_numeric_and_username_only() {
        assert_eq!(
            TelegramChatTarget::parse(b"-1001234567890").expect("numeric"),
            TelegramChatTarget::Numeric(-1_001_234_567_890)
        );
        assert_eq!(
            TelegramChatTarget::parse(b"@valid_name").expect("username"),
            TelegramChatTarget::Username("@valid_name".to_owned())
        );
        assert!(TelegramChatTarget::parse(b"name without at").is_err());
        assert!(TelegramChatTarget::parse(b"@bad-name").is_err());
    }

    #[test]
    fn update_mapping_advances_over_non_text_without_inventing_event() {
        let batch = map_update_batch(
            vec![
                TelegramUpdateWire {
                    update_id: 40,
                    message: Some(TelegramMessageWire {
                        date: 1_700_000_000,
                        chat: TelegramChatWire { id: -10 },
                        from: Some(TelegramActorWire { id: 7 }),
                        text: Some("hello".to_owned()),
                    }),
                },
                TelegramUpdateWire {
                    update_id: 41,
                    message: None,
                },
            ],
            Some(40),
        )
        .expect("batch");
        assert_eq!(batch.updates.len(), 1);
        assert_eq!(batch.next_offset, Some(42));
        assert_eq!(batch.updates[0].text, "hello");
    }
    #[test]
    fn update_mapping_rejects_zero_actor_identity() {
        let error = map_update_batch(
            vec![TelegramUpdateWire {
                update_id: 50,
                message: Some(TelegramMessageWire {
                    date: 1_700_000_000,
                    chat: TelegramChatWire { id: -10 },
                    from: Some(TelegramActorWire { id: 0 }),
                    text: Some("hello".to_owned()),
                }),
            }],
            Some(50),
        )
        .expect_err("zero actor must fail closed");
        assert_eq!(error, TelegramBoundaryError::InvalidProviderResponse);
    }

    #[test]
    fn token_parser_rejects_path_and_query_injection_material() {
        assert!(TelegramBotToken::new("123456:ABC/def").is_err());
        assert!(TelegramBotToken::new("123456:ABC?def").is_err());
        assert!(TelegramBotToken::new("123456:ABC def").is_err());
    }

    #[test]
    fn http_status_classification_separates_rejection_from_ambiguity() {
        assert_eq!(classify_http_status(200), Ok(()));
        assert_eq!(
            classify_http_status(429),
            Err(TelegramApiFailure::RateLimited)
        );
        assert_eq!(classify_http_status(403), Err(TelegramApiFailure::Rejected));
        assert_eq!(
            classify_http_status(500),
            Err(TelegramApiFailure::Ambiguous)
        );
        assert_eq!(
            classify_http_status(302),
            Err(TelegramApiFailure::Ambiguous)
        );
    }

    #[test]
    fn bounded_body_rejects_provider_response_bombs() {
        let limit = usize::try_from(TELEGRAM_MAX_RESPONSE_BODY_BYTES).expect("body limit");
        let data = vec![b'x'; limit + 1];
        assert_eq!(
            read_bounded_body(&mut data.as_slice()),
            Err(TelegramApiFailure::MalformedResponse)
        );
    }
}

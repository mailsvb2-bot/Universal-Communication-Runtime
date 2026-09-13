#![forbid(unsafe_code)]

use core::fmt;
use std::{collections::BTreeSet, io::Read, sync::Mutex};

use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use ucr_bridge::{BridgeProvider, BridgeProviderFailure, BridgeProviderFailureKind};
use ucr_model::{
    BridgeAction, BridgeCapability, BridgeDataPermission, BridgeEventCursor, BridgeEventPage,
    BridgeInboundEvent, BridgeProviderAcceptance, BridgeProviderManifest, IntegrationId,
    ProtocolVersion, TenantScope,
};
use ucr_protocol::{BRIDGE_SDK_VERSION, MAX_BRIDGE_EVENT_PAGE_ITEMS, validate_bridge_event_page};

pub const VK_PROVIDER_ID: &str = "vendor.vk.api";
pub const VK_API_VERSION: &str = "5.199";
pub const VK_MAX_TEXT_CHARS: usize = 4_096;
const VK_API_ROOT: &str = "https://api.vk.com/method";
const VK_HTTP_TIMEOUT_SECS: u64 = 35;
const VK_LONG_POLL_WAIT_SECS: u8 = 25;
const VK_MAX_RESPONSE_BODY_BYTES: u64 = 4 * 1024 * 1024;
const VK_MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct VkAccessToken(String);

impl VkAccessToken {
    /// Creates bounded VK access-token material without logging or normalization.
    ///
    /// # Errors
    /// Rejects empty, oversized, whitespace/control-containing or non-ASCII credentials.
    pub fn new(value: impl Into<String>) -> Result<Self, VkConfigError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > 4_096 || !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(VkConfigError::InvalidAccessToken);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VkAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VkAccessToken(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VkConfigError {
    InvalidAccessToken,
    InvalidGroupId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VkGroupId(u64);

impl VkGroupId {
    /// Creates a non-zero VK community identifier.
    ///
    /// # Errors
    /// Zero is not a valid configured group identity.
    pub const fn new(value: u64) -> Result<Self, VkConfigError> {
        if value == 0 {
            return Err(VkConfigError::InvalidGroupId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VkPeerTarget(i64);

impl VkPeerTarget {
    /// Parses one opaque canonical bridge target as VK `peer_id`.
    ///
    /// # Errors
    /// Rejects malformed UTF-8, non-integers and zero.
    pub fn parse(value: &[u8]) -> Result<Self, VkBoundaryError> {
        let value = std::str::from_utf8(value).map_err(|_| VkBoundaryError::InvalidTarget)?;
        let peer_id = value
            .parse::<i64>()
            .map_err(|_| VkBoundaryError::InvalidTarget)?;
        if peer_id == 0 {
            return Err(VkBoundaryError::InvalidTarget);
        }
        Ok(Self(peer_id))
    }

    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Debug for VkPeerTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VkPeerTarget(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VkBoundaryError {
    InvalidTarget,
    InvalidText,
    InvalidCursor,
    InvalidLongPollServer,
    InvalidProviderResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VkApiFailure {
    Rejected,
    RateLimited,
    Ambiguous,
    MalformedResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkSentMessage {
    pub message_id: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VkTextEvent {
    pub event_id: String,
    pub peer_id: i64,
    pub actor_id: i64,
    pub text: String,
    pub occurred_at_unix_seconds: i64,
}

impl fmt::Debug for VkTextEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VkTextEvent")
            .field("event_id", &"<opaque>")
            .field("peer_id", &"<opaque>")
            .field("actor_id", &"<opaque>")
            .field("text", &"<redacted>")
            .field("text_len", &self.text.len())
            .field("occurred_at_unix_seconds", &self.occurred_at_unix_seconds)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkEventBatch {
    pub events: Vec<VkTextEvent>,
    pub next_ts: String,
}

pub trait VkApiClient: fmt::Debug + Send + Sync {
    /// Sends plain text through VK `messages.send` semantics.
    ///
    /// `random_id` must remain stable for the same canonical bridge action.
    ///
    /// # Errors
    /// Returns a classified provider failure without exposing credentials/plaintext.
    fn send_text(
        &self,
        target: VkPeerTarget,
        random_id: i32,
        text: &str,
    ) -> Result<VkSentMessage, VkApiFailure>;

    /// Polls one bounded page of `message_new` Long Poll events.
    ///
    /// # Errors
    /// Returns explicit provider/network/response failure.
    fn poll_text_events(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<VkEventBatch, VkApiFailure>;
}

#[derive(Debug, Clone)]
struct VkLongPollSession {
    server: String,
    key: String,
    ts: String,
}

pub struct VkHttpApiClient {
    token: VkAccessToken,
    group_id: VkGroupId,
    long_poll: Mutex<Option<VkLongPollSession>>,
}

impl fmt::Debug for VkHttpApiClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VkHttpApiClient")
            .field("token", &self.token)
            .field("group_id", &"<opaque>")
            .field("api_root", &VK_API_ROOT)
            .field("redirects", &0)
            .finish_non_exhaustive()
    }
}

impl VkHttpApiClient {
    #[must_use]
    pub fn new(token: VkAccessToken, group_id: VkGroupId) -> Self {
        Self {
            token,
            group_id,
            long_poll: Mutex::new(None),
        }
    }

    fn post_api<T: DeserializeOwned>(
        &self,
        method: &str,
        params: &[(&str, String)],
    ) -> Result<T, VkApiFailure> {
        let mut fields = params.to_vec();
        fields.push(("access_token", self.token.expose().to_owned()));
        fields.push(("v", VK_API_VERSION.to_owned()));
        let body = encode_form(&fields);
        let url = format!("{VK_API_ROOT}/{method}");
        let mut response = minreq::post(url)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_timeout(VK_HTTP_TIMEOUT_SECS)
            .with_follow_redirects(false)
            .with_max_headers_size(VK_MAX_RESPONSE_HEADER_BYTES)
            .with_body(body)
            .send_lazy()
            .map_err(|_| VkApiFailure::Ambiguous)?;
        classify_http_status(response.status_code)?;
        let bytes = read_bounded_body(&mut response)?;
        decode_api_envelope(&bytes)
    }

    fn fetch_long_poll_server(&self) -> Result<VkLongPollSession, VkApiFailure> {
        let response: VkLongPollServerWire = self.post_api(
            "groups.getLongPollServer",
            &[("group_id", self.group_id.get().to_string())],
        )?;
        validate_long_poll_server(&response.server).map_err(|_| VkApiFailure::MalformedResponse)?;
        validate_cursor_text(&response.ts).map_err(|_| VkApiFailure::MalformedResponse)?;
        if response.key.is_empty()
            || response.key.len() > 1_024
            || !response.key.as_bytes().iter().all(u8::is_ascii_graphic)
        {
            return Err(VkApiFailure::MalformedResponse);
        }
        Ok(VkLongPollSession {
            server: response.server,
            key: response.key,
            ts: response.ts,
        })
    }

    fn check_long_poll(
        session: &VkLongPollSession,
        ts: &str,
    ) -> Result<VkLongPollWire, VkApiFailure> {
        validate_long_poll_server(&session.server).map_err(|_| VkApiFailure::MalformedResponse)?;
        validate_cursor_text(ts).map_err(|_| VkApiFailure::MalformedResponse)?;
        let fields = [
            ("act", "a_check".to_owned()),
            ("key", session.key.clone()),
            ("ts", ts.to_owned()),
            ("wait", VK_LONG_POLL_WAIT_SECS.to_string()),
        ];
        let body = encode_form(&fields);
        let mut response = minreq::post(&session.server)
            .with_header("content-type", "application/x-www-form-urlencoded")
            .with_timeout(VK_HTTP_TIMEOUT_SECS)
            .with_follow_redirects(false)
            .with_max_headers_size(VK_MAX_RESPONSE_HEADER_BYTES)
            .with_body(body)
            .send_lazy()
            .map_err(|_| VkApiFailure::Ambiguous)?;
        classify_http_status(response.status_code)?;
        let bytes = read_bounded_body(&mut response)?;
        serde_json::from_slice(&bytes).map_err(|_| VkApiFailure::MalformedResponse)
    }
}

impl VkApiClient for VkHttpApiClient {
    fn send_text(
        &self,
        target: VkPeerTarget,
        random_id: i32,
        text: &str,
    ) -> Result<VkSentMessage, VkApiFailure> {
        let message_id: i64 = self.post_api(
            "messages.send",
            &[
                ("peer_id", target.get().to_string()),
                ("random_id", random_id.to_string()),
                ("message", text.to_owned()),
            ],
        )?;
        if message_id <= 0 {
            return Err(VkApiFailure::MalformedResponse);
        }
        Ok(VkSentMessage { message_id })
    }

    fn poll_text_events(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<VkEventBatch, VkApiFailure> {
        if limit == 0 || limit > MAX_BRIDGE_EVENT_PAGE_ITEMS {
            return Err(VkApiFailure::Rejected);
        }
        if let Some(cursor) = cursor {
            validate_cursor_text(cursor).map_err(|_| VkApiFailure::Rejected)?;
        }

        let mut guard = self.long_poll.lock().map_err(|_| VkApiFailure::Ambiguous)?;
        if guard.is_none() {
            *guard = Some(self.fetch_long_poll_server()?);
        }
        let session = guard.as_ref().ok_or(VkApiFailure::Ambiguous)?;
        let requested_ts = cursor.unwrap_or(&session.ts).to_owned();
        let wire = Self::check_long_poll(session, &requested_ts)?;

        if let Some(failed) = wire.failed {
            match failed {
                1 => {
                    let ts = wire.ts.ok_or(VkApiFailure::MalformedResponse)?;
                    validate_cursor_text(&ts).map_err(|_| VkApiFailure::MalformedResponse)?;
                    if let Some(session) = guard.as_mut() {
                        session.ts.clone_from(&ts);
                    }
                    return Ok(VkEventBatch {
                        events: vec![],
                        next_ts: ts,
                    });
                }
                2..=4 => {
                    *guard = None;
                    return Err(VkApiFailure::Ambiguous);
                }
                _ => return Err(VkApiFailure::MalformedResponse),
            }
        }

        let ts = wire.ts.ok_or(VkApiFailure::MalformedResponse)?;
        validate_cursor_text(&ts).map_err(|_| VkApiFailure::MalformedResponse)?;
        let events = map_long_poll_updates(wire.updates, limit)?;
        if let Some(session) = guard.as_mut() {
            session.ts.clone_from(&ts);
        }
        Ok(VkEventBatch {
            events,
            next_ts: ts,
        })
    }
}

pub struct VkProvider<C> {
    client: C,
}

impl<C> fmt::Debug for VkProvider<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VkProvider")
            .field("provider_id", &VK_PROVIDER_ID)
            .finish_non_exhaustive()
    }
}

impl<C> VkProvider<C> {
    #[must_use]
    pub const fn new(client: C) -> Self {
        Self { client }
    }

    #[must_use]
    pub const fn client(&self) -> &C {
        &self.client
    }
}

impl<C> BridgeProvider for VkProvider<C>
where
    C: VkApiClient,
{
    fn manifest(&self) -> BridgeProviderManifest {
        BridgeProviderManifest {
            provider_id: VK_PROVIDER_ID.to_owned(),
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
        let target = VkPeerTarget::parse(&action.external_target)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let text = validate_text(&action.provider_payload)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let random_id = stable_random_id(action, target);
        let result = self
            .client
            .send_text(target, random_id, text)
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
        let cursor =
            parse_cursor(cursor).map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        let batch = self
            .client
            .poll_text_events(cursor, limit)
            .map_err(map_poll_failure)?;
        validate_cursor_text(&batch.next_ts)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        if batch.events.len() > limit {
            return Err(not_accepted(BridgeProviderFailureKind::Rejected));
        }
        let mut events = Vec::with_capacity(batch.events.len());
        for event in batch.events {
            events.push(BridgeInboundEvent {
                scope: scope.clone(),
                integration_id: integration_id.clone(),
                external_event_id: event.event_id.into_bytes(),
                external_conversation_id: event.peer_id.to_string().into_bytes(),
                external_actor_id: Some(event.actor_id.to_string().into_bytes()),
                capability: BridgeCapability::Text,
                payload: event.text.into_bytes(),
                occurred_at_unix_ms: event
                    .occurred_at_unix_seconds
                    .checked_mul(1_000)
                    .ok_or_else(|| not_accepted(BridgeProviderFailureKind::Rejected))?,
            });
        }
        let page = BridgeEventPage {
            events,
            next_cursor: Some(BridgeEventCursor {
                token: batch.next_ts.into_bytes(),
            }),
        };
        validate_bridge_event_page(&page)
            .map_err(|_| not_accepted(BridgeProviderFailureKind::Rejected))?;
        Ok(page)
    }
}

fn stable_random_id(action: &BridgeAction, target: VkPeerTarget) -> i32 {
    let mut hasher = Sha256::new();
    hasher.update(b"ucr-vk-random-id-v1");
    hash_component(
        &mut hasher,
        action.scope.tenant_id.as_opaque().as_wire_bytes(),
    );
    match &action.scope.namespace_id {
        Some(namespace_id) => {
            hasher.update([1]);
            hash_component(&mut hasher, namespace_id.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
    hash_component(
        &mut hasher,
        action.integration_id.as_opaque().as_wire_bytes(),
    );
    hash_component(&mut hasher, action.action_id.as_opaque().as_wire_bytes());
    hasher.update(target.0.to_be_bytes());
    let digest = hasher.finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) & 0x7fff_ffff;
    i32::try_from(value.max(1)).expect("masked VK random_id fits i32")
}

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("canonical component length fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

fn validate_text(payload: &[u8]) -> Result<&str, VkBoundaryError> {
    let text = std::str::from_utf8(payload).map_err(|_| VkBoundaryError::InvalidText)?;
    let count = text.chars().count();
    if count == 0 || count > VK_MAX_TEXT_CHARS {
        return Err(VkBoundaryError::InvalidText);
    }
    Ok(text)
}

fn parse_cursor(cursor: Option<&BridgeEventCursor>) -> Result<Option<&str>, VkBoundaryError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&cursor.token).map_err(|_| VkBoundaryError::InvalidCursor)?;
    validate_cursor_text(text)?;
    Ok(Some(text))
}

fn validate_cursor_text(value: &str) -> Result<(), VkBoundaryError> {
    if value.is_empty() || value.len() > 64 || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(VkBoundaryError::InvalidCursor);
    }
    Ok(())
}

fn validate_long_poll_server(value: &str) -> Result<(), VkBoundaryError> {
    if value.len() > 2_048
        || !value.starts_with("https://")
        || value.contains('@')
        || value.contains('#')
        || value.as_bytes().iter().any(u8::is_ascii_control)
    {
        return Err(VkBoundaryError::InvalidLongPollServer);
    }
    let authority = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .ok_or(VkBoundaryError::InvalidLongPollServer)?;
    let host = authority.split(':').next().unwrap_or_default();
    if host != "vk.com" && !host.ends_with(".vk.com") {
        return Err(VkBoundaryError::InvalidLongPollServer);
    }
    Ok(())
}

fn map_long_poll_updates(
    updates: Vec<VkUpdateWire>,
    limit: usize,
) -> Result<Vec<VkTextEvent>, VkApiFailure> {
    let mut seen = BTreeSet::new();
    let mut mapped = Vec::new();
    for update in updates {
        if update.kind != "message_new" {
            continue;
        }
        let object = update.object.ok_or(VkApiFailure::MalformedResponse)?;
        let message = object.message.ok_or(VkApiFailure::MalformedResponse)?;
        if message.id <= 0
            || message.peer_id == 0
            || message.from_id == 0
            || message.date <= 0
            || message.text.is_empty()
            || message.text.chars().count() > VK_MAX_TEXT_CHARS
        {
            return Err(VkApiFailure::MalformedResponse);
        }
        let event_id = update
            .event_id
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .unwrap_or_else(|| format!("message_new:{}:{}", message.peer_id, message.id));
        if !seen.insert(event_id.clone()) {
            return Err(VkApiFailure::MalformedResponse);
        }
        mapped.push(VkTextEvent {
            event_id,
            peer_id: message.peer_id,
            actor_id: message.from_id,
            text: message.text,
            occurred_at_unix_seconds: message.date,
        });
        if mapped.len() > limit {
            return Err(VkApiFailure::MalformedResponse);
        }
    }
    Ok(mapped)
}

fn classify_http_status(status: u16) -> Result<(), VkApiFailure> {
    match status {
        200..=299 => Ok(()),
        429 => Err(VkApiFailure::RateLimited),
        400..=499 => Err(VkApiFailure::Rejected),
        _ => Err(VkApiFailure::Ambiguous),
    }
}

fn read_bounded_body(reader: &mut impl Read) -> Result<Vec<u8>, VkApiFailure> {
    let mut bytes = Vec::new();
    reader
        .take(VK_MAX_RESPONSE_BODY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VkApiFailure::Ambiguous)?;
    if bytes.len() as u64 > VK_MAX_RESPONSE_BODY_BYTES {
        return Err(VkApiFailure::MalformedResponse);
    }
    Ok(bytes)
}

fn decode_api_envelope<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, VkApiFailure> {
    let envelope = serde_json::from_slice::<VkApiEnvelope<T>>(bytes)
        .map_err(|_| VkApiFailure::MalformedResponse)?;
    if let Some(error) = envelope.error {
        return Err(match error.error_code {
            6 | 9 | 29 => VkApiFailure::RateLimited,
            _ => VkApiFailure::Rejected,
        });
    }
    envelope.response.ok_or(VkApiFailure::MalformedResponse)
}

fn encode_form(fields: &[(&str, String)]) -> Vec<u8> {
    let mut body = String::new();
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            body.push('&');
        }
        push_form_component(&mut body, key);
        body.push('=');
        push_form_component(&mut body, value);
    }
    body.into_bytes()
}

fn push_form_component(target: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                target.push(char::from(byte));
            }
            b' ' => target.push('+'),
            _ => {
                target.push('%');
                target.push(char::from(HEX[usize::from(byte >> 4)]));
                target.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
}

const fn map_send_failure(error: VkApiFailure) -> BridgeProviderFailure {
    match error {
        VkApiFailure::Rejected => not_accepted(BridgeProviderFailureKind::Rejected),
        VkApiFailure::RateLimited => not_accepted(BridgeProviderFailureKind::RateLimited),
        VkApiFailure::Ambiguous | VkApiFailure::MalformedResponse => {
            BridgeProviderFailure::AcceptanceUnknown(BridgeProviderFailureKind::Unavailable)
        }
    }
}

const fn map_poll_failure(error: VkApiFailure) -> BridgeProviderFailure {
    match error {
        VkApiFailure::Rejected => not_accepted(BridgeProviderFailureKind::Rejected),
        VkApiFailure::RateLimited => not_accepted(BridgeProviderFailureKind::RateLimited),
        VkApiFailure::Ambiguous | VkApiFailure::MalformedResponse => {
            not_accepted(BridgeProviderFailureKind::Unavailable)
        }
    }
}

const fn not_accepted(kind: BridgeProviderFailureKind) -> BridgeProviderFailure {
    BridgeProviderFailure::NotAccepted(kind)
}

#[derive(Debug, Deserialize)]
struct VkApiEnvelope<T> {
    response: Option<T>,
    error: Option<VkApiErrorWire>,
}

#[derive(Debug, Deserialize)]
struct VkApiErrorWire {
    error_code: i64,
}

#[derive(Debug, Deserialize)]
struct VkLongPollServerWire {
    key: String,
    server: String,
    ts: String,
}

#[derive(Debug, Deserialize)]
struct VkLongPollWire {
    ts: Option<String>,
    #[serde(default)]
    updates: Vec<VkUpdateWire>,
    failed: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct VkUpdateWire {
    #[serde(rename = "type")]
    kind: String,
    object: Option<VkUpdateObjectWire>,
    event_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VkUpdateObjectWire {
    message: Option<VkMessageWire>,
}

#[derive(Debug, Deserialize)]
struct VkMessageWire {
    id: i64,
    date: i64,
    peer_id: i64,
    from_id: i64,
    text: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{BridgeActionId, CorrelationContext, OpaqueId};

    fn action(id: &str) -> BridgeAction {
        BridgeAction {
            action_id: BridgeActionId::from_opaque(OpaqueId::new(id).expect("id")),
            scope: TenantScope {
                tenant_id: ucr_model::TenantId::from_opaque(OpaqueId::new("tenant").expect("id")),
                namespace_id: None,
            },
            integration_id: IntegrationId::from_opaque(OpaqueId::new("integration").expect("id")),
            capability: BridgeCapability::Text,
            external_target: b"2000000001".to_vec(),
            canonical_message_id: Some(ucr_model::MessageId::from_opaque(
                OpaqueId::new("message").expect("id"),
            )),
            provider_payload: b"hello".to_vec(),
            attachment_ids: vec![],
            correlation: CorrelationContext {
                correlation_id: OpaqueId::new("correlation").expect("id"),
                causation_id: None,
                idempotency_key: Some("idem".to_owned()),
            },
        }
    }

    #[test]
    fn token_debug_never_contains_secret() {
        let token = VkAccessToken::new("vk1.secret-token_ABC").expect("token");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "VkAccessToken(<redacted>)");
        assert!(!rendered.contains("secret-token"));
    }

    #[test]
    fn stable_random_id_is_action_stable_and_context_bound() {
        let target = VkPeerTarget(2_000_000_001);
        let first = stable_random_id(&action("action-one"), target);
        assert_eq!(first, stable_random_id(&action("action-one"), target));
        assert_ne!(first, 0);
        assert_ne!(first, stable_random_id(&action("action-two"), target));
        assert_ne!(
            first,
            stable_random_id(&action("action-one"), VkPeerTarget(2_000_000_002))
        );

        let mut other_integration = action("action-one");
        other_integration.integration_id =
            IntegrationId::from_opaque(OpaqueId::new("other-integration").expect("id"));
        assert_ne!(first, stable_random_id(&other_integration, target));
    }

    #[test]
    fn form_encoding_does_not_allow_parameter_injection() {
        let body = String::from_utf8(encode_form(&[(
            "message",
            "x&access_token=evil + ok".to_owned(),
        )]))
        .expect("utf8");
        assert_eq!(body, "message=x%26access_token%3Devil+%2B+ok");
    }

    #[test]
    fn long_poll_server_is_https_and_vk_scoped() {
        assert!(validate_long_poll_server("https://lp.vk.com/wh123").is_ok());
        assert!(validate_long_poll_server("http://lp.vk.com/wh123").is_err());
        assert!(validate_long_poll_server("https://evil.example/wh123").is_err());
        assert!(validate_long_poll_server("https://vk.com@evil.example/wh123").is_err());
    }

    #[test]
    fn api_error_classification_separates_rate_limit() {
        assert_eq!(
            decode_api_envelope::<i64>(br#"{"error":{"error_code":6}}"#),
            Err(VkApiFailure::RateLimited)
        );
        assert_eq!(
            decode_api_envelope::<i64>(br#"{"error":{"error_code":5}}"#),
            Err(VkApiFailure::Rejected)
        );
    }

    #[test]
    fn response_body_is_bounded() {
        let limit = usize::try_from(VK_MAX_RESPONSE_BODY_BYTES).expect("limit");
        let data = vec![b'x'; limit + 1];
        assert_eq!(
            read_bounded_body(&mut data.as_slice()),
            Err(VkApiFailure::MalformedResponse)
        );
    }
}

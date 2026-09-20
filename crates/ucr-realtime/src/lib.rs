#![forbid(unsafe_code)]

use core::fmt;
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use ucr_core::generate_opaque_id;
use ucr_model::{
    CallId, DeviceId, NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, SessionId,
    SfuForwardEnvelope, TenantId, TenantScope,
};
use ucr_sfu::{SfuForwardSink, SfuForwardSinkError};

pub const MIN_JOIN_TTL_SECONDS: u32 = 30;
pub const MAX_JOIN_TTL_SECONDS: u32 = 900;
pub const DEFAULT_JOIN_TTL_SECONDS: u32 = 300;
pub const DEFAULT_REALTIME_QUEUE_CAPACITY: usize = 64;
pub const MAX_REALTIME_SESSIONS: usize = 4096;
pub const MAX_JOIN_GRANTS: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinGrantUsePolicy {
    SingleUse,
    Reusable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct JoinTokenKey([u8; 32]);

impl JoinTokenKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for JoinTokenKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("JoinTokenKey")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeSessionClaims {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub participant: PrincipalRef,
    pub device_id: Option<DeviceId>,
    pub session_id: SessionId,
    pub issued_at_unix_ms: i64,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub use_policy: JoinGrantUsePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedJoinGrant {
    pub claims: RealtimeSessionClaims,
    pub join_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinTokenError {
    InvalidBaseUrl,
    InvalidTtl,
    InvalidWindow,
    ClockOverflow,
    RandomUnavailable,
    Malformed,
    InvalidSignature,
    NotYetValid,
    Expired,
    UnknownGrant,
    Revoked,
    AlreadyUsed,
    CapacityExceeded,
    StateUnavailable,
    Internal,
}

#[derive(Debug, Clone)]
pub struct JoinTokenIssuer {
    key: JoinTokenKey,
    join_base_url: String,
    grants: Arc<Mutex<Vec<JoinGrantState>>>,
}

#[derive(Debug, Clone)]
struct JoinGrantState {
    claims: RealtimeSessionClaims,
    revoked: bool,
    redeemed: bool,
}

impl JoinTokenIssuer {
    /// Creates an issuer for one HTTPS browser/native join entrypoint.
    ///
    /// # Errors
    /// Rejects non-HTTPS, fragment-bearing, or whitespace-bearing base URLs.
    pub fn new(
        key: JoinTokenKey,
        join_base_url: impl Into<String>,
    ) -> Result<Self, JoinTokenError> {
        let join_base_url = join_base_url.into();
        if !join_base_url.starts_with("https://")
            || join_base_url.contains('#')
            || join_base_url.chars().any(char::is_whitespace)
        {
            return Err(JoinTokenError::InvalidBaseUrl);
        }
        Ok(Self {
            key,
            join_base_url,
            grants: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Issues one short-lived reusable session grant.
    ///
    /// # Errors
    /// Rejects invalid TTL, clock overflow, random failure, or exhausted bounded grant state.
    pub fn issue(
        &self,
        scope: TenantScope,
        call_id: CallId,
        participant: PrincipalRef,
        device_id: Option<DeviceId>,
        ttl_seconds: u32,
        now_unix_ms: i64,
    ) -> Result<IssuedJoinGrant, JoinTokenError> {
        self.issue_with_policy(
            scope,
            call_id,
            participant,
            device_id,
            ttl_seconds,
            JoinGrantUsePolicy::Reusable,
            None,
            None,
            now_unix_ms,
        )
    }

    /// Issues one bounded grant with explicit use and validity policy.
    ///
    /// Explicit bounds may only narrow the TTL window; they can never extend it.
    ///
    /// # Errors
    /// Rejects invalid time windows, TTL, exhausted state, clock overflow, or random failure.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_policy(
        &self,
        scope: TenantScope,
        call_id: CallId,
        participant: PrincipalRef,
        device_id: Option<DeviceId>,
        ttl_seconds: u32,
        use_policy: JoinGrantUsePolicy,
        not_before_unix_ms: Option<i64>,
        not_after_unix_ms: Option<i64>,
        now_unix_ms: i64,
    ) -> Result<IssuedJoinGrant, JoinTokenError> {
        if !(MIN_JOIN_TTL_SECONDS..=MAX_JOIN_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(JoinTokenError::InvalidTtl);
        }
        let ttl_ms = i64::from(ttl_seconds)
            .checked_mul(1000)
            .ok_or(JoinTokenError::ClockOverflow)?;
        let maximum_expiry = now_unix_ms
            .checked_add(ttl_ms)
            .ok_or(JoinTokenError::ClockOverflow)?;
        let not_before_unix_ms = not_before_unix_ms.unwrap_or(now_unix_ms);
        let expires_at_unix_ms = not_after_unix_ms.unwrap_or(maximum_expiry);
        let minimum_expiry = now_unix_ms
            .checked_add(i64::from(MIN_JOIN_TTL_SECONDS) * 1000)
            .ok_or(JoinTokenError::ClockOverflow)?;
        if not_before_unix_ms < now_unix_ms
            || not_before_unix_ms >= expires_at_unix_ms
            || expires_at_unix_ms < minimum_expiry
            || expires_at_unix_ms > maximum_expiry
        {
            return Err(JoinTokenError::InvalidWindow);
        }
        let session_id = SessionId::from_opaque(
            generate_opaque_id().map_err(|_| JoinTokenError::RandomUnavailable)?,
        );
        let claims = RealtimeSessionClaims {
            scope,
            call_id,
            participant,
            device_id,
            session_id,
            issued_at_unix_ms: now_unix_ms,
            not_before_unix_ms,
            expires_at_unix_ms,
            use_policy,
        };
        let token = self.sign(&claims)?;
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| JoinTokenError::StateUnavailable)?;
        grants.retain(|entry| now_unix_ms < entry.claims.expires_at_unix_ms);
        if grants.len() >= MAX_JOIN_GRANTS {
            return Err(JoinTokenError::CapacityExceeded);
        }
        grants.push(JoinGrantState {
            claims: claims.clone(),
            revoked: false,
            redeemed: false,
        });
        Ok(IssuedJoinGrant {
            join_url: format!("{}#ucr_join={token}", self.join_base_url),
            claims,
        })
    }

    /// Issues a grant for a caller-supplied stable session ID without storing control state
    /// in the in-memory compatibility registry. Durable callers persist the claims separately.
    ///
    /// # Errors
    /// Rejects invalid TTL/window values or signing failures.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_session_id(
        &self,
        scope: TenantScope,
        call_id: CallId,
        participant: PrincipalRef,
        device_id: Option<DeviceId>,
        session_id: SessionId,
        ttl_seconds: u32,
        use_policy: JoinGrantUsePolicy,
        not_before_unix_ms: Option<i64>,
        not_after_unix_ms: Option<i64>,
        now_unix_ms: i64,
    ) -> Result<IssuedJoinGrant, JoinTokenError> {
        if !(MIN_JOIN_TTL_SECONDS..=MAX_JOIN_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(JoinTokenError::InvalidTtl);
        }
        let ttl_ms = i64::from(ttl_seconds)
            .checked_mul(1000)
            .ok_or(JoinTokenError::ClockOverflow)?;
        let maximum_expiry = now_unix_ms
            .checked_add(ttl_ms)
            .ok_or(JoinTokenError::ClockOverflow)?;
        let not_before_unix_ms = not_before_unix_ms.unwrap_or(now_unix_ms);
        let expires_at_unix_ms = not_after_unix_ms.unwrap_or(maximum_expiry);
        let minimum_expiry = now_unix_ms
            .checked_add(i64::from(MIN_JOIN_TTL_SECONDS) * 1000)
            .ok_or(JoinTokenError::ClockOverflow)?;
        if not_before_unix_ms < now_unix_ms
            || not_before_unix_ms >= expires_at_unix_ms
            || expires_at_unix_ms < minimum_expiry
            || expires_at_unix_ms > maximum_expiry
        {
            return Err(JoinTokenError::InvalidWindow);
        }
        let claims = RealtimeSessionClaims {
            scope,
            call_id,
            participant,
            device_id,
            session_id,
            issued_at_unix_ms: now_unix_ms,
            not_before_unix_ms,
            expires_at_unix_ms,
            use_policy,
        };
        self.signed_grant_for_claims(&claims)
    }

    /// Recreates the exact signed URL for already-durable claims without changing grant state.
    ///
    /// # Errors
    /// Returns a signing failure for malformed internal state.
    pub fn signed_grant_for_claims(
        &self,
        claims: &RealtimeSessionClaims,
    ) -> Result<IssuedJoinGrant, JoinTokenError> {
        let token = self.sign(claims)?;
        Ok(IssuedJoinGrant {
            join_url: format!("{}#ucr_join={token}", self.join_base_url),
            claims: claims.clone(),
        })
    }

    /// Verifies only cryptographic and temporal token claims.
    ///
    /// Durable callers separately check canonical grant control state.
    ///
    /// # Errors
    /// Rejects malformed, tampered, not-yet-valid or expired tokens.
    pub fn verify_signed_claims(
        &self,
        token: &str,
        now_unix_ms: i64,
    ) -> Result<RealtimeSessionClaims, JoinTokenError> {
        self.verify_signed(token, now_unix_ms)
    }

    /// Verifies signature and temporal validity and returns the exact signed claims.
    ///
    /// # Errors
    /// Rejects malformed/tampered tokens and grants that are not currently valid.
    pub fn verify(
        &self,
        token: &str,
        now_unix_ms: i64,
    ) -> Result<RealtimeSessionClaims, JoinTokenError> {
        let claims = self.verify_signed(token, now_unix_ms)?;
        self.require_live_grant(&claims)?;
        Ok(claims)
    }

    /// Redeems a grant for a realtime join.
    ///
    /// Reusable grants may be redeemed again for reconnect. Single-use grants reject a second
    /// join while remaining valid for the already-open session's heartbeat and media requests.
    ///
    /// # Errors
    /// Returns signature, time, state, revocation, or already-used errors.
    pub fn redeem(
        &self,
        token: &str,
        now_unix_ms: i64,
    ) -> Result<RealtimeSessionClaims, JoinTokenError> {
        let claims = self.verify_signed(token, now_unix_ms)?;
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| JoinTokenError::StateUnavailable)?;
        let entry = grants
            .iter_mut()
            .find(|entry| entry.claims.session_id == claims.session_id)
            .ok_or(JoinTokenError::UnknownGrant)?;
        if entry.claims != claims {
            return Err(JoinTokenError::Malformed);
        }
        if entry.revoked {
            return Err(JoinTokenError::Revoked);
        }
        if entry.claims.use_policy == JoinGrantUsePolicy::SingleUse && entry.redeemed {
            return Err(JoinTokenError::AlreadyUsed);
        }
        entry.redeemed = true;
        Ok(claims)
    }

    /// Returns immutable claims for one exact scoped controlled grant.
    ///
    /// # Errors
    /// Returns unavailable state if the bounded control registry is poisoned.
    pub fn grant_claims(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<Option<RealtimeSessionClaims>, JoinTokenError> {
        let grants = self
            .grants
            .lock()
            .map_err(|_| JoinTokenError::StateUnavailable)?;
        Ok(grants
            .iter()
            .find(|entry| entry.claims.scope == *scope && entry.claims.session_id == *session_id)
            .map(|entry| entry.claims.clone()))
    }

    /// Revokes one exact scoped grant. Repeating the same revocation is idempotent.
    ///
    /// # Errors
    /// Returns `UnknownGrant` or unavailable control state.
    pub fn revoke(
        &self,
        scope: &TenantScope,
        session_id: &SessionId,
    ) -> Result<RealtimeSessionClaims, JoinTokenError> {
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| JoinTokenError::StateUnavailable)?;
        let entry = grants
            .iter_mut()
            .find(|entry| entry.claims.scope == *scope && entry.claims.session_id == *session_id)
            .ok_or(JoinTokenError::UnknownGrant)?;
        entry.revoked = true;
        Ok(entry.claims.clone())
    }

    fn verify_signed(
        &self,
        token: &str,
        now_unix_ms: i64,
    ) -> Result<RealtimeSessionClaims, JoinTokenError> {
        let (payload_text, signature_text) =
            token.split_once('.').ok_or(JoinTokenError::Malformed)?;
        if signature_text.contains('.') {
            return Err(JoinTokenError::Malformed);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_text)
            .map_err(|_| JoinTokenError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_text)
            .map_err(|_| JoinTokenError::Malformed)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key.0).map_err(|_| JoinTokenError::Internal)?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| JoinTokenError::InvalidSignature)?;
        let claims = decode_claims(&payload)?;
        if claims.not_before_unix_ms < claims.issued_at_unix_ms
            || claims.not_before_unix_ms >= claims.expires_at_unix_ms
        {
            return Err(JoinTokenError::Malformed);
        }
        if now_unix_ms < claims.not_before_unix_ms {
            return Err(JoinTokenError::NotYetValid);
        }
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(JoinTokenError::Expired);
        }
        let maximum_lifetime_ms = i64::from(MAX_JOIN_TTL_SECONDS) * 1000;
        let lifetime = claims
            .expires_at_unix_ms
            .checked_sub(claims.issued_at_unix_ms)
            .ok_or(JoinTokenError::Malformed)?;
        if lifetime < i64::from(MIN_JOIN_TTL_SECONDS) * 1000 || lifetime > maximum_lifetime_ms {
            return Err(JoinTokenError::Malformed);
        }
        Ok(claims)
    }

    fn require_live_grant(&self, claims: &RealtimeSessionClaims) -> Result<(), JoinTokenError> {
        let grants = self
            .grants
            .lock()
            .map_err(|_| JoinTokenError::StateUnavailable)?;
        let entry = grants
            .iter()
            .find(|entry| entry.claims.session_id == claims.session_id)
            .ok_or(JoinTokenError::UnknownGrant)?;
        if entry.claims != *claims {
            return Err(JoinTokenError::Malformed);
        }
        if entry.revoked {
            return Err(JoinTokenError::Revoked);
        }
        Ok(())
    }

    fn sign(&self, claims: &RealtimeSessionClaims) -> Result<String, JoinTokenError> {
        let payload = encode_claims(claims)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key.0).map_err(|_| JoinTokenError::Internal)?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttendanceTransitionKind {
    Joined,
    Left,
    Reconnected,
    MediaReady,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttendanceTransition {
    pub kind: AttendanceTransitionKind,
    pub claims: RealtimeSessionClaims,
    pub session_sequence: u64,
    pub occurred_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealtimeRegistryError {
    Expired,
    CapacityExceeded,
    ClaimMismatch,
    SessionUnavailable,
    SequenceOverflow,
}

struct SessionEntry {
    claims: RealtimeSessionClaims,
    sender: mpsc::Sender<SfuForwardEnvelope>,
    receiver: Option<mpsc::Receiver<SfuForwardEnvelope>>,
    sequence: u64,
    media_ready: bool,
}

impl fmt::Debug for SessionEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionEntry")
            .field("claims", &self.claims)
            .field("sequence", &self.sequence)
            .field("media_ready", &self.media_ready)
            .field("queue_capacity", &self.sender.capacity())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct RealtimeSessionRegistry {
    entries: Mutex<Vec<SessionEntry>>,
    max_sessions: usize,
    queue_capacity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeJoinOutcome {
    pub claims: RealtimeSessionClaims,
    pub transition: AttendanceTransition,
}

pub struct RealtimeDownlinkAttachment {
    pub receiver: mpsc::Receiver<SfuForwardEnvelope>,
    pub transition: Option<AttendanceTransition>,
}

impl Default for RealtimeSessionRegistry {
    fn default() -> Self {
        Self::new(MAX_REALTIME_SESSIONS, DEFAULT_REALTIME_QUEUE_CAPACITY)
    }
}

impl RealtimeSessionRegistry {
    #[must_use]
    pub const fn new(max_sessions: usize, queue_capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            max_sessions,
            queue_capacity,
        }
    }

    /// Opens or reconnects the exact signed session. Reconnect replaces the old downlink sender,
    /// causing the prior receiver to close rather than keeping two consumers for one session ID.
    ///
    /// # Errors
    /// Fails for expired claims, a changed claim set reusing a session ID, exhausted bounded state,
    /// poisoned state, or sequence overflow.
    pub fn join(
        &self,
        claims: RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<RealtimeJoinOutcome, RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        if self.max_sessions == 0 || self.queue_capacity == 0 {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        prune_expired(&mut entries, now_unix_ms);
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| same_session(entry, &claims))
        {
            if entry.claims != claims {
                return Err(RealtimeRegistryError::ClaimMismatch);
            }
            entry.sequence = entry
                .sequence
                .checked_add(1)
                .ok_or(RealtimeRegistryError::SequenceOverflow)?;
            entry.media_ready = false;
            let (sender, receiver) = mpsc::channel(self.queue_capacity);
            entry.sender = sender;
            entry.receiver = Some(receiver);
            let transition = AttendanceTransition {
                kind: AttendanceTransitionKind::Reconnected,
                claims: claims.clone(),
                session_sequence: entry.sequence,
                occurred_at_unix_ms: now_unix_ms,
            };
            return Ok(RealtimeJoinOutcome { claims, transition });
        }
        if entries.len() >= self.max_sessions {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        let (sender, receiver) = mpsc::channel(self.queue_capacity);
        let transition = AttendanceTransition {
            kind: AttendanceTransitionKind::Joined,
            claims: claims.clone(),
            session_sequence: 1,
            occurred_at_unix_ms: now_unix_ms,
        };
        entries.push(SessionEntry {
            claims: claims.clone(),
            sender,
            receiver: Some(receiver),
            sequence: 1,
            media_ready: false,
        });
        Ok(RealtimeJoinOutcome { claims, transition })
    }

    /// Attaches the one downlink consumer for the current connection.
    ///
    /// The first attachment consumes the prepared receiver. If that receiver was later dropped by
    /// a broken browser/network stream, the exact authenticated session may attach a fresh bounded
    /// queue without redeeming its join grant a second time. A still-live receiver remains
    /// single-consumer and rejects a competing attachment.
    ///
    /// # Errors
    /// Fails for expiry, claim mismatch, missing session/downlink, unavailable state, or sequence
    /// overflow.
    pub fn attach_downlink(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<RealtimeDownlinkAttachment, RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        prune_expired(&mut entries, now_unix_ms);
        let entry = entries
            .iter_mut()
            .find(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entry.claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        if let Some(receiver) = entry.receiver.take() {
            return Ok(RealtimeDownlinkAttachment {
                receiver,
                transition: None,
            });
        }
        if !entry.sender.is_closed() {
            return Err(RealtimeRegistryError::SessionUnavailable);
        }

        entry.sequence = entry
            .sequence
            .checked_add(1)
            .ok_or(RealtimeRegistryError::SequenceOverflow)?;
        entry.media_ready = false;
        let (sender, receiver) = mpsc::channel(self.queue_capacity);
        entry.sender = sender;
        let transition = AttendanceTransition {
            kind: AttendanceTransitionKind::Reconnected,
            claims: claims.clone(),
            session_sequence: entry.sequence,
            occurred_at_unix_ms: now_unix_ms,
        };
        Ok(RealtimeDownlinkAttachment {
            receiver,
            transition: Some(transition),
        })
    }

    /// Compatibility helper for internal callers that do not consume attendance transitions.
    ///
    /// # Errors
    /// Returns the same bounded registry failures as attach_downlink.
    pub fn take_downlink(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<mpsc::Receiver<SfuForwardEnvelope>, RealtimeRegistryError> {
        self.attach_downlink(claims, now_unix_ms)
            .map(|attachment| attachment.receiver)
    }

    /// Verifies liveness for the exact session and returns its current attendance sequence.
    ///
    /// # Errors
    /// Fails for expiry, claim mismatch, missing session, or unavailable state.
    pub fn heartbeat(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<u64, RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        prune_expired(&mut entries, now_unix_ms);
        let entry = entries
            .iter()
            .find(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entry.claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        Ok(entry.sequence)
    }

    /// Marks the first media-ready transition for the current connection.
    ///
    /// # Errors
    /// Fails for expiry, claim mismatch, missing state, unavailable state, or sequence overflow.
    pub fn mark_media_ready(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<Option<AttendanceTransition>, RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        prune_expired(&mut entries, now_unix_ms);
        let entry = entries
            .iter_mut()
            .find(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entry.claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        if entry.media_ready {
            return Ok(None);
        }
        entry.media_ready = true;
        entry.sequence = entry
            .sequence
            .checked_add(1)
            .ok_or(RealtimeRegistryError::SequenceOverflow)?;
        Ok(Some(AttendanceTransition {
            kind: AttendanceTransitionKind::MediaReady,
            claims: claims.clone(),
            session_sequence: entry.sequence,
            occurred_at_unix_ms: now_unix_ms,
        }))
    }

    /// Removes the exact session and returns its durable-attendance transition data.
    ///
    /// # Errors
    /// Fails for claim mismatch, missing session, unavailable state, or sequence overflow.
    pub fn leave(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<AttendanceTransition, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        let index = entries
            .iter()
            .position(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entries[index].claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        let entry = entries.remove(index);
        let sequence = entry
            .sequence
            .checked_add(1)
            .ok_or(RealtimeRegistryError::SequenceOverflow)?;
        Ok(AttendanceTransition {
            kind: AttendanceTransitionKind::Left,
            claims: claims.clone(),
            session_sequence: sequence,
            occurred_at_unix_ms: now_unix_ms,
        })
    }

    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }
}

impl SfuForwardSink for RealtimeSessionRegistry {
    fn forward_encrypted(
        &self,
        target: &ucr_model::SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let now_unix_ms = system_now_unix_ms().ok_or(SfuForwardSinkError::Unavailable)?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| SfuForwardSinkError::Unavailable)?;
        prune_expired(&mut entries, now_unix_ms);

        let matching = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.claims.scope == envelope.frame.header.scope
                    && entry.claims.call_id == envelope.frame.header.call_id
                    && entry.claims.participant == target.recipient
                    && !entry.sender.is_closed()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(SfuForwardSinkError::Unavailable);
        }
        if matching
            .iter()
            .any(|index| entries[*index].sender.capacity() == 0)
        {
            return Err(SfuForwardSinkError::Backpressure);
        }

        for index in matching {
            entries[index]
                .sender
                .try_send(envelope.clone())
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => SfuForwardSinkError::Backpressure,
                    mpsc::error::TrySendError::Closed(_) => SfuForwardSinkError::Unavailable,
                })?;
        }
        Ok(())
    }
}

fn same_session(entry: &SessionEntry, claims: &RealtimeSessionClaims) -> bool {
    entry.claims.scope == claims.scope
        && entry.claims.call_id == claims.call_id
        && entry.claims.session_id == claims.session_id
}

fn prune_expired(entries: &mut Vec<SessionEntry>, now_unix_ms: i64) {
    entries.retain(|entry| now_unix_ms < entry.claims.expires_at_unix_ms);
}

fn system_now_unix_ms() -> Option<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

fn encode_claims(claims: &RealtimeSessionClaims) -> Result<Vec<u8>, JoinTokenError> {
    let mut output = Vec::with_capacity(512);
    output.push(2);
    push_id(&mut output, claims.scope.tenant_id.as_opaque())?;
    match &claims.scope.namespace_id {
        Some(namespace_id) => {
            output.push(1);
            push_id(&mut output, namespace_id.as_opaque())?;
        }
        None => output.push(0),
    }
    push_id(&mut output, claims.call_id.as_opaque())?;
    output.push(principal_kind_code(claims.participant.kind));
    push_id(&mut output, claims.participant.principal_id.as_opaque())?;
    match &claims.device_id {
        Some(device_id) => {
            output.push(1);
            push_id(&mut output, device_id.as_opaque())?;
        }
        None => output.push(0),
    }
    push_id(&mut output, claims.session_id.as_opaque())?;
    output.extend_from_slice(&claims.issued_at_unix_ms.to_be_bytes());
    output.extend_from_slice(&claims.expires_at_unix_ms.to_be_bytes());
    output.extend_from_slice(&claims.not_before_unix_ms.to_be_bytes());
    output.push(match claims.use_policy {
        JoinGrantUsePolicy::SingleUse => 1,
        JoinGrantUsePolicy::Reusable => 2,
    });
    Ok(output)
}

fn decode_claims(payload: &[u8]) -> Result<RealtimeSessionClaims, JoinTokenError> {
    let mut cursor = 0_usize;
    let version = take_u8(payload, &mut cursor)?;
    if !matches!(version, 1 | 2) {
        return Err(JoinTokenError::Malformed);
    }
    let tenant_id = TenantId::from_opaque(take_id(payload, &mut cursor)?);
    let namespace_id = match take_u8(payload, &mut cursor)? {
        0 => None,
        1 => Some(NamespaceId::from_opaque(take_id(payload, &mut cursor)?)),
        _ => return Err(JoinTokenError::Malformed),
    };
    let call_id = CallId::from_opaque(take_id(payload, &mut cursor)?);
    let kind = principal_kind_from_code(take_u8(payload, &mut cursor)?)?;
    let principal_id = PrincipalId::from_opaque(take_id(payload, &mut cursor)?);
    let device_id = match take_u8(payload, &mut cursor)? {
        0 => None,
        1 => Some(DeviceId::from_opaque(take_id(payload, &mut cursor)?)),
        _ => return Err(JoinTokenError::Malformed),
    };
    let session_id = SessionId::from_opaque(take_id(payload, &mut cursor)?);
    let issued_at_unix_ms = take_i64(payload, &mut cursor)?;
    let expires_at_unix_ms = take_i64(payload, &mut cursor)?;
    let (not_before_unix_ms, use_policy) = if version == 1 {
        (issued_at_unix_ms, JoinGrantUsePolicy::Reusable)
    } else {
        let not_before_unix_ms = take_i64(payload, &mut cursor)?;
        let use_policy = match take_u8(payload, &mut cursor)? {
            1 => JoinGrantUsePolicy::SingleUse,
            2 => JoinGrantUsePolicy::Reusable,
            _ => return Err(JoinTokenError::Malformed),
        };
        (not_before_unix_ms, use_policy)
    };
    if cursor != payload.len() {
        return Err(JoinTokenError::Malformed);
    }
    Ok(RealtimeSessionClaims {
        scope: TenantScope {
            tenant_id,
            namespace_id,
        },
        call_id,
        participant: PrincipalRef { principal_id, kind },
        device_id,
        session_id,
        issued_at_unix_ms,
        not_before_unix_ms,
        expires_at_unix_ms,
        use_policy,
    })
}

fn push_id(output: &mut Vec<u8>, id: &OpaqueId) -> Result<(), JoinTokenError> {
    let length = u16::try_from(id.as_wire_bytes().len()).map_err(|_| JoinTokenError::Malformed)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(id.as_wire_bytes());
    Ok(())
}

fn take_id(payload: &[u8], cursor: &mut usize) -> Result<OpaqueId, JoinTokenError> {
    let length_bytes = take(payload, cursor, 2)?;
    let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    let value = take(payload, cursor, length)?;
    OpaqueId::from_wire_bytes(value).map_err(|_| JoinTokenError::Malformed)
}

fn take_i64(payload: &[u8], cursor: &mut usize) -> Result<i64, JoinTokenError> {
    let value = take(payload, cursor, 8)?;
    let bytes: [u8; 8] = value.try_into().map_err(|_| JoinTokenError::Malformed)?;
    Ok(i64::from_be_bytes(bytes))
}

fn take_u8(payload: &[u8], cursor: &mut usize) -> Result<u8, JoinTokenError> {
    Ok(take(payload, cursor, 1)?[0])
}

fn take<'a>(
    payload: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], JoinTokenError> {
    let end = cursor
        .checked_add(length)
        .ok_or(JoinTokenError::Malformed)?;
    let slice = payload.get(*cursor..end).ok_or(JoinTokenError::Malformed)?;
    *cursor = end;
    Ok(slice)
}

const fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Person => 1,
        PrincipalKind::Device => 2,
        PrincipalKind::ServiceAccount => 3,
        PrincipalKind::AiAgent => 4,
        PrincipalKind::Bot => 5,
        PrincipalKind::Organization => 6,
        PrincipalKind::Automation => 7,
        PrincipalKind::ExternalPlatform => 8,
    }
}

const fn principal_kind_from_code(value: u8) -> Result<PrincipalKind, JoinTokenError> {
    match value {
        1 => Ok(PrincipalKind::Person),
        2 => Ok(PrincipalKind::Device),
        3 => Ok(PrincipalKind::ServiceAccount),
        4 => Ok(PrincipalKind::AiAgent),
        5 => Ok(PrincipalKind::Bot),
        6 => Ok(PrincipalKind::Organization),
        7 => Ok(PrincipalKind::Automation),
        8 => Ok(PrincipalKind::ExternalPlatform),
        _ => Err(JoinTokenError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{
        CryptoSuite, GroupId, GroupMediaFrameHeader, GroupMediaSourceSignature, KeyId, MediaKind,
        SfuForwardTarget,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(id("tenant")),
            namespace_id: Some(NamespaceId::from_opaque(id("namespace"))),
        }
    }

    fn participant() -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(id("participant")),
            kind: PrincipalKind::Person,
        }
    }

    fn issuer() -> JoinTokenIssuer {
        JoinTokenIssuer::new(
            JoinTokenKey::from_bytes([7_u8; 32]),
            "https://join.example.test/conference",
        )
        .expect("issuer")
    }

    fn token_from_url(url: &str) -> &str {
        url.split_once("#ucr_join=").expect("join fragment").1
    }

    fn envelope(call_id: CallId, source: PrincipalRef) -> SfuForwardEnvelope {
        SfuForwardEnvelope {
            frame: ucr_model::EncryptedGroupMediaFrame {
                header: GroupMediaFrameHeader {
                    scope: scope(),
                    call_id,
                    group_id: GroupId::from_opaque(id("group")),
                    stream_id: id("stream"),
                    source,
                    source_device_id: DeviceId::from_opaque(id("source-device")),
                    negotiation_ref: id("negotiation"),
                    negotiation_generation: 1,
                    crypto_epoch: 1,
                    crypto_state_ref: id("crypto-state"),
                    crypto_suite: CryptoSuite::UcrV1,
                    media_kind: MediaKind::Video,
                    sequence: 1,
                    media_timestamp: 1,
                    keyframe: true,
                },
                nonce: [3_u8; 24],
                ciphertext: vec![1, 2, 3],
                source_signature: GroupMediaSourceSignature {
                    key_id: KeyId::from_opaque(id("key")),
                    algorithm_id: "ed25519".to_owned(),
                    algorithm_version: 1,
                    signature: vec![4_u8; 64],
                },
            },
        }
    }

    #[test]
    fn signed_join_grant_round_trips_and_fragment_hides_credential_from_request_url() {
        let issuer = issuer();
        let grant = issuer
            .issue(
                scope(),
                CallId::from_opaque(id("call")),
                participant(),
                Some(DeviceId::from_opaque(id("device"))),
                300,
                10_000,
            )
            .expect("issue");
        assert!(grant.join_url.starts_with("https://"));
        assert!(grant.join_url.contains("#ucr_join="));
        assert!(!grant.join_url.contains("?token="));
        let decoded = issuer
            .verify(token_from_url(&grant.join_url), 10_001)
            .expect("verify");
        assert_eq!(decoded, grant.claims);
        assert_eq!(
            issuer.verify(
                token_from_url(&grant.join_url),
                grant.claims.expires_at_unix_ms
            ),
            Err(JoinTokenError::Expired)
        );
    }

    #[test]
    fn single_use_grant_rejects_second_redemption_and_revocation_blocks_verify() {
        let issuer = issuer();
        let grant = issuer
            .issue_with_policy(
                scope(),
                CallId::from_opaque(id("call")),
                participant(),
                Some(DeviceId::from_opaque(id("device"))),
                300,
                JoinGrantUsePolicy::SingleUse,
                Some(40_010),
                Some(80_000),
                40_000,
            )
            .expect("issue");
        let token = token_from_url(&grant.join_url);
        assert_eq!(
            issuer.redeem(token, 40_001),
            Err(JoinTokenError::NotYetValid)
        );
        assert!(issuer.redeem(token, 40_010).is_ok());
        assert_eq!(
            issuer.redeem(token, 40_011),
            Err(JoinTokenError::AlreadyUsed)
        );
        assert!(issuer.verify(token, 40_011).is_ok());
        issuer
            .revoke(&scope(), &grant.claims.session_id)
            .expect("revoke");
        assert_eq!(issuer.verify(token, 40_012), Err(JoinTokenError::Revoked));
    }

    #[test]
    fn tampered_join_grant_fails_signature_validation() {
        let issuer = issuer();
        let grant = issuer
            .issue(
                scope(),
                CallId::from_opaque(id("call")),
                participant(),
                None,
                60,
                20_000,
            )
            .expect("issue");
        let token = token_from_url(&grant.join_url);
        let mut tampered = token.as_bytes().to_vec();
        let index = tampered
            .iter()
            .position(|byte| *byte != b'.')
            .expect("byte");
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ascii token");
        assert!(matches!(
            issuer.verify(&tampered, 20_001),
            Err(JoinTokenError::InvalidSignature | JoinTokenError::Malformed)
        ));
    }

    #[test]
    fn reconnect_replaces_downlink_and_advances_attendance_sequence() {
        let issuer = issuer();
        let claims = issuer
            .issue(
                scope(),
                CallId::from_opaque(id("call")),
                participant(),
                None,
                300,
                30_000,
            )
            .expect("issue")
            .claims;
        let registry = RealtimeSessionRegistry::new(8, 2);
        let first = registry.join(claims.clone(), 30_001).expect("join");
        assert_eq!(first.transition.kind, AttendanceTransitionKind::Joined);
        let mut first_downlink = registry
            .take_downlink(&claims, 30_001)
            .expect("first downlink");
        let second = registry.join(claims.clone(), 30_002).expect("reconnect");
        assert_eq!(
            second.transition.kind,
            AttendanceTransitionKind::Reconnected
        );
        assert_eq!(second.transition.session_sequence, 2);
        assert_eq!(registry.active_session_count(), 1);
        assert!(first_downlink.try_recv().is_err());
        assert!(registry.take_downlink(&claims, 30_002).is_ok());
    }

    #[test]
    fn dropped_downlink_resumes_without_redeeming_the_join_grant() {
        let issuer = issuer();
        let claims = issuer
            .issue_with_policy(
                scope(),
                CallId::from_opaque(id("call")),
                participant(),
                None,
                300,
                JoinGrantUsePolicy::SingleUse,
                None,
                None,
                31_000,
            )
            .expect("issue")
            .claims;
        let registry = RealtimeSessionRegistry::new(8, 2);
        registry.join(claims.clone(), 31_001).expect("join");

        let first = registry
            .attach_downlink(&claims, 31_001)
            .expect("first downlink");
        assert!(first.transition.is_none());
        drop(first.receiver);

        let resumed = registry
            .attach_downlink(&claims, 31_002)
            .expect("resumed downlink");
        let transition = resumed.transition.expect("reconnect transition");
        assert_eq!(transition.kind, AttendanceTransitionKind::Reconnected);
        assert_eq!(transition.session_sequence, 2);
        assert_eq!(registry.active_session_count(), 1);
    }

    #[test]
    fn multi_device_backpressure_is_preflighted_before_any_new_enqueue() {
        let now = system_now_unix_ms().expect("clock");
        let call_id = CallId::from_opaque(id("call"));
        let recipient = participant();
        let registry = RealtimeSessionRegistry::new(8, 1);
        let first_claims = RealtimeSessionClaims {
            scope: scope(),
            call_id: call_id.clone(),
            participant: recipient.clone(),
            device_id: Some(DeviceId::from_opaque(id("device-a"))),
            session_id: SessionId::from_opaque(id("session-a")),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            use_policy: JoinGrantUsePolicy::Reusable,
        };
        let second_claims = RealtimeSessionClaims {
            device_id: Some(DeviceId::from_opaque(id("device-b"))),
            session_id: SessionId::from_opaque(id("session-b")),
            ..first_claims.clone()
        };
        registry.join(first_claims.clone(), now).expect("first");
        registry.join(second_claims.clone(), now).expect("second");
        let mut first = registry
            .take_downlink(&first_claims, now)
            .expect("first downlink");
        let mut second = registry
            .take_downlink(&second_claims, now)
            .expect("second downlink");
        let frame = envelope(
            call_id,
            PrincipalRef {
                principal_id: PrincipalId::from_opaque(id("source")),
                kind: PrincipalKind::Person,
            },
        );
        let target = SfuForwardTarget {
            recipient: recipient.clone(),
        };
        registry
            .forward_encrypted(&target, &frame)
            .expect("initial fanout");
        let _ = first.try_recv().expect("drain first only");
        assert_eq!(
            registry.forward_encrypted(&target, &frame),
            Err(SfuForwardSinkError::Backpressure)
        );
        assert!(first.try_recv().is_err());
        assert!(second.try_recv().is_ok());
        assert!(second.try_recv().is_err());
    }
}

#![forbid(unsafe_code)]

use core::fmt;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use ucr_core::generate_opaque_id;
use ucr_model::{
    AdaptiveMediaStage, CallId, DeviceId, NamespaceId, OpaqueId, PrincipalId, PrincipalKind,
    PrincipalRef, ScopedPrincipal, SessionId, SfuForwardEnvelope, TenantId, TenantScope,
};
use ucr_protocol::adaptive_stage_allows_media;
use ucr_secrets::{SecretHandle, SecretProvider, SecretPurpose};
use ucr_sfu::{SfuForwardSink, SfuForwardSinkError};

pub const MIN_JOIN_TTL_SECONDS: u32 = 30;
pub const MAX_JOIN_TTL_SECONDS: u32 = 900;
pub const DEFAULT_JOIN_TTL_SECONDS: u32 = 300;
pub const DEFAULT_REALTIME_QUEUE_CAPACITY: usize = 64;
pub const MAX_REALTIME_SESSIONS: usize = 4096;
pub const MAX_JOIN_GRANTS: usize = 4096;
/// How long a session stays on the live roster after its last heartbeat.
///
/// The downlink sender stays open while this process still holds the receiver,
/// so a tab that never attached — or whose leave never arrived — would otherwise
/// count as present until the 15-minute grant expired. Heartbeats are every 15
/// seconds; two minutes covers a timer delayed by a background tab.
pub const CONNECTED_HEARTBEAT_GRACE_MS: i64 = 120_000;
const BANDWIDTH_WINDOW_MS: i64 = 1_000;

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
    KeyUnavailable,
    Internal,
}

#[derive(Clone)]
enum JoinTokenKeySource {
    Static(JoinTokenKey),
    Provider {
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    },
}

impl fmt::Debug for JoinTokenKeySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(_) => formatter.write_str("Static(<redacted>)"),
            Self::Provider { handle, .. } => formatter
                .debug_struct("Provider")
                .field("handle", handle)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JoinTokenIssuer {
    key_source: JoinTokenKeySource,
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
            key_source: JoinTokenKeySource::Static(key),
            join_base_url,
            grants: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Creates an issuer backed by the shared secret-provider boundary.
    ///
    /// New tokens use the current secret version; verification accepts current and previous during
    /// the provider's bounded rotation overlap. The join-token wire format is unchanged.
    ///
    /// # Errors
    /// Rejects non-join handles, unavailable providers, malformed key material, or invalid URLs.
    pub fn with_secret_provider(
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
        join_base_url: impl Into<String>,
    ) -> Result<Self, JoinTokenError> {
        if handle.purpose != SecretPurpose::JoinSigning {
            return Err(JoinTokenError::KeyUnavailable);
        }
        let join_base_url = join_base_url.into();
        if !join_base_url.starts_with("https://")
            || join_base_url.contains('#')
            || join_base_url.chars().any(char::is_whitespace)
        {
            return Err(JoinTokenError::InvalidBaseUrl);
        }
        let set = provider
            .active_secret_set(&handle)
            .map_err(|_| JoinTokenError::KeyUnavailable)?;
        join_token_key_from_material(set.current.material.as_bytes())?;
        if let Some(previous) = set.previous {
            join_token_key_from_material(previous.material.as_bytes())?;
        }
        Ok(Self {
            key_source: JoinTokenKeySource::Provider { provider, handle },
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

    /// Revalidates already-authenticated claims against current temporal and legacy control state.
    ///
    /// This is used by long-lived transports after initial token authentication so revocation
    /// remains effective without resending bearer credentials on every encrypted media frame.
    ///
    /// # Errors
    /// Rejects not-yet-valid, expired, missing, changed or revoked controlled claims.
    pub fn validate_live_claims(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<(), JoinTokenError> {
        if now_unix_ms < claims.not_before_unix_ms {
            return Err(JoinTokenError::NotYetValid);
        }
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(JoinTokenError::Expired);
        }
        self.require_live_grant(claims)
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
        let keys = self.verification_keys()?;
        let mut verified = false;
        for key in keys {
            let mut mac =
                HmacSha256::new_from_slice(&key.0).map_err(|_| JoinTokenError::Internal)?;
            mac.update(&payload);
            if mac.verify_slice(&signature).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(JoinTokenError::InvalidSignature);
        }
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
        let key = self.current_signing_key()?;
        let mut mac = HmacSha256::new_from_slice(&key.0).map_err(|_| JoinTokenError::Internal)?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn current_signing_key(&self) -> Result<JoinTokenKey, JoinTokenError> {
        match &self.key_source {
            JoinTokenKeySource::Static(key) => Ok(key.clone()),
            JoinTokenKeySource::Provider { provider, handle } => {
                let set = provider
                    .active_secret_set(handle)
                    .map_err(|_| JoinTokenError::KeyUnavailable)?;
                join_token_key_from_material(set.current.material.as_bytes())
            }
        }
    }

    fn verification_keys(&self) -> Result<Vec<JoinTokenKey>, JoinTokenError> {
        match &self.key_source {
            JoinTokenKeySource::Static(key) => Ok(vec![key.clone()]),
            JoinTokenKeySource::Provider { provider, handle } => {
                let set = provider
                    .active_secret_set(handle)
                    .map_err(|_| JoinTokenError::KeyUnavailable)?;
                let mut keys = Vec::with_capacity(2);
                keys.push(join_token_key_from_material(
                    set.current.material.as_bytes(),
                )?);
                if let Some(previous) = set.previous {
                    keys.push(join_token_key_from_material(previous.material.as_bytes())?);
                }
                Ok(keys)
            }
        }
    }
}

fn join_token_key_from_material(material: &[u8]) -> Result<JoinTokenKey, JoinTokenError> {
    let bytes: [u8; 32] = material
        .try_into()
        .map_err(|_| JoinTokenError::KeyUnavailable)?;
    Ok(JoinTokenKey::from_bytes(bytes))
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
    ClockRollback,
    SessionUnavailable,
    SequenceOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BandwidthWindow {
    owner: ScopedPrincipal,
    window_start_unix_ms: i64,
    used_bits: u64,
}

struct SessionEntry {
    claims: RealtimeSessionClaims,
    sender: mpsc::Sender<SfuForwardEnvelope>,
    receiver: Option<mpsc::Receiver<SfuForwardEnvelope>>,
    sequence: u64,
    // Connection lease fence: stable from this Join until the next actual Join.
    // MediaReady and downlink reattachment only increment attendance sequence.
    join_generation: u64,
    media_ready: bool,
    adaptive_stage: Option<AdaptiveMediaStage>,
    publisher_owner: Option<ScopedPrincipal>,
    last_seen_unix_ms: i64,
}

impl fmt::Debug for SessionEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionEntry")
            .field("claims", &self.claims)
            .field("sequence", &self.sequence)
            .field("join_generation", &self.join_generation)
            .field("media_ready", &self.media_ready)
            .field("adaptive_stage", &self.adaptive_stage)
            .field("publisher_active", &self.publisher_owner.is_some())
            .field("queue_capacity", &self.sender.capacity())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct RealtimeSessionRegistry {
    entries: Mutex<Vec<SessionEntry>>,
    expired_call_cleanup: Mutex<Vec<(TenantScope, CallId)>>,
    track_expired_call_cleanup: bool,
    bandwidth_usage: Mutex<Vec<BandwidthWindow>>,
    // Monotonic within one running registry: Leave+Join cannot reuse a lease
    // generation even when the previous entry was fully removed (ABA).
    last_join_generation: AtomicU64,
    max_sessions: usize,
    queue_capacity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeJoinOutcome {
    pub claims: RealtimeSessionClaims,
    pub transition: AttendanceTransition,
    pub join_generation: u64,
}

#[derive(Debug)]
pub struct RealtimeDownlinkAttachment {
    pub receiver: mpsc::Receiver<SfuForwardEnvelope>,
    pub transition: Option<AttendanceTransition>,
}

/// Maximum Join generation exactly representable by JavaScript clients.
pub const MAX_JOIN_GENERATION: u64 = (1 << 53) - 1;
const INITIAL_JOIN_GENERATION_MASK: u64 = (1 << 52) - 1;

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
            expired_call_cleanup: Mutex::new(Vec::new()),
            track_expired_call_cleanup: false,
            bandwidth_usage: Mutex::new(Vec::new()),
            last_join_generation: AtomicU64::new(0),
            max_sessions,
            queue_capacity,
        }
    }

    /// Creates a registry that additionally tracks final-session expiry coordinates for the
    /// optional horizontal-SFU placement lifecycle.
    ///
    /// The normal registry intentionally leaves this disabled so deployments that do not enable
    /// SFU placement cannot accumulate cleanup-only state or inherit a new capacity failure mode.
    #[must_use]
    pub const fn with_expired_call_cleanup(max_sessions: usize, queue_capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            expired_call_cleanup: Mutex::new(Vec::new()),
            track_expired_call_cleanup: true,
            bandwidth_usage: Mutex::new(Vec::new()),
            last_join_generation: AtomicU64::new(0),
            max_sessions,
            queue_capacity,
        }
    }

    /// Returns Calls whose SFU placement cleanup has not yet been acknowledged.
    ///
    /// Candidates originate from final-session expiry or explicit terminal-conference cleanup.
    ///
    /// This is derived, bounded infrastructure cleanup metadata only. The canonical session roster
    /// remains `entries`; cleanup coordinates contain no participant, authorization or media state.
    /// Candidates remain pending until the infrastructure owner acknowledges successful idempotent
    /// cleanup, so a transient placement-release failure can be retried without recreating a second
    /// session owner.
    ///
    /// # Errors
    /// Fails when bounded registry/cleanup state is unavailable or cleanup capacity is exhausted.
    pub fn expired_call_cleanup_candidates_at(
        &self,
        now_unix_ms: i64,
    ) -> Result<Vec<(TenantScope, CallId)>, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        drop(entries);
        self.expired_call_cleanup
            .lock()
            .map(|pending| pending.clone())
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)
    }

    /// Acknowledges one idempotently completed (or stale-after-rejoin) cleanup candidate.
    ///
    /// # Errors
    /// Fails only when cleanup state is unavailable.
    pub fn acknowledge_expired_call_cleanup(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<(), RealtimeRegistryError> {
        let mut pending = self
            .expired_call_cleanup
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        pending.retain(|(candidate_scope, candidate_call_id)| {
            candidate_scope != scope || candidate_call_id != call_id
        });
        Ok(())
    }

    /// Queues one canonical Call for idempotent infrastructure cleanup after terminal reaping.
    ///
    /// The queue is enabled only for registries that opted into SFU placement cleanup. Repeated
    /// queueing of the same scope/Call is idempotent and the bounded queue contains coordinates
    /// only, never participant, authorization, media, or key material.
    ///
    /// # Errors
    /// Fails when cleanup state is unavailable or the bounded cleanup queue is exhausted.
    pub fn queue_call_cleanup_candidate(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<(), RealtimeRegistryError> {
        if !self.track_expired_call_cleanup {
            return Ok(());
        }
        let mut pending = self
            .expired_call_cleanup
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        if pending.iter().any(|(pending_scope, pending_call_id)| {
            pending_scope == scope && pending_call_id == call_id
        }) {
            return Ok(());
        }
        if pending.len() >= self.max_sessions {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        pending.push((scope.clone(), call_id.clone()));
        Ok(())
    }

    fn prune_expired(
        &self,
        entries: &mut Vec<SessionEntry>,
        now_unix_ms: i64,
    ) -> Result<(), RealtimeRegistryError> {
        if !self.track_expired_call_cleanup {
            entries.retain(|entry| now_unix_ms < entry.claims.expires_at_unix_ms);
            return Ok(());
        }

        let mut final_expired_calls = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| now_unix_ms >= entry.claims.expires_at_unix_ms)
        {
            let scope = &entry.claims.scope;
            let call_id = &entry.claims.call_id;
            if final_expired_calls
                .iter()
                .any(|(candidate_scope, candidate_call_id)| {
                    candidate_scope == scope && candidate_call_id == call_id
                })
            {
                continue;
            }
            let has_live_session = entries.iter().any(|candidate| {
                now_unix_ms < candidate.claims.expires_at_unix_ms
                    && candidate.claims.scope == *scope
                    && candidate.claims.call_id == *call_id
            });
            if !has_live_session {
                final_expired_calls.push((scope.clone(), call_id.clone()));
            }
        }

        let mut pending = self
            .expired_call_cleanup
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        let new_candidates = final_expired_calls
            .iter()
            .filter(|(scope, call_id)| {
                !pending.iter().any(|(pending_scope, pending_call_id)| {
                    pending_scope == scope && pending_call_id == call_id
                })
            })
            .count();
        if pending.len().saturating_add(new_candidates) > self.max_sessions {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }

        entries.retain(|entry| now_unix_ms < entry.claims.expires_at_unix_ms);
        for candidate in final_expired_calls {
            if !pending.iter().any(|existing| existing == &candidate) {
                pending.push(candidate);
            }
        }
        Ok(())
    }

    /// Returns the current number of non-expired authenticated realtime sessions.
    ///
    /// This is operator capacity evidence only. It is not attendance, billing, a quota decision or
    /// durable Conference state.
    ///
    /// # Errors
    /// Fails when the bounded registry state is unavailable.
    pub fn active_session_count_at(
        &self,
        now_unix_ms: i64,
    ) -> Result<usize, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        Ok(entries.len())
    }

    /// Returns a bounded snapshot of all non-expired authenticated realtime claims.
    ///
    /// The snapshot is for internal runtime cleanup only. It preserves exact signed claim binding
    /// and does not create a second durable session owner. Expiry pruning still flows through the
    /// registry's canonical cleanup queue so SFU placement release cannot be bypassed.
    ///
    /// # Errors
    /// Fails when the bounded registry state is unavailable.
    pub fn active_claims_at(
        &self,
        now_unix_ms: i64,
    ) -> Result<Vec<RealtimeSessionClaims>, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        Ok(entries.iter().map(|entry| entry.claims.clone()).collect())
    }

    /// Returns the number of non-expired realtime sessions that belong to one canonical Call.
    ///
    /// This query deliberately reads the existing session registry rather than maintaining a
    /// second Call/session roster for SFU placement lifecycle decisions.
    ///
    /// # Errors
    /// Fails when the bounded registry state is unavailable.
    pub fn active_call_session_count_at(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        now_unix_ms: i64,
    ) -> Result<usize, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        Ok(entries
            .iter()
            .filter(|entry| entry.claims.scope == *scope && entry.claims.call_id == *call_id)
            .count())
    }

    /// Returns how many participants still have an open downlink on one canonical Call.
    ///
    /// A registry entry can outlive the browser tab. A closed downlink means that tab is gone, so
    /// the local room must not treat it as someone still in the call.
    ///
    /// # Errors
    /// Fails when the bounded registry state is unavailable.
    pub fn connected_call_participant_count_at(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        now_unix_ms: i64,
    ) -> Result<usize, RealtimeRegistryError> {
        Ok(self
            .connected_call_participants_at(scope, call_id, now_unix_ms)?
            .len())
    }

    /// Participants whose downlink is still open and who have heartbeated recently.
    ///
    /// Accepted membership outlives a closed tab. Receive rosters use this set so a
    /// subscriber is not pinned to someone who is no longer in the room. A join
    /// counts as the first heartbeat: a fresh session is live before its first
    /// timer, and a crashed tab leaves the roster after `CONNECTED_HEARTBEAT_GRACE_MS`.
    ///
    /// # Errors
    /// Fails when the bounded registry state is unavailable.
    pub fn connected_call_participants_at(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        now_unix_ms: i64,
    ) -> Result<std::collections::BTreeSet<PrincipalId>, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        let mut participants = std::collections::BTreeSet::new();
        for entry in entries.iter() {
            if entry.claims.scope == *scope
                && entry.claims.call_id == *call_id
                && !entry.sender.is_closed()
                && now_unix_ms.saturating_sub(entry.last_seen_unix_ms)
                    <= CONNECTED_HEARTBEAT_GRACE_MS
            {
                participants.insert(entry.claims.participant.principal_id.clone());
            }
        }
        Ok(participants)
    }

    /// Returns whether the exact signed session is already active.
    ///
    /// This is used by admission policy to distinguish a first entry from a reconnect when a
    /// Conference host closes entry after participants are already present.
    ///
    /// # Errors
    /// Fails only when bounded registry state is unavailable.
    pub fn contains_active_session(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<bool, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        Ok(entries
            .iter()
            .any(|entry| same_session(entry, claims) && entry.claims == *claims))
    }

    /// Allocates a unique connection lease fence. A CSPRNG-derived registry
    /// incarnation prevents the ordinary ABA problem after an API restart:
    /// sequence 1 on an old process must not represent sequence 1 on a new
    /// process that reused the same unexpired Join grant.
    ///
    /// This is still only infrastructure state of the canonical session owner,
    /// not another persistent Identity, Device, Call or Conference store.
    fn next_join_generation(&self) -> Result<u64, RealtimeRegistryError> {
        if self.last_join_generation.load(Ordering::Relaxed) == 0 {
            // Native opaque ID has 128 bits from the OS CSPRNG; hash the entire
            // random ID and use an unpredictable 52-bit initial generation.
            // Keep the generation in the exact JavaScript integer range.
            let nonce =
                generate_opaque_id().map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
            let digest = Sha256::digest(nonce.as_wire_bytes());
            let initial = u64::from_be_bytes([
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                digest[7],
            ]) & INITIAL_JOIN_GENERATION_MASK;
            let _ = self.last_join_generation.compare_exchange(
                0,
                initial.max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        self.last_join_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
                    .filter(|next| *next <= MAX_JOIN_GENERATION)
            })
            .map(|previous| previous + 1)
            .map_err(|_| RealtimeRegistryError::SequenceOverflow)
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
        self.prune_expired(&mut entries, now_unix_ms)?;
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
            let generation = self.next_join_generation()?;
            entry.join_generation = generation;
            entry.media_ready = false;
            entry.publisher_owner = None;
            entry.last_seen_unix_ms = now_unix_ms;
            let (sender, receiver) = mpsc::channel(self.queue_capacity);
            entry.sender = sender;
            entry.receiver = Some(receiver);
            let transition = AttendanceTransition {
                kind: AttendanceTransitionKind::Reconnected,
                claims: claims.clone(),
                session_sequence: entry.sequence,
                occurred_at_unix_ms: now_unix_ms,
            };
            return Ok(RealtimeJoinOutcome {
                claims,
                transition,
                join_generation: generation,
            });
        }
        if entries.len() >= self.max_sessions {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        let generation = self.next_join_generation()?;
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
            join_generation: generation,
            media_ready: false,
            adaptive_stage: None,
            publisher_owner: None,
            last_seen_unix_ms: now_unix_ms,
        });
        Ok(RealtimeJoinOutcome {
            claims,
            transition,
            join_generation: generation,
        })
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
        self.prune_expired(&mut entries, now_unix_ms)?;
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
    /// Returns the same bounded registry failures as `attach_downlink`.
    pub fn take_downlink(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<mpsc::Receiver<SfuForwardEnvelope>, RealtimeRegistryError> {
        self.attach_downlink(claims, now_unix_ms)
            .map(|attachment| attachment.receiver)
    }

    /// Resolves exact active claims for one ciphertext ingress binding.
    ///
    /// Scope and Call are taken from the encrypted envelope routing header and must match the
    /// session that owns the WebRTC peer. Ambiguous session IDs fail closed.
    ///
    /// # Errors
    /// Fails for expiry, missing/ambiguous bindings, or unavailable registry state.
    pub fn active_claims_for_ingress(
        &self,
        session_id: &SessionId,
        scope: &TenantScope,
        call_id: &CallId,
        now_unix_ms: i64,
    ) -> Result<RealtimeSessionClaims, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        let mut matching = entries.iter().filter(|entry| {
            entry.claims.session_id == *session_id
                && entry.claims.scope == *scope
                && entry.claims.call_id == *call_id
        });
        let claims = matching
            .next()
            .ok_or(RealtimeRegistryError::SessionUnavailable)?
            .claims
            .clone();
        if matching.next().is_some() || now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::SessionUnavailable);
        }
        Ok(claims)
    }

    /// Returns active WebRTC session IDs for one exact current SFU recipient.
    ///
    /// # Errors
    /// Fails only when bounded registry state is unavailable.
    pub fn active_session_ids_for_recipient(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        participant: &PrincipalRef,
        now_unix_ms: i64,
    ) -> Result<Vec<SessionId>, RealtimeRegistryError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        Ok(entries
            .iter()
            .filter(|entry| {
                entry.claims.scope == *scope
                    && entry.claims.call_id == *call_id
                    && entry.claims.participant == *participant
            })
            .map(|entry| entry.claims.session_id.clone())
            .collect())
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
        self.heartbeat_with_generation(claims, None, now_unix_ms)
            .map(|(sequence, _)| sequence)
    }

    /// Refreshes liveness ONLY for the exact current Join lease. An old tab may
    /// still hold a valid reusable signed grant after another tab reconnects
    /// the same Session, but it must not keep the replacement on the live roster.
    /// Compare the generation and mutate `last_seen` under ONE registry mutex.
    ///
    /// Returns None on an obsolete/zero generation without changing liveness.
    ///
    /// # Errors
    /// Fails for expiry, claim mismatch, missing session, or unavailable state.
    pub fn heartbeat_if_join_generation(
        &self,
        claims: &RealtimeSessionClaims,
        expected_join_generation: u64,
        now_unix_ms: i64,
    ) -> Result<Option<u64>, RealtimeRegistryError> {
        if expected_join_generation == 0 {
            return Ok(None);
        }
        self.heartbeat_with_generation(claims, Some(expected_join_generation), now_unix_ms)
            .map(|(sequence, matched)| matched.then_some(sequence))
    }

    fn heartbeat_with_generation(
        &self,
        claims: &RealtimeSessionClaims,
        expected_join_generation: Option<u64>,
        now_unix_ms: i64,
    ) -> Result<(u64, bool), RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        let entry = entries
            .iter_mut()
            .find(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entry.claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        if expected_join_generation.is_some_and(|expected| expected != entry.join_generation) {
            return Ok((entry.sequence, false));
        }
        entry.last_seen_unix_ms = now_unix_ms;
        Ok((entry.sequence, true))
    }

    /// Stable generation of the current Join, not the mutable attendance
    /// sequence returned by heartbeat. Use this for external Leave fencing.
    ///
    /// # Errors
    /// Fails closed if the signed claims have expired, changed or disappeared.
    pub fn current_join_generation(
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
        self.prune_expired(&mut entries, now_unix_ms)?;
        let entry = entries
            .iter()
            .find(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entry.claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        Ok(entry.join_generation)
    }

    /// Applies one already-evaluated adaptive-media stage to the exact live realtime session.
    ///
    /// This registry owns only endpoint delivery state. Adaptive policy/hysteresis remains in the
    /// Phase-23 controller; the stage is used solely to suppress media that the endpoint should no
    /// longer receive.
    ///
    /// # Errors
    /// Fails for expiry, claim mismatch, missing session, or unavailable registry state.
    pub fn set_adaptive_media_stage(
        &self,
        claims: &RealtimeSessionClaims,
        stage: AdaptiveMediaStage,
        now_unix_ms: i64,
    ) -> Result<(), RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        let entry = entries
            .iter_mut()
            .find(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entry.claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        entry.adaptive_stage = Some(stage);
        Ok(())
    }

    /// Atomically claims one publisher slot for the exact live realtime session.
    ///
    /// A session claims at most one slot regardless of how many audio/video/screen sources it
    /// publishes. Slots are scoped by the exact Service Account owner, and are released when the
    /// session leaves, expires, or performs a full reconnect through `join`.
    ///
    /// # Errors
    /// Fails for expiry, claim/owner mismatch, missing session state, unavailable registry state,
    /// or when the owner's configured concurrent publisher ceiling is already exhausted.
    pub fn claim_publisher_slot(
        &self,
        claims: &RealtimeSessionClaims,
        owner: &ScopedPrincipal,
        max_concurrent_publishers: u64,
        now_unix_ms: i64,
    ) -> Result<(), RealtimeRegistryError> {
        if now_unix_ms >= claims.expires_at_unix_ms {
            return Err(RealtimeRegistryError::Expired);
        }
        if owner.scope != claims.scope || owner.principal.kind != PrincipalKind::ServiceAccount {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        if max_concurrent_publishers == 0 {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        self.prune_expired(&mut entries, now_unix_ms)?;
        let index = entries
            .iter()
            .position(|entry| same_session(entry, claims))
            .ok_or(RealtimeRegistryError::SessionUnavailable)?;
        if entries[index].claims != *claims {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        if let Some(existing_owner) = &entries[index].publisher_owner {
            return if existing_owner == owner {
                Ok(())
            } else {
                Err(RealtimeRegistryError::ClaimMismatch)
            };
        }
        let active = entries
            .iter()
            .filter(|entry| entry.publisher_owner.as_ref() == Some(owner))
            .count();
        let active = u64::try_from(active).map_err(|_| RealtimeRegistryError::CapacityExceeded)?;
        if active >= max_concurrent_publishers {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        entries[index].publisher_owner = Some(owner.clone());
        Ok(())
    }

    /// Atomically charges one encrypted SFU wire copy against the Service Account's aggregate
    /// media bandwidth ceiling in a fixed one-second window.
    ///
    /// The same owner window is shared by every realtime session, so concurrent publishers and
    /// SFU fan-out recipients consume one aggregate budget. The window is ephemeral runtime state:
    /// policy is durable, while instantaneous traffic accounting resets naturally across restart.
    ///
    /// # Errors
    /// Fails for invalid owners/limits, clock rollback, unavailable registry state, bounded usage
    /// state exhaustion, arithmetic overflow, or when the aggregate bandwidth ceiling is exceeded.
    pub fn charge_aggregate_bandwidth(
        &self,
        owner: &ScopedPrincipal,
        max_aggregate_bandwidth_bps: u64,
        wire_bytes: usize,
        now_unix_ms: i64,
    ) -> Result<(), RealtimeRegistryError> {
        if owner.principal.kind != PrincipalKind::ServiceAccount {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        if max_aggregate_bandwidth_bps == 0 {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        if now_unix_ms < 0 {
            return Err(RealtimeRegistryError::ClockRollback);
        }
        let wire_bits = u64::try_from(wire_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or(RealtimeRegistryError::CapacityExceeded)?;
        if wire_bits > max_aggregate_bandwidth_bps {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        let window_start_unix_ms = now_unix_ms - now_unix_ms.rem_euclid(BANDWIDTH_WINDOW_MS);
        let mut usage = self
            .bandwidth_usage
            .lock()
            .map_err(|_| RealtimeRegistryError::SessionUnavailable)?;
        if let Some(entry) = usage.iter_mut().find(|entry| entry.owner == *owner) {
            if entry.window_start_unix_ms > window_start_unix_ms {
                return Err(RealtimeRegistryError::ClockRollback);
            }
            if entry.window_start_unix_ms < window_start_unix_ms {
                entry.window_start_unix_ms = window_start_unix_ms;
                entry.used_bits = wire_bits;
                return Ok(());
            }
            let next = entry
                .used_bits
                .checked_add(wire_bits)
                .ok_or(RealtimeRegistryError::CapacityExceeded)?;
            if next > max_aggregate_bandwidth_bps {
                return Err(RealtimeRegistryError::CapacityExceeded);
            }
            entry.used_bits = next;
            return Ok(());
        }
        let oldest_relevant_window = window_start_unix_ms.saturating_sub(BANDWIDTH_WINDOW_MS);
        usage.retain(|entry| entry.window_start_unix_ms >= oldest_relevant_window);
        let max_bandwidth_windows = self.max_sessions.saturating_mul(2);
        if usage.len() >= max_bandwidth_windows {
            return Err(RealtimeRegistryError::CapacityExceeded);
        }
        usage.push(BandwidthWindow {
            owner: owner.clone(),
            window_start_unix_ms,
            used_bits: wire_bits,
        });
        Ok(())
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
        self.prune_expired(&mut entries, now_unix_ms)?;
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

    /// Removes an exact session for internal rollback and lifecycle cleanup.
    ///
    /// An external network Leave must use `leave_if_sequence`, because an
    /// earlier connection's delayed Leave must never retire a new Join.
    ///
    /// # Errors
    /// Fails for mismatch, missing session, unavailable state, or overflow.
    pub fn leave(
        &self,
        claims: &RealtimeSessionClaims,
        now_unix_ms: i64,
    ) -> Result<AttendanceTransition, RealtimeRegistryError> {
        self.leave_matching_sequence(claims, None, now_unix_ms)
    }

    /// Retires only the stable connection generation established by the matching Join.
    /// `MediaReady` and downlink attendance events cannot invalidate this lease fence.
    ///
    /// The sequence comparison and removal happen under the same registry lock,
    /// so a stale external Leave cannot remove an intervening reconnect.
    ///
    /// # Errors
    /// Fails closed for a zero/stale sequence or absent/mismatched session.
    pub fn leave_if_sequence(
        &self,
        claims: &RealtimeSessionClaims,
        expected_session_sequence: u64,
        now_unix_ms: i64,
    ) -> Result<AttendanceTransition, RealtimeRegistryError> {
        if expected_session_sequence == 0 {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        self.leave_matching_sequence(claims, Some(expected_session_sequence), now_unix_ms)
    }

    fn leave_matching_sequence(
        &self,
        claims: &RealtimeSessionClaims,
        expected_session_sequence: Option<u64>,
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
        if entries[index].claims != *claims
            || expected_session_sequence
                .is_some_and(|generation| entries[index].join_generation != generation)
        {
            return Err(RealtimeRegistryError::ClaimMismatch);
        }
        let next_sequence = entries[index]
            .sequence
            .checked_add(1)
            .ok_or(RealtimeRegistryError::SequenceOverflow)?;
        entries.remove(index);
        Ok(AttendanceTransition {
            kind: AttendanceTransitionKind::Left,
            claims: claims.clone(),
            session_sequence: next_sequence,
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
        self.prune_expired(&mut entries, now_unix_ms)
            .map_err(|_| SfuForwardSinkError::Unavailable)?;

        let recipient_sessions = entries
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
        if recipient_sessions.is_empty() {
            return Err(SfuForwardSinkError::Unavailable);
        }
        let matching = recipient_sessions
            .into_iter()
            .filter(|index| {
                entries[*index].adaptive_stage.is_none_or(|stage| {
                    adaptive_stage_allows_media(stage, envelope.frame.header.media_kind)
                })
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Ok(());
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

    #[test]
    fn join_generation_stays_exact_in_browser_json_numbers() {
        for _ in 0..256 {
            let registry = RealtimeSessionRegistry::default();
            let first = registry.next_join_generation().expect("generation");
            let second = registry.next_join_generation().expect("generation");
            assert!((1..=MAX_JOIN_GENERATION).contains(&first));
            assert_eq!(second, first + 1);
        }
        let registry = RealtimeSessionRegistry::default();
        registry
            .last_join_generation
            .store(MAX_JOIN_GENERATION - 1, Ordering::Relaxed);
        assert_eq!(registry.next_join_generation(), Ok(MAX_JOIN_GENERATION));
        assert_eq!(
            registry.next_join_generation(),
            Err(RealtimeRegistryError::SequenceOverflow)
        );
    }
    use ucr_model::{
        CryptoSuite, GroupId, GroupMediaFrameHeader, GroupMediaSourceSignature, KeyId, MediaKind,
        SfuForwardTarget,
    };
    use ucr_secrets::{
        InMemorySecretProvider, SecretHandle, SecretMaterial, SecretProvider, SecretPurpose,
        SecretVersion,
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

    fn service_owner(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(id(value)),
                kind: PrincipalKind::ServiceAccount,
            },
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
                    header_version: 1,
                    media_kind: MediaKind::Video,
                    video_source_kind: Some(ucr_model::VideoSourceKind::Camera),
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
    fn join_tokens_survive_one_secret_rotation_without_wire_format_change() {
        let provider = Arc::new(InMemorySecretProvider::default());
        let handle = SecretHandle {
            secret_id: id("join-signing-secret"),
            purpose: SecretPurpose::JoinSigning,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: id("v1"),
                    material: SecretMaterial::new(vec![7_u8; 32]).expect("v1"),
                },
            )
            .expect("provision");
        let issuer = JoinTokenIssuer::with_secret_provider(
            provider.clone(),
            handle.clone(),
            "https://join.example.test/conference",
        )
        .expect("provider issuer");

        let first = issuer
            .issue(
                scope(),
                CallId::from_opaque(id("rotation-call")),
                participant(),
                Some(DeviceId::from_opaque(id("rotation-device"))),
                300,
                20_000,
            )
            .expect("issue v1");
        let first_token = token_from_url(&first.join_url).to_owned();

        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: id("v2"),
                    material: SecretMaterial::new(vec![8_u8; 32]).expect("v2"),
                },
            )
            .expect("rotate");

        assert_eq!(
            issuer
                .verify_signed_claims(&first_token, 20_001)
                .expect("old token remains valid"),
            first.claims
        );

        let second = issuer
            .issue(
                scope(),
                CallId::from_opaque(id("rotation-call")),
                participant(),
                Some(DeviceId::from_opaque(id("rotation-device-2"))),
                300,
                20_002,
            )
            .expect("issue v2");
        assert_ne!(first.join_url, second.join_url);

        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: id("v3"),
                    material: SecretMaterial::new(vec![9_u8; 32]).expect("v3"),
                },
            )
            .expect("rotate again");
        assert_eq!(
            issuer.verify_signed_claims(&first_token, 20_003),
            Err(JoinTokenError::InvalidSignature)
        );
    }

    #[test]
    fn e2ee_ingress_lookup_requires_exact_session_scope_and_call_binding() {
        let registry = RealtimeSessionRegistry::default();
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("call")),
                participant(),
                Some(DeviceId::from_opaque(id("device"))),
                300,
                10_000,
            )
            .expect("issue")
            .claims;
        registry.join(claims.clone(), 10_001).expect("join");
        assert_eq!(
            registry
                .active_claims_for_ingress(
                    &claims.session_id,
                    &claims.scope,
                    &claims.call_id,
                    10_002
                )
                .expect("lookup"),
            claims
        );
        assert_eq!(
            registry.active_claims_for_ingress(
                &claims.session_id,
                &claims.scope,
                &CallId::from_opaque(id("other-call")),
                10_002
            ),
            Err(RealtimeRegistryError::SessionUnavailable)
        );
    }

    #[test]
    fn active_session_lookup_distinguishes_first_join_from_reconnect() {
        let registry = RealtimeSessionRegistry::default();
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("call-active-session")),
                participant(),
                Some(DeviceId::from_opaque(id("device-active-session"))),
                300,
                15_000,
            )
            .expect("issue")
            .claims;

        assert!(
            !registry
                .contains_active_session(&claims, 15_001)
                .expect("lookup before join")
        );
        registry.join(claims.clone(), 15_002).expect("join");
        assert!(
            registry
                .contains_active_session(&claims, 15_003)
                .expect("lookup after join")
        );
        assert!(
            !registry
                .contains_active_session(&claims, claims.expires_at_unix_ms)
                .expect("expired lookup")
        );
    }

    #[test]
    fn independent_process_incarnations_use_distinct_randomized_join_fences() {
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("restart-lease-call")),
                participant(),
                Some(DeviceId::from_opaque(id("restart-lease-device"))),
                300,
                18_000,
            )
            .expect("issue")
            .claims;
        let before_restart = RealtimeSessionRegistry::new(8, 4);
        let first = before_restart
            .join(claims.clone(), 18_001)
            .expect("first process");
        let after_restart = RealtimeSessionRegistry::new(8, 4);
        let second = after_restart
            .join(claims.clone(), 18_002)
            .expect("restarted process");
        assert_ne!(first.join_generation, second.join_generation);
        assert!(
            after_restart
                .leave_if_sequence(&claims, first.join_generation, 18_003)
                .is_err(),
            "stale Leave from previous process may not retire the new process's connection"
        );
        after_restart
            .leave_if_sequence(&claims, second.join_generation, 18_004)
            .expect("new incarnation's participant can leave");
    }

    #[test]
    fn leave_then_join_cannot_reuse_removed_lease_generation() {
        let registry = RealtimeSessionRegistry::new(8, 4);
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("leave-rejoin-aba-call")),
                participant(),
                Some(DeviceId::from_opaque(id("leave-rejoin-aba-device"))),
                300,
                18_000,
            )
            .expect("issue")
            .claims;
        let first = registry.join(claims.clone(), 18_001).expect("first");
        registry
            .leave_if_sequence(&claims, first.join_generation, 18_002)
            .expect("leave");
        let second = registry.join(claims.clone(), 18_003).expect("fresh Join");
        assert_ne!(first.join_generation, second.join_generation);
        assert!(
            registry
                .leave_if_sequence(&claims, first.join_generation, 18_004)
                .is_err()
        );
        registry
            .leave_if_sequence(&claims, second.join_generation, 18_005)
            .expect("new owner can leave");
    }

    #[test]
    fn obsolete_join_heartbeat_cannot_revive_reconnected_participant() {
        let registry = RealtimeSessionRegistry::new(8, 4);
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("heartbeat-generation-call")),
                participant(),
                Some(DeviceId::from_opaque(id("heartbeat-generation-device"))),
                300,
                18_000,
            )
            .expect("issue")
            .claims;
        let old = registry.join(claims.clone(), 18_001).expect("old Join");
        let current = registry.join(claims.clone(), 18_002).expect("new Join");
        assert_ne!(old.join_generation, current.join_generation);

        // A delayed heartbeat from the previous browser tab arrives after the
        // new tab's two-minute liveness grace. It must NOT keep the new tab
        // visible or extend its media-receive eligibility.
        let late = 18_002 + CONNECTED_HEARTBEAT_GRACE_MS + 1;
        assert_eq!(
            registry.heartbeat_if_join_generation(&claims, old.join_generation, late),
            Ok(None)
        );
        assert_eq!(
            registry.heartbeat_if_join_generation(&claims, 0, late),
            Ok(None)
        );
        assert!(
            registry
                .connected_call_participants_at(&claims.scope, &claims.call_id, late)
                .expect("current roster")
                .is_empty()
        );

        assert_eq!(
            registry.heartbeat_if_join_generation(&claims, current.join_generation, late + 1),
            Ok(Some(current.transition.session_sequence))
        );
        assert_eq!(
            registry
                .connected_call_participants_at(&claims.scope, &claims.call_id, late + 1)
                .expect("fresh roster")
                .len(),
            1
        );
    }

    #[test]
    fn media_ready_and_downlink_reattachment_do_not_invalidate_leave_generation() {
        let registry = RealtimeSessionRegistry::new(8, 4);
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("stable-lease-call")),
                participant(),
                Some(DeviceId::from_opaque(id("stable-lease-device"))),
                300,
                18_000,
            )
            .expect("issue")
            .claims;
        let joined = registry.join(claims.clone(), 18_001).expect("join");
        let generation = joined.join_generation;
        let media = registry
            .mark_media_ready(&claims, 18_002)
            .expect("media ready")
            .expect("transition");
        assert!(
            media.session_sequence > joined.transition.session_sequence,
            "MediaReady advances attendance, not the Join lease"
        );
        assert_eq!(
            registry
                .current_join_generation(&claims, 18_002)
                .expect("current lease"),
            generation,
            "MediaReady must leave the authenticated Join generation unchanged"
        );
        let receiver = registry
            .take_downlink(&claims, 18_003)
            .expect("initial downlink");
        drop(receiver);
        let attachment = registry.attach_downlink(&claims, 18_004).expect("reattach");
        assert!(
            attachment
                .transition
                .expect("attendance reconnect")
                .session_sequence
                > media.session_sequence
        );
        assert_eq!(
            registry.heartbeat(&claims, 18_005).expect("heartbeat"),
            media.session_sequence + 1,
            "attendance sequence may advance without replacing the Join"
        );
        registry
            .leave_if_sequence(&claims, generation, 18_006)
            .expect("the original Join lease must remain valid");
        assert_eq!(registry.active_session_count(), 0);
    }

    #[test]
    fn delayed_leave_cannot_retire_a_new_connection_generation() {
        let registry = RealtimeSessionRegistry::new(8, 4);
        let claims = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("leave-fence-call")),
                participant(),
                Some(DeviceId::from_opaque(id("leave-fence-device"))),
                300,
                18_000,
            )
            .expect("issue")
            .claims;
        let first = registry.join(claims.clone(), 18_001).expect("first join");
        let second = registry.join(claims.clone(), 18_002).expect("reconnect");
        assert!(second.transition.session_sequence > first.transition.session_sequence);

        assert_eq!(
            registry.leave_if_sequence(&claims, 0, 18_003),
            Err(RealtimeRegistryError::ClaimMismatch),
            "unfenced external Leave must fail closed"
        );
        assert_eq!(
            registry.leave_if_sequence(&claims, first.join_generation, 18_004),
            Err(RealtimeRegistryError::ClaimMismatch),
            "a delayed old Leave must not close a reconnected session"
        );
        assert_eq!(
            registry
                .heartbeat(&claims, 18_005)
                .expect("new session still active"),
            second.transition.session_sequence
        );
        assert_eq!(registry.active_session_count(), 1);

        let retired = registry
            .leave_if_sequence(&claims, second.join_generation, 18_006)
            .expect("current Leave");
        assert_eq!(retired.kind, AttendanceTransitionKind::Left);
        assert_eq!(registry.active_session_count(), 0);
    }

    #[test]
    fn e2ee_egress_lookup_returns_only_exact_active_recipient_sessions() {
        let registry = RealtimeSessionRegistry::default();
        let alice = issuer()
            .issue(
                scope(),
                CallId::from_opaque(id("call-egress")),
                participant(),
                Some(DeviceId::from_opaque(id("alice-device"))),
                300,
                20_000,
            )
            .expect("alice")
            .claims;
        registry.join(alice.clone(), 20_001).expect("join alice");
        let sessions = registry
            .active_session_ids_for_recipient(
                &alice.scope,
                &alice.call_id,
                &alice.participant,
                20_002,
            )
            .expect("sessions");
        assert_eq!(sessions, vec![alice.session_id]);
        assert!(
            registry
                .active_session_ids_for_recipient(
                    &alice.scope,
                    &CallId::from_opaque(id("other-call")),
                    &alice.participant,
                    20_002,
                )
                .expect("other")
                .is_empty()
        );
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
    fn publisher_slots_are_scoped_atomic_idempotent_and_released_by_leave() {
        let now = 28_000;
        let registry = RealtimeSessionRegistry::new(8, 2);
        let base = RealtimeSessionClaims {
            scope: scope(),
            call_id: CallId::from_opaque(id("publisher-call")),
            participant: participant(),
            device_id: Some(DeviceId::from_opaque(id("publisher-device-a"))),
            session_id: SessionId::from_opaque(id("publisher-session-a")),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            use_policy: JoinGrantUsePolicy::Reusable,
        };
        let second = RealtimeSessionClaims {
            participant: PrincipalRef {
                principal_id: PrincipalId::from_opaque(id("publisher-participant-b")),
                kind: PrincipalKind::Person,
            },
            device_id: Some(DeviceId::from_opaque(id("publisher-device-b"))),
            session_id: SessionId::from_opaque(id("publisher-session-b")),
            ..base.clone()
        };
        let third = RealtimeSessionClaims {
            participant: PrincipalRef {
                principal_id: PrincipalId::from_opaque(id("publisher-participant-c")),
                kind: PrincipalKind::Person,
            },
            device_id: Some(DeviceId::from_opaque(id("publisher-device-c"))),
            session_id: SessionId::from_opaque(id("publisher-session-c")),
            ..base.clone()
        };
        registry.join(base.clone(), now).expect("join first");
        registry.join(second.clone(), now).expect("join second");
        registry.join(third.clone(), now).expect("join third");

        let owner_a = service_owner("publisher-owner-a");
        let owner_b = service_owner("publisher-owner-b");
        registry
            .claim_publisher_slot(&base, &owner_a, 1, now + 1)
            .expect("first publisher");
        registry
            .claim_publisher_slot(&base, &owner_a, 1, now + 2)
            .expect("repeat same session is idempotent");
        assert_eq!(
            registry.claim_publisher_slot(&second, &owner_a, 1, now + 3),
            Err(RealtimeRegistryError::CapacityExceeded)
        );
        registry
            .claim_publisher_slot(&third, &owner_b, 1, now + 4)
            .expect("other integration has independent capacity");

        registry.leave(&base, now + 5).expect("leave releases slot");
        registry
            .claim_publisher_slot(&second, &owner_a, 1, now + 6)
            .expect("released owner slot can be reused");
    }

    #[test]
    fn publisher_slots_are_released_by_full_reconnect_and_expiry() {
        let now = 28_500;
        let registry = RealtimeSessionRegistry::new(8, 2);
        let first = RealtimeSessionClaims {
            scope: scope(),
            call_id: CallId::from_opaque(id("publisher-release-call")),
            participant: participant(),
            device_id: Some(DeviceId::from_opaque(id("publisher-release-device-a"))),
            session_id: SessionId::from_opaque(id("publisher-release-session-a")),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 10,
            use_policy: JoinGrantUsePolicy::Reusable,
        };
        let second = RealtimeSessionClaims {
            participant: PrincipalRef {
                principal_id: PrincipalId::from_opaque(id("publisher-release-participant-b")),
                kind: PrincipalKind::Person,
            },
            device_id: Some(DeviceId::from_opaque(id("publisher-release-device-b"))),
            session_id: SessionId::from_opaque(id("publisher-release-session-b")),
            expires_at_unix_ms: now + 60_000,
            ..first.clone()
        };
        let owner = service_owner("publisher-release-owner");

        registry.join(first.clone(), now).expect("join first");
        registry.join(second.clone(), now).expect("join second");
        registry
            .claim_publisher_slot(&first, &owner, 1, now + 1)
            .expect("first publisher");

        registry
            .join(first.clone(), now + 2)
            .expect("full reconnect resets publisher presence");
        registry
            .claim_publisher_slot(&second, &owner, 1, now + 3)
            .expect("reconnect released first slot");
        registry.leave(&second, now + 4).expect("release second");

        registry
            .claim_publisher_slot(&first, &owner, 1, now + 5)
            .expect("first reclaims slot");
        registry
            .join(second.clone(), now + 5)
            .expect("rejoin second");
        registry
            .claim_publisher_slot(&second, &owner, 1, first.expires_at_unix_ms)
            .expect("expiry pruning released first slot");
    }

    #[test]
    fn aggregate_bandwidth_is_integration_scoped_windowed_and_clock_safe() {
        let registry = RealtimeSessionRegistry::new(8, 2);
        let owner_a = service_owner("bandwidth-owner-a");
        let owner_b = service_owner("bandwidth-owner-b");
        let now = 28_000;

        registry
            .charge_aggregate_bandwidth(&owner_a, 16, 1, now + 1)
            .expect("first byte");
        registry
            .charge_aggregate_bandwidth(&owner_a, 16, 1, now + 2)
            .expect("second byte reaches exact ceiling");
        assert_eq!(
            registry.charge_aggregate_bandwidth(&owner_a, 16, 1, now + 3),
            Err(RealtimeRegistryError::CapacityExceeded)
        );
        registry
            .charge_aggregate_bandwidth(&owner_b, 16, 1, now + 4)
            .expect("other integration has independent bandwidth");
        registry
            .charge_aggregate_bandwidth(&owner_a, 16, 1, now + BANDWIDTH_WINDOW_MS)
            .expect("new second resets instantaneous budget");
        registry
            .charge_aggregate_bandwidth(&owner_b, 16, 1, now + 5)
            .expect("another integration's newer window cannot cross-starve this owner");
        assert_eq!(
            registry.charge_aggregate_bandwidth(&owner_a, 16, 1, now + BANDWIDTH_WINDOW_MS - 1,),
            Err(RealtimeRegistryError::ClockRollback)
        );
        assert_eq!(
            registry.charge_aggregate_bandwidth(&owner_a, 7, 1, now + BANDWIDTH_WINDOW_MS + 1),
            Err(RealtimeRegistryError::CapacityExceeded)
        );
    }

    #[test]
    fn explicit_call_cleanup_candidate_is_bounded_idempotent_and_acknowledged() {
        let registry = RealtimeSessionRegistry::with_expired_call_cleanup(1, 1);
        let first_scope = scope();
        let first_call = CallId::from_opaque(id("cleanup-first"));
        registry
            .queue_call_cleanup_candidate(&first_scope, &first_call)
            .expect("queue first cleanup");
        registry
            .queue_call_cleanup_candidate(&first_scope, &first_call)
            .expect("duplicate cleanup is idempotent");
        assert_eq!(
            registry
                .expired_call_cleanup_candidates_at(1_000)
                .expect("pending cleanup"),
            vec![(first_scope.clone(), first_call.clone())]
        );

        assert_eq!(
            registry
                .queue_call_cleanup_candidate(&scope(), &CallId::from_opaque(id("cleanup-second"))),
            Err(RealtimeRegistryError::CapacityExceeded)
        );
        registry
            .acknowledge_expired_call_cleanup(&first_scope, &first_call)
            .expect("ack cleanup");
        assert!(
            registry
                .expired_call_cleanup_candidates_at(1_001)
                .expect("cleanup drained")
                .is_empty()
        );
    }

    #[test]
    fn operator_session_count_prunes_expired_sessions() {
        let issuer = issuer();
        let claims = issuer
            .issue(
                scope(),
                CallId::from_opaque(id("operator-count-call")),
                participant(),
                None,
                300,
                29_000,
            )
            .expect("issue")
            .claims;
        let expires_at = claims.expires_at_unix_ms;
        let registry = RealtimeSessionRegistry::new(8, 2);
        registry.join(claims.clone(), 29_001).expect("join");
        assert_eq!(
            registry.active_claims_at(29_001).expect("active claims"),
            vec![claims.clone()]
        );
        assert_eq!(
            registry
                .active_session_count_at(29_001)
                .expect("active count"),
            1
        );
        assert_eq!(
            registry
                .active_session_count_at(expires_at)
                .expect("expired count"),
            0
        );
        assert!(
            registry
                .active_claims_at(expires_at)
                .expect("expired claims")
                .is_empty()
        );
    }

    #[test]
    fn call_session_count_reuses_registry_and_prunes_expiry() {
        let issuer = issuer();
        let call_id = CallId::from_opaque(id("placement-lifecycle-call"));
        let first = issuer
            .issue(
                scope(),
                call_id.clone(),
                participant(),
                Some(DeviceId::from_opaque(id("placement-device-a"))),
                300,
                29_500,
            )
            .expect("first issue")
            .claims;
        let second = RealtimeSessionClaims {
            device_id: Some(DeviceId::from_opaque(id("placement-device-b"))),
            session_id: SessionId::from_opaque(id("placement-session-b")),
            ..first.clone()
        };
        let other_call = RealtimeSessionClaims {
            call_id: CallId::from_opaque(id("placement-other-call")),
            device_id: Some(DeviceId::from_opaque(id("placement-device-c"))),
            session_id: SessionId::from_opaque(id("placement-session-c")),
            ..first.clone()
        };
        let expires_at = first.expires_at_unix_ms;
        let registry = RealtimeSessionRegistry::new(8, 2);
        registry.join(first.clone(), 29_501).expect("first join");
        registry.join(second, 29_502).expect("second join");
        registry.join(other_call, 29_503).expect("other join");

        assert_eq!(
            registry
                .active_call_session_count_at(&first.scope, &call_id, 29_504)
                .expect("call count"),
            2
        );
        assert_eq!(
            registry
                .active_call_session_count_at(&first.scope, &call_id, expires_at)
                .expect("expired call count"),
            0
        );
    }

    #[test]
    fn ordinary_registry_prunes_expiry_without_creating_sfu_cleanup_state() {
        let now = 29_700;
        let registry = RealtimeSessionRegistry::new(1, 1);
        let claims = RealtimeSessionClaims {
            scope: scope(),
            call_id: CallId::from_opaque(id("ordinary-expiry-call")),
            participant: participant(),
            device_id: None,
            session_id: SessionId::from_opaque(id("ordinary-expiry-session")),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 1,
            use_policy: JoinGrantUsePolicy::Reusable,
        };
        registry.join(claims, now).expect("join");
        assert_eq!(registry.active_session_count_at(now + 1).expect("prune"), 0);
        assert!(
            registry
                .expired_call_cleanup_candidates_at(now + 1)
                .expect("no placement tracking")
                .is_empty()
        );
    }

    #[test]
    fn expired_call_cleanup_candidates_track_only_final_session_and_require_ack() {
        let now = 29_750;
        let registry = RealtimeSessionRegistry::with_expired_call_cleanup(8, 2);
        let first = RealtimeSessionClaims {
            scope: scope(),
            call_id: CallId::from_opaque(id("expiry-cleanup-call")),
            participant: participant(),
            device_id: Some(DeviceId::from_opaque(id("expiry-cleanup-device-a"))),
            session_id: SessionId::from_opaque(id("expiry-cleanup-session-a")),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 10,
            use_policy: JoinGrantUsePolicy::Reusable,
        };
        let sibling = RealtimeSessionClaims {
            device_id: Some(DeviceId::from_opaque(id("expiry-cleanup-device-b"))),
            session_id: SessionId::from_opaque(id("expiry-cleanup-session-b")),
            expires_at_unix_ms: now + 20,
            ..first.clone()
        };
        let other = RealtimeSessionClaims {
            call_id: CallId::from_opaque(id("expiry-cleanup-other-call")),
            device_id: Some(DeviceId::from_opaque(id("expiry-cleanup-device-c"))),
            session_id: SessionId::from_opaque(id("expiry-cleanup-session-c")),
            ..first.clone()
        };
        registry.join(first.clone(), now).expect("join first");
        registry.join(sibling, now).expect("join sibling");
        registry.join(other.clone(), now).expect("join other call");

        let first_sweep = registry
            .expired_call_cleanup_candidates_at(now + 10)
            .expect("first cleanup candidates");
        assert_eq!(first_sweep.len(), 1);
        assert_eq!(first_sweep[0].0, other.scope);
        assert_eq!(first_sweep[0].1, other.call_id);
        assert_eq!(
            registry
                .expired_call_cleanup_candidates_at(now + 11)
                .expect("candidate persists until ack"),
            first_sweep
        );
        registry
            .acknowledge_expired_call_cleanup(&other.scope, &other.call_id)
            .expect("ack other call");
        assert!(
            registry
                .expired_call_cleanup_candidates_at(now + 11)
                .expect("acked cleanup")
                .is_empty()
        );

        let final_sweep = registry
            .expired_call_cleanup_candidates_at(now + 20)
            .expect("final sibling expiry");
        assert_eq!(final_sweep.len(), 1);
        assert_eq!(final_sweep[0].0, first.scope);
        assert_eq!(final_sweep[0].1, first.call_id);
        registry
            .acknowledge_expired_call_cleanup(&first.scope, &first.call_id)
            .expect("ack final call");
        assert!(
            registry
                .expired_call_cleanup_candidates_at(now + 21)
                .expect("cleanup drained")
                .is_empty()
        );
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
    fn connected_roster_forgets_a_tab_that_stops_heartbeating() {
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
        let now = 40_000;
        registry.join(claims.clone(), now).expect("join");
        let live = registry
            .connected_call_participants_at(&claims.scope, &claims.call_id, now)
            .expect("fresh join is live");
        assert!(live.contains(&claims.participant.principal_id));
        let stale = registry
            .connected_call_participants_at(
                &claims.scope,
                &claims.call_id,
                now + CONNECTED_HEARTBEAT_GRACE_MS + 1,
            )
            .expect("stale roster");
        assert!(stale.is_empty());
        registry
            .heartbeat(&claims, now + CONNECTED_HEARTBEAT_GRACE_MS + 1)
            .expect("heartbeat restores liveness");
        let restored = registry
            .connected_call_participants_at(
                &claims.scope,
                &claims.call_id,
                now + CONNECTED_HEARTBEAT_GRACE_MS + 1,
            )
            .expect("restored roster");
        assert!(restored.contains(&claims.participant.principal_id));
    }

    #[test]
    fn adaptive_stage_filters_exact_recipient_sessions() {
        let now = system_now_unix_ms().expect("clock");
        let call_id = CallId::from_opaque(id("adaptive-call"));
        let recipient = participant();
        let registry = RealtimeSessionRegistry::new(8, 2);
        let constrained = RealtimeSessionClaims {
            scope: scope(),
            call_id: call_id.clone(),
            participant: recipient.clone(),
            device_id: Some(DeviceId::from_opaque(id("adaptive-device-a"))),
            session_id: SessionId::from_opaque(id("adaptive-session-a")),
            issued_at_unix_ms: now,
            not_before_unix_ms: now,
            expires_at_unix_ms: now + 60_000,
            use_policy: JoinGrantUsePolicy::Reusable,
        };
        let healthy = RealtimeSessionClaims {
            device_id: Some(DeviceId::from_opaque(id("adaptive-device-b"))),
            session_id: SessionId::from_opaque(id("adaptive-session-b")),
            ..constrained.clone()
        };
        registry
            .join(constrained.clone(), now)
            .expect("constrained join");
        registry.join(healthy.clone(), now).expect("healthy join");
        let mut constrained_downlink = registry
            .take_downlink(&constrained, now)
            .expect("constrained downlink");
        let mut healthy_downlink = registry
            .take_downlink(&healthy, now)
            .expect("healthy downlink");

        registry
            .set_adaptive_media_stage(&constrained, AdaptiveMediaStage::Audio, now)
            .expect("constrained stage");
        registry
            .set_adaptive_media_stage(&healthy, AdaptiveMediaStage::Video1080p, now)
            .expect("healthy stage");

        let frame = envelope(
            call_id,
            PrincipalRef {
                principal_id: PrincipalId::from_opaque(id("adaptive-source")),
                kind: PrincipalKind::Person,
            },
        );
        let target = SfuForwardTarget { recipient };

        registry
            .forward_encrypted(&target, &frame)
            .expect("session-aware fanout");
        assert!(constrained_downlink.try_recv().is_err());
        assert!(healthy_downlink.try_recv().is_ok());

        registry
            .set_adaptive_media_stage(&healthy, AdaptiveMediaStage::EventualFallbackRequired, now)
            .expect("healthy fallback");
        registry
            .forward_encrypted(&target, &frame)
            .expect("intentional suppression is not transport failure");
        assert!(constrained_downlink.try_recv().is_err());
        assert!(healthy_downlink.try_recv().is_err());
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

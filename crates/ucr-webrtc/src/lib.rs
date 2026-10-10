#![forbid(unsafe_code)]

mod e2ee_bridge;
pub use e2ee_bridge::{
    LIVE_WEBRTC_E2EE_INGRESS_CAPACITY, MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES,
    MAX_WEBRTC_E2EE_WIRE_BYTES, WEBRTC_E2EE_DATA_CHANNEL_LABEL, WebRtcE2eeIngressFrame,
    WebRtcE2eeReassembler, WebRtcE2eeWireError, decode_webrtc_e2ee_envelope,
    encode_webrtc_e2ee_chunks, encode_webrtc_e2ee_envelope,
};

use core::fmt;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use ucr_model::{
    IceCredentialType, IceServerConfig, IceTransportPolicy, SessionId, SfuForwardEnvelope,
    WebRtcIceCandidate, WebRtcSessionDescription,
};
use ucr_protocol::{
    CapabilityDescriptor, WebRtcProtocolError, canonical_ice_server, canonical_webrtc_candidate,
    canonical_webrtc_description, phase46_webrtc_capabilities,
};
use ucr_secrets::{ActiveSecretSet, SecretHandle, SecretProvider, SecretPurpose};
use webrtc::{
    api::{
        APIBuilder, interceptor_registry::register_default_interceptors, media_engine::MediaEngine,
    },
    ice_transport::{ice_candidate::RTCIceCandidateInit, ice_server::RTCIceServer},
    interceptor::registry::Registry,
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        policy::ice_transport_policy::RTCIceTransportPolicy,
        sdp::session_description::RTCSessionDescription as EngineSessionDescription,
    },
    rtp_transceiver::rtp_codec::RTPCodecType,
};
use zeroize::ZeroizeOnDrop;

use crate::e2ee_bridge::{LiveWebRtcE2eeChannel, create_live_e2ee_data_channel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcProviderError {
    InvalidProtocol(WebRtcProtocolError),
    SessionUnavailable,
    Conflict,
    CapacityExceeded,
    TemporarilyUnavailable,
    Internal,
}

impl From<WebRtcProtocolError> for WebRtcProviderError {
    fn from(error: WebRtcProtocolError) -> Self {
        Self::InvalidProtocol(error)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WebRtcSessionConfig {
    pub session_id: SessionId,
    pub ice_servers: Vec<IceServerConfig>,
    pub ice_transport_policy: IceTransportPolicy,
}

impl fmt::Debug for WebRtcSessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcSessionConfig")
            .field("session_id", &self.session_id)
            .field("ice_server_count", &self.ice_servers.len())
            .field("ice_transport_policy", &self.ice_transport_policy)
            .finish()
    }
}

pub trait WebRtcProvider: fmt::Debug + Send + Sync {
    /// Returns truthful runtime capability maturity for this provider.
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;

    /// Creates one ephemeral peer-connection session. Canonical Call/Conference state stays
    /// outside this provider.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures.
    fn create_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError>;

    /// Restarts ICE for one existing peer session and returns a fresh local offer.
    ///
    /// The configuration may contain freshly issued TURN credentials for the same authenticated
    /// realtime session. Canonical Call/Conference state is unchanged.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures or `SessionUnavailable` for an unknown session.
    fn restart_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError>;

    /// Returns the immutable original offer identity for this live transport attempt.
    /// ICE restart generates a new SDP but keeps this identity until peer replacement.
    ///
    /// # Errors
    /// Returns `SessionUnavailable` if no matching active transport exists.
    fn session_offer_id(&self, _session_id: &SessionId) -> Result<String, WebRtcProviderError> {
        Err(WebRtcProviderError::SessionUnavailable)
    }

    /// Applies the remote offer/answer for an existing provider session.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures.
    fn set_remote_description(
        &self,
        description: &WebRtcSessionDescription,
    ) -> Result<(), WebRtcProviderError>;

    /// Applies one trickle-ICE candidate.
    ///
    /// # Errors
    /// Returns bounded provider/protocol failures.
    fn add_remote_candidate(
        &self,
        candidate: &WebRtcIceCandidate,
    ) -> Result<(), WebRtcProviderError>;

    /// Applies signaling only to the active transport attempt; never to its successor.
    ///
    /// # Errors
    /// Returns `SessionUnavailable` if the attempt differs or is absent.
    fn set_remote_description_if_offer_matches(
        &self,
        _description: &WebRtcSessionDescription,
        _offer_id: &str,
    ) -> Result<(), WebRtcProviderError> {
        Err(WebRtcProviderError::SessionUnavailable)
    }

    /// Applies an ICE candidate only to its owning transport attempt.
    ///
    /// # Errors
    /// Returns `SessionUnavailable` if the attempt differs or is absent.
    fn add_remote_candidate_if_offer_matches(
        &self,
        _candidate: &WebRtcIceCandidate,
        _offer_id: &str,
    ) -> Result<(), WebRtcProviderError> {
        Err(WebRtcProviderError::SessionUnavailable)
    }

    /// Closes ephemeral provider state. It does not end the canonical Call by itself.
    ///
    /// # Errors
    /// Returns bounded provider failures.
    fn close_session(&self, session_id: &SessionId) -> Result<(), WebRtcProviderError>;

    /// Closes only the transport attempt identified by its original offer.
    /// A delayed close must not tear down a subsequent attempt for the same session.
    ///
    /// # Errors
    /// Returns `SessionUnavailable` when the active attempt differs or is absent.
    fn close_session_if_offer_matches(
        &self,
        _session_id: &SessionId,
        _offer_id: &str,
    ) -> Result<(), WebRtcProviderError> {
        Err(WebRtcProviderError::SessionUnavailable)
    }
}

pub const MIN_TURN_CREDENTIAL_TTL_SECONDS: u32 = 30;
pub const MAX_TURN_CREDENTIAL_TTL_SECONDS: u32 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnCredentialError {
    InvalidTtl,
    ClockOverflow,
    KeyUnavailable,
    CryptoUnavailable,
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct TurnRestSecret([u8; 32]);

impl TurnRestSecret {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for TurnRestSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TurnRestSecret")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IssuedTurnCredential {
    pub username: String,
    pub credential: String,
    pub expires_at_unix_seconds: u64,
}

impl fmt::Debug for IssuedTurnCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTurnCredential")
            .field("username", &"<redacted>")
            .field("credential", &"<redacted>")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

#[derive(Clone)]
enum TurnRestSecretSource {
    Static(TurnRestSecret),
    Provider {
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    },
}

impl fmt::Debug for TurnRestSecretSource {
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

#[derive(Clone)]
pub struct TurnRestCredentialIssuer {
    secret_source: TurnRestSecretSource,
}

impl fmt::Debug for TurnRestCredentialIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnRestCredentialIssuer")
            .field("secret_source", &self.secret_source)
            .finish()
    }
}

impl TurnRestCredentialIssuer {
    #[must_use]
    pub const fn new(secret: TurnRestSecret) -> Self {
        Self {
            secret_source: TurnRestSecretSource::Static(secret),
        }
    }

    /// Creates a TURN REST issuer backed by the shared secret-provider boundary.
    ///
    /// Issuance always reads the provider's current `TurnCredentials` version so rotations become
    /// effective without rebuilding the WebRTC session-config factory. TURN infrastructure must
    /// separately prove overlap/reload semantics before zero-downtime rotation is claimed.
    ///
    /// # Errors
    /// Rejects a non-TURN handle, unavailable/missing provider state, or malformed key material.
    pub fn with_secret_provider(
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    ) -> Result<Self, TurnCredentialError> {
        if handle.purpose != SecretPurpose::TurnCredentials {
            return Err(TurnCredentialError::KeyUnavailable);
        }
        let set = provider
            .active_secret_set(&handle)
            .map_err(|_| TurnCredentialError::KeyUnavailable)?;
        turn_rest_secret_from_active_set(&set)?;
        Ok(Self {
            secret_source: TurnRestSecretSource::Provider { provider, handle },
        })
    }

    fn current_secret(&self) -> Result<TurnRestSecret, TurnCredentialError> {
        match &self.secret_source {
            TurnRestSecretSource::Static(secret) => Ok(secret.clone()),
            TurnRestSecretSource::Provider { provider, handle } => {
                let set = provider
                    .active_secret_set(handle)
                    .map_err(|_| TurnCredentialError::KeyUnavailable)?;
                turn_rest_secret_from_active_set(&set)
            }
        }
    }

    /// Issues coturn TURN REST API compatible time-limited credentials for one realtime session.
    ///
    /// The username embeds the expiry timestamp and canonical session identifier. The credential
    /// is HMAC-SHA1 as required by coturn shared-secret mode. The shared secret never leaves this
    /// issuer and is not persisted by the WebRTC provider.
    ///
    /// # Errors
    /// Returns `InvalidTtl` outside the bounded lifetime, `ClockOverflow` on expiry overflow, or
    /// `CryptoUnavailable` if the platform crypto provider fails.
    pub fn issue(
        &self,
        session_id: &SessionId,
        ttl_seconds: u32,
        now_unix_seconds: u64,
    ) -> Result<IssuedTurnCredential, TurnCredentialError> {
        if !(MIN_TURN_CREDENTIAL_TTL_SECONDS..=MAX_TURN_CREDENTIAL_TTL_SECONDS)
            .contains(&ttl_seconds)
        {
            return Err(TurnCredentialError::InvalidTtl);
        }
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(u64::from(ttl_seconds))
            .ok_or(TurnCredentialError::ClockOverflow)?;
        let username = format!(
            "{expires_at_unix_seconds}:{}",
            session_id.as_opaque().as_str()
        );
        let secret = self.current_secret()?;
        let key = PKey::hmac(&secret.0).map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        let mut signer = Signer::new(MessageDigest::sha1(), &key)
            .map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        signer
            .update(username.as_bytes())
            .map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        let mac = signer
            .sign_to_vec()
            .map_err(|_| TurnCredentialError::CryptoUnavailable)?;
        Ok(IssuedTurnCredential {
            username,
            credential: STANDARD.encode(mac),
            expires_at_unix_seconds,
        })
    }
}

fn turn_rest_secret_from_active_set(
    set: &ActiveSecretSet,
) -> Result<TurnRestSecret, TurnCredentialError> {
    let current = turn_rest_secret_from_material(set.current.material.as_bytes())?;
    if let Some(previous) = &set.previous {
        turn_rest_secret_from_material(previous.material.as_bytes())?;
    }
    Ok(current)
}

/// Validates deployment TURN REST root material against the canonical coturn-safe alphabet.
///
/// UCR intentionally uses a base64url-safe subset so the same bytes can be represented without
/// quoting or control-character ambiguity in coturn configuration and SQL-backed dynamic secrets.
///
/// # Errors
/// Returns `KeyUnavailable` unless the material is exactly 32 bytes of ASCII alphanumeric,
/// '-' or '_'.
pub fn validate_coturn_rest_secret_material(material: &[u8]) -> Result<(), TurnCredentialError> {
    if material.len() != 32
        || !material
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
    {
        return Err(TurnCredentialError::KeyUnavailable);
    }
    Ok(())
}

fn turn_rest_secret_from_material(material: &[u8]) -> Result<TurnRestSecret, TurnCredentialError> {
    validate_coturn_rest_secret_material(material)?;
    let bytes: [u8; 32] = material
        .try_into()
        .map_err(|_| TurnCredentialError::KeyUnavailable)?;
    Ok(TurnRestSecret::from_bytes(bytes))
}

pub const LIVE_WEBRTC_COMMAND_QUEUE_CAPACITY: usize = 256;
pub const LIVE_WEBRTC_MAX_SESSIONS: usize = 1_024;
pub const LIVE_WEBRTC_REQUEST_TIMEOUT_SECONDS: u64 = 20;
pub const LIVE_WEBRTC_ICE_GATHER_TIMEOUT_SECONDS: u64 = 12;

enum LiveWebRtcCommand {
    Create {
        config: WebRtcSessionConfig,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<WebRtcSessionDescription, WebRtcProviderError>>,
    },
    Restart {
        config: WebRtcSessionConfig,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<WebRtcSessionDescription, WebRtcProviderError>>,
    },
    GetOfferId {
        session_id: SessionId,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<String, WebRtcProviderError>>,
    },
    SetRemoteDescription {
        description: WebRtcSessionDescription,
        offer_id: Option<String>,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
    AddRemoteCandidate {
        candidate: WebRtcIceCandidate,
        offer_id: Option<String>,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
    SendE2ee {
        session_id: SessionId,
        envelope: Box<SfuForwardEnvelope>,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
    Close {
        session_id: SessionId,
        offer_id: Option<String>,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
}

pub struct LiveWebRtcProvider {
    command_tx: Option<tokio::sync::mpsc::Sender<LiveWebRtcCommand>>,
    worker: Option<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    request_timeout: Duration,
}

impl fmt::Debug for LiveWebRtcProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveWebRtcProvider")
            .field(
                "command_queue_capacity",
                &LIVE_WEBRTC_COMMAND_QUEUE_CAPACITY,
            )
            .field("max_sessions", &LIVE_WEBRTC_MAX_SESSIONS)
            .finish_non_exhaustive()
    }
}

impl LiveWebRtcProvider {
    /// Starts one isolated Tokio worker that owns all ephemeral peer-connection state.
    ///
    /// Canonical Call/Conference/SFU state never enters this worker. The bounded command queue
    /// prevents synchronous callers from creating an unbounded amount of transport work.
    ///
    /// # Errors
    /// Returns `TemporarilyUnavailable` if the worker runtime cannot be started.
    pub fn new() -> Result<Self, WebRtcProviderError> {
        Self::start(None)
    }

    /// Starts the live peer engine with one bounded ciphertext-only E2EE ingress queue.
    ///
    /// # Errors
    /// Returns a temporary-unavailable error if the isolated worker runtime cannot be started.
    pub fn with_e2ee_ingress(
        ingress_tx: tokio::sync::mpsc::Sender<WebRtcE2eeIngressFrame>,
    ) -> Result<Self, WebRtcProviderError> {
        Self::start(Some(ingress_tx))
    }

    fn start(
        e2ee_ingress: Option<tokio::sync::mpsc::Sender<WebRtcE2eeIngressFrame>>,
    ) -> Result<Self, WebRtcProviderError> {
        let (command_tx, command_rx) =
            tokio::sync::mpsc::channel(LIVE_WEBRTC_COMMAND_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let shutdown_notify = Arc::new(tokio::sync::Notify::new());
        let worker_shutdown_notify = Arc::clone(&shutdown_notify);
        let worker = thread::Builder::new()
            .name("ucr-webrtc-peer-engine".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => {
                        let _ = ready_tx.send(Ok(()));
                        runtime.block_on(run_live_webrtc_worker(
                            command_rx,
                            worker_shutdown,
                            worker_shutdown_notify,
                            e2ee_ingress,
                        ));
                    }
                    Err(_) => {
                        let _ = ready_tx.send(Err(WebRtcProviderError::TemporarilyUnavailable));
                    }
                }
            })
            .map_err(|_| WebRtcProviderError::TemporarilyUnavailable)?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                command_tx: Some(command_tx),
                worker: Some(worker),
                shutdown,
                shutdown_notify,
                request_timeout: Duration::from_secs(LIVE_WEBRTC_REQUEST_TIMEOUT_SECONDS),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                drop(command_tx);
                let _ = worker.join();
                Err(WebRtcProviderError::TemporarilyUnavailable)
            }
        }
    }

    fn request<T>(
        &self,
        command: impl FnOnce(
            std_mpsc::Sender<Result<T, WebRtcProviderError>>,
            Instant,
        ) -> LiveWebRtcCommand,
    ) -> Result<T, WebRtcProviderError> {
        let sender = self
            .command_tx
            .as_ref()
            .ok_or(WebRtcProviderError::TemporarilyUnavailable)?;
        if self.shutdown.load(Ordering::Acquire) {
            return Err(WebRtcProviderError::TemporarilyUnavailable);
        }
        let deadline = Instant::now()
            .checked_add(self.request_timeout)
            .ok_or(WebRtcProviderError::TemporarilyUnavailable)?;
        let (reply_tx, reply_rx) = std_mpsc::channel();
        sender
            .try_send(command(reply_tx, deadline))
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    WebRtcProviderError::CapacityExceeded
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    WebRtcProviderError::TemporarilyUnavailable
                }
            })?;
        reply_rx
            .recv_timeout(self.request_timeout)
            .map_err(|_| WebRtcProviderError::TemporarilyUnavailable)?
    }

    /// Returns whether the isolated peer-engine worker is still available to accept commands.
    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
            && self
                .command_tx
                .as_ref()
                .is_some_and(|sender| !sender.is_closed())
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }

    /// Sends one already-encrypted canonical SFU envelope through the session E2EE `DataChannel`.
    /// No endpoint keys or plaintext enter this provider.
    ///
    /// # Errors
    /// Returns bounded session, backpressure or transport failures.
    pub fn send_e2ee_envelope(
        &self,
        session_id: &SessionId,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), WebRtcProviderError> {
        self.request(|reply, deadline| LiveWebRtcCommand::SendE2ee {
            session_id: session_id.clone(),
            envelope: Box::new(envelope.clone()),
            deadline,
            reply,
        })
    }
}

impl Drop for LiveWebRtcProvider {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.shutdown_notify.notify_one();
        self.command_tx.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl WebRtcProvider for LiveWebRtcProvider {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        // The engine is real, but UCR keeps these capabilities Prepared until public signalling,
        // browser/mobile interoperability and production TURN evidence pass their release gates.
        phase46_webrtc_capabilities()
    }

    fn create_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError> {
        validate_live_config(config)?;
        self.request(|reply, deadline| LiveWebRtcCommand::Create {
            config: config.clone(),
            deadline,
            reply,
        })
    }

    fn restart_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError> {
        validate_live_config(config)?;
        self.request(|reply, deadline| LiveWebRtcCommand::Restart {
            config: config.clone(),
            deadline,
            reply,
        })
    }

    fn session_offer_id(&self, session_id: &SessionId) -> Result<String, WebRtcProviderError> {
        self.request(|reply, deadline| LiveWebRtcCommand::GetOfferId {
            session_id: session_id.clone(),
            deadline,
            reply,
        })
    }

    fn set_remote_description(
        &self,
        description: &WebRtcSessionDescription,
    ) -> Result<(), WebRtcProviderError> {
        let description = canonical_webrtc_description(description)?;
        self.request(|reply, deadline| LiveWebRtcCommand::SetRemoteDescription {
            description,
            offer_id: None,
            deadline,
            reply,
        })
    }

    fn add_remote_candidate(
        &self,
        candidate: &WebRtcIceCandidate,
    ) -> Result<(), WebRtcProviderError> {
        let candidate = canonical_webrtc_candidate(candidate)?;
        self.request(|reply, deadline| LiveWebRtcCommand::AddRemoteCandidate {
            candidate,
            offer_id: None,
            deadline,
            reply,
        })
    }

    fn set_remote_description_if_offer_matches(
        &self,
        description: &WebRtcSessionDescription,
        offer_id: &str,
    ) -> Result<(), WebRtcProviderError> {
        let description = canonical_webrtc_description(description)?;
        self.request(|reply, deadline| LiveWebRtcCommand::SetRemoteDescription {
            description,
            offer_id: Some(offer_id.to_owned()),
            deadline,
            reply,
        })
    }

    fn add_remote_candidate_if_offer_matches(
        &self,
        candidate: &WebRtcIceCandidate,
        offer_id: &str,
    ) -> Result<(), WebRtcProviderError> {
        let candidate = canonical_webrtc_candidate(candidate)?;
        self.request(|reply, deadline| LiveWebRtcCommand::AddRemoteCandidate {
            candidate,
            offer_id: Some(offer_id.to_owned()),
            deadline,
            reply,
        })
    }

    fn close_session(&self, session_id: &SessionId) -> Result<(), WebRtcProviderError> {
        self.request(|reply, deadline| LiveWebRtcCommand::Close {
            session_id: session_id.clone(),
            offer_id: None,
            deadline,
            reply,
        })
    }

    fn close_session_if_offer_matches(
        &self,
        session_id: &SessionId,
        offer_id: &str,
    ) -> Result<(), WebRtcProviderError> {
        if offer_id.is_empty() || offer_id.len() > 64 {
            return Err(WebRtcProviderError::SessionUnavailable);
        }
        self.request(|reply, deadline| LiveWebRtcCommand::Close {
            session_id: session_id.clone(),
            offer_id: Some(offer_id.to_owned()),
            deadline,
            reply,
        })
    }
}

fn validate_live_config(config: &WebRtcSessionConfig) -> Result<(), WebRtcProviderError> {
    if config.ice_servers.len() > ucr_protocol::MAX_ICE_SERVERS {
        return Err(WebRtcProviderError::InvalidProtocol(
            WebRtcProtocolError::TooManyIceServers,
        ));
    }
    for server in &config.ice_servers {
        canonical_ice_server(server)?;
    }
    Ok(())
}

struct LiveWebRtcSession {
    offer_id: String,
    peer_connection: Arc<RTCPeerConnection>,
    e2ee_channel: Option<LiveWebRtcE2eeChannel>,
}

async fn run_live_webrtc_worker(
    mut commands: tokio::sync::mpsc::Receiver<LiveWebRtcCommand>,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    e2ee_ingress: Option<tokio::sync::mpsc::Sender<WebRtcE2eeIngressFrame>>,
) {
    let mut sessions = HashMap::<String, LiveWebRtcSession>::new();
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let command = tokio::select! {
            biased;
            () = shutdown_notify.notified() => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                continue;
            }
            command = commands.recv() => command,
        };
        let Some(command) = command else {
            break;
        };
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        match command {
            LiveWebRtcCommand::Create {
                config,
                deadline,
                reply,
            } => {
                handle_live_create(
                    &mut sessions,
                    &shutdown,
                    e2ee_ingress.as_ref(),
                    config,
                    deadline,
                    reply,
                )
                .await;
            }
            LiveWebRtcCommand::Restart {
                config,
                deadline,
                reply,
            } => handle_live_restart(&sessions, config, deadline, reply).await,
            LiveWebRtcCommand::GetOfferId {
                session_id,
                deadline,
                reply,
            } => {
                let result = if command_expired(deadline) {
                    Err(WebRtcProviderError::TemporarilyUnavailable)
                } else {
                    sessions
                        .get(&session_key(&session_id))
                        .map(|session| session.offer_id.clone())
                        .ok_or(WebRtcProviderError::SessionUnavailable)
                };
                let _ = reply.send(result);
            }
            LiveWebRtcCommand::SetRemoteDescription {
                description,
                offer_id,
                deadline,
                reply,
            } => {
                handle_live_remote_description(&sessions, description, offer_id, deadline, reply)
                    .await;
            }
            LiveWebRtcCommand::AddRemoteCandidate {
                candidate,
                offer_id,
                deadline,
                reply,
            } => {
                handle_live_remote_candidate(&sessions, candidate, offer_id, deadline, reply).await;
            }
            LiveWebRtcCommand::SendE2ee {
                session_id,
                envelope,
                deadline,
                reply,
            } => {
                handle_live_send_e2ee(&mut sessions, session_id, *envelope, deadline, reply).await;
            }
            LiveWebRtcCommand::Close {
                session_id,
                offer_id,
                deadline,
                reply,
            } => handle_live_close(&mut sessions, session_id, offer_id, deadline, reply).await,
        }
    }
    commands.close();
    for (_, session) in sessions {
        let _ = session.peer_connection.close().await;
    }
}

async fn handle_live_create(
    sessions: &mut HashMap<String, LiveWebRtcSession>,
    shutdown: &AtomicBool,
    e2ee_ingress: Option<&tokio::sync::mpsc::Sender<WebRtcE2eeIngressFrame>>,
    config: WebRtcSessionConfig,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<WebRtcSessionDescription, WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let key = session_key(&config.session_id);
    if sessions.contains_key(&key) {
        let _ = reply.send(Err(WebRtcProviderError::Conflict));
        return;
    }
    if sessions.len() >= LIVE_WEBRTC_MAX_SESSIONS {
        let _ = reply.send(Err(WebRtcProviderError::CapacityExceeded));
        return;
    }
    match create_live_peer_connection(&config, e2ee_ingress.cloned()).await {
        Ok((session, description)) => {
            if shutdown.load(Ordering::Acquire) || command_expired(deadline) {
                let _ = session.peer_connection.close().await;
                let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
                return;
            }
            let peer_connection = Arc::clone(&session.peer_connection);
            let mut session = session;
            session.offer_id = webrtc_offer_id(&description.sdp);
            sessions.insert(key.clone(), session);
            if reply.send(Ok(description)).is_err() {
                sessions.remove(&key);
                let _ = peer_connection.close().await;
            }
        }
        Err(error) => {
            let _ = reply.send(Err(error));
        }
    }
}

async fn handle_live_restart(
    sessions: &HashMap<String, LiveWebRtcSession>,
    config: WebRtcSessionConfig,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<WebRtcSessionDescription, WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.get(&session_key(&config.session_id)) {
        Some(session) => restart_live_peer_connection(&session.peer_connection, &config).await,
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

async fn handle_live_remote_description(
    sessions: &HashMap<String, LiveWebRtcSession>,
    description: WebRtcSessionDescription,
    offer_id: Option<String>,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.get(&session_key(&description.session_id)) {
        Some(session) if offer_id.as_deref().is_some_and(|id| id != session.offer_id) => {
            Err(WebRtcProviderError::SessionUnavailable)
        }
        Some(session) => {
            set_engine_remote_description(&session.peer_connection, &description).await
        }
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

async fn handle_live_remote_candidate(
    sessions: &HashMap<String, LiveWebRtcSession>,
    candidate: WebRtcIceCandidate,
    offer_id: Option<String>,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.get(&session_key(&candidate.session_id)) {
        Some(session) if offer_id.as_deref().is_some_and(|id| id != session.offer_id) => {
            Err(WebRtcProviderError::SessionUnavailable)
        }
        Some(session) => add_engine_remote_candidate(&session.peer_connection, &candidate).await,
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

async fn handle_live_send_e2ee(
    sessions: &mut HashMap<String, LiveWebRtcSession>,
    session_id: SessionId,
    envelope: SfuForwardEnvelope,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.get_mut(&session_key(&session_id)) {
        Some(LiveWebRtcSession {
            e2ee_channel: Some(channel),
            ..
        }) => channel.send(&envelope, deadline).await,
        Some(_) | None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

async fn handle_live_close(
    sessions: &mut HashMap<String, LiveWebRtcSession>,
    session_id: SessionId,
    offer_id: Option<String>,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let key = session_key(&session_id);
    if offer_id.as_deref().is_some_and(|expected| {
        sessions
            .get(&key)
            .is_none_or(|current| current.offer_id != expected)
    }) {
        let _ = reply.send(Err(WebRtcProviderError::SessionUnavailable));
        return;
    }
    let result = match sessions.remove(&key) {
        Some(session) => session
            .peer_connection
            .close()
            .await
            .map_err(|_| WebRtcProviderError::Internal),
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

/// Stable opaque identifier derived from the server's unique original SDP offer.
/// It is a fencing value, not a bearer credential or an authorization grant.
#[must_use]
pub fn webrtc_offer_id(sdp: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(openssl::sha::sha256(sdp.as_bytes()))
}

fn command_expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

async fn create_live_peer_connection(
    config: &WebRtcSessionConfig,
    e2ee_ingress: Option<tokio::sync::mpsc::Sender<WebRtcE2eeIngressFrame>>,
) -> Result<(LiveWebRtcSession, WebRtcSessionDescription), WebRtcProviderError> {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .map_err(|_| WebRtcProviderError::Internal)?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)
        .map_err(|_| WebRtcProviderError::Internal)?;
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    let engine_config = RTCConfiguration {
        ice_servers: config
            .ice_servers
            .iter()
            .map(engine_ice_server)
            .collect::<Vec<_>>(),
        ice_transport_policy: match config.ice_transport_policy {
            IceTransportPolicy::All => RTCIceTransportPolicy::All,
            IceTransportPolicy::RelayOnly => RTCIceTransportPolicy::Relay,
        },
        ..Default::default()
    };
    let peer_connection = Arc::new(
        api.new_peer_connection(engine_config)
            .await
            .map_err(|_| WebRtcProviderError::TemporarilyUnavailable)?,
    );

    let e2ee_channel = match e2ee_ingress {
        Some(ingress_tx) => Some(
            create_live_e2ee_data_channel(&peer_connection, &config.session_id, ingress_tx).await?,
        ),
        None => None,
    };

    let result = async {
        peer_connection
            .add_transceiver_from_kind(RTPCodecType::Audio, None)
            .await
            .map_err(|_| WebRtcProviderError::Internal)?;
        peer_connection
            .add_transceiver_from_kind(RTPCodecType::Video, None)
            .await
            .map_err(|_| WebRtcProviderError::Internal)?;
        let offer = peer_connection
            .create_offer(None)
            .await
            .map_err(|_| WebRtcProviderError::Internal)?;
        let mut gathering_complete = peer_connection.gathering_complete_promise().await;
        peer_connection
            .set_local_description(offer)
            .await
            .map_err(|_| WebRtcProviderError::Internal)?;
        tokio::time::timeout(
            Duration::from_secs(LIVE_WEBRTC_ICE_GATHER_TIMEOUT_SECONDS),
            gathering_complete.recv(),
        )
        .await
        .map_err(|_| WebRtcProviderError::TemporarilyUnavailable)?;
        let local = peer_connection
            .local_description()
            .await
            .ok_or(WebRtcProviderError::Internal)?;
        Ok(WebRtcSessionDescription {
            session_id: config.session_id.clone(),
            sdp_type: ucr_model::WebRtcSdpType::Offer,
            sdp: local.sdp,
        })
    }
    .await;

    match result {
        Ok(description) => Ok((
            LiveWebRtcSession {
                offer_id: String::new(),
                peer_connection,
                e2ee_channel,
            },
            description,
        )),
        Err(error) => {
            let _ = peer_connection.close().await;
            Err(error)
        }
    }
}

async fn restart_live_peer_connection(
    peer_connection: &RTCPeerConnection,
    config: &WebRtcSessionConfig,
) -> Result<WebRtcSessionDescription, WebRtcProviderError> {
    peer_connection
        .set_configuration(RTCConfiguration {
            ice_servers: config
                .ice_servers
                .iter()
                .map(engine_ice_server)
                .collect::<Vec<_>>(),
            ice_transport_policy: match config.ice_transport_policy {
                IceTransportPolicy::All => RTCIceTransportPolicy::All,
                IceTransportPolicy::RelayOnly => RTCIceTransportPolicy::Relay,
            },
            ..Default::default()
        })
        .await
        .map_err(|_| WebRtcProviderError::Conflict)?;
    peer_connection
        .restart_ice()
        .await
        .map_err(|_| WebRtcProviderError::TemporarilyUnavailable)?;
    let offer = peer_connection
        .create_offer(None)
        .await
        .map_err(|_| WebRtcProviderError::Internal)?;
    let mut gathering_complete = peer_connection.gathering_complete_promise().await;
    peer_connection
        .set_local_description(offer)
        .await
        .map_err(|_| WebRtcProviderError::Conflict)?;
    tokio::time::timeout(
        Duration::from_secs(LIVE_WEBRTC_ICE_GATHER_TIMEOUT_SECONDS),
        gathering_complete.recv(),
    )
    .await
    .map_err(|_| WebRtcProviderError::TemporarilyUnavailable)?;
    let local = peer_connection
        .local_description()
        .await
        .ok_or(WebRtcProviderError::Internal)?;
    Ok(WebRtcSessionDescription {
        session_id: config.session_id.clone(),
        sdp_type: ucr_model::WebRtcSdpType::Offer,
        sdp: local.sdp,
    })
}

fn engine_ice_server(server: &IceServerConfig) -> RTCIceServer {
    RTCIceServer {
        urls: server.urls.clone(),
        username: server.username.clone().unwrap_or_default(),
        credential: server.credential.clone().unwrap_or_default(),
    }
}

async fn set_engine_remote_description(
    peer_connection: &RTCPeerConnection,
    description: &WebRtcSessionDescription,
) -> Result<(), WebRtcProviderError> {
    let engine_description = match description.sdp_type {
        ucr_model::WebRtcSdpType::Offer => EngineSessionDescription::offer(description.sdp.clone()),
        ucr_model::WebRtcSdpType::Answer => {
            EngineSessionDescription::answer(description.sdp.clone())
        }
    }
    .map_err(|_| WebRtcProviderError::InvalidProtocol(WebRtcProtocolError::InvalidSdp))?;
    peer_connection
        .set_remote_description(engine_description)
        .await
        .map_err(|_| WebRtcProviderError::Conflict)
}

async fn add_engine_remote_candidate(
    peer_connection: &RTCPeerConnection,
    candidate: &WebRtcIceCandidate,
) -> Result<(), WebRtcProviderError> {
    peer_connection
        .add_ice_candidate(RTCIceCandidateInit {
            candidate: candidate.candidate.clone(),
            sdp_mid: candidate.sdp_mid.clone(),
            sdp_mline_index: candidate.sdp_mline_index,
            ..Default::default()
        })
        .await
        .map_err(|_| WebRtcProviderError::Conflict)
}

fn session_key(session_id: &SessionId) -> String {
    session_id.as_opaque().as_str().to_owned()
}

#[derive(Clone)]
pub struct WebRtcSessionConfigFactory {
    stun_urls: Vec<String>,
    turn_urls: Vec<String>,
    turn_issuer: Option<TurnRestCredentialIssuer>,
    turn_ttl_seconds: u32,
    ice_transport_policy: IceTransportPolicy,
}

impl fmt::Debug for WebRtcSessionConfigFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcSessionConfigFactory")
            .field("stun_server_count", &self.stun_urls.len())
            .field("turn_server_count", &self.turn_urls.len())
            .field("has_turn_issuer", &self.turn_issuer.is_some())
            .field("turn_ttl_seconds", &self.turn_ttl_seconds)
            .field("ice_transport_policy", &self.ice_transport_policy)
            .finish()
    }
}

impl Default for WebRtcSessionConfigFactory {
    fn default() -> Self {
        Self {
            stun_urls: Vec::new(),
            turn_urls: Vec::new(),
            turn_issuer: None,
            turn_ttl_seconds: 300,
            ice_transport_policy: IceTransportPolicy::All,
        }
    }
}

impl WebRtcSessionConfigFactory {
    /// Validates deployment ICE settings once, while keeping TURN credentials session-bound.
    ///
    /// # Errors
    /// Rejects invalid STUN/TURN URLs, excessive server counts, inconsistent TURN-secret
    /// configuration or a TURN credential lifetime outside the bounded policy.
    pub fn new(
        stun_urls: Vec<String>,
        turn_urls: Vec<String>,
        turn_issuer: Option<TurnRestCredentialIssuer>,
        turn_ttl_seconds: u32,
        ice_transport_policy: IceTransportPolicy,
    ) -> Result<Self, WebRtcProviderError> {
        if stun_urls.len().saturating_add(turn_urls.len()) > ucr_protocol::MAX_ICE_SERVERS {
            return Err(WebRtcProviderError::InvalidProtocol(
                WebRtcProtocolError::TooManyIceServers,
            ));
        }
        if turn_urls.is_empty() != turn_issuer.is_none() {
            return Err(WebRtcProviderError::InvalidProtocol(
                WebRtcProtocolError::InvalidIceCredential,
            ));
        }
        if !turn_urls.is_empty()
            && !(MIN_TURN_CREDENTIAL_TTL_SECONDS..=MAX_TURN_CREDENTIAL_TTL_SECONDS)
                .contains(&turn_ttl_seconds)
        {
            return Err(WebRtcProviderError::InvalidProtocol(
                WebRtcProtocolError::InvalidIceCredential,
            ));
        }
        for url in &stun_urls {
            canonical_ice_server(&IceServerConfig {
                urls: vec![url.clone()],
                username: None,
                credential: None,
                credential_type: IceCredentialType::Password,
            })?;
        }
        for url in &turn_urls {
            canonical_ice_server(&IceServerConfig {
                urls: vec![url.clone()],
                username: Some("validation".to_owned()),
                credential: Some("validation".to_owned()),
                credential_type: IceCredentialType::Password,
            })?;
        }
        Ok(Self {
            stun_urls,
            turn_urls,
            turn_issuer,
            turn_ttl_seconds,
            ice_transport_policy,
        })
    }

    #[must_use]
    pub fn has_turn(&self) -> bool {
        !self.turn_urls.is_empty() && self.turn_issuer.is_some()
    }

    /// Creates one ephemeral ICE configuration for the authenticated realtime session.
    ///
    /// # Errors
    /// Returns bounded TURN issuance or protocol failures without persisting generated credentials.
    pub fn session_config(
        &self,
        session_id: &SessionId,
        now_unix_seconds: u64,
    ) -> Result<WebRtcSessionConfig, WebRtcProviderError> {
        self.session_config_with_turn_ttl(session_id, now_unix_seconds, self.turn_ttl_seconds)
    }

    /// Creates one ephemeral ICE configuration whose TURN credential cannot outlive the
    /// authenticated realtime session.
    ///
    /// # Errors
    /// Refuses TURN issuance when the realtime session is expired or has less than the minimum
    /// credential lifetime remaining.
    pub fn session_config_until(
        &self,
        session_id: &SessionId,
        now_unix_seconds: u64,
        session_expires_at_unix_seconds: u64,
    ) -> Result<WebRtcSessionConfig, WebRtcProviderError> {
        if self.turn_issuer.is_none() {
            return self.session_config(session_id, now_unix_seconds);
        }
        let remaining = session_expires_at_unix_seconds
            .checked_sub(now_unix_seconds)
            .ok_or(WebRtcProviderError::TemporarilyUnavailable)?;
        let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
        let effective_ttl = self.turn_ttl_seconds.min(remaining);
        if effective_ttl < MIN_TURN_CREDENTIAL_TTL_SECONDS {
            return Err(WebRtcProviderError::TemporarilyUnavailable);
        }
        self.session_config_with_turn_ttl(session_id, now_unix_seconds, effective_ttl)
    }

    fn session_config_with_turn_ttl(
        &self,
        session_id: &SessionId,
        now_unix_seconds: u64,
        turn_ttl_seconds: u32,
    ) -> Result<WebRtcSessionConfig, WebRtcProviderError> {
        let mut ice_servers = Vec::with_capacity(self.stun_urls.len() + self.turn_urls.len());
        for url in &self.stun_urls {
            ice_servers.push(IceServerConfig {
                urls: vec![url.clone()],
                username: None,
                credential: None,
                credential_type: IceCredentialType::Password,
            });
        }
        if let Some(issuer) = &self.turn_issuer {
            let issued = issuer
                .issue(session_id, turn_ttl_seconds, now_unix_seconds)
                .map_err(map_turn_credential_error)?;
            for url in &self.turn_urls {
                ice_servers.push(IceServerConfig {
                    urls: vec![url.clone()],
                    username: Some(issued.username.clone()),
                    credential: Some(issued.credential.clone()),
                    credential_type: IceCredentialType::Password,
                });
            }
        }
        Ok(WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers,
            ice_transport_policy: self.ice_transport_policy,
        })
    }
}

const fn map_turn_credential_error(error: TurnCredentialError) -> WebRtcProviderError {
    match error {
        TurnCredentialError::InvalidTtl => {
            WebRtcProviderError::InvalidProtocol(WebRtcProtocolError::InvalidIceCredential)
        }
        TurnCredentialError::KeyUnavailable => WebRtcProviderError::TemporarilyUnavailable,
        TurnCredentialError::ClockOverflow | TurnCredentialError::CryptoUnavailable => {
            WebRtcProviderError::Internal
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedWebRtcProvider;

impl WebRtcProvider for PreparedWebRtcProvider {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        phase46_webrtc_capabilities()
    }

    fn create_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError> {
        if config.ice_servers.len() > ucr_protocol::MAX_ICE_SERVERS {
            return Err(WebRtcProviderError::InvalidProtocol(
                WebRtcProtocolError::TooManyIceServers,
            ));
        }
        for server in &config.ice_servers {
            canonical_ice_server(server)?;
        }
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn restart_session(
        &self,
        config: &WebRtcSessionConfig,
    ) -> Result<WebRtcSessionDescription, WebRtcProviderError> {
        validate_live_config(config)?;
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn set_remote_description(
        &self,
        description: &WebRtcSessionDescription,
    ) -> Result<(), WebRtcProviderError> {
        canonical_webrtc_description(description)?;
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn add_remote_candidate(
        &self,
        candidate: &WebRtcIceCandidate,
    ) -> Result<(), WebRtcProviderError> {
        canonical_webrtc_candidate(candidate)?;
        Err(WebRtcProviderError::TemporarilyUnavailable)
    }

    fn close_session(&self, _session_id: &SessionId) -> Result<(), WebRtcProviderError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{IceCredentialType, OpaqueId};
    use ucr_protocol::{CapabilityMaturity, WEBRTC_BROWSER_CAPABILITY};
    use ucr_secrets::{
        InMemorySecretProvider, SecretHandle, SecretMaterial, SecretProvider, SecretPurpose,
        SecretVersion,
    };

    #[test]
    fn turn_rest_credentials_are_short_lived_session_bound_and_redacted() {
        let session_id = SessionId::from_opaque(OpaqueId::new("session").expect("id"));
        let issuer = TurnRestCredentialIssuer::new(TurnRestSecret::from_bytes([7_u8; 32]));
        let first = issuer.issue(&session_id, 300, 1_000).expect("issue");
        let second = issuer.issue(&session_id, 300, 1_000).expect("issue");
        assert_eq!(first, second);
        assert_eq!(first.expires_at_unix_seconds, 1_300);
        assert_eq!(first.username, "1300:session");
        assert!(!first.credential.is_empty());
        let debug = format!("{first:?}");
        assert!(!debug.contains(&first.username));
        assert!(!debug.contains("session"));
        assert!(!debug.contains(&first.credential));
        assert!(!format!("{issuer:?}").contains("AAAAAAAA"));
        assert_eq!(
            issuer.issue(&session_id, MIN_TURN_CREDENTIAL_TTL_SECONDS - 1, 1_000),
            Err(TurnCredentialError::InvalidTtl)
        );
        assert_eq!(
            issuer.issue(&session_id, MAX_TURN_CREDENTIAL_TTL_SECONDS + 1, 1_000),
            Err(TurnCredentialError::InvalidTtl)
        );
    }

    #[test]
    fn turn_provider_rotation_changes_new_credentials_without_static_secret_fallback() {
        let provider = Arc::new(InMemorySecretProvider::default());
        let handle = SecretHandle {
            secret_id: OpaqueId::new("turn-root").expect("id"),
            purpose: SecretPurpose::TurnCredentials,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("v1").expect("version"),
                    material: SecretMaterial::new(vec![b'A'; 32]).expect("secret"),
                },
            )
            .expect("provision");
        let issuer =
            TurnRestCredentialIssuer::with_secret_provider(provider.clone(), handle.clone())
                .expect("provider issuer");
        let session_id =
            SessionId::from_opaque(OpaqueId::new("provider-session").expect("session"));
        let first = issuer
            .issue(&session_id, 300, 1_000)
            .expect("v1 credential");

        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: OpaqueId::new("v2").expect("version"),
                    material: SecretMaterial::new(vec![b'B'; 32]).expect("secret"),
                },
            )
            .expect("rotate");
        let second = issuer
            .issue(&session_id, 300, 1_000)
            .expect("v2 credential");

        assert_eq!(first.username, second.username);
        assert_ne!(first.credential, second.credential);
        assert!(!format!("{issuer:?}").contains("07070707"));
        assert!(matches!(
            TurnRestCredentialIssuer::with_secret_provider(
                provider,
                SecretHandle {
                    secret_id: OpaqueId::new("turn-root").expect("id"),
                    purpose: SecretPurpose::JoinSigning,
                },
            ),
            Err(TurnCredentialError::KeyUnavailable)
        ));
    }

    #[test]
    fn coturn_provider_material_uses_unambiguous_base64url_safe_alphabet() {
        assert_eq!(
            validate_coturn_rest_secret_material(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Ok(())
        );
        assert_eq!(
            validate_coturn_rest_secret_material(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"),
            Err(TurnCredentialError::KeyUnavailable)
        );
        assert_eq!(
            validate_coturn_rest_secret_material(b"short"),
            Err(TurnCredentialError::KeyUnavailable)
        );
    }

    #[test]
    fn turn_provider_rejects_non_textual_or_mixed_overlap_roots() {
        let provider = Arc::new(InMemorySecretProvider::default());
        let handle = SecretHandle {
            secret_id: OpaqueId::new("turn-portability").expect("id"),
            purpose: SecretPurpose::TurnCredentials,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("binary").expect("version"),
                    material: SecretMaterial::new(vec![7_u8; 32]).expect("secret"),
                },
            )
            .expect("provision");
        assert!(matches!(
            TurnRestCredentialIssuer::with_secret_provider(provider.clone(), handle.clone()),
            Err(TurnCredentialError::KeyUnavailable)
        ));

        provider
            .rotate(
                &handle,
                SecretVersion {
                    version_id: OpaqueId::new("portable").expect("version"),
                    material: SecretMaterial::new(vec![b'C'; 32]).expect("secret"),
                },
            )
            .expect("rotate");
        assert!(matches!(
            TurnRestCredentialIssuer::with_secret_provider(provider, handle),
            Err(TurnCredentialError::KeyUnavailable)
        ));
    }

    #[test]
    fn expired_queued_create_cannot_leave_an_orphan_session() {
        let provider = LiveWebRtcProvider::new().expect("live provider");
        let session_id = SessionId::from_opaque(OpaqueId::new("expired-session").expect("id"));
        let config = WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        };
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("expired deadline");
        let (reply_tx, reply_rx) = std_mpsc::channel();
        provider
            .command_tx
            .as_ref()
            .expect("command sender")
            .try_send(LiveWebRtcCommand::Create {
                config: config.clone(),
                deadline: expired,
                reply: reply_tx,
            })
            .expect("queue expired create");
        assert_eq!(
            reply_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("expired response"),
            Err(WebRtcProviderError::TemporarilyUnavailable)
        );

        let offer = provider.create_session(&config).expect("retry live offer");
        assert_eq!(offer.session_id, session_id);
        assert_eq!(provider.close_session(&session_id), Ok(()));
    }

    #[test]
    fn shutdown_flag_bypasses_buffered_commands() {
        let mut provider = LiveWebRtcProvider::new().expect("live provider");
        let sender = provider
            .command_tx
            .as_ref()
            .expect("command sender")
            .clone();
        let deadline = Instant::now()
            .checked_add(Duration::from_mins(1))
            .expect("future deadline");
        for index in 0..LIVE_WEBRTC_COMMAND_QUEUE_CAPACITY {
            let (reply, _receiver) = std_mpsc::channel();
            let session_id =
                SessionId::from_opaque(OpaqueId::new(format!("queued-{index}")).expect("id"));
            match sender.try_send(LiveWebRtcCommand::Close {
                session_id,
                offer_id: None,
                deadline,
                reply,
            }) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => break,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    panic!("worker closed unexpectedly")
                }
            }
        }
        provider.shutdown.store(true, Ordering::Release);
        provider.shutdown_notify.notify_one();
        provider.command_tx.take();
        let worker = provider.worker.take().expect("worker");
        let started = Instant::now();
        worker.join().expect("worker shutdown");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn live_provider_creates_audio_video_offer_and_closes_ephemeral_session() {
        let provider = LiveWebRtcProvider::new().expect("live provider");
        assert!(provider.is_available());
        let session_id = SessionId::from_opaque(OpaqueId::new("live-session").expect("id"));
        let config = WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        };
        let offer = provider.create_session(&config).expect("live offer");
        assert_eq!(offer.session_id, session_id);
        assert_eq!(offer.sdp_type, ucr_model::WebRtcSdpType::Offer);
        assert!(offer.sdp.starts_with("v=0"));
        assert!(offer.sdp.contains("m=audio"));
        assert!(offer.sdp.contains("m=video"));
        let original_offer_id = webrtc_offer_id(&offer.sdp);
        assert_eq!(
            provider.close_session_if_offer_matches(&session_id, "old-attempt"),
            Err(WebRtcProviderError::SessionUnavailable)
        );
        assert_eq!(
            provider.create_session(&config),
            Err(WebRtcProviderError::Conflict),
            "stale close must preserve the current peer"
        );
        assert_eq!(
            provider.close_session_if_offer_matches(&session_id, &original_offer_id),
            Ok(())
        );
        let replacement = provider.create_session(&config).expect("replacement peer");
        assert_ne!(webrtc_offer_id(&replacement.sdp), original_offer_id);
        assert_eq!(
            provider.set_remote_description_if_offer_matches(&replacement, &original_offer_id),
            Err(WebRtcProviderError::SessionUnavailable),
            "stale SDP cannot mutate the replacement peer"
        );
        assert_eq!(
            provider.create_session(&config),
            Err(WebRtcProviderError::Conflict),
            "rejected stale SDP must preserve the replacement peer"
        );
        assert_eq!(
            provider.close_session_if_offer_matches(&session_id, &original_offer_id),
            Err(WebRtcProviderError::SessionUnavailable),
            "late old close cannot delete replacement session"
        );
        assert_eq!(
            provider
                .close_session_if_offer_matches(&session_id, &webrtc_offer_id(&replacement.sdp)),
            Ok(())
        );
        assert_eq!(
            provider.close_session(&session_id),
            Err(WebRtcProviderError::SessionUnavailable)
        );
    }

    #[test]
    fn live_provider_ice_restart_preserves_session_and_emits_fresh_offer() {
        let provider = LiveWebRtcProvider::new().expect("live provider");
        let session_id = SessionId::from_opaque(OpaqueId::new("restart-session").expect("id"));
        let config = WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        };
        let initial = provider.create_session(&config).expect("initial offer");
        let offer_id = provider
            .session_offer_id(&session_id)
            .expect("original offer ID");
        assert_eq!(offer_id, webrtc_offer_id(&initial.sdp));
        let restarted = provider.restart_session(&config).expect("restart offer");
        assert_eq!(provider.session_offer_id(&session_id), Ok(offer_id.clone()));
        assert_eq!(restarted.session_id, session_id);
        assert_eq!(restarted.sdp_type, ucr_model::WebRtcSdpType::Offer);
        assert!(restarted.sdp.starts_with("v=0"));
        assert_ne!(initial.sdp, restarted.sdp);
        assert_ne!(offer_id, webrtc_offer_id(&restarted.sdp));
        assert_eq!(
            provider.close_session_if_offer_matches(&session_id, &offer_id),
            Ok(())
        );
    }

    #[test]
    fn session_config_factory_issues_fresh_session_bound_turn_credentials() {
        let factory = WebRtcSessionConfigFactory::new(
            vec!["stun:stun.example.test:3478".to_owned()],
            vec!["turns:turn.example.test:5349?transport=tcp".to_owned()],
            Some(TurnRestCredentialIssuer::new(TurnRestSecret::from_bytes(
                [9_u8; 32],
            ))),
            300,
            IceTransportPolicy::RelayOnly,
        )
        .expect("factory");
        let first_session =
            SessionId::from_opaque(OpaqueId::new("session-a").expect("first session"));
        let second_session =
            SessionId::from_opaque(OpaqueId::new("session-b").expect("second session"));
        let first = factory
            .session_config(&first_session, 1_000)
            .expect("first config");
        let second = factory
            .session_config(&second_session, 1_000)
            .expect("second config");
        assert_eq!(first.ice_servers.len(), 2);
        assert_eq!(first.ice_transport_policy, IceTransportPolicy::RelayOnly);
        assert_eq!(first.ice_servers[0].username, None);
        assert_ne!(
            first.ice_servers[1].username,
            second.ice_servers[1].username
        );
        assert_ne!(
            first.ice_servers[1].credential,
            second.ice_servers[1].credential
        );
        assert!(!format!("{factory:?}").contains("09090909"));
    }

    #[test]
    fn turn_credentials_never_outlive_authenticated_realtime_session() {
        let factory = WebRtcSessionConfigFactory::new(
            Vec::new(),
            vec!["turn:turn.example.test:3478?transport=udp".to_owned()],
            Some(TurnRestCredentialIssuer::new(TurnRestSecret::from_bytes(
                [7_u8; 32],
            ))),
            300,
            IceTransportPolicy::All,
        )
        .expect("factory");
        let session = SessionId::from_opaque(OpaqueId::new("bounded-session").expect("session"));
        let config = factory
            .session_config_until(&session, 1_000, 1_090)
            .expect("bounded config");
        assert_eq!(
            config.ice_servers[0].username.as_deref(),
            Some("1090:bounded-session")
        );
        assert_eq!(
            factory.session_config_until(&session, 1_000, 1_020),
            Err(WebRtcProviderError::TemporarilyUnavailable)
        );
    }

    #[test]
    fn prepared_provider_is_truthful_and_never_claims_live_transport() {
        let provider = PreparedWebRtcProvider;
        let capabilities = provider.current_capabilities();
        assert!(capabilities.iter().any(|capability| {
            capability.id == WEBRTC_BROWSER_CAPABILITY
                && capability.maturity == CapabilityMaturity::Prepared
        }));
        let config = WebRtcSessionConfig {
            session_id: SessionId::from_opaque(OpaqueId::new("session").expect("id")),
            ice_servers: vec![IceServerConfig {
                urls: vec!["stun:stun.example.test:3478".to_owned()],
                username: None,
                credential: None,
                credential_type: IceCredentialType::Password,
            }],
            ice_transport_policy: IceTransportPolicy::All,
        };
        assert_eq!(
            provider.create_session(&config),
            Err(WebRtcProviderError::TemporarilyUnavailable)
        );
    }
}

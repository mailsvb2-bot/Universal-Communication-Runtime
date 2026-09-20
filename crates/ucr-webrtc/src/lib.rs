#![forbid(unsafe_code)]

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
    IceCredentialType, IceServerConfig, IceTransportPolicy, SessionId, WebRtcIceCandidate,
    WebRtcSessionDescription,
};
use ucr_protocol::{
    CapabilityDescriptor, WebRtcProtocolError, canonical_ice_server, canonical_webrtc_candidate,
    canonical_webrtc_description, phase46_webrtc_capabilities,
};
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

    /// Closes ephemeral provider state. It does not end the canonical Call by itself.
    ///
    /// # Errors
    /// Returns bounded provider failures.
    fn close_session(&self, session_id: &SessionId) -> Result<(), WebRtcProviderError>;
}

pub const MIN_TURN_CREDENTIAL_TTL_SECONDS: u32 = 30;
pub const MAX_TURN_CREDENTIAL_TTL_SECONDS: u32 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnCredentialError {
    InvalidTtl,
    ClockOverflow,
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
pub struct TurnRestCredentialIssuer {
    secret: TurnRestSecret,
}

impl fmt::Debug for TurnRestCredentialIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnRestCredentialIssuer")
            .finish_non_exhaustive()
    }
}

impl TurnRestCredentialIssuer {
    #[must_use]
    pub const fn new(secret: TurnRestSecret) -> Self {
        Self { secret }
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
        let key = PKey::hmac(&self.secret.0).map_err(|_| TurnCredentialError::CryptoUnavailable)?;
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
    SetRemoteDescription {
        description: WebRtcSessionDescription,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
    AddRemoteCandidate {
        candidate: WebRtcIceCandidate,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
    Close {
        session_id: SessionId,
        deadline: Instant,
        reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
    },
}

pub struct LiveWebRtcProvider {
    command_tx: Option<tokio::sync::mpsc::Sender<LiveWebRtcCommand>>,
    worker: Option<thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
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
        let (command_tx, command_rx) =
            tokio::sync::mpsc::channel(LIVE_WEBRTC_COMMAND_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
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
                        runtime.block_on(run_live_webrtc_worker(command_rx, worker_shutdown));
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
}

impl Drop for LiveWebRtcProvider {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
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

    fn set_remote_description(
        &self,
        description: &WebRtcSessionDescription,
    ) -> Result<(), WebRtcProviderError> {
        let description = canonical_webrtc_description(description)?;
        self.request(|reply, deadline| LiveWebRtcCommand::SetRemoteDescription {
            description,
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
            deadline,
            reply,
        })
    }

    fn close_session(&self, session_id: &SessionId) -> Result<(), WebRtcProviderError> {
        self.request(|reply, deadline| LiveWebRtcCommand::Close {
            session_id: session_id.clone(),
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

async fn run_live_webrtc_worker(
    mut commands: tokio::sync::mpsc::Receiver<LiveWebRtcCommand>,
    shutdown: Arc<AtomicBool>,
) {
    let mut sessions = HashMap::<String, Arc<RTCPeerConnection>>::new();
    while !shutdown.load(Ordering::Acquire) {
        let Some(command) = commands.recv().await else {
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
            } => handle_live_create(&mut sessions, &shutdown, config, deadline, reply).await,
            LiveWebRtcCommand::SetRemoteDescription {
                description,
                deadline,
                reply,
            } => handle_live_remote_description(&sessions, description, deadline, reply).await,
            LiveWebRtcCommand::AddRemoteCandidate {
                candidate,
                deadline,
                reply,
            } => handle_live_remote_candidate(&sessions, candidate, deadline, reply).await,
            LiveWebRtcCommand::Close {
                session_id,
                deadline,
                reply,
            } => handle_live_close(&mut sessions, session_id, deadline, reply).await,
        }
    }
    commands.close();
    for (_, peer_connection) in sessions {
        let _ = peer_connection.close().await;
    }
}

async fn handle_live_create(
    sessions: &mut HashMap<String, Arc<RTCPeerConnection>>,
    shutdown: &AtomicBool,
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
    match create_live_peer_connection(&config).await {
        Ok((peer_connection, description)) => {
            if shutdown.load(Ordering::Acquire) || command_expired(deadline) {
                let _ = peer_connection.close().await;
                let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
                return;
            }
            sessions.insert(key.clone(), Arc::clone(&peer_connection));
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

async fn handle_live_remote_description(
    sessions: &HashMap<String, Arc<RTCPeerConnection>>,
    description: WebRtcSessionDescription,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.get(&session_key(&description.session_id)) {
        Some(peer_connection) => set_engine_remote_description(peer_connection, &description).await,
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

async fn handle_live_remote_candidate(
    sessions: &HashMap<String, Arc<RTCPeerConnection>>,
    candidate: WebRtcIceCandidate,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.get(&session_key(&candidate.session_id)) {
        Some(peer_connection) => add_engine_remote_candidate(peer_connection, &candidate).await,
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

async fn handle_live_close(
    sessions: &mut HashMap<String, Arc<RTCPeerConnection>>,
    session_id: SessionId,
    deadline: Instant,
    reply: std_mpsc::Sender<Result<(), WebRtcProviderError>>,
) {
    if command_expired(deadline) {
        let _ = reply.send(Err(WebRtcProviderError::TemporarilyUnavailable));
        return;
    }
    let result = match sessions.remove(&session_key(&session_id)) {
        Some(peer_connection) => peer_connection
            .close()
            .await
            .map_err(|_| WebRtcProviderError::Internal),
        None => Err(WebRtcProviderError::SessionUnavailable),
    };
    let _ = reply.send(result);
}

fn command_expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

async fn create_live_peer_connection(
    config: &WebRtcSessionConfig,
) -> Result<(Arc<RTCPeerConnection>, WebRtcSessionDescription), WebRtcProviderError> {
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
        Ok(description) => Ok((peer_connection, description)),
        Err(error) => {
            let _ = peer_connection.close().await;
            Err(error)
        }
    }
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

    /// Creates one ephemeral ICE configuration for the authenticated realtime session.
    ///
    /// # Errors
    /// Returns bounded TURN issuance or protocol failures without persisting generated credentials.
    pub fn session_config(
        &self,
        session_id: &SessionId,
        now_unix_seconds: u64,
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
                .issue(session_id, self.turn_ttl_seconds, now_unix_seconds)
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
        assert!(!format!("{issuer:?}").contains("07070707"));
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
        provider.command_tx.take();
        let worker = provider.worker.take().expect("worker");
        let started = Instant::now();
        worker.join().expect("worker shutdown");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn live_provider_creates_audio_video_offer_and_closes_ephemeral_session() {
        let provider = LiveWebRtcProvider::new().expect("live provider");
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
        assert_eq!(provider.close_session(&session_id), Ok(()));
        assert_eq!(
            provider.close_session(&session_id),
            Err(WebRtcProviderError::SessionUnavailable)
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

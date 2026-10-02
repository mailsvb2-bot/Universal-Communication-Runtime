#![forbid(unsafe_code)]

use std::{
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_stream::{StreamExt as _, wrappers::TcpListenerStream};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig, server::Connected};
use ucr_api_grpc::{
    GrpcAttachmentService, GrpcCallService, GrpcConferenceService, GrpcDeviceService,
    GrpcEventService, GrpcGroupService, GrpcIntegrationService, GrpcMachineAuthService,
    GrpcOperatorRuntimeService, GrpcRealtimeService, GrpcRecordingService, GrpcSfuNodeMediaService,
    GrpcSfuPlacementService, GrpcStoreForwardService, GrpcSyncService,
    GrpcUniversalConferenceService, MachineAuthDiscovery, MachineTokenVerificationKeyProvider,
    OperatorRuntimeHealthSource, OperatorSfuClusterControl, OperatorSfuClusterError,
    OperatorSfuNodeHeartbeat, PlacementAwareSfuNodeRouter, RealtimeSfuMediaRouter,
    RealtimeSfuPlacementLifecycle, RealtimeWebRtcDependencies, SfuNodeMediaClientTlsConfig,
    SfuPlacementRoutingPolicy, UniversalConferenceRuntimeCapabilities, attachment_service_server,
    call_service_server, conference_service_server, device_service_server, event_service_server,
    expire_due_recordings_once, group_service_server, integration_service_server,
    machine_auth_service_server, operator_runtime_service_server, pb, realtime_service_server,
    recording_service_server, sfu_node_media_service_server, sfu_placement_service_server,
    store_forward_service_server, sync_service_server, universal_conference_service_server,
};
use ucr_conference::ConferenceRuntimeState;
use ucr_core::{
    DurableStoreError, EventWebhookDispatcher, MAX_RECORDING_PROVIDER_OPERATION_BATCH,
    MAX_RECORDING_RETENTION_BATCH, RecordingMediaProvider, RecordingProviderDispatchSweep,
    StorageHealth, StorageProvider, SystemEventDeliveryClock, SystemServiceQuotaClock,
    WebhookDispatchOutcome, dispatch_recording_provider_operations_once, generate_opaque_id,
};
use ucr_crypto::{
    MAX_MACHINE_TOKEN_TTL_SECONDS, MachineTokenPolicy, MachineTokenPublicKeySet,
    MachineTokenSigningKey,
};
use ucr_model::{
    EventSubscriptionId, IceTransportPolicy, KeyId, NamespaceId, OpaqueId, SfuForwardEnvelope,
    TenantId, TenantScope,
};
use ucr_realtime::{JoinTokenIssuer, JoinTokenKey, RealtimeSessionRegistry};
use ucr_secrets::{MAX_SECRET_BYTES, SecretHandle, SecretProvider, SecretPurpose};
use ucr_sfu::{
    SfuClusterDirectory, SfuForwardSink, SfuForwardSinkError, SfuNodeCapacitySnapshot,
    SfuNodeDescriptor, SfuPlacementError, SfuPlacementPolicy,
};
use ucr_storage_sqlite::{
    RECORDING_RETENTION_WORKER_KIND, SqliteLocalStore, WEBHOOK_DELIVERY_WORKER_KIND,
};
use ucr_webhook::{
    HardenedWebhookSink, NativeTlsWebhookExecutor, SystemWebhookDnsResolver, WebhookSigningSecret,
};
use ucr_webrtc::{
    LIVE_WEBRTC_E2EE_INGRESS_CAPACITY, LIVE_WEBRTC_MAX_SESSIONS, LiveWebRtcProvider,
    TurnRestCredentialIssuer, TurnRestSecret, WebRtcE2eeIngressFrame, WebRtcProvider,
    WebRtcProviderError, WebRtcSessionConfigFactory,
};

pub const DEFAULT_RUNTIME_BIND: &str = "127.0.0.1:50051";
pub const DEFAULT_OPERATOR_BIND: &str = "127.0.0.1:50052";
pub const RUNTIME_MODE: &str = "local-daemon";

const WEBHOOK_DISPATCH_TARGET_PAGE: usize = 128;
pub const DEFAULT_WEBHOOK_WORKER_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const MIN_WEBHOOK_WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_WEBHOOK_WORKER_POLL_INTERVAL: Duration = Duration::from_mins(1);
const WEBHOOK_WORKER_LEASE_DURATION_MS: i64 = 120_000;

pub const DEFAULT_RECORDING_RETENTION_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const MIN_RECORDING_RETENTION_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_RECORDING_RETENTION_POLL_INTERVAL: Duration = Duration::from_mins(1);
const RECORDING_RETENTION_WORKER_LEASE_DURATION_MS: i64 = 120_000;
const DEFAULT_SFU_PLACEMENT_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct WebhookWorkerSweep {
    targets: usize,
    delivered: usize,
    retry_scheduled: usize,
    dead_lettered: usize,
    rejected: usize,
}

#[derive(Clone)]
enum MachineAuthSigningConfig {
    Static {
        signing_key: Arc<MachineTokenSigningKey>,
        verification_keys: Arc<MachineTokenPublicKeySet>,
    },
    Provider {
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    },
}

impl core::fmt::Debug for MachineAuthSigningConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Static { .. } => formatter
                .debug_struct("MachineAuthSigningConfig")
                .field("mode", &"static")
                .field("material", &"<redacted>")
                .finish_non_exhaustive(),
            Self::Provider { handle, .. } => formatter
                .debug_struct("MachineAuthSigningConfig")
                .field("mode", &"provider")
                .field("handle", handle)
                .field("material", &"<redacted>")
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MachineAuthRuntimeConfig {
    policy: MachineTokenPolicy,
    signing: MachineAuthSigningConfig,
    discovery: MachineAuthDiscovery,
}

impl MachineAuthRuntimeConfig {
    /// Builds the loopback machine-auth daemon configuration from a deployment-owned stable
    /// Ed25519 seed. Public URLs must be HTTPS because external reachability belongs behind a
    /// trusted TLS edge.
    ///
    /// # Errors
    /// Rejects malformed identifiers, non-HTTPS public URLs, empty audience, or invalid TTL.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        signing_key_id: impl Into<String>,
        signing_seed: [u8; 32],
        token_endpoint: impl Into<String>,
        jwks_uri: impl Into<String>,
        max_ttl_seconds: u32,
    ) -> Result<Self, String> {
        let issuer = issuer.into();
        let audience = audience.into();
        let token_endpoint = token_endpoint.into();
        let jwks_uri = jwks_uri.into();
        validate_public_https_url(&issuer, "machine token issuer")?;
        validate_public_https_url(&token_endpoint, "machine token endpoint")?;
        validate_public_https_url(&jwks_uri, "machine token JWKS URI")?;
        if audience.is_empty() || audience.chars().any(char::is_whitespace) {
            return Err(
                "machine token audience must be a non-empty token without whitespace".to_owned(),
            );
        }
        if max_ttl_seconds == 0 || max_ttl_seconds > MAX_MACHINE_TOKEN_TTL_SECONDS {
            return Err(format!(
                "machine token max TTL must be between 1 and {MAX_MACHINE_TOKEN_TTL_SECONDS} seconds"
            ));
        }
        let key_id = KeyId::from_opaque(runtime_opaque(
            &signing_key_id.into(),
            "machine token signing key id",
        )?);
        let signing_key = Arc::new(MachineTokenSigningKey::from_seed(key_id, signing_seed));
        let verification_keys = Arc::new(
            MachineTokenPublicKeySet::new(vec![signing_key.public_key()])
                .map_err(|error| format!("build machine token verification key set: {error:?}"))?,
        );
        Ok(Self {
            policy: MachineTokenPolicy {
                issuer,
                audience,
                max_ttl_seconds,
            },
            signing: MachineAuthSigningConfig::Static {
                signing_key,
                verification_keys,
            },
            discovery: MachineAuthDiscovery {
                token_endpoint,
                jwks_uri,
            },
        })
    }

    /// Builds machine-auth configuration backed by the shared secret provider.
    ///
    /// # Errors
    /// Rejects invalid URLs/policy, a wrong-purpose handle, unavailable provider material, or a
    /// signing seed that is not exactly 32 bytes.
    pub fn with_secret_provider(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
        token_endpoint: impl Into<String>,
        jwks_uri: impl Into<String>,
        max_ttl_seconds: u32,
    ) -> Result<Self, String> {
        if handle.purpose != SecretPurpose::MachineTokenSigning {
            return Err(
                "machine token signing handle must use MachineTokenSigning purpose".to_owned(),
            );
        }
        let active = provider
            .active_secret_set(&handle)
            .map_err(|error| format!("resolve machine token signing secret: {error:?}"))?;
        if active.current.material.as_bytes().len() != 32
            || active
                .previous
                .as_ref()
                .is_some_and(|version| version.material.as_bytes().len() != 32)
        {
            return Err("machine token signing secret must be exactly 32 bytes".to_owned());
        }

        let issuer = issuer.into();
        let audience = audience.into();
        let token_endpoint = token_endpoint.into();
        let jwks_uri = jwks_uri.into();
        validate_public_https_url(&issuer, "machine token issuer")?;
        validate_public_https_url(&token_endpoint, "machine token endpoint")?;
        validate_public_https_url(&jwks_uri, "machine token JWKS URI")?;
        if audience.is_empty() || audience.chars().any(char::is_whitespace) {
            return Err(
                "machine token audience must be a non-empty token without whitespace".to_owned(),
            );
        }
        if max_ttl_seconds == 0 || max_ttl_seconds > MAX_MACHINE_TOKEN_TTL_SECONDS {
            return Err(format!(
                "machine token max TTL must be between 1 and {MAX_MACHINE_TOKEN_TTL_SECONDS} seconds"
            ));
        }

        Ok(Self {
            policy: MachineTokenPolicy {
                issuer,
                audience,
                max_ttl_seconds,
            },
            signing: MachineAuthSigningConfig::Provider { provider, handle },
            discovery: MachineAuthDiscovery {
                token_endpoint,
                jwks_uri,
            },
        })
    }

    /// Adds one deployment-owned previous signing key for a bounded rotation overlap window.
    ///
    /// New tokens continue to be signed only by the active key. The previous private seed is used
    /// only long enough to derive its public verification key and is zeroized by
    /// `MachineTokenSigningKey::from_seed` before this function returns.
    ///
    /// # Errors
    /// Rejects malformed or duplicate key identifiers.
    pub fn with_previous_signing_key(
        mut self,
        previous_key_id: impl Into<String>,
        previous_seed: [u8; 32],
    ) -> Result<Self, String> {
        let previous_key_id = KeyId::from_opaque(runtime_opaque(
            &previous_key_id.into(),
            "previous machine token signing key id",
        )?);
        let previous_key = MachineTokenSigningKey::from_seed(previous_key_id, previous_seed);
        let MachineAuthSigningConfig::Static {
            verification_keys, ..
        } = &mut self.signing
        else {
            return Err(
                "previous machine token key is managed by SecretProvider in provider mode"
                    .to_owned(),
            );
        };
        let mut updated = (**verification_keys).clone();
        updated
            .insert(previous_key.public_key())
            .map_err(|error| format!("add previous machine token verification key: {error:?}"))?;
        *verification_keys = Arc::new(updated);
        Ok(self)
    }
}

#[derive(Clone)]
enum MachineBearerVerificationConfig {
    Static(Arc<MachineTokenPublicKeySet>),
    Provider(Arc<dyn MachineTokenVerificationKeyProvider>),
}

impl core::fmt::Debug for MachineBearerVerificationConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Static(keys) => formatter
                .debug_tuple("Static")
                .field(&keys.keys().len())
                .finish(),
            Self::Provider(_) => formatter
                .debug_tuple("Provider")
                .field(&"<dynamic>")
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MachineBearerRuntimeConfig {
    policy: MachineTokenPolicy,
    verification: MachineBearerVerificationConfig,
}

impl MachineBearerRuntimeConfig {
    /// Builds verifier-only machine Bearer configuration for the public API process.
    ///
    /// This type contains public verification material only. The private signing seed remains
    /// isolated in the machine-auth daemon.
    ///
    /// # Errors
    /// Rejects a non-HTTPS issuer, malformed audience, invalid TTL, or an empty key set.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        max_ttl_seconds: u32,
        verification_keys: MachineTokenPublicKeySet,
    ) -> Result<Self, String> {
        let issuer = issuer.into();
        let audience = audience.into();
        validate_public_https_url(&issuer, "machine token issuer")?;
        if audience.is_empty() || audience.chars().any(char::is_whitespace) {
            return Err(
                "machine token audience must be a non-empty token without whitespace".to_owned(),
            );
        }
        if max_ttl_seconds == 0 || max_ttl_seconds > MAX_MACHINE_TOKEN_TTL_SECONDS {
            return Err(format!(
                "machine token max TTL must be between 1 and {MAX_MACHINE_TOKEN_TTL_SECONDS} seconds"
            ));
        }
        if verification_keys.keys().is_empty() {
            return Err("machine token verification key set must not be empty".to_owned());
        }
        Ok(Self {
            policy: MachineTokenPolicy {
                issuer,
                audience,
                max_ttl_seconds,
            },
            verification: MachineBearerVerificationConfig::Static(Arc::new(verification_keys)),
        })
    }

    /// Builds machine Bearer verification over a dynamically reloaded public-key provider.
    ///
    /// # Errors
    /// Rejects invalid policy or an unavailable/empty provider key set.
    pub fn with_verification_provider(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        max_ttl_seconds: u32,
        provider: Arc<dyn MachineTokenVerificationKeyProvider>,
    ) -> Result<Self, String> {
        let issuer = issuer.into();
        let audience = audience.into();
        validate_public_https_url(&issuer, "machine token issuer")?;
        if audience.is_empty() || audience.chars().any(char::is_whitespace) {
            return Err(
                "machine token audience must be a non-empty token without whitespace".to_owned(),
            );
        }
        if max_ttl_seconds == 0 || max_ttl_seconds > MAX_MACHINE_TOKEN_TTL_SECONDS {
            return Err(format!(
                "machine token max TTL must be between 1 and {MAX_MACHINE_TOKEN_TTL_SECONDS} seconds"
            ));
        }
        let keys = provider
            .current_verification_keys()
            .map_err(|error| format!("resolve machine token verification keys: {error:?}"))?;
        if keys.keys().is_empty() {
            return Err("machine token verification key set must not be empty".to_owned());
        }
        Ok(Self {
            policy: MachineTokenPolicy {
                issuer,
                audience,
                max_ttl_seconds,
            },
            verification: MachineBearerVerificationConfig::Provider(provider),
        })
    }
}

#[derive(Clone)]
pub struct SfuNodeMediaRuntimeConfig {
    bind: SocketAddr,
    provider: Arc<dyn SecretProvider>,
    certificate_handle: SecretHandle,
    private_key_handle: SecretHandle,
    client_ca_pem: Arc<[u8]>,
    previous_client_ca_pem: Option<Arc<[u8]>>,
}

impl core::fmt::Debug for SfuNodeMediaRuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SfuNodeMediaRuntimeConfig")
            .field("bind", &self.bind)
            .field("certificate_handle", &self.certificate_handle)
            .field("private_key_handle", &self.private_key_handle)
            .field("client_ca", &"<redacted-public-trust-material>")
            .finish_non_exhaustive()
    }
}

impl SfuNodeMediaRuntimeConfig {
    /// Builds the private horizontal-SFU node listener configuration.
    ///
    /// The server identity is resolved through the shared `SecretProvider`. Client trust anchors are
    /// public deployment material but remain bounded and are supplied explicitly so this listener
    /// cannot silently trust the system root store.
    ///
    /// # Errors
    /// Rejects public/unspecified binds, wrong-purpose handles, unavailable secret material, or
    /// empty/oversized client trust anchors.
    pub fn new(
        bind: SocketAddr,
        provider: Arc<dyn SecretProvider>,
        certificate_handle: SecretHandle,
        private_key_handle: SecretHandle,
        client_ca_pem: Vec<u8>,
        previous_client_ca_pem: Option<Vec<u8>>,
    ) -> Result<Self, String> {
        validate_private_sfu_node_bind(bind)?;
        if certificate_handle.purpose != SecretPurpose::TlsCertificate {
            return Err("SFU node certificate handle must use TlsCertificate purpose".to_owned());
        }
        if private_key_handle.purpose != SecretPurpose::TlsPrivateKey {
            return Err("SFU node private key handle must use TlsPrivateKey purpose".to_owned());
        }
        provider
            .active_secret_set(&certificate_handle)
            .map_err(|error| format!("resolve SFU node certificate secret: {error:?}"))?;
        provider
            .active_secret_set(&private_key_handle)
            .map_err(|error| format!("resolve SFU node private-key secret: {error:?}"))?;
        validate_sfu_node_ca(&client_ca_pem)?;
        if let Some(previous) = previous_client_ca_pem.as_deref() {
            validate_sfu_node_ca(previous)?;
        }
        Ok(Self {
            bind,
            provider,
            certificate_handle,
            private_key_handle,
            client_ca_pem: Arc::from(client_ca_pem),
            previous_client_ca_pem: previous_client_ca_pem.map(Arc::from),
        })
    }

    fn tls_server(&self) -> Result<Server, String> {
        // The full workspace also contains dependencies that enable another rustls backend.
        // Select the same provider as the canonical HTTPS edge before Tonic builds TLS state.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificates = self
            .provider
            .active_secret_set(&self.certificate_handle)
            .map_err(|error| format!("resolve SFU node certificate secret: {error:?}"))?;
        let private_keys = self
            .provider
            .active_secret_set(&self.private_key_handle)
            .map_err(|error| format!("resolve SFU node private-key secret: {error:?}"))?;

        let certificate_versions = std::iter::once(&certificates.current)
            .chain(certificates.previous.iter())
            .collect::<Vec<_>>();
        let private_key_versions = std::iter::once(&private_keys.current)
            .chain(private_keys.previous.iter())
            .collect::<Vec<_>>();
        let mut trust = self.client_ca_pem.as_ref().to_vec();
        if let Some(previous) = &self.previous_client_ca_pem {
            trust.extend_from_slice(b"\n");
            trust.extend_from_slice(previous);
        }

        for certificate in certificate_versions {
            for private_key in &private_key_versions {
                let tls = ServerTlsConfig::new()
                    .identity(Identity::from_pem(
                        certificate.material.as_bytes(),
                        private_key.material.as_bytes(),
                    ))
                    .client_ca_root(Certificate::from_pem(trust.clone()));
                if let Ok(server) = Server::builder().tls_config(tls) {
                    return Ok(server);
                }
            }
        }
        Err("no active SFU node TLS certificate/private-key pair is valid".to_owned())
    }
}

fn validate_sfu_node_ca(value: &[u8]) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_SECRET_BYTES {
        Err("SFU node client CA material must be non-empty and bounded".to_owned())
    } else {
        Ok(())
    }
}

fn validate_private_sfu_node_bind(bind: SocketAddr) -> Result<(), String> {
    let private = match bind.ip() {
        std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        std::net::IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    };
    if private {
        Ok(())
    } else {
        Err("SFU node media listener must bind loopback or private network address".to_owned())
    }
}

#[derive(Debug, Clone)]
pub struct SfuPlacementMediaRuntimeConfig {
    node_tls: SfuNodeMediaClientTlsConfig,
    policy: SfuPlacementRoutingPolicy,
}

impl SfuPlacementMediaRuntimeConfig {
    #[must_use]
    pub fn new(node_tls: SfuNodeMediaClientTlsConfig, policy: SfuPlacementRoutingPolicy) -> Self {
        Self { node_tls, policy }
    }
}

#[derive(Clone)]
pub struct RealtimeRuntimeConfig {
    join_issuer: Arc<JoinTokenIssuer>,
    webrtc_config: Arc<WebRtcSessionConfigFactory>,
    browser_realtime_gateway: bool,
    sfu_node_media: Option<SfuNodeMediaRuntimeConfig>,
    sfu_placement_lifecycle: bool,
    sfu_placement_media: Option<SfuPlacementMediaRuntimeConfig>,
}

impl core::fmt::Debug for RealtimeRuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealtimeRuntimeConfig")
            .field("join_issuer", &"<redacted-provider-aware>")
            .field("webrtc_config", &self.webrtc_config)
            .field("browser_realtime_gateway", &self.browser_realtime_gateway)
            .field("sfu_node_media", &self.sfu_node_media)
            .field("sfu_placement_lifecycle", &self.sfu_placement_lifecycle)
            .field("sfu_placement_media", &self.sfu_placement_media)
            .finish()
    }
}

impl RealtimeRuntimeConfig {
    /// Builds the loopback realtime service configuration. The join base URL must be HTTPS even
    /// though the daemon itself stays loopback-only; a trusted TLS edge terminates public traffic.
    ///
    /// # Errors
    /// Rejects an invalid public join URL.
    pub fn new(join_base_url: impl Into<String>, join_token_key: [u8; 32]) -> Result<Self, String> {
        let join_token_key = JoinTokenKey::from_bytes(join_token_key);
        let join_issuer = JoinTokenIssuer::new(join_token_key, join_base_url)
            .map_err(|error| format!("invalid realtime join configuration: {error:?}"))?;
        Ok(Self {
            join_issuer: Arc::new(join_issuer),
            webrtc_config: Arc::new(WebRtcSessionConfigFactory::default()),
            browser_realtime_gateway: false,
            sfu_node_media: None,
            sfu_placement_lifecycle: false,
            sfu_placement_media: None,
        })
    }

    /// Builds realtime configuration using the shared rotation-safe join-signing provider.
    ///
    /// # Errors
    /// Rejects an invalid join URL, wrong-purpose handle, unavailable provider, or malformed key.
    pub fn with_join_secret_provider(
        join_base_url: impl Into<String>,
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    ) -> Result<Self, String> {
        let join_issuer = JoinTokenIssuer::with_secret_provider(provider, handle, join_base_url)
            .map_err(|error| format!("invalid realtime join provider configuration: {error:?}"))?;
        Ok(Self {
            join_issuer: Arc::new(join_issuer),
            webrtc_config: Arc::new(WebRtcSessionConfigFactory::default()),
            browser_realtime_gateway: false,
            sfu_node_media: None,
            sfu_placement_lifecycle: false,
            sfu_placement_media: None,
        })
    }

    #[must_use]
    pub fn with_browser_realtime_gateway(mut self, enabled: bool) -> Self {
        self.browser_realtime_gateway = enabled;
        self
    }

    #[must_use]
    pub fn with_sfu_node_media(mut self, config: SfuNodeMediaRuntimeConfig) -> Self {
        self.sfu_node_media = Some(config);
        self
    }

    /// Enables the pre-production Call placement lifecycle gate.
    ///
    /// This does not advertise horizontal SFU capability by itself: media forwarding/failover must
    /// still be proven separately. When enabled, realtime join fails closed until healthy SFU
    /// capacity has been registered through the private operator plane.
    #[must_use]
    pub fn with_sfu_placement_lifecycle(mut self, enabled: bool) -> Self {
        self.sfu_placement_lifecycle = enabled;
        self
    }

    /// Enables placement-aware forwarding of canonically validated realtime media batches.
    ///
    /// This remains pre-production and does not advertise the public horizontal-SFU capability.
    #[must_use]
    pub fn with_sfu_placement_media(mut self, config: SfuPlacementMediaRuntimeConfig) -> Self {
        self.sfu_placement_media = Some(config);
        self
    }

    #[must_use]
    fn universal_conference_capabilities(&self) -> UniversalConferenceRuntimeCapabilities {
        UniversalConferenceRuntimeCapabilities {
            browser_realtime_gateway: self.browser_realtime_gateway,
            production_webrtc: false,
            turn: self.webrtc_config.has_turn(),
            recording: false,
            horizontal_sfu: false,
        }
    }

    /// Adds deployment STUN/TURN configuration for browser/mobile peer connections.
    ///
    /// # Errors
    /// Rejects invalid ICE URLs, TURN without a secret, invalid TTL, or excessive server counts.
    pub fn with_webrtc_ice(
        self,
        stun_urls: Vec<String>,
        turn_urls: Vec<String>,
        turn_rest_secret: Option<[u8; 32]>,
        turn_ttl_seconds: u32,
        relay_only: bool,
    ) -> Result<Self, String> {
        let turn_issuer = turn_rest_secret
            .map(TurnRestSecret::from_bytes)
            .map(TurnRestCredentialIssuer::new);
        self.with_webrtc_ice_issuer(
            stun_urls,
            turn_urls,
            turn_issuer,
            turn_ttl_seconds,
            relay_only,
        )
    }

    /// Adds deployment STUN/TURN configuration using the shared rotation-safe TURN root provider.
    ///
    /// # Errors
    /// Rejects invalid ICE settings, wrong-purpose/unavailable provider state, or malformed material.
    pub fn with_webrtc_ice_secret_provider(
        self,
        stun_urls: Vec<String>,
        turn_urls: Vec<String>,
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
        turn_ttl_seconds: u32,
        relay_only: bool,
    ) -> Result<Self, String> {
        let turn_issuer = TurnRestCredentialIssuer::with_secret_provider(provider, handle)
            .map_err(|error| format!("invalid TURN secret provider configuration: {error:?}"))?;
        self.with_webrtc_ice_issuer(
            stun_urls,
            turn_urls,
            Some(turn_issuer),
            turn_ttl_seconds,
            relay_only,
        )
    }

    fn with_webrtc_ice_issuer(
        mut self,
        stun_urls: Vec<String>,
        turn_urls: Vec<String>,
        turn_issuer: Option<TurnRestCredentialIssuer>,
        turn_ttl_seconds: u32,
        relay_only: bool,
    ) -> Result<Self, String> {
        let ice_transport_policy = if relay_only {
            IceTransportPolicy::RelayOnly
        } else {
            IceTransportPolicy::All
        };
        self.webrtc_config = Arc::new(
            WebRtcSessionConfigFactory::new(
                stun_urls,
                turn_urls,
                turn_issuer,
                turn_ttl_seconds,
                ice_transport_policy,
            )
            .map_err(|error| format!("invalid WebRTC ICE configuration: {error:?}"))?,
        );
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeDiagnostics {
    pub schema_version: u32,
    pub storage_health: StorageHealth,
    pub runtime_mode: &'static str,
}

impl RuntimeDiagnostics {
    #[must_use]
    pub fn json(&self) -> String {
        format!(
            "{{\"runtime_mode\":\"{}\",\"schema_version\":{},\"storage_health\":\"{}\"}}",
            self.runtime_mode,
            self.schema_version,
            health_label(self.storage_health)
        )
    }

    #[must_use]
    pub fn prometheus(&self) -> String {
        let healthy = u8::from(self.storage_health == StorageHealth::Healthy);
        format!(
            "# TYPE ucr_runtime_up gauge\n\
             ucr_runtime_up 1\n\
             # TYPE ucr_storage_schema_version gauge\n\
             ucr_storage_schema_version {}\n\
             # TYPE ucr_storage_healthy gauge\n\
             ucr_storage_healthy {}\n",
            self.schema_version, healthy
        )
    }
}

#[derive(Debug)]
pub struct ProductionRuntime {
    store: Arc<SqliteLocalStore>,
}

struct PreparedRealtimeRuntime {
    clock: Arc<SystemServiceQuotaClock>,
    event_clock: Arc<SystemEventDeliveryClock>,
    store: Arc<SqliteLocalStore>,
    authorization: Arc<SqliteLocalStore>,
    conference_state: Arc<ConferenceRuntimeState>,
    runtime_capabilities: UniversalConferenceRuntimeCapabilities,
    sfu_node_media_config: Option<SfuNodeMediaRuntimeConfig>,
    sfu_placement_service: GrpcSfuPlacementService<SystemServiceQuotaClock>,
    realtime_service:
        GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    sfu_expiry_task: Option<tokio::task::JoinHandle<()>>,
    bridge_task: tokio::task::JoinHandle<()>,
    sfu_node_media_service: Option<GrpcSfuNodeMediaService<SqliteLocalStore, SqliteLocalStore>>,
    operator_health: Arc<ProductionOperatorHealthSource>,
    join_issuer: Arc<JoinTokenIssuer>,
}

#[derive(Debug)]
struct RealtimeOperatorHealth {
    registry: Arc<RealtimeSessionRegistry>,
    live_provider: Arc<LiveWebRtcProvider>,
    turn_configured: bool,
}

#[derive(Debug)]
struct ProductionOperatorHealthSource {
    store: Arc<SqliteLocalStore>,
    realtime: Option<RealtimeOperatorHealth>,
    sfu_cluster: Option<Arc<Mutex<SfuClusterDirectory>>>,
}

impl ProductionOperatorHealthSource {
    fn basic(store: Arc<SqliteLocalStore>) -> Self {
        Self {
            store,
            realtime: None,
            sfu_cluster: None,
        }
    }

    fn realtime(
        store: Arc<SqliteLocalStore>,
        registry: Arc<RealtimeSessionRegistry>,
        live_provider: Arc<LiveWebRtcProvider>,
        turn_configured: bool,
        sfu_cluster: Arc<Mutex<SfuClusterDirectory>>,
    ) -> Self {
        Self {
            store,
            realtime: Some(RealtimeOperatorHealth {
                registry,
                live_provider,
                turn_configured,
            }),
            sfu_cluster: Some(sfu_cluster),
        }
    }
}

impl OperatorRuntimeHealthSource for ProductionOperatorHealthSource {
    fn snapshot(&self) -> pb::OperatorRuntimeHealthResponse {
        let realtime = operator_realtime_health(self.realtime.as_ref());
        pb::OperatorRuntimeHealthResponse {
            api: Some(operator_component(
                pb::OperatorComponentStatus::Healthy,
                "private loopback operator API is serving",
            )),
            sfu: Some(realtime.sfu),
            turn: Some(realtime.turn),
            storage: Some(operator_storage_health(self.store.as_ref())),
            webhook_worker: Some(operator_webhook_worker_health(self.store.as_ref())),
            recorder: Some(operator_component(
                pb::OperatorComponentStatus::NotConfigured,
                "recording provider is not configured",
            )),
            capacity: Some(realtime.capacity),
        }
    }
}

impl OperatorSfuClusterControl for ProductionOperatorHealthSource {
    fn heartbeat_sfu_node(
        &self,
        heartbeat: OperatorSfuNodeHeartbeat,
    ) -> Result<SfuNodeCapacitySnapshot, OperatorSfuClusterError> {
        let cluster = self
            .sfu_cluster
            .as_ref()
            .ok_or(OperatorSfuClusterError::NotConfigured)?;
        let now_unix_ms =
            runtime_now_unix_ms().map_err(|_| OperatorSfuClusterError::Unavailable)?;
        let lease_expires_at_unix_ms = now_unix_ms
            .checked_add(i64::from(heartbeat.lease_ttl_ms))
            .ok_or(OperatorSfuClusterError::InvalidNode)?;
        let endpoint = heartbeat.endpoint;
        let node = SfuNodeDescriptor {
            node_id: heartbeat.node_id,
            region: heartbeat.region,
            state: heartbeat.state,
            active_sessions: heartbeat.active_sessions,
            max_sessions: heartbeat.max_sessions,
            lease_expires_at_unix_ms,
        };
        let mut directory = cluster
            .lock()
            .map_err(|_| OperatorSfuClusterError::Unavailable)?;
        directory.prune_expired_nodes(now_unix_ms);
        directory
            .upsert_node_with_endpoint(node.clone(), endpoint)
            .map_err(map_sfu_cluster_error)?;
        directory
            .node_with_capacity(&node.node_id)
            .ok_or(OperatorSfuClusterError::InvalidNode)
    }

    fn drain_sfu_node(
        &self,
        node_id: &OpaqueId,
    ) -> Result<SfuNodeCapacitySnapshot, OperatorSfuClusterError> {
        let cluster = self
            .sfu_cluster
            .as_ref()
            .ok_or(OperatorSfuClusterError::NotConfigured)?;
        let now_unix_ms =
            runtime_now_unix_ms().map_err(|_| OperatorSfuClusterError::Unavailable)?;
        let mut directory = cluster
            .lock()
            .map_err(|_| OperatorSfuClusterError::Unavailable)?;
        directory.prune_expired_nodes(now_unix_ms);
        directory
            .mark_draining(node_id)
            .map_err(map_sfu_cluster_error)?;
        directory
            .node_with_capacity(node_id)
            .ok_or(OperatorSfuClusterError::InvalidNode)
    }

    fn list_sfu_nodes(&self) -> Result<Vec<SfuNodeCapacitySnapshot>, OperatorSfuClusterError> {
        let cluster = self
            .sfu_cluster
            .as_ref()
            .ok_or(OperatorSfuClusterError::NotConfigured)?;
        let now_unix_ms =
            runtime_now_unix_ms().map_err(|_| OperatorSfuClusterError::Unavailable)?;
        let mut directory = cluster
            .lock()
            .map_err(|_| OperatorSfuClusterError::Unavailable)?;
        directory.prune_expired_nodes(now_unix_ms);
        Ok(directory.nodes_with_capacity())
    }
}

const fn map_sfu_cluster_error(error: SfuPlacementError) -> OperatorSfuClusterError {
    match error {
        SfuPlacementError::InvalidNode | SfuPlacementError::InvalidEndpoint => {
            OperatorSfuClusterError::InvalidNode
        }
        SfuPlacementError::EndpointUnavailable | SfuPlacementError::NoHealthyCapacity => {
            OperatorSfuClusterError::Unavailable
        }
    }
}

#[derive(Debug)]
struct OperatorRealtimeHealthSnapshot {
    sfu: pb::OperatorComponentHealth,
    turn: pb::OperatorComponentHealth,
    capacity: pb::OperatorCapacityStatus,
}

fn operator_webhook_worker_health(store: &SqliteLocalStore) -> pb::OperatorComponentHealth {
    let Ok(now_unix_ms) = runtime_now_unix_ms() else {
        return operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "webhook delivery worker health clock is unavailable",
        );
    };
    operator_webhook_worker_health_at(store, now_unix_ms)
}

fn operator_webhook_worker_health_at(
    store: &SqliteLocalStore,
    now_unix_ms: i64,
) -> pb::OperatorComponentHealth {
    match store.runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND) {
        Ok(Some(lease)) if lease.lease_expires_unix_ms > now_unix_ms => operator_component(
            pb::OperatorComponentStatus::Healthy,
            "webhook delivery worker durable lease is active",
        ),
        Ok(Some(_)) => operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "webhook delivery worker durable lease has expired",
        ),
        Ok(None) => operator_component(
            pb::OperatorComponentStatus::NotConfigured,
            "webhook delivery worker has no durable lease",
        ),
        Err(_) => operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "webhook delivery worker lease health check failed",
        ),
    }
}

fn operator_storage_health(store: &SqliteLocalStore) -> pb::OperatorComponentHealth {
    match store.health() {
        Ok(StorageHealth::Healthy) => operator_component(
            pb::OperatorComponentStatus::Healthy,
            "durable storage is healthy",
        ),
        Ok(StorageHealth::ReadOnly) => operator_component(
            pb::OperatorComponentStatus::Degraded,
            "durable storage is read-only",
        ),
        Ok(StorageHealth::Unavailable) => operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "durable storage is unavailable",
        ),
        Ok(StorageHealth::Corrupt) => operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "durable storage is corrupt",
        ),
        Err(_) => operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "durable storage health check failed",
        ),
    }
}

fn operator_realtime_health(
    realtime: Option<&RealtimeOperatorHealth>,
) -> OperatorRealtimeHealthSnapshot {
    let Some(realtime) = realtime else {
        return OperatorRealtimeHealthSnapshot {
            sfu: operator_component(
                pb::OperatorComponentStatus::NotConfigured,
                "realtime/SFU runtime is not enabled",
            ),
            turn: operator_component(
                pb::OperatorComponentStatus::NotConfigured,
                "TURN is not configured",
            ),
            capacity: pb::OperatorCapacityStatus {
                status: pb::OperatorComponentStatus::NotConfigured as i32,
                active_realtime_sessions: 0,
                max_realtime_sessions: 0,
                available_realtime_sessions: 0,
            },
        };
    };

    let sfu = if realtime.live_provider.is_available() {
        operator_component(
            pb::OperatorComponentStatus::Healthy,
            "encrypted SFU/WebRTC transport worker is available",
        )
    } else {
        operator_component(
            pb::OperatorComponentStatus::Unavailable,
            "encrypted SFU/WebRTC transport worker is unavailable",
        )
    };
    let turn = if realtime.turn_configured {
        operator_component(
            pb::OperatorComponentStatus::Unverified,
            "TURN configured but network reachability is unverified",
        )
    } else {
        operator_component(
            pb::OperatorComponentStatus::NotConfigured,
            "TURN is not configured",
        )
    };
    OperatorRealtimeHealthSnapshot {
        sfu,
        turn,
        capacity: realtime_capacity(&realtime.registry),
    }
}

fn operator_component(
    status: pb::OperatorComponentStatus,
    detail: &str,
) -> pb::OperatorComponentHealth {
    pb::OperatorComponentHealth {
        status: status as i32,
        detail: detail.to_owned(),
    }
}

fn unavailable_realtime_capacity() -> pb::OperatorCapacityStatus {
    pb::OperatorCapacityStatus {
        status: pb::OperatorComponentStatus::Unavailable as i32,
        active_realtime_sessions: 0,
        max_realtime_sessions: u32::try_from(LIVE_WEBRTC_MAX_SESSIONS).unwrap_or(u32::MAX),
        available_realtime_sessions: 0,
    }
}

fn realtime_capacity(registry: &RealtimeSessionRegistry) -> pb::OperatorCapacityStatus {
    let Ok(now_unix_ms) = runtime_now_unix_ms() else {
        return unavailable_realtime_capacity();
    };
    let Ok(active) = registry.active_session_count_at(now_unix_ms) else {
        return unavailable_realtime_capacity();
    };
    let maximum = LIVE_WEBRTC_MAX_SESSIONS;
    let available = maximum.saturating_sub(active);
    let status = if active >= maximum {
        pb::OperatorComponentStatus::Degraded
    } else {
        pb::OperatorComponentStatus::Healthy
    };
    pb::OperatorCapacityStatus {
        status: status as i32,
        active_realtime_sessions: u32::try_from(active).unwrap_or(u32::MAX),
        max_realtime_sessions: u32::try_from(maximum).unwrap_or(u32::MAX),
        available_realtime_sessions: u32::try_from(available).unwrap_or(u32::MAX),
    }
}

impl ProductionRuntime {
    /// Initializes a durable UCR `SQLite` database without creating credentials, identities,
    /// permissions, test transports, or other development bootstrap state.
    ///
    /// # Errors
    /// Returns explicit storage/migration/health failures.
    pub fn initialize_database(path: impl AsRef<Path>) -> Result<RuntimeDiagnostics, String> {
        let store = SqliteLocalStore::open(path)
            .map_err(|error| format!("initialize durable store: {error:?}"))?;
        diagnostics_for(&store)
    }

    /// Opens an already initialized durable database for the local-daemon runtime.
    ///
    /// New databases must be initialized explicitly so `serve` cannot silently create an empty
    /// production state or development credentials.
    ///
    /// # Errors
    /// Fails closed for a missing path, unsafe/corrupt schema, or unhealthy durable store.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(
                "production runtime requires an explicitly initialized database".to_owned(),
            );
        }
        let store = Arc::new(
            SqliteLocalStore::open(path)
                .map_err(|error| format!("open durable store: {error:?}"))?,
        );
        let diagnostics = diagnostics_for(store.as_ref())?;
        if diagnostics.storage_health != StorageHealth::Healthy {
            return Err("production runtime refuses an unhealthy durable store".to_owned());
        }
        Ok(Self { store })
    }

    /// Returns redaction-safe operational health and schema diagnostics only.
    ///
    /// # Errors
    /// Returns explicit durable-store health/metadata failures.
    pub fn diagnostics(&self) -> Result<RuntimeDiagnostics, String> {
        diagnostics_for(self.store.as_ref())
    }

    /// Executes one durable webhook-delivery attempt for an existing Event subscription.
    ///
    /// The canonical Event subscription remains the sole owner of retry/cursor/DLQ state. The
    /// signing key is supplied by the operator for this process invocation and is never persisted.
    ///
    /// # Errors
    /// Rejects invalid identifiers, missing/corrupt subscriptions, unsafe destinations, DNS/TLS
    /// failures and durable-store failures without exposing payloads or signing material.
    pub fn dispatch_webhook_once(
        &self,
        tenant_id: &str,
        namespace_id: Option<&str>,
        subscription_id: &str,
        signing_key: [u8; 32],
    ) -> Result<WebhookDispatchOutcome, String> {
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(runtime_opaque(tenant_id, "tenant id")?),
            namespace_id: namespace_id
                .map(|value| runtime_opaque(value, "namespace id").map(NamespaceId::from_opaque))
                .transpose()?,
        };
        let subscription_id =
            EventSubscriptionId::from_opaque(runtime_opaque(subscription_id, "subscription id")?);
        let clock = SystemEventDeliveryClock;
        let sink = HardenedWebhookSink::new(
            SystemWebhookDnsResolver,
            NativeTlsWebhookExecutor::default(),
            WebhookSigningSecret::from_bytes(signing_key),
        );
        EventWebhookDispatcher::new(&clock, self.store.as_ref(), &sink)
            .dispatch_once(&scope, &subscription_id)
            .map_err(|error| format!("dispatch durable webhook: {error:?}"))
    }

    /// Executes one durable webhook-delivery attempt with the shared secret provider.
    ///
    /// The provider-backed sink resolves the current `WebhookSigning` version for each attempt,
    /// so rotations take effect without recreating the runtime or persisting key material.
    ///
    /// # Errors
    /// Fails closed when the provider handle is unavailable, wrong-purpose, malformed, or when
    /// normal webhook delivery validation fails.
    pub fn dispatch_webhook_once_with_secret_provider(
        &self,
        tenant_id: &str,
        namespace_id: Option<&str>,
        subscription_id: &str,
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
    ) -> Result<WebhookDispatchOutcome, String> {
        let scope = TenantScope {
            tenant_id: TenantId::from_opaque(runtime_opaque(tenant_id, "tenant id")?),
            namespace_id: namespace_id
                .map(|value| runtime_opaque(value, "namespace id").map(NamespaceId::from_opaque))
                .transpose()?,
        };
        let subscription_id =
            EventSubscriptionId::from_opaque(runtime_opaque(subscription_id, "subscription id")?);
        let clock = SystemEventDeliveryClock;
        let sink = HardenedWebhookSink::with_secret_provider(
            SystemWebhookDnsResolver,
            NativeTlsWebhookExecutor::default(),
            provider,
            handle,
        )
        .map_err(|error| format!("configure webhook signing provider: {error:?}"))?;
        EventWebhookDispatcher::new(&clock, self.store.as_ref(), &sink)
            .dispatch_once(&scope, &subscription_id)
            .map_err(|error| format!("dispatch durable webhook: {error:?}"))
    }

    /// Runs the production webhook worker over all canonical Service Account-owned webhook
    /// subscriptions in the durable `SQLite` store.
    ///
    /// Discovery is bounded and paginated. The worker does not own retry, cursor or dead-letter
    /// state: every attempt is delegated to `EventWebhookDispatcher`, which revalidates the exact
    /// durable owner immediately before polling or network I/O. The signing key remains process
    /// memory only and is zeroized with the sink on shutdown.
    ///
    /// # Errors
    /// Rejects unsafe polling intervals and stops on durable-store/worker infrastructure failures.
    pub async fn run_webhook_worker(
        self: Arc<Self>,
        signing_key: [u8; 32],
        poll_interval: Duration,
    ) -> Result<(), String> {
        if !(MIN_WEBHOOK_WORKER_POLL_INTERVAL..=MAX_WEBHOOK_WORKER_POLL_INTERVAL)
            .contains(&poll_interval)
        {
            return Err("webhook worker poll interval must be between 100 ms and 60 s".to_owned());
        }

        let holder_id = generate_opaque_id()
            .map_err(|_| "generate webhook worker lease holder id".to_owned())?
            .as_str()
            .to_owned();
        let now_unix_ms = runtime_now_unix_ms()?;
        let acquired = self
            .store
            .try_acquire_runtime_worker_lease(
                WEBHOOK_DELIVERY_WORKER_KIND,
                &holder_id,
                now_unix_ms,
                WEBHOOK_WORKER_LEASE_DURATION_MS,
            )
            .map_err(|error| format!("acquire webhook worker durable lease: {error:?}"))?;
        if !acquired {
            return Err("another webhook worker holds the durable delivery lease".to_owned());
        }

        let clock = SystemEventDeliveryClock;
        let sink = HardenedWebhookSink::new(
            SystemWebhookDnsResolver,
            NativeTlsWebhookExecutor::default(),
            WebhookSigningSecret::from_bytes(signing_key),
        );
        println!(
            "UCR_WEBHOOK_WORKER_READY poll_interval_ms={}",
            poll_interval.as_millis()
        );

        loop {
            let sweep = match self.dispatch_webhook_sweep(clock, &sink, &holder_id) {
                Ok(sweep) => sweep,
                Err(error) => {
                    let _ = self
                        .store
                        .release_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, &holder_id);
                    return Err(error);
                }
            };
            if sweep.delivered > 0
                || sweep.retry_scheduled > 0
                || sweep.dead_lettered > 0
                || sweep.rejected > 0
            {
                println!(
                    "UCR_WEBHOOK_WORKER_SWEEP targets={} delivered={} retry_scheduled={} dead_lettered={} rejected={}",
                    sweep.targets,
                    sweep.delivered,
                    sweep.retry_scheduled,
                    sweep.dead_lettered,
                    sweep.rejected,
                );
            }

            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|error| format!("webhook worker shutdown signal: {error}"))?;
                    self.store
                        .release_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, &holder_id)
                        .map_err(|error| format!("release webhook worker durable lease: {error:?}"))?;
                    println!("UCR_WEBHOOK_WORKER_STOPPED");
                    return Ok(());
                }
                () = tokio::time::sleep(poll_interval) => {}
            }
        }
    }

    /// Runs the production webhook worker using the shared rotation-safe signing provider.
    ///
    /// The current webhook signing version is resolved for every delivery attempt. Provider
    /// outages fail closed through the canonical retry path rather than falling back to a stale key.
    ///
    /// # Errors
    /// Rejects unsafe polling intervals, provider configuration failures, lease loss, and durable
    /// worker failures.
    pub async fn run_webhook_worker_with_secret_provider(
        self: Arc<Self>,
        provider: Arc<dyn SecretProvider>,
        handle: SecretHandle,
        poll_interval: Duration,
    ) -> Result<(), String> {
        if !(MIN_WEBHOOK_WORKER_POLL_INTERVAL..=MAX_WEBHOOK_WORKER_POLL_INTERVAL)
            .contains(&poll_interval)
        {
            return Err("webhook worker poll interval must be between 100 ms and 60 s".to_owned());
        }

        let clock = SystemEventDeliveryClock;
        let sink = HardenedWebhookSink::with_secret_provider(
            SystemWebhookDnsResolver,
            NativeTlsWebhookExecutor::default(),
            provider,
            handle,
        )
        .map_err(|error| format!("configure webhook signing provider: {error:?}"))?;

        let holder_id = generate_opaque_id()
            .map_err(|_| "generate webhook worker lease holder id".to_owned())?
            .as_str()
            .to_owned();
        let now_unix_ms = runtime_now_unix_ms()?;
        let acquired = self
            .store
            .try_acquire_runtime_worker_lease(
                WEBHOOK_DELIVERY_WORKER_KIND,
                &holder_id,
                now_unix_ms,
                WEBHOOK_WORKER_LEASE_DURATION_MS,
            )
            .map_err(|error| format!("acquire webhook worker durable lease: {error:?}"))?;
        if !acquired {
            return Err("another webhook worker holds the durable delivery lease".to_owned());
        }
        println!(
            "UCR_WEBHOOK_WORKER_READY poll_interval_ms={}",
            poll_interval.as_millis()
        );

        loop {
            let sweep = match self.dispatch_webhook_sweep(clock, &sink, &holder_id) {
                Ok(sweep) => sweep,
                Err(error) => {
                    let _ = self
                        .store
                        .release_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, &holder_id);
                    return Err(error);
                }
            };
            if sweep.delivered > 0
                || sweep.retry_scheduled > 0
                || sweep.dead_lettered > 0
                || sweep.rejected > 0
            {
                println!(
                    "UCR_WEBHOOK_WORKER_SWEEP targets={} delivered={} retry_scheduled={} dead_lettered={} rejected={}",
                    sweep.targets,
                    sweep.delivered,
                    sweep.retry_scheduled,
                    sweep.dead_lettered,
                    sweep.rejected,
                );
            }

            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    result.map_err(|error| format!("webhook worker shutdown signal: {error}"))?;
                    self.store
                        .release_runtime_worker_lease(WEBHOOK_DELIVERY_WORKER_KIND, &holder_id)
                        .map_err(|error| format!("release webhook worker durable lease: {error:?}"))?;
                    println!("UCR_WEBHOOK_WORKER_STOPPED");
                    return Ok(());
                }
                () = tokio::time::sleep(poll_interval) => {}
            }
        }
    }

    /// Executes one bounded durable Recording provider-operation sweep.
    ///
    /// This method does not enable Recording capability by itself. A deployment must provide a
    /// concrete `RecordingMediaProvider`; the durable outbox remains the retry/idempotency owner.
    ///
    /// # Errors
    /// Returns durable-store failures without dropping pending provider operations.
    pub fn dispatch_recording_provider_once(
        &self,
        provider: &dyn RecordingMediaProvider,
    ) -> Result<RecordingProviderDispatchSweep, String> {
        let now_unix_ms = runtime_now_unix_ms()?;
        dispatch_recording_provider_operations_once(
            self.store.as_ref(),
            provider,
            now_unix_ms,
            MAX_RECORDING_PROVIDER_OPERATION_BATCH,
        )
        .map_err(|error| format!("dispatch recording provider operations: {error:?}"))
    }

    /// Runs the durable finite-retention executor for Recording lifecycle state.
    ///
    /// The worker owns no recording/media state. It only discovers bounded due snapshots and
    /// delegates each candidate to the canonical atomic expiry+Event transition. A durable worker
    /// lease prevents concurrent active workers against the same `SQLite` store.
    ///
    /// # Errors
    /// Rejects unsafe polling intervals, lease loss, clock failures, and durable-store errors.
    pub async fn run_recording_retention_worker(
        self: Arc<Self>,
        poll_interval: Duration,
    ) -> Result<(), String> {
        if !(MIN_RECORDING_RETENTION_POLL_INTERVAL..=MAX_RECORDING_RETENTION_POLL_INTERVAL)
            .contains(&poll_interval)
        {
            return Err(
                "recording retention poll interval must be between 100 ms and 60 s".to_owned(),
            );
        }

        let holder_id = generate_opaque_id()
            .map_err(|_| "generate recording retention worker lease holder id".to_owned())?
            .as_str()
            .to_owned();
        let now_unix_ms = runtime_now_unix_ms()?;
        let acquired = self
            .store
            .try_acquire_runtime_worker_lease(
                RECORDING_RETENTION_WORKER_KIND,
                &holder_id,
                now_unix_ms,
                RECORDING_RETENTION_WORKER_LEASE_DURATION_MS,
            )
            .map_err(|error| format!("acquire recording retention worker lease: {error:?}"))?;
        if !acquired {
            return Err("another recording retention worker holds the durable lease".to_owned());
        }

        println!(
            "UCR_RECORDING_RETENTION_WORKER_READY poll_interval_ms={}",
            poll_interval.as_millis()
        );

        loop {
            if let Err(error) = self.renew_recording_retention_worker_lease(&holder_id) {
                let _ = self
                    .store
                    .release_runtime_worker_lease(RECORDING_RETENTION_WORKER_KIND, &holder_id);
                return Err(error);
            }
            let now_unix_ms = match runtime_now_unix_ms() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(error) => {
                    let _ = self
                        .store
                        .release_runtime_worker_lease(RECORDING_RETENTION_WORKER_KIND, &holder_id);
                    return Err(error);
                }
            };
            let sweep = match expire_due_recordings_once(
                self.store.as_ref(),
                now_unix_ms,
                MAX_RECORDING_RETENTION_BATCH,
            ) {
                Ok(sweep) => sweep,
                Err(error) => {
                    let _ = self
                        .store
                        .release_runtime_worker_lease(RECORDING_RETENTION_WORKER_KIND, &holder_id);
                    return Err(format!("expire due recordings: {error:?}"));
                }
            };
            if sweep.examined > 0 {
                println!(
                    "UCR_RECORDING_RETENTION_SWEEP examined={} expired={} stale={}",
                    sweep.examined, sweep.expired, sweep.stale
                );
            }

            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if let Err(error) = result {
                        let _ = self.store.release_runtime_worker_lease(
                            RECORDING_RETENTION_WORKER_KIND,
                            &holder_id,
                        );
                        return Err(format!("recording retention shutdown signal: {error}"));
                    }
                    self.store
                        .release_runtime_worker_lease(RECORDING_RETENTION_WORKER_KIND, &holder_id)
                        .map_err(|error| format!("release recording retention worker lease: {error:?}"))?;
                    println!("UCR_RECORDING_RETENTION_WORKER_STOPPED");
                    return Ok(());
                }
                () = tokio::time::sleep(poll_interval) => {}
            }
        }
    }

    fn renew_recording_retention_worker_lease(&self, holder_id: &str) -> Result<(), String> {
        let now_unix_ms = runtime_now_unix_ms()?;
        let renewed = self
            .store
            .renew_runtime_worker_lease(
                RECORDING_RETENTION_WORKER_KIND,
                holder_id,
                now_unix_ms,
                RECORDING_RETENTION_WORKER_LEASE_DURATION_MS,
            )
            .map_err(|error| format!("renew recording retention worker lease: {error:?}"))?;
        if renewed {
            Ok(())
        } else {
            Err("recording retention worker durable lease was lost or expired".to_owned())
        }
    }

    fn dispatch_webhook_sweep(
        &self,
        clock: SystemEventDeliveryClock,
        sink: &HardenedWebhookSink<SystemWebhookDnsResolver, NativeTlsWebhookExecutor>,
        holder_id: &str,
    ) -> Result<WebhookWorkerSweep, String> {
        self.renew_webhook_worker_lease(holder_id)?;
        let dispatcher = EventWebhookDispatcher::new(&clock, self.store.as_ref(), sink);
        let mut after = None;
        let mut sweep = WebhookWorkerSweep::default();

        loop {
            let targets = self
                .store
                .service_webhook_dispatch_targets(after.as_ref(), WEBHOOK_DISPATCH_TARGET_PAGE)
                .map_err(|error| format!("enumerate durable webhook targets: {error:?}"))?;
            if targets.is_empty() {
                break;
            }

            for (scope, subscription_id) in &targets {
                self.renew_webhook_worker_lease(holder_id)?;
                sweep.targets = sweep.targets.saturating_add(1);
                match dispatcher.dispatch_once(scope, subscription_id) {
                    Ok(WebhookDispatchOutcome::Delivered) => {
                        sweep.delivered = sweep.delivered.saturating_add(1);
                    }
                    Ok(WebhookDispatchOutcome::RetryScheduled) => {
                        sweep.retry_scheduled = sweep.retry_scheduled.saturating_add(1);
                    }
                    Ok(WebhookDispatchOutcome::DeadLettered) => {
                        sweep.dead_lettered = sweep.dead_lettered.saturating_add(1);
                    }
                    Ok(
                        WebhookDispatchOutcome::Idle | WebhookDispatchOutcome::RetryAfter { .. },
                    ) => {}
                    Err(
                        DurableStoreError::InvalidRecord
                        | DurableStoreError::Conflict
                        | DurableStoreError::PermissionDenied,
                    ) => {
                        sweep.rejected = sweep.rejected.saturating_add(1);
                    }
                    Err(error) => {
                        return Err(format!("dispatch durable webhook target: {error:?}"));
                    }
                }
            }

            if targets.len() < WEBHOOK_DISPATCH_TARGET_PAGE {
                break;
            }
            after = targets.last().cloned();
        }

        Ok(sweep)
    }

    fn renew_webhook_worker_lease(&self, holder_id: &str) -> Result<(), String> {
        let now_unix_ms = runtime_now_unix_ms()?;
        let renewed = self
            .store
            .renew_runtime_worker_lease(
                WEBHOOK_DELIVERY_WORKER_KIND,
                holder_id,
                now_unix_ms,
                WEBHOOK_WORKER_LEASE_DURATION_MS,
            )
            .map_err(|error| format!("renew webhook worker durable lease: {error:?}"))?;
        if renewed {
            Ok(())
        } else {
            Err("webhook worker durable lease was lost or expired".to_owned())
        }
    }

    /// Serves the existing public UCR gRPC contract as a durable local daemon.
    ///
    /// Phase 45 deliberately refuses non-loopback plaintext binds. A future remote-service mode
    /// requires an explicit authenticated TLS/public-listener boundary rather than silently
    /// widening this local IPC surface.
    ///
    /// # Errors
    /// Returns explicit bind, storage, or gRPC server errors.
    pub async fn serve(self: Arc<Self>, bind: SocketAddr) -> Result<(), String> {
        self.serve_api(bind, None, None).await
    }

    /// Serves the canonical API plus the private operator API on a separate loopback listener.
    ///
    /// # Errors
    /// Returns explicit bind, storage, or gRPC server errors.
    pub async fn serve_with_operator(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: SocketAddr,
    ) -> Result<(), String> {
        self.serve_api(bind, None, Some(operator_bind)).await
    }

    /// Serves the canonical API with verifier-only machine Bearer support.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_with_machine_bearer(
        self: Arc<Self>,
        bind: SocketAddr,
        machine_bearer: MachineBearerRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_api(bind, Some(machine_bearer), None).await
    }

    /// Serves the canonical API with machine Bearer support and a separately bound private
    /// operator API.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_with_machine_bearer_and_operator(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: SocketAddr,
        machine_bearer: MachineBearerRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_api(bind, Some(machine_bearer), Some(operator_bind))
            .await
    }

    async fn serve_api(
        self: Arc<Self>,
        bind: SocketAddr,
        machine_bearer: Option<MachineBearerRuntimeConfig>,
        operator_bind: Option<SocketAddr>,
    ) -> Result<(), String> {
        validate_local_bind(bind)?;
        let diagnostics = self.diagnostics()?;
        if diagnostics.storage_health != StorageHealth::Healthy {
            return Err("production runtime refuses unhealthy storage".to_owned());
        }

        let listener = TcpListener::bind(bind)
            .await
            .map_err(|error| format!("bind local runtime API: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("resolve local runtime API: {error}"))?;
        println!("UCR_RUNTIME_READY endpoint=http://{address}");
        println!("UCR_RUNTIME_MODE={RUNTIME_MODE} storage=sqlite auth=required test_mode=false");

        let incoming = TcpListenerStream::new(listener);
        let operator_incoming = match operator_bind {
            Some(operator_bind) => Some(
                bind_private_operator_listener(bind, operator_bind, "api")
                    .await?
                    .0,
            ),
            None => None,
        };
        let clock = Arc::new(SystemServiceQuotaClock);
        let event_clock = Arc::new(SystemEventDeliveryClock);
        let store = Arc::clone(&self.store);
        let authorization = Arc::clone(&self.store);
        let conference_state = Arc::new(ConferenceRuntimeState::new());
        let operator_health = Arc::new(ProductionOperatorHealthSource::basic(Arc::clone(&store)));
        let public_server = serve_api_public_services(
            clock,
            event_clock,
            store,
            authorization,
            conference_state,
            machine_bearer,
            incoming,
        );

        match operator_incoming {
            Some(operator_incoming) => {
                let operator_server =
                    serve_basic_operator_services(operator_health, operator_incoming);
                tokio::try_join!(public_server, operator_server)
                    .map(|_| ())
                    .map_err(|error| format!("local runtime/operator API server: {error}"))
            }
            None => public_server
                .await
                .map_err(|error| format!("local runtime API server: {error}")),
        }
    }

    /// Serves the canonical machine-auth gRPC service on a loopback-only listener.
    ///
    /// The signing key is deployment-owned and stable across restart. Public OAuth2/JWKS
    /// reachability belongs to a separate trusted HTTPS gateway; this method never exposes
    /// plaintext remotely.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_machine_auth(
        self: Arc<Self>,
        bind: SocketAddr,
        config: MachineAuthRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_machine_auth_inner(bind, None, config).await
    }

    /// Serves machine-auth plus the private operator API on a separate loopback listener.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_machine_auth_with_operator(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: SocketAddr,
        config: MachineAuthRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_machine_auth_inner(bind, Some(operator_bind), config)
            .await
    }

    async fn serve_machine_auth_inner(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: Option<SocketAddr>,
        config: MachineAuthRuntimeConfig,
    ) -> Result<(), String> {
        validate_local_bind(bind)?;
        if self.diagnostics()?.storage_health != StorageHealth::Healthy {
            return Err("production runtime refuses unhealthy storage".to_owned());
        }

        let listener = TcpListener::bind(bind)
            .await
            .map_err(|error| format!("bind local machine-auth API: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("resolve local machine-auth API: {error}"))?;
        println!("UCR_MACHINE_AUTH_READY endpoint=http://{address} tls_edge=required");
        println!("UCR_RUNTIME_MODE={RUNTIME_MODE} machine_auth=true test_mode=false");

        let incoming = TcpListenerStream::new(listener);
        let operator_incoming = match operator_bind {
            Some(operator_bind) => Some(
                bind_private_operator_listener(bind, operator_bind, "machine-auth")
                    .await?
                    .0,
            ),
            None => None,
        };
        let clock = Arc::new(SystemServiceQuotaClock);
        let store = Arc::clone(&self.store);
        let operator_health = Arc::new(ProductionOperatorHealthSource::basic(Arc::clone(&store)));
        let service = match config.signing {
            MachineAuthSigningConfig::Static {
                signing_key,
                verification_keys,
            } => GrpcMachineAuthService::new(
                clock,
                Arc::clone(&store),
                store,
                signing_key,
                verification_keys,
                config.policy,
                config.discovery,
            ),
            MachineAuthSigningConfig::Provider { provider, handle } => {
                GrpcMachineAuthService::with_secret_provider(
                    clock,
                    Arc::clone(&store),
                    store,
                    provider,
                    handle,
                    config.policy,
                    config.discovery,
                )?
            }
        };

        let public_server = Server::builder()
            .add_service(machine_auth_service_server(service))
            .serve_with_incoming(incoming);
        match operator_incoming {
            Some(operator_incoming) => {
                let operator_server =
                    serve_basic_operator_services(operator_health, operator_incoming);
                tokio::try_join!(public_server, operator_server)
                    .map(|_| ())
                    .map_err(|error| format!("local machine-auth/operator API server: {error}"))
            }
            None => public_server
                .await
                .map_err(|error| format!("local machine-auth API server: {error}")),
        }
    }

    /// Serves the canonical API plus Conference join and Realtime media on a loopback-only
    /// listener. Public reachability belongs to a separate authenticated TLS reverse proxy or
    /// gateway; this method never opens plaintext on a non-loopback address.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_realtime(
        self: Arc<Self>,
        bind: SocketAddr,
        config: RealtimeRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_realtime_inner(bind, None, config, None).await
    }

    /// Serves realtime plus a separately bound private operator/SFU placement API.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_realtime_with_operator(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: SocketAddr,
        config: RealtimeRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_realtime_inner(bind, Some(operator_bind), config, None)
            .await
    }

    /// Serves realtime plus Universal Conference with verifier-only machine Bearer support.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_realtime_with_machine_bearer(
        self: Arc<Self>,
        bind: SocketAddr,
        config: RealtimeRuntimeConfig,
        machine_bearer: MachineBearerRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_realtime_inner(bind, None, config, Some(machine_bearer))
            .await
    }

    /// Serves realtime with machine Bearer support and a separately bound private operator/SFU
    /// placement API.
    ///
    /// # Errors
    /// Returns explicit configuration, bind, storage, or gRPC server errors.
    pub async fn serve_realtime_with_machine_bearer_and_operator(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: SocketAddr,
        config: RealtimeRuntimeConfig,
        machine_bearer: MachineBearerRuntimeConfig,
    ) -> Result<(), String> {
        self.serve_realtime_inner(bind, Some(operator_bind), config, Some(machine_bearer))
            .await
    }

    async fn serve_realtime_inner(
        self: Arc<Self>,
        bind: SocketAddr,
        operator_bind: Option<SocketAddr>,
        config: RealtimeRuntimeConfig,
        machine_bearer: Option<MachineBearerRuntimeConfig>,
    ) -> Result<(), String> {
        if config.sfu_placement_media.is_some() && !config.sfu_placement_lifecycle {
            return Err(
                "SFU placement media routing requires the placement lifecycle gate".to_owned(),
            );
        }
        let (incoming, operator_incoming) = self
            .prepare_realtime_listeners(bind, operator_bind, config.sfu_placement_lifecycle)
            .await?;
        let resolved_operator_endpoint = operator_incoming.as_ref().map(|(_, address)| *address);
        let PreparedRealtimeRuntime {
            clock,
            event_clock,
            store,
            authorization,
            conference_state,
            runtime_capabilities,
            sfu_node_media_config,
            sfu_placement_service,
            realtime_service,
            sfu_expiry_task,
            bridge_task,
            sfu_node_media_service,
            operator_health,
            join_issuer,
        } = self.prepare_realtime_runtime(config, resolved_operator_endpoint)?;

        let services = RealtimeServerServices {
            clock,
            event_clock,
            store,
            authorization,
            conference_state,
            runtime_capabilities,
            join_issuer,
            machine_bearer,
            realtime_service,
        };
        let public_server = serve_realtime_services(services, incoming);
        let public_and_operator = async move {
            match operator_incoming {
                Some((operator_incoming, _operator_endpoint)) => {
                    let operator_server = serve_realtime_operator_services(
                        operator_health,
                        sfu_placement_service,
                        operator_incoming,
                    );
                    tokio::try_join!(public_server, operator_server)
                        .map(|_| ())
                        .map_err(|error| format!("local realtime/operator API server: {error}"))
                }
                None => public_server
                    .await
                    .map_err(|error| format!("local realtime API server: {error}")),
            }
        };
        let server_result = match (sfu_node_media_config, sfu_node_media_service) {
            (Some(config), Some(service)) => tokio::try_join!(
                public_and_operator,
                serve_sfu_node_media_services(config, service)
            )
            .map(|_| ()),
            (None, None) => public_and_operator.await,
            _ => Err("SFU node media runtime configuration mismatch".to_owned()),
        };
        bridge_task.abort();
        if let Some(task) = sfu_expiry_task {
            task.abort();
        }
        server_result
    }

    fn prepare_realtime_runtime(
        &self,
        config: RealtimeRuntimeConfig,
        resolved_operator_endpoint: Option<SocketAddr>,
    ) -> Result<PreparedRealtimeRuntime, String> {
        let clock = Arc::new(SystemServiceQuotaClock);
        let event_clock = Arc::new(SystemEventDeliveryClock);
        let store = Arc::clone(&self.store);
        let authorization = Arc::clone(&self.store);
        let conference_state = Arc::new(ConferenceRuntimeState::new());
        let runtime_capabilities = config.universal_conference_capabilities();
        let sfu_node_media_config = config.sfu_node_media.clone();
        let sfu_placement_lifecycle = config.sfu_placement_lifecycle;
        let sfu_placement_media_config = config.sfu_placement_media.clone();
        let dependencies = realtime_dependencies(config)?;
        let join_issuer = Arc::clone(&dependencies.join_issuer);
        let registry = Arc::clone(&dependencies.registry);
        let sfu_cluster = Arc::new(Mutex::new(SfuClusterDirectory::default()));
        let operator_health = realtime_operator_health(
            &store,
            &registry,
            &dependencies.live_provider,
            runtime_capabilities.turn,
            &sfu_cluster,
        );
        let lifecycle_placement_policy =
            sfu_placement_media_config
                .as_ref()
                .map(|config| SfuPlacementPolicy {
                    preferred_region: config.policy.preferred_region.clone(),
                    allow_cross_region_failover: config.policy.allow_cross_region_failover,
                });
        let sfu_placement_service = if let Some(policy) = lifecycle_placement_policy {
            GrpcSfuPlacementService::with_lifecycle_policy(
                Arc::clone(&clock),
                Arc::clone(&sfu_cluster),
                policy,
            )
        } else {
            GrpcSfuPlacementService::new(Arc::clone(&clock), Arc::clone(&sfu_cluster))
        };
        let realtime_service = GrpcRealtimeService::with_webrtc(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
            Arc::clone(&join_issuer),
            Arc::clone(&registry),
            Arc::clone(&conference_state),
            dependencies.webrtc,
        );
        let (realtime_service, sfu_expiry_task) = configure_sfu_placement_lifecycle(
            realtime_service,
            &sfu_placement_service,
            sfu_placement_lifecycle,
        );
        let realtime_service = configure_sfu_placement_media_router(
            realtime_service,
            resolved_operator_endpoint,
            sfu_placement_media_config,
        )?;
        let bridge_task = spawn_webrtc_e2ee_bridge(
            dependencies.e2ee_ingress,
            &dependencies.live_provider,
            &registry,
            &realtime_service,
        );
        let sfu_node_media_service = sfu_node_media_config.as_ref().map(|_| {
            let sink: Arc<dyn SfuForwardSink> = Arc::new(WebRtcE2eeForwardSink {
                registry: Arc::clone(&registry),
                provider: Arc::clone(&dependencies.live_provider),
            });
            GrpcSfuNodeMediaService::new(Arc::clone(&authorization), Arc::clone(&store), sink)
        });

        Ok(PreparedRealtimeRuntime {
            clock,
            event_clock,
            store,
            authorization,
            conference_state,
            runtime_capabilities,
            sfu_node_media_config,
            sfu_placement_service,
            realtime_service,
            sfu_expiry_task,
            bridge_task,
            sfu_node_media_service,
            operator_health,
            join_issuer,
        })
    }

    async fn prepare_realtime_listeners(
        &self,
        bind: SocketAddr,
        operator_bind: Option<SocketAddr>,
        sfu_placement_lifecycle: bool,
    ) -> Result<(TcpListenerStream, Option<(TcpListenerStream, SocketAddr)>), String> {
        validate_local_bind(bind)?;
        if sfu_placement_lifecycle && operator_bind.is_none() {
            return Err(
                "SFU placement lifecycle requires the private realtime operator plane".to_owned(),
            );
        }
        if self.diagnostics()?.storage_health != StorageHealth::Healthy {
            return Err("production runtime refuses unhealthy storage".to_owned());
        }

        let listener = TcpListener::bind(bind)
            .await
            .map_err(|error| format!("bind local realtime API: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("resolve local realtime API: {error}"))?;
        println!("UCR_REALTIME_READY endpoint=http://{address}");
        println!("UCR_RUNTIME_MODE={RUNTIME_MODE} realtime=true tls_edge=required test_mode=false");
        let incoming = TcpListenerStream::new(listener);
        let operator_incoming = bind_realtime_operator_listener(bind, operator_bind).await?;
        Ok((incoming, operator_incoming))
    }
}

async fn bind_realtime_operator_listener(
    public_bind: SocketAddr,
    operator_bind: Option<SocketAddr>,
) -> Result<Option<(TcpListenerStream, SocketAddr)>, String> {
    let Some(operator_bind) = operator_bind else {
        return Ok(None);
    };
    bind_private_operator_listener(public_bind, operator_bind, "realtime")
        .await
        .map(Some)
}

async fn serve_api_public_services(
    clock: Arc<SystemServiceQuotaClock>,
    event_clock: Arc<SystemEventDeliveryClock>,
    store: Arc<SqliteLocalStore>,
    authorization: Arc<SqliteLocalStore>,
    conference_state: Arc<ConferenceRuntimeState>,
    machine_bearer: Option<MachineBearerRuntimeConfig>,
    incoming: TcpListenerStream,
) -> Result<(), tonic::transport::Error> {
    let mut universal_service = GrpcUniversalConferenceService::with_state(
        Arc::clone(&clock),
        Arc::clone(&authorization),
        Arc::clone(&store),
        Arc::clone(&conference_state),
    );
    let attachment_service =
        configured_attachment_service(&clock, &authorization, &store, machine_bearer.as_ref());
    if let Some(config) = machine_bearer {
        match config.verification {
            MachineBearerVerificationConfig::Static(keys) => {
                universal_service = universal_service.with_machine_bearer_auth(keys, config.policy);
            }
            MachineBearerVerificationConfig::Provider(provider) => {
                universal_service =
                    universal_service.with_machine_bearer_auth_provider(provider, config.policy);
            }
        }
    }

    Server::builder()
        .add_service(integration_service_server(GrpcIntegrationService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(attachment_service_server(attachment_service))
        .add_service(group_service_server(GrpcGroupService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(device_service_server(GrpcDeviceService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(sync_service_server(GrpcSyncService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(call_service_server(GrpcCallService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(conference_service_server(
            GrpcConferenceService::with_state(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
                Arc::clone(&conference_state),
            ),
        ))
        .add_service(universal_conference_service_server(universal_service))
        .add_service(event_service_server(GrpcEventService::new(
            Arc::clone(&clock),
            event_clock,
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(store_forward_service_server(GrpcStoreForwardService::new(
            clock,
            authorization,
            store,
        )))
        .serve_with_incoming(incoming)
        .await
}

struct RealtimeServerServices {
    clock: Arc<SystemServiceQuotaClock>,
    event_clock: Arc<SystemEventDeliveryClock>,
    store: Arc<SqliteLocalStore>,
    authorization: Arc<SqliteLocalStore>,
    conference_state: Arc<ConferenceRuntimeState>,
    runtime_capabilities: UniversalConferenceRuntimeCapabilities,
    join_issuer: Arc<JoinTokenIssuer>,
    machine_bearer: Option<MachineBearerRuntimeConfig>,
    realtime_service:
        GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
}

async fn serve_realtime_services(
    services: RealtimeServerServices,
    incoming: TcpListenerStream,
) -> Result<(), tonic::transport::Error> {
    let RealtimeServerServices {
        clock,
        event_clock,
        store,
        authorization,
        conference_state,
        runtime_capabilities,
        join_issuer,
        machine_bearer,
        realtime_service,
    } = services;
    let mut universal_service =
        GrpcUniversalConferenceService::with_state_join_issuer_and_runtime_capabilities(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
            Arc::clone(&conference_state),
            Arc::clone(&join_issuer),
            runtime_capabilities,
        );
    let mut recording_service = GrpcRecordingService::new(
        Arc::clone(&clock),
        Arc::clone(&authorization),
        Arc::clone(&store),
        Arc::clone(&join_issuer),
        runtime_capabilities.recording,
    );
    let attachment_service =
        configured_attachment_service(&clock, &authorization, &store, machine_bearer.as_ref());
    (universal_service, recording_service) =
        apply_realtime_machine_bearer(universal_service, recording_service, machine_bearer);

    Server::builder()
        .add_service(integration_service_server(GrpcIntegrationService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(attachment_service_server(attachment_service))
        .add_service(group_service_server(GrpcGroupService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(device_service_server(GrpcDeviceService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(sync_service_server(GrpcSyncService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(call_service_server(GrpcCallService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(conference_service_server(
            GrpcConferenceService::with_state_and_join_issuer(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
                Arc::clone(&conference_state),
                Arc::clone(&join_issuer),
            ),
        ))
        .add_service(realtime_service_server(realtime_service))
        .add_service(universal_conference_service_server(universal_service))
        .add_service(recording_service_server(recording_service))
        .add_service(event_service_server(GrpcEventService::new(
            Arc::clone(&clock),
            event_clock,
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
        .add_service(store_forward_service_server(GrpcStoreForwardService::new(
            clock,
            authorization,
            store,
        )))
        .serve_with_incoming(incoming)
        .await
}

async fn bind_private_operator_listener(
    public_bind: SocketAddr,
    operator_bind: SocketAddr,
    mode: &str,
) -> Result<(TcpListenerStream, SocketAddr), String> {
    validate_local_bind(operator_bind)?;
    if public_bind == operator_bind && public_bind.port() != 0 {
        return Err("operator bind must be different from the public runtime bind".to_owned());
    }
    let listener = TcpListener::bind(operator_bind)
        .await
        .map_err(|error| format!("bind private operator API: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve private operator API: {error}"))?;
    println!("UCR_OPERATOR_READY endpoint=http://{address} mode={mode} private=true");
    Ok((TcpListenerStream::new(listener), address))
}

async fn serve_sfu_node_media_services(
    config: SfuNodeMediaRuntimeConfig,
    service: GrpcSfuNodeMediaService<SqliteLocalStore, SqliteLocalStore>,
) -> Result<(), String> {
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("bind private SFU node media listener: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve private SFU node media listener: {error}"))?;
    println!("UCR_SFU_NODE_MEDIA_READY endpoint=https://{address} private=true mtls=required");
    serve_sfu_node_media_listener(config, service, listener).await
}

#[derive(Debug)]
struct SfuNodeMediaConnection {
    stream: TcpStream,
    closed: Option<oneshot::Sender<()>>,
}

impl SfuNodeMediaConnection {
    fn new(stream: TcpStream, closed: oneshot::Sender<()>) -> Self {
        Self {
            stream,
            closed: Some(closed),
        }
    }
}

impl Drop for SfuNodeMediaConnection {
    fn drop(&mut self) {
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}

impl Connected for SfuNodeMediaConnection {
    type ConnectInfo = <TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for SfuNodeMediaConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for SfuNodeMediaConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

async fn serve_sfu_node_media_listener(
    config: SfuNodeMediaRuntimeConfig,
    service: GrpcSfuNodeMediaService<SqliteLocalStore, SqliteLocalStore>,
    listener: TcpListener,
) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept private SFU node media connection: {error}"))?;
        let connection_config = config.clone();
        let connection_service = service.clone();
        tokio::spawn(async move {
            let mut server = match connection_config.tls_server() {
                Ok(server) => server,
                Err(error) => {
                    eprintln!("ucr-runtime: reject SFU node media connection: {error}");
                    return;
                }
            };
            let (closed_tx, closed_rx) = oneshot::channel();
            let connection = SfuNodeMediaConnection::new(stream, closed_tx);
            let incoming = tokio_stream::once(Ok::<_, std::io::Error>(connection)).chain(
                tokio_stream::pending::<Result<SfuNodeMediaConnection, std::io::Error>>(),
            );
            if let Err(error) = server
                .add_service(sfu_node_media_service_server(connection_service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = closed_rx.await;
                })
                .await
            {
                eprintln!("ucr-runtime: SFU node media connection closed: {error}");
            }
        });
    }
}

async fn serve_basic_operator_services(
    operator_health: Arc<ProductionOperatorHealthSource>,
    incoming: TcpListenerStream,
) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .add_service(operator_runtime_service_server(
            GrpcOperatorRuntimeService::new(operator_health),
        ))
        .serve_with_incoming(incoming)
        .await
}

async fn serve_realtime_operator_services(
    operator_health: Arc<ProductionOperatorHealthSource>,
    sfu_placement_service: GrpcSfuPlacementService<SystemServiceQuotaClock>,
    incoming: TcpListenerStream,
) -> Result<(), tonic::transport::Error> {
    Server::builder()
        .add_service(operator_runtime_service_server(
            GrpcOperatorRuntimeService::new(operator_health),
        ))
        .add_service(sfu_placement_service_server(sfu_placement_service))
        .serve_with_incoming(incoming)
        .await
}

fn configured_attachment_service(
    clock: &Arc<SystemServiceQuotaClock>,
    authorization: &Arc<SqliteLocalStore>,
    store: &Arc<SqliteLocalStore>,
    machine_bearer: Option<&MachineBearerRuntimeConfig>,
) -> GrpcAttachmentService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore> {
    let service = GrpcAttachmentService::new(
        Arc::clone(clock),
        Arc::clone(authorization),
        Arc::clone(store),
    );
    match machine_bearer {
        None => service,
        Some(config) => match &config.verification {
            MachineBearerVerificationConfig::Static(keys) => {
                service.with_machine_bearer_auth(Arc::clone(keys), config.policy.clone())
            }
            MachineBearerVerificationConfig::Provider(provider) => service
                .with_machine_bearer_auth_provider(Arc::clone(provider), config.policy.clone()),
        },
    }
}

fn apply_realtime_machine_bearer(
    mut universal_service: GrpcUniversalConferenceService<
        SystemServiceQuotaClock,
        SqliteLocalStore,
        SqliteLocalStore,
    >,
    mut recording_service: GrpcRecordingService<
        SystemServiceQuotaClock,
        SqliteLocalStore,
        SqliteLocalStore,
    >,
    machine_bearer: Option<MachineBearerRuntimeConfig>,
) -> (
    GrpcUniversalConferenceService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    GrpcRecordingService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
) {
    if let Some(config) = machine_bearer {
        match config.verification {
            MachineBearerVerificationConfig::Static(keys) => {
                universal_service = universal_service
                    .with_machine_bearer_auth(Arc::clone(&keys), config.policy.clone());
                recording_service = recording_service.with_machine_bearer_auth(keys, config.policy);
            }
            MachineBearerVerificationConfig::Provider(provider) => {
                universal_service = universal_service.with_machine_bearer_auth_provider(
                    Arc::clone(&provider),
                    config.policy.clone(),
                );
                recording_service =
                    recording_service.with_machine_bearer_auth_provider(provider, config.policy);
            }
        }
    }
    (universal_service, recording_service)
}

struct RealtimeRuntimeDependencies {
    join_issuer: Arc<JoinTokenIssuer>,
    registry: Arc<RealtimeSessionRegistry>,
    webrtc: RealtimeWebRtcDependencies,
    live_provider: Arc<LiveWebRtcProvider>,
    e2ee_ingress: tokio::sync::mpsc::Receiver<WebRtcE2eeIngressFrame>,
}

fn realtime_dependencies(
    config: RealtimeRuntimeConfig,
) -> Result<RealtimeRuntimeDependencies, String> {
    let RealtimeRuntimeConfig {
        join_issuer,
        webrtc_config,
        browser_realtime_gateway: _,
        sfu_node_media: _,
        sfu_placement_lifecycle,
        sfu_placement_media: _,
    } = config;
    let (e2ee_ingress_tx, e2ee_ingress) =
        tokio::sync::mpsc::channel(LIVE_WEBRTC_E2EE_INGRESS_CAPACITY);
    let live_provider = Arc::new(
        LiveWebRtcProvider::with_e2ee_ingress(e2ee_ingress_tx)
            .map_err(|error| format!("start live WebRTC provider: {error:?}"))?,
    );
    let provider: Arc<dyn WebRtcProvider> = live_provider.clone();
    let registry = if sfu_placement_lifecycle {
        RealtimeSessionRegistry::with_expired_call_cleanup(
            ucr_realtime::MAX_REALTIME_SESSIONS,
            ucr_realtime::DEFAULT_REALTIME_QUEUE_CAPACITY,
        )
    } else {
        RealtimeSessionRegistry::default()
    };
    Ok(RealtimeRuntimeDependencies {
        join_issuer,
        registry: Arc::new(registry),
        webrtc: RealtimeWebRtcDependencies::new(provider, webrtc_config),
        live_provider,
        e2ee_ingress,
    })
}

#[derive(Debug)]
struct WebRtcE2eeForwardSink {
    registry: Arc<RealtimeSessionRegistry>,
    provider: Arc<LiveWebRtcProvider>,
}

impl SfuForwardSink for WebRtcE2eeForwardSink {
    fn forward_encrypted(
        &self,
        target: &ucr_model::SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let now_unix_ms = runtime_now_unix_ms().map_err(|_| SfuForwardSinkError::Unavailable)?;
        let sessions = self
            .registry
            .active_session_ids_for_recipient(
                &envelope.frame.header.scope,
                &envelope.frame.header.call_id,
                &target.recipient,
                now_unix_ms,
            )
            .map_err(|_| SfuForwardSinkError::Unavailable)?;
        if sessions.is_empty() {
            return Err(SfuForwardSinkError::Unavailable);
        }
        let mut accepted = false;
        let mut saw_backpressure = false;
        for session_id in sessions {
            match self.provider.send_e2ee_envelope(&session_id, envelope) {
                Ok(()) => accepted = true,
                Err(WebRtcProviderError::SessionUnavailable) => {}
                Err(WebRtcProviderError::CapacityExceeded) => saw_backpressure = true,
                Err(error) => return Err(map_webrtc_sink_error(error)),
            }
        }
        if accepted {
            Ok(())
        } else if saw_backpressure {
            Err(SfuForwardSinkError::Backpressure)
        } else {
            Err(SfuForwardSinkError::Unavailable)
        }
    }
}

fn realtime_operator_health(
    store: &Arc<SqliteLocalStore>,
    registry: &Arc<RealtimeSessionRegistry>,
    live_provider: &Arc<LiveWebRtcProvider>,
    turn_configured: bool,
    sfu_cluster: &Arc<Mutex<SfuClusterDirectory>>,
) -> Arc<ProductionOperatorHealthSource> {
    Arc::new(ProductionOperatorHealthSource::realtime(
        Arc::clone(store),
        Arc::clone(registry),
        Arc::clone(live_provider),
        turn_configured,
        Arc::clone(sfu_cluster),
    ))
}

fn configure_sfu_placement_media_router(
    realtime_service: GrpcRealtimeService<
        SystemServiceQuotaClock,
        SqliteLocalStore,
        SqliteLocalStore,
    >,
    operator_bind: Option<SocketAddr>,
    config: Option<SfuPlacementMediaRuntimeConfig>,
) -> Result<GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>, String>
{
    let Some(config) = config else {
        return Ok(realtime_service);
    };
    let operator_endpoint = operator_bind.ok_or_else(|| {
        "SFU placement media routing requires the private realtime operator plane".to_owned()
    })?;
    let router = PlacementAwareSfuNodeRouter::connect_lazy(
        operator_endpoint,
        config.node_tls,
        config.policy,
    )
    .map_err(|error| format!("configure SFU placement media router: {error:?}"))?;
    let router: Arc<dyn RealtimeSfuMediaRouter> = Arc::new(router);
    Ok(realtime_service.with_sfu_media_router(router))
}

fn configure_sfu_placement_lifecycle(
    realtime_service: GrpcRealtimeService<
        SystemServiceQuotaClock,
        SqliteLocalStore,
        SqliteLocalStore,
    >,
    sfu_placement_service: &GrpcSfuPlacementService<SystemServiceQuotaClock>,
    enabled: bool,
) -> (
    GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if !enabled {
        return (realtime_service, None);
    }
    let lifecycle: Arc<dyn RealtimeSfuPlacementLifecycle> = Arc::new(sfu_placement_service.clone());
    let realtime_service = realtime_service.with_sfu_placement_lifecycle(lifecycle);
    let task = spawn_sfu_placement_expiry_sweeper(
        realtime_service.clone(),
        DEFAULT_SFU_PLACEMENT_EXPIRY_SWEEP_INTERVAL,
    );
    (realtime_service, Some(task))
}

fn spawn_sfu_placement_expiry_sweeper(
    service: GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_sfu_placement_expiry_sweeper(service, interval))
}

async fn run_sfu_placement_expiry_sweeper(
    service: GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Ok(now_unix_ms) = runtime_now_unix_ms() else {
            continue;
        };
        let _ = service.sweep_expired_sfu_placements_at(now_unix_ms).await;
    }
}

fn spawn_webrtc_e2ee_bridge(
    ingress: tokio::sync::mpsc::Receiver<WebRtcE2eeIngressFrame>,
    provider: &Arc<LiveWebRtcProvider>,
    registry: &Arc<RealtimeSessionRegistry>,
    service: &GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_webrtc_e2ee_bridge(
        ingress,
        Arc::clone(provider),
        Arc::clone(registry),
        service.clone(),
    ))
}

async fn run_webrtc_e2ee_bridge(
    mut ingress: tokio::sync::mpsc::Receiver<WebRtcE2eeIngressFrame>,
    provider: Arc<LiveWebRtcProvider>,
    registry: Arc<RealtimeSessionRegistry>,
    service: GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
) {
    while let Some(frame) = ingress.recv().await {
        if service.has_sfu_media_router() {
            let _ = route_webrtc_e2ee_frame_via_configured_route(
                &service, &registry, &provider, &frame,
            )
            .await;
            continue;
        }
        let provider = Arc::clone(&provider);
        let registry = Arc::clone(&registry);
        let service = service.clone();
        let _ = tokio::task::spawn_blocking(move || {
            route_webrtc_e2ee_frame(&service, &registry, &provider, &frame)
        })
        .await;
    }
}

async fn route_webrtc_e2ee_frame_via_configured_route(
    service: &GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    registry: &Arc<RealtimeSessionRegistry>,
    provider: &Arc<LiveWebRtcProvider>,
    frame: &WebRtcE2eeIngressFrame,
) -> Result<usize, ()> {
    let now_unix_ms = runtime_now_unix_ms().map_err(|_| ())?;
    let header = &frame.envelope.frame.header;
    let claims = registry
        .active_claims_for_ingress(
            &frame.session_id,
            &header.scope,
            &header.call_id,
            now_unix_ms,
        )
        .map_err(|_| ())?;
    let sink = WebRtcE2eeForwardSink {
        registry: Arc::clone(registry),
        provider: Arc::clone(provider),
    };
    service
        .forward_authenticated_e2ee_media_via_configured_route(&claims, &frame.envelope, &sink)
        .await
        .map_err(|_| ())
}

fn route_webrtc_e2ee_frame(
    service: &GrpcRealtimeService<SystemServiceQuotaClock, SqliteLocalStore, SqliteLocalStore>,
    registry: &Arc<RealtimeSessionRegistry>,
    provider: &Arc<LiveWebRtcProvider>,
    frame: &WebRtcE2eeIngressFrame,
) -> Result<usize, ()> {
    let now_unix_ms = runtime_now_unix_ms().map_err(|_| ())?;
    let header = &frame.envelope.frame.header;
    let claims = registry
        .active_claims_for_ingress(
            &frame.session_id,
            &header.scope,
            &header.call_id,
            now_unix_ms,
        )
        .map_err(|_| ())?;
    let sink = WebRtcE2eeForwardSink {
        registry: Arc::clone(registry),
        provider: Arc::clone(provider),
    };
    service
        .forward_authenticated_e2ee_media(&claims, &frame.envelope, &sink)
        .map_err(|_| ())
}

const fn map_webrtc_sink_error(error: WebRtcProviderError) -> SfuForwardSinkError {
    match error {
        WebRtcProviderError::CapacityExceeded => SfuForwardSinkError::Backpressure,
        WebRtcProviderError::SessionUnavailable
        | WebRtcProviderError::TemporarilyUnavailable
        | WebRtcProviderError::Internal => SfuForwardSinkError::Unavailable,
        WebRtcProviderError::InvalidProtocol(_) | WebRtcProviderError::Conflict => {
            SfuForwardSinkError::Rejected
        }
    }
}

fn runtime_now_unix_ms() -> Result<i64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes unix epoch".to_owned())?
        .as_millis();
    i64::try_from(millis).map_err(|_| "system clock exceeds realtime range".to_owned())
}

/// Refuses plaintext remote exposure for the Phase-45 local-daemon production boundary.
///
/// # Errors
/// Returns an error for every non-loopback bind.
pub fn validate_local_bind(bind: SocketAddr) -> Result<(), String> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err("production local-daemon API requires a loopback bind".to_owned())
    }
}

fn validate_public_https_url(value: &str, label: &str) -> Result<(), String> {
    if value.starts_with("https://")
        && value.len() > "https://".len()
        && !value.chars().any(char::is_whitespace)
    {
        Ok(())
    } else {
        Err(format!("{label} must be an absolute HTTPS URL"))
    }
}

fn runtime_opaque(value: &str, label: &str) -> Result<OpaqueId, String> {
    OpaqueId::new(value.to_owned()).map_err(|_| format!("invalid {label}"))
}

fn diagnostics_for(store: &SqliteLocalStore) -> Result<RuntimeDiagnostics, String> {
    let schema_version = store
        .schema_version()
        .map_err(|error| format!("read durable schema version: {error:?}"))?;
    let storage_health = store
        .health()
        .map_err(|error| format!("read durable storage health: {error:?}"))?;
    Ok(RuntimeDiagnostics {
        schema_version,
        storage_health,
        runtime_mode: RUNTIME_MODE,
    })
}

const fn health_label(health: StorageHealth) -> &'static str {
    match health {
        StorageHealth::Healthy => "healthy",
        StorageHealth::ReadOnly => "read_only",
        StorageHealth::Unavailable => "unavailable",
        StorageHealth::Corrupt => "corrupt",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use ucr_secrets::{InMemorySecretProvider, SecretMaterial, SecretVersion};

    struct TestMtlsMaterial {
        ca: String,
        server_certificate: String,
        server_private_key: String,
        rotated_server_certificate: String,
        rotated_server_private_key: String,
        client_certificate: String,
        client_private_key: String,
    }

    fn test_mtls_leaf(
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        name: &str,
        usage: ExtendedKeyUsagePurpose,
    ) -> (String, String) {
        let mut params =
            CertificateParams::new(vec![name.to_owned()]).expect("test certificate name");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(usage);
        let key = KeyPair::generate().expect("test leaf key");
        let certificate = params
            .signed_by(&key, ca, ca_key)
            .expect("test leaf certificate");
        (certificate.pem(), key.serialize_pem())
    }

    fn test_mtls_material() -> TestMtlsMaterial {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("test CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
        let ca_key = KeyPair::generate().expect("test CA key");
        let ca = ca_params.self_signed(&ca_key).expect("test CA certificate");
        let (server_certificate_pem, server_private_key_pem) = test_mtls_leaf(
            &ca,
            &ca_key,
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (rotated_server_certificate_pem, rotated_server_private_key_pem) = test_mtls_leaf(
            &ca,
            &ca_key,
            "rotated.localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (client_certificate_pem, client_private_key_pem) = test_mtls_leaf(
            &ca,
            &ca_key,
            "ucr-sfu-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        TestMtlsMaterial {
            ca: ca.pem(),
            server_certificate: server_certificate_pem,
            server_private_key: server_private_key_pem,
            rotated_server_certificate: rotated_server_certificate_pem,
            rotated_server_private_key: rotated_server_private_key_pem,
            client_certificate: client_certificate_pem,
            client_private_key: client_private_key_pem,
        }
    }

    fn test_sfu_node_tls_config_with_provider(
        material: &TestMtlsMaterial,
    ) -> (
        SfuNodeMediaRuntimeConfig,
        Arc<InMemorySecretProvider>,
        SecretHandle,
        SecretHandle,
    ) {
        let provider = Arc::new(InMemorySecretProvider::default());
        let certificate_handle = SecretHandle {
            secret_id: OpaqueId::new("sfu-test-certificate").expect("certificate secret id"),
            purpose: SecretPurpose::TlsCertificate,
        };
        let private_key_handle = SecretHandle {
            secret_id: OpaqueId::new("sfu-test-private-key").expect("private key secret id"),
            purpose: SecretPurpose::TlsPrivateKey,
        };
        provider
            .provision(
                certificate_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("cert-v1").expect("certificate version id"),
                    material: SecretMaterial::new(material.server_certificate.as_bytes().to_vec())
                        .expect("certificate material"),
                },
            )
            .expect("provision certificate");
        provider
            .provision(
                private_key_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("key-v1").expect("private key version id"),
                    material: SecretMaterial::new(material.server_private_key.as_bytes().to_vec())
                        .expect("private key material"),
                },
            )
            .expect("provision private key");
        let provider_boundary: Arc<dyn SecretProvider> = provider.clone();
        let config = SfuNodeMediaRuntimeConfig::new(
            "127.0.0.1:0".parse().expect("private bind"),
            provider_boundary,
            certificate_handle.clone(),
            private_key_handle.clone(),
            material.ca.as_bytes().to_vec(),
            None,
        )
        .expect("SFU node TLS config");
        (config, provider, certificate_handle, private_key_handle)
    }

    fn test_sfu_node_tls_config(material: &TestMtlsMaterial) -> SfuNodeMediaRuntimeConfig {
        test_sfu_node_tls_config_with_provider(material).0
    }

    #[derive(Debug)]
    struct AcceptAllSfuSink;

    impl SfuForwardSink for AcceptAllSfuSink {
        fn forward_encrypted(
            &self,
            _target: &ucr_model::SfuForwardTarget,
            _envelope: &SfuForwardEnvelope,
        ) -> Result<(), SfuForwardSinkError> {
            Ok(())
        }
    }

    #[test]
    fn private_sfu_node_listener_rejects_public_or_unspecified_bind() {
        assert!(
            validate_private_sfu_node_bind("127.0.0.1:7001".parse().expect("loopback")).is_ok()
        );
        assert!(validate_private_sfu_node_bind("10.42.0.8:7001".parse().expect("private")).is_ok());
        assert!(validate_private_sfu_node_bind("8.8.8.8:7001".parse().expect("public")).is_err());
        assert!(
            validate_private_sfu_node_bind("0.0.0.0:7001".parse().expect("unspecified")).is_err()
        );
    }

    #[tokio::test]
    async fn private_sfu_node_listener_observes_rotated_server_identity_on_new_connection() {
        let initial = test_mtls_material();
        let (config, provider, certificate_handle, private_key_handle) =
            test_sfu_node_tls_config_with_provider(&initial);
        let listener = TcpListener::bind(config.bind)
            .await
            .expect("bind reloadable SFU node listener");
        let address = listener.local_addr().expect("SFU node listener address");
        let path = std::env::temp_dir().join(format!(
            "ucr-runtime-sfu-reload-{}-{}.sqlite",
            std::process::id(),
            runtime_now_unix_ms().expect("clock")
        ));
        let store = Arc::new(SqliteLocalStore::open(&path).expect("open store"));
        let sink: Arc<dyn SfuForwardSink> = Arc::new(AcceptAllSfuSink);
        let service = GrpcSfuNodeMediaService::new(Arc::clone(&store), Arc::clone(&store), sink);
        let server_task = tokio::spawn(serve_sfu_node_media_listener(config, service, listener));

        let client_certificate = initial.client_certificate.clone();
        let client_private_key = initial.client_private_key.clone();
        let connect = |server_ca: String, server_name: &'static str| {
            let client_certificate = client_certificate.clone();
            let client_private_key = client_private_key.clone();
            async move {
                let uri = format!("https://127.0.0.1:{}", address.port());
                let tls = tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(server_ca))
                    .domain_name(server_name)
                    .identity(Identity::from_pem(
                        client_certificate.as_bytes(),
                        client_private_key.as_bytes(),
                    ));
                let channel = tonic::transport::Endpoint::from_shared(uri)
                    .expect("endpoint")
                    .tls_config(tls)
                    .expect("TLS config")
                    .connect()
                    .await
                    .expect("mTLS channel");
                let mut client =
                    pb::sfu_node_media_service_client::SfuNodeMediaServiceClient::new(channel);
                client
                    .forward_encrypted(tokio_stream::empty::<pb::SfuNodeEncryptedMedia>())
                    .await
                    .expect("mTLS request");
            }
        };

        connect(initial.ca.clone(), "localhost").await;

        provider
            .rotate(
                &certificate_handle,
                SecretVersion {
                    version_id: OpaqueId::new("cert-v2").expect("certificate version id"),
                    material: SecretMaterial::new(
                        initial.rotated_server_certificate.as_bytes().to_vec(),
                    )
                    .expect("certificate material"),
                },
            )
            .expect("rotate server certificate");
        provider
            .rotate(
                &private_key_handle,
                SecretVersion {
                    version_id: OpaqueId::new("key-v2").expect("private key version id"),
                    material: SecretMaterial::new(
                        initial.rotated_server_private_key.as_bytes().to_vec(),
                    )
                    .expect("private key material"),
                },
            )
            .expect("rotate server private key");

        connect(initial.ca.clone(), "rotated.localhost").await;

        server_task.abort();
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn private_sfu_node_listener_enforces_real_mtls_handshake() {
        let material = test_mtls_material();
        let config = test_sfu_node_tls_config(&material);
        let listener = TcpListener::bind(config.bind)
            .await
            .expect("bind SFU node listener");
        let address = listener.local_addr().expect("SFU node listener address");
        let path = std::env::temp_dir().join(format!(
            "ucr-runtime-sfu-mtls-{}-{}.sqlite",
            std::process::id(),
            runtime_now_unix_ms().expect("clock")
        ));
        let store = Arc::new(SqliteLocalStore::open(&path).expect("open store"));
        let sink: Arc<dyn SfuForwardSink> = Arc::new(AcceptAllSfuSink);
        let service = GrpcSfuNodeMediaService::new(Arc::clone(&store), Arc::clone(&store), sink);
        let mut server = config.tls_server().expect("SFU node TLS server");
        let server_task = tokio::spawn(async move {
            server
                .add_service(sfu_node_media_service_server(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        });

        let uri = format!("https://127.0.0.1:{}", address.port());
        let unauthenticated_tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(material.ca.as_bytes()))
            .domain_name("localhost");
        let unauthenticated_rejected = match tonic::transport::Endpoint::from_shared(uri.clone())
            .expect("unauthenticated endpoint")
            .tls_config(unauthenticated_tls)
            .expect("unauthenticated TLS config")
            .connect()
            .await
        {
            Err(_) => true,
            Ok(channel) => {
                let mut client =
                    pb::sfu_node_media_service_client::SfuNodeMediaServiceClient::new(channel);
                client
                    .forward_encrypted(tokio_stream::empty::<pb::SfuNodeEncryptedMedia>())
                    .await
                    .is_err()
            }
        };
        assert!(
            unauthenticated_rejected,
            "server accepted an SFU node RPC without a client certificate"
        );

        let authenticated_tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(material.ca.as_bytes()))
            .domain_name("localhost")
            .identity(Identity::from_pem(
                material.client_certificate.as_bytes(),
                material.client_private_key.as_bytes(),
            ));
        let channel = tonic::transport::Endpoint::from_shared(uri)
            .expect("authenticated endpoint")
            .tls_config(authenticated_tls)
            .expect("authenticated TLS config")
            .connect()
            .await
            .expect("mutually authenticated channel");
        let mut client = pb::sfu_node_media_service_client::SfuNodeMediaServiceClient::new(channel);
        client
            .forward_encrypted(tokio_stream::empty::<pb::SfuNodeEncryptedMedia>())
            .await
            .expect("mTLS request reaches peer-certificate-gated service");

        server_task.abort();
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn private_operator_listener_reports_resolved_ephemeral_address() {
        let public_bind: SocketAddr = "127.0.0.1:55051".parse().expect("public bind");
        let operator_bind: SocketAddr = "127.0.0.1:0".parse().expect("operator bind");
        let (_incoming, resolved) =
            bind_private_operator_listener(public_bind, operator_bind, "test")
                .await
                .expect("bind ephemeral operator listener");

        assert!(resolved.ip().is_loopback());
        assert_ne!(resolved.port(), 0);
    }

    #[tokio::test]
    async fn private_operator_listener_rejects_public_bind_alias() {
        let bind: SocketAddr = "127.0.0.1:55051".parse().expect("bind");
        let error = bind_private_operator_listener(bind, bind, "test")
            .await
            .expect_err("same public/operator bind must fail closed");
        assert!(error.contains("operator bind must be different"));
    }

    fn static_machine_auth_verification_keys(
        config: &MachineAuthRuntimeConfig,
    ) -> &MachineTokenPublicKeySet {
        match &config.signing {
            MachineAuthSigningConfig::Static {
                verification_keys, ..
            } => verification_keys,
            MachineAuthSigningConfig::Provider { .. } => {
                panic!("expected static machine auth config")
            }
        }
    }

    #[test]
    fn machine_auth_config_requires_https_and_redacts_signing_key() {
        let config = MachineAuthRuntimeConfig::new(
            "https://auth.example.test",
            "ucr-api",
            "key-2026-09",
            [7_u8; 32],
            "https://auth.example.test/oauth2/token",
            "https://auth.example.test/.well-known/jwks.json",
            900,
        )
        .expect("machine auth config")
        .with_previous_signing_key("key-2026-08", [6_u8; 32])
        .expect("previous signing key");
        assert_eq!(
            static_machine_auth_verification_keys(&config).keys().len(),
            2
        );
        assert_eq!(
            static_machine_auth_verification_keys(&config).keys()[0]
                .key_id
                .as_opaque()
                .as_str(),
            "key-2026-09"
        );
        assert_eq!(
            static_machine_auth_verification_keys(&config).keys()[1]
                .key_id
                .as_opaque()
                .as_str(),
            "key-2026-08"
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[7, 7, 7"));
        assert!(
            MachineAuthRuntimeConfig::new(
                "http://auth.example.test",
                "ucr-api",
                "key-a",
                [1_u8; 32],
                "https://auth.example.test/oauth2/token",
                "https://auth.example.test/.well-known/jwks.json",
                900,
            )
            .is_err()
        );
    }

    #[test]
    fn machine_auth_overlap_is_restart_stable_and_retirement_is_explicit() {
        let build = || {
            MachineAuthRuntimeConfig::new(
                "https://auth.example.test",
                "ucr-api",
                "key-active",
                [9_u8; 32],
                "https://auth.example.test/oauth2/token",
                "https://auth.example.test/.well-known/jwks.json",
                900,
            )
            .expect("active machine auth config")
            .with_previous_signing_key("key-previous", [8_u8; 32])
            .expect("previous signing key")
        };

        let before_restart = build();
        let after_restart = build();
        assert_eq!(
            static_machine_auth_verification_keys(&before_restart),
            static_machine_auth_verification_keys(&after_restart)
        );
        assert_eq!(
            static_machine_auth_verification_keys(&after_restart)
                .keys()
                .len(),
            2
        );

        let retired = MachineAuthRuntimeConfig::new(
            "https://auth.example.test",
            "ucr-api",
            "key-active",
            [9_u8; 32],
            "https://auth.example.test/oauth2/token",
            "https://auth.example.test/.well-known/jwks.json",
            900,
        )
        .expect("retired previous key config");
        assert_eq!(
            static_machine_auth_verification_keys(&retired).keys().len(),
            1
        );
        assert_eq!(
            static_machine_auth_verification_keys(&retired).keys()[0]
                .key_id
                .as_opaque()
                .as_str(),
            "key-active"
        );
    }

    #[test]
    fn realtime_capability_projection_defaults_fail_closed_and_derives_turn() {
        let base = RealtimeRuntimeConfig::new("https://conference.example.test/join", [3_u8; 32])
            .expect("realtime config");
        let default_capabilities = base.universal_conference_capabilities();
        assert!(!default_capabilities.browser_realtime_gateway);
        assert!(!default_capabilities.production_webrtc);
        assert!(!default_capabilities.turn);
        assert!(!default_capabilities.recording);
        assert!(!default_capabilities.horizontal_sfu);

        let configured = base
            .with_webrtc_ice(
                Vec::new(),
                vec!["turns:turn.example.test:5349?transport=tcp".to_owned()],
                Some([4_u8; 32]),
                300,
                false,
            )
            .expect("TURN config")
            .with_browser_realtime_gateway(true)
            .with_sfu_placement_lifecycle(true);
        assert!(configured.sfu_placement_lifecycle);
        let capabilities = configured.universal_conference_capabilities();
        assert!(capabilities.browser_realtime_gateway);
        assert!(!capabilities.production_webrtc);
        assert!(capabilities.turn);
        assert!(!capabilities.recording);
        assert!(!capabilities.horizontal_sfu);
    }

    #[test]
    fn production_local_daemon_refuses_remote_plaintext_bind() {
        let loopback: SocketAddr = "127.0.0.1:50051".parse().expect("loopback");
        let remote: SocketAddr = "0.0.0.0:50051".parse().expect("remote");
        assert_eq!(validate_local_bind(loopback), Ok(()));
        assert!(validate_local_bind(remote).is_err());
    }

    #[test]
    fn webhook_worker_health_reflects_durable_lease_without_exposing_holder() {
        let path = std::env::temp_dir().join(format!(
            "ucr-runtime-worker-health-{}-{}.sqlite",
            std::process::id(),
            runtime_now_unix_ms().expect("clock")
        ));
        let store = SqliteLocalStore::open(&path).expect("open store");

        let absent = operator_webhook_worker_health_at(&store, 1_000);
        assert_eq!(
            absent.status,
            pb::OperatorComponentStatus::NotConfigured as i32
        );

        assert!(
            store
                .try_acquire_runtime_worker_lease(
                    WEBHOOK_DELIVERY_WORKER_KIND,
                    "worker-private-id",
                    1_000,
                    1_000,
                )
                .expect("acquire lease")
        );
        let healthy = operator_webhook_worker_health_at(&store, 1_500);
        assert_eq!(healthy.status, pb::OperatorComponentStatus::Healthy as i32);
        assert!(!healthy.detail.contains("worker-private-id"));

        let expired = operator_webhook_worker_health_at(&store, 2_000);
        assert_eq!(
            expired.status,
            pb::OperatorComponentStatus::Unavailable as i32
        );
        assert!(!expired.detail.contains("worker-private-id"));

        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn operator_sfu_control_registers_lists_and_drains_only_in_realtime_runtime() {
        let path = std::env::temp_dir().join(format!(
            "ucr-runtime-sfu-control-{}-{}.sqlite",
            std::process::id(),
            runtime_now_unix_ms().expect("clock")
        ));
        let store = Arc::new(SqliteLocalStore::open(&path).expect("open store"));
        let heartbeat = OperatorSfuNodeHeartbeat {
            node_id: OpaqueId::new("sfu-eu-1").expect("node id"),
            region: "eu-west-1".to_owned(),
            state: ucr_sfu::SfuNodeState::Healthy,
            active_sessions: 2,
            max_sessions: 100,
            lease_ttl_ms: 30_000,
            endpoint: ucr_sfu::SfuNodeEndpoint::new("127.0.0.1:7001".parse().expect("endpoint"))
                .expect("valid endpoint"),
        };

        let basic = ProductionOperatorHealthSource::basic(Arc::clone(&store));
        assert_eq!(
            basic.heartbeat_sfu_node(heartbeat.clone()),
            Err(OperatorSfuClusterError::NotConfigured)
        );

        let realtime = ProductionOperatorHealthSource::realtime(
            Arc::clone(&store),
            Arc::new(RealtimeSessionRegistry::new(8, 2)),
            Arc::new(LiveWebRtcProvider::new().expect("live provider")),
            false,
            Arc::new(Mutex::new(SfuClusterDirectory::default())),
        );
        let registered = realtime
            .heartbeat_sfu_node(heartbeat)
            .expect("register heartbeat");
        assert_eq!(registered.node.node_id.as_str(), "sfu-eu-1");
        assert_eq!(registered.node.active_sessions, 2);
        assert_eq!(registered.reserved_sessions, 0);
        assert_eq!(registered.effective_sessions, 2);
        assert!(registered.node.lease_expires_at_unix_ms > 0);

        let nodes = realtime.list_sfu_nodes().expect("list nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node.node_id.as_str(), "sfu-eu-1");
        assert_eq!(nodes[0].reserved_sessions, 0);
        assert_eq!(nodes[0].effective_sessions, 2);

        let drained = realtime
            .drain_sfu_node(&OpaqueId::new("sfu-eu-1").expect("node id"))
            .expect("drain node");
        assert_eq!(drained.node.state, ucr_sfu::SfuNodeState::Draining);
        assert_eq!(drained.reserved_sessions, 0);
        assert_eq!(drained.effective_sessions, 2);

        drop(realtime);
        drop(basic);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn diagnostics_and_metrics_are_metadata_only() {
        let diagnostics = RuntimeDiagnostics {
            schema_version: 31,
            storage_health: StorageHealth::Healthy,
            runtime_mode: RUNTIME_MODE,
        };
        let json = diagnostics.json();
        let metrics = diagnostics.prometheus();

        assert!(json.contains("storage_health"));
        assert!(metrics.contains("ucr_runtime_up 1"));
        for forbidden in ["message", "payload", "credential", "secret", "private_key"] {
            assert!(!json.contains(forbidden));
            assert!(!metrics.contains(forbidden));
        }
    }
}

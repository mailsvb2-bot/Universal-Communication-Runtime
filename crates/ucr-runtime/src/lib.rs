#![forbid(unsafe_code)]

use std::{
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use ucr_api_grpc::{
    GrpcCallService, GrpcConferenceService, GrpcDeviceService, GrpcEventService, GrpcGroupService,
    GrpcIntegrationService, GrpcMachineAuthService, GrpcOperatorRuntimeService,
    GrpcRealtimeService, GrpcStoreForwardService, GrpcSyncService, GrpcUniversalConferenceService,
    MachineAuthDiscovery, OperatorRuntimeHealthSource, RealtimeWebRtcDependencies,
    UniversalConferenceRuntimeCapabilities, call_service_server, conference_service_server,
    device_service_server, event_service_server, group_service_server, integration_service_server,
    machine_auth_service_server, operator_runtime_service_server, pb, realtime_service_server,
    store_forward_service_server, sync_service_server, universal_conference_service_server,
};
use ucr_conference::ConferenceRuntimeState;
use ucr_core::{
    DurableStoreError, EventWebhookDispatcher, StorageHealth, StorageProvider,
    SystemEventDeliveryClock, SystemServiceQuotaClock, WebhookDispatchOutcome, generate_opaque_id,
};
use ucr_crypto::{MAX_MACHINE_TOKEN_TTL_SECONDS, MachineTokenPolicy, MachineTokenSigningKey};
use ucr_model::{
    EventSubscriptionId, IceTransportPolicy, KeyId, NamespaceId, OpaqueId, SfuForwardEnvelope,
    TenantId, TenantScope,
};
use ucr_realtime::{JoinTokenIssuer, JoinTokenKey, RealtimeSessionRegistry};
use ucr_sfu::{SfuForwardSink, SfuForwardSinkError};
use ucr_storage_sqlite::{SqliteLocalStore, WEBHOOK_DELIVERY_WORKER_KIND};
use ucr_webhook::{
    HardenedWebhookSink, NativeTlsWebhookExecutor, SystemWebhookDnsResolver, WebhookSigningSecret,
};
use ucr_webrtc::{
    LIVE_WEBRTC_E2EE_INGRESS_CAPACITY, LIVE_WEBRTC_MAX_SESSIONS, LiveWebRtcProvider,
    TurnRestCredentialIssuer, TurnRestSecret, WebRtcE2eeIngressFrame, WebRtcProvider,
    WebRtcProviderError, WebRtcSessionConfigFactory,
};

pub const DEFAULT_RUNTIME_BIND: &str = "127.0.0.1:50051";
pub const RUNTIME_MODE: &str = "local-daemon";

const WEBHOOK_DISPATCH_TARGET_PAGE: usize = 128;
pub const DEFAULT_WEBHOOK_WORKER_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const MIN_WEBHOOK_WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_WEBHOOK_WORKER_POLL_INTERVAL: Duration = Duration::from_mins(1);
const WEBHOOK_WORKER_LEASE_DURATION_MS: i64 = 120_000;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct WebhookWorkerSweep {
    targets: usize,
    delivered: usize,
    retry_scheduled: usize,
    dead_lettered: usize,
    rejected: usize,
}

#[derive(Clone, Debug)]
pub struct MachineAuthRuntimeConfig {
    policy: MachineTokenPolicy,
    signing_key: Arc<MachineTokenSigningKey>,
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
        Ok(Self {
            policy: MachineTokenPolicy {
                issuer,
                audience,
                max_ttl_seconds,
            },
            signing_key: Arc::new(MachineTokenSigningKey::from_seed(key_id, signing_seed)),
            discovery: MachineAuthDiscovery {
                token_endpoint,
                jwks_uri,
            },
        })
    }
}

#[derive(Clone)]
pub struct RealtimeRuntimeConfig {
    join_base_url: String,
    join_token_key: JoinTokenKey,
    webrtc_config: Arc<WebRtcSessionConfigFactory>,
    browser_realtime_gateway: bool,
}

impl core::fmt::Debug for RealtimeRuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealtimeRuntimeConfig")
            .field("join_base_url", &self.join_base_url)
            .field("join_token_key", &"<redacted>")
            .field("webrtc_config", &self.webrtc_config)
            .field("browser_realtime_gateway", &self.browser_realtime_gateway)
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
        let join_base_url = join_base_url.into();
        let join_token_key = JoinTokenKey::from_bytes(join_token_key);
        JoinTokenIssuer::new(join_token_key.clone(), join_base_url.clone())
            .map_err(|error| format!("invalid realtime join configuration: {error:?}"))?;
        Ok(Self {
            join_base_url,
            join_token_key,
            webrtc_config: Arc::new(WebRtcSessionConfigFactory::default()),
            browser_realtime_gateway: false,
        })
    }

    #[must_use]
    pub fn with_browser_realtime_gateway(mut self, enabled: bool) -> Self {
        self.browser_realtime_gateway = enabled;
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
        mut self,
        stun_urls: Vec<String>,
        turn_urls: Vec<String>,
        turn_rest_secret: Option<[u8; 32]>,
        turn_ttl_seconds: u32,
        relay_only: bool,
    ) -> Result<Self, String> {
        let turn_issuer = turn_rest_secret
            .map(TurnRestSecret::from_bytes)
            .map(TurnRestCredentialIssuer::new);
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
}

impl ProductionOperatorHealthSource {
    fn basic(store: Arc<SqliteLocalStore>) -> Self {
        Self {
            store,
            realtime: None,
        }
    }

    fn realtime(
        store: Arc<SqliteLocalStore>,
        registry: Arc<RealtimeSessionRegistry>,
        live_provider: Arc<LiveWebRtcProvider>,
        turn_configured: bool,
    ) -> Self {
        Self {
            store,
            realtime: Some(RealtimeOperatorHealth {
                registry,
                live_provider,
                turn_configured,
            }),
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
        let clock = Arc::new(SystemServiceQuotaClock);
        let event_clock = Arc::new(SystemEventDeliveryClock);
        let store = Arc::clone(&self.store);
        let authorization = Arc::clone(&self.store);
        let conference_state = Arc::new(ConferenceRuntimeState::new());
        let operator_health = Arc::new(ProductionOperatorHealthSource::basic(Arc::clone(&store)));

        Server::builder()
            .add_service(operator_runtime_service_server(
                GrpcOperatorRuntimeService::new(operator_health),
            ))
            .add_service(integration_service_server(GrpcIntegrationService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
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
            .add_service(universal_conference_service_server(
                GrpcUniversalConferenceService::with_state(
                    Arc::clone(&clock),
                    Arc::clone(&authorization),
                    Arc::clone(&store),
                    conference_state,
                ),
            ))
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
            .map_err(|error| format!("local runtime API server: {error}"))
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
        let clock = Arc::new(SystemServiceQuotaClock);
        let store = Arc::clone(&self.store);
        let operator_health = Arc::new(ProductionOperatorHealthSource::basic(Arc::clone(&store)));
        let service = GrpcMachineAuthService::new(
            clock,
            Arc::clone(&store),
            store,
            config.signing_key,
            config.policy,
            config.discovery,
        );

        Server::builder()
            .add_service(operator_runtime_service_server(
                GrpcOperatorRuntimeService::new(operator_health),
            ))
            .add_service(machine_auth_service_server(service))
            .serve_with_incoming(incoming)
            .await
            .map_err(|error| format!("local machine-auth API server: {error}"))
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
        validate_local_bind(bind)?;
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
        let clock = Arc::new(SystemServiceQuotaClock);
        let event_clock = Arc::new(SystemEventDeliveryClock);
        let store = Arc::clone(&self.store);
        let authorization = Arc::clone(&self.store);
        let conference_state = Arc::new(ConferenceRuntimeState::new());
        let runtime_capabilities = config.universal_conference_capabilities();
        let dependencies = realtime_dependencies(config)?;
        let join_issuer = Arc::clone(&dependencies.join_issuer);
        let registry = Arc::clone(&dependencies.registry);
        let operator_health = realtime_operator_health(
            &store,
            &registry,
            &dependencies.live_provider,
            runtime_capabilities.turn,
        );
        let realtime_service = GrpcRealtimeService::with_webrtc(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
            Arc::clone(&join_issuer),
            Arc::clone(&registry),
            Arc::clone(&conference_state),
            dependencies.webrtc,
        );
        let bridge_task = spawn_webrtc_e2ee_bridge(
            dependencies.e2ee_ingress,
            &dependencies.live_provider,
            &registry,
            &realtime_service,
        );

        let services = RealtimeServerServices {
            clock,
            event_clock,
            store,
            authorization,
            conference_state,
            runtime_capabilities,
            join_issuer,
            operator_health,
            realtime_service,
        };
        let server_result = serve_realtime_services(services, incoming).await;
        bridge_task.abort();
        server_result.map_err(|error| format!("local realtime API server: {error}"))
    }
}

struct RealtimeServerServices {
    clock: Arc<SystemServiceQuotaClock>,
    event_clock: Arc<SystemEventDeliveryClock>,
    store: Arc<SqliteLocalStore>,
    authorization: Arc<SqliteLocalStore>,
    conference_state: Arc<ConferenceRuntimeState>,
    runtime_capabilities: UniversalConferenceRuntimeCapabilities,
    join_issuer: Arc<JoinTokenIssuer>,
    operator_health: Arc<ProductionOperatorHealthSource>,
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
        operator_health,
        realtime_service,
    } = services;
    Server::builder()
        .add_service(operator_runtime_service_server(
            GrpcOperatorRuntimeService::new(operator_health),
        ))
        .add_service(integration_service_server(GrpcIntegrationService::new(
            Arc::clone(&clock),
            Arc::clone(&authorization),
            Arc::clone(&store),
        )))
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
        .add_service(universal_conference_service_server(
            GrpcUniversalConferenceService::with_state_join_issuer_and_runtime_capabilities(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
                Arc::clone(&conference_state),
                join_issuer,
                runtime_capabilities,
            ),
        ))
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
        join_base_url,
        join_token_key,
        webrtc_config,
        browser_realtime_gateway: _,
    } = config;
    let join_issuer = Arc::new(
        JoinTokenIssuer::new(join_token_key, join_base_url)
            .map_err(|error| format!("configure realtime join issuer: {error:?}"))?,
    );
    let (e2ee_ingress_tx, e2ee_ingress) =
        tokio::sync::mpsc::channel(LIVE_WEBRTC_E2EE_INGRESS_CAPACITY);
    let live_provider = Arc::new(
        LiveWebRtcProvider::with_e2ee_ingress(e2ee_ingress_tx)
            .map_err(|error| format!("start live WebRTC provider: {error:?}"))?,
    );
    let provider: Arc<dyn WebRtcProvider> = live_provider.clone();
    Ok(RealtimeRuntimeDependencies {
        join_issuer,
        registry: Arc::new(RealtimeSessionRegistry::default()),
        webrtc: RealtimeWebRtcDependencies::new(provider, webrtc_config),
        live_provider,
        e2ee_ingress,
    })
}

#[derive(Debug)]
struct WebRtcE2eeForwardSink {
    registry: Arc<RealtimeSessionRegistry>,
    provider: Arc<LiveWebRtcProvider>,
    now_unix_ms: i64,
}

impl SfuForwardSink for WebRtcE2eeForwardSink {
    fn forward_encrypted(
        &self,
        target: &ucr_model::SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let sessions = self
            .registry
            .active_session_ids_for_recipient(
                &envelope.frame.header.scope,
                &envelope.frame.header.call_id,
                &target.recipient,
                self.now_unix_ms,
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
) -> Arc<ProductionOperatorHealthSource> {
    Arc::new(ProductionOperatorHealthSource::realtime(
        Arc::clone(store),
        Arc::clone(registry),
        Arc::clone(live_provider),
        turn_configured,
    ))
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
        let provider = Arc::clone(&provider);
        let registry = Arc::clone(&registry);
        let service = service.clone();
        let _ = tokio::task::spawn_blocking(move || {
            route_webrtc_e2ee_frame(&service, &registry, &provider, &frame)
        })
        .await;
    }
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
        now_unix_ms,
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
        .expect("machine auth config");
        let debug = format!("{config:?}");
        assert!(debug.contains("<secret>"));
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
            .with_browser_realtime_gateway(true);
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

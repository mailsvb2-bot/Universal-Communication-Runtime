#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::Path, sync::Arc};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use ucr_api_grpc::{
    GrpcCallService, GrpcConferenceService, GrpcDeviceService, GrpcEventService, GrpcGroupService,
    GrpcIntegrationService, GrpcRealtimeService, GrpcStoreForwardService, GrpcSyncService,
    GrpcUniversalConferenceService, call_service_server, conference_service_server,
    device_service_server, event_service_server, group_service_server, integration_service_server,
    realtime_service_server, store_forward_service_server, sync_service_server,
    universal_conference_service_server,
};
use ucr_conference::ConferenceRuntimeState;
use ucr_core::{
    EventWebhookDispatcher, StorageHealth, StorageProvider, SystemEventDeliveryClock,
    SystemServiceQuotaClock, WebhookDispatchOutcome,
};
use ucr_model::{EventSubscriptionId, NamespaceId, OpaqueId, TenantId, TenantScope};
use ucr_realtime::{JoinTokenIssuer, JoinTokenKey, RealtimeSessionRegistry};
use ucr_storage_sqlite::SqliteLocalStore;
use ucr_webhook::{
    HardenedWebhookSink, NativeTlsWebhookExecutor, SystemWebhookDnsResolver, WebhookSigningSecret,
};

pub const DEFAULT_RUNTIME_BIND: &str = "127.0.0.1:50051";
pub const RUNTIME_MODE: &str = "local-daemon";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeRuntimeConfig {
    join_base_url: String,
    join_token_key: JoinTokenKey,
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
        })
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
                .map(|value| {
                    runtime_opaque(value, "namespace id").map(NamespaceId::from_opaque)
                })
                .transpose()?,
        };
        let subscription_id = EventSubscriptionId::from_opaque(runtime_opaque(
            subscription_id,
            "subscription id",
        )?);
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

        Server::builder()
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
            .add_service(conference_service_server(GrpcConferenceService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
            )))
            .add_service(universal_conference_service_server(
                GrpcUniversalConferenceService::new(
                    Arc::clone(&clock),
                    Arc::clone(&authorization),
                    Arc::clone(&store),
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
        let diagnostics = self.diagnostics()?;
        if diagnostics.storage_health != StorageHealth::Healthy {
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
        let join_issuer = Arc::new(
            JoinTokenIssuer::new(config.join_token_key, config.join_base_url)
                .map_err(|error| format!("configure realtime join issuer: {error:?}"))?,
        );
        let registry = Arc::new(RealtimeSessionRegistry::default());

        Server::builder()
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
            .add_service(realtime_service_server(GrpcRealtimeService::new(
                Arc::clone(&clock),
                Arc::clone(&authorization),
                Arc::clone(&store),
                Arc::clone(&join_issuer),
                registry,
                conference_state,
            )))
            .add_service(universal_conference_service_server(
                GrpcUniversalConferenceService::with_join_issuer(
                    Arc::clone(&clock),
                    Arc::clone(&authorization),
                    Arc::clone(&store),
                    join_issuer,
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
            .map_err(|error| format!("local realtime API server: {error}"))
    }
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
    fn production_local_daemon_refuses_remote_plaintext_bind() {
        let loopback: SocketAddr = "127.0.0.1:50051".parse().expect("loopback");
        let remote: SocketAddr = "0.0.0.0:50051".parse().expect("remote");
        assert_eq!(validate_local_bind(loopback), Ok(()));
        assert!(validate_local_bind(remote).is_err());
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

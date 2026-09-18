#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::Path, sync::Arc};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use ucr_api_grpc::{
    GrpcCallService, GrpcDeviceService, GrpcEventService, GrpcGroupService, GrpcIntegrationService,
    GrpcStoreForwardService, GrpcSyncService, call_service_server, device_service_server,
    event_service_server, group_service_server, integration_service_server,
    store_forward_service_server, sync_service_server,
};
use ucr_core::{StorageHealth, StorageProvider, SystemEventDeliveryClock, SystemServiceQuotaClock};
use ucr_storage_sqlite::SqliteLocalStore;

pub const DEFAULT_RUNTIME_BIND: &str = "127.0.0.1:50051";
pub const RUNTIME_MODE: &str = "local-daemon";

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
    /// Initializes a durable UCR SQLite database without creating credentials, identities,
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

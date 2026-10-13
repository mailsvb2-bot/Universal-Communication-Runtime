//! Loopback WebRTC engine for the local room.
//!
//! This is the existing live peer engine, not a second media stack and not a
//! Production WebRTC claim. Ciphertext from one browser is validated by the
//! canonical SFU path and written to the other browser's data channel.

use std::sync::Arc;

use ucr_api_grpc::{GrpcRealtimeService, RealtimeWebRtcDependencies};
use ucr_model::{SfuForwardEnvelope, SfuForwardTarget};
use ucr_realtime::RealtimeSessionRegistry;
use ucr_sfu::{SfuForwardSink, SfuForwardSinkError};
use ucr_storage_sqlite::SqliteLocalStore;
use ucr_webrtc::{
    LIVE_WEBRTC_E2EE_INGRESS_CAPACITY, LiveWebRtcProvider, WebRtcE2eeIngressFrame,
    WebRtcProviderError, WebRtcSessionConfigFactory,
};

pub(crate) fn start() -> Result<
    (
        RealtimeWebRtcDependencies,
        Arc<LiveWebRtcProvider>,
        tokio::sync::mpsc::Receiver<WebRtcE2eeIngressFrame>,
    ),
    String,
> {
    let (ingress_tx, ingress_rx) = tokio::sync::mpsc::channel(LIVE_WEBRTC_E2EE_INGRESS_CAPACITY);
    let provider = Arc::new(
        LiveWebRtcProvider::with_e2ee_ingress(ingress_tx)
            .map_err(|error| format!("start loopback WebRTC: {error:?}"))?,
    );
    let concrete = Arc::clone(&provider);
    let shared: Arc<dyn ucr_webrtc::WebRtcProvider> = concrete;
    let dependencies =
        RealtimeWebRtcDependencies::new(shared, Arc::new(WebRtcSessionConfigFactory::default()));
    Ok((dependencies, provider, ingress_rx))
}

pub(crate) fn spawn_bridge<C>(
    ingress: tokio::sync::mpsc::Receiver<WebRtcE2eeIngressFrame>,
    provider: Arc<LiveWebRtcProvider>,
    registry: Arc<RealtimeSessionRegistry>,
    service: GrpcRealtimeService<C, SqliteLocalStore, SqliteLocalStore>,
) where
    C: ucr_core::ServiceQuotaClock + 'static,
{
    tokio::spawn(run_bridge(ingress, provider, registry, service));
}

async fn run_bridge<C>(
    mut ingress: tokio::sync::mpsc::Receiver<WebRtcE2eeIngressFrame>,
    provider: Arc<LiveWebRtcProvider>,
    registry: Arc<RealtimeSessionRegistry>,
    service: GrpcRealtimeService<C, SqliteLocalStore, SqliteLocalStore>,
) where
    C: ucr_core::ServiceQuotaClock + 'static,
{
    while let Some(frame) = ingress.recv().await {
        let provider = Arc::clone(&provider);
        let registry = Arc::clone(&registry);
        let service = service.clone();
        let _ = tokio::task::spawn_blocking(move || {
            route_frame(&service, &registry, &provider, &frame)
        })
        .await;
    }
}

fn route_frame<C>(
    service: &GrpcRealtimeService<C, SqliteLocalStore, SqliteLocalStore>,
    registry: &Arc<RealtimeSessionRegistry>,
    provider: &Arc<LiveWebRtcProvider>,
    frame: &WebRtcE2eeIngressFrame,
) -> Result<usize, ()>
where
    C: ucr_core::ServiceQuotaClock,
{
    let now_unix_ms = system_unix_ms()?;
    let header = &frame.envelope.frame.header;
    let claims = registry
        .active_claims_for_ingress(
            &frame.session_id,
            &header.scope,
            &header.call_id,
            now_unix_ms,
        )
        .map_err(|_| ())?;
    let sink = LoopbackForwardSink {
        registry: registry.clone(),
        provider: provider.clone(),
    };
    service
        .forward_authenticated_e2ee_media(&claims, &frame.envelope, &sink)
        .map_err(|_| ())
}

fn system_unix_ms() -> Result<i64, ()> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis();
    i64::try_from(millis).map_err(|_| ())
}

#[derive(Debug)]
struct LoopbackForwardSink {
    registry: Arc<RealtimeSessionRegistry>,
    provider: Arc<LiveWebRtcProvider>,
}

impl SfuForwardSink for LoopbackForwardSink {
    fn forward_encrypted(
        &self,
        target: &SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError> {
        let now_unix_ms = system_unix_ms().map_err(|()| SfuForwardSinkError::Unavailable)?;
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
                Err(error) => return Err(sink_error(error)),
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

const fn sink_error(error: WebRtcProviderError) -> SfuForwardSinkError {
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

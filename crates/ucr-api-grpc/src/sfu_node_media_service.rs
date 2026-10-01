use std::{fmt, pin::Pin, sync::Arc};

use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};
use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, GroupStore,
    PrincipalIdentityBindingStore,
};
use ucr_crypto::TrustedSigningKeyResolver;
use ucr_media_e2ee::PreparedGroupMediaE2eeCapabilities;
use ucr_model::{ScopedPrincipal, SfuForwardTarget};
use ucr_sfu::{PreparedSfuCapabilities, SfuError, SfuForwardSink, SfuForwardSinkError, SfuRuntime};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, decode_principal_ref, pb,
    realtime_service::decode_sfu_forward_envelope,
};

pub const SFU_NODE_RECEIPT_CHANNEL_CAPACITY: usize = 32;

pub struct GrpcSfuNodeMediaService<A, S> {
    authorization: Arc<A>,
    store: Arc<S>,
    sink: Arc<dyn SfuForwardSink>,
}

impl<A, S> GrpcSfuNodeMediaService<A, S> {
    #[must_use]
    pub fn new(authorization: Arc<A>, store: Arc<S>, sink: Arc<dyn SfuForwardSink>) -> Self {
        Self {
            authorization,
            store,
            sink,
        }
    }
}

impl<A, S> Clone for GrpcSfuNodeMediaService<A, S> {
    fn clone(&self) -> Self {
        Self {
            authorization: Arc::clone(&self.authorization),
            store: Arc::clone(&self.store),
            sink: Arc::clone(&self.sink),
        }
    }
}

impl<A, S> fmt::Debug for GrpcSfuNodeMediaService<A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcSfuNodeMediaService")
            .field("sink", &"<encrypted-media-sink>")
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn sfu_node_media_service_server<A, S>(
    service: GrpcSfuNodeMediaService<A, S>,
) -> pb::sfu_node_media_service_server::SfuNodeMediaServiceServer<GrpcSfuNodeMediaService<A, S>>
where
    A: AuthorizationEvaluator + 'static,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + 'static,
{
    pb::sfu_node_media_service_server::SfuNodeMediaServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<A, S> pb::sfu_node_media_service_server::SfuNodeMediaService for GrpcSfuNodeMediaService<A, S>
where
    A: AuthorizationEvaluator + 'static,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver
        + 'static,
{
    type ForwardEncryptedStream =
        Pin<Box<dyn Stream<Item = Result<pb::SfuNodeForwardReceipt, Status>> + Send + 'static>>;

    async fn forward_encrypted(
        &self,
        request: Request<tonic::Streaming<pb::SfuNodeEncryptedMedia>>,
    ) -> Result<Response<Self::ForwardEncryptedStream>, Status> {
        require_mtls_peer(&request)?;

        let inbound = request.into_inner();
        let authorization = Arc::clone(&self.authorization);
        let store = Arc::clone(&self.store);
        let sink = Arc::clone(&self.sink);
        let (sender, receiver) = tokio::sync::mpsc::channel(SFU_NODE_RECEIPT_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            if let Err(status) =
                forward_node_media_stream(inbound, &sender, authorization, store, sink).await
            {
                let _ = sender.send(Err(status)).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

async fn forward_node_media_stream<A, S>(
    mut inbound: tonic::Streaming<pb::SfuNodeEncryptedMedia>,
    sender: &tokio::sync::mpsc::Sender<Result<pb::SfuNodeForwardReceipt, Status>>,
    authorization: Arc<A>,
    store: Arc<S>,
    sink: Arc<dyn SfuForwardSink>,
) -> Result<(), Status>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
{
    let mut expected_sequence = 1_u64;
    while let Some(item) = inbound.next().await {
        let body = item
            .map_err(|_| Status::invalid_argument("invalid SFU node media stream item"))?;
        let (receipt, next_sequence) = process_node_media_item(
            authorization.as_ref(),
            store.as_ref(),
            sink.as_ref(),
            body,
            expected_sequence,
        )?;
        if sender.send(Ok(receipt)).await.is_err() {
            return Ok(());
        }
        expected_sequence = next_sequence;
    }
    Ok(())
}

fn process_node_media_item<A, S>(
    authorization: &A,
    store: &S,
    sink: &dyn SfuForwardSink,
    body: pb::SfuNodeEncryptedMedia,
    expected_sequence: u64,
) -> Result<(pb::SfuNodeForwardReceipt, u64), Status>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
{
    if body.stream_sequence != expected_sequence {
        return Err(Status::invalid_argument(
            "invalid SFU node media stream sequence",
        ));
    }
    let next_sequence = expected_sequence
        .checked_add(1)
        .ok_or_else(|| Status::resource_exhausted("SFU node media stream sequence exhausted"))?;
    let target = decode_target(body.target)?;
    let envelope = body
        .envelope
        .ok_or_else(|| Status::invalid_argument("missing SFU node media envelope"))
        .and_then(|value| {
            decode_sfu_forward_envelope(value)
                .map_err(|_| Status::invalid_argument("invalid SFU node media envelope"))
        })?;

    let authenticated_source = ScopedPrincipal {
        scope: envelope.frame.header.scope.clone(),
        principal: envelope.frame.header.source.clone(),
    };
    let authenticated_source_device = envelope.frame.header.source_device_id.clone();
    let group_media = PreparedGroupMediaE2eeCapabilities;
    let sfu_capabilities = PreparedSfuCapabilities;
    let runtime = SfuRuntime::new(authorization, store, &group_media, &sfu_capabilities);
    let status = match runtime.forward_selected(
        &authenticated_source,
        &authenticated_source_device,
        &envelope,
        std::slice::from_ref(&target.recipient),
        sink,
    ) {
        Ok(_) => pb::SfuNodeForwardStatus::Accepted,
        Err(SfuError::Sink {
            error: SfuForwardSinkError::Backpressure,
            ..
        }) => pb::SfuNodeForwardStatus::Backpressure,
        Err(SfuError::Sink {
            error: SfuForwardSinkError::Unavailable | SfuForwardSinkError::Rejected,
            ..
        }) => pb::SfuNodeForwardStatus::Rejected,
        Err(_) => {
            return Err(Status::permission_denied(
                "SFU node media authorization rejected",
            ));
        }
    };
    Ok((
        pb::SfuNodeForwardReceipt {
            stream_sequence: body.stream_sequence,
            status: status as i32,
        },
        next_sequence,
    ))
}

fn require_mtls_peer<T>(request: &Request<T>) -> Result<(), Status> {
    if request
        .peer_certs()
        .is_some_and(|certificates| !certificates.is_empty())
    {
        Ok(())
    } else {
        Err(Status::unauthenticated(
            "SFU node media requires an authenticated TLS peer",
        ))
    }
}

fn decode_target(value: Option<pb::SfuForwardTarget>) -> Result<SfuForwardTarget, Status> {
    let value = value.ok_or_else(|| Status::invalid_argument("missing SFU node media target"))?;
    let recipient = value
        .recipient
        .ok_or_else(|| Status::invalid_argument("missing SFU node media recipient"))
        .and_then(|recipient| {
            decode_principal_ref(recipient)
                .map_err(|_| Status::invalid_argument("invalid SFU node media recipient"))
        })?;
    Ok(SfuForwardTarget { recipient })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_request_without_tls_peer_evidence_fails_closed() {
        let request = Request::new(());
        let error = require_mtls_peer(&request).expect_err("mTLS peer certificate is mandatory");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn missing_target_is_rejected_before_runtime_authorization() {
        let error = decode_target(None).expect_err("missing target");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}

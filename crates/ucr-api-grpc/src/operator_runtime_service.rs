use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};

use super::{GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, pb};

/// Private operator health source. Implementations must return bounded, non-secret deployment
/// evidence only. Integration credentials and tenant business data do not belong here.
pub trait OperatorRuntimeHealthSource: fmt::Debug + Send + Sync {
    fn snapshot(&self) -> pb::OperatorRuntimeHealthResponse;
}

/// Thin gRPC binding for the private loopback/operator runtime boundary.
pub struct GrpcOperatorRuntimeService<H> {
    source: Arc<H>,
}

impl<H> GrpcOperatorRuntimeService<H> {
    #[must_use]
    pub const fn new(source: Arc<H>) -> Self {
        Self { source }
    }
}

impl<H> Clone for GrpcOperatorRuntimeService<H> {
    fn clone(&self) -> Self {
        Self {
            source: Arc::clone(&self.source),
        }
    }
}

impl<H> fmt::Debug for GrpcOperatorRuntimeService<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcOperatorRuntimeService")
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn operator_runtime_service_server<H>(
    service: GrpcOperatorRuntimeService<H>,
) -> pb::operator_runtime_service_server::OperatorRuntimeServiceServer<GrpcOperatorRuntimeService<H>>
where
    H: OperatorRuntimeHealthSource + 'static,
{
    pb::operator_runtime_service_server::OperatorRuntimeServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<H> pb::operator_runtime_service_server::OperatorRuntimeService
    for GrpcOperatorRuntimeService<H>
where
    H: OperatorRuntimeHealthSource + 'static,
{
    async fn get_health(
        &self,
        _request: Request<pb::OperatorRuntimeHealthRequest>,
    ) -> Result<Response<pb::OperatorRuntimeHealthResponse>, Status> {
        Ok(Response::new(self.source.snapshot()))
    }
}

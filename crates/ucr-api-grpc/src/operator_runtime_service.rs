use std::{fmt, sync::Arc};

use tonic::{Request, Response, Status};
use ucr_model::OpaqueId;
use ucr_sfu::{MAX_SFU_REGION_BYTES, SfuNodeDescriptor, SfuNodeState};

use super::{GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, pb};

pub const MIN_OPERATOR_SFU_LEASE_TTL_MS: u32 = 1_000;
pub const MAX_OPERATOR_SFU_LEASE_TTL_MS: u32 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSfuNodeHeartbeat {
    pub node_id: OpaqueId,
    pub region: String,
    pub state: SfuNodeState,
    pub active_sessions: u32,
    pub max_sessions: u32,
    pub lease_ttl_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorSfuClusterError {
    NotConfigured,
    InvalidNode,
    Unavailable,
}

/// Private operator health source. Implementations must return bounded, non-secret deployment
/// evidence only. Integration credentials and tenant business data do not belong here.
pub trait OperatorRuntimeHealthSource: fmt::Debug + Send + Sync {
    fn snapshot(&self) -> pb::OperatorRuntimeHealthResponse;
}

/// Private horizontal-SFU control plane.
///
/// This boundary accepts only worker metadata. It never carries Conference rosters, participant
/// identities, join credentials, media keys, plaintext media, or tenant business data.
pub trait OperatorSfuClusterControl: fmt::Debug + Send + Sync {
    fn heartbeat_sfu_node(
        &self,
        heartbeat: OperatorSfuNodeHeartbeat,
    ) -> Result<SfuNodeDescriptor, OperatorSfuClusterError>;

    fn drain_sfu_node(
        &self,
        node_id: &OpaqueId,
    ) -> Result<SfuNodeDescriptor, OperatorSfuClusterError>;

    fn list_sfu_nodes(&self) -> Result<Vec<SfuNodeDescriptor>, OperatorSfuClusterError>;
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
    H: OperatorRuntimeHealthSource + OperatorSfuClusterControl + 'static,
{
    pb::operator_runtime_service_server::OperatorRuntimeServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<H> pb::operator_runtime_service_server::OperatorRuntimeService
    for GrpcOperatorRuntimeService<H>
where
    H: OperatorRuntimeHealthSource + OperatorSfuClusterControl + 'static,
{
    async fn get_health(
        &self,
        _request: Request<pb::OperatorRuntimeHealthRequest>,
    ) -> Result<Response<pb::OperatorRuntimeHealthResponse>, Status> {
        Ok(Response::new(self.source.snapshot()))
    }

    async fn heartbeat_sfu_node(
        &self,
        request: Request<pb::OperatorSfuNodeHeartbeatRequest>,
    ) -> Result<Response<pb::OperatorSfuNodeHeartbeatResponse>, Status> {
        let heartbeat = decode_sfu_heartbeat(request.into_inner())?;
        let node = self
            .source
            .heartbeat_sfu_node(heartbeat)
            .map_err(map_sfu_control_error)?;
        Ok(Response::new(pb::OperatorSfuNodeHeartbeatResponse {
            node: Some(pb_sfu_node(&node)),
        }))
    }

    async fn drain_sfu_node(
        &self,
        request: Request<pb::OperatorSfuNodeDrainRequest>,
    ) -> Result<Response<pb::OperatorSfuNodeDrainResponse>, Status> {
        let node_id = decode_node_id(&request.into_inner().node_id)?;
        let node = self
            .source
            .drain_sfu_node(&node_id)
            .map_err(map_sfu_control_error)?;
        Ok(Response::new(pb::OperatorSfuNodeDrainResponse {
            node: Some(pb_sfu_node(&node)),
        }))
    }

    async fn list_sfu_nodes(
        &self,
        _request: Request<pb::OperatorSfuNodeListRequest>,
    ) -> Result<Response<pb::OperatorSfuNodeListResponse>, Status> {
        let nodes = self
            .source
            .list_sfu_nodes()
            .map_err(map_sfu_control_error)?;
        Ok(Response::new(pb::OperatorSfuNodeListResponse {
            nodes: nodes.iter().map(pb_sfu_node).collect(),
        }))
    }
}

fn decode_sfu_heartbeat(
    body: pb::OperatorSfuNodeHeartbeatRequest,
) -> Result<OperatorSfuNodeHeartbeat, Status> {
    let node_id = decode_node_id(&body.node_id)?;
    if body.region.is_empty()
        || body.region.len() > MAX_SFU_REGION_BYTES
        || body.region.chars().any(char::is_control)
        || body.max_sessions == 0
        || body.active_sessions > body.max_sessions
        || !(MIN_OPERATOR_SFU_LEASE_TTL_MS..=MAX_OPERATOR_SFU_LEASE_TTL_MS)
            .contains(&body.lease_ttl_ms)
    {
        return Err(Status::invalid_argument("invalid SFU node heartbeat"));
    }
    let state = match body.state {
        value if value == pb::OperatorSfuNodeState::Healthy as i32 => SfuNodeState::Healthy,
        value if value == pb::OperatorSfuNodeState::Draining as i32 => SfuNodeState::Draining,
        value if value == pb::OperatorSfuNodeState::Unavailable as i32 => SfuNodeState::Unavailable,
        _ => return Err(Status::invalid_argument("invalid SFU node state")),
    };
    Ok(OperatorSfuNodeHeartbeat {
        node_id,
        region: body.region,
        state,
        active_sessions: body.active_sessions,
        max_sessions: body.max_sessions,
        lease_ttl_ms: body.lease_ttl_ms,
    })
}

fn decode_node_id(value: &str) -> Result<OpaqueId, Status> {
    OpaqueId::new(value).map_err(|_| Status::invalid_argument("invalid SFU node id"))
}

fn pb_sfu_node(node: &SfuNodeDescriptor) -> pb::OperatorSfuNodeSnapshot {
    pb::OperatorSfuNodeSnapshot {
        node_id: node.node_id.as_str().to_owned(),
        region: node.region.clone(),
        state: match node.state {
            SfuNodeState::Healthy => pb::OperatorSfuNodeState::Healthy,
            SfuNodeState::Draining => pb::OperatorSfuNodeState::Draining,
            SfuNodeState::Unavailable => pb::OperatorSfuNodeState::Unavailable,
        } as i32,
        active_sessions: node.active_sessions,
        max_sessions: node.max_sessions,
        lease_expires_at_unix_ms: node.lease_expires_at_unix_ms,
    }
}

fn map_sfu_control_error(error: OperatorSfuClusterError) -> Status {
    match error {
        OperatorSfuClusterError::NotConfigured => {
            Status::failed_precondition("horizontal SFU control plane is not configured")
        }
        OperatorSfuClusterError::InvalidNode => Status::invalid_argument("invalid SFU node"),
        OperatorSfuClusterError::Unavailable => {
            Status::unavailable("horizontal SFU control plane is unavailable")
        }
    }
}

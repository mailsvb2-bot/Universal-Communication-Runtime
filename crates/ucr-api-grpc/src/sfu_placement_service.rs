use std::{
    fmt,
    sync::{Arc, Mutex},
};

use tonic::{Request, Response, Status};
use ucr_core::ServiceQuotaClock;
use ucr_model::{CallId, TenantScope};
use ucr_protocol::{CanonicalError, CanonicalErrorCode};
use ucr_sfu::{MAX_SFU_REGION_BYTES, SfuClusterDirectory, SfuPlacementError, SfuPlacementPolicy};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, RealtimeSfuPlacementLifecycle,
    decode_opaque, decode_scope, pb, pb_opaque,
};

/// Private runtime-only horizontal-SFU placement binding.
///
/// This service owns no Conference, participant, authorization or media state. It only projects the
/// ephemeral `SfuClusterDirectory` through a loopback gRPC boundary for trusted infrastructure.
pub struct GrpcSfuPlacementService<C> {
    clock: Arc<C>,
    cluster: Arc<Mutex<SfuClusterDirectory>>,
    lifecycle_policy: SfuPlacementPolicy,
}

impl<C> GrpcSfuPlacementService<C> {
    #[must_use]
    pub fn new(clock: Arc<C>, cluster: Arc<Mutex<SfuClusterDirectory>>) -> Self {
        Self::with_lifecycle_policy(clock, cluster, SfuPlacementPolicy::default())
    }

    #[must_use]
    pub const fn with_lifecycle_policy(
        clock: Arc<C>,
        cluster: Arc<Mutex<SfuClusterDirectory>>,
        lifecycle_policy: SfuPlacementPolicy,
    ) -> Self {
        Self {
            clock,
            cluster,
            lifecycle_policy,
        }
    }
}

impl<C> Clone for GrpcSfuPlacementService<C> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            cluster: Arc::clone(&self.cluster),
            lifecycle_policy: self.lifecycle_policy.clone(),
        }
    }
}

impl<C> fmt::Debug for GrpcSfuPlacementService<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcSfuPlacementService")
            .finish_non_exhaustive()
    }
}

#[tonic::async_trait]
impl<C> RealtimeSfuPlacementLifecycle for GrpcSfuPlacementService<C>
where
    C: ServiceQuotaClock + 'static,
{
    async fn ensure_call_placement(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<(), CanonicalError> {
        let now_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
        let mut cluster = self
            .cluster
            .lock()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
        cluster.prune_expired_nodes(now_unix_ms);
        cluster
            .place_session(scope, call_id, &self.lifecycle_policy, now_unix_ms)
            .map(|_| ())
            .map_err(map_lifecycle_placement_error)
    }

    async fn release_call_placement(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<(), CanonicalError> {
        let mut cluster = self
            .cluster
            .lock()
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
        cluster
            .release_session_if_present(scope, call_id)
            .map(|_| ())
            .map_err(map_lifecycle_placement_error)
    }
}

#[must_use]
pub fn sfu_placement_service_server<C>(
    service: GrpcSfuPlacementService<C>,
) -> pb::sfu_placement_service_server::SfuPlacementServiceServer<GrpcSfuPlacementService<C>>
where
    C: ServiceQuotaClock + 'static,
{
    pb::sfu_placement_service_server::SfuPlacementServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
        .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE)
}

#[tonic::async_trait]
impl<C> pb::sfu_placement_service_server::SfuPlacementService for GrpcSfuPlacementService<C>
where
    C: ServiceQuotaClock + 'static,
{
    async fn place_call(
        &self,
        request: Request<pb::SfuPlaceCallRequest>,
    ) -> Result<Response<pb::SfuPlaceCallResponse>, Status> {
        let body = request.into_inner();
        let scope = decode_scope(
            body.scope
                .ok_or_else(|| Status::invalid_argument("missing tenant scope"))?,
        )
        .map_err(|_| Status::invalid_argument("invalid tenant scope"))?;
        let call_id = CallId::from_opaque(
            decode_opaque(body.call_id).map_err(|_| Status::invalid_argument("invalid call id"))?,
        );
        let preferred_region = decode_preferred_region(&body.preferred_region)?;
        let policy = SfuPlacementPolicy {
            preferred_region,
            allow_cross_region_failover: body.allow_cross_region_failover,
        };
        let now_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| Status::unavailable("SFU placement clock unavailable"))?;

        let mut cluster = self
            .cluster
            .lock()
            .map_err(|_| Status::unavailable("SFU placement directory unavailable"))?;
        cluster.prune_expired_nodes(now_unix_ms);
        let placement = cluster
            .place_session(&scope, &call_id, &policy, now_unix_ms)
            .map_err(map_placement_error)?;

        Ok(Response::new(pb::SfuPlaceCallResponse {
            placement: Some(pb::SfuPlacement {
                node_id: Some(pb_opaque(&placement.node_id)),
                retained_sticky_placement: placement.retained_sticky_placement,
                crossed_region: placement.crossed_region,
            }),
        }))
    }

    async fn release_call(
        &self,
        request: Request<pb::SfuReleaseCallRequest>,
    ) -> Result<Response<pb::SfuReleaseCallResponse>, Status> {
        let body = request.into_inner();
        let scope = decode_scope(
            body.scope
                .ok_or_else(|| Status::invalid_argument("missing tenant scope"))?,
        )
        .map_err(|_| Status::invalid_argument("invalid tenant scope"))?;
        let call_id = CallId::from_opaque(
            decode_opaque(body.call_id).map_err(|_| Status::invalid_argument("invalid call id"))?,
        );

        let mut cluster = self
            .cluster
            .lock()
            .map_err(|_| Status::unavailable("SFU placement directory unavailable"))?;
        cluster
            .release_session_if_present(&scope, &call_id)
            .map_err(map_placement_error)?;

        Ok(Response::new(pb::SfuReleaseCallResponse {
            released_call_id: Some(pb_opaque(call_id.as_opaque())),
        }))
    }

    async fn resolve_node(
        &self,
        request: Request<pb::SfuResolveNodeRequest>,
    ) -> Result<Response<pb::SfuResolveNodeResponse>, Status> {
        let node_id = decode_opaque(request.into_inner().node_id)
            .map_err(|_| Status::invalid_argument("invalid SFU node id"))?;
        let now_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|_| Status::unavailable("SFU placement clock unavailable"))?;
        let mut cluster = self
            .cluster
            .lock()
            .map_err(|_| Status::unavailable("SFU placement directory unavailable"))?;
        let endpoint = cluster.resolve_live_endpoint(&node_id, now_unix_ms);
        cluster.prune_expired_nodes(now_unix_ms);
        let endpoint = endpoint.map_err(map_placement_error)?;

        Ok(Response::new(pb::SfuResolveNodeResponse {
            route: Some(pb::SfuNodeRoute {
                node_id: Some(pb_opaque(&node_id)),
                endpoint_ip: endpoint.address.ip().to_string(),
                endpoint_port: u32::from(endpoint.address.port()),
            }),
        }))
    }
}

fn decode_preferred_region(value: &str) -> Result<Option<String>, Status> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_SFU_REGION_BYTES || value.chars().any(char::is_control) {
        return Err(Status::invalid_argument("invalid preferred SFU region"));
    }
    Ok(Some(value.to_owned()))
}

fn map_placement_error(error: SfuPlacementError) -> Status {
    match error {
        SfuPlacementError::InvalidNode => Status::failed_precondition("SFU placement unavailable"),
        SfuPlacementError::InvalidEndpoint => Status::invalid_argument("invalid SFU endpoint"),
        SfuPlacementError::EndpointUnavailable => Status::unavailable("SFU endpoint unavailable"),
        SfuPlacementError::NoHealthyCapacity => {
            Status::resource_exhausted("no healthy SFU capacity")
        }
    }
}

fn map_lifecycle_placement_error(error: SfuPlacementError) -> CanonicalError {
    match error {
        SfuPlacementError::NoHealthyCapacity => {
            CanonicalError::new(CanonicalErrorCode::ResourceExhausted)
        }
        SfuPlacementError::InvalidEndpoint => CanonicalError::new(CanonicalErrorCode::Internal),
        SfuPlacementError::InvalidNode | SfuPlacementError::EndpointUnavailable => {
            CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_core::ServiceQuotaClockError;
    use ucr_model::OpaqueId;
    use ucr_sfu::{SfuNodeDescriptor, SfuNodeEndpoint, SfuNodeState};

    #[derive(Debug)]
    struct FixedClock(i64);

    impl ServiceQuotaClock for FixedClock {
        fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
            Ok(self.0)
        }
    }

    fn pb_id(value: &str) -> pb::OpaqueId {
        pb::OpaqueId {
            value: value.as_bytes().to_vec(),
        }
    }

    fn place_request() -> pb::SfuPlaceCallRequest {
        pb::SfuPlaceCallRequest {
            scope: Some(pb::TenantScope {
                tenant_id: Some(pb_id("tenant-a")),
                namespace_id: None,
            }),
            call_id: Some(pb_id("call-a")),
            preferred_region: "eu".to_owned(),
            allow_cross_region_failover: false,
        }
    }

    #[test]
    fn preferred_region_is_optional_but_bounded() {
        assert_eq!(decode_preferred_region("").expect("empty"), None);
        assert_eq!(
            decode_preferred_region("eu-west-1").expect("region"),
            Some("eu-west-1".to_owned())
        );
        assert!(decode_preferred_region("eu\nwest").is_err());
        assert!(decode_preferred_region(&"r".repeat(MAX_SFU_REGION_BYTES + 1)).is_err());
    }

    #[tokio::test]
    async fn place_call_is_sticky_and_release_returns_capacity() {
        let cluster = Arc::new(Mutex::new(SfuClusterDirectory::default()));
        cluster
            .lock()
            .expect("cluster")
            .upsert_node(SfuNodeDescriptor {
                node_id: OpaqueId::new("sfu-a").expect("node"),
                region: "eu".to_owned(),
                state: SfuNodeState::Healthy,
                active_sessions: 0,
                max_sessions: 10,
                lease_expires_at_unix_ms: 20_000,
            })
            .expect("register node");
        let service = GrpcSfuPlacementService::new(Arc::new(FixedClock(10_000)), cluster);

        let first = pb::sfu_placement_service_server::SfuPlacementService::place_call(
            &service,
            Request::new(place_request()),
        )
        .await
        .expect("first placement")
        .into_inner()
        .placement
        .expect("placement");
        assert_eq!(first.node_id.expect("node id").value, b"sfu-a");
        assert!(!first.retained_sticky_placement);

        let sticky = pb::sfu_placement_service_server::SfuPlacementService::place_call(
            &service,
            Request::new(place_request()),
        )
        .await
        .expect("sticky placement")
        .into_inner()
        .placement
        .expect("placement");
        assert!(sticky.retained_sticky_placement);

        pb::sfu_placement_service_server::SfuPlacementService::release_call(
            &service,
            Request::new(pb::SfuReleaseCallRequest {
                scope: place_request().scope,
                call_id: Some(pb_id("call-a")),
            }),
        )
        .await
        .expect("release placement");

        pb::sfu_placement_service_server::SfuPlacementService::release_call(
            &service,
            Request::new(pb::SfuReleaseCallRequest {
                scope: place_request().scope,
                call_id: Some(pb_id("call-a")),
            }),
        )
        .await
        .expect("idempotent release retry");
    }

    #[tokio::test]
    async fn realtime_lifecycle_applies_routing_policy_before_sticky_media_resolution() {
        let cluster = Arc::new(Mutex::new(SfuClusterDirectory::default()));
        {
            let mut directory = cluster.lock().expect("cluster");
            for (node_id, region) in [("sfu-eu", "eu"), ("sfu-us", "us")] {
                directory
                    .upsert_node(SfuNodeDescriptor {
                        node_id: OpaqueId::new(node_id).expect("node"),
                        region: region.to_owned(),
                        state: SfuNodeState::Healthy,
                        active_sessions: 0,
                        max_sessions: 10,
                        lease_expires_at_unix_ms: 20_000,
                    })
                    .expect("register node");
            }
        }
        let service = GrpcSfuPlacementService::with_lifecycle_policy(
            Arc::new(FixedClock(10_000)),
            cluster,
            SfuPlacementPolicy {
                preferred_region: Some("eu".to_owned()),
                allow_cross_region_failover: false,
            },
        );
        let request = place_request();
        let scope = decode_scope(request.scope.clone().expect("scope")).expect("decoded scope");
        let call_id =
            CallId::from_opaque(decode_opaque(request.call_id.clone()).expect("decoded call"));

        RealtimeSfuPlacementLifecycle::ensure_call_placement(&service, &scope, &call_id)
            .await
            .expect("lifecycle placement");

        let mut conflicting_media_request = request;
        conflicting_media_request.preferred_region = "us".to_owned();
        let sticky = pb::sfu_placement_service_server::SfuPlacementService::place_call(
            &service,
            Request::new(conflicting_media_request),
        )
        .await
        .expect("sticky media placement")
        .into_inner()
        .placement
        .expect("placement");

        assert_eq!(sticky.node_id.expect("node id").value, b"sfu-eu");
        assert!(sticky.retained_sticky_placement);
    }

    #[tokio::test]
    async fn realtime_lifecycle_reuses_sticky_call_and_release_is_idempotent() {
        let cluster = Arc::new(Mutex::new(SfuClusterDirectory::default()));
        cluster
            .lock()
            .expect("cluster")
            .upsert_node(SfuNodeDescriptor {
                node_id: OpaqueId::new("sfu-lifecycle").expect("node"),
                region: "eu".to_owned(),
                state: SfuNodeState::Healthy,
                active_sessions: 0,
                max_sessions: 1,
                lease_expires_at_unix_ms: 20_000,
            })
            .expect("register node");
        let service =
            GrpcSfuPlacementService::new(Arc::new(FixedClock(10_000)), Arc::clone(&cluster));
        let request = place_request();
        let scope = decode_scope(request.scope.expect("scope")).expect("decoded scope");
        let call_id = CallId::from_opaque(decode_opaque(request.call_id).expect("decoded call"));

        RealtimeSfuPlacementLifecycle::ensure_call_placement(&service, &scope, &call_id)
            .await
            .expect("first placement");
        RealtimeSfuPlacementLifecycle::ensure_call_placement(&service, &scope, &call_id)
            .await
            .expect("sticky placement");

        let snapshot = cluster
            .lock()
            .expect("cluster")
            .node_with_capacity(&OpaqueId::new("sfu-lifecycle").expect("node"))
            .expect("snapshot");
        assert_eq!(snapshot.reserved_sessions, 1);

        RealtimeSfuPlacementLifecycle::release_call_placement(&service, &scope, &call_id)
            .await
            .expect("release");
        RealtimeSfuPlacementLifecycle::release_call_placement(&service, &scope, &call_id)
            .await
            .expect("idempotent release retry");
        let snapshot = cluster
            .lock()
            .expect("cluster")
            .node_with_capacity(&OpaqueId::new("sfu-lifecycle").expect("node"))
            .expect("snapshot");
        assert_eq!(snapshot.reserved_sessions, 0);
    }

    #[tokio::test]
    async fn resolve_node_returns_only_live_private_endpoint() {
        let cluster = Arc::new(Mutex::new(SfuClusterDirectory::default()));
        cluster
            .lock()
            .expect("cluster")
            .upsert_node_with_endpoint(
                SfuNodeDescriptor {
                    node_id: OpaqueId::new("sfu-route").expect("node"),
                    region: "eu".to_owned(),
                    state: SfuNodeState::Healthy,
                    active_sessions: 0,
                    max_sessions: 10,
                    lease_expires_at_unix_ms: 20_000,
                },
                SfuNodeEndpoint::new("127.0.0.1:7001".parse().expect("socket")).expect("endpoint"),
            )
            .expect("register node endpoint");

        let service =
            GrpcSfuPlacementService::new(Arc::new(FixedClock(10_000)), Arc::clone(&cluster));
        let route = pb::sfu_placement_service_server::SfuPlacementService::resolve_node(
            &service,
            Request::new(pb::SfuResolveNodeRequest {
                node_id: Some(pb_id("sfu-route")),
            }),
        )
        .await
        .expect("resolve live node")
        .into_inner()
        .route
        .expect("route");
        assert_eq!(route.node_id.expect("node id").value, b"sfu-route");
        assert_eq!(route.endpoint_ip, "127.0.0.1");
        assert_eq!(route.endpoint_port, 7001);

        let expired =
            GrpcSfuPlacementService::new(Arc::new(FixedClock(20_000)), Arc::clone(&cluster));
        let error = pb::sfu_placement_service_server::SfuPlacementService::resolve_node(
            &expired,
            Request::new(pb::SfuResolveNodeRequest {
                node_id: Some(pb_id("sfu-route")),
            }),
        )
        .await
        .expect_err("expired endpoint must fail closed");
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(cluster.lock().expect("cluster").is_empty());
    }

    #[tokio::test]
    async fn place_call_fails_closed_without_healthy_capacity() {
        let service = GrpcSfuPlacementService::new(
            Arc::new(FixedClock(10_000)),
            Arc::new(Mutex::new(SfuClusterDirectory::default())),
        );
        let error = pb::sfu_placement_service_server::SfuPlacementService::place_call(
            &service,
            Request::new(place_request()),
        )
        .await
        .expect_err("no capacity");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }
}

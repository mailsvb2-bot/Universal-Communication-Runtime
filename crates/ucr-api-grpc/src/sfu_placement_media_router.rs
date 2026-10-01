use std::{fmt, net::SocketAddr};

use tonic::transport::{Channel, Endpoint};
use ucr_model::{CallId, OpaqueId, TenantScope};
use ucr_sfu::{MAX_SFU_REGION_BYTES, SfuForwardOutcome, SfuNodeEndpoint, SfuValidatedForwardBatch};

use super::{
    GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, SfuNodeMediaClientError,
    SfuNodeMediaClientTlsConfig, decode_opaque, pb, pb_opaque, pb_scope,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SfuPlacementRoutingPolicy {
    pub preferred_region: Option<String>,
    pub allow_cross_region_failover: bool,
}

impl SfuPlacementRoutingPolicy {
    /// Creates one bounded infrastructure placement policy.
    ///
    /// # Errors
    /// Rejects oversized or control-character region hints.
    pub fn new(
        preferred_region: Option<String>,
        allow_cross_region_failover: bool,
    ) -> Result<Self, String> {
        if let Some(region) = preferred_region.as_deref()
            && (region.is_empty()
                || region.len() > MAX_SFU_REGION_BYTES
                || region.chars().any(char::is_control))
        {
            return Err("invalid preferred SFU region".to_owned());
        }
        Ok(Self {
            preferred_region,
            allow_cross_region_failover,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuPlacementForwardResult {
    pub node_id: OpaqueId,
    pub retained_sticky_placement: bool,
    pub crossed_region: bool,
    pub outcome: SfuForwardOutcome,
}

#[derive(Debug)]
pub enum SfuPlacementMediaRouterError {
    PlacementTransport(String),
    PlacementRpc(tonic::Status),
    Protocol(&'static str),
    InvalidEndpoint,
    Node(SfuNodeMediaClientError),
}

#[derive(Clone)]
pub struct PlacementAwareSfuNodeRouter {
    placement: pb::sfu_placement_service_client::SfuPlacementServiceClient<Channel>,
    node_tls: SfuNodeMediaClientTlsConfig,
    policy: SfuPlacementRoutingPolicy,
}

impl fmt::Debug for PlacementAwareSfuNodeRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlacementAwareSfuNodeRouter")
            .field("policy", &self.policy)
            .field("node_tls", &self.node_tls)
            .finish_non_exhaustive()
    }
}

impl PlacementAwareSfuNodeRouter {
    /// Connects to the private loopback placement service.
    ///
    /// The control plane is intentionally plaintext only on loopback; the resolved inter-node media
    /// hop is separately protected by the deployment-scoped mTLS configuration.
    ///
    /// # Errors
    /// Rejects non-loopback control-plane endpoints and connection failures.
    pub async fn connect(
        operator_endpoint: SocketAddr,
        node_tls: SfuNodeMediaClientTlsConfig,
        policy: SfuPlacementRoutingPolicy,
    ) -> Result<Self, SfuPlacementMediaRouterError> {
        if !operator_endpoint.ip().is_loopback() {
            return Err(SfuPlacementMediaRouterError::PlacementTransport(
                "SFU placement client requires a loopback operator endpoint".to_owned(),
            ));
        }
        let uri = format!("http://{operator_endpoint}");
        let channel = Endpoint::from_shared(uri)
            .map_err(|error| SfuPlacementMediaRouterError::PlacementTransport(error.to_string()))?
            .connect()
            .await
            .map_err(|error| SfuPlacementMediaRouterError::PlacementTransport(error.to_string()))?;
        let placement = pb::sfu_placement_service_client::SfuPlacementServiceClient::new(channel)
            .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
            .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE);
        Ok(Self {
            placement,
            node_tls,
            policy,
        })
    }

    /// Places the canonical Call, resolves only the selected live node endpoint, then forwards the
    /// already-validated encrypted batch over the private mTLS node transport.
    ///
    /// This method deliberately does not invent automatic failover or release the sticky placement
    /// after each frame. Placement lifetime belongs to the later realtime-session routing owner.
    ///
    /// # Errors
    /// Fails closed on placement/route mismatch, invalid/private-route violation, mTLS failure,
    /// missing or invalid destination receipts, backpressure, or destination rejection.
    pub async fn forward_batch(
        &mut self,
        batch: &SfuValidatedForwardBatch,
    ) -> Result<SfuPlacementForwardResult, SfuPlacementMediaRouterError> {
        let scope = &batch.envelope().frame.header.scope;
        let call_id = &batch.envelope().frame.header.call_id;
        let resolved = self.place_and_resolve(scope, call_id).await?;
        let mut node = self
            .node_tls
            .connect(resolved.endpoint.address)
            .await
            .map_err(SfuPlacementMediaRouterError::Node)?;
        let outcome = node
            .forward_batch(batch)
            .await
            .map_err(SfuPlacementMediaRouterError::Node)?;
        Ok(SfuPlacementForwardResult {
            node_id: resolved.node_id,
            retained_sticky_placement: resolved.retained_sticky_placement,
            crossed_region: resolved.crossed_region,
            outcome,
        })
    }

    async fn place_and_resolve(
        &mut self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<ResolvedPlacement, SfuPlacementMediaRouterError> {
        let placement = self
            .placement
            .place_call(pb::SfuPlaceCallRequest {
                scope: Some(pb_scope(scope)),
                call_id: Some(pb_opaque(call_id.as_opaque())),
                preferred_region: self.policy.preferred_region.clone().unwrap_or_default(),
                allow_cross_region_failover: self.policy.allow_cross_region_failover,
            })
            .await
            .map_err(SfuPlacementMediaRouterError::PlacementRpc)?
            .into_inner()
            .placement
            .ok_or(SfuPlacementMediaRouterError::Protocol(
                "SFU placement response omitted placement",
            ))?;
        let selected_pb = placement
            .node_id
            .ok_or(SfuPlacementMediaRouterError::Protocol(
                "SFU placement response omitted node id",
            ))?;
        let selected_node = decode_opaque(Some(selected_pb.clone()))
            .map_err(|_| SfuPlacementMediaRouterError::Protocol("invalid selected SFU node id"))?;

        let route = self
            .placement
            .resolve_node(pb::SfuResolveNodeRequest {
                node_id: Some(selected_pb.clone()),
            })
            .await
            .map_err(SfuPlacementMediaRouterError::PlacementRpc)?
            .into_inner()
            .route
            .ok_or(SfuPlacementMediaRouterError::Protocol(
                "SFU node resolution omitted route",
            ))?;
        let route_node = route.node_id.ok_or(SfuPlacementMediaRouterError::Protocol(
            "SFU node resolution omitted node id",
        ))?;
        if route_node.value != selected_pb.value {
            return Err(SfuPlacementMediaRouterError::Protocol(
                "SFU node resolution returned a different node",
            ));
        }

        let port = u16::try_from(route.endpoint_port)
            .ok()
            .filter(|value| *value != 0)
            .ok_or(SfuPlacementMediaRouterError::InvalidEndpoint)?;
        let ip = route
            .endpoint_ip
            .parse()
            .map_err(|_| SfuPlacementMediaRouterError::InvalidEndpoint)?;
        let endpoint = SfuNodeEndpoint::new(SocketAddr::new(ip, port))
            .map_err(|_| SfuPlacementMediaRouterError::InvalidEndpoint)?;
        if !is_private_node_endpoint(endpoint.address) {
            return Err(SfuPlacementMediaRouterError::InvalidEndpoint);
        }

        Ok(ResolvedPlacement {
            node_id: selected_node,
            retained_sticky_placement: placement.retained_sticky_placement,
            crossed_region: placement.crossed_region,
            endpoint,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedPlacement {
    node_id: OpaqueId,
    retained_sticky_placement: bool,
    crossed_region: bool,
    endpoint: SfuNodeEndpoint,
}

fn is_private_node_endpoint(address: SocketAddr) -> bool {
    match address.ip() {
        std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        std::net::IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status, transport::Server};
    use ucr_model::{NamespaceId, TenantId};
    use ucr_secrets::{
        InMemorySecretProvider, SecretHandle, SecretMaterial, SecretProvider, SecretPurpose,
        SecretVersion,
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct FixedPlacementService {
        route_node_id: &'static str,
        endpoint_ip: &'static str,
        endpoint_port: u32,
    }

    #[tonic::async_trait]
    impl pb::sfu_placement_service_server::SfuPlacementService for FixedPlacementService {
        async fn place_call(
            &self,
            request: Request<pb::SfuPlaceCallRequest>,
        ) -> Result<Response<pb::SfuPlaceCallResponse>, Status> {
            let body = request.into_inner();
            if body.scope.is_none() || body.call_id.is_none() {
                return Err(Status::invalid_argument("missing placement coordinates"));
            }
            Ok(Response::new(pb::SfuPlaceCallResponse {
                placement: Some(pb::SfuPlacement {
                    node_id: Some(pb::OpaqueId {
                        value: b"node-a".to_vec(),
                    }),
                    retained_sticky_placement: true,
                    crossed_region: false,
                }),
            }))
        }

        async fn release_call(
            &self,
            _request: Request<pb::SfuReleaseCallRequest>,
        ) -> Result<Response<pb::SfuReleaseCallResponse>, Status> {
            Ok(Response::new(pb::SfuReleaseCallResponse {
                released_call_id: Some(pb::OpaqueId {
                    value: b"call-a".to_vec(),
                }),
            }))
        }

        async fn resolve_node(
            &self,
            _request: Request<pb::SfuResolveNodeRequest>,
        ) -> Result<Response<pb::SfuResolveNodeResponse>, Status> {
            Ok(Response::new(pb::SfuResolveNodeResponse {
                route: Some(pb::SfuNodeRoute {
                    node_id: Some(pb::OpaqueId {
                        value: self.route_node_id.as_bytes().to_vec(),
                    }),
                    endpoint_ip: self.endpoint_ip.to_owned(),
                    endpoint_port: self.endpoint_port,
                }),
            }))
        }
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").expect("tenant")),
            namespace_id: Some(NamespaceId::from_opaque(
                OpaqueId::new("namespace-a").expect("namespace"),
            )),
        }
    }

    fn call() -> CallId {
        CallId::from_opaque(OpaqueId::new("call-a").expect("call"))
    }

    fn dummy_node_tls() -> SfuNodeMediaClientTlsConfig {
        let provider = InMemorySecretProvider::default();
        let certificate_handle = SecretHandle {
            secret_id: OpaqueId::new("router-cert").expect("cert id"),
            purpose: SecretPurpose::TlsCertificate,
        };
        let private_key_handle = SecretHandle {
            secret_id: OpaqueId::new("router-key").expect("key id"),
            purpose: SecretPurpose::TlsPrivateKey,
        };
        provider
            .provision(
                certificate_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("router-cert-v1").expect("cert version"),
                    material: SecretMaterial::new(b"certificate".to_vec()).expect("cert"),
                },
            )
            .expect("provision cert");
        provider
            .provision(
                private_key_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("router-key-v1").expect("key version"),
                    material: SecretMaterial::new(b"private-key".to_vec()).expect("key"),
                },
            )
            .expect("provision key");
        let provider: Arc<dyn SecretProvider> = Arc::new(provider);
        SfuNodeMediaClientTlsConfig::new(
            provider,
            certificate_handle,
            private_key_handle,
            b"server-ca".to_vec(),
            None,
            "localhost",
        )
        .expect("node TLS")
    }

    async fn router_for(
        service: FixedPlacementService,
    ) -> (
        PlacementAwareSfuNodeRouter,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind placement service");
        let address = listener.local_addr().expect("placement address");
        let server_task = tokio::spawn(async move {
            Server::builder()
                .add_service(
                    pb::sfu_placement_service_server::SfuPlacementServiceServer::new(service),
                )
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        });
        let router = PlacementAwareSfuNodeRouter::connect(
            address,
            dummy_node_tls(),
            SfuPlacementRoutingPolicy::new(Some("eu".to_owned()), false).expect("policy"),
        )
        .await
        .expect("router");
        (router, server_task)
    }

    #[tokio::test]
    async fn placement_router_uses_selected_private_route_only() {
        let (mut router, task) = router_for(FixedPlacementService {
            route_node_id: "node-a",
            endpoint_ip: "10.42.0.8",
            endpoint_port: 7001,
        })
        .await;
        let resolved = router
            .place_and_resolve(&scope(), &call())
            .await
            .expect("resolved placement");
        assert_eq!(resolved.node_id.as_str(), "node-a");
        assert_eq!(
            resolved.endpoint.address,
            "10.42.0.8:7001"
                .parse::<SocketAddr>()
                .expect("private endpoint")
        );
        assert!(resolved.retained_sticky_placement);
        assert!(!resolved.crossed_region);
        task.abort();
    }

    #[tokio::test]
    async fn placement_router_rejects_route_node_confusion() {
        let (mut router, task) = router_for(FixedPlacementService {
            route_node_id: "node-b",
            endpoint_ip: "10.42.0.8",
            endpoint_port: 7001,
        })
        .await;
        assert!(matches!(
            router.place_and_resolve(&scope(), &call()).await,
            Err(SfuPlacementMediaRouterError::Protocol(
                "SFU node resolution returned a different node"
            ))
        ));
        task.abort();
    }

    #[tokio::test]
    async fn placement_router_rejects_public_media_endpoint() {
        let (mut router, task) = router_for(FixedPlacementService {
            route_node_id: "node-a",
            endpoint_ip: "8.8.8.8",
            endpoint_port: 7001,
        })
        .await;
        assert!(matches!(
            router.place_and_resolve(&scope(), &call()).await,
            Err(SfuPlacementMediaRouterError::InvalidEndpoint)
        ));
        task.abort();
    }

    #[tokio::test]
    async fn placement_router_rejects_non_loopback_control_plane() {
        let error = PlacementAwareSfuNodeRouter::connect(
            "10.42.0.8:50052".parse().expect("operator endpoint"),
            dummy_node_tls(),
            SfuPlacementRoutingPolicy::default(),
        )
        .await
        .expect_err("remote plaintext control plane must fail closed");
        assert!(matches!(
            error,
            SfuPlacementMediaRouterError::PlacementTransport(_)
        ));
    }
}

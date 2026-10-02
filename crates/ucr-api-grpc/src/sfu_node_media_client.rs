use std::{fmt, net::SocketAddr, sync::Arc};

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use ucr_secrets::{MAX_SECRET_BYTES, SecretHandle, SecretProvider, SecretPurpose};
use ucr_sfu::{SfuForwardOutcome, SfuValidatedForwardBatch};

use super::realtime_service::pb_sfu_forward_envelope;
use super::{GRPC_MAX_DECODING_MESSAGE_SIZE, GRPC_MAX_ENCODING_MESSAGE_SIZE, pb, pb_principal_ref};

pub const MAX_SFU_NODE_TLS_SERVER_NAME_BYTES: usize = 253;

#[derive(Clone)]
pub struct SfuNodeMediaClientTlsConfig {
    provider: Arc<dyn SecretProvider>,
    certificate_handle: SecretHandle,
    private_key_handle: SecretHandle,
    server_ca_pem: Arc<[u8]>,
    previous_server_ca_pem: Option<Arc<[u8]>>,
    server_name: Arc<str>,
}

impl fmt::Debug for SfuNodeMediaClientTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SfuNodeMediaClientTlsConfig")
            .field("certificate_handle", &self.certificate_handle)
            .field("private_key_handle", &self.private_key_handle)
            .field("server_ca", &"<redacted-public-trust-material>")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl SfuNodeMediaClientTlsConfig {
    /// Builds deployment-scoped mTLS credentials for the private SFU node client.
    ///
    /// # Errors
    /// Rejects wrong-purpose or unavailable secret handles, invalid trust material, and malformed
    /// TLS server names. Tenant/user credentials are deliberately not accepted here.
    pub fn new(
        provider: Arc<dyn SecretProvider>,
        certificate_handle: SecretHandle,
        private_key_handle: SecretHandle,
        server_ca_pem: Vec<u8>,
        previous_server_ca_pem: Option<Vec<u8>>,
        server_name: impl Into<String>,
    ) -> Result<Self, String> {
        if certificate_handle.purpose != SecretPurpose::TlsCertificate {
            return Err(
                "SFU node client certificate handle must use TlsCertificate purpose".to_owned(),
            );
        }
        if private_key_handle.purpose != SecretPurpose::TlsPrivateKey {
            return Err(
                "SFU node client private key handle must use TlsPrivateKey purpose".to_owned(),
            );
        }
        provider
            .active_secret_set(&certificate_handle)
            .map_err(|error| format!("resolve SFU node client certificate secret: {error:?}"))?;
        provider
            .active_secret_set(&private_key_handle)
            .map_err(|error| format!("resolve SFU node client private-key secret: {error:?}"))?;
        validate_ca(&server_ca_pem)?;
        if let Some(previous) = previous_server_ca_pem.as_deref() {
            validate_ca(previous)?;
        }
        let server_name = server_name.into();
        if server_name.is_empty()
            || server_name.len() > MAX_SFU_NODE_TLS_SERVER_NAME_BYTES
            || server_name.chars().any(char::is_whitespace)
            || server_name.chars().any(char::is_control)
        {
            return Err(
                "SFU node TLS server name must be a bounded non-whitespace token".to_owned(),
            );
        }
        Ok(Self {
            provider,
            certificate_handle,
            private_key_handle,
            server_ca_pem: Arc::from(server_ca_pem),
            previous_server_ca_pem: previous_server_ca_pem.map(Arc::from),
            server_name: Arc::from(server_name),
        })
    }

    /// Opens one authenticated HTTP/2 channel to a resolved private SFU endpoint.
    ///
    /// Current and previous certificate/key versions are tried only to support bounded credential
    /// overlap. The endpoint itself is supplied by the placement/resolution owner.
    ///
    /// # Errors
    /// Fails closed when secret resolution, TLS configuration, peer authentication, or connection
    /// establishment fails.
    pub async fn connect(
        &self,
        endpoint: SocketAddr,
    ) -> Result<GrpcSfuNodeMediaClient, SfuNodeMediaClientError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificates = self
            .provider
            .active_secret_set(&self.certificate_handle)
            .map_err(|error| {
                SfuNodeMediaClientError::Transport(format!(
                    "resolve SFU node client certificate secret: {error:?}"
                ))
            })?;
        let private_keys = self
            .provider
            .active_secret_set(&self.private_key_handle)
            .map_err(|error| {
                SfuNodeMediaClientError::Transport(format!(
                    "resolve SFU node client private-key secret: {error:?}"
                ))
            })?;

        let certificate_versions = std::iter::once(&certificates.current)
            .chain(certificates.previous.iter())
            .collect::<Vec<_>>();
        let private_key_versions = std::iter::once(&private_keys.current)
            .chain(private_keys.previous.iter())
            .collect::<Vec<_>>();
        let mut trust = self.server_ca_pem.as_ref().to_vec();
        if let Some(previous) = &self.previous_server_ca_pem {
            trust.extend_from_slice(b"\n");
            trust.extend_from_slice(previous);
        }

        let uri = format!("https://{endpoint}");
        let mut last_error = None;
        for certificate in &certificate_versions {
            for private_key in &private_key_versions {
                let tls = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(trust.clone()))
                    .identity(Identity::from_pem(
                        certificate.material.as_bytes(),
                        private_key.material.as_bytes(),
                    ))
                    .domain_name(self.server_name.as_ref());
                let transport = Endpoint::from_shared(uri.clone())
                    .map_err(|error| SfuNodeMediaClientError::Transport(error.to_string()))?
                    .tls_config(tls)
                    .map_err(|error| SfuNodeMediaClientError::Transport(error.to_string()))?;
                match transport.connect().await {
                    Ok(channel) => return Ok(GrpcSfuNodeMediaClient::new(channel)),
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
        }
        Err(SfuNodeMediaClientError::Transport(
            last_error.unwrap_or_else(|| "no active SFU node client TLS identity".to_owned()),
        ))
    }
}

fn validate_ca(value: &[u8]) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_SECRET_BYTES {
        Err("SFU node server CA material must be non-empty and bounded".to_owned())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum SfuNodeMediaClientError {
    Transport(String),
    Rpc(tonic::Status),
    Protocol(&'static str),
    Backpressure { accepted_before_failure: usize },
    Rejected { accepted_before_failure: usize },
}

#[derive(Clone)]
pub struct GrpcSfuNodeMediaClient {
    inner: pb::sfu_node_media_service_client::SfuNodeMediaServiceClient<Channel>,
}

impl fmt::Debug for GrpcSfuNodeMediaClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcSfuNodeMediaClient")
            .finish_non_exhaustive()
    }
}

impl GrpcSfuNodeMediaClient {
    fn new(channel: Channel) -> Self {
        Self {
            inner: pb::sfu_node_media_service_client::SfuNodeMediaServiceClient::new(channel)
                .max_decoding_message_size(GRPC_MAX_DECODING_MESSAGE_SIZE)
                .max_encoding_message_size(GRPC_MAX_ENCODING_MESSAGE_SIZE),
        }
    }

    /// Verifies that the mutually authenticated node service can accept an empty bounded stream.
    ///
    /// # Errors
    /// Returns transport/RPC/protocol failures. This is infrastructure reachability evidence only.
    pub async fn probe(&mut self) -> Result<(), SfuNodeMediaClientError> {
        let response = self
            .inner
            .forward_encrypted(tokio_stream::empty::<pb::SfuNodeEncryptedMedia>())
            .await
            .map_err(SfuNodeMediaClientError::Rpc)?;
        let mut receipts = response.into_inner();
        if receipts
            .message()
            .await
            .map_err(SfuNodeMediaClientError::Rpc)?
            .is_some()
        {
            return Err(SfuNodeMediaClientError::Protocol(
                "empty SFU node stream returned an unexpected receipt",
            ));
        }
        Ok(())
    }

    /// Forwards one already-canonicalized SFU batch and waits for the destination's receipt for
    /// every target before reporting success.
    ///
    /// # Errors
    /// Fails on missing/out-of-order/extra receipts, authenticated RPC failure, backpressure, or
    /// rejection. Partial acceptance is reported explicitly and never upgraded to full success.
    pub async fn forward_batch(
        &mut self,
        batch: &SfuValidatedForwardBatch,
    ) -> Result<SfuForwardOutcome, SfuNodeMediaClientError> {
        if batch.target_count() == 0 {
            return Err(SfuNodeMediaClientError::Protocol(
                "validated SFU batch must contain at least one target",
            ));
        }
        let mut items = Vec::with_capacity(batch.target_count());
        for (index, target) in batch.targets().iter().enumerate() {
            let stream_sequence = u64::try_from(index + 1).map_err(|_| {
                SfuNodeMediaClientError::Protocol("SFU node stream sequence overflow")
            })?;
            items.push(pb::SfuNodeEncryptedMedia {
                stream_sequence,
                target: Some(pb::SfuForwardTarget {
                    recipient: Some(pb_principal_ref(&target.recipient)),
                }),
                envelope: Some(pb_sfu_forward_envelope(batch.envelope())),
            });
        }

        let response = self
            .inner
            .forward_encrypted(tokio_stream::iter(items))
            .await
            .map_err(SfuNodeMediaClientError::Rpc)?;
        let mut receipts = response.into_inner();
        let mut accepted = 0_usize;
        for index in 0..batch.target_count() {
            let expected_sequence = u64::try_from(index + 1).map_err(|_| {
                SfuNodeMediaClientError::Protocol("SFU node receipt sequence overflow")
            })?;
            let receipt = receipts
                .message()
                .await
                .map_err(SfuNodeMediaClientError::Rpc)?
                .ok_or(SfuNodeMediaClientError::Protocol(
                    "SFU node stream ended before every target had a receipt",
                ))?;
            if receipt.stream_sequence != expected_sequence {
                return Err(SfuNodeMediaClientError::Protocol(
                    "SFU node receipt sequence is not exact and monotonic",
                ));
            }
            match pb::SfuNodeForwardStatus::try_from(receipt.status) {
                Ok(pb::SfuNodeForwardStatus::Accepted) => accepted += 1,
                Ok(pb::SfuNodeForwardStatus::Backpressure) => {
                    return Err(SfuNodeMediaClientError::Backpressure {
                        accepted_before_failure: accepted,
                    });
                }
                Ok(pb::SfuNodeForwardStatus::Rejected) => {
                    return Err(SfuNodeMediaClientError::Rejected {
                        accepted_before_failure: accepted,
                    });
                }
                Ok(pb::SfuNodeForwardStatus::Unspecified) | Err(_) => {
                    return Err(SfuNodeMediaClientError::Protocol(
                        "SFU node returned an invalid receipt status",
                    ));
                }
            }
        }
        if receipts
            .message()
            .await
            .map_err(SfuNodeMediaClientError::Rpc)?
            .is_some()
        {
            return Err(SfuNodeMediaClientError::Protocol(
                "SFU node returned more receipts than submitted targets",
            ));
        }
        Ok(SfuForwardOutcome {
            accepted_recipients: accepted,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use tokio::net::TcpListener;
    use tokio_stream::{Stream, wrappers::TcpListenerStream};
    use tonic::transport::{Identity as ServerIdentity, Server, ServerTlsConfig};
    use tonic::{Request, Response, Status};
    use ucr_model::OpaqueId;
    use ucr_secrets::{InMemorySecretProvider, SecretMaterial, SecretVersion};

    use super::*;

    struct TestCa {
        certificate: rcgen::Certificate,
        key: KeyPair,
    }

    fn test_ca() -> TestCa {
        let mut params = CertificateParams::new(Vec::new()).expect("test CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let key = KeyPair::generate().expect("test CA key");
        let certificate = params.self_signed(&key).expect("test CA certificate");
        TestCa { certificate, key }
    }

    fn test_leaf(ca: &TestCa, name: &str, usage: ExtendedKeyUsagePurpose) -> (String, String) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).expect("test leaf params");
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(usage);
        let key = KeyPair::generate().expect("test leaf key");
        let certificate = params
            .signed_by(&key, &ca.certificate, &ca.key)
            .expect("test leaf certificate");
        (certificate.pem(), key.serialize_pem())
    }

    fn client_config(
        server_ca_pem: &str,
        client_certificate: &str,
        client_private_key: &str,
    ) -> SfuNodeMediaClientTlsConfig {
        let provider = InMemorySecretProvider::default();
        let certificate_handle = SecretHandle {
            secret_id: OpaqueId::new("sfu-client-certificate").expect("certificate id"),
            purpose: SecretPurpose::TlsCertificate,
        };
        let private_key_handle = SecretHandle {
            secret_id: OpaqueId::new("sfu-client-private-key").expect("private key id"),
            purpose: SecretPurpose::TlsPrivateKey,
        };
        provider
            .provision(
                certificate_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("client-cert-v1").expect("certificate version"),
                    material: SecretMaterial::new(client_certificate.as_bytes().to_vec())
                        .expect("certificate material"),
                },
            )
            .expect("provision certificate");
        provider
            .provision(
                private_key_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("client-key-v1").expect("private key version"),
                    material: SecretMaterial::new(client_private_key.as_bytes().to_vec())
                        .expect("private key material"),
                },
            )
            .expect("provision private key");
        let provider: Arc<dyn SecretProvider> = Arc::new(provider);
        SfuNodeMediaClientTlsConfig::new(
            provider,
            certificate_handle,
            private_key_handle,
            server_ca_pem.as_bytes().to_vec(),
            None,
            "localhost",
        )
        .expect("client TLS config")
    }

    #[derive(Debug, Default)]
    struct EmptyNodeService;

    #[tonic::async_trait]
    impl pb::sfu_node_media_service_server::SfuNodeMediaService for EmptyNodeService {
        type ForwardEncryptedStream =
            Pin<Box<dyn Stream<Item = Result<pb::SfuNodeForwardReceipt, Status>> + Send + 'static>>;

        async fn forward_encrypted(
            &self,
            request: Request<tonic::Streaming<pb::SfuNodeEncryptedMedia>>,
        ) -> Result<Response<Self::ForwardEncryptedStream>, Status> {
            if request
                .peer_certs()
                .is_none_or(|certificates| certificates.is_empty())
            {
                return Err(Status::unauthenticated("missing mTLS peer"));
            }
            Ok(Response::new(Box::pin(tokio_stream::empty())))
        }
    }

    #[tokio::test]
    async fn outbound_node_client_requires_trusted_mtls_identity_and_reaches_service() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let trusted_ca = test_ca();
        let (server_certificate, server_private_key) = test_leaf(
            &trusted_ca,
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (trusted_client_certificate, trusted_client_private_key) = test_leaf(
            &trusted_ca,
            "ucr-sfu-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let untrusted_ca = test_ca();
        let (untrusted_client_certificate, untrusted_client_private_key) = test_leaf(
            &untrusted_ca,
            "ucr-sfu-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind node service");
        let address = listener.local_addr().expect("node service address");
        let tls = ServerTlsConfig::new()
            .identity(ServerIdentity::from_pem(
                server_certificate.as_bytes(),
                server_private_key.as_bytes(),
            ))
            .client_ca_root(Certificate::from_pem(trusted_ca.certificate.pem()));
        let mut server = Server::builder().tls_config(tls).expect("server TLS");
        let server_task = tokio::spawn(async move {
            server
                .add_service(
                    pb::sfu_node_media_service_server::SfuNodeMediaServiceServer::new(
                        EmptyNodeService,
                    ),
                )
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
        });

        let trusted = client_config(
            &trusted_ca.certificate.pem(),
            &trusted_client_certificate,
            &trusted_client_private_key,
        );
        let mut client = trusted
            .connect(address)
            .await
            .expect("trusted mTLS client connects");
        client
            .probe()
            .await
            .expect("authenticated node service probe");

        let untrusted = client_config(
            &trusted_ca.certificate.pem(),
            &untrusted_client_certificate,
            &untrusted_client_private_key,
        );
        let untrusted_rejected = match untrusted.connect(address).await {
            Err(_) => true,
            Ok(mut client) => client.probe().await.is_err(),
        };
        assert!(
            untrusted_rejected,
            "untrusted client certificate must fail mTLS admission before an RPC is accepted"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn outbound_node_client_observes_rotated_identity_without_reconstruction() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server_ca = test_ca();
        let (server_certificate, server_private_key) = test_leaf(
            &server_ca,
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let client_ca_v1 = test_ca();
        let (client_certificate_v1, client_private_key_v1) = test_leaf(
            &client_ca_v1,
            "ucr-sfu-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let client_ca_v2 = test_ca();
        let (client_certificate_v2, client_private_key_v2) = test_leaf(
            &client_ca_v2,
            "ucr-sfu-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let provider = Arc::new(InMemorySecretProvider::default());
        let certificate_handle = SecretHandle {
            secret_id: OpaqueId::new("reload-client-certificate").expect("certificate id"),
            purpose: SecretPurpose::TlsCertificate,
        };
        let private_key_handle = SecretHandle {
            secret_id: OpaqueId::new("reload-client-private-key").expect("private key id"),
            purpose: SecretPurpose::TlsPrivateKey,
        };
        provider
            .provision(
                certificate_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("client-cert-v1").expect("certificate version"),
                    material: SecretMaterial::new(client_certificate_v1.as_bytes().to_vec())
                        .expect("certificate material"),
                },
            )
            .expect("provision certificate");
        provider
            .provision(
                private_key_handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("client-key-v1").expect("private key version"),
                    material: SecretMaterial::new(client_private_key_v1.as_bytes().to_vec())
                        .expect("private key material"),
                },
            )
            .expect("provision private key");
        let provider_boundary: Arc<dyn SecretProvider> = provider.clone();
        let client_config = SfuNodeMediaClientTlsConfig::new(
            provider_boundary,
            certificate_handle.clone(),
            private_key_handle.clone(),
            server_ca.certificate.pem().into_bytes(),
            None,
            "localhost",
        )
        .expect("reloadable client config");

        let start_server = |client_ca_pem: String| {
            let server_certificate = server_certificate.clone();
            let server_private_key = server_private_key.clone();
            async move {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind node service");
                let address = listener.local_addr().expect("node service address");
                let tls = ServerTlsConfig::new()
                    .identity(ServerIdentity::from_pem(
                        server_certificate.as_bytes(),
                        server_private_key.as_bytes(),
                    ))
                    .client_ca_root(Certificate::from_pem(client_ca_pem));
                let mut server = Server::builder().tls_config(tls).expect("server TLS");
                let task = tokio::spawn(async move {
                    server
                        .add_service(
                            pb::sfu_node_media_service_server::SfuNodeMediaServiceServer::new(
                                EmptyNodeService,
                            ),
                        )
                        .serve_with_incoming(TcpListenerStream::new(listener))
                        .await
                });
                (address, task)
            }
        };

        let (v1_address, v1_task) = start_server(client_ca_v1.certificate.pem()).await;
        let mut v1_client = client_config
            .connect(v1_address)
            .await
            .expect("v1 client identity connects");
        v1_client.probe().await.expect("v1 authenticated probe");
        v1_task.abort();

        provider
            .rotate(
                &certificate_handle,
                SecretVersion {
                    version_id: OpaqueId::new("client-cert-v2").expect("certificate version"),
                    material: SecretMaterial::new(client_certificate_v2.as_bytes().to_vec())
                        .expect("certificate material"),
                },
            )
            .expect("rotate certificate");
        provider
            .rotate(
                &private_key_handle,
                SecretVersion {
                    version_id: OpaqueId::new("client-key-v2").expect("private key version"),
                    material: SecretMaterial::new(client_private_key_v2.as_bytes().to_vec())
                        .expect("private key material"),
                },
            )
            .expect("rotate private key");

        let (v2_address, v2_task) = start_server(client_ca_v2.certificate.pem()).await;
        let mut v2_client = client_config
            .connect(v2_address)
            .await
            .expect("same config observes v2 client identity");
        v2_client.probe().await.expect("v2 authenticated probe");
        v2_task.abort();
    }

    #[test]
    fn outbound_node_client_config_rejects_wrong_secret_purpose() {
        let provider = InMemorySecretProvider::default();
        let certificate_handle = SecretHandle {
            secret_id: OpaqueId::new("wrong-client-certificate").expect("certificate id"),
            purpose: SecretPurpose::JoinSigning,
        };
        let private_key_handle = SecretHandle {
            secret_id: OpaqueId::new("wrong-client-private-key").expect("private key id"),
            purpose: SecretPurpose::TlsPrivateKey,
        };
        let provider: Arc<dyn SecretProvider> = Arc::new(provider);
        assert!(
            SfuNodeMediaClientTlsConfig::new(
                provider,
                certificate_handle,
                private_key_handle,
                b"ca".to_vec(),
                None,
                "localhost",
            )
            .is_err()
        );
    }
}

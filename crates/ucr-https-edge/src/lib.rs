#![forbid(unsafe_code)]

use std::{fs, io::Cursor, net::SocketAddr, path::Path, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};
use ucr_secrets::{ActiveSecretSet, SecretHandle, SecretProvider, SecretPurpose};

const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;


#[derive(Clone)]
pub struct ProviderBackedTlsAcceptor {
    provider: Arc<dyn SecretProvider>,
    certificate_handle: SecretHandle,
    private_key_handle: SecretHandle,
}

impl std::fmt::Debug for ProviderBackedTlsAcceptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderBackedTlsAcceptor")
            .field("certificate_handle", &self.certificate_handle)
            .field("private_key_handle", &self.private_key_handle)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl ProviderBackedTlsAcceptor {
    /// Creates a provider-backed TLS acceptor factory.
    ///
    /// # Errors
    /// Rejects wrong-purpose handles or currently unavailable/malformed provider material.
    pub fn new(
        provider: Arc<dyn SecretProvider>,
        certificate_handle: SecretHandle,
        private_key_handle: SecretHandle,
    ) -> Result<Self, String> {
        if certificate_handle.purpose != SecretPurpose::TlsCertificate {
            return Err("TLS certificate handle must use TlsCertificate purpose".to_owned());
        }
        if private_key_handle.purpose != SecretPurpose::TlsPrivateKey {
            return Err("TLS private key handle must use TlsPrivateKey purpose".to_owned());
        }
        let factory = Self {
            provider,
            certificate_handle,
            private_key_handle,
        };
        factory.current_acceptor()?;
        Ok(factory)
    }

    /// Resolves current/previous overlap and builds an acceptor for one new connection.
    ///
    /// New connections prefer the current/current pair. During independently sequenced
    /// certificate and key rotations, bounded previous versions are tried so an already-valid
    /// pair remains usable until both handles converge.
    ///
    /// # Errors
    /// Fails closed when the provider is unavailable or no active certificate/key pair matches.
    pub fn current_acceptor(&self) -> Result<TlsAcceptor, String> {
        let certificates = self
            .provider
            .active_secret_set(&self.certificate_handle)
            .map_err(|error| format!("resolve TLS certificate secret: {error:?}"))?;
        let private_keys = self
            .provider
            .active_secret_set(&self.private_key_handle)
            .map_err(|error| format!("resolve TLS private key secret: {error:?}"))?;
        acceptor_from_active_secret_sets(&certificates, &private_keys)
    }
}

fn acceptor_from_active_secret_sets(
    certificates: &ActiveSecretSet,
    private_keys: &ActiveSecretSet,
) -> Result<TlsAcceptor, String> {
    let certificate_versions = std::iter::once(&certificates.current)
        .chain(certificates.previous.iter())
        .collect::<Vec<_>>();
    let private_key_versions = std::iter::once(&private_keys.current)
        .chain(private_keys.previous.iter())
        .collect::<Vec<_>>();

    for certificate in &certificate_versions {
        for private_key in &private_key_versions {
            if let Ok(acceptor) = tls_acceptor_from_pem_bytes(
                certificate.material.as_bytes(),
                private_key.material.as_bytes(),
            ) {
                return Ok(acceptor);
            }
        }
    }
    Err("no active TLS certificate/private-key pair is valid".to_owned())
}

/// Starts the HTTPS edge with provider-backed TLS material.
///
/// The provider is resolved for every accepted connection, so new connections observe the newest
/// valid keypair without restarting the listener. Existing TLS sessions keep the acceptor snapshot
/// they already negotiated with.
///
/// # Errors
/// Returns bind, provider, certificate, key, or upstream configuration errors.
pub async fn run_with_secret_provider(
    bind: SocketAddr,
    upstream: SocketAddr,
    provider: Arc<dyn SecretProvider>,
    certificate_handle: SecretHandle,
    private_key_handle: SecretHandle,
) -> Result<(), String> {
    validate_loopback_upstream(upstream)?;
    let acceptor_factory =
        ProviderBackedTlsAcceptor::new(provider, certificate_handle, private_key_handle)?;
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind HTTPS edge: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve HTTPS edge: {error}"))?;
    println!("UCR_HTTPS_EDGE_READY endpoint=https://{address} upstream=http://{upstream}");

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept HTTPS edge connection: {error}"))?;
        let acceptor = match acceptor_factory.current_acceptor() {
            Ok(acceptor) => acceptor,
            Err(error) => {
                eprintln!("ucr-https-edge: TLS secret provider unavailable: {error}");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(error) = proxy_connection(acceptor, stream, upstream).await {
                eprintln!("ucr-https-edge: connection closed: {error}");
            }
        });
    }
}

/// Starts the TLS edge from process environment variables.
///
/// # Errors
/// Returns bind, certificate, or upstream configuration errors. Connection
/// failures are logged and do not stop the listener.
pub async fn run() -> Result<(), String> {
    let bind = std::env::var("UCR_HTTPS_EDGE_BIND")
        .map_err(|_| "UCR_HTTPS_EDGE_BIND is required".to_owned())?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid UCR_HTTPS_EDGE_BIND: {error}"))?;
    let upstream = std::env::var("UCR_HTTPS_EDGE_UPSTREAM")
        .map_err(|_| "UCR_HTTPS_EDGE_UPSTREAM is required".to_owned())?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid UCR_HTTPS_EDGE_UPSTREAM: {error}"))?;
    validate_loopback_upstream(upstream)?;
    let certificate = required_env("UCR_HTTPS_EDGE_CERT_FILE")?;
    let private_key = required_env("UCR_HTTPS_EDGE_KEY_FILE")?;
    let acceptor = tls_acceptor(&certificate, &private_key)?;

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind HTTPS edge: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("resolve HTTPS edge: {error}"))?;
    println!("UCR_HTTPS_EDGE_READY endpoint=https://{address} upstream=http://{upstream}");

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("accept HTTPS edge connection: {error}"))?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy_connection(acceptor, stream, upstream).await {
                eprintln!("ucr-https-edge: connection closed: {error}");
            }
        });
    }
}

fn required_env(variable: &str) -> Result<String, String> {
    std::env::var(variable).map_err(|_| format!("{variable} is required"))
}

fn validate_loopback_upstream(upstream: SocketAddr) -> Result<(), String> {
    if upstream.ip().is_loopback() {
        Ok(())
    } else {
        Err("HTTPS edge upstream must be a loopback listener".to_owned())
    }
}

/// Builds a TLS acceptor from bounded PEM certificate and private-key files.
///
/// # Errors
/// Returns explicit file, parse, or certificate configuration errors.
pub fn tls_acceptor(
    certificate_path: &str,
    private_key_path: &str,
) -> Result<tokio_rustls::TlsAcceptor, String> {
    bounded_file(certificate_path, MAX_CERTIFICATE_BYTES, "certificate")?;
    bounded_file(private_key_path, MAX_PRIVATE_KEY_BYTES, "private key")?;
    let certificate_pem =
        fs::read(certificate_path).map_err(|error| format!("open TLS certificate: {error}"))?;
    let private_key_pem =
        fs::read(private_key_path).map_err(|error| format!("open TLS private key: {error}"))?;
    tls_acceptor_from_pem_bytes(&certificate_pem, &private_key_pem)
}

fn tls_acceptor_from_pem_bytes(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<TlsAcceptor, String> {
    if certificate_pem.is_empty()
        || certificate_pem.len() > MAX_CERTIFICATE_BYTES as usize
        || private_key_pem.is_empty()
        || private_key_pem.len() > MAX_PRIVATE_KEY_BYTES as usize
    {
        return Err("TLS secret material must be non-empty and bounded".to_owned());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificates = parse_certificates(certificate_pem)?;
    let private_key = parse_private_key(private_key_pem)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| format!("build TLS server config: {error}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn parse_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = Cursor::new(pem);
    let certificates = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse TLS certificate: {error}"))?;
    if certificates.is_empty() {
        return Err("TLS certificate material contained no certificates".to_owned());
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = Cursor::new(pem);
    PrivateKeyDer::from_pem_reader(&mut reader)
        .map_err(|error| format!("parse TLS private key: {error}"))
}

fn bounded_file(path: &str, limit: u64, label: &str) -> Result<(), String> {
    let metadata = fs::metadata(Path::new(path))
        .map_err(|error| format!("inspect TLS {label} file: {error}"))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("TLS {label} must be a bounded regular file"));
    }
    Ok(())
}

/// Accepts one TLS connection and copies bytes to a loopback upstream.
///
/// # Errors
/// Returns handshake, dial, or copy errors.
pub async fn proxy_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: TcpStream,
    upstream: SocketAddr,
) -> Result<(), String> {
    let mut tls = acceptor
        .accept(stream)
        .await
        .map_err(|error| format!("accept TLS handshake: {error}"))?;
    let mut upstream = TcpStream::connect(upstream)
        .await
        .map_err(|error| format!("connect loopback upstream: {error}"))?;
    copy_bidirectional(&mut tls, &mut upstream)
        .await
        .map(|_| ())
        .map_err(|error| format!("proxy TLS connection: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        process::Command,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::{tls_acceptor, validate_loopback_upstream};

    #[test]
    fn https_edge_refuses_a_non_loopback_upstream() {
        let public: SocketAddr = "8.8.8.8:8082".parse().expect("address");
        assert!(validate_loopback_upstream(public).is_err());
        let loopback: SocketAddr = "127.0.0.1:8082".parse().expect("address");
        assert!(validate_loopback_upstream(loopback).is_ok());
    }

    fn mint_certificate(directory: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let certificate = directory.join("cert.pem");
        let private_key = directory.join("key.pem");
        let status = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
            .arg(&private_key)
            .arg("-out")
            .arg(&certificate)
            .args([
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                "subjectAltName=DNS:localhost",
            ])
            .status()
            .expect("openssl");
        assert!(status.success(), "openssl must mint the test certificate");
        (certificate, private_key)
    }

    async fn connect_edge(
        certificate: &std::path::Path,
        edge_address: SocketAddr,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut certificates =
            std::io::BufReader::new(std::fs::File::open(certificate).expect("cert"));
        let certificate = CertificateDer::pem_reader_iter(&mut certificates)
            .next()
            .expect("certificate")
            .expect("parse certificate");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust test certificate");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(edge_address)
            .await
            .expect("connect edge");
        connector
            .connect(ServerName::try_from("localhost").expect("server name"), tcp)
            .await
            .expect("tls handshake")
    }

    #[tokio::test]
    async fn https_edge_negotiates_http2_alpn() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ucr-https-edge-h2-{stamp}"));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let (certificate, private_key) = mint_certificate(&directory);

        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let edge = TcpListener::bind("127.0.0.1:0").await.expect("edge");
        let edge_address = edge.local_addr().expect("edge address");
        let acceptor = tls_acceptor(
            certificate.to_str().expect("certificate path"),
            private_key.to_str().expect("key path"),
        )
        .expect("acceptor");

        tokio::spawn(async move {
            let _ = upstream.accept().await.expect("upstream accept");
        });
        tokio::spawn(async move {
            let (stream, _) = edge.accept().await.expect("edge accept");
            super::proxy_connection(acceptor, stream, upstream_address)
                .await
                .expect("proxy");
        });

        let mut certificates =
            std::io::BufReader::new(std::fs::File::open(&certificate).expect("cert"));
        let certificate_der = CertificateDer::pem_reader_iter(&mut certificates)
            .next()
            .expect("certificate")
            .expect("parse certificate");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate_der).expect("trust test certificate");
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(edge_address)
            .await
            .expect("connect edge");
        let tls = connector
            .connect(ServerName::try_from("localhost").expect("server name"), tcp)
            .await
            .expect("tls handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn https_edge_proxies_tls_bytes_to_loopback_upstream() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ucr-https-edge-{stamp}"));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let (certificate, private_key) = mint_certificate(&directory);

        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let edge = TcpListener::bind("127.0.0.1:0").await.expect("edge");
        let edge_address = edge.local_addr().expect("edge address");
        let acceptor = tls_acceptor(
            certificate.to_str().expect("certificate path"),
            private_key.to_str().expect("key path"),
        )
        .expect("acceptor");

        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.expect("upstream read");
            assert_eq!(&buffer, b"ping");
            stream.write_all(b"pong").await.expect("upstream write");
        });
        tokio::spawn(async move {
            let (stream, _) = edge.accept().await.expect("edge accept");
            super::proxy_connection(acceptor, stream, upstream_address)
                .await
                .expect("proxy");
        });

        let mut tls = connect_edge(&certificate, edge_address).await;
        tls.write_all(b"ping").await.expect("client write");
        let mut buffer = [0_u8; 4];
        tls.read_exact(&mut buffer).await.expect("client read");
        assert_eq!(&buffer, b"pong");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn https_edge_proxies_an_http1_request_to_loopback() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ucr-https-edge-http-{stamp}"));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let (certificate, private_key) = mint_certificate(&directory);
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let edge = TcpListener::bind("127.0.0.1:0").await.expect("edge");
        let edge_address = edge.local_addr().expect("edge address");
        let acceptor = tls_acceptor(
            certificate.to_str().expect("certificate path"),
            private_key.to_str().expect("key path"),
        )
        .expect("acceptor");

        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut received = Vec::new();
            let mut byte = [0_u8; 1];
            while !received.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.expect("header byte");
                received.push(byte[0]);
                assert!(received.len() < 1024, "HTTP request stayed bounded");
            }
            assert!(received.starts_with(b"GET /healthz HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("upstream write");
        });
        tokio::spawn(async move {
            let (stream, _) = edge.accept().await.expect("edge accept");
            super::proxy_connection(acceptor, stream, upstream_address)
                .await
                .expect("proxy");
        });

        let mut tls = connect_edge(&certificate, edge_address).await;
        tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("client write");
        let mut response = [0_u8; 40];
        tls.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response[response.len() - 2..], b"ok");
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let _ = std::fs::remove_dir_all(directory);
    }
}

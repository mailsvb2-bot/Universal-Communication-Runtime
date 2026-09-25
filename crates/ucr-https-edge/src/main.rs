#![forbid(unsafe_code)]

use std::{fs, net::SocketAddr, path::Path, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};

const MAX_CERTIFICATE_BYTES: u64 = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ucr-https-edge: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
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

fn tls_acceptor(
    certificate_path: &str,
    private_key_path: &str,
) -> Result<tokio_rustls::TlsAcceptor, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| format!("build TLS server config: {error}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    bounded_file(path, MAX_CERTIFICATE_BYTES, "certificate")?;
    let mut reader = std::io::BufReader::new(
        fs::File::open(path).map_err(|error| format!("open TLS certificate: {error}"))?,
    );
    let certificates = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse TLS certificate: {error}"))?;
    if certificates.is_empty() {
        return Err("TLS certificate file contained no certificates".to_owned());
    }
    Ok(certificates)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    bounded_file(path, MAX_PRIVATE_KEY_BYTES, "private key")?;
    let mut reader = std::io::BufReader::new(
        fs::File::open(path).map_err(|error| format!("open TLS private key: {error}"))?,
    );
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

async fn proxy_connection(
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

    #[tokio::test]
    async fn https_edge_proxies_tls_bytes_to_loopback_upstream() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ucr-https-edge-{stamp}"));
        std::fs::create_dir_all(&directory).expect("temp directory");
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

        let mut certificates =
            std::io::BufReader::new(std::fs::File::open(&certificate).expect("cert"));
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
        let mut tls = connector
            .connect(ServerName::try_from("localhost").expect("server name"), tcp)
            .await
            .expect("tls handshake");
        tls.write_all(b"ping").await.expect("client write");
        let mut buffer = [0_u8; 4];
        tls.read_exact(&mut buffer).await.expect("client read");
        assert_eq!(&buffer, b"pong");
        let _ = std::fs::remove_dir_all(directory);
    }
}

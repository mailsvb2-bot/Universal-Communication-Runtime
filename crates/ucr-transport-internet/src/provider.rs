use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::Duration;

use prost::Message;
use sha2::{Digest, Sha256};
use ucr_core::{CanonicalTransportError, RouteCandidate, TransportHealth, TransportProvider};
use ucr_crypto::{Ciphertext, EstablishedSession};
use ucr_model::{CapabilityDescriptor, CapabilityMaturity, EndpointId, OpaqueId, TenantScope};

use crate::handshake::{
    InternetHandshakeError, InternetTransportIdentity, accept_handshake, initiate_handshake,
};
#[cfg(test)]
use crate::route::test_socket_addr;
use crate::route::{
    INTERNET_TCP_CAPABILITY, InternetRouteError, is_public_internet_ip, public_socket_addr,
};
use crate::wire::{
    HANDSHAKE_AAD_DOMAIN, INTERNET_CHUNK_PLAINTEXT_MAX, INTERNET_CHUNK_PLAINTEXT_MIN,
    INTERNET_ENVELOPE_MAX, INTERNET_NONCE_LEN, INTERNET_RECEIPT_AAD_DOMAIN,
    INTERNET_RECEIPT_ACCEPTED, INTERNET_RECEIPT_DUPLICATE, WireError, data_frame, decode_opaque,
    pb, pb_opaque, read_message_frame, receipt_frame, write_frame,
};

const ATTEMPT_ID_DOMAIN: &[u8] = b"UCR-INTERNET-ATTEMPT-ID-V2\0";
const HEALTHY: u8 = 0;
const DEGRADED: u8 = 1;
const UNAVAILABLE: u8 = 2;
const MAX_RETRY_ATTEMPTS: u32 = 16;
const MAX_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_BACKOFF: Duration = Duration::from_mins(1);
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternetTransportConfigError {
    Timeout,
    RetryPolicy,
    EnvelopeBudget,
    ChunkBudget,
    Identity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetTransportPolicy {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_envelope_len: usize,
    pub chunk_plaintext_len: usize,
}

impl Default for InternetTransportPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(10),
            max_attempts: 4,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            max_envelope_len: INTERNET_ENVELOPE_MAX,
            chunk_plaintext_len: INTERNET_CHUNK_PLAINTEXT_MAX,
        }
    }
}

impl InternetTransportPolicy {
    /// Validates bounded retry, timeout and memory budgets.
    ///
    /// # Errors
    /// Rejects zero/unbounded values and budgets outside canonical framing limits.
    pub fn validate(&self) -> Result<(), InternetTransportConfigError> {
        if self.connect_timeout.is_zero()
            || self.io_timeout.is_zero()
            || self.connect_timeout > MAX_TIMEOUT
            || self.io_timeout > MAX_TIMEOUT
        {
            return Err(InternetTransportConfigError::Timeout);
        }
        if self.max_attempts == 0
            || self.max_attempts > MAX_RETRY_ATTEMPTS
            || self.initial_backoff.is_zero()
            || self.initial_backoff > self.max_backoff
            || self.max_backoff > MAX_BACKOFF
        {
            return Err(InternetTransportConfigError::RetryPolicy);
        }
        if self.max_envelope_len == 0 || self.max_envelope_len > INTERNET_ENVELOPE_MAX {
            return Err(InternetTransportConfigError::EnvelopeBudget);
        }
        if self.chunk_plaintext_len < INTERNET_CHUNK_PLAINTEXT_MIN
            || self.chunk_plaintext_len > INTERNET_CHUNK_PLAINTEXT_MAX
            || self.chunk_plaintext_len > self.max_envelope_len
        {
            return Err(InternetTransportConfigError::ChunkBudget);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternetAcceptStatus {
    Accepted,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternetSinkError {
    Rejected,
    PolicyDenied,
    ResourceExhausted,
    Unavailable,
    Internal,
}

pub trait InternetEnvelopeSink: core::fmt::Debug + Send + Sync {
    /// Durably accepts or deduplicates one complete opaque encrypted envelope.
    ///
    /// Implementations own inbound persistence/idempotency. Returning `Accepted`
    /// or `Duplicate` authorizes only a transport receipt, never higher delivery proof.
    ///
    /// # Errors
    /// Returns a bounded canonical sink failure; no provider-specific secret may leak to the peer.
    fn accept_once(
        &self,
        scope: &TenantScope,
        source_endpoint_id: &EndpointId,
        attempt_id: &OpaqueId,
        encrypted_envelope: &[u8],
    ) -> Result<InternetAcceptStatus, InternetSinkError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InternetTransportMetrics {
    pub connection_attempts: u64,
    pub reconnects: u64,
    pub handshakes_established: u64,
    pub accepted_receipts: u64,
    pub duplicate_receipts: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Default)]
struct MetricsState {
    connection_attempts: AtomicU64,
    reconnects: AtomicU64,
    handshakes_established: AtomicU64,
    accepted_receipts: AtomicU64,
    duplicate_receipts: AtomicU64,
    failures: AtomicU64,
    timeouts: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl MetricsState {
    fn snapshot(&self) -> InternetTransportMetrics {
        InternetTransportMetrics {
            connection_attempts: self.connection_attempts.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            handshakes_established: self.handshakes_established.load(Ordering::Relaxed),
            accepted_receipts: self.accepted_receipts.load(Ordering::Relaxed),
            duplicate_receipts: self.duplicate_receipts.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct InternetTransportProvider {
    identity: Arc<InternetTransportIdentity>,
    policy: InternetTransportPolicy,
    metrics: Arc<MetricsState>,
    health: AtomicU8,
    allow_loopback_for_tests: bool,
}

impl InternetTransportProvider {
    /// Creates a public-Internet-only transport provider.
    ///
    /// # Errors
    /// Rejects invalid policy or local cryptographic identity before network use.
    pub fn new(
        identity: Arc<InternetTransportIdentity>,
        policy: InternetTransportPolicy,
    ) -> Result<Self, InternetTransportConfigError> {
        Self::new_inner(identity, policy, false)
    }

    fn new_inner(
        identity: Arc<InternetTransportIdentity>,
        policy: InternetTransportPolicy,
        allow_loopback_for_tests: bool,
    ) -> Result<Self, InternetTransportConfigError> {
        policy.validate()?;
        identity
            .validate()
            .map_err(|_| InternetTransportConfigError::Identity)?;
        Ok(Self {
            identity,
            policy,
            metrics: Arc::new(MetricsState::default()),
            health: AtomicU8::new(DEGRADED),
            allow_loopback_for_tests,
        })
    }

    #[cfg(test)]
    fn new_for_loopback_test(
        identity: Arc<InternetTransportIdentity>,
        policy: InternetTransportPolicy,
    ) -> Result<Self, InternetTransportConfigError> {
        Self::new_inner(identity, policy, true)
    }

    #[must_use]
    pub fn metrics(&self) -> InternetTransportMetrics {
        self.metrics.snapshot()
    }

    fn socket_addr(&self, route: &RouteCandidate) -> Result<SocketAddr, CanonicalTransportError> {
        #[cfg(test)]
        if self.allow_loopback_for_tests {
            return test_socket_addr(route).map_err(map_route_error);
        }
        let _ = self.allow_loopback_for_tests;
        public_socket_addr(route).map_err(map_route_error)
    }

    fn transmit_once(
        &self,
        socket: SocketAddr,
        route: &RouteCandidate,
        attempt_id: &OpaqueId,
        encrypted_envelope: &[u8],
    ) -> Result<InternetAcceptStatus, CanonicalTransportError> {
        let mut stream = TcpStream::connect_timeout(&socket, self.policy.connect_timeout)
            .map_err(|error| map_connect_error(&error))?;
        configure_stream(&stream, self.policy.io_timeout)?;
        let session = initiate_handshake(&mut stream, &self.identity, &route.endpoint_id)
            .map_err(map_handshake_error)?;
        self.metrics
            .handshakes_established
            .fetch_add(1, Ordering::Relaxed);
        send_envelope(
            &mut stream,
            &session,
            attempt_id,
            encrypted_envelope,
            self.policy.chunk_plaintext_len,
            &self.metrics,
        )?;
        receive_receipt(&mut stream, &session, attempt_id, &self.metrics)
    }
}

impl TransportProvider for InternetTransportProvider {
    fn capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: INTERNET_TCP_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }]
    }

    fn health(&self) -> TransportHealth {
        match self.health.load(Ordering::Relaxed) {
            HEALTHY => TransportHealth::Healthy,
            UNAVAILABLE => TransportHealth::Unavailable,
            _ => TransportHealth::Degraded,
        }
    }

    fn transmit(
        &self,
        scope: &TenantScope,
        route: &RouteCandidate,
        encrypted_envelope: &[u8],
    ) -> Result<(), CanonicalTransportError> {
        if *scope != self.identity.scope {
            return Err(CanonicalTransportError::PolicyDenied);
        }
        if encrypted_envelope.is_empty() || encrypted_envelope.len() > self.policy.max_envelope_len
        {
            return Err(CanonicalTransportError::Rejected);
        }
        let socket = self.socket_addr(route)?;
        let attempt_id = transport_attempt_id(
            scope,
            &self.identity.endpoint_id,
            &route.endpoint_id,
            encrypted_envelope,
        )
        .map_err(|_| CanonicalTransportError::Internal)?;
        let mut last_error = CanonicalTransportError::Unavailable;
        for attempt in 0..self.policy.max_attempts {
            self.metrics
                .connection_attempts
                .fetch_add(1, Ordering::Relaxed);
            if attempt > 0 {
                self.metrics.reconnects.fetch_add(1, Ordering::Relaxed);
            }
            match self.transmit_once(socket, route, &attempt_id, encrypted_envelope) {
                Ok(InternetAcceptStatus::Accepted) => {
                    self.metrics
                        .accepted_receipts
                        .fetch_add(1, Ordering::Relaxed);
                    self.health.store(HEALTHY, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(InternetAcceptStatus::Duplicate) => {
                    self.metrics
                        .duplicate_receipts
                        .fetch_add(1, Ordering::Relaxed);
                    self.health.store(HEALTHY, Ordering::Relaxed);
                    return Ok(());
                }
                Err(error) => {
                    last_error = error;
                    self.metrics.failures.fetch_add(1, Ordering::Relaxed);
                    if error == CanonicalTransportError::Timeout {
                        self.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    if !is_retryable(error) || attempt + 1 == self.policy.max_attempts {
                        break;
                    }
                    self.health.store(DEGRADED, Ordering::Relaxed);
                    std::thread::sleep(retry_delay(&self.policy, &attempt_id, attempt));
                }
            }
        }
        self.health.store(UNAVAILABLE, Ordering::Relaxed);
        Err(last_error)
    }
}

#[derive(Debug)]
pub struct InternetTransportServer {
    identity: Arc<InternetTransportIdentity>,
    policy: InternetTransportPolicy,
    sink: Arc<dyn InternetEnvelopeSink>,
    metrics: Arc<MetricsState>,
    allow_non_public_peer_for_tests: bool,
}

impl InternetTransportServer {
    /// Creates one exact-scope Internet transport server handler.
    ///
    /// Listener lifecycle/cancellation stay owned by the caller; no hidden runtime is created.
    ///
    /// # Errors
    /// Rejects invalid bounded transport policy or malformed local transport identity.
    pub fn new(
        identity: Arc<InternetTransportIdentity>,
        policy: InternetTransportPolicy,
        sink: Arc<dyn InternetEnvelopeSink>,
    ) -> Result<Self, InternetTransportConfigError> {
        Self::new_inner(identity, policy, sink, false)
    }

    fn new_inner(
        identity: Arc<InternetTransportIdentity>,
        policy: InternetTransportPolicy,
        sink: Arc<dyn InternetEnvelopeSink>,
        allow_non_public_peer_for_tests: bool,
    ) -> Result<Self, InternetTransportConfigError> {
        policy.validate()?;
        identity
            .validate()
            .map_err(|_| InternetTransportConfigError::Identity)?;
        Ok(Self {
            identity,
            policy,
            sink,
            metrics: Arc::new(MetricsState::default()),
            allow_non_public_peer_for_tests,
        })
    }

    #[cfg(test)]
    fn new_for_loopback_test(
        identity: Arc<InternetTransportIdentity>,
        policy: InternetTransportPolicy,
        sink: Arc<dyn InternetEnvelopeSink>,
    ) -> Result<Self, InternetTransportConfigError> {
        Self::new_inner(identity, policy, sink, true)
    }

    #[must_use]
    pub fn metrics(&self) -> InternetTransportMetrics {
        self.metrics.snapshot()
    }

    /// Accepts and processes exactly one Internet connection.
    ///
    /// # Errors
    /// Rejects non-public peers, malformed/authentication failures, timeout, and sink failures.
    pub fn accept_once(&self, listener: &TcpListener) -> Result<(), CanonicalTransportError> {
        let (mut stream, peer) = listener
            .accept()
            .map_err(|error| map_connect_error(&error))?;
        if !self.allow_non_public_peer_for_tests && !is_public_internet_ip(peer.ip()) {
            return Err(CanonicalTransportError::PolicyDenied);
        }
        self.serve_stream(&mut stream, true)
    }

    fn serve_stream(
        &self,
        stream: &mut TcpStream,
        emit_receipt: bool,
    ) -> Result<(), CanonicalTransportError> {
        configure_stream(stream, self.policy.io_timeout)?;
        self.metrics
            .connection_attempts
            .fetch_add(1, Ordering::Relaxed);
        let (session, source_endpoint_id) =
            accept_handshake(stream, &self.identity).map_err(map_handshake_error)?;
        self.metrics
            .handshakes_established
            .fetch_add(1, Ordering::Relaxed);
        let (attempt_id, envelope) = receive_envelope(
            stream,
            &session,
            self.policy.max_envelope_len,
            self.policy.chunk_plaintext_len,
            &self.metrics,
        )?;
        let expected_attempt = transport_attempt_id(
            &self.identity.scope,
            &source_endpoint_id,
            &self.identity.endpoint_id,
            &envelope,
        )
        .map_err(|_| CanonicalTransportError::Internal)?;
        if attempt_id != expected_attempt {
            return Err(CanonicalTransportError::Rejected);
        }
        let status = self
            .sink
            .accept_once(
                &self.identity.scope,
                &source_endpoint_id,
                &attempt_id,
                &envelope,
            )
            .map_err(map_sink_error)?;
        if emit_receipt {
            send_receipt(stream, &session, &attempt_id, status, &self.metrics)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn accept_once_for_loopback_test(
        &self,
        listener: &TcpListener,
        emit_receipt: bool,
    ) -> Result<(), CanonicalTransportError> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| map_connect_error(&error))?;
        self.serve_stream(&mut stream, emit_receipt)
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), CanonicalTransportError> {
    stream
        .set_nodelay(true)
        .map_err(|error| map_connect_error(&error))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| map_connect_error(&error))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| map_connect_error(&error))?;
    Ok(())
}

fn send_envelope(
    stream: &mut TcpStream,
    session: &EstablishedSession,
    attempt_id: &OpaqueId,
    envelope: &[u8],
    chunk_size: usize,
    metrics: &MetricsState,
) -> Result<(), CanonicalTransportError> {
    let chunk_count = envelope.len().div_ceil(chunk_size);
    let chunk_count = u32::try_from(chunk_count).map_err(|_| CanonicalTransportError::Rejected)?;
    for (index, chunk) in envelope.chunks(chunk_size).enumerate() {
        let chunk_index = u32::try_from(index).map_err(|_| CanonicalTransportError::Rejected)?;
        let aad = chunk_aad(session, attempt_id, chunk_index, chunk_count);
        let ciphertext = session
            .encrypt_outbound(chunk, &aad)
            .map_err(|_| CanonicalTransportError::Internal)?;
        let message = pb::InternetTransportData {
            attempt_id: Some(pb_opaque(attempt_id)),
            chunk_index,
            chunk_count,
            nonce: ciphertext.nonce.to_vec(),
            ciphertext: ciphertext.bytes,
        };
        let frame = data_frame(&message).map_err(map_wire_error)?;
        write_frame(stream, &frame).map_err(map_wire_error)?;
        metrics
            .bytes_sent
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
    }
    Ok(())
}

fn receive_envelope(
    stream: &mut TcpStream,
    session: &EstablishedSession,
    max_envelope_len: usize,
    max_chunk_plaintext_len: usize,
    metrics: &MetricsState,
) -> Result<(OpaqueId, Vec<u8>), CanonicalTransportError> {
    let mut attempt_id = None;
    let mut chunk_count = None;
    let mut next_index = 0_u32;
    let mut envelope = Vec::new();
    let max_chunks = max_envelope_len.div_ceil(INTERNET_CHUNK_PLAINTEXT_MIN);
    let max_chunks = u32::try_from(max_chunks).unwrap_or(u32::MAX);
    loop {
        let (frame, message) = read_message_frame::<pb::InternetTransportData>(
            stream,
            ucr_protocol::FrameKind::InternetData,
        )
        .map_err(map_wire_error)?;
        metrics
            .bytes_received
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        let current_attempt = decode_opaque(
            message
                .attempt_id
                .as_ref()
                .ok_or(CanonicalTransportError::MalformedResponse)?,
        )
        .map_err(map_wire_error)?;
        let total = message.chunk_count;
        if total == 0 || total > max_chunks {
            return Err(CanonicalTransportError::ResourceExhausted);
        }
        if message.chunk_index != next_index {
            return Err(CanonicalTransportError::MalformedResponse);
        }
        if attempt_id
            .as_ref()
            .is_some_and(|value| *value != current_attempt)
            || chunk_count.is_some_and(|value| value != total)
        {
            return Err(CanonicalTransportError::MalformedResponse);
        }
        if attempt_id.is_none() {
            attempt_id = Some(current_attempt.clone());
            chunk_count = Some(total);
        }
        let nonce: [u8; INTERNET_NONCE_LEN] = message
            .nonce
            .try_into()
            .map_err(|_| CanonicalTransportError::MalformedResponse)?;
        if message.ciphertext.len() > max_chunk_plaintext_len.saturating_add(16) {
            return Err(CanonicalTransportError::ResourceExhausted);
        }
        let aad = chunk_aad(session, &current_attempt, message.chunk_index, total);
        let plaintext = session
            .decrypt_inbound(
                &Ciphertext {
                    nonce,
                    bytes: message.ciphertext,
                },
                &aad,
            )
            .map_err(|_| CanonicalTransportError::MalformedResponse)?;
        if plaintext.is_empty()
            || plaintext.len() > max_chunk_plaintext_len
            || (message.chunk_index + 1 < total && plaintext.len() < INTERNET_CHUNK_PLAINTEXT_MIN)
            || envelope.len().saturating_add(plaintext.len()) > max_envelope_len
        {
            return Err(CanonicalTransportError::ResourceExhausted);
        }
        envelope.extend_from_slice(&plaintext);
        if message.chunk_index + 1 == total {
            break;
        }
        next_index = next_index
            .checked_add(1)
            .ok_or(CanonicalTransportError::ResourceExhausted)?;
    }
    let attempt_id = attempt_id.ok_or(CanonicalTransportError::MalformedResponse)?;
    if envelope.is_empty() {
        return Err(CanonicalTransportError::Rejected);
    }
    Ok((attempt_id, envelope))
}

fn send_receipt(
    stream: &mut TcpStream,
    session: &EstablishedSession,
    attempt_id: &OpaqueId,
    status: InternetAcceptStatus,
    metrics: &MetricsState,
) -> Result<(), CanonicalTransportError> {
    let status = match status {
        InternetAcceptStatus::Accepted => INTERNET_RECEIPT_ACCEPTED,
        InternetAcceptStatus::Duplicate => INTERNET_RECEIPT_DUPLICATE,
    };
    let plaintext = pb::InternetTransportReceiptPlaintext {
        attempt_id: Some(pb_opaque(attempt_id)),
        status,
    }
    .encode_to_vec();
    let aad = receipt_aad(session, attempt_id);
    let ciphertext = session
        .encrypt_outbound(&plaintext, &aad)
        .map_err(|_| CanonicalTransportError::Internal)?;
    let frame = receipt_frame(&pb::InternetTransportReceipt {
        attempt_id: Some(pb_opaque(attempt_id)),
        nonce: ciphertext.nonce.to_vec(),
        ciphertext: ciphertext.bytes,
    })
    .map_err(map_wire_error)?;
    write_frame(stream, &frame).map_err(map_wire_error)?;
    metrics
        .bytes_sent
        .fetch_add(frame.len() as u64, Ordering::Relaxed);
    Ok(())
}

fn receive_receipt(
    stream: &mut TcpStream,
    session: &EstablishedSession,
    expected_attempt_id: &OpaqueId,
    metrics: &MetricsState,
) -> Result<InternetAcceptStatus, CanonicalTransportError> {
    let (frame, receipt) = read_message_frame::<pb::InternetTransportReceipt>(
        stream,
        ucr_protocol::FrameKind::InternetReceipt,
    )
    .map_err(map_wire_error)?;
    metrics
        .bytes_received
        .fetch_add(frame.len() as u64, Ordering::Relaxed);
    let outer_attempt = decode_opaque(
        receipt
            .attempt_id
            .as_ref()
            .ok_or(CanonicalTransportError::MalformedResponse)?,
    )
    .map_err(map_wire_error)?;
    if outer_attempt != *expected_attempt_id {
        return Err(CanonicalTransportError::MalformedResponse);
    }
    let nonce: [u8; INTERNET_NONCE_LEN] = receipt
        .nonce
        .try_into()
        .map_err(|_| CanonicalTransportError::MalformedResponse)?;
    let aad = receipt_aad(session, expected_attempt_id);
    let plaintext = session
        .decrypt_inbound(
            &Ciphertext {
                nonce,
                bytes: receipt.ciphertext,
            },
            &aad,
        )
        .map_err(|_| CanonicalTransportError::MalformedResponse)?;
    let receipt = pb::InternetTransportReceiptPlaintext::decode(plaintext.as_slice())
        .map_err(|_| CanonicalTransportError::MalformedResponse)?;
    let inner_attempt = decode_opaque(
        receipt
            .attempt_id
            .as_ref()
            .ok_or(CanonicalTransportError::MalformedResponse)?,
    )
    .map_err(map_wire_error)?;
    if inner_attempt != *expected_attempt_id {
        return Err(CanonicalTransportError::MalformedResponse);
    }
    match receipt.status {
        INTERNET_RECEIPT_ACCEPTED => Ok(InternetAcceptStatus::Accepted),
        INTERNET_RECEIPT_DUPLICATE => Ok(InternetAcceptStatus::Duplicate),
        _ => Err(CanonicalTransportError::MalformedResponse),
    }
}

fn chunk_aad(
    session: &EstablishedSession,
    attempt_id: &OpaqueId,
    chunk_index: u32,
    chunk_count: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HANDSHAKE_AAD_DOMAIN.len() + 32 + 8 + OpaqueId::MAX_LEN + 8);
    aad.extend_from_slice(HANDSHAKE_AAD_DOMAIN);
    aad.extend_from_slice(session.transcript_binding().as_bytes());
    append_len_prefixed(&mut aad, attempt_id.as_wire_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad
}

fn receipt_aad(session: &EstablishedSession, attempt_id: &OpaqueId) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(INTERNET_RECEIPT_AAD_DOMAIN.len() + 32 + 8 + OpaqueId::MAX_LEN);
    aad.extend_from_slice(INTERNET_RECEIPT_AAD_DOMAIN);
    aad.extend_from_slice(session.transcript_binding().as_bytes());
    append_len_prefixed(&mut aad, attempt_id.as_wire_bytes());
    aad
}

fn append_len_prefixed(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn transport_attempt_id(
    scope: &TenantScope,
    source_endpoint_id: &EndpointId,
    destination_endpoint_id: &EndpointId,
    envelope: &[u8],
) -> Result<OpaqueId, ucr_model::OpaqueIdError> {
    let mut hasher = Sha256::new();
    hasher.update(ATTEMPT_ID_DOMAIN);
    hash_len_prefixed(&mut hasher, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hasher.update([1]);
            hash_len_prefixed(&mut hasher, namespace.as_opaque().as_wire_bytes());
        }
        None => hasher.update([0]),
    }
    hash_len_prefixed(&mut hasher, source_endpoint_id.as_opaque().as_wire_bytes());
    hash_len_prefixed(
        &mut hasher,
        destination_endpoint_id.as_opaque().as_wire_bytes(),
    );
    hash_len_prefixed(&mut hasher, envelope);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut token = String::with_capacity(68);
    token.push_str("it2-");
    for byte in digest {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    OpaqueId::new(token)
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn retry_delay(
    policy: &InternetTransportPolicy,
    attempt_id: &OpaqueId,
    retry_index: u32,
) -> Duration {
    let shift = retry_index.min(31);
    let factor = 1_u32 << shift;
    let exponential = policy
        .initial_backoff
        .saturating_mul(factor)
        .min(policy.max_backoff);
    let jitter_ceiling_ms = (exponential.as_millis() / 4).max(1);
    let mut hasher = Sha256::new();
    hasher.update(b"UCR-INTERNET-RETRY-JITTER-V1\0");
    hasher.update(attempt_id.as_wire_bytes());
    hasher.update(retry_index.to_be_bytes());
    let digest = hasher.finalize();
    let seed = u64::from_be_bytes(digest[..8].try_into().expect("fixed digest"));
    let ceiling = u64::try_from(jitter_ceiling_ms).unwrap_or(u64::MAX);
    let jitter = Duration::from_millis(seed % ceiling.saturating_add(1));
    exponential.saturating_add(jitter).min(policy.max_backoff)
}

fn is_retryable(error: CanonicalTransportError) -> bool {
    matches!(
        error,
        CanonicalTransportError::Unavailable
            | CanonicalTransportError::Timeout
            | CanonicalTransportError::Internal
    )
}

fn map_route_error(error: InternetRouteError) -> CanonicalTransportError {
    match error {
        InternetRouteError::UnsupportedCapability | InternetRouteError::UnsupportedScheme => {
            CanonicalTransportError::UnsupportedCapability
        }
        InternetRouteError::NonPublicInternetAddress => CanonicalTransportError::PolicyDenied,
        InternetRouteError::InvalidAddressEncoding
        | InternetRouteError::InvalidSocketAddress
        | InternetRouteError::ZeroPort => CanonicalTransportError::Rejected,
    }
}

fn map_connect_error(error: &std::io::Error) -> CanonicalTransportError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            CanonicalTransportError::Timeout
        }
        std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::AddrNotAvailable => CanonicalTransportError::Unavailable,
        _ => CanonicalTransportError::Internal,
    }
}

fn map_wire_error(error: WireError) -> CanonicalTransportError {
    match error {
        WireError::Io(std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {
            CanonicalTransportError::Timeout
        }
        WireError::Io(
            std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe,
        ) => CanonicalTransportError::Unavailable,
        WireError::PayloadTooLarge => CanonicalTransportError::ResourceExhausted,
        WireError::Io(_)
        | WireError::Frame
        | WireError::Encode
        | WireError::Decode
        | WireError::UnexpectedFrameKind
        | WireError::InvalidValue => CanonicalTransportError::MalformedResponse,
    }
}

fn map_handshake_error(error: InternetHandshakeError) -> CanonicalTransportError {
    match error {
        InternetHandshakeError::WireTimeout => CanonicalTransportError::Timeout,
        InternetHandshakeError::WireUnavailable => CanonicalTransportError::Unavailable,
        InternetHandshakeError::PeerEndpointMismatch
        | InternetHandshakeError::PeerDeviceMismatch
        | InternetHandshakeError::PeerKeyMismatch
        | InternetHandshakeError::PeerExpectation(_)
        | InternetHandshakeError::InvalidLocalIdentity => CanonicalTransportError::PolicyDenied,
        InternetHandshakeError::WireMalformed
        | InternetHandshakeError::Negotiation(_)
        | InternetHandshakeError::NegotiationMismatch
        | InternetHandshakeError::Crypto(_) => CanonicalTransportError::Rejected,
        InternetHandshakeError::LocalCrypto => CanonicalTransportError::Internal,
    }
}

fn map_sink_error(error: InternetSinkError) -> CanonicalTransportError {
    match error {
        InternetSinkError::Rejected => CanonicalTransportError::Rejected,
        InternetSinkError::PolicyDenied => CanonicalTransportError::PolicyDenied,
        InternetSinkError::ResourceExhausted => CanonicalTransportError::ResourceExhausted,
        InternetSinkError::Unavailable => CanonicalTransportError::Unavailable,
        InternetSinkError::Internal => CanonicalTransportError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::thread;

    use ucr_core::{RouteCandidate, TransportProvider};
    use ucr_crypto::{
        ReplayError, ReplayProtector, SigningKeyMaterial, TranscriptBinding,
        TrustedKeyResolutionError, TrustedSigningKeyResolver, VerifyingKeyBytes,
    };
    use ucr_model::{
        CryptoSuite, DeviceId, EndpointAddress, HandshakeNonce, KeyId, KeyPurpose, NamespaceId,
        PublicKeyDescriptor, TenantId,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, CapabilityRequirement, CryptoPolicy, KEY_FORMAT_VERSION,
        NegotiationPolicy, PeerHello, ProtocolVersion, SIGNATURE_ALGORITHM_ID, VersionPolicy,
        VersionRange,
    };

    use super::*;
    use crate::handshake::{
        InternetPeerExpectation, InternetPeerExpectationError, InternetPeerExpectationResolver,
    };
    use crate::route::INTERNET_TCP_SCHEME;

    #[derive(Debug)]
    struct StaticTrust {
        by_key: HashMap<(String, String), PublicKeyDescriptor>,
    }

    impl TrustedSigningKeyResolver for StaticTrust {
        fn resolve_active_signing_key(
            &self,
            _scope: &TenantScope,
            device_id: &DeviceId,
            _identity_id: Option<&ucr_model::IdentityId>,
            key_id: &KeyId,
        ) -> Result<PublicKeyDescriptor, TrustedKeyResolutionError> {
            self.by_key
                .get(&(
                    device_id.as_opaque().as_str().to_owned(),
                    key_id.as_opaque().as_str().to_owned(),
                ))
                .cloned()
                .ok_or(TrustedKeyResolutionError::NotTrusted)
        }
    }

    #[derive(Debug, Default)]
    struct MemoryReplay(Mutex<HashSet<([u8; 32], [u8; 32])>>);

    impl ReplayProtector for MemoryReplay {
        fn record_once(
            &self,
            peer_verifying_key: &VerifyingKeyBytes,
            binding: &TranscriptBinding,
        ) -> Result<(), ReplayError> {
            let mut seen = self.0.lock().map_err(|_| ReplayError::Internal)?;
            if !seen.insert((peer_verifying_key.0, *binding.as_bytes())) {
                return Err(ReplayError::Replayed);
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct StaticExpectation {
        by_endpoint: HashMap<String, InternetPeerExpectation>,
    }

    impl InternetPeerExpectationResolver for StaticExpectation {
        fn expected_peer(
            &self,
            _scope: &TenantScope,
            endpoint_id: &EndpointId,
        ) -> Result<InternetPeerExpectation, InternetPeerExpectationError> {
            self.by_endpoint
                .get(endpoint_id.as_opaque().as_str())
                .cloned()
                .ok_or(InternetPeerExpectationError::NotFound)
        }
    }

    #[derive(Debug, Default)]
    struct DedupSink {
        accepted: Mutex<HashMap<String, Vec<u8>>>,
        calls: AtomicU64,
    }

    impl InternetEnvelopeSink for DedupSink {
        fn accept_once(
            &self,
            _scope: &TenantScope,
            _source_endpoint_id: &EndpointId,
            attempt_id: &OpaqueId,
            encrypted_envelope: &[u8],
        ) -> Result<InternetAcceptStatus, InternetSinkError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut accepted = self
                .accepted
                .lock()
                .map_err(|_| InternetSinkError::Internal)?;
            match accepted.get(attempt_id.as_str()) {
                Some(existing) if existing == encrypted_envelope => {
                    Ok(InternetAcceptStatus::Duplicate)
                }
                Some(_) => Err(InternetSinkError::Rejected),
                None => {
                    accepted.insert(attempt_id.as_str().to_owned(), encrypted_envelope.to_vec());
                    Ok(InternetAcceptStatus::Accepted)
                }
            }
        }
    }

    struct PairFixture {
        client_identity: Arc<InternetTransportIdentity>,
        server_identity: Arc<InternetTransportIdentity>,
        client_endpoint: EndpointId,
        server_endpoint: EndpointId,
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-phase15")),
            namespace_id: Some(NamespaceId::from_opaque(oid("production"))),
        }
    }

    fn descriptor(
        key_id: &str,
        device_id: &str,
        signing: &SigningKeyMaterial,
    ) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id: KeyId::from_opaque(oid(key_id)),
            device_id: DeviceId::from_opaque(oid(device_id)),
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: signing.verifying_key().0.to_vec(),
        }
    }

    fn hello() -> PeerHello {
        PeerHello {
            supported_versions: vec![
                VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                    .expect("version"),
            ],
            supported_crypto_suites: vec![CryptoSuite::UcrV1],
            nonce: HandshakeNonce::new([1; 32]),
            capabilities: vec![CapabilityDescriptor {
                id: INTERNET_TCP_CAPABILITY.to_owned(),
                maturity: CapabilityMaturity::Prepared,
                extensions: Vec::new(),
            }],
            extensions: Vec::new(),
        }
    }

    fn negotiation_policy() -> NegotiationPolicy {
        NegotiationPolicy {
            version: VersionPolicy {
                minimum: ProtocolVersion::new(1, 0),
            },
            crypto: CryptoPolicy {
                preferred_suites: vec![CryptoSuite::UcrV1],
            },
            required_capabilities: vec![CapabilityRequirement {
                id: INTERNET_TCP_CAPABILITY.to_owned(),
                minimum: CapabilityMaturity::Prepared,
                allow_deprecated: false,
            }],
        }
    }

    fn fixture() -> PairFixture {
        fixture_with_server_signer(None)
    }

    fn fixture_with_server_signer(attacker: Option<Arc<SigningKeyMaterial>>) -> PairFixture {
        let client_signing = Arc::new(SigningKeyMaterial::generate().expect("client signing"));
        let trusted_server_signing =
            Arc::new(SigningKeyMaterial::generate().expect("server signing"));
        let actual_server_signing = attacker.unwrap_or_else(|| trusted_server_signing.clone());
        let client_descriptor = descriptor("key-client", "device-client", client_signing.as_ref());
        let trusted_server_descriptor = descriptor(
            "key-server",
            "device-server",
            trusted_server_signing.as_ref(),
        );
        let actual_server_descriptor = descriptor(
            "key-server",
            "device-server",
            actual_server_signing.as_ref(),
        );
        let client_endpoint = EndpointId::from_opaque(oid("endpoint-client"));
        let server_endpoint = EndpointId::from_opaque(oid("endpoint-server"));
        let trust = Arc::new(StaticTrust {
            by_key: HashMap::from([
                (
                    ("device-client".to_owned(), "key-client".to_owned()),
                    client_descriptor.clone(),
                ),
                (
                    ("device-server".to_owned(), "key-server".to_owned()),
                    trusted_server_descriptor,
                ),
            ]),
        });
        let expectations = Arc::new(StaticExpectation {
            by_endpoint: HashMap::from([
                (
                    "endpoint-client".to_owned(),
                    InternetPeerExpectation {
                        device_id: client_descriptor.device_id.clone(),
                        signing_key_id: Some(client_descriptor.key_id.clone()),
                    },
                ),
                (
                    "endpoint-server".to_owned(),
                    InternetPeerExpectation {
                        device_id: actual_server_descriptor.device_id.clone(),
                        signing_key_id: Some(actual_server_descriptor.key_id.clone()),
                    },
                ),
            ]),
        });
        let client_identity = Arc::new(InternetTransportIdentity {
            scope: scope(),
            endpoint_id: client_endpoint.clone(),
            hello_template: hello(),
            negotiation_policy: negotiation_policy(),
            signing_descriptor: client_descriptor,
            signing_key: client_signing,
            trusted_keys: trust.clone(),
            replay: Arc::new(MemoryReplay::default()),
            peer_expectations: expectations.clone(),
        });
        let server_identity = Arc::new(InternetTransportIdentity {
            scope: scope(),
            endpoint_id: server_endpoint.clone(),
            hello_template: hello(),
            negotiation_policy: negotiation_policy(),
            signing_descriptor: actual_server_descriptor,
            signing_key: actual_server_signing,
            trusted_keys: trust,
            replay: Arc::new(MemoryReplay::default()),
            peer_expectations: expectations,
        });
        PairFixture {
            client_identity,
            server_identity,
            client_endpoint,
            server_endpoint,
        }
    }

    fn fast_policy() -> InternetTransportPolicy {
        InternetTransportPolicy {
            connect_timeout: Duration::from_secs(1),
            io_timeout: Duration::from_secs(2),
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(4),
            max_envelope_len: INTERNET_ENVELOPE_MAX,
            chunk_plaintext_len: INTERNET_CHUNK_PLAINTEXT_MAX,
        }
    }

    fn route(endpoint: EndpointId, address: SocketAddr) -> RouteCandidate {
        RouteCandidate {
            endpoint_id: endpoint,
            transport_capability: INTERNET_TCP_CAPABILITY.to_owned(),
            address: EndpointAddress {
                scheme: INTERNET_TCP_SCHEME.to_owned(),
                value: address.to_string().into_bytes(),
            },
        }
    }

    #[test]
    fn authenticated_chunked_transport_round_trip_and_metrics() {
        let fixture = fixture();
        let sink = Arc::new(DedupSink::default());
        let server = InternetTransportServer::new_for_loopback_test(
            fixture.server_identity,
            fast_policy(),
            sink.clone(),
        )
        .expect("server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_thread = thread::spawn(move || {
            server
                .accept_once_for_loopback_test(&listener, true)
                .expect("serve");
        });
        let provider = InternetTransportProvider::new_for_loopback_test(
            fixture.client_identity,
            fast_policy(),
        )
        .expect("provider");
        let payload = vec![0x5a; INTERNET_CHUNK_PLAINTEXT_MAX + 17];
        provider
            .transmit(&scope(), &route(fixture.server_endpoint, address), &payload)
            .expect("transmit");
        server_thread.join().expect("server join");
        assert_eq!(sink.calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.health(), TransportHealth::Healthy);
        let metrics = provider.metrics();
        assert_eq!(metrics.connection_attempts, 1);
        assert_eq!(metrics.handshakes_established, 1);
        assert_eq!(metrics.accepted_receipts, 1);
        assert!(metrics.bytes_sent > payload.len() as u64);
    }

    #[test]
    fn lost_receipt_reconnects_with_same_attempt_and_deduplicates() {
        let fixture = fixture();
        let sink = Arc::new(DedupSink::default());
        let server = Arc::new(
            InternetTransportServer::new_for_loopback_test(
                fixture.server_identity,
                fast_policy(),
                sink.clone(),
            )
            .expect("server"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            server_clone
                .accept_once_for_loopback_test(&listener, false)
                .expect("first accepted without receipt");
            server_clone
                .accept_once_for_loopback_test(&listener, true)
                .expect("retry accepted with receipt");
        });
        let provider = InternetTransportProvider::new_for_loopback_test(
            fixture.client_identity,
            fast_policy(),
        )
        .expect("provider");
        provider
            .transmit(
                &scope(),
                &route(fixture.server_endpoint, address),
                b"opaque-e2ee-envelope",
            )
            .expect("reconnect transmit");
        server_thread.join().expect("server join");
        assert_eq!(sink.calls.load(Ordering::Relaxed), 2);
        assert_eq!(sink.accepted.lock().expect("sink").len(), 1);
        let metrics = provider.metrics();
        assert_eq!(metrics.connection_attempts, 2);
        assert_eq!(metrics.reconnects, 1);
        assert_eq!(metrics.duplicate_receipts, 1);
    }

    #[test]
    fn maximum_canonical_envelope_round_trip_remains_bounded() {
        let fixture = fixture();
        let sink = Arc::new(DedupSink::default());
        let server = InternetTransportServer::new_for_loopback_test(
            fixture.server_identity,
            fast_policy(),
            sink.clone(),
        )
        .expect("server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_thread = thread::spawn(move || {
            server
                .accept_once_for_loopback_test(&listener, true)
                .expect("serve max");
        });
        let provider = InternetTransportProvider::new_for_loopback_test(
            fixture.client_identity,
            fast_policy(),
        )
        .expect("provider");
        let payload = vec![0x7c; INTERNET_ENVELOPE_MAX];
        provider
            .transmit(&scope(), &route(fixture.server_endpoint, address), &payload)
            .expect("max transmit");
        server_thread.join().expect("server join");
        assert_eq!(sink.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            sink.accepted
                .lock()
                .expect("sink")
                .values()
                .next()
                .map(Vec::len),
            Some(INTERNET_ENVELOPE_MAX)
        );
    }

    #[test]
    fn public_provider_rejects_lan_loopback_and_scope_mismatch_before_connect() {
        let fixture = fixture();
        let provider = InternetTransportProvider::new(fixture.client_identity, fast_policy())
            .expect("provider");
        let loopback: SocketAddr = "127.0.0.1:4444".parse().expect("address");
        assert_eq!(
            provider.transmit(
                &scope(),
                &route(fixture.server_endpoint.clone(), loopback),
                b"opaque",
            ),
            Err(CanonicalTransportError::PolicyDenied)
        );
        let other_scope = TenantScope {
            tenant_id: TenantId::from_opaque(oid("other-tenant")),
            namespace_id: None,
        };
        let public: SocketAddr = "8.8.8.8:443".parse().expect("address");
        assert_eq!(
            provider.transmit(
                &other_scope,
                &route(fixture.server_endpoint, public),
                b"opaque",
            ),
            Err(CanonicalTransportError::PolicyDenied)
        );
        assert_eq!(provider.metrics().connection_attempts, 0);
    }

    #[test]
    fn deterministic_attempt_id_binds_scope_source_destination_and_envelope() {
        let source_a = EndpointId::from_opaque(oid("source-a"));
        let source_b = EndpointId::from_opaque(oid("source-b"));
        let destination_a = EndpointId::from_opaque(oid("destination-a"));
        let destination_b = EndpointId::from_opaque(oid("destination-b"));
        let first =
            transport_attempt_id(&scope(), &source_a, &destination_a, b"ciphertext").expect("id");
        let retry =
            transport_attempt_id(&scope(), &source_a, &destination_a, b"ciphertext").expect("id");
        assert_eq!(first, retry);
        assert_ne!(
            first,
            transport_attempt_id(&scope(), &source_b, &destination_a, b"ciphertext").expect("id")
        );
        assert_ne!(
            first,
            transport_attempt_id(&scope(), &source_a, &destination_b, b"ciphertext").expect("id")
        );
        assert_ne!(
            first,
            transport_attempt_id(&scope(), &source_a, &destination_a, b"other").expect("id")
        );
    }

    #[test]
    fn network_mitm_with_substituted_signing_key_fails_before_sink() {
        let attacker = Arc::new(SigningKeyMaterial::generate().expect("attacker"));
        let fixture = fixture_with_server_signer(Some(attacker));
        let sink = Arc::new(DedupSink::default());
        let server = InternetTransportServer::new_for_loopback_test(
            fixture.server_identity,
            fast_policy(),
            sink.clone(),
        )
        .expect("server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_thread =
            thread::spawn(move || server.accept_once_for_loopback_test(&listener, true));
        let mut one_attempt = fast_policy();
        one_attempt.max_attempts = 1;
        let provider =
            InternetTransportProvider::new_for_loopback_test(fixture.client_identity, one_attempt)
                .expect("provider");
        assert_eq!(
            provider.transmit(
                &scope(),
                &route(fixture.server_endpoint, address),
                b"opaque",
            ),
            Err(CanonicalTransportError::Rejected)
        );
        let _ = server_thread.join().expect("server join");
        assert_eq!(sink.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn authenticated_peer_cannot_force_unbounded_chunk_reassembly() {
        let fixture = fixture();
        let sink = Arc::new(DedupSink::default());
        let server = InternetTransportServer::new_for_loopback_test(
            fixture.server_identity,
            fast_policy(),
            sink.clone(),
        )
        .expect("server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_thread =
            thread::spawn(move || server.accept_once_for_loopback_test(&listener, true));
        let mut stream = TcpStream::connect(address).expect("connect");
        configure_stream(&stream, Duration::from_secs(2)).expect("configure");
        let session = initiate_handshake(
            &mut stream,
            &fixture.client_identity,
            &fixture.server_endpoint,
        )
        .expect("handshake");
        let attempt = transport_attempt_id(
            &scope(),
            &fixture.client_endpoint,
            &fixture.server_endpoint,
            b"x",
        )
        .expect("attempt");
        let aad = chunk_aad(&session, &attempt, 0, u32::MAX);
        let encrypted = session.encrypt_outbound(b"x", &aad).expect("encrypt");
        let frame = data_frame(&pb::InternetTransportData {
            attempt_id: Some(pb_opaque(&attempt)),
            chunk_index: 0,
            chunk_count: u32::MAX,
            nonce: encrypted.nonce.to_vec(),
            ciphertext: encrypted.bytes,
        })
        .expect("frame");
        write_frame(&mut stream, &frame).expect("write");
        assert_eq!(
            server_thread.join().expect("server join"),
            Err(CanonicalTransportError::ResourceExhausted)
        );
        assert_eq!(sink.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn authenticated_peer_reordered_chunk_is_rejected_before_sink() {
        let fixture = fixture();
        let sink = Arc::new(DedupSink::default());
        let server = InternetTransportServer::new_for_loopback_test(
            fixture.server_identity,
            fast_policy(),
            sink.clone(),
        )
        .expect("server");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_thread =
            thread::spawn(move || server.accept_once_for_loopback_test(&listener, true));
        let mut stream = TcpStream::connect(address).expect("connect");
        configure_stream(&stream, Duration::from_secs(2)).expect("configure");
        let session = initiate_handshake(
            &mut stream,
            &fixture.client_identity,
            &fixture.server_endpoint,
        )
        .expect("handshake");
        let attempt = transport_attempt_id(
            &scope(),
            &fixture.client_endpoint,
            &fixture.server_endpoint,
            b"payload",
        )
        .expect("attempt");
        let aad = chunk_aad(&session, &attempt, 1, 2);
        let encrypted = session.encrypt_outbound(b"payload", &aad).expect("encrypt");
        let frame = data_frame(&pb::InternetTransportData {
            attempt_id: Some(pb_opaque(&attempt)),
            chunk_index: 1,
            chunk_count: 2,
            nonce: encrypted.nonce.to_vec(),
            ciphertext: encrypted.bytes,
        })
        .expect("frame");
        write_frame(&mut stream, &frame).expect("write");
        assert_eq!(
            server_thread.join().expect("server join"),
            Err(CanonicalTransportError::MalformedResponse)
        );
        assert_eq!(sink.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn tampered_encrypted_receipt_fails_closed() {
        let fixture = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server_identity = fixture.server_identity.clone();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            configure_stream(&stream, Duration::from_secs(2)).expect("configure");
            let (session, source_endpoint) =
                accept_handshake(&mut stream, &server_identity).expect("handshake");
            let (attempt, envelope) = receive_envelope(
                &mut stream,
                &session,
                INTERNET_ENVELOPE_MAX,
                INTERNET_CHUNK_PLAINTEXT_MAX,
                &MetricsState::default(),
            )
            .expect("envelope");
            let expected = transport_attempt_id(
                &server_identity.scope,
                &source_endpoint,
                &server_identity.endpoint_id,
                &envelope,
            )
            .expect("attempt");
            assert_eq!(attempt, expected);
            let plaintext = pb::InternetTransportReceiptPlaintext {
                attempt_id: Some(pb_opaque(&attempt)),
                status: INTERNET_RECEIPT_ACCEPTED,
            }
            .encode_to_vec();
            let aad = receipt_aad(&session, &attempt);
            let mut encrypted = session.encrypt_outbound(&plaintext, &aad).expect("encrypt");
            encrypted.bytes[0] ^= 0x80;
            let frame = receipt_frame(&pb::InternetTransportReceipt {
                attempt_id: Some(pb_opaque(&attempt)),
                nonce: encrypted.nonce.to_vec(),
                ciphertext: encrypted.bytes,
            })
            .expect("frame");
            write_frame(&mut stream, &frame).expect("write");
        });
        let mut one_attempt = fast_policy();
        one_attempt.max_attempts = 1;
        let provider =
            InternetTransportProvider::new_for_loopback_test(fixture.client_identity, one_attempt)
                .expect("provider");
        assert_eq!(
            provider.transmit(
                &scope(),
                &route(fixture.server_endpoint, address),
                b"receipt-tamper",
            ),
            Err(CanonicalTransportError::MalformedResponse)
        );
        server_thread.join().expect("server join");
    }
}

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use bytes::Bytes;
use tokio::sync::mpsc;
use webrtc::{data_channel::RTCDataChannel, peer_connection::RTCPeerConnection};

use ucr_model::{SessionId, SfuForwardEnvelope};
use ucr_protocol::{
    MAX_SFU_FORWARD_WIRE_BYTES, SfuForwardWireError, SfuProtocolError, decode_sfu_forward_envelope,
    encode_sfu_forward_envelope,
};

pub const WEBRTC_E2EE_DATA_CHANNEL_LABEL: &str = "ucr.e2ee.media.v1";
pub const LIVE_WEBRTC_E2EE_INGRESS_CAPACITY: usize = 128;
pub const MAX_WEBRTC_E2EE_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WEBRTC_E2EE_WIRE_BYTES: usize = MAX_SFU_FORWARD_WIRE_BYTES;
pub const MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES: usize = 16_000;
const WEBRTC_E2EE_CHUNK_MAGIC: &[u8; 8] = b"UCRCHK01";
const WEBRTC_E2EE_CHUNK_HEADER_BYTES: usize = 24;
const WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES: usize =
    MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES - WEBRTC_E2EE_CHUNK_HEADER_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcE2eeIngressFrame {
    pub session_id: SessionId,
    pub envelope: SfuForwardEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingWebRtcE2eeMessage {
    message_id: u64,
    total_length: usize,
    chunk_count: u16,
    next_chunk_index: u16,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct WebRtcE2eeReassembler {
    pending: Option<PendingWebRtcE2eeMessage>,
}

impl WebRtcE2eeReassembler {
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: None }
    }

    /// Accepts one ordered reliable `DataChannel` chunk and returns a complete canonical envelope
    /// only after the final bounded chunk arrives.
    ///
    /// # Errors
    /// Rejects malformed/out-of-order/oversized chunk sequences and clears partial state.
    pub fn push_chunk(
        &mut self,
        chunk: &[u8],
    ) -> Result<Option<SfuForwardEnvelope>, WebRtcE2eeWireError> {
        let result = self.push_chunk_impl(chunk);
        if result.is_err() {
            self.pending = None;
        }
        result
    }

    fn push_chunk_impl(
        &mut self,
        chunk: &[u8],
    ) -> Result<Option<SfuForwardEnvelope>, WebRtcE2eeWireError> {
        if chunk.len() > MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES
            || chunk.len() < WEBRTC_E2EE_CHUNK_HEADER_BYTES
        {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        let mut reader = WireReader::new(chunk);
        if reader.take(WEBRTC_E2EE_CHUNK_MAGIC.len())? != WEBRTC_E2EE_CHUNK_MAGIC {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        let message_id = reader.u64()?;
        let chunk_index = reader.u16()?;
        let chunk_count = reader.u16()?;
        let total_length =
            usize::try_from(reader.u32()?).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
        if chunk_count == 0
            || chunk_index >= chunk_count
            || total_length == 0
            || total_length > MAX_WEBRTC_E2EE_WIRE_BYTES
        {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        let payload = reader.take(chunk.len().saturating_sub(reader.cursor))?;
        if payload.len() > WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES {
            return Err(WebRtcE2eeWireError::TooLarge);
        }

        if chunk_index == 0 {
            if self.pending.is_some() {
                return Err(WebRtcE2eeWireError::Malformed);
            }
            self.pending = Some(PendingWebRtcE2eeMessage {
                message_id,
                total_length,
                chunk_count,
                next_chunk_index: 0,
                bytes: Vec::with_capacity(total_length),
            });
        }
        let pending = self
            .pending
            .as_mut()
            .ok_or(WebRtcE2eeWireError::Malformed)?;
        if pending.message_id != message_id
            || pending.total_length != total_length
            || pending.chunk_count != chunk_count
            || pending.next_chunk_index != chunk_index
        {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        let new_length = pending
            .bytes
            .len()
            .checked_add(payload.len())
            .ok_or(WebRtcE2eeWireError::TooLarge)?;
        if new_length > pending.total_length {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        pending.bytes.extend_from_slice(payload);
        pending.next_chunk_index = pending
            .next_chunk_index
            .checked_add(1)
            .ok_or(WebRtcE2eeWireError::Malformed)?;

        if pending.next_chunk_index != pending.chunk_count {
            return Ok(None);
        }
        let completed = self.pending.take().ok_or(WebRtcE2eeWireError::Malformed)?;
        if completed.bytes.len() != completed.total_length {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        decode_webrtc_e2ee_envelope(&completed.bytes).map(Some)
    }
}

pub(crate) struct LiveWebRtcE2eeChannel {
    channel: Arc<RTCDataChannel>,
    next_message_id: u64,
    /// Item C2: optional unordered/no-retransmit channel. Used for sending
    /// only after the peer proved v2 support by sending a valid v2 chunk;
    /// until then (or forever, for v1-only peers) the reliable v1 channel is
    /// used — that is the version negotiation and fallback.
    unordered: Option<UnorderedE2eeChannel>,
}

struct UnorderedE2eeChannel {
    channel: Arc<RTCDataChannel>,
    peer_speaks_v2: Arc<AtomicBool>,
    keyframe_wanted: Arc<AtomicBool>,
}

impl LiveWebRtcE2eeChannel {
    /// Returns (and clears) a pending request for a keyframe caused by an
    /// unrecoverable loss on the unordered channel.
    #[allow(dead_code)] // Consumed once the media source path is wired.
    pub(crate) fn take_keyframe_request(&self) -> bool {
        self.unordered
            .as_ref()
            .is_some_and(|u| u.keyframe_wanted.swap(false, Ordering::SeqCst))
    }
}

impl LiveWebRtcE2eeChannel {
    pub(crate) async fn send(
        &mut self,
        envelope: &SfuForwardEnvelope,
        deadline: Instant,
    ) -> Result<(), crate::WebRtcProviderError> {
        let message_id = self.next_message_id;
        self.next_message_id = self
            .next_message_id
            .checked_add(1)
            .ok_or(crate::WebRtcProviderError::CapacityExceeded)?;
        let (channel, chunks) = match &self.unordered {
            Some(unordered) if unordered.peer_speaks_v2.load(Ordering::SeqCst) => (
                &unordered.channel,
                encode_webrtc_e2ee_chunks_v2(envelope, message_id)
                    .map_err(|_| crate::WebRtcProviderError::Internal)?,
            ),
            _ => (
                &self.channel,
                encode_webrtc_e2ee_chunks(envelope, message_id)
                    .map_err(|_| crate::WebRtcProviderError::Internal)?,
            ),
        };
        // This channel is driven by the single canonical WebRTC worker.
        // Awaiting a stale/disconnected DataChannel without a deadline blocks
        // EVERY later Create, ICE and Close operation in that worker.
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(crate::WebRtcProviderError::TemporarilyUnavailable)?
            .min(std::time::Duration::from_millis(250));
        let buffered = tokio::time::timeout(remaining, channel.buffered_amount())
            .await
            .map_err(|_| crate::WebRtcProviderError::TemporarilyUnavailable)?;
        if buffered > MAX_WEBRTC_E2EE_BUFFERED_BYTES {
            return Err(crate::WebRtcProviderError::CapacityExceeded);
        }
        for chunk in chunks {
            if Instant::now() >= deadline {
                return Err(crate::WebRtcProviderError::TemporarilyUnavailable);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(crate::WebRtcProviderError::TemporarilyUnavailable)?
                .min(std::time::Duration::from_millis(250));
            tokio::time::timeout(remaining, channel.send(&Bytes::from(chunk)))
                .await
                .map_err(|_| crate::WebRtcProviderError::TemporarilyUnavailable)?
                .map_err(|_| crate::WebRtcProviderError::TemporarilyUnavailable)?;
        }
        Ok(())
    }
}

pub(crate) async fn create_live_e2ee_data_channel(
    peer_connection: &RTCPeerConnection,
    session_id: &SessionId,
    ingress_tx: mpsc::Sender<WebRtcE2eeIngressFrame>,
) -> Result<LiveWebRtcE2eeChannel, crate::WebRtcProviderError> {
    let ingress_tx_v2 = ingress_tx.clone();
    let channel = peer_connection
        .create_data_channel(WEBRTC_E2EE_DATA_CHANNEL_LABEL, None)
        .await
        .map_err(|_| crate::WebRtcProviderError::Internal)?;
    let reassembler = Arc::new(tokio::sync::Mutex::new(WebRtcE2eeReassembler::new()));
    let callback_reassembler = Arc::clone(&reassembler);
    let callback_session_id = session_id.clone();
    channel.on_message(Box::new(move |message| {
        let reassembler = Arc::clone(&callback_reassembler);
        let ingress_tx = ingress_tx.clone();
        let session_id = callback_session_id.clone();
        Box::pin(async move {
            if message.is_string {
                return;
            }
            let decoded = {
                let mut reassembler = reassembler.lock().await;
                reassembler.push_chunk(&message.data)
            };
            if let Ok(Some(envelope)) = decoded {
                let _ = ingress_tx.try_send(WebRtcE2eeIngressFrame {
                    session_id,
                    envelope,
                });
            }
        })
    }));
    let unordered = if unordered_e2ee_enabled_from_env() {
        Some(create_unordered_channel(peer_connection, session_id, ingress_tx_v2).await?)
    } else {
        None
    };
    Ok(LiveWebRtcE2eeChannel {
        channel,
        next_message_id: 1,
        unordered,
    })
}

/// `UCR_WEBRTC_E2EE_UNORDERED=1` (default off) additionally offers the
/// unordered, `maxRetransmits=0` v2 channel.
#[must_use]
pub fn unordered_e2ee_enabled_from_env() -> bool {
    std::env::var("UCR_WEBRTC_E2EE_UNORDERED").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "on"
        )
    })
}

async fn create_unordered_channel(
    peer_connection: &RTCPeerConnection,
    session_id: &SessionId,
    ingress_tx: mpsc::Sender<WebRtcE2eeIngressFrame>,
) -> Result<UnorderedE2eeChannel, crate::WebRtcProviderError> {
    let init = webrtc::data_channel::data_channel_init::RTCDataChannelInit {
        ordered: Some(false),
        max_retransmits: Some(0),
        ..Default::default()
    };
    let channel = peer_connection
        .create_data_channel(WEBRTC_E2EE_UNORDERED_DATA_CHANNEL_LABEL, Some(init))
        .await
        .map_err(|_| crate::WebRtcProviderError::Internal)?;
    let peer_speaks_v2 = Arc::new(AtomicBool::new(false));
    let keyframe_wanted = Arc::new(AtomicBool::new(false));
    let reassembler = Arc::new(tokio::sync::Mutex::new(WebRtcE2eeLossyReassembler::new()));
    let (cb_v2, cb_key, cb_session) = (
        Arc::clone(&peer_speaks_v2),
        Arc::clone(&keyframe_wanted),
        session_id.clone(),
    );
    channel.on_message(Box::new(move |message| {
        let reassembler = Arc::clone(&reassembler);
        let ingress_tx = ingress_tx.clone();
        let session_id = cb_session.clone();
        let (peer_speaks_v2, keyframe_wanted) = (Arc::clone(&cb_v2), Arc::clone(&cb_key));
        Box::pin(async move {
            if message.is_string {
                return;
            }
            let (decoded, wants_keyframe) = {
                let mut reassembler = reassembler.lock().await;
                let decoded = reassembler.push_chunk(&message.data);
                (decoded, reassembler.take_keyframe_request())
            };
            if wants_keyframe {
                keyframe_wanted.store(true, Ordering::SeqCst);
            }
            match decoded {
                Ok(Some(envelope)) => {
                    peer_speaks_v2.store(true, Ordering::SeqCst);
                    let _ = ingress_tx.try_send(WebRtcE2eeIngressFrame {
                        session_id,
                        envelope,
                    });
                }
                Ok(None) => peer_speaks_v2.store(true, Ordering::SeqCst),
                Err(_) => {}
            }
        })
    }));
    Ok(UnorderedE2eeChannel {
        channel,
        peer_speaks_v2,
        keyframe_wanted,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcE2eeWireError {
    TooLarge,
    Malformed,
    UnsupportedVersion,
    InvalidEnvelope(SfuProtocolError),
}

impl From<SfuForwardWireError> for WebRtcE2eeWireError {
    fn from(error: SfuForwardWireError) -> Self {
        match error {
            SfuForwardWireError::TooLarge => Self::TooLarge,
            SfuForwardWireError::Malformed => Self::Malformed,
            SfuForwardWireError::UnsupportedVersion => Self::UnsupportedVersion,
            SfuForwardWireError::InvalidEnvelope(error) => Self::InvalidEnvelope(error),
        }
    }
}

/// Encodes one canonical SFU ciphertext envelope using the protocol-owned wire codec.
///
/// # Errors
/// Returns protocol validation or bounded-wire failures without exposing endpoint key material.
pub fn encode_webrtc_e2ee_envelope(
    envelope: &SfuForwardEnvelope,
) -> Result<Vec<u8>, WebRtcE2eeWireError> {
    encode_sfu_forward_envelope(envelope).map_err(Into::into)
}

/// Splits one canonical encrypted SFU envelope into ordered `DataChannel` messages below the
/// WebRTC-rs/browser per-message compatibility ceiling.
///
/// # Errors
/// Rejects an invalid envelope, impossible message identifier arithmetic, or excessive chunk count.
pub fn encode_webrtc_e2ee_chunks(
    envelope: &SfuForwardEnvelope,
    message_id: u64,
) -> Result<Vec<Vec<u8>>, WebRtcE2eeWireError> {
    let wire = encode_webrtc_e2ee_envelope(envelope)?;
    let chunk_count_usize = wire.len().div_ceil(WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES);
    let chunk_count =
        u16::try_from(chunk_count_usize).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
    let total_length = u32::try_from(wire.len()).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
    let mut chunks = Vec::with_capacity(chunk_count_usize);
    for (index, payload) in wire.chunks(WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES).enumerate() {
        let chunk_index = u16::try_from(index).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
        let mut chunk = Vec::with_capacity(WEBRTC_E2EE_CHUNK_HEADER_BYTES + payload.len());
        chunk.extend_from_slice(WEBRTC_E2EE_CHUNK_MAGIC);
        chunk.extend_from_slice(&message_id.to_be_bytes());
        chunk.extend_from_slice(&chunk_index.to_be_bytes());
        chunk.extend_from_slice(&chunk_count.to_be_bytes());
        chunk.extend_from_slice(&total_length.to_be_bytes());
        chunk.extend_from_slice(payload);
        if chunk.len() > MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES {
            return Err(WebRtcE2eeWireError::TooLarge);
        }
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// Decodes one reassembled WebRTC message through the protocol-owned SFU wire codec.
///
/// # Errors
/// Rejects oversized, malformed, unknown-version, trailing-byte or non-canonical ciphertext input.
pub fn decode_webrtc_e2ee_envelope(
    bytes: &[u8],
) -> Result<SfuForwardEnvelope, WebRtcE2eeWireError> {
    decode_sfu_forward_envelope(bytes).map_err(Into::into)
}

/// Item C2 v2 chunk format for the unordered, no-retransmit channel:
/// `UCRCHK02 | seq u64 | index u16 | count u16 | total u32 | flags u8 | payload`.
/// `flags` bit 0 = keyframe. Chunks may arrive in any order or not at all.
pub const WEBRTC_E2EE_UNORDERED_DATA_CHANNEL_LABEL: &str = "ucr.e2ee.media.v2";
const WEBRTC_E2EE_CHUNK_MAGIC_V2: &[u8; 8] = b"UCRCHK02";
const WEBRTC_E2EE_CHUNK_HEADER_BYTES_V2: usize = 25;
const WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES_V2: usize =
    MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES - WEBRTC_E2EE_CHUNK_HEADER_BYTES_V2;
/// Messages concurrently under reassembly; older incomplete ones are lost.
const WEBRTC_E2EE_LOSSY_WINDOW: usize = 4;
const WEBRTC_E2EE_FLAG_KEYFRAME: u8 = 1;

/// Splits an envelope into v2 chunks carrying sequence, keyframe flag and
/// fragmentation metadata.
///
/// # Errors
/// Rejects an invalid envelope or excessive chunk count.
pub fn encode_webrtc_e2ee_chunks_v2(
    envelope: &SfuForwardEnvelope,
    sequence: u64,
) -> Result<Vec<Vec<u8>>, WebRtcE2eeWireError> {
    let wire = encode_webrtc_e2ee_envelope(envelope)?;
    let chunk_count = u16::try_from(wire.len().div_ceil(WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES_V2))
        .map_err(|_| WebRtcE2eeWireError::TooLarge)?;
    let total_length = u32::try_from(wire.len()).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
    let flags = if envelope.frame.header.keyframe {
        WEBRTC_E2EE_FLAG_KEYFRAME
    } else {
        0
    };
    wire.chunks(WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES_V2)
        .enumerate()
        .map(|(index, payload)| {
            let index = u16::try_from(index).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
            let mut chunk = Vec::with_capacity(WEBRTC_E2EE_CHUNK_HEADER_BYTES_V2 + payload.len());
            chunk.extend_from_slice(WEBRTC_E2EE_CHUNK_MAGIC_V2);
            chunk.extend_from_slice(&sequence.to_be_bytes());
            chunk.extend_from_slice(&index.to_be_bytes());
            chunk.extend_from_slice(&chunk_count.to_be_bytes());
            chunk.extend_from_slice(&total_length.to_be_bytes());
            chunk.push(flags);
            chunk.extend_from_slice(payload);
            Ok(chunk)
        })
        .collect()
}

#[derive(Debug)]
struct LossyPending {
    sequence: u64,
    total_length: usize,
    keyframe: bool,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
}

/// Reassembles v2 chunks arriving unordered and with loss. A message that
/// can no longer complete (evicted from the bounded window or overtaken by a
/// completed newer one) is counted as lost and raises a keyframe request
/// that stays pending until a keyframe is delivered.
#[derive(Debug, Default)]
pub struct WebRtcE2eeLossyReassembler {
    pending: Vec<LossyPending>,
    last_delivered: Option<u64>,
    keyframe_needed: bool,
    keyframe_request: bool,
    lost: u64,
}

impl WebRtcE2eeLossyReassembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of messages known to be lost.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))] // Diagnostics hook; read by tests.
    pub const fn lost(&self) -> u64 {
        self.lost
    }

    /// Returns (and clears) a new keyframe request.
    pub fn take_keyframe_request(&mut self) -> bool {
        std::mem::take(&mut self.keyframe_request)
    }

    fn mark_lost(&mut self, count: u64) {
        if count > 0 {
            self.lost = self.lost.saturating_add(count);
            if !self.keyframe_needed {
                self.keyframe_request = true;
            }
            self.keyframe_needed = true;
        }
    }

    /// Accepts one v2 chunk in any order.
    ///
    /// # Errors
    /// Rejects malformed or oversized chunks (the chunk is ignored; other
    /// in-flight messages are kept).
    pub fn push_chunk(
        &mut self,
        chunk: &[u8],
    ) -> Result<Option<SfuForwardEnvelope>, WebRtcE2eeWireError> {
        if chunk.len() > MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES
            || chunk.len() <= WEBRTC_E2EE_CHUNK_HEADER_BYTES_V2
        {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        let mut reader = WireReader::new(chunk);
        if reader.take(WEBRTC_E2EE_CHUNK_MAGIC_V2.len())? != WEBRTC_E2EE_CHUNK_MAGIC_V2 {
            return Err(WebRtcE2eeWireError::UnsupportedVersion);
        }
        let sequence = reader.u64()?;
        let index = usize::from(reader.u16()?);
        let count = usize::from(reader.u16()?);
        let total_length =
            usize::try_from(reader.u32()?).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
        let flags = reader.take(1)?[0];
        let payload = &chunk[reader.cursor..];
        if count == 0
            || index >= count
            || total_length == 0
            || total_length > MAX_WEBRTC_E2EE_WIRE_BYTES
            || count != total_length.div_ceil(WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES_V2)
            || flags & !WEBRTC_E2EE_FLAG_KEYFRAME != 0
        {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        let expected = if index + 1 == count {
            total_length - index * WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES_V2
        } else {
            WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES_V2
        };
        if payload.len() != expected {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        if self.last_delivered.is_some_and(|last| sequence <= last) {
            return Ok(None); // Late duplicate / straggler of a resolved message.
        }
        let position =
            if let Some(position) = self.pending.iter().position(|p| p.sequence == sequence) {
                position
            } else {
                if self.pending.len() == WEBRTC_E2EE_LOSSY_WINDOW {
                    let oldest = (0..self.pending.len())
                        .min_by_key(|&i| self.pending[i].sequence)
                        .unwrap_or(0);
                    if self.pending[oldest].sequence > sequence {
                        return Ok(None); // Older than everything in flight: already lost.
                    }
                    self.pending.swap_remove(oldest);
                    self.mark_lost(1);
                }
                self.pending.push(LossyPending {
                    sequence,
                    total_length,
                    keyframe: flags & WEBRTC_E2EE_FLAG_KEYFRAME != 0,
                    parts: vec![None; count],
                    received: 0,
                });
                self.pending.len() - 1
            };
        let entry = &mut self.pending[position];
        if entry.total_length != total_length || entry.parts.len() != count {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        if entry.parts[index].is_some() {
            return Ok(None);
        }
        entry.parts[index] = Some(payload.to_vec());
        entry.received += 1;
        if entry.received != count {
            return Ok(None);
        }
        let done = self.pending.swap_remove(position);
        let before = self.pending.len();
        self.pending.retain(|p| p.sequence > sequence);
        let skipped_gap = self
            .last_delivered
            .map_or(0, |last| sequence.saturating_sub(last).saturating_sub(1));
        let dropped_pending = u64::try_from(before - self.pending.len()).unwrap_or(u64::MAX);
        // Every sequence between the previous delivery and this one is gone.
        self.mark_lost(skipped_gap.max(dropped_pending));
        self.last_delivered = Some(sequence);
        if done.keyframe {
            self.keyframe_needed = false;
            self.keyframe_request = false;
        }
        let bytes: Vec<u8> = done.parts.into_iter().flatten().flatten().collect();
        decode_webrtc_e2ee_envelope(&bytes).map(Some)
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> WireReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WebRtcE2eeWireError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(WebRtcE2eeWireError::Malformed)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(WebRtcE2eeWireError::Malformed)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WebRtcE2eeWireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WebRtcE2eeWireError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, WebRtcE2eeWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WebRtcE2eeWireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WebRtcE2eeWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{
        CallId, CryptoSuite, DeviceId, EncryptedGroupMediaFrame, GroupId, GroupMediaFrameHeader,
        GroupMediaSourceSignature, KeyId, MediaKind, NamespaceId, OpaqueId, PrincipalId,
        PrincipalKind, PrincipalRef, TenantId, TenantScope, VideoSourceKind,
    };
    use ucr_protocol::{
        ALGORITHM_VERSION, GROUP_MEDIA_FRAME_HEADER_VERSION, SFU_FORWARD_WIRE_MAGIC,
        SIGNATURE_ALGORITHM_ID,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }

    fn envelope() -> SfuForwardEnvelope {
        SfuForwardEnvelope {
            frame: EncryptedGroupMediaFrame {
                header: GroupMediaFrameHeader {
                    scope: TenantScope {
                        tenant_id: TenantId::from_opaque(id("tenant")),
                        namespace_id: Some(NamespaceId::from_opaque(id("namespace"))),
                    },
                    call_id: CallId::from_opaque(id("call")),
                    group_id: GroupId::from_opaque(id("group")),
                    stream_id: id("video-main"),
                    source: PrincipalRef {
                        principal_id: PrincipalId::from_opaque(id("alice")),
                        kind: PrincipalKind::Person,
                    },
                    source_device_id: DeviceId::from_opaque(id("alice-device")),
                    negotiation_ref: id("negotiation"),
                    negotiation_generation: 2,
                    crypto_epoch: 9,
                    crypto_state_ref: id("crypto-state"),
                    crypto_suite: CryptoSuite::UcrV1,
                    header_version: GROUP_MEDIA_FRAME_HEADER_VERSION,
                    media_kind: MediaKind::Video,
                    video_source_kind: Some(VideoSourceKind::Camera),
                    sequence: 44,
                    media_timestamp: 90_000,
                    keyframe: true,
                },
                nonce: [3_u8; 24],
                ciphertext: vec![7_u8; 512],
                source_signature: GroupMediaSourceSignature {
                    key_id: KeyId::from_opaque(id("signing-key")),
                    algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                    algorithm_version: ALGORITHM_VERSION,
                    signature: vec![5_u8; 64],
                },
            },
        }
    }

    #[test]
    fn v2_unordered_reassembly_tolerates_reorder_and_requests_keyframe_on_loss() {
        let mut big = envelope();
        big.frame.ciphertext = vec![9_u8; 40 * 1024];
        big.frame.header.keyframe = false;
        let mut key = envelope();
        key.frame.header.keyframe = true;
        let mut r = WebRtcE2eeLossyReassembler::new();

        // Out-of-order chunks of one message still reassemble.
        let mut chunks = encode_webrtc_e2ee_chunks_v2(&big, 1).unwrap();
        assert!(chunks.len() > 2);
        chunks.reverse();
        let last = chunks.pop().unwrap();
        for c in &chunks {
            assert_eq!(r.push_chunk(c).unwrap(), None);
        }
        assert_eq!(r.push_chunk(&last).unwrap(), Some(big.clone()));
        assert!(!r.take_keyframe_request());

        // Message 2 loses a chunk; message 3 completes -> loss + keyframe request once.
        let two = encode_webrtc_e2ee_chunks_v2(&big, 2).unwrap();
        r.push_chunk(&two[0]).unwrap();
        for c in encode_webrtc_e2ee_chunks_v2(&big, 3).unwrap() {
            r.push_chunk(&c).unwrap();
        }
        assert_eq!(r.lost(), 1);
        assert!(r.take_keyframe_request());
        assert!(!r.take_keyframe_request(), "request is edge-triggered");
        // Straggler of the lost message is ignored.
        assert_eq!(r.push_chunk(&two[1]).unwrap(), None);
        // Further loss before a keyframe does not spam requests.
        for c in encode_webrtc_e2ee_chunks_v2(&big, 5).unwrap() {
            r.push_chunk(&c).unwrap();
        }
        assert_eq!(r.lost(), 2);
        assert!(!r.take_keyframe_request());
        // Keyframe clears the need; next loss raises a new request.
        for c in encode_webrtc_e2ee_chunks_v2(&key, 6).unwrap() {
            assert!(r.push_chunk(&c).is_ok());
        }
        for c in encode_webrtc_e2ee_chunks_v2(&big, 8).unwrap() {
            r.push_chunk(&c).unwrap();
        }
        assert!(r.take_keyframe_request());
        // A gap healed by a keyframe itself needs no request.
        for c in encode_webrtc_e2ee_chunks_v2(&key, 10).unwrap() {
            r.push_chunk(&c).unwrap();
        }
        assert!(!r.take_keyframe_request());
    }

    #[test]
    fn v2_rejects_v1_chunks_and_malformed_headers_without_dropping_state() {
        let mut r = WebRtcE2eeLossyReassembler::new();
        let v1 = encode_webrtc_e2ee_chunks(&envelope(), 1).unwrap();
        assert_eq!(
            r.push_chunk(&v1[0]),
            Err(WebRtcE2eeWireError::UnsupportedVersion)
        );
        let mut bad = encode_webrtc_e2ee_chunks_v2(&envelope(), 1)
            .unwrap()
            .remove(0);
        bad[24] = 0x80; // unknown flag bit
        assert_eq!(r.push_chunk(&bad), Err(WebRtcE2eeWireError::Malformed));
        let good = encode_webrtc_e2ee_chunks_v2(&envelope(), 1).unwrap();
        assert_eq!(r.push_chunk(&good[0]).unwrap(), Some(envelope()));
        // v1 reassembler likewise ignores v2 chunks (fallback stays isolated).
        assert!(WebRtcE2eeReassembler::new().push_chunk(&good[0]).is_err());
    }

    #[test]
    fn unordered_flag_defaults_off() {
        if std::env::var_os("UCR_WEBRTC_E2EE_UNORDERED").is_none() {
            assert!(!unordered_e2ee_enabled_from_env());
        }
    }

    #[test]
    fn canonical_envelope_round_trips_without_key_material() {
        let expected = envelope();
        let wire = encode_webrtc_e2ee_envelope(&expected).expect("encode");
        assert!(wire.len() < MAX_WEBRTC_E2EE_WIRE_BYTES);
        assert_eq!(
            decode_webrtc_e2ee_envelope(&wire).expect("decode"),
            expected
        );
    }

    #[test]
    fn decoder_rejects_trailing_and_unknown_version_data() {
        let mut wire = encode_webrtc_e2ee_envelope(&envelope()).expect("encode");
        wire.push(0);
        assert_eq!(
            decode_webrtc_e2ee_envelope(&wire),
            Err(WebRtcE2eeWireError::Malformed)
        );

        let mut version = encode_webrtc_e2ee_envelope(&envelope()).expect("encode");
        version[SFU_FORWARD_WIRE_MAGIC.len()] = 99;
        assert_eq!(
            decode_webrtc_e2ee_envelope(&version),
            Err(WebRtcE2eeWireError::UnsupportedVersion)
        );
    }

    #[test]
    fn chunking_round_trips_large_video_envelope_below_datachannel_ceiling() {
        let mut expected = envelope();
        expected.frame.ciphertext = vec![9_u8; 128 * 1024];
        let chunks = encode_webrtc_e2ee_chunks(&expected, 77).expect("chunks");
        assert!(chunks.len() > 1);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.len() <= MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES)
        );
        let mut reassembler = WebRtcE2eeReassembler::new();
        let mut completed = None;
        for chunk in chunks {
            let next = reassembler.push_chunk(&chunk).expect("chunk");
            if next.is_some() {
                completed = next;
            }
        }
        assert_eq!(completed, Some(expected));
    }

    #[test]
    fn reassembler_fails_closed_on_out_of_order_chunks() {
        let mut expected = envelope();
        expected.frame.ciphertext = vec![8_u8; 64 * 1024];
        let mut chunks = encode_webrtc_e2ee_chunks(&expected, 88).expect("chunks");
        chunks.swap(0, 1);
        let mut reassembler = WebRtcE2eeReassembler::new();
        assert_eq!(
            reassembler.push_chunk(&chunks[0]),
            Err(WebRtcE2eeWireError::Malformed)
        );
    }

    async fn independent_e2ee_peer() -> (
        std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
        tokio::sync::mpsc::Receiver<std::sync::Arc<webrtc::data_channel::RTCDataChannel>>,
    ) {
        use webrtc::{
            api::{
                APIBuilder, interceptor_registry::register_default_interceptors,
                media_engine::MediaEngine,
            },
            interceptor::registry::Registry,
            peer_connection::configuration::RTCConfiguration,
        };
        let mut engine = MediaEngine::default();
        engine.register_default_codecs().expect("codecs");
        let interceptors =
            register_default_interceptors(Registry::new(), &mut engine).expect("interceptors");
        let api = APIBuilder::new()
            .with_media_engine(engine)
            .with_interceptor_registry(interceptors)
            .build();
        let remote = std::sync::Arc::new(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("independent peer"),
        );
        let (channel_tx, channel_rx) = tokio::sync::mpsc::channel(1);
        remote.on_data_channel(Box::new(move |channel| {
            let channel_tx = channel_tx.clone();
            Box::pin(async move {
                let _ = channel_tx.try_send(channel);
            })
        }));
        (remote, channel_rx)
    }

    #[test]
    fn live_datachannel_ingress_preserves_ciphertext_and_session_binding() {
        use crate::{LiveWebRtcProvider, WebRtcProvider, WebRtcSessionConfig};
        use std::time::Duration;
        use ucr_model::{IceTransportPolicy, SessionId, WebRtcSdpType, WebRtcSessionDescription};
        use webrtc::peer_connection::{
            peer_connection_state::RTCPeerConnectionState,
            sdp::session_description::RTCSessionDescription,
        };

        // Another concurrent WebRTC test may have installed the same provider.
        // rustls installation is process-global and intentionally single-shot.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let (ingress_tx, mut ingress_rx) = tokio::sync::mpsc::channel(4);
            let provider =
                LiveWebRtcProvider::with_e2ee_ingress(ingress_tx).expect("live ingress provider");
            let session_id = SessionId::from_opaque(id("e2ee-live-ingress-session"));
            let config = WebRtcSessionConfig {
                session_id: session_id.clone(),
                ice_servers: Vec::new(),
                ice_transport_policy: IceTransportPolicy::All,
            };
            let (remote, mut channel_rx) = independent_e2ee_peer().await;
            let offer = provider.create_session(&config).expect("server offer");
            remote
                .set_remote_description(
                    RTCSessionDescription::offer(offer.sdp).expect("valid offer"),
                )
                .await
                .expect("apply offer");
            let answer = remote.create_answer(None).await.expect("create answer");
            let mut gathered = remote.gathering_complete_promise().await;
            remote
                .set_local_description(answer)
                .await
                .expect("set answer");
            tokio::time::timeout(Duration::from_secs(12), gathered.recv())
                .await
                .expect("gather ICE");
            let answer_sdp = remote
                .local_description()
                .await
                .expect("gathered answer")
                .sdp;
            provider
                .set_remote_description(&WebRtcSessionDescription {
                    session_id: session_id.clone(),
                    sdp_type: WebRtcSdpType::Answer,
                    sdp: answer_sdp,
                })
                .expect("apply answer");

            let channel = tokio::time::timeout(Duration::from_secs(15), channel_rx.recv())
                .await
                .expect("server DataChannel arrives")
                .expect("channel");
            assert_eq!(channel.label(), WEBRTC_E2EE_DATA_CHANNEL_LABEL);
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if channel.ready_state()
                        == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
                        && remote.connection_state() == RTCPeerConnectionState::Connected
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("DataChannel established");

            let expected = envelope();
            for chunk in encode_webrtc_e2ee_chunks(&expected, 42).expect("canonical chunks") {
                channel
                    .send(&bytes::Bytes::from(chunk))
                    .await
                    .expect("send ciphertext");
            }
            let frame = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
                .await
                .expect("bounded live ingress")
                .expect("ingress frame");
            assert_eq!(frame.session_id, session_id);
            assert_eq!(
                frame.envelope, expected,
                "SFU ingress must receive unchanged ciphertext"
            );
            assert!(
                ingress_rx.try_recv().is_err(),
                "one envelope produces one ingress"
            );
            assert_live_ciphertext_egress(&provider, &session_id, &channel, &expected).await;
            remote.close().await.expect("close peer");
            assert_eq!(provider.close_session(&session_id), Ok(()));
        });
    }

    async fn assert_live_ciphertext_egress(
        provider: &crate::LiveWebRtcProvider,
        session_id: &ucr_model::SessionId,
        channel: &std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
        expected: &SfuForwardEnvelope,
    ) {
        use std::time::Duration;
        let (message_tx, mut message_rx) = tokio::sync::mpsc::channel(1);
        let reassembler =
            std::sync::Arc::new(tokio::sync::Mutex::new(WebRtcE2eeReassembler::new()));
        channel.on_message(Box::new(move |message| {
            let reassembler = std::sync::Arc::clone(&reassembler);
            let message_tx = message_tx.clone();
            Box::pin(async move {
                if message.is_string {
                    return;
                }
                let complete = reassembler
                    .lock()
                    .await
                    .push_chunk(&message.data)
                    .expect("valid outbound canonical ciphertext chunks");
                if let Some(envelope) = complete {
                    message_tx
                        .send(envelope)
                        .await
                        .expect("capture live ciphertext");
                }
            })
        }));
        provider
            .send_e2ee_envelope(session_id, expected)
            .expect("send SFU ciphertext over real DataChannel");
        let delivered = tokio::time::timeout(Duration::from_secs(5), message_rx.recv())
            .await
            .expect("outbound E2EE must reach independent WebRTC peer")
            .expect("captured ciphertext envelope");
        assert_eq!(
            delivered, *expected,
            "outbound WebRTC must preserve the encrypted envelope verbatim"
        );
        assert!(
            message_rx.try_recv().is_err(),
            "one outbound envelope must not be delivered twice"
        );
    }

    #[test]
    fn closed_session_rejects_e2ee_egress() {
        use crate::{LiveWebRtcProvider, WebRtcProvider, WebRtcSessionConfig};
        use ucr_model::{IceTransportPolicy, SessionId};

        let provider = LiveWebRtcProvider::new().expect("live peer provider");
        let session_id = SessionId::from_opaque(id("closed-e2ee-peer"));
        let config = WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        };
        provider.create_session(&config).expect("create live peer");
        assert_eq!(provider.close_session(&session_id), Ok(()));
        assert_eq!(
            provider.send_e2ee_envelope(&session_id, &envelope()),
            Err(crate::WebRtcProviderError::SessionUnavailable),
            "closed peer must never accept encrypted egress"
        );
    }

    async fn attach_independent_e2ee_peer(
        provider: &crate::LiveWebRtcProvider,
        session_id: &ucr_model::SessionId,
    ) -> (
        std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
        std::sync::Arc<webrtc::data_channel::RTCDataChannel>,
    ) {
        use crate::{WebRtcProvider, WebRtcSessionConfig};
        use ucr_model::{IceTransportPolicy, WebRtcSdpType, WebRtcSessionDescription};
        use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

        let config = WebRtcSessionConfig {
            session_id: session_id.clone(),
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
        };
        let (remote, mut channel_rx) = independent_e2ee_peer().await;
        let offer = provider.create_session(&config).expect("server offer");
        remote
            .set_remote_description(
                RTCSessionDescription::offer(offer.sdp).expect("valid server offer"),
            )
            .await
            .expect("apply offer");
        let answer = remote.create_answer(None).await.expect("peer answer");
        let mut gathered = remote.gathering_complete_promise().await;
        remote
            .set_local_description(answer)
            .await
            .expect("set peer answer");
        tokio::time::timeout(std::time::Duration::from_secs(12), gathered.recv())
            .await
            .expect("ICE gathering");
        provider
            .set_remote_description(&WebRtcSessionDescription {
                session_id: session_id.clone(),
                sdp_type: WebRtcSdpType::Answer,
                sdp: remote.local_description().await.expect("peer SDP").sdp,
            })
            .expect("apply remote answer");
        let channel = tokio::time::timeout(std::time::Duration::from_secs(15), channel_rx.recv())
            .await
            .expect("remote channel establishment")
            .expect("E2EE channel");
        assert_eq!(channel.label(), WEBRTC_E2EE_DATA_CHANNEL_LABEL);
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if channel.ready_state()
                    == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("open live E2EE channel");
        (remote, channel)
    }

    #[test]
    fn two_independent_peers_transfer_canonical_ciphertext_without_server_decryption() {
        use crate::{LiveWebRtcProvider, WebRtcProvider};
        use ucr_model::SessionId;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let (ingress_tx, mut ingress_rx) = tokio::sync::mpsc::channel(4);
            let provider =
                LiveWebRtcProvider::with_e2ee_ingress(ingress_tx).expect("live provider");
            let alice_id = SessionId::from_opaque(id("rt0-alice-peer"));
            let bob_id = SessionId::from_opaque(id("rt0-bob-peer"));
            let (alice, alice_channel) = attach_independent_e2ee_peer(&provider, &alice_id).await;
            let (bob, bob_channel) = attach_independent_e2ee_peer(&provider, &bob_id).await;
            let expected = envelope();
            for chunk in encode_webrtc_e2ee_chunks(&expected, 63).expect("wire chunks") {
                alice_channel
                    .send(&bytes::Bytes::from(chunk))
                    .await
                    .expect("Alice sends E2EE ciphertext");
            }
            let frame = tokio::time::timeout(std::time::Duration::from_secs(5), ingress_rx.recv())
                .await
                .expect("live ingress")
                .expect("Alice ingress");
            assert_eq!(frame.session_id, alice_id, "bind ciphertext to Alice");
            assert_eq!(frame.envelope, expected, "ingress preserves ciphertext");
            assert_live_ciphertext_egress(&provider, &bob_id, &bob_channel, &frame.envelope).await;
            assert!(ingress_rx.try_recv().is_err(), "no duplicate ingress");
            alice.close().await.expect("close Alice");
            bob.close().await.expect("close Bob");
            assert_eq!(provider.close_session(&alice_id), Ok(()));
            assert_eq!(provider.close_session(&bob_id), Ok(()));
        });
    }

    #[test]
    fn decoder_rejects_unbounded_messages_before_parsing() {
        let wire = vec![0_u8; MAX_WEBRTC_E2EE_WIRE_BYTES + 1];
        assert_eq!(
            decode_webrtc_e2ee_envelope(&wire),
            Err(WebRtcE2eeWireError::TooLarge)
        );
    }
}

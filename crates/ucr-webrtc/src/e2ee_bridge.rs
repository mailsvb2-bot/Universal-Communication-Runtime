use std::{sync::Arc, time::Instant};

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
}

impl LiveWebRtcE2eeChannel {
    pub(crate) async fn send(
        &mut self,
        envelope: &SfuForwardEnvelope,
        deadline: Instant,
    ) -> Result<(), crate::WebRtcProviderError> {
        if self.channel.buffered_amount().await > MAX_WEBRTC_E2EE_BUFFERED_BYTES {
            return Err(crate::WebRtcProviderError::CapacityExceeded);
        }
        let message_id = self.next_message_id;
        self.next_message_id = self
            .next_message_id
            .checked_add(1)
            .ok_or(crate::WebRtcProviderError::CapacityExceeded)?;
        let chunks = encode_webrtc_e2ee_chunks(envelope, message_id)
            .map_err(|_| crate::WebRtcProviderError::Internal)?;
        for chunk in chunks {
            if Instant::now() >= deadline {
                return Err(crate::WebRtcProviderError::TemporarilyUnavailable);
            }
            self.channel
                .send(&Bytes::from(chunk))
                .await
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
    Ok(LiveWebRtcE2eeChannel {
        channel,
        next_message_id: 1,
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
        GroupMediaFrameAuthVersion, GroupMediaSourceKind, GroupMediaSourceSignature, KeyId,
        MediaKind, NamespaceId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, TenantId,
        TenantScope,
    };
    use ucr_protocol::{ALGORITHM_VERSION, SFU_FORWARD_WIRE_MAGIC, SIGNATURE_ALGORITHM_ID};

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
                    media_kind: MediaKind::Video,
                    source_kind: GroupMediaSourceKind::ScreenShare,
                    auth_version: GroupMediaFrameAuthVersion::V2,
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

    #[test]
    fn decoder_rejects_unbounded_messages_before_parsing() {
        let wire = vec![0_u8; MAX_WEBRTC_E2EE_WIRE_BYTES + 1];
        assert_eq!(
            decode_webrtc_e2ee_envelope(&wire),
            Err(WebRtcE2eeWireError::TooLarge)
        );
    }
}

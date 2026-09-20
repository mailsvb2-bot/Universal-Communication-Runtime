use ucr_model::{
    CallId, CryptoSuite, DeviceId, EncryptedGroupMediaFrame, GroupId, GroupMediaFrameHeader,
    GroupMediaSourceSignature, KeyId, MediaKind, NamespaceId, OpaqueId, PrincipalId, PrincipalKind,
    PrincipalRef, SessionId, SfuForwardEnvelope, TenantId, TenantScope,
};
use ucr_protocol::{
    MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES, SfuProtocolError, canonical_sfu_forward_envelope,
};

pub const WEBRTC_E2EE_DATA_CHANNEL_LABEL: &str = "ucr.e2ee.media.v1";
pub const MAX_WEBRTC_E2EE_WIRE_BYTES: usize = MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES + 8_192;
pub const MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES: usize = 16_000;
const WEBRTC_E2EE_WIRE_MAGIC: &[u8; 8] = b"UCRE2EE1";
const WEBRTC_E2EE_CHUNK_MAGIC: &[u8; 8] = b"UCRCHK01";
const WEBRTC_E2EE_CHUNK_HEADER_BYTES: usize = 24;
const WEBRTC_E2EE_CHUNK_PAYLOAD_BYTES: usize =
    MAX_WEBRTC_E2EE_DATA_MESSAGE_BYTES - WEBRTC_E2EE_CHUNK_HEADER_BYTES;
const WEBRTC_E2EE_WIRE_VERSION: u8 = 1;
const MAX_WIRE_STRING_BYTES: usize = 256;

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

    /// Accepts one ordered reliable DataChannel chunk and returns a complete canonical envelope
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
        let completed = self
            .pending
            .take()
            .ok_or(WebRtcE2eeWireError::Malformed)?;
        if completed.bytes.len() != completed.total_length {
            return Err(WebRtcE2eeWireError::Malformed);
        }
        decode_webrtc_e2ee_envelope(&completed.bytes).map(Some)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcE2eeWireError {
    TooLarge,
    Malformed,
    UnsupportedVersion,
    InvalidEnvelope(SfuProtocolError),
}

impl From<SfuProtocolError> for WebRtcE2eeWireError {
    fn from(error: SfuProtocolError) -> Self {
        Self::InvalidEnvelope(error)
    }
}

/// Encodes one canonical SFU ciphertext envelope for the WebRTC E2EE data-channel boundary.
///
/// No endpoint key material enters this codec. The clear routing header, source signature metadata,
/// nonce and ciphertext are serialized exactly once and revalidated before emission.
///
/// # Errors
/// Rejects malformed/non-canonical SFU envelopes or values exceeding the bounded wire budget.
pub fn encode_webrtc_e2ee_envelope(
    envelope: &SfuForwardEnvelope,
) -> Result<Vec<u8>, WebRtcE2eeWireError> {
    let (_, envelope) = canonical_sfu_forward_envelope(envelope)?;
    let frame = &envelope.frame;
    let mut output = Vec::with_capacity(frame.ciphertext.len().saturating_add(1_024));
    output.extend_from_slice(WEBRTC_E2EE_WIRE_MAGIC);
    output.push(WEBRTC_E2EE_WIRE_VERSION);
    push_scope(&mut output, &frame.header.scope)?;
    push_id(&mut output, frame.header.call_id.as_opaque())?;
    push_id(&mut output, frame.header.group_id.as_opaque())?;
    push_id(&mut output, &frame.header.stream_id)?;
    output.push(principal_kind_code(frame.header.source.kind));
    push_id(&mut output, frame.header.source.principal_id.as_opaque())?;
    push_id(&mut output, frame.header.source_device_id.as_opaque())?;
    push_id(&mut output, &frame.header.negotiation_ref)?;
    output.extend_from_slice(&frame.header.negotiation_generation.to_be_bytes());
    output.extend_from_slice(&frame.header.crypto_epoch.to_be_bytes());
    push_id(&mut output, &frame.header.crypto_state_ref)?;
    output.push(crypto_suite_code(frame.header.crypto_suite));
    output.push(media_kind_code(frame.header.media_kind));
    output.extend_from_slice(&frame.header.sequence.to_be_bytes());
    output.extend_from_slice(&frame.header.media_timestamp.to_be_bytes());
    output.push(u8::from(frame.header.keyframe));
    output.extend_from_slice(&frame.nonce);
    push_bytes_u32(&mut output, &frame.ciphertext)?;
    push_id(&mut output, frame.source_signature.key_id.as_opaque())?;
    push_string(&mut output, &frame.source_signature.algorithm_id)?;
    output.extend_from_slice(&frame.source_signature.algorithm_version.to_be_bytes());
    push_bytes_u16(&mut output, &frame.source_signature.signature)?;
    if output.len() > MAX_WEBRTC_E2EE_WIRE_BYTES {
        return Err(WebRtcE2eeWireError::TooLarge);
    }
    Ok(output)
}

/// Splits one canonical encrypted SFU envelope into ordered DataChannel messages below the
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

/// Decodes and revalidates one WebRTC E2EE data-channel message as a canonical SFU envelope.
///
/// # Errors
/// Rejects oversized, malformed, unknown-version, trailing-byte or non-canonical ciphertext input.
pub fn decode_webrtc_e2ee_envelope(
    bytes: &[u8],
) -> Result<SfuForwardEnvelope, WebRtcE2eeWireError> {
    if bytes.len() > MAX_WEBRTC_E2EE_WIRE_BYTES {
        return Err(WebRtcE2eeWireError::TooLarge);
    }
    let mut reader = WireReader::new(bytes);
    if reader.take(WEBRTC_E2EE_WIRE_MAGIC.len())? != WEBRTC_E2EE_WIRE_MAGIC {
        return Err(WebRtcE2eeWireError::Malformed);
    }
    if reader.u8()? != WEBRTC_E2EE_WIRE_VERSION {
        return Err(WebRtcE2eeWireError::UnsupportedVersion);
    }
    let scope = reader.scope()?;
    let call_id = CallId::from_opaque(reader.id()?);
    let group_id = GroupId::from_opaque(reader.id()?);
    let stream_id = reader.id()?;
    let source = PrincipalRef {
        kind: principal_kind_from_code(reader.u8()?)?,
        principal_id: PrincipalId::from_opaque(reader.id()?),
    };
    let source_device_id = DeviceId::from_opaque(reader.id()?);
    let negotiation_ref = reader.id()?;
    let negotiation_generation = reader.u64()?;
    let crypto_epoch = reader.u64()?;
    let crypto_state_ref = reader.id()?;
    let crypto_suite = crypto_suite_from_code(reader.u8()?)?;
    let media_kind = media_kind_from_code(reader.u8()?)?;
    let sequence = reader.u64()?;
    let media_timestamp = reader.u64()?;
    let keyframe = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(WebRtcE2eeWireError::Malformed),
    };
    let nonce = reader.array::<24>()?;
    let ciphertext = reader.bytes_u32(MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES)?;
    let key_id = KeyId::from_opaque(reader.id()?);
    let algorithm_id = reader.string(MAX_WIRE_STRING_BYTES)?;
    let algorithm_version = reader.u32()?;
    let signature = reader.bytes_u16(MAX_WIRE_STRING_BYTES)?;
    if !reader.is_done() {
        return Err(WebRtcE2eeWireError::Malformed);
    }
    let envelope = SfuForwardEnvelope {
        frame: EncryptedGroupMediaFrame {
            header: GroupMediaFrameHeader {
                scope,
                call_id,
                group_id,
                stream_id,
                source,
                source_device_id,
                negotiation_ref,
                negotiation_generation,
                crypto_epoch,
                crypto_state_ref,
                crypto_suite,
                media_kind,
                sequence,
                media_timestamp,
                keyframe,
            },
            nonce,
            ciphertext,
            source_signature: GroupMediaSourceSignature {
                key_id,
                algorithm_id,
                algorithm_version,
                signature,
            },
        },
    };
    canonical_sfu_forward_envelope(&envelope)
        .map(|(_, canonical)| canonical)
        .map_err(WebRtcE2eeWireError::InvalidEnvelope)
}

fn push_scope(
    output: &mut Vec<u8>,
    scope: &TenantScope,
) -> Result<(), WebRtcE2eeWireError> {
    push_id(output, scope.tenant_id.as_opaque())?;
    match &scope.namespace_id {
        Some(namespace_id) => {
            output.push(1);
            push_id(output, namespace_id.as_opaque())?;
        }
        None => output.push(0),
    }
    Ok(())
}

fn push_id(output: &mut Vec<u8>, id: &OpaqueId) -> Result<(), WebRtcE2eeWireError> {
    push_bytes_u16(output, id.as_wire_bytes())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), WebRtcE2eeWireError> {
    if value.len() > MAX_WIRE_STRING_BYTES {
        return Err(WebRtcE2eeWireError::TooLarge);
    }
    push_bytes_u16(output, value.as_bytes())
}

fn push_bytes_u16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WebRtcE2eeWireError> {
    let length = u16::try_from(value.len()).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_bytes_u32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WebRtcE2eeWireError> {
    let length = u32::try_from(value.len()).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

const fn principal_kind_code(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::Person => 1,
        PrincipalKind::Device => 2,
        PrincipalKind::ServiceAccount => 3,
        PrincipalKind::AiAgent => 4,
        PrincipalKind::Bot => 5,
        PrincipalKind::Organization => 6,
        PrincipalKind::Automation => 7,
        PrincipalKind::ExternalPlatform => 8,
    }
}

const fn principal_kind_from_code(code: u8) -> Result<PrincipalKind, WebRtcE2eeWireError> {
    match code {
        1 => Ok(PrincipalKind::Person),
        2 => Ok(PrincipalKind::Device),
        3 => Ok(PrincipalKind::ServiceAccount),
        4 => Ok(PrincipalKind::AiAgent),
        5 => Ok(PrincipalKind::Bot),
        6 => Ok(PrincipalKind::Organization),
        7 => Ok(PrincipalKind::Automation),
        8 => Ok(PrincipalKind::ExternalPlatform),
        _ => Err(WebRtcE2eeWireError::Malformed),
    }
}

const fn crypto_suite_code(suite: CryptoSuite) -> u8 {
    match suite {
        CryptoSuite::UcrV1 => 1,
    }
}

const fn crypto_suite_from_code(code: u8) -> Result<CryptoSuite, WebRtcE2eeWireError> {
    match code {
        1 => Ok(CryptoSuite::UcrV1),
        _ => Err(WebRtcE2eeWireError::Malformed),
    }
}

const fn media_kind_code(kind: MediaKind) -> u8 {
    match kind {
        MediaKind::Audio => 1,
        MediaKind::Video => 2,
    }
}

const fn media_kind_from_code(code: u8) -> Result<MediaKind, WebRtcE2eeWireError> {
    match code {
        1 => Ok(MediaKind::Audio),
        2 => Ok(MediaKind::Video),
        _ => Err(WebRtcE2eeWireError::Malformed),
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

    fn u8(&mut self) -> Result<u8, WebRtcE2eeWireError> {
        Ok(self.take(1)?[0])
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

    fn id(&mut self) -> Result<OpaqueId, WebRtcE2eeWireError> {
        let length = usize::from(self.u16()?);
        OpaqueId::from_wire_bytes(self.take(length)?).map_err(|_| WebRtcE2eeWireError::Malformed)
    }

    fn scope(&mut self) -> Result<TenantScope, WebRtcE2eeWireError> {
        let tenant_id = TenantId::from_opaque(self.id()?);
        let namespace_id = match self.u8()? {
            0 => None,
            1 => Some(NamespaceId::from_opaque(self.id()?)),
            _ => return Err(WebRtcE2eeWireError::Malformed),
        };
        Ok(TenantScope {
            tenant_id,
            namespace_id,
        })
    }

    fn bytes_u16(&mut self, maximum: usize) -> Result<Vec<u8>, WebRtcE2eeWireError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(WebRtcE2eeWireError::TooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn bytes_u32(&mut self, maximum: usize) -> Result<Vec<u8>, WebRtcE2eeWireError> {
        let length = usize::try_from(self.u32()?).map_err(|_| WebRtcE2eeWireError::TooLarge)?;
        if length > maximum {
            return Err(WebRtcE2eeWireError::TooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, maximum: usize) -> Result<String, WebRtcE2eeWireError> {
        String::from_utf8(self.bytes_u16(maximum)?).map_err(|_| WebRtcE2eeWireError::Malformed)
    }

    fn is_done(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_protocol::{ALGORITHM_VERSION, SIGNATURE_ALGORITHM_ID};

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
        version[WEBRTC_E2EE_WIRE_MAGIC.len()] = 99;
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

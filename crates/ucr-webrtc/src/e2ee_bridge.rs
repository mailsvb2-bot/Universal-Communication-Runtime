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
const WEBRTC_E2EE_WIRE_MAGIC: &[u8; 8] = b"UCRE2EE1";
const WEBRTC_E2EE_WIRE_VERSION: u8 = 1;
const MAX_WIRE_STRING_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRtcE2eeIngressFrame {
    pub session_id: SessionId,
    pub envelope: SfuForwardEnvelope,
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
    fn decoder_rejects_unbounded_messages_before_parsing() {
        let wire = vec![0_u8; MAX_WEBRTC_E2EE_WIRE_BYTES + 1];
        assert_eq!(
            decode_webrtc_e2ee_envelope(&wire),
            Err(WebRtcE2eeWireError::TooLarge)
        );
    }
}

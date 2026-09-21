use ucr_model::{
    CallId, CapabilityDescriptor, CapabilityMaturity, CryptoSuite, DeviceId,
    EncryptedGroupMediaFrame, GroupId, GroupMediaE2eeContext, GroupMediaFrameHeader,
    GroupMediaSourceSignature, KeyId, MediaKind, NamespaceId, OpaqueId, PrincipalId, PrincipalKind,
    PrincipalRef, SfuForwardEnvelope, TenantId, TenantScope,
};

use crate::{
    GroupMediaE2eeProtocolError, MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES,
    group_media_context_from_frame, validate_encrypted_group_media_frame,
};

pub const SFU_MEDIA_CAPABILITY: &str = "ucr.media.sfu";
pub const SFU_FORWARD_WIRE_MAGIC: &[u8; 8] = b"UCRE2EE1";
pub const SFU_FORWARD_WIRE_VERSION: u8 = 1;
pub const MAX_SFU_FORWARD_WIRE_BYTES: usize = MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES + 8_192;
const MAX_SFU_FORWARD_WIRE_STRING_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuProtocolError {
    GroupMedia(GroupMediaE2eeProtocolError),
}

impl From<GroupMediaE2eeProtocolError> for SfuProtocolError {
    fn from(error: GroupMediaE2eeProtocolError) -> Self {
        Self::GroupMedia(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuForwardWireError {
    TooLarge,
    Malformed,
    UnsupportedVersion,
    InvalidEnvelope(SfuProtocolError),
}

impl From<SfuProtocolError> for SfuForwardWireError {
    fn from(error: SfuProtocolError) -> Self {
        Self::InvalidEnvelope(error)
    }
}

#[must_use]
pub fn phase29_sfu_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: SFU_MEDIA_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Validates the public encrypted group-media shape an SFU may route without decrypting it and
/// returns the exact authenticated epoch context reconstructed from the frame header.
///
/// # Errors
/// Rejects malformed MLS-backed group media before any infrastructure side effect.
pub fn canonical_sfu_forward_envelope(
    envelope: &SfuForwardEnvelope,
) -> Result<(GroupMediaE2eeContext, SfuForwardEnvelope), SfuProtocolError> {
    let context = group_media_context_from_frame(&envelope.frame)?;
    validate_encrypted_group_media_frame(&context, &envelope.frame)?;
    Ok((context, envelope.clone()))
}

/// Encodes one canonical encrypted SFU envelope into the transport-neutral UCR wire representation.
///
/// This codec owns no endpoint key material and performs no encryption. The clear routing header,
/// source-signature metadata, nonce and ciphertext are serialized only after canonical validation.
///
/// # Errors
/// Rejects malformed/non-canonical envelopes or values exceeding the bounded wire budget.
pub fn encode_sfu_forward_envelope(
    envelope: &SfuForwardEnvelope,
) -> Result<Vec<u8>, SfuForwardWireError> {
    let (_, envelope) = canonical_sfu_forward_envelope(envelope)?;
    let frame = &envelope.frame;
    let mut output = Vec::with_capacity(frame.ciphertext.len().saturating_add(1_024));
    output.extend_from_slice(SFU_FORWARD_WIRE_MAGIC);
    output.push(SFU_FORWARD_WIRE_VERSION);
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
    if output.len() > MAX_SFU_FORWARD_WIRE_BYTES {
        return Err(SfuForwardWireError::TooLarge);
    }
    Ok(output)
}

/// Decodes one transport-neutral UCR SFU wire envelope and revalidates its canonical semantics.
///
/// # Errors
/// Rejects oversized, malformed, unknown-version, trailing-byte or non-canonical ciphertext input.
pub fn decode_sfu_forward_envelope(
    bytes: &[u8],
) -> Result<SfuForwardEnvelope, SfuForwardWireError> {
    if bytes.len() > MAX_SFU_FORWARD_WIRE_BYTES {
        return Err(SfuForwardWireError::TooLarge);
    }
    let mut reader = WireReader::new(bytes);
    if reader.take(SFU_FORWARD_WIRE_MAGIC.len())? != SFU_FORWARD_WIRE_MAGIC {
        return Err(SfuForwardWireError::Malformed);
    }
    if reader.u8()? != SFU_FORWARD_WIRE_VERSION {
        return Err(SfuForwardWireError::UnsupportedVersion);
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
        _ => return Err(SfuForwardWireError::Malformed),
    };
    let nonce = reader.array::<24>()?;
    let ciphertext = reader.bytes_u32(MAX_ENCRYPTED_GROUP_MEDIA_PAYLOAD_BYTES)?;
    let key_id = KeyId::from_opaque(reader.id()?);
    let algorithm_id = reader.string(MAX_SFU_FORWARD_WIRE_STRING_BYTES)?;
    let algorithm_version = reader.u32()?;
    let signature = reader.bytes_u16(MAX_SFU_FORWARD_WIRE_STRING_BYTES)?;
    if !reader.is_done() {
        return Err(SfuForwardWireError::Malformed);
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
        .map_err(SfuForwardWireError::InvalidEnvelope)
}

fn push_scope(output: &mut Vec<u8>, scope: &TenantScope) -> Result<(), SfuForwardWireError> {
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

fn push_id(output: &mut Vec<u8>, id: &OpaqueId) -> Result<(), SfuForwardWireError> {
    push_bytes_u16(output, id.as_wire_bytes())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), SfuForwardWireError> {
    if value.len() > MAX_SFU_FORWARD_WIRE_STRING_BYTES {
        return Err(SfuForwardWireError::TooLarge);
    }
    push_bytes_u16(output, value.as_bytes())
}

fn push_bytes_u16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SfuForwardWireError> {
    let length = u16::try_from(value.len()).map_err(|_| SfuForwardWireError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_bytes_u32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), SfuForwardWireError> {
    let length = u32::try_from(value.len()).map_err(|_| SfuForwardWireError::TooLarge)?;
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

const fn principal_kind_from_code(code: u8) -> Result<PrincipalKind, SfuForwardWireError> {
    match code {
        1 => Ok(PrincipalKind::Person),
        2 => Ok(PrincipalKind::Device),
        3 => Ok(PrincipalKind::ServiceAccount),
        4 => Ok(PrincipalKind::AiAgent),
        5 => Ok(PrincipalKind::Bot),
        6 => Ok(PrincipalKind::Organization),
        7 => Ok(PrincipalKind::Automation),
        8 => Ok(PrincipalKind::ExternalPlatform),
        _ => Err(SfuForwardWireError::Malformed),
    }
}

const fn crypto_suite_code(suite: CryptoSuite) -> u8 {
    match suite {
        CryptoSuite::UcrV1 => 1,
    }
}

const fn crypto_suite_from_code(code: u8) -> Result<CryptoSuite, SfuForwardWireError> {
    match code {
        1 => Ok(CryptoSuite::UcrV1),
        _ => Err(SfuForwardWireError::Malformed),
    }
}

const fn media_kind_code(kind: MediaKind) -> u8 {
    match kind {
        MediaKind::Audio => 1,
        MediaKind::Video => 2,
    }
}

const fn media_kind_from_code(code: u8) -> Result<MediaKind, SfuForwardWireError> {
    match code {
        1 => Ok(MediaKind::Audio),
        2 => Ok(MediaKind::Video),
        _ => Err(SfuForwardWireError::Malformed),
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], SfuForwardWireError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SfuForwardWireError::Malformed)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SfuForwardWireError::Malformed)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SfuForwardWireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SfuForwardWireError::Malformed)
    }

    fn u8(&mut self) -> Result<u8, SfuForwardWireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SfuForwardWireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, SfuForwardWireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SfuForwardWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn id(&mut self) -> Result<OpaqueId, SfuForwardWireError> {
        let length = usize::from(self.u16()?);
        OpaqueId::from_wire_bytes(self.take(length)?).map_err(|_| SfuForwardWireError::Malformed)
    }

    fn scope(&mut self) -> Result<TenantScope, SfuForwardWireError> {
        let tenant_id = TenantId::from_opaque(self.id()?);
        let namespace_id = match self.u8()? {
            0 => None,
            1 => Some(NamespaceId::from_opaque(self.id()?)),
            _ => return Err(SfuForwardWireError::Malformed),
        };
        Ok(TenantScope {
            tenant_id,
            namespace_id,
        })
    }

    fn bytes_u16(&mut self, maximum: usize) -> Result<Vec<u8>, SfuForwardWireError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(SfuForwardWireError::TooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn bytes_u32(&mut self, maximum: usize) -> Result<Vec<u8>, SfuForwardWireError> {
        let length = usize::try_from(self.u32()?).map_err(|_| SfuForwardWireError::TooLarge)?;
        if length > maximum {
            return Err(SfuForwardWireError::TooLarge);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, maximum: usize) -> Result<String, SfuForwardWireError> {
        String::from_utf8(self.bytes_u16(maximum)?).map_err(|_| SfuForwardWireError::Malformed)
    }

    const fn is_done(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use crate::{ALGORITHM_VERSION, SIGNATURE_ALGORITHM_ID};

    use super::*;

    const WIRE_V1_VECTOR_HEX: &str = "554352453245453101000674656e616e740100096e616d657370616365000463616c6c000567726f7570000a766964656f2d6d61696e010005616c696365000c616c6963652d646576696365000b6e65676f74696174696f6e00000000000000020000000000000009000c63727970746f2d73746174650102000000000000002c0000000000015f900103030303030303030303030303030303030303030303030300000003070809000b7369676e696e672d6b657900076564323535313900000001004005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505";

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
                ciphertext: vec![7, 8, 9],
                source_signature: GroupMediaSourceSignature {
                    key_id: KeyId::from_opaque(id("signing-key")),
                    algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                    algorithm_version: ALGORITHM_VERSION,
                    signature: vec![5_u8; 64],
                },
            },
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        let mut value = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            write!(&mut value, "{byte:02x}").expect("string write");
        }
        value
    }

    #[test]
    fn wire_v1_matches_cross_language_test_vector() {
        let expected = envelope();
        let wire = encode_sfu_forward_envelope(&expected).expect("encode");
        assert_eq!(lower_hex(&wire), WIRE_V1_VECTOR_HEX);
        assert_eq!(
            decode_sfu_forward_envelope(&wire).expect("decode"),
            expected
        );
    }

    #[test]
    fn wire_decoder_rejects_trailing_unknown_version_and_unbounded_input() {
        let mut trailing = encode_sfu_forward_envelope(&envelope()).expect("encode");
        trailing.push(0);
        assert_eq!(
            decode_sfu_forward_envelope(&trailing),
            Err(SfuForwardWireError::Malformed)
        );

        let mut version = encode_sfu_forward_envelope(&envelope()).expect("encode");
        version[SFU_FORWARD_WIRE_MAGIC.len()] = 99;
        assert_eq!(
            decode_sfu_forward_envelope(&version),
            Err(SfuForwardWireError::UnsupportedVersion)
        );

        let oversized = vec![0_u8; MAX_SFU_FORWARD_WIRE_BYTES + 1];
        assert_eq!(
            decode_sfu_forward_envelope(&oversized),
            Err(SfuForwardWireError::TooLarge)
        );
    }
}

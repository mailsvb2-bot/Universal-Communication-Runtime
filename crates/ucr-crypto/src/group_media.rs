use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use ucr_model::{
    DeviceId, EncryptedGroupMediaFrame, GroupMediaE2eeContext, GroupMediaFrameHeader,
    GroupMediaSourceSignature, KeyId, MediaKind, OpaqueId, PrincipalRef,
};
use ucr_protocol::{
    ALGORITHM_VERSION, GroupMediaE2eeProtocolError, SIGNATURE_ALGORITHM_ID,
    group_media_context_binding, group_media_frame_aad, group_media_key_context,
    group_media_source_signing_binding, validate_encrypted_group_media_frame,
};

use crate::{
    AeadError, SignatureBytes, SignatureError, SigningKeyMaterial, TrafficKey, VerifyingKeyBytes,
    verify_group_media_binding_signature,
};
use ucr_protocol::GroupMediaSigningBinding;

const GROUP_MEDIA_TRAFFIC_KDF_V1_DOMAIN: &[u8] = b"UCR-GROUP-MEDIA-TRAFFIC-KDF-V1\0";

/// Non-exporting signing boundary for source-authenticated group media.
pub trait GroupMediaSigningKeyHandle: core::fmt::Debug + Send + Sync {
    fn verifying_key(&self) -> VerifyingKeyBytes;

    /// Signs one already domain-separated canonical group-media frame binding.
    ///
    /// # Errors
    /// Returns an explicit provider/signature failure without exporting private key bytes.
    fn sign_group_media_binding(
        &self,
        binding: &GroupMediaSigningBinding,
    ) -> Result<SignatureBytes, SignatureError>;
}

impl GroupMediaSigningKeyHandle for SigningKeyMaterial {
    fn verifying_key(&self) -> VerifyingKeyBytes {
        SigningKeyMaterial::verifying_key(self)
    }

    fn sign_group_media_binding(
        &self,
        binding: &GroupMediaSigningBinding,
    ) -> Result<SignatureBytes, SignatureError> {
        Ok(SigningKeyMaterial::sign_group_media_binding(self, binding))
    }
}

/// MLS exporter material for one exact group epoch.
///
/// This value is endpoint-only key material. It must never cross the SFU boundary, appear in logs,
/// or be persisted by UCR outside the standardized MLS provider's own protected state.
pub struct GroupMediaEpochSecret(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for GroupMediaEpochSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("GroupMediaEpochSecret")
            .field(&"<secret>")
            .finish()
    }
}

impl GroupMediaEpochSecret {
    /// Wraps exactly 32 bytes exported by the standardized MLS provider.
    #[must_use]
    pub fn from_exporter_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMediaKeyError {
    Protocol(GroupMediaE2eeProtocolError),
    ExpandFailed,
}

impl From<GroupMediaE2eeProtocolError> for GroupMediaKeyError {
    fn from(error: GroupMediaE2eeProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Derives a source/stream-specific AEAD key from one MLS epoch exporter secret.
///
/// The exact UCR group-media context is used as HKDF salt and the source Device, stream and media
/// kind are included in HKDF info. This prevents key reuse between independent senders/streams while
/// preserving one MLS group epoch as the membership/key-lifecycle authority.
///
/// # Errors
/// Rejects malformed context/source bindings or HKDF expansion failure.
pub fn derive_group_media_traffic_key(
    epoch_secret: &GroupMediaEpochSecret,
    context: &GroupMediaE2eeContext,
    source: &PrincipalRef,
    source_device_id: &DeviceId,
    stream_id: &OpaqueId,
    media_kind: MediaKind,
) -> Result<TrafficKey, GroupMediaKeyError> {
    let binding = group_media_context_binding(context)?;
    let key_context =
        group_media_key_context(context, source, source_device_id, stream_id, media_kind)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&binding), epoch_secret.0.as_ref());
    let mut info = Vec::with_capacity(GROUP_MEDIA_TRAFFIC_KDF_V1_DOMAIN.len() + key_context.len());
    info.extend_from_slice(GROUP_MEDIA_TRAFFIC_KDF_V1_DOMAIN);
    info.extend_from_slice(&key_context);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| GroupMediaKeyError::ExpandFailed)?;
    Ok(TrafficKey::from_bytes(output))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointGroupMediaCryptoError {
    Protocol(GroupMediaE2eeProtocolError),
    Key(GroupMediaKeyError),
    Aead(AeadError),
    Signature(SignatureError),
    InvalidSignatureBytes,
}

impl From<GroupMediaE2eeProtocolError> for EndpointGroupMediaCryptoError {
    fn from(error: GroupMediaE2eeProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<GroupMediaKeyError> for EndpointGroupMediaCryptoError {
    fn from(error: GroupMediaKeyError) -> Self {
        Self::Key(error)
    }
}

impl From<AeadError> for EndpointGroupMediaCryptoError {
    fn from(error: AeadError) -> Self {
        Self::Aead(error)
    }
}

impl From<SignatureError> for EndpointGroupMediaCryptoError {
    fn from(error: SignatureError) -> Self {
        Self::Signature(error)
    }
}

/// Seals one endpoint-owned group-media payload using the canonical UCR MLS-derived crypto
/// contract without requiring server-side stores or authorization state.
///
/// The caller must provide a header already derived from its current canonical endpoint state.
/// This function validates that header against the exact group-media context, derives the same
/// per-source/stream traffic key used by the runtime, encrypts the payload, and signs the exact
/// canonical frame binding with the endpoint-held Device signing key.
///
/// # Errors
/// Rejects context/header drift, key-derivation failures, AEAD failures, or signing failures.
pub fn seal_endpoint_group_media_payload(
    epoch_secret: &GroupMediaEpochSecret,
    context: &GroupMediaE2eeContext,
    header: GroupMediaFrameHeader,
    plaintext: &[u8],
    signing_key_id: KeyId,
    signer: &impl GroupMediaSigningKeyHandle,
) -> Result<EncryptedGroupMediaFrame, EndpointGroupMediaCryptoError> {
    let traffic_key = derive_group_media_traffic_key(
        epoch_secret,
        context,
        &header.source,
        &header.source_device_id,
        &header.stream_id,
        header.media_kind,
    )?;
    let aad = group_media_frame_aad(&header)?;
    let encrypted = traffic_key.encrypt(plaintext, &aad)?;
    let signing_binding =
        group_media_source_signing_binding(&header, &encrypted.nonce, &encrypted.bytes)?;
    let signature = signer.sign_group_media_binding(&signing_binding)?;
    let frame = EncryptedGroupMediaFrame {
        header,
        nonce: encrypted.nonce,
        ciphertext: encrypted.bytes,
        source_signature: GroupMediaSourceSignature {
            key_id: signing_key_id,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            signature: signature.0.to_vec(),
        },
    };
    validate_encrypted_group_media_frame(context, &frame)?;
    Ok(frame)
}

/// Opens one canonical endpoint-encrypted group-media frame using endpoint-held MLS exporter
/// material and the trusted source Device Ed25519 verification key.
///
/// This function intentionally owns no membership lookup or authorization policy. Those remain in
/// the caller's canonical endpoint state. It validates the exact frame/context binding and source
/// signature before decrypting.
///
/// # Errors
/// Rejects malformed/cross-context frames, malformed signatures, signature forgery, key-derivation
/// failures, or AEAD integrity failures.
pub fn open_endpoint_group_media_payload(
    epoch_secret: &GroupMediaEpochSecret,
    context: &GroupMediaE2eeContext,
    frame: &EncryptedGroupMediaFrame,
    source_verifying_key: VerifyingKeyBytes,
) -> Result<Vec<u8>, EndpointGroupMediaCryptoError> {
    validate_encrypted_group_media_frame(context, frame)?;
    let signature_bytes: [u8; 64] = frame
        .source_signature
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| EndpointGroupMediaCryptoError::InvalidSignatureBytes)?;
    let signing_binding =
        group_media_source_signing_binding(&frame.header, &frame.nonce, &frame.ciphertext)?;
    verify_group_media_binding_signature(
        source_verifying_key,
        &signing_binding,
        SignatureBytes(signature_bytes),
    )?;
    let traffic_key = derive_group_media_traffic_key(
        epoch_secret,
        context,
        &frame.header.source,
        &frame.header.source_device_id,
        &frame.header.stream_id,
        frame.header.media_kind,
    )?;
    let aad = group_media_frame_aad(&frame.header)?;
    Ok(traffic_key.decrypt(
        &crate::Ciphertext {
            nonce: frame.nonce,
            bytes: frame.ciphertext.clone(),
        },
        &aad,
    )?)
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use ucr_model::{
        CallId, CryptoSuite, GroupId, PrincipalId, PrincipalKind, TenantId, TenantScope,
        VideoSourceKind,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn context() -> GroupMediaE2eeContext {
        GroupMediaE2eeContext {
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant")),
                namespace_id: None,
            },
            call_id: CallId::from_opaque(oid("call")),
            group_id: GroupId::from_opaque(oid("group")),
            negotiation_ref: oid("negotiation"),
            negotiation_generation: 1,
            crypto_epoch: 7,
            crypto_state_ref: oid("crypto-state"),
            crypto_suite: CryptoSuite::UcrV1,
        }
    }

    fn header(context: &GroupMediaE2eeContext) -> GroupMediaFrameHeader {
        GroupMediaFrameHeader {
            scope: context.scope.clone(),
            call_id: context.call_id.clone(),
            group_id: context.group_id.clone(),
            stream_id: oid("camera"),
            source: PrincipalRef {
                principal_id: PrincipalId::from_opaque(oid("alice")),
                kind: PrincipalKind::Person,
            },
            source_device_id: DeviceId::from_opaque(oid("alice-device")),
            negotiation_ref: context.negotiation_ref.clone(),
            negotiation_generation: context.negotiation_generation,
            crypto_epoch: context.crypto_epoch,
            crypto_state_ref: context.crypto_state_ref.clone(),
            crypto_suite: context.crypto_suite,
            header_version: 2,
            media_kind: MediaKind::Video,
            video_source_kind: Some(VideoSourceKind::Camera),
            sequence: 1,
            media_timestamp: 90_000,
            keyframe: true,
        }
    }

    #[test]
    fn endpoint_group_media_core_round_trips_and_verifies_source_signature() {
        let context = context();
        let epoch_secret = GroupMediaEpochSecret::from_exporter_bytes([7; 32]);
        let signer = SigningKeyMaterial::generate().expect("signer");
        let frame = seal_endpoint_group_media_payload(
            &epoch_secret,
            &context,
            header(&context),
            b"endpoint frame",
            KeyId::from_opaque(oid("signing-key")),
            &signer,
        )
        .expect("seal");

        let plaintext = open_endpoint_group_media_payload(
            &epoch_secret,
            &context,
            &frame,
            signer.verifying_key(),
        )
        .expect("open");
        assert_eq!(plaintext, b"endpoint frame");
    }

    #[test]
    fn endpoint_group_media_core_rejects_signature_and_context_tampering() {
        let context = context();
        let epoch_secret = GroupMediaEpochSecret::from_exporter_bytes([9; 32]);
        let signer = SigningKeyMaterial::generate().expect("signer");
        let mut frame = seal_endpoint_group_media_payload(
            &epoch_secret,
            &context,
            header(&context),
            b"protected",
            KeyId::from_opaque(oid("signing-key")),
            &signer,
        )
        .expect("seal");

        frame.source_signature.signature[0] ^= 1;
        assert!(matches!(
            open_endpoint_group_media_payload(
                &epoch_secret,
                &context,
                &frame,
                signer.verifying_key(),
            ),
            Err(EndpointGroupMediaCryptoError::Signature(
                SignatureError::InvalidSignature
            ))
        ));

        let mut wrong_context = context.clone();
        wrong_context.crypto_epoch += 1;
        assert!(matches!(
            open_endpoint_group_media_payload(
                &epoch_secret,
                &wrong_context,
                &seal_endpoint_group_media_payload(
                    &epoch_secret,
                    &context,
                    header(&context),
                    b"protected",
                    KeyId::from_opaque(oid("signing-key-2")),
                    &signer,
                )
                .expect("seal"),
                signer.verifying_key(),
            ),
            Err(EndpointGroupMediaCryptoError::Protocol(
                GroupMediaE2eeProtocolError::ContextMismatch
            ))
        ));
    }
}

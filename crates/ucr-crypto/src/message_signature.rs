use ucr_model::{CryptoSuite, KeyPurpose, MessageEnvelope, PublicKeyDescriptor};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, CryptoContractError, MessageError, message_signing_binding,
    validate_public_key_descriptor,
};

use crate::{
    SignatureBytes, SignatureError, TrustedKeyResolutionError, TrustedSigningKeyResolver,
    VerifyingKeyBytes, verify_message_binding_signature,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSignatureVerificationError {
    MissingSignature,
    InvalidMessage(MessageError),
    InvalidTrustedKeyDescriptor(CryptoContractError),
    WrongKeyPurpose,
    KeyIdMismatch,
    AuthorDeviceMismatch,
    InvalidPublicKey,
    InvalidSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedMessageSignatureError {
    Trust(TrustedKeyResolutionError),
    Verification(MessageSignatureVerificationError),
}

impl From<MessageSignatureVerificationError> for CanonicalError {
    fn from(error: MessageSignatureVerificationError) -> Self {
        match error {
            MessageSignatureVerificationError::InvalidMessage(error) => error.into(),
            MessageSignatureVerificationError::InvalidTrustedKeyDescriptor(_) => {
                Self::new(CanonicalErrorCode::Internal)
            }
            MessageSignatureVerificationError::MissingSignature
            | MessageSignatureVerificationError::WrongKeyPurpose
            | MessageSignatureVerificationError::KeyIdMismatch
            | MessageSignatureVerificationError::AuthorDeviceMismatch
            | MessageSignatureVerificationError::InvalidPublicKey
            | MessageSignatureVerificationError::InvalidSignature => {
                Self::new(CanonicalErrorCode::Unauthenticated)
            }
        }
    }
}

/// Verifies a canonical Message signature against an already trusted public-key descriptor.
///
/// This function does not provision, discover, or trust keys. The caller must resolve a trusted
/// descriptor through the separate key-lifecycle layer. Verification binds the descriptor to the
/// Message signature key ID and author device before checking Ed25519 over canonical signing bytes.
///
/// # Errors
/// Fails closed for missing/malformed signatures, descriptor mismatch, author-device mismatch,
/// malformed public keys, or cryptographic verification failure.
pub fn verify_message_signature(
    message: &MessageEnvelope,
    trusted_descriptor: &PublicKeyDescriptor,
) -> Result<(), MessageSignatureVerificationError> {
    let signature = message
        .signature
        .as_ref()
        .ok_or(MessageSignatureVerificationError::MissingSignature)?;
    let binding = message_signing_binding(message)
        .map_err(MessageSignatureVerificationError::InvalidMessage)?;

    if trusted_descriptor.purpose != KeyPurpose::Signing {
        return Err(MessageSignatureVerificationError::WrongKeyPurpose);
    }
    validate_public_key_descriptor(CryptoSuite::UcrV1, trusted_descriptor)
        .map_err(MessageSignatureVerificationError::InvalidTrustedKeyDescriptor)?;
    if signature.key_id != trusted_descriptor.key_id {
        return Err(MessageSignatureVerificationError::KeyIdMismatch);
    }
    if trusted_descriptor.device_id != message.author_device.device_id {
        return Err(MessageSignatureVerificationError::AuthorDeviceMismatch);
    }

    let public_key: [u8; 32] = trusted_descriptor
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| MessageSignatureVerificationError::InvalidPublicKey)?;
    let signature_bytes: [u8; 64] = signature
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MessageSignatureVerificationError::InvalidSignature)?;
    verify_message_binding_signature(
        VerifyingKeyBytes(public_key),
        &binding,
        SignatureBytes(signature_bytes),
    )
    .map_err(map_signature_error)
}

/// Resolves the Message author's active trusted signing key and verifies the signature.
///
/// The Message-provided key ID is only a lookup claim. The resolver must independently
/// establish active trust for the exact scope/device/key tuple.
///
/// # Errors
/// Returns a non-disclosing trust failure or the underlying fail-closed signature error.
pub fn verify_message_signature_with_trust<R: TrustedSigningKeyResolver>(
    message: &MessageEnvelope,
    resolver: &R,
) -> Result<(), TrustedMessageSignatureError> {
    let signature =
        message
            .signature
            .as_ref()
            .ok_or(TrustedMessageSignatureError::Verification(
                MessageSignatureVerificationError::MissingSignature,
            ))?;
    let trusted = resolver
        .resolve_active_signing_key(
            &message.scope,
            &message.author_device.device_id,
            Some(&message.author_device.identity_id),
            &signature.key_id,
        )
        .map_err(TrustedMessageSignatureError::Trust)?;
    verify_message_signature(message, &trusted).map_err(TrustedMessageSignatureError::Verification)
}

const fn map_signature_error(error: SignatureError) -> MessageSignatureVerificationError {
    match error {
        SignatureError::InvalidPublicKey => MessageSignatureVerificationError::InvalidPublicKey,
        SignatureError::InvalidSignature | SignatureError::OsRandomUnavailable => {
            MessageSignatureVerificationError::InvalidSignature
        }
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::*;
    use ucr_protocol::{
        ALGORITHM_VERSION, KEY_FORMAT_VERSION, SIGNATURE_ALGORITHM_ID, message_signing_binding,
    };

    use super::*;
    use crate::{SigningKeyHandle, SigningKeyMaterial};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn message() -> MessageEnvelope {
        MessageEnvelope {
            message_id: MessageId::from_opaque(oid("message-a")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: None,
            },
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation-a")),
                kind: ConversationKind::Direct,
            },
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::Person,
                on_behalf_of: None,
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            created_at_unix_ms: 100,
            logical_order: 7,
            content: b"signed content".to_vec(),
            attachment_ids: Vec::new(),
            reply_to: None,
            relations: Vec::new(),
            crypto_metadata: None,
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(PrincipalId::from_opaque(oid("principal-a"))),
                endpoint_id: None,
                integration_id: None,
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: None,
                idempotency_key: Some("idempotency-a".to_owned()),
            },
            extensions: Vec::new(),
            external_mappings: Vec::new(),
            signature: None,
        }
    }

    fn sign(
        mut message: MessageEnvelope,
        key: &SigningKeyMaterial,
        key_id: KeyId,
    ) -> MessageEnvelope {
        let binding = message_signing_binding(&message).expect("message binding");
        let signature = SigningKeyHandle::sign_message_binding(key, &binding).expect("sign");
        message.signature = Some(MessageSignature {
            key_id,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            signature: signature.0.to_vec(),
        });
        message
    }

    fn descriptor(
        key: &SigningKeyMaterial,
        key_id: KeyId,
        device_id: DeviceId,
    ) -> PublicKeyDescriptor {
        PublicKeyDescriptor {
            key_id,
            device_id,
            purpose: KeyPurpose::Signing,
            algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
            algorithm_version: ALGORITHM_VERSION,
            key_format_version: KEY_FORMAT_VERSION,
            public_key: key.verifying_key().0.to_vec(),
        }
    }

    #[test]
    fn trusted_author_device_signature_verifies_and_runtime_fields_do_not_break_it() {
        let key = SigningKeyMaterial::generate().expect("signing key");
        let key_id = KeyId::from_opaque(oid("key-a"));
        let mut signed = sign(message(), &key, key_id.clone());
        let trusted = descriptor(&key, key_id, signed.author_device.device_id.clone());
        assert_eq!(verify_message_signature(&signed, &trusted), Ok(()));

        signed.delivery_state = DeliveryState::Persisted;
        signed.external_mappings.push(ExternalMessageMapping {
            integration_id: IntegrationId::from_opaque(oid("integration-a")),
            external_message_id: b"provider-id".to_vec(),
        });
        assert_eq!(verify_message_signature(&signed, &trusted), Ok(()));
    }

    #[test]
    fn authored_tampering_and_wrong_crypto_key_fail_closed() {
        let key = SigningKeyMaterial::generate().expect("signing key");
        let key_id = KeyId::from_opaque(oid("key-a"));
        let signed = sign(message(), &key, key_id.clone());
        let trusted = descriptor(&key, key_id.clone(), signed.author_device.device_id.clone());

        let mut tampered = signed.clone();
        tampered.content.push(b'!');
        assert_eq!(
            verify_message_signature(&tampered, &trusted),
            Err(MessageSignatureVerificationError::InvalidSignature)
        );

        let other_key = SigningKeyMaterial::generate().expect("other key");
        let wrong_crypto = descriptor(&other_key, key_id, signed.author_device.device_id.clone());
        assert_eq!(
            verify_message_signature(&signed, &wrong_crypto),
            Err(MessageSignatureVerificationError::InvalidSignature)
        );
    }

    #[test]
    fn key_id_and_author_device_are_bound_before_crypto_verification() {
        let key = SigningKeyMaterial::generate().expect("signing key");
        let key_id = KeyId::from_opaque(oid("key-a"));
        let mut signed = sign(message(), &key, key_id.clone());
        let trusted = descriptor(&key, key_id, signed.author_device.device_id.clone());

        signed.signature.as_mut().expect("signature").key_id = KeyId::from_opaque(oid("key-b"));
        assert_eq!(
            verify_message_signature(&signed, &trusted),
            Err(MessageSignatureVerificationError::KeyIdMismatch)
        );

        let signed = sign(message(), &key, KeyId::from_opaque(oid("key-a")));
        let wrong_device = descriptor(
            &key,
            KeyId::from_opaque(oid("key-a")),
            DeviceId::from_opaque(oid("device-b")),
        );
        assert_eq!(
            verify_message_signature(&signed, &wrong_device),
            Err(MessageSignatureVerificationError::AuthorDeviceMismatch)
        );
    }

    #[test]
    fn missing_signature_and_malformed_trusted_descriptor_fail_closed() {
        let unsigned = message();
        let key = SigningKeyMaterial::generate().expect("signing key");
        let trusted = descriptor(
            &key,
            KeyId::from_opaque(oid("key-a")),
            unsigned.author_device.device_id.clone(),
        );
        assert_eq!(
            verify_message_signature(&unsigned, &trusted),
            Err(MessageSignatureVerificationError::MissingSignature)
        );

        let signed = sign(unsigned, &key, KeyId::from_opaque(oid("key-a")));
        let mut malformed = trusted;
        malformed.public_key.pop();
        assert_eq!(
            verify_message_signature(&signed, &malformed),
            Err(
                MessageSignatureVerificationError::InvalidTrustedKeyDescriptor(
                    CryptoContractError::WrongPublicKeyLength
                )
            )
        );
        assert_eq!(
            CanonicalError::from(MessageSignatureVerificationError::MissingSignature).code,
            CanonicalErrorCode::Unauthenticated
        );
        assert_eq!(
            CanonicalError::from(
                MessageSignatureVerificationError::InvalidTrustedKeyDescriptor(
                    CryptoContractError::WrongPublicKeyLength
                )
            )
            .code,
            CanonicalErrorCode::Internal
        );
    }
}

use std::{collections::HashSet, sync::Mutex};

use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::x25519;

use crate::kdf::derive_session_secrets;

fn test_binding(result: &[u8]) -> TranscriptBinding {
    bind_handshake_transcript(
        b"initiator-hello-frame",
        b"responder-hello-frame",
        result,
        AgreementPublicKey([1_u8; 32]),
        AgreementPublicKey([2_u8; 32]),
    )
    .expect("complete transcript")
}

use crate::{
    AgreementError, AgreementKeyPair, AgreementPublicKey, ReplayError, ReplayProtector,
    SessionError, SessionHandshakeInput, SessionRole, SigningKeyMaterial, TranscriptBinding,
    VerifyingKeyBytes, begin_session, bind_handshake_transcript, verify_transcript_signature,
};

#[test]
fn generated_signing_key_authenticates_transcript() {
    let key = SigningKeyMaterial::generate().expect("OS randomness");
    let binding = test_binding(b"result");
    let signature = key.sign_transcript(&binding);
    verify_transcript_signature(key.verifying_key(), &binding, signature).expect("signature valid");

    let changed = test_binding(b"changed");
    assert!(verify_transcript_signature(key.verifying_key(), &changed, signature).is_err());
}

#[test]
fn x25519_agreement_derives_matching_directional_secrets() {
    let initiator = AgreementKeyPair::generate().expect("OS randomness");
    let responder = AgreementKeyPair::generate().expect("OS randomness");
    let initiator_public = initiator.public_key();
    let responder_public = responder.public_key();
    let initiator_shared = initiator.agree(responder_public).expect("agreement");
    let responder_shared = responder.agree(initiator_public).expect("agreement");
    assert_eq!(initiator_shared.as_ref(), responder_shared.as_ref());

    let binding = test_binding(b"negotiated-session");
    let i = derive_session_secrets(
        &initiator_shared,
        &binding,
        initiator_public,
        responder_public,
    )
    .expect("derive initiator");
    let r = derive_session_secrets(
        &responder_shared,
        &binding,
        initiator_public,
        responder_public,
    )
    .expect("derive responder");

    let ciphertext = i
        .initiator_to_responder
        .encrypt(b"secret payload", b"header")
        .expect("encrypt");
    assert_eq!(
        r.initiator_to_responder
            .decrypt(&ciphertext, b"header")
            .expect("decrypt"),
        b"secret payload"
    );
    assert!(
        r.initiator_to_responder
            .decrypt(&ciphertext, b"wrong")
            .is_err()
    );

    let initiator_tag = i
        .initiator_confirmation
        .tag(&binding)
        .expect("confirmation tag");
    r.initiator_confirmation
        .verify(&binding, initiator_tag)
        .expect("confirmation valid");
}

#[test]
fn non_contributory_x25519_peer_key_is_rejected() {
    let local = AgreementKeyPair::generate().expect("OS randomness");
    assert_eq!(
        local.agree(AgreementPublicKey([0_u8; 32])),
        Err(AgreementError::NonContributoryPeerKey)
    );
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("valid test vector");
    }
    output
}

#[test]
fn rfc7748_x25519_vector_is_supported() {
    let scalar =
        decode_hex::<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let point =
        decode_hex::<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let expected =
        decode_hex::<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    assert_eq!(x25519(scalar, point), expected);
}

#[test]
fn rfc8032_ed25519_vector_one_is_supported() {
    let seed = decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_public =
        decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_signature = decode_hex::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(key.verifying_key().to_bytes(), expected_public);
    assert_eq!(key.sign(b"").to_bytes(), expected_signature);
}

#[test]
fn rfc5869_hkdf_sha256_vector_one_is_supported() {
    let ikm = [0x0b_u8; 22];
    let salt = decode_hex::<13>("000102030405060708090a0b0c");
    let info = decode_hex::<10>("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = decode_hex::<42>(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0_u8; 42];
    hkdf.expand(&info, &mut okm)
        .expect("RFC output length valid");
    assert_eq!(okm, expected_okm);
}

#[test]
fn aead_tampering_never_returns_partial_plaintext() {
    let initiator = AgreementKeyPair::generate().expect("OS randomness");
    let responder = AgreementKeyPair::generate().expect("OS randomness");
    let initiator_public = initiator.public_key();
    let responder_public = responder.public_key();
    let shared = initiator.agree(responder_public).expect("agreement");
    let binding = test_binding(b"tamper-test");
    let secrets = derive_session_secrets(&shared, &binding, initiator_public, responder_public)
        .expect("derive");
    let original = secrets
        .initiator_to_responder
        .encrypt(b"classified", b"aad")
        .expect("encrypt");

    let mut changed_ciphertext = original.clone();
    changed_ciphertext.bytes[0] ^= 1;
    assert!(
        secrets
            .initiator_to_responder
            .decrypt(&changed_ciphertext, b"aad")
            .is_err()
    );

    let mut changed_nonce = original.clone();
    changed_nonce.nonce[0] ^= 1;
    assert!(
        secrets
            .initiator_to_responder
            .decrypt(&changed_nonce, b"aad")
            .is_err()
    );
    assert!(
        secrets
            .initiator_to_responder
            .decrypt(&original, b"wrong-aad")
            .is_err()
    );
}

#[test]
fn aead_requires_context_and_enforces_budgets_before_allocation() {
    let initiator = AgreementKeyPair::generate().expect("OS randomness");
    let responder = AgreementKeyPair::generate().expect("OS randomness");
    let initiator_public = initiator.public_key();
    let responder_public = responder.public_key();
    let shared = initiator.agree(responder_public).expect("agreement");
    let binding = test_binding(b"budget-test");
    let secrets = derive_session_secrets(&shared, &binding, initiator_public, responder_public)
        .expect("derive");

    assert_eq!(
        secrets.initiator_to_responder.encrypt(b"payload", b""),
        Err(crate::AeadError::EmptyAssociatedData)
    );
    let oversized_aad = vec![0_u8; crate::aead::MAX_AAD_LEN + 1];
    assert_eq!(
        secrets
            .initiator_to_responder
            .encrypt(b"payload", &oversized_aad),
        Err(crate::AeadError::AssociatedDataTooLarge)
    );
    let oversized_payload = vec![0_u8; crate::aead::MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        secrets
            .initiator_to_responder
            .encrypt(&oversized_payload, b"header"),
        Err(crate::AeadError::PayloadTooLarge)
    );
}

#[derive(Debug, Default)]
struct TestReplayProtector {
    seen: Mutex<HashSet<([u8; 32], [u8; 32])>>,
}

impl ReplayProtector for TestReplayProtector {
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError> {
        let mut seen = self.seen.lock().map_err(|_| ReplayError::Internal)?;
        if !seen.insert((peer_verifying_key.0, *binding.as_bytes())) {
            return Err(ReplayError::Replayed);
        }
        Ok(())
    }
}

#[test]
fn session_requires_authentication_replay_check_and_key_confirmation() {
    let initiator_signing = SigningKeyMaterial::generate().expect("initiator signing");
    let responder_signing = SigningKeyMaterial::generate().expect("responder signing");
    let initiator_agreement = AgreementKeyPair::generate().expect("initiator agreement");
    let responder_agreement = AgreementKeyPair::generate().expect("responder agreement");
    let initiator_public = initiator_agreement.public_key();
    let responder_public = responder_agreement.public_key();
    let binding = test_binding(b"suite-v1");

    let initiator_replay = TestReplayProtector::default();
    let responder_replay = TestReplayProtector::default();
    let initiator_pending = begin_session(
        initiator_agreement,
        SessionHandshakeInput {
            suite: ucr_model::CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: responder_public,
            initiator_public,
            responder_public,
            trusted_peer_verifying_key: responder_signing.verifying_key(),
            peer_signature: responder_signing.sign_transcript(&binding),
            binding,
        },
        &initiator_replay,
    )
    .expect("initiator pending");
    let responder_pending = begin_session(
        responder_agreement,
        SessionHandshakeInput {
            suite: ucr_model::CryptoSuite::UcrV1,
            role: SessionRole::Responder,
            peer_agreement: initiator_public,
            initiator_public,
            responder_public,
            trusted_peer_verifying_key: initiator_signing.verifying_key(),
            peer_signature: initiator_signing.sign_transcript(&binding),
            binding,
        },
        &responder_replay,
    )
    .expect("responder pending");
    let initiator_tag = initiator_pending
        .local_confirmation_tag()
        .expect("initiator confirmation");
    let responder_tag = responder_pending
        .local_confirmation_tag()
        .expect("responder confirmation");

    let initiator_session = initiator_pending
        .confirm_peer(responder_tag)
        .expect("initiator established");
    let responder_session = responder_pending
        .confirm_peer(initiator_tag)
        .expect("responder established");
    let ciphertext = initiator_session
        .encrypt_outbound(b"application-data", b"session-aad")
        .expect("encrypt established session");
    assert_eq!(
        responder_session
            .decrypt_inbound(&ciphertext, b"session-aad")
            .expect("decrypt established session"),
        b"application-data"
    );
}

#[test]
fn session_rejects_local_ephemeral_key_not_bound_in_transcript() {
    let peer_signing = SigningKeyMaterial::generate().expect("peer signing");
    let advertised_local = AgreementKeyPair::generate().expect("advertised local");
    let actual_local = AgreementKeyPair::generate().expect("actual local");
    let peer_agreement = AgreementKeyPair::generate().expect("peer agreement");
    let initiator_public = advertised_local.public_key();
    let responder_public = peer_agreement.public_key();
    let binding = test_binding(b"local-key-mismatch");
    let result = begin_session(
        actual_local,
        SessionHandshakeInput {
            suite: ucr_model::CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: responder_public,
            initiator_public,
            responder_public,
            trusted_peer_verifying_key: peer_signing.verifying_key(),
            peer_signature: peer_signing.sign_transcript(&binding),
            binding,
        },
        &TestReplayProtector::default(),
    );
    assert!(matches!(
        result,
        Err(SessionError::LocalAgreementKeyMismatch)
    ));
}

#[test]
fn replay_rejection_precedes_key_agreement_work() {
    #[derive(Debug)]
    struct AlwaysReplay;

    impl ReplayProtector for AlwaysReplay {
        fn record_once(
            &self,
            _peer_verifying_key: &VerifyingKeyBytes,
            _binding: &TranscriptBinding,
        ) -> Result<(), ReplayError> {
            Err(ReplayError::Replayed)
        }
    }

    let peer_signing = SigningKeyMaterial::generate().expect("peer signing");
    let local = AgreementKeyPair::generate().expect("local agreement");
    let local_public = local.public_key();
    let binding = test_binding(b"replay-before-agreement");
    let result = begin_session(
        local,
        SessionHandshakeInput {
            suite: ucr_model::CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: AgreementPublicKey([0_u8; 32]),
            initiator_public: local_public,
            responder_public: AgreementPublicKey([0_u8; 32]),
            trusted_peer_verifying_key: peer_signing.verifying_key(),
            peer_signature: peer_signing.sign_transcript(&binding),
            binding,
        },
        &AlwaysReplay,
    );
    assert!(matches!(
        result,
        Err(SessionError::Replay(ReplayError::Replayed))
    ));
}

#[test]
fn session_rejects_peer_ephemeral_key_not_bound_in_transcript() {
    let peer_signing = SigningKeyMaterial::generate().expect("peer signing");
    let local = AgreementKeyPair::generate().expect("local agreement");
    let transcript_peer = AgreementKeyPair::generate().expect("transcript peer");
    let unbound_peer = AgreementKeyPair::generate().expect("unbound peer");
    let local_public = local.public_key();
    let binding = test_binding(b"peer-key-binding");

    let result = begin_session(
        local,
        SessionHandshakeInput {
            suite: ucr_model::CryptoSuite::UcrV1,
            role: SessionRole::Initiator,
            peer_agreement: unbound_peer.public_key(),
            initiator_public: local_public,
            responder_public: transcript_peer.public_key(),
            trusted_peer_verifying_key: peer_signing.verifying_key(),
            peer_signature: peer_signing.sign_transcript(&binding),
            binding,
        },
        &TestReplayProtector::default(),
    );
    assert!(matches!(
        result,
        Err(SessionError::PeerAgreementKeyMismatch)
    ));
}

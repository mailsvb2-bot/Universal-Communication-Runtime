#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_crypto::{
    RecoverySecret, SignatureBytes, TranscriptBinding, VerifyingKeyBytes, open_recovery_material,
    verify_message_binding_signature, verify_transcript_signature,
};
use ucr_model::{
    CryptoSuite, DeviceId, DeviceLifecycleState, EncryptedRecoveryPackage, HistoricalMessageAccess,
    IdentityId, KeyId, KeyPurpose, OpaqueId, PublicKeyDescriptor, RecoveryAuthority,
    RecoveryPackageAlgorithm, RecoveryPlan, RecoveryPlanId, RecoveryTrustModel, TenantId,
    TenantScope,
};
use ucr_protocol::{MessageSigningBinding, validate_public_key_descriptor};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static fuzz id")
}

fn recovery_plan() -> RecoveryPlan {
    RecoveryPlan {
        plan_id: RecoveryPlanId::from_opaque(oid("fuzz-recovery-plan")),
        scope: TenantScope {
            tenant_id: TenantId::from_opaque(oid("fuzz-tenant")),
            namespace_id: None,
        },
        identity_id: IdentityId::from_opaque(oid("fuzz-identity")),
        authorities: vec![RecoveryAuthority::RecoveryKey],
        historical_message_access: HistoricalMessageAccess::ExplicitEncryptedRecovery,
        trust_model: RecoveryTrustModel::UserControlled,
        recovered_device_state: DeviceLifecycleState::ReverificationRequired,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut key = [0_u8; 32];
    let key_len = data.len().min(32);
    key[..key_len].copy_from_slice(&data[..key_len]);

    let mut signature = [0_u8; 64];
    if data.len() > 32 {
        let available = (data.len() - 32).min(64);
        signature[..available].copy_from_slice(&data[32..32 + available]);
    }

    let mut binding = [0_u8; 32];
    if data.len() > 96 {
        let available = (data.len() - 96).min(32);
        binding[..available].copy_from_slice(&data[96..96 + available]);
    }
    let verifying_key = VerifyingKeyBytes(key);
    let signature = SignatureBytes(signature);
    let message_binding = MessageSigningBinding::from_bytes(binding);
    let transcript_binding = TranscriptBinding::from_bytes(binding);

    let _ = verify_message_binding_signature(verifying_key, &message_binding, signature);
    let _ = verify_transcript_signature(verifying_key, &transcript_binding, signature);

    let descriptor = PublicKeyDescriptor {
        key_id: KeyId::from_opaque(oid("fuzz-key")),
        device_id: DeviceId::from_opaque(oid("fuzz-device")),
        purpose: if data.first().copied().unwrap_or(0) & 1 == 0 {
            KeyPurpose::Signing
        } else {
            KeyPurpose::KeyAgreement
        },
        algorithm_id: if data.get(1).copied().unwrap_or(0) & 1 == 0 {
            "ed25519".to_owned()
        } else {
            "x25519".to_owned()
        },
        algorithm_version: u32::from(data.get(2).copied().unwrap_or(0)),
        key_format_version: u32::from(data.get(3).copied().unwrap_or(0)),
        public_key: data.iter().take(40).copied().collect(),
    };
    let _ = validate_public_key_descriptor(CryptoSuite::UcrV1, &descriptor);

    let secret = RecoverySecret::import_user_backup([7_u8; 32]).expect("fixed non-zero secret");
    let mut nonce = [0_u8; 24];
    let nonce_len = data.len().min(nonce.len());
    nonce[..nonce_len].copy_from_slice(&data[..nonce_len]);
    let package = EncryptedRecoveryPackage {
        algorithm: RecoveryPackageAlgorithm::UcrV1,
        format_version: u32::from_be_bytes([
            data.first().copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]),
        nonce,
        ciphertext: data.iter().skip(24).take(232).copied().collect(),
    };
    let _ = open_recovery_material(&secret, &recovery_plan(), &package);
});

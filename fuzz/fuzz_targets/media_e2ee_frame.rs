#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::{
    CallId, CryptoSuite, DeviceId, EncryptedMediaFrame, MediaE2eeContext, MediaE2eeFrameHeader,
    MediaKind, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, TenantId, TenantScope,
};
use ucr_protocol::{media_e2ee_frame_aad, validate_encrypted_media_frame};

fn oid(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("static fuzz id")
}

fn principal(value: &str) -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid(value)),
        kind: PrincipalKind::Person,
    }
}

fuzz_target!(|data: &[u8]| {
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(oid("fuzz-media-tenant")),
        namespace_id: None,
    };
    let alice = principal("fuzz-media-alice");
    let bob = principal("fuzz-media-bob");
    let context = MediaE2eeContext {
        scope: scope.clone(),
        call_id: CallId::from_opaque(oid("fuzz-media-call")),
        initiator: alice.clone(),
        responder: bob.clone(),
        initiator_device_id: DeviceId::from_opaque(oid("fuzz-media-device-a")),
        responder_device_id: DeviceId::from_opaque(oid("fuzz-media-device-b")),
        negotiation_ref: oid("fuzz-media-negotiation"),
        negotiation_generation: u64::from(data.first().copied().unwrap_or(0)).saturating_add(1),
        key_epoch: u64::from(data.get(1).copied().unwrap_or(0)).saturating_add(1),
        crypto_suite: CryptoSuite::UcrV1,
    };
    let mut session_binding = [0_u8; 32];
    for (target, source) in session_binding.iter_mut().zip(data.iter().copied()) {
        *target = source;
    }
    if session_binding.iter().all(|byte| *byte == 0) {
        session_binding[0] = 1;
    }
    let header = MediaE2eeFrameHeader {
        scope,
        call_id: context.call_id.clone(),
        stream_id: oid("fuzz-media-stream"),
        source: alice,
        recipient: bob,
        negotiation_ref: context.negotiation_ref.clone(),
        negotiation_generation: context.negotiation_generation,
        key_epoch: context.key_epoch,
        crypto_suite: CryptoSuite::UcrV1,
        session_binding,
        media_kind: if data.get(2).copied().unwrap_or(0) & 1 == 0 {
            MediaKind::Audio
        } else {
            MediaKind::Video
        },
        sequence: u64::from_be_bytes(data.get(3..11).unwrap_or(&[]).try_into().unwrap_or([0; 8])),
        media_timestamp: u64::from_be_bytes(
            data.get(11..19).unwrap_or(&[]).try_into().unwrap_or([0; 8]),
        ),
        keyframe: data.get(19).copied().unwrap_or(0) & 1 != 0,
    };
    let _ = media_e2ee_frame_aad(&header);
    let frame = EncryptedMediaFrame {
        header,
        nonce: [0_u8; 24],
        ciphertext: data.iter().skip(20).copied().collect(),
    };
    let _ = validate_encrypted_media_frame(&context, &frame);
});

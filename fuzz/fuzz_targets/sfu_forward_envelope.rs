#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::*;
use ucr_protocol::{ALGORITHM_VERSION, SIGNATURE_ALGORITHM_ID, canonical_sfu_forward_envelope};

fn oid(prefix: &str, value: u8) -> OpaqueId {
    OpaqueId::new(format!("{prefix}-{value:02x}")).expect("bounded fuzz id")
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let a = data[0];
    let b = data.get(1).copied().unwrap_or(a.wrapping_add(1));
    let media_kind = if data.get(2).is_some_and(|value| value & 1 == 1) {
        MediaKind::Audio
    } else {
        MediaKind::Video
    };
    let source = PrincipalRef {
        principal_id: PrincipalId::from_opaque(oid("sfu-person", a)),
        kind: PrincipalKind::Person,
    };
    let ciphertext = if data.len() > 8 {
        data[8..].to_vec()
    } else {
        vec![a]
    };
    let signature_len = if data.get(3).is_some_and(|value| value & 1 == 1) {
        64
    } else {
        usize::from(data.get(4).copied().unwrap_or(1))
    };
    let envelope = SfuForwardEnvelope {
        frame: EncryptedGroupMediaFrame {
            header: GroupMediaFrameHeader {
                scope: TenantScope {
                    tenant_id: TenantId::from_opaque(oid("sfu-tenant", a)),
                    namespace_id: None,
                },
                call_id: CallId::from_opaque(oid("sfu-call", b)),
                group_id: GroupId::from_opaque(oid("sfu-group", a ^ b)),
                stream_id: oid("sfu-stream", a),
                source,
                source_device_id: DeviceId::from_opaque(oid("sfu-device", a)),
                negotiation_ref: oid("sfu-negotiation", b),
                negotiation_generation: u64::from(data.get(5).copied().unwrap_or(1)),
                crypto_epoch: u64::from(data.get(6).copied().unwrap_or(0)),
                crypto_state_ref: oid("sfu-mls-state", data.get(6).copied().unwrap_or(0)),
                crypto_suite: CryptoSuite::UcrV1,
                media_kind,
                sequence: u64::from(a),
                media_timestamp: u64::from(b),
                keyframe: data.get(7).is_some_and(|value| value & 1 == 1),
            },
            nonce: [data.get(7).copied().unwrap_or(1); 24],
            ciphertext,
            source_signature: GroupMediaSourceSignature {
                key_id: KeyId::from_opaque(oid("sfu-key", a)),
                algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                algorithm_version: ALGORITHM_VERSION,
                signature: vec![data.get(4).copied().unwrap_or(7); signature_len],
            },
        },
    };
    let _ = canonical_sfu_forward_envelope(&envelope);
});

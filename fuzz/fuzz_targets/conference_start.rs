#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::{
    CallId, ConferenceMediaSubscription, ConferenceStart, ConferenceSubscriptionSet, GroupId,
    MediaKind, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, TenantId, TenantScope,
};
use ucr_protocol::{canonical_conference_start, canonical_conference_subscription_set};

fn opaque(prefix: &str, bytes: &[u8]) -> OpaqueId {
    let mut text = String::with_capacity(prefix.len() + bytes.len() * 2);
    text.push_str(prefix);
    for byte in bytes.iter().take(48) {
        use core::fmt::Write as _;
        let _ = write!(&mut text, "{byte:02x}");
    }
    OpaqueId::new(&text).unwrap_or_else(|_| OpaqueId::new(prefix).expect("static id"))
}

fn principal(prefix: &str, bytes: &[u8]) -> PrincipalRef {
    PrincipalRef {
        principal_id: PrincipalId::from_opaque(opaque(prefix, bytes)),
        kind: PrincipalKind::Person,
    }
}

fuzz_target!(|data: &[u8]| {
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(opaque("tenant-", data.get(..8).unwrap_or(data))),
        namespace_id: None,
    };
    let actor = principal("actor-", data.get(8..16).unwrap_or(data));
    let count = data
        .get(..2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0) as usize
        % 1100;
    let mut invitees = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 2 + (index % 100).saturating_mul(3);
        let end = (offset + 3).min(data.len());
        let bytes = data.get(offset..end).unwrap_or(&[]);
        invitees.push(principal(&format!("p{index}-"), bytes));
    }
    let call_id = CallId::from_opaque(opaque("call-", data.get(16..24).unwrap_or(data)));
    let start = ConferenceStart {
        scope: scope.clone(),
        call_id: call_id.clone(),
        group_id: GroupId::from_opaque(opaque("group-", data.get(24..32).unwrap_or(data))),
        invitees,
    };
    let _ = canonical_conference_start(&start, &scope, &actor);

    let subscription_count = data.get(2).copied().unwrap_or(0) as usize % 40;
    let mut subscriptions = Vec::with_capacity(subscription_count);
    for index in 0..subscription_count {
        let offset = 32 + (index % 32).saturating_mul(2);
        let end = (offset + 2).min(data.len());
        subscriptions.push(ConferenceMediaSubscription {
            source: principal(
                &format!("source-{index}-"),
                data.get(offset..end).unwrap_or(&[]),
            ),
            media_kind: if data.get(offset).copied().unwrap_or(0) & 1 == 0 {
                MediaKind::Audio
            } else {
                MediaKind::Video
            },
        });
    }
    let set = ConferenceSubscriptionSet {
        scope: scope.clone(),
        call_id,
        subscriptions,
    };
    let _ = canonical_conference_subscription_set(&set, &scope, &actor);
});

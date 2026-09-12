#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_model::{
    BridgeAction, BridgeActionId, BridgeCapability, BridgeDataPermission, BridgeEventPage,
    BridgeInboundEvent, BridgeProviderManifest, CorrelationContext, IntegrationId, OpaqueId,
    ProtocolVersion, TenantId, TenantScope,
};
use ucr_protocol::{
    BRIDGE_SDK_VERSION, bridge_action_fingerprint, canonical_bridge_manifest,
    validate_bridge_event_page,
};

fn opaque(prefix: &str, bytes: &[u8]) -> OpaqueId {
    let mut text = String::from(prefix);
    for byte in bytes.iter().take(48) {
        use core::fmt::Write as _;
        let _ = write!(&mut text, "{byte:02x}");
    }
    OpaqueId::new(text).unwrap_or_else(|_| OpaqueId::new(prefix).expect("static id"))
}

fn capability(value: u8) -> BridgeCapability {
    match value % 13 {
        0 => BridgeCapability::Text,
        1 => BridgeCapability::Edit,
        2 => BridgeCapability::Delete,
        3 => BridgeCapability::Reaction,
        4 => BridgeCapability::Files,
        5 => BridgeCapability::Audio,
        6 => BridgeCapability::Video,
        7 => BridgeCapability::Group,
        8 => BridgeCapability::Presence,
        9 => BridgeCapability::Typing,
        10 => BridgeCapability::Calls,
        11 => BridgeCapability::Threads,
        _ => BridgeCapability::Reply,
    }
}

fuzz_target!(|data: &[u8]| {
    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(opaque("tenant-", data.get(..8).unwrap_or(data))),
        namespace_id: None,
    };
    let integration_id =
        IntegrationId::from_opaque(opaque("integration-", data.get(8..16).unwrap_or(data)));
    let cap_count = data.first().copied().unwrap_or(0) as usize % 20;
    let capabilities = (0..cap_count)
        .map(|index| capability(data.get(index + 1).copied().unwrap_or(index as u8)))
        .collect();
    let manifest = BridgeProviderManifest {
        provider_id: "vendor.fuzz.reference.bridge".to_owned(),
        sdk_min: BRIDGE_SDK_VERSION,
        sdk_max: BRIDGE_SDK_VERSION,
        protocol_min: ProtocolVersion::new(1, 0),
        protocol_max: ProtocolVersion::new(1, 0),
        capabilities,
        permissions: vec![
            BridgeDataPermission::MessageContent,
            BridgeDataPermission::InboundEvents,
        ],
        extensions: vec![],
    };
    let _ = canonical_bridge_manifest(&manifest);

    let payload = data
        .get(16..)
        .unwrap_or(&[])
        .iter()
        .copied()
        .take(4096)
        .collect();
    let action = BridgeAction {
        action_id: BridgeActionId::from_opaque(opaque("action-", data.get(4..12).unwrap_or(data))),
        scope: scope.clone(),
        integration_id: integration_id.clone(),
        capability: capability(data.get(1).copied().unwrap_or(0)),
        external_target: data.get(12..20).unwrap_or(data).to_vec(),
        canonical_message_id: None,
        provider_payload: payload,
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: opaque("correlation-", data.get(20..28).unwrap_or(data)),
            causation_id: None,
            idempotency_key: Some("bridge-fuzz".to_owned()),
        },
    };
    let _ = bridge_action_fingerprint(&action);

    let event_count = data.get(2).copied().unwrap_or(0) as usize % 300;
    let events = (0..event_count)
        .map(|index| BridgeInboundEvent {
            scope: scope.clone(),
            integration_id: integration_id.clone(),
            external_event_id: format!("event-{index}").into_bytes(),
            external_conversation_id: b"conversation".to_vec(),
            external_actor_id: None,
            capability: capability(index as u8),
            payload: data.iter().copied().take(1024).collect(),
            occurred_at_unix_ms: 1_700_000_000_000 + index as i64,
        })
        .collect();
    let _ = validate_bridge_event_page(&BridgeEventPage {
        events,
        next_cursor: None,
    });
});

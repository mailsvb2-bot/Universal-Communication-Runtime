#![no_main]

use libfuzzer_sys::fuzz_target;
use ucr_bridge::{BridgeProvider, BridgeProviderFailure};
use ucr_bridge_telegram::{
    TelegramApiClient, TelegramApiFailure, TelegramBotToken, TelegramChatTarget, TelegramProvider,
    TelegramSentMessage, TelegramTextUpdate, TelegramUpdateBatch,
};
use ucr_model::{
    BridgeAction, BridgeActionId, BridgeCapability, BridgeEventCursor, CorrelationContext,
    IntegrationId, MessageId, OpaqueId, TenantId, TenantScope,
};

#[derive(Debug, Clone)]
struct FuzzClient {
    data: Vec<u8>,
}

impl TelegramApiClient for FuzzClient {
    fn send_text(
        &self,
        _target: &TelegramChatTarget,
        _text: &str,
    ) -> Result<TelegramSentMessage, TelegramApiFailure> {
        match self.data.first().copied().unwrap_or(0) % 4 {
            0 => Ok(TelegramSentMessage { message_id: 1 }),
            1 => Err(TelegramApiFailure::Rejected),
            2 => Err(TelegramApiFailure::RateLimited),
            _ => Err(TelegramApiFailure::Ambiguous),
        }
    }

    fn poll_text_updates(
        &self,
        offset: Option<i64>,
        _limit: usize,
    ) -> Result<TelegramUpdateBatch, TelegramApiFailure> {
        if self.data.get(1).copied().unwrap_or(0) % 5 == 0 {
            return Err(TelegramApiFailure::Ambiguous);
        }
        let base = offset.unwrap_or(1).max(1);
        let text = String::from_utf8_lossy(self.data.get(4..).unwrap_or(&[]))
            .chars()
            .take(256)
            .collect::<String>();
        let updates = if text.is_empty() {
            Vec::new()
        } else {
            vec![TelegramTextUpdate {
                update_id: base,
                chat_id: -100_123,
                actor_id: Some(7),
                text,
                occurred_at_unix_seconds: 1_700_000_000,
            }]
        };
        Ok(TelegramUpdateBatch {
            updates,
            next_offset: base.checked_add(1),
        })
    }
}

fn opaque(prefix: &str, bytes: &[u8]) -> OpaqueId {
    let mut value = String::from(prefix);
    for byte in bytes.iter().take(32) {
        use core::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    OpaqueId::new(value).unwrap_or_else(|_| OpaqueId::new(prefix).expect("static id"))
}

fuzz_target!(|data: &[u8]| {
    let token_candidate = String::from_utf8_lossy(data)
        .chars()
        .take(256)
        .collect::<String>();
    let _ = TelegramBotToken::new(token_candidate);
    let _ = TelegramChatTarget::parse(data.get(..64).unwrap_or(data));

    let client = FuzzClient {
        data: data.to_vec(),
    };
    let provider = TelegramProvider::new(client);
    let _ = provider.manifest();

    let scope = TenantScope {
        tenant_id: TenantId::from_opaque(opaque("telegram-fuzz-tenant-", data)),
        namespace_id: None,
    };
    let integration_id = IntegrationId::from_opaque(opaque(
        "telegram-fuzz-integration-",
        data.get(8..).unwrap_or(data),
    ));
    let action = BridgeAction {
        action_id: BridgeActionId::from_opaque(opaque(
            "telegram-fuzz-action-",
            data.get(16..).unwrap_or(data),
        )),
        scope: scope.clone(),
        integration_id: integration_id.clone(),
        capability: if data.first().copied().unwrap_or(0) & 1 == 0 {
            BridgeCapability::Text
        } else {
            BridgeCapability::Files
        },
        external_target: data.get(..64).unwrap_or(data).to_vec(),
        canonical_message_id: Some(MessageId::from_opaque(opaque(
            "telegram-fuzz-message-",
            data.get(24..).unwrap_or(data),
        ))),
        provider_payload: data
            .get(32..)
            .unwrap_or(&[])
            .iter()
            .copied()
            .take(8192)
            .collect(),
        attachment_ids: vec![],
        correlation: CorrelationContext {
            correlation_id: opaque("telegram-fuzz-correlation-", data.get(4..).unwrap_or(data)),
            causation_id: None,
            idempotency_key: Some("telegram-fuzz".to_owned()),
        },
    };
    let _: Result<_, BridgeProviderFailure> = provider.execute(&action);

    let cursor = (!data.is_empty()).then(|| BridgeEventCursor {
        token: data.iter().copied().take(64).collect(),
    });
    let limit = usize::from(data.get(2).copied().unwrap_or(0));
    let _ = provider.poll_events(&scope, &integration_id, cursor.as_ref(), limit);
});

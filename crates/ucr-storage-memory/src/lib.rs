#![forbid(unsafe_code)]

use std::{collections::HashMap, fmt, sync::Mutex};

use ucr_core::{CommandAcceptanceStore, DurableStoreError, StorageHealth, StorageProvider};
use ucr_model::CommandEnvelope;
use ucr_protocol::{
    CommandError, CommandReceipt, CommandReceiptStatus, IdempotencyDecision,
    compare_command_idempotency, validate_command,
};

const SCHEMA_VERSION: u32 = 1;
type CommandKey = (String, String, String);

#[derive(Default)]
pub struct MemoryCommandStore {
    accepted: Mutex<HashMap<CommandKey, CommandEnvelope>>,
}

impl fmt::Debug for MemoryCommandStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCommandStore")
            .field("accepted", &"<redacted>")
            .finish()
    }
}

impl StorageProvider for MemoryCommandStore {
    fn schema_version(&self) -> Result<u32, DurableStoreError> {
        Ok(SCHEMA_VERSION)
    }

    fn health(&self) -> Result<StorageHealth, DurableStoreError> {
        self.accepted
            .lock()
            .map(|_| StorageHealth::Healthy)
            .map_err(|_| DurableStoreError::Internal)
    }
}

impl CommandAcceptanceStore for MemoryCommandStore {
    fn accept_command(
        &self,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, DurableStoreError> {
        validate_command(command).map_err(map_command_error)?;
        let key = command_key(command)?;
        let mut accepted = self
            .accepted
            .lock()
            .map_err(|_| DurableStoreError::Internal)?;

        if let Some(original) = accepted.get(&key) {
            return receipt_for_existing(original, command);
        }

        accepted.insert(key, command.clone());
        Ok(CommandReceipt {
            command_id: command.command_id.clone(),
            status: CommandReceiptStatus::Accepted,
            original_command_id: None,
        })
    }
}

fn map_command_error(error: CommandError) -> DurableStoreError {
    match error {
        CommandError::IdempotencyConflict => DurableStoreError::Conflict,
        CommandError::InvalidCommandType
        | CommandError::MissingIdempotencyKey
        | CommandError::EmptyIdempotencyKey
        | CommandError::IdempotencyKeyTooLong
        | CommandError::PayloadTooLarge => DurableStoreError::InvalidRecord,
    }
}

fn command_key(command: &CommandEnvelope) -> Result<CommandKey, DurableStoreError> {
    let idempotency_key = command
        .correlation
        .idempotency_key
        .clone()
        .ok_or(DurableStoreError::InvalidRecord)?;
    let namespace = command
        .scope
        .namespace_id
        .as_ref()
        .map_or_else(String::new, |value| value.as_opaque().as_str().to_owned());

    Ok((
        command.scope.tenant_id.as_opaque().as_str().to_owned(),
        namespace,
        idempotency_key,
    ))
}

fn receipt_for_existing(
    original: &CommandEnvelope,
    incoming: &CommandEnvelope,
) -> Result<CommandReceipt, DurableStoreError> {
    match compare_command_idempotency(original, incoming).map_err(map_command_error)? {
        IdempotencyDecision::DuplicateOf(original_command_id) => Ok(CommandReceipt {
            command_id: incoming.command_id.clone(),
            status: CommandReceiptStatus::Duplicate,
            original_command_id: Some(original_command_id),
        }),
        IdempotencyDecision::New => Err(DurableStoreError::Internal),
    }
}

#[cfg(test)]
mod tests {
    use ucr_core::{CommandAcceptanceStore, DurableStoreError, StorageProvider};
    use ucr_model::{
        CommandEnvelope, CommandId, CorrelationContext, NamespaceId, OpaqueId, TenantId,
        TenantScope,
    };
    use ucr_protocol::CommandReceiptStatus;

    use super::MemoryCommandStore;

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn command(id: &str, key: &str, payload: &[u8]) -> CommandEnvelope {
        CommandEnvelope {
            command_id: CommandId::from_opaque(opaque(id)),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(opaque("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(opaque("namespace-a"))),
            },
            command_type: "ucr.message.send".to_owned(),
            payload: payload.to_vec(),
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: None,
                idempotency_key: Some(key.to_owned()),
            },
        }
    }

    #[test]
    fn memory_store_is_healthy_and_versioned() {
        let store = MemoryCommandStore::default();
        assert_eq!(store.schema_version(), Ok(1));
        assert_eq!(store.health(), Ok(ucr_core::StorageHealth::Healthy));
    }

    #[test]
    fn memory_store_accepts_then_deduplicates() {
        let store = MemoryCommandStore::default();
        let first = command("command-a", "retry-a", b"payload");
        let retry = command("command-b", "retry-a", b"payload");

        let accepted = store.accept_command(&first).expect("accepted");
        assert_eq!(accepted.status, CommandReceiptStatus::Accepted);
        assert!(accepted.original_command_id.is_none());

        let duplicate = store.accept_command(&retry).expect("duplicate");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(duplicate.original_command_id, Some(first.command_id));
    }

    #[test]
    fn memory_store_conflict_fails_closed() {
        let store = MemoryCommandStore::default();
        store
            .accept_command(&command("command-a", "retry-a", b"payload-a"))
            .expect("accepted");
        assert_eq!(
            store.accept_command(&command("command-b", "retry-a", b"payload-b")),
            Err(DurableStoreError::Conflict)
        );
    }
}

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Mutex,
};

use ucr_core::{
    CommandAcceptanceStore, CommandOutcomeStore, DurableStoreError, EventAppendStatus,
    EventJournalStore, StorageHealth, StorageProvider,
};
use ucr_crypto::{ReplayError, ReplayProtector, TranscriptBinding, VerifyingKeyBytes};
use ucr_model::{CommandEnvelope, CommandId, EventEnvelope, EventId, TenantScope};
use ucr_protocol::{
    CommandError, CommandReceipt, CommandReceiptStatus, EventError, IdempotencyDecision,
    compare_command_idempotency, validate_command, validate_event,
};

const SCHEMA_VERSION: u32 = 3;
type ScopeKey = (String, Option<String>);
type CommandKey = (ScopeKey, String);
type CommandRefKey = (ScopeKey, String);
type EventKey = (ScopeKey, String);
type ReplayKey = ([u8; 32], [u8; 32]);

#[derive(Default)]
struct MemoryState {
    accepted: HashMap<CommandKey, CommandEnvelope>,
    accepted_by_id: HashMap<CommandRefKey, CommandEnvelope>,
    events: HashMap<EventKey, EventEnvelope>,
    terminal_events: HashMap<CommandRefKey, EventId>,
    seen_handshakes: HashSet<ReplayKey>,
}

#[derive(Default)]
pub struct MemoryLocalStore {
    state: Mutex<MemoryState>,
}

impl fmt::Debug for MemoryLocalStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryLocalStore")
            .field("state", &"<redacted>")
            .finish()
    }
}

impl StorageProvider for MemoryLocalStore {
    fn schema_version(&self) -> Result<u32, DurableStoreError> {
        Ok(SCHEMA_VERSION)
    }

    fn health(&self) -> Result<StorageHealth, DurableStoreError> {
        self.state
            .lock()
            .map(|_| StorageHealth::Healthy)
            .map_err(|_| DurableStoreError::Internal)
    }
}

impl ReplayProtector for MemoryLocalStore {
    fn record_once(
        &self,
        peer_verifying_key: &VerifyingKeyBytes,
        binding: &TranscriptBinding,
    ) -> Result<(), ReplayError> {
        let mut state = self.state.lock().map_err(|_| ReplayError::Internal)?;
        if !state
            .seen_handshakes
            .insert((peer_verifying_key.0, *binding.as_bytes()))
        {
            return Err(ReplayError::Replayed);
        }
        Ok(())
    }
}

impl CommandAcceptanceStore for MemoryLocalStore {
    fn accept_command(
        &self,
        command: &CommandEnvelope,
    ) -> Result<CommandReceipt, DurableStoreError> {
        validate_command(command).map_err(map_command_error)?;
        let key = command_key(command)?;
        let command_ref = command_ref_key(&command.scope, &command.command_id);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;

        if let Some(original) = state.accepted.get(&key) {
            return receipt_for_existing(original, command);
        }
        if state.accepted_by_id.contains_key(&command_ref) {
            return Err(DurableStoreError::Conflict);
        }

        state.accepted.insert(key, command.clone());
        state.accepted_by_id.insert(command_ref, command.clone());
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

fn scope_key(scope: &TenantScope) -> ScopeKey {
    (
        scope.tenant_id.as_opaque().as_str().to_owned(),
        scope
            .namespace_id
            .as_ref()
            .map(|value| value.as_opaque().as_str().to_owned()),
    )
}

fn command_key(command: &CommandEnvelope) -> Result<CommandKey, DurableStoreError> {
    let idempotency_key = command
        .correlation
        .idempotency_key
        .clone()
        .ok_or(DurableStoreError::InvalidRecord)?;
    Ok((scope_key(&command.scope), idempotency_key))
}

fn command_ref_key(scope: &TenantScope, command_id: &CommandId) -> CommandRefKey {
    (scope_key(scope), command_id.as_opaque().as_str().to_owned())
}

fn event_key(event: &EventEnvelope) -> EventKey {
    (
        scope_key(&event.scope),
        event.event_id.as_opaque().as_str().to_owned(),
    )
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

fn map_event_error(_error: EventError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

impl EventJournalStore for MemoryLocalStore {
    fn append_event(&self, event: &EventEnvelope) -> Result<EventAppendStatus, DurableStoreError> {
        validate_event(event).map_err(map_event_error)?;
        let key = event_key(event);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if let Some(original) = state.events.get(&key) {
            return if original == event {
                Ok(EventAppendStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        state.events.insert(key, event.clone());
        Ok(EventAppendStatus::Appended)
    }
}

impl CommandOutcomeStore for MemoryLocalStore {
    fn record_terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, DurableStoreError> {
        validate_event(event).map_err(map_event_error)?;
        if &event.scope != scope
            || event.correlation.causation_id.as_ref() != Some(command_id.as_opaque())
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let command_ref = command_ref_key(scope, command_id);
        let event_key = event_key(event);
        let mut state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        if !state.accepted_by_id.contains_key(&command_ref) {
            return Err(DurableStoreError::InvalidRecord);
        }
        if let Some(existing_id) = state.terminal_events.get(&command_ref) {
            if existing_id != &event.event_id {
                return Err(DurableStoreError::Conflict);
            }
            return match state.events.get(&event_key) {
                Some(original) if original == event => Ok(EventAppendStatus::Duplicate),
                _ => Err(DurableStoreError::Conflict),
            };
        }
        if let Some(original) = state.events.get(&event_key) {
            if original != event {
                return Err(DurableStoreError::Conflict);
            }
        } else {
            state.events.insert(event_key, event.clone());
        }
        state
            .terminal_events
            .insert(command_ref, event.event_id.clone());
        Ok(EventAppendStatus::Appended)
    }

    fn terminal_event(
        &self,
        scope: &TenantScope,
        command_id: &CommandId,
    ) -> Result<Option<EventId>, DurableStoreError> {
        let state = self.state.lock().map_err(|_| DurableStoreError::Internal)?;
        Ok(state
            .terminal_events
            .get(&command_ref_key(scope, command_id))
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use ucr_core::{
        CommandAcceptanceStore, CommandOutcomeStore, DurableStoreError, EventAppendStatus,
        EventJournalStore, StorageProvider,
    };
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CommandEnvelope, CommandId, CorrelationContext, DeviceId,
        DeviceRef, EventEnvelope, EventId, IdentityId, NamespaceId, OpaqueId, ProtocolVersion,
        TenantId, TenantScope,
    };
    use ucr_protocol::CommandReceiptStatus;

    use super::MemoryLocalStore;

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

    fn event(id: &str, causation: &str, payload: &[u8]) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(opaque(id)),
            scope: command("scope-source", "scope-key", b"").scope,
            event_type: "ucr.command.completed".to_owned(),
            payload: payload.to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(opaque("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(opaque("device-a")),
                identity_id: IdentityId::from_opaque(opaque("identity-a")),
            },
            wall_time_unix_ms: 1_788_330_000_000,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: Some(opaque(causation)),
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: Vec::new(),
        }
    }

    #[test]
    fn memory_store_is_healthy_and_versioned() {
        let store = MemoryLocalStore::default();
        assert_eq!(store.schema_version(), Ok(3));
        assert_eq!(store.health(), Ok(ucr_core::StorageHealth::Healthy));
    }

    #[test]
    fn memory_store_accepts_then_deduplicates() {
        let store = MemoryLocalStore::default();
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
        let store = MemoryLocalStore::default();
        store
            .accept_command(&command("command-a", "retry-a", b"payload-a"))
            .expect("accepted");
        assert_eq!(
            store.accept_command(&command("command-b", "retry-a", b"payload-b")),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn scoped_command_id_cannot_be_reused_with_another_idempotency_key() {
        let store = MemoryLocalStore::default();
        store
            .accept_command(&command("command-a", "retry-a", b"payload"))
            .expect("accepted");
        assert_eq!(
            store.accept_command(&command("command-a", "retry-b", b"payload")),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn event_append_is_idempotent_but_event_id_reuse_conflicts() {
        let store = MemoryLocalStore::default();
        let first = event("event-a", "command-a", b"done");
        assert_eq!(store.append_event(&first), Ok(EventAppendStatus::Appended));
        assert_eq!(store.append_event(&first), Ok(EventAppendStatus::Duplicate));
        let changed = event("event-a", "command-a", b"different");
        assert_eq!(
            store.append_event(&changed),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn terminal_event_requires_accepted_command_and_matching_causation() {
        let store = MemoryLocalStore::default();
        let accepted = command("command-a", "retry-a", b"payload");
        let terminal = event("event-a", "command-a", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Err(DurableStoreError::InvalidRecord)
        );
        store.accept_command(&accepted).expect("accepted");
        let wrong = event("event-b", "command-b", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &wrong),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn terminal_event_is_atomic_and_idempotent() {
        let store = MemoryLocalStore::default();
        let accepted = command("command-a", "retry-a", b"payload");
        store.accept_command(&accepted).expect("accepted");
        let terminal = event("event-a", "command-a", b"done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Appended)
        );
        assert_eq!(
            store.terminal_event(&accepted.scope, &accepted.command_id),
            Ok(Some(terminal.event_id.clone()))
        );
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &terminal),
            Ok(EventAppendStatus::Duplicate)
        );
        let second = event("event-b", "command-a", b"also-done");
        assert_eq!(
            store.record_terminal_event(&accepted.scope, &accepted.command_id, &second),
            Err(DurableStoreError::Conflict)
        );
    }
}

#[cfg(test)]
mod replay_tests {
    use ucr_crypto::{ReplayError, ReplayProtector, TranscriptBinding, VerifyingKeyBytes};

    use super::MemoryLocalStore;

    #[test]
    fn memory_replay_guard_accepts_once() {
        let store = MemoryLocalStore::default();
        let peer = VerifyingKeyBytes([7_u8; 32]);
        let binding = TranscriptBinding::from_bytes([9_u8; 32]);
        assert_eq!(store.record_once(&peer, &binding), Ok(()));
        assert_eq!(
            store.record_once(&peer, &binding),
            Err(ReplayError::Replayed)
        );
    }
}

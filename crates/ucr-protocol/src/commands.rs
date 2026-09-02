use ucr_model::{CommandEnvelope, CommandId, EventEnvelope};

use crate::{DEFAULT_MAX_PAYLOAD_LEN, validate_namespaced_identifier};

pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;
pub const MAX_COMMAND_PAYLOAD_LEN: usize = DEFAULT_MAX_PAYLOAD_LEN as usize;
pub const MAX_EVENT_PAYLOAD_LEN: usize = DEFAULT_MAX_PAYLOAD_LEN as usize;
pub const MAX_EVENT_INTEGRITY_METADATA_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    InvalidCommandType,
    MissingIdempotencyKey,
    EmptyIdempotencyKey,
    IdempotencyKeyTooLong,
    PayloadTooLarge,
    IdempotencyConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    InvalidEventType,
    PayloadTooLarge,
    IntegrityMetadataTooLarge,
    InvalidSchemaVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyDecision {
    New,
    DuplicateOf(CommandId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandReceiptStatus {
    Accepted,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    AcceptedHasOriginal,
    DuplicateMissingOriginal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReceipt {
    pub command_id: CommandId,
    pub status: CommandReceiptStatus,
    pub original_command_id: Option<CommandId>,
}

/// Validates receipt shape. A receipt records command acceptance/deduplication,
/// not completion of the requested real-world effect.
///
/// # Errors
/// Rejects inconsistent accepted/duplicate receipt fields.
pub const fn validate_command_receipt(receipt: &CommandReceipt) -> Result<(), ReceiptError> {
    match (receipt.status, receipt.original_command_id.is_some()) {
        (CommandReceiptStatus::Accepted, true) => Err(ReceiptError::AcceptedHasOriginal),
        (CommandReceiptStatus::Duplicate, false) => Err(ReceiptError::DuplicateMissingOriginal),
        _ => Ok(()),
    }
}

/// Validates canonical command semantics before durable acceptance.
///
/// # Errors
/// Rejects malformed command types and unsafe/missing idempotency keys.
pub fn validate_command(command: &CommandEnvelope) -> Result<(), CommandError> {
    validate_namespaced_identifier(&command.command_type)
        .map_err(|_| CommandError::InvalidCommandType)?;
    let key = command
        .correlation
        .idempotency_key
        .as_deref()
        .ok_or(CommandError::MissingIdempotencyKey)?;
    if key.is_empty() {
        return Err(CommandError::EmptyIdempotencyKey);
    }
    if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(CommandError::IdempotencyKeyTooLong);
    }
    if command.payload.len() > MAX_COMMAND_PAYLOAD_LEN {
        return Err(CommandError::PayloadTooLarge);
    }
    Ok(())
}

/// Validates canonical event type syntax.
///
/// Events record facts; validating an event does not imply that any command
/// requested that fact.
///
/// # Errors
/// Rejects malformed event type identifiers.
pub fn validate_event(event: &EventEnvelope) -> Result<(), EventError> {
    validate_namespaced_identifier(&event.event_type).map_err(|_| EventError::InvalidEventType)?;
    if event.payload.len() > MAX_EVENT_PAYLOAD_LEN {
        return Err(EventError::PayloadTooLarge);
    }
    if event.integrity_metadata.len() > MAX_EVENT_INTEGRITY_METADATA_LEN {
        return Err(EventError::IntegrityMetadataTooLarge);
    }
    if event.schema_version.major == 0 {
        return Err(EventError::InvalidSchemaVersion);
    }
    Ok(())
}

/// Classifies an incoming command against a previously accepted command.
///
/// Idempotency keys are scoped. Reuse of the same key for different command
/// semantics inside the same scope is a conflict, never a second operation.
///
/// # Errors
/// Returns validation failure for either command before comparison.
pub fn compare_command_idempotency(
    original: &CommandEnvelope,
    incoming: &CommandEnvelope,
) -> Result<IdempotencyDecision, CommandError> {
    validate_command(original)?;
    validate_command(incoming)?;
    if original.scope != incoming.scope
        || original.correlation.idempotency_key != incoming.correlation.idempotency_key
    {
        return Ok(IdempotencyDecision::New);
    }
    if original.command_type == incoming.command_type && original.payload == incoming.payload {
        return Ok(IdempotencyDecision::DuplicateOf(
            original.command_id.clone(),
        ));
    }
    Err(CommandError::IdempotencyConflict)
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CommandEnvelope, CommandId, CorrelationContext, DeviceId,
        DeviceRef, EventEnvelope, EventId, IdentityId, NamespaceId, OpaqueId, ProtocolVersion,
        TenantId, TenantScope,
    };

    use super::{
        CommandError, CommandReceipt, CommandReceiptStatus, EventError, IdempotencyDecision,
        ReceiptError, compare_command_idempotency, validate_command, validate_command_receipt,
        validate_event,
    };

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn scope(tenant: &str, namespace: &str) -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque(tenant)),
            namespace_id: Some(NamespaceId::from_opaque(opaque(namespace))),
        }
    }

    fn command(id: &str, key: Option<&str>, payload: &[u8]) -> CommandEnvelope {
        CommandEnvelope {
            command_id: CommandId::from_opaque(opaque(id)),
            scope: scope("tenant-a", "namespace-a"),
            command_type: "ucr.message.send".to_owned(),
            payload: payload.to_vec(),
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: None,
                idempotency_key: key.map(str::to_owned),
            },
        }
    }

    fn event(event_type: &str) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(opaque("event-a")),
            scope: scope("tenant-a", "namespace-a"),
            event_type: event_type.to_owned(),
            payload: b"fact".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(opaque("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(opaque("device-a")),
                identity_id: IdentityId::from_opaque(opaque("identity-a")),
            },
            wall_time_unix_ms: 1_700_000_000_000,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: opaque("correlation-a"),
                causation_id: Some(opaque("command-a")),
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: b"integrity".to_vec(),
        }
    }

    #[test]
    fn command_requires_idempotency_key() {
        assert_eq!(
            validate_command(&command("command-a", None, b"payload")),
            Err(CommandError::MissingIdempotencyKey)
        );
    }

    #[test]
    fn same_scoped_key_and_semantics_is_duplicate() {
        let original = command("command-a", Some("retry-key"), b"payload");
        let incoming = command("command-b", Some("retry-key"), b"payload");
        assert_eq!(
            compare_command_idempotency(&original, &incoming),
            Ok(IdempotencyDecision::DuplicateOf(
                original.command_id.clone()
            ))
        );
    }

    #[test]
    fn same_scoped_key_with_changed_payload_is_conflict() {
        let original = command("command-a", Some("retry-key"), b"payload-a");
        let incoming = command("command-b", Some("retry-key"), b"payload-b");
        assert_eq!(
            compare_command_idempotency(&original, &incoming),
            Err(CommandError::IdempotencyConflict)
        );
    }

    #[test]
    fn same_key_in_different_scope_is_new_command() {
        let original = command("command-a", Some("retry-key"), b"payload");
        let mut incoming = command("command-b", Some("retry-key"), b"payload");
        incoming.scope = scope("tenant-a", "namespace-b");
        assert_eq!(
            compare_command_idempotency(&original, &incoming),
            Ok(IdempotencyDecision::New)
        );
    }

    #[test]
    fn command_and_event_types_must_be_namespaced() {
        let mut invalid_command = command("command-a", Some("retry-key"), b"payload");
        invalid_command.command_type = "send".to_owned();
        assert_eq!(
            validate_command(&invalid_command),
            Err(CommandError::InvalidCommandType)
        );
        assert_eq!(
            validate_event(&event("sent")),
            Err(EventError::InvalidEventType)
        );
        assert_eq!(validate_event(&event("ucr.message.sent")), Ok(()));
    }

    #[test]
    fn receipt_shape_cannot_confuse_acceptance_and_duplicate() {
        let accepted = CommandReceipt {
            command_id: CommandId::from_opaque(opaque("command-a")),
            status: CommandReceiptStatus::Accepted,
            original_command_id: None,
        };
        assert_eq!(validate_command_receipt(&accepted), Ok(()));

        let invalid_duplicate = CommandReceipt {
            command_id: CommandId::from_opaque(opaque("command-b")),
            status: CommandReceiptStatus::Duplicate,
            original_command_id: None,
        };
        assert_eq!(
            validate_command_receipt(&invalid_duplicate),
            Err(ReceiptError::DuplicateMissingOriginal)
        );
    }

    #[test]
    fn idempotency_key_boundaries_fail_closed() {
        assert_eq!(
            validate_command(&command("command-a", Some(""), b"payload")),
            Err(CommandError::EmptyIdempotencyKey)
        );
        let oversized = "x".repeat(super::MAX_IDEMPOTENCY_KEY_LEN + 1);
        assert_eq!(
            validate_command(&command("command-a", Some(&oversized), b"payload")),
            Err(CommandError::IdempotencyKeyTooLong)
        );
    }

    #[test]
    fn accepted_receipt_cannot_claim_an_original_duplicate() {
        let invalid = CommandReceipt {
            command_id: CommandId::from_opaque(opaque("command-b")),
            status: CommandReceiptStatus::Accepted,
            original_command_id: Some(CommandId::from_opaque(opaque("command-a"))),
        };
        assert_eq!(
            validate_command_receipt(&invalid),
            Err(ReceiptError::AcceptedHasOriginal)
        );
    }

    #[test]
    fn command_payload_budget_fails_closed_before_storage() {
        let oversized = vec![0_u8; super::MAX_COMMAND_PAYLOAD_LEN + 1];
        assert_eq!(
            validate_command(&command("command-a", Some("retry-key"), &oversized)),
            Err(CommandError::PayloadTooLarge)
        );
    }
    #[test]
    fn event_payload_budget_fails_closed_before_storage() {
        let mut oversized = event("ucr.message.created");
        oversized.payload = vec![0_u8; super::MAX_EVENT_PAYLOAD_LEN + 1];
        assert_eq!(validate_event(&oversized), Err(EventError::PayloadTooLarge));
    }

    #[test]
    fn event_integrity_metadata_budget_fails_closed_before_storage() {
        let mut oversized = event("ucr.message.created");
        oversized.integrity_metadata = vec![0_u8; super::MAX_EVENT_INTEGRITY_METADATA_LEN + 1];
        assert_eq!(
            validate_event(&oversized),
            Err(EventError::IntegrityMetadataTooLarge)
        );
    }

    #[test]
    fn event_schema_version_must_be_explicit() {
        let mut invalid = event("ucr.message.created");
        invalid.schema_version = ProtocolVersion::new(0, 0);
        assert_eq!(
            validate_event(&invalid),
            Err(EventError::InvalidSchemaVersion)
        );
    }
}

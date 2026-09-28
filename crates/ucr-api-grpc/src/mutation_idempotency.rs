use ucr_core::{CommandAcceptanceStore, DurableStoreError, generate_opaque_id};
use ucr_model::{CommandEnvelope, CommandId, CorrelationContext, ProtocolVersion, TenantScope};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, CommandReceiptStatus, MAX_IDEMPOTENCY_KEY_LEN,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedMutation {
    pub command_id: CommandId,
    pub duplicate: bool,
}

pub(crate) fn validate_mutation_idempotency_key(value: &str) -> Result<(), CanonicalError> {
    if value.is_empty()
        || value.len() > MAX_IDEMPOTENCY_KEY_LEN
        || value.chars().any(char::is_control)
    {
        Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument))
    } else {
        Ok(())
    }
}

pub(crate) fn accept_mutation_receipt<S: CommandAcceptanceStore>(
    store: &S,
    scope: &TenantScope,
    command_type: &str,
    idempotency_key: &str,
    payload: Vec<u8>,
) -> Result<AcceptedMutation, CanonicalError> {
    validate_mutation_idempotency_key(idempotency_key)?;
    let command_id = CommandId::from_opaque(
        generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let command = CommandEnvelope {
        command_id: command_id.clone(),
        scope: scope.clone(),
        command_type: command_type.to_owned(),
        payload,
        correlation: CorrelationContext {
            correlation_id: command_id.as_opaque().clone(),
            causation_id: None,
            idempotency_key: Some(idempotency_key.to_owned()),
        },
        schema_version: ProtocolVersion::new(1, 0),
        extensions: Vec::new(),
    };
    let receipt = store.accept_command(&command).map_err(map_store_error)?;
    match receipt.status {
        CommandReceiptStatus::Accepted => Ok(AcceptedMutation {
            command_id: receipt.command_id,
            duplicate: false,
        }),
        CommandReceiptStatus::Duplicate => Ok(AcceptedMutation {
            command_id: receipt
                .original_command_id
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?,
            duplicate: true,
        }),
    }
}

pub(crate) fn accept_mutation_receipt_with_legacy_reservation<S: CommandAcceptanceStore>(
    store: &S,
    scope: &TenantScope,
    command_type: &str,
    idempotency_key: &str,
    legacy_idempotency_key: &str,
    payload: Vec<u8>,
) -> Result<AcceptedMutation, CanonicalError> {
    validate_mutation_idempotency_key(idempotency_key)?;
    validate_mutation_idempotency_key(legacy_idempotency_key)?;
    let command_id = CommandId::from_opaque(
        generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?,
    );
    let command = CommandEnvelope {
        command_id: command_id.clone(),
        scope: scope.clone(),
        command_type: command_type.to_owned(),
        payload,
        correlation: CorrelationContext {
            correlation_id: command_id.as_opaque().clone(),
            causation_id: None,
            idempotency_key: Some(idempotency_key.to_owned()),
        },
        schema_version: ProtocolVersion::new(1, 0),
        extensions: Vec::new(),
    };
    let receipt = store
        .accept_command_with_legacy_reservation(&command, legacy_idempotency_key)
        .map_err(map_store_error)?;
    match receipt.status {
        CommandReceiptStatus::Accepted => Ok(AcceptedMutation {
            command_id: receipt.command_id,
            duplicate: false,
        }),
        CommandReceiptStatus::Duplicate => Ok(AcceptedMutation {
            command_id: receipt
                .original_command_id
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?,
            duplicate: true,
        }),
    }
}

const fn map_store_error(error: DurableStoreError) -> CanonicalError {
    let code = match error {
        DurableStoreError::InvalidRecord => CanonicalErrorCode::InvalidArgument,
        DurableStoreError::Conflict => CanonicalErrorCode::Conflict,
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

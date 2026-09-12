use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use ucr_model::{
    BridgeAction, BridgeActionRecord, BridgeActionState, BridgeCapability, BridgeDataPermission,
    BridgeEventCursor, BridgeEventPage, BridgeInboundEvent, BridgeProviderAcceptance,
    BridgeProviderManifest, BridgeRegistration, BridgeRegistrationState, ProtocolVersion,
};

use crate::{
    DEFAULT_MAX_PAYLOAD_LEN, ExtensionError, MAX_IDEMPOTENCY_KEY_LEN, RUNTIME_ENVELOPE_SCHEMA_V1,
    canonical_protocol_extensions, validate_namespaced_identifier,
};

pub const BRIDGE_SDK_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
pub const MAX_BRIDGE_EXTERNAL_ID_LEN: usize = 2_048;
pub const MAX_BRIDGE_EVENT_CURSOR_LEN: usize = 512;
pub const MAX_BRIDGE_EVENT_PAGE_ITEMS: usize = 256;
pub const MAX_BRIDGE_ATTACHMENTS: usize = 128;
const BRIDGE_ACTION_FINGERPRINT_V1_DOMAIN: &[u8] = b"UCR-BRIDGE-ACTION-V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeProtocolError {
    InvalidProviderId,
    InvalidSdkRange,
    IncompatibleSdk,
    InvalidProtocolRange,
    IncompatibleProtocol,
    EmptyCapabilities,
    DuplicateCapability,
    DuplicatePermission,
    InvalidExtension,
    DuplicateExtension,
    TooManyExtensions,
    ExtensionPayloadTooLarge,
    InvalidRegistrationGeneration,
    InvalidRegistrationTransition,
    InvalidActionGeneration,
    InvalidActionResult,
    InvalidDegradation,
    InvalidActionTransition,
    InvalidExternalTarget,
    PayloadTooLarge,
    TooManyAttachments,
    DuplicateAttachment,
    InvalidInboundEvent,
    TooManyEvents,
    DuplicateInboundEvent,
    InvalidCursor,
}

/// Canonicalizes one provider manifest and verifies SDK/protocol compatibility.
///
/// # Errors
/// Returns a bridge protocol error for malformed identifiers/ranges, incompatible versions,
/// duplicate capability/data-permission declarations, or invalid extensions.
pub fn canonical_bridge_manifest(
    manifest: &BridgeProviderManifest,
) -> Result<BridgeProviderManifest, BridgeProtocolError> {
    validate_namespaced_identifier(&manifest.provider_id)
        .map_err(|_| BridgeProtocolError::InvalidProviderId)?;
    validate_version_range(
        manifest.sdk_min,
        manifest.sdk_max,
        BridgeProtocolError::InvalidSdkRange,
    )?;
    if BRIDGE_SDK_VERSION < manifest.sdk_min || BRIDGE_SDK_VERSION > manifest.sdk_max {
        return Err(BridgeProtocolError::IncompatibleSdk);
    }
    validate_version_range(
        manifest.protocol_min,
        manifest.protocol_max,
        BridgeProtocolError::InvalidProtocolRange,
    )?;
    if RUNTIME_ENVELOPE_SCHEMA_V1 < manifest.protocol_min
        || RUNTIME_ENVELOPE_SCHEMA_V1 > manifest.protocol_max
    {
        return Err(BridgeProtocolError::IncompatibleProtocol);
    }
    if manifest.capabilities.is_empty() {
        return Err(BridgeProtocolError::EmptyCapabilities);
    }
    let mut canonical = manifest.clone();
    canonical.capabilities.sort_unstable();
    if canonical
        .capabilities
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(BridgeProtocolError::DuplicateCapability);
    }
    canonical.permissions.sort_unstable();
    if canonical
        .permissions
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(BridgeProtocolError::DuplicatePermission);
    }
    canonical.extensions =
        canonical_protocol_extensions(&manifest.extensions).map_err(map_extension_error)?;
    Ok(canonical)
}

/// Canonicalizes one durable bridge registration.
///
/// # Errors
/// Returns a bridge protocol error for generation zero or an invalid/incompatible manifest.
pub fn canonical_bridge_registration(
    registration: &BridgeRegistration,
) -> Result<BridgeRegistration, BridgeProtocolError> {
    if registration.generation == 0 {
        return Err(BridgeProtocolError::InvalidRegistrationGeneration);
    }
    let mut canonical = registration.clone();
    canonical.manifest = canonical_bridge_manifest(&registration.manifest)?;
    Ok(canonical)
}

/// Validates one outbound bridge action before fingerprinting or provider execution.
///
/// # Errors
/// Returns a bridge protocol error for invalid targets, oversized payload/idempotency data,
/// excessive attachments, or duplicate attachment identifiers.
pub fn validate_bridge_action(action: &BridgeAction) -> Result<(), BridgeProtocolError> {
    if action.external_target.is_empty()
        || action.external_target.len() > MAX_BRIDGE_EXTERNAL_ID_LEN
    {
        return Err(BridgeProtocolError::InvalidExternalTarget);
    }
    if action.provider_payload.len() > DEFAULT_MAX_PAYLOAD_LEN as usize
        || action
            .correlation
            .idempotency_key
            .as_ref()
            .is_some_and(|value| value.len() > MAX_IDEMPOTENCY_KEY_LEN)
    {
        return Err(BridgeProtocolError::PayloadTooLarge);
    }
    if action.attachment_ids.len() > MAX_BRIDGE_ATTACHMENTS {
        return Err(BridgeProtocolError::TooManyAttachments);
    }
    let mut attachments = BTreeSet::new();
    for attachment in &action.attachment_ids {
        if !attachments.insert(attachment.as_opaque().as_wire_bytes()) {
            return Err(BridgeProtocolError::DuplicateAttachment);
        }
    }
    Ok(())
}

/// Produces the versioned canonical fingerprint for one validated bridge action.
///
/// # Errors
/// Returns a bridge protocol error when the action is invalid or any length cannot be encoded in
/// the bounded fingerprint representation.
pub fn bridge_action_fingerprint(action: &BridgeAction) -> Result<[u8; 32], BridgeProtocolError> {
    validate_bridge_action(action)?;
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, action.action_id.as_opaque().as_wire_bytes())?;
    push_bytes(
        &mut bytes,
        action.scope.tenant_id.as_opaque().as_wire_bytes(),
    )?;
    match &action.scope.namespace_id {
        Some(namespace) => {
            bytes.push(1);
            push_bytes(&mut bytes, namespace.as_opaque().as_wire_bytes())?;
        }
        None => bytes.push(0),
    }
    push_bytes(
        &mut bytes,
        action.integration_id.as_opaque().as_wire_bytes(),
    )?;
    bytes.push(capability_code(action.capability));
    push_bytes(&mut bytes, &action.external_target)?;
    match &action.canonical_message_id {
        Some(message_id) => {
            bytes.push(1);
            push_bytes(&mut bytes, message_id.as_opaque().as_wire_bytes())?;
        }
        None => bytes.push(0),
    }
    push_bytes(&mut bytes, &action.provider_payload)?;
    let attachment_count = u32::try_from(action.attachment_ids.len())
        .map_err(|_| BridgeProtocolError::TooManyAttachments)?;
    bytes.extend_from_slice(&attachment_count.to_be_bytes());
    for attachment in &action.attachment_ids {
        push_bytes(&mut bytes, attachment.as_opaque().as_wire_bytes())?;
    }
    push_bytes(
        &mut bytes,
        action.correlation.correlation_id.as_wire_bytes(),
    )?;
    match &action.correlation.causation_id {
        Some(value) => {
            bytes.push(1);
            push_bytes(&mut bytes, value.as_wire_bytes())?;
        }
        None => bytes.push(0),
    }
    match &action.correlation.idempotency_key {
        Some(value) => {
            bytes.push(1);
            push_bytes(&mut bytes, value.as_bytes())?;
        }
        None => bytes.push(0),
    }
    let mut hasher = Sha256::new();
    hasher.update(BRIDGE_ACTION_FINGERPRINT_V1_DOMAIN);
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

/// Validates provider acceptance/degradation without promoting it to Delivery evidence.
///
/// # Errors
/// Returns a bridge protocol error for invalid provider identifiers or undeclared/contradictory
/// degradation metadata. Any fallback must remain inside both the durable registration ceiling and
/// the provider's current live manifest.
pub fn validate_bridge_provider_acceptance(
    action: &BridgeAction,
    registered_manifest: &BridgeProviderManifest,
    current_manifest: &BridgeProviderManifest,
    acceptance: &BridgeProviderAcceptance,
) -> Result<(), BridgeProtocolError> {
    if acceptance
        .external_message_id
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_BRIDGE_EXTERNAL_ID_LEN)
    {
        return Err(BridgeProtocolError::InvalidActionResult);
    }
    if let Some(degradation) = &acceptance.degradation
        && (degradation.requested != action.capability
            || degradation.fallback == Some(action.capability)
            || degradation.fallback.is_some_and(|fallback| {
                !bridge_manifest_supports(registered_manifest, fallback)
                    || !bridge_manifest_supports(current_manifest, fallback)
            }))
    {
        return Err(BridgeProtocolError::InvalidDegradation);
    }
    Ok(())
}

/// Validates one metadata-only durable bridge action record.
///
/// # Errors
/// Returns a bridge protocol error for invalid generations, result/state mismatches, or malformed
/// persisted provider acceptance metadata.
pub fn validate_bridge_action_record(
    record: &BridgeActionRecord,
) -> Result<(), BridgeProtocolError> {
    if record.generation == 0 {
        return Err(BridgeProtocolError::InvalidActionGeneration);
    }
    if record.state == BridgeActionState::Accepted {
        let acceptance = record
            .acceptance
            .as_ref()
            .ok_or(BridgeProtocolError::InvalidActionResult)?;
        if acceptance
            .external_message_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_BRIDGE_EXTERNAL_ID_LEN)
        {
            return Err(BridgeProtocolError::InvalidActionResult);
        }
        if acceptance
            .degradation
            .as_ref()
            .is_some_and(|degradation| degradation.fallback == Some(degradation.requested))
        {
            return Err(BridgeProtocolError::InvalidDegradation);
        }
    } else if record.acceptance.is_some() {
        return Err(BridgeProtocolError::InvalidActionResult);
    }
    Ok(())
}

/// Validates an exact registration lifecycle transition.
///
/// # Errors
/// Returns `InvalidRegistrationTransition` for non-canonical, no-op, or post-revocation changes.
pub const fn validate_bridge_registration_transition(
    current: BridgeRegistrationState,
    next: BridgeRegistrationState,
) -> Result<(), BridgeProtocolError> {
    match (current, next) {
        (
            BridgeRegistrationState::Active,
            BridgeRegistrationState::Disabled | BridgeRegistrationState::Revoked,
        )
        | (
            BridgeRegistrationState::Disabled,
            BridgeRegistrationState::Active | BridgeRegistrationState::Revoked,
        ) => Ok(()),
        _ => Err(BridgeProtocolError::InvalidRegistrationTransition),
    }
}

/// Validates one bridge-action ledger state transition.
///
/// # Errors
/// Returns `InvalidActionTransition` when the requested transition would violate crash/acceptance
/// semantics.
pub const fn validate_bridge_action_transition(
    current: BridgeActionState,
    next: BridgeActionState,
) -> Result<(), BridgeProtocolError> {
    match (current, next) {
        (
            BridgeActionState::Prepared | BridgeActionState::FailedNotAccepted,
            BridgeActionState::InFlight,
        )
        | (
            BridgeActionState::InFlight,
            BridgeActionState::Accepted
            | BridgeActionState::FailedNotAccepted
            | BridgeActionState::AcceptanceUnknown,
        ) => Ok(()),
        _ => Err(BridgeProtocolError::InvalidActionTransition),
    }
}

/// Validates one bounded page of untrusted inbound provider events.
///
/// # Errors
/// Returns a bridge protocol error for excessive or duplicate events, malformed event fields, or
/// an invalid continuation cursor.
pub fn validate_bridge_event_page(page: &BridgeEventPage) -> Result<(), BridgeProtocolError> {
    if page.events.len() > MAX_BRIDGE_EVENT_PAGE_ITEMS {
        return Err(BridgeProtocolError::TooManyEvents);
    }
    let mut ids = BTreeSet::new();
    for event in &page.events {
        validate_bridge_inbound_event(event)?;
        let key = (
            event.integration_id.as_opaque().as_wire_bytes(),
            event.external_event_id.as_slice(),
        );
        if !ids.insert(key) {
            return Err(BridgeProtocolError::DuplicateInboundEvent);
        }
    }
    if let Some(cursor) = &page.next_cursor {
        validate_bridge_event_cursor(cursor)?;
    }
    Ok(())
}

/// Validates one untrusted inbound provider event shape.
///
/// # Errors
/// Returns `InvalidInboundEvent` for missing/oversized external identifiers, oversized payloads,
/// or non-positive provider event time.
pub fn validate_bridge_inbound_event(
    event: &BridgeInboundEvent,
) -> Result<(), BridgeProtocolError> {
    if event.external_event_id.is_empty()
        || event.external_event_id.len() > MAX_BRIDGE_EXTERNAL_ID_LEN
        || event.external_conversation_id.is_empty()
        || event.external_conversation_id.len() > MAX_BRIDGE_EXTERNAL_ID_LEN
        || event
            .external_actor_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_BRIDGE_EXTERNAL_ID_LEN)
        || event.payload.len() > DEFAULT_MAX_PAYLOAD_LEN as usize
        || event.occurred_at_unix_ms <= 0
    {
        return Err(BridgeProtocolError::InvalidInboundEvent);
    }
    Ok(())
}

/// Validates one opaque bounded provider event cursor.
///
/// # Errors
/// Returns `InvalidCursor` for an empty or oversized cursor token.
pub fn validate_bridge_event_cursor(cursor: &BridgeEventCursor) -> Result<(), BridgeProtocolError> {
    if cursor.token.is_empty() || cursor.token.len() > MAX_BRIDGE_EVENT_CURSOR_LEN {
        return Err(BridgeProtocolError::InvalidCursor);
    }
    Ok(())
}

#[must_use]
pub fn bridge_manifest_supports(
    manifest: &BridgeProviderManifest,
    capability: BridgeCapability,
) -> bool {
    manifest.capabilities.contains(&capability)
}

#[must_use]
pub fn bridge_manifest_allows_data(
    manifest: &BridgeProviderManifest,
    permission: BridgeDataPermission,
) -> bool {
    manifest.permissions.contains(&permission)
}

fn validate_version_range(
    min: ProtocolVersion,
    max: ProtocolVersion,
    error: BridgeProtocolError,
) -> Result<(), BridgeProtocolError> {
    if min.major != max.major || min > max {
        return Err(error);
    }
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), BridgeProtocolError> {
    let len = u32::try_from(value.len()).map_err(|_| BridgeProtocolError::PayloadTooLarge)?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

const fn capability_code(value: BridgeCapability) -> u8 {
    value as u8
}

const fn map_extension_error(error: ExtensionError) -> BridgeProtocolError {
    match error {
        ExtensionError::InvalidNamespace | ExtensionError::UnsupportedCritical => {
            BridgeProtocolError::InvalidExtension
        }
        ExtensionError::DuplicateExtension => BridgeProtocolError::DuplicateExtension,
        ExtensionError::TooManyExtensions => BridgeProtocolError::TooManyExtensions,
        ExtensionError::PayloadTooLarge => BridgeProtocolError::ExtensionPayloadTooLarge,
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        BridgeCapability, BridgeDataPermission, BridgeProviderManifest, ProtocolVersion,
    };

    use super::{BRIDGE_SDK_VERSION, BridgeProtocolError, canonical_bridge_manifest};

    fn manifest() -> BridgeProviderManifest {
        BridgeProviderManifest {
            provider_id: "vendor.example.bridge".to_owned(),
            sdk_min: BRIDGE_SDK_VERSION,
            sdk_max: BRIDGE_SDK_VERSION,
            protocol_min: ProtocolVersion::new(1, 0),
            protocol_max: ProtocolVersion::new(1, 0),
            capabilities: vec![BridgeCapability::Text, BridgeCapability::Reply],
            permissions: vec![BridgeDataPermission::MessageContent],
            extensions: vec![],
        }
    }

    #[test]
    fn manifest_is_canonical_and_duplicate_capabilities_fail_closed() {
        let mut value = manifest();
        value.capabilities.reverse();
        assert_eq!(
            canonical_bridge_manifest(&value)
                .expect("canonical")
                .capabilities,
            vec![BridgeCapability::Text, BridgeCapability::Reply]
        );
        value.capabilities.push(BridgeCapability::Reply);
        assert_eq!(
            canonical_bridge_manifest(&value),
            Err(BridgeProtocolError::DuplicateCapability)
        );
    }

    #[test]
    fn incompatible_sdk_fails_closed() {
        let mut value = manifest();
        value.sdk_min = ProtocolVersion::new(2, 0);
        value.sdk_max = ProtocolVersion::new(2, 0);
        assert_eq!(
            canonical_bridge_manifest(&value),
            Err(BridgeProtocolError::IncompatibleSdk)
        );
    }
}

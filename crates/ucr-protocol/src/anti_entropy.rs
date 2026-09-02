use sha2::{Digest, Sha256};
use ucr_model::{
    ActorKind, EventEnvelope, EventFingerprint, EventFingerprintAlgorithm, SyncMode, SyncSession,
    SyncState,
};

use crate::{EventError, canonical_event};

pub const EVENT_FINGERPRINT_SHA256_V1_DOMAIN: &[u8] = b"ucr:event-fingerprint:sha256:v1\0";
pub const ANTI_ENTROPY_SESSION_BINDING_V1_DOMAIN: &[u8] =
    b"ucr:anti-entropy-session-binding:sha256:v1\0";
pub const MAX_ANTI_ENTROPY_PAGE_ITEMS: usize = 256;
pub const MAX_ANTI_ENTROPY_CURSOR_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiEntropyError {
    SessionNotActive,
    PartialSelectionUnsupported,
    InvalidPageSize,
    TooManySummaries,
    EmptyCursor,
    CursorTooLarge,
    CursorBindingMismatch,
    MalformedCursor,
}

/// Validates that a `SyncSession` can perform Event-level anti-entropy.
///
/// Phase 12 intentionally fails closed for conversation-selected Partial Sync:
/// UCR does not yet define canonical Event-to-Conversation applicability.
///
/// # Errors
/// Returns an explicit lifecycle or selection error.
pub const fn validate_anti_entropy_session(session: &SyncSession) -> Result<(), AntiEntropyError> {
    if !matches!(session.state, SyncState::Active) {
        return Err(AntiEntropyError::SessionNotActive);
    }
    if matches!(session.selection.mode, SyncMode::Partial) {
        return Err(AntiEntropyError::PartialSelectionUnsupported);
    }
    Ok(())
}

/// Validates one requested anti-entropy page size.
///
/// # Errors
/// Returns [`AntiEntropyError::InvalidPageSize`] for zero or over-budget pages.
pub const fn validate_anti_entropy_page_size(max_items: usize) -> Result<(), AntiEntropyError> {
    if max_items == 0 || max_items > MAX_ANTI_ENTROPY_PAGE_ITEMS {
        Err(AntiEntropyError::InvalidPageSize)
    } else {
        Ok(())
    }
}

/// Validates one incoming Anti-Entropy summary batch before allocation-heavy classification.
///
/// Empty batches are valid; over-budget batches fail closed.
///
/// # Errors
/// Returns [`AntiEntropyError::TooManySummaries`] above the canonical page budget.
pub const fn validate_anti_entropy_summary_count(count: usize) -> Result<(), AntiEntropyError> {
    if count > MAX_ANTI_ENTROPY_PAGE_ITEMS {
        Err(AntiEntropyError::TooManySummaries)
    } else {
        Ok(())
    }
}

/// Validates the opaque cursor resource budget without interpreting its bytes.
///
/// # Errors
/// Returns an explicit empty/over-budget cursor error.
pub fn validate_anti_entropy_cursor(token: &[u8]) -> Result<(), AntiEntropyError> {
    if token.is_empty() {
        return Err(AntiEntropyError::EmptyCursor);
    }
    if token.len() > MAX_ANTI_ENTROPY_CURSOR_LEN {
        return Err(AntiEntropyError::CursorTooLarge);
    }
    Ok(())
}

/// Produces the versioned canonical SHA-256 fingerprint for an Event.
///
/// The encoding is protocol-owned and domain-separated. Extension order is
/// canonicalized first, so semantically identical extension sets hash equally.
///
/// # Errors
/// Returns Event validation failures before any fingerprint is produced.
pub fn event_fingerprint(event: &EventEnvelope) -> Result<EventFingerprint, EventError> {
    let event = canonical_event(event)?;
    let mut hash = Sha256::new();
    hash.update(EVENT_FINGERPRINT_SHA256_V1_DOMAIN);
    hash_string(&mut hash, event.event_id.as_opaque().as_str());
    hash_scope(&mut hash, &event.scope);
    hash_string(&mut hash, &event.event_type);
    hash_bytes(&mut hash, &event.payload);
    hash_string(&mut hash, event.actor.actor_id.as_opaque().as_str());
    hash.update([actor_kind_code(event.actor.kind)]);
    hash_optional_id(
        &mut hash,
        event
            .actor
            .on_behalf_of
            .as_ref()
            .map(|id| id.as_opaque().as_str()),
    );
    hash_string(
        &mut hash,
        event.source_device.device_id.as_opaque().as_str(),
    );
    hash_string(
        &mut hash,
        event.source_device.identity_id.as_opaque().as_str(),
    );
    hash.update(event.wall_time_unix_ms.to_be_bytes());
    hash.update(event.logical_order.to_be_bytes());
    hash_string(&mut hash, event.correlation.correlation_id.as_str());
    hash_optional_id(
        &mut hash,
        event
            .correlation
            .causation_id
            .as_ref()
            .map(ucr_model::OpaqueId::as_str),
    );
    hash_optional_string(&mut hash, event.correlation.idempotency_key.as_deref());
    hash.update(event.schema_version.major.to_be_bytes());
    hash.update(event.schema_version.minor.to_be_bytes());
    hash_bytes(&mut hash, &event.integrity_metadata);
    hash.update((event.extensions.len() as u64).to_be_bytes());
    for extension in &event.extensions {
        hash_string(&mut hash, &extension.name);
        hash.update([u8::from(extension.critical)]);
        hash_bytes(&mut hash, &extension.payload);
    }
    Ok(EventFingerprint {
        algorithm: EventFingerprintAlgorithm::Sha256V1,
        digest: hash.finalize().into(),
    })
}

/// Produces a session/source/target binding digest for opaque store cursors.
///
/// The digest is not a resume position and exposes no storage ordering.
#[must_use]
pub fn anti_entropy_session_binding(session: &SyncSession) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ANTI_ENTROPY_SESSION_BINDING_V1_DOMAIN);
    hash_string(&mut hash, session.session_id.as_opaque().as_str());
    hash_scope(&mut hash, &session.scope);
    hash_string(&mut hash, session.source_endpoint_id.as_opaque().as_str());
    hash_string(&mut hash, session.target_endpoint_id.as_opaque().as_str());
    hash.finalize().into()
}

fn hash_scope(hash: &mut Sha256, scope: &ucr_model::TenantScope) {
    hash_string(hash, scope.tenant_id.as_opaque().as_str());
    match &scope.namespace_id {
        Some(namespace) => {
            hash.update([1]);
            hash_string(hash, namespace.as_opaque().as_str());
        }
        None => hash.update([0]),
    }
}

fn hash_optional_id(hash: &mut Sha256, value: Option<&str>) {
    hash_optional_string(hash, value);
}

fn hash_optional_string(hash: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash_string(hash, value);
        }
        None => hash.update([0]),
    }
}

fn hash_string(hash: &mut Sha256, value: &str) {
    hash_bytes(hash, value.as_bytes());
}

fn hash_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

const fn actor_kind_code(kind: ActorKind) -> u8 {
    match kind {
        ActorKind::Person => 1,
        ActorKind::AiAgent => 2,
        ActorKind::Bot => 3,
        ActorKind::Organization => 4,
        ActorKind::System => 5,
    }
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EventEnvelope,
        EventId, IdentityId, NamespaceId, OpaqueId, ProtocolExtension, ProtocolVersion, TenantId,
        TenantScope,
    };

    use super::event_fingerprint;

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid id")
    }

    fn golden_event() -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_opaque(oid("event-golden")),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(oid("tenant-a")),
                namespace_id: Some(NamespaceId::from_opaque(oid("namespace-a"))),
            },
            event_type: "ucr.message.created".to_owned(),
            payload: b"hello".to_vec(),
            actor: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            wall_time_unix_ms: 1_700_000_000_123,
            logical_order: 42,
            correlation: CorrelationContext {
                correlation_id: oid("corr-a"),
                causation_id: Some(oid("cmd-a")),
                idempotency_key: None,
            },
            schema_version: ProtocolVersion::new(1, 2),
            integrity_metadata: b"integrity".to_vec(),
            extensions: vec![
                ProtocolExtension {
                    name: "vendor.example.z".to_owned(),
                    critical: false,
                    payload: b"z".to_vec(),
                },
                ProtocolExtension {
                    name: "ucr.example.a".to_owned(),
                    critical: true,
                    payload: b"a".to_vec(),
                },
            ],
        }
    }

    #[test]
    fn incoming_summary_count_is_bounded_before_classification() {
        assert_eq!(super::validate_anti_entropy_summary_count(0), Ok(()));
        assert_eq!(
            super::validate_anti_entropy_summary_count(super::MAX_ANTI_ENTROPY_PAGE_ITEMS),
            Ok(())
        );
        assert_eq!(
            super::validate_anti_entropy_summary_count(super::MAX_ANTI_ENTROPY_PAGE_ITEMS + 1),
            Err(super::AntiEntropyError::TooManySummaries)
        );
    }

    #[test]
    fn actor_kind_fingerprint_codes_are_stable() {
        assert_eq!(super::actor_kind_code(ActorKind::Person), 1);
        assert_eq!(super::actor_kind_code(ActorKind::AiAgent), 2);
        assert_eq!(super::actor_kind_code(ActorKind::Bot), 3);
        assert_eq!(super::actor_kind_code(ActorKind::Organization), 4);
        assert_eq!(super::actor_kind_code(ActorKind::System), 5);
    }

    #[test]
    fn event_fingerprint_sha256_v1_matches_golden_vector() {
        let fingerprint = event_fingerprint(&golden_event()).expect("fingerprint");
        assert_eq!(
            fingerprint.digest,
            [
                0xef, 0xc6, 0xbb, 0x9f, 0xdc, 0x49, 0x5c, 0xcb, 0x4e, 0x81, 0x2a, 0xb4, 0xd8, 0xcd,
                0x68, 0x81, 0x62, 0x71, 0x98, 0x3f, 0x7a, 0xaf, 0x8b, 0x62, 0xa9, 0xc3, 0xd7, 0x35,
                0x9e, 0xa8, 0x2e, 0x61,
            ]
        );
    }

    #[test]
    fn extension_order_does_not_change_fingerprint_but_payload_does() {
        let original = golden_event();
        let mut reordered = original.clone();
        reordered.extensions.reverse();
        assert_eq!(event_fingerprint(&original), event_fingerprint(&reordered));

        let mut changed = original.clone();
        changed.extensions[0].payload.push(b'!');
        assert_ne!(event_fingerprint(&original), event_fingerprint(&changed));
    }
}

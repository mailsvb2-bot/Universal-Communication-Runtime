use sha2::{Digest, Sha256};
use ucr_model::{
    EventConsumerCursor, EventEnvelope, EventSubscription, EventSubscriptionMode, OpaqueId,
    TenantScope,
};

use crate::{
    MAX_EVENT_INTEGRITY_METADATA_LEN, MAX_EVENT_PAYLOAD_LEN, MAX_EXTENSION_PAYLOAD_LEN,
    MAX_IDEMPOTENCY_KEY_LEN, MAX_NAMESPACED_IDENTIFIER_LEN, MAX_PROTOCOL_EXTENSIONS,
    canonical_event, validate_event, validate_namespaced_identifier,
};

pub const EVENT_CONSUMER_CURSOR_V1_DOMAIN: &[u8] = b"UCR-EVENT-CONSUMER-CURSOR-V1\0";
pub const MAX_EVENT_SUBSCRIPTION_FILTERS: usize = 64;
pub const MAX_EVENT_BATCH_ITEMS: usize = 256;
/// Maximum semantic byte weight of one canonical Event at current protocol limits.
/// This deliberately includes every variable-length Event field, not only `payload`.
pub const MAX_EVENT_DELIVERY_SIZE: usize = MAX_EVENT_PAYLOAD_LEN
    + MAX_EVENT_INTEGRITY_METADATA_LEN
    + MAX_PROTOCOL_EXTENSIONS * (MAX_NAMESPACED_IDENTIFIER_LEN + MAX_EXTENSION_PAYLOAD_LEN)
    + 9 * OpaqueId::MAX_LEN
    + MAX_IDEMPOTENCY_KEY_LEN
    + MAX_NAMESPACED_IDENTIFIER_LEN
    + 64;
/// Aggregate semantic byte budget for one Event delivery batch. It is at least large enough
/// for one maximum canonical Event while preventing item-count-only multi-gigabyte batches.
pub const MAX_EVENT_DELIVERY_BATCH_BYTES: usize = MAX_EVENT_DELIVERY_SIZE;
pub const MAX_EVENT_DELIVERY_ATTEMPTS: u32 = 100;
pub const MAX_EVENT_CONSUMER_CURSOR_LEN: usize = 64;
pub const MAX_WEBHOOK_URI_LEN: usize = 2048;
pub const EVENT_RETRY_BASE_MS: u64 = 1_000;
pub const EVENT_RETRY_MAX_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventApiError {
    InvalidFilter,
    DuplicateFilter,
    TooManyFilters,
    InvalidMaxInFlight,
    InvalidMaxAttempts,
    InvalidWebhookUri,
    InvalidCursor,
    InvalidBatchSize,
}

/// Validates one Phase-14 durable Event subscription.
///
/// Webhook authentication material is deliberately not part of this canonical object.
/// The persisted URI is a bounded HTTPS destination only; deployment-specific secrets
/// remain outside UCR durable subscription state.
///
/// # Errors
/// Rejects malformed filters, queue budgets, or webhook destinations.
pub fn validate_event_subscription(subscription: &EventSubscription) -> Result<(), EventApiError> {
    if subscription.event_types.len() > MAX_EVENT_SUBSCRIPTION_FILTERS {
        return Err(EventApiError::TooManyFilters);
    }
    let mut filters = subscription.event_types.clone();
    filters.sort();
    for (index, filter) in filters.iter().enumerate() {
        validate_namespaced_identifier(filter).map_err(|_| EventApiError::InvalidFilter)?;
        if index > 0 && filters[index - 1] == *filter {
            return Err(EventApiError::DuplicateFilter);
        }
    }
    if subscription.max_in_flight == 0
        || usize::try_from(subscription.max_in_flight)
            .ok()
            .is_none_or(|value| value > MAX_EVENT_BATCH_ITEMS)
    {
        return Err(EventApiError::InvalidMaxInFlight);
    }
    if subscription.max_attempts == 0 || subscription.max_attempts > MAX_EVENT_DELIVERY_ATTEMPTS {
        return Err(EventApiError::InvalidMaxAttempts);
    }
    match subscription.mode {
        EventSubscriptionMode::DurableStream => {
            if subscription.webhook_uri.is_some() {
                return Err(EventApiError::InvalidWebhookUri);
            }
        }
        EventSubscriptionMode::Webhook => {
            if subscription.max_in_flight != 1 {
                return Err(EventApiError::InvalidMaxInFlight);
            }
            let Some(uri) = subscription.webhook_uri.as_deref() else {
                return Err(EventApiError::InvalidWebhookUri);
            };
            validate_webhook_uri(uri)?;
        }
    }
    let _ = subscription.start;
    Ok(())
}

/// Returns a deterministic subscription representation for idempotent comparison.
///
/// # Errors
/// Returns the same validation failures as [`validate_event_subscription`].
pub fn canonical_event_subscription(
    subscription: &EventSubscription,
) -> Result<EventSubscription, EventApiError> {
    validate_event_subscription(subscription)?;
    let mut canonical = subscription.clone();
    canonical.event_types.sort();
    Ok(canonical)
}

fn validate_webhook_uri(uri: &str) -> Result<(), EventApiError> {
    if uri.len() > MAX_WEBHOOK_URI_LEN
        || !uri.is_ascii()
        || !uri.starts_with("https://")
        || uri.contains('@')
        || uri.contains('?')
        || uri.contains('#')
    {
        return Err(EventApiError::InvalidWebhookUri);
    }
    let authority_and_path = &uri[8..];
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.starts_with('.') || authority.ends_with('.') {
        return Err(EventApiError::InvalidWebhookUri);
    }
    Ok(())
}

/// Validates an opaque consumer cursor resource budget without interpreting it.
///
/// # Errors
/// Rejects empty or over-budget cursors.
pub fn validate_event_consumer_cursor(cursor: &EventConsumerCursor) -> Result<(), EventApiError> {
    if cursor.token.is_empty() || cursor.token.len() > MAX_EVENT_CONSUMER_CURSOR_LEN {
        return Err(EventApiError::InvalidCursor);
    }
    Ok(())
}

/// Validates a requested public delivery batch size.
///
/// # Errors
/// Rejects zero or over-budget item counts.
pub fn validate_event_batch_size(max_items: usize) -> Result<(), EventApiError> {
    if max_items == 0 || max_items > MAX_EVENT_BATCH_ITEMS {
        return Err(EventApiError::InvalidBatchSize);
    }
    Ok(())
}

/// Returns bounded exponential retry delay for the next delivery attempt.
#[must_use]
pub fn event_retry_delay_ms(next_attempt: u32) -> u64 {
    let exponent = next_attempt.saturating_sub(2).min(31);
    EVENT_RETRY_BASE_MS
        .saturating_mul(1_u64 << exponent)
        .min(EVENT_RETRY_MAX_MS)
}

/// Derives the opaque public cursor token from private store position metadata.
/// The digest prevents leaking a raw local database sequence into the public contract.
#[must_use]
pub fn event_consumer_cursor_token(
    scope: &TenantScope,
    subscription: &EventSubscription,
    generation: u64,
    end_position: u64,
    attempt: u32,
) -> EventConsumerCursor {
    let mut hash = Sha256::new();
    hash.update(EVENT_CONSUMER_CURSOR_V1_DOMAIN);
    hash_id(&mut hash, scope.tenant_id.as_opaque().as_wire_bytes());
    match &scope.namespace_id {
        Some(namespace) => {
            hash.update([1]);
            hash_id(&mut hash, namespace.as_opaque().as_wire_bytes());
        }
        None => hash.update([0]),
    }
    hash_id(
        &mut hash,
        subscription.subscription_id.as_opaque().as_wire_bytes(),
    );
    hash.update(generation.to_be_bytes());
    hash.update(end_position.to_be_bytes());
    hash.update(attempt.to_be_bytes());
    EventConsumerCursor {
        token: hash.finalize().to_vec(),
    }
}

/// Computes the bounded semantic byte weight charged to one Event delivery batch.
///
/// The weight includes all variable-length canonical Event fields plus a conservative fixed
/// scalar allowance. It is transport-neutral; concrete bindings add their own wire overhead.
///
/// # Errors
/// Returns the canonical Event validation error before calculating the weight.
pub fn event_delivery_size(event: &EventEnvelope) -> Result<usize, crate::EventError> {
    validate_event(event)?;
    let mut size = event.event_id.as_opaque().as_wire_bytes().len()
        + event.scope.tenant_id.as_opaque().as_wire_bytes().len()
        + event
            .scope
            .namespace_id
            .as_ref()
            .map_or(0, |id| id.as_opaque().as_wire_bytes().len())
        + event.event_type.len()
        + event.payload.len()
        + event.actor.actor_id.as_opaque().as_wire_bytes().len()
        + event
            .actor
            .on_behalf_of
            .as_ref()
            .map_or(0, |id| id.as_opaque().as_wire_bytes().len())
        + event
            .source_device
            .device_id
            .as_opaque()
            .as_wire_bytes()
            .len()
        + event
            .source_device
            .identity_id
            .as_opaque()
            .as_wire_bytes()
            .len()
        + event.correlation.correlation_id.as_wire_bytes().len()
        + event
            .correlation
            .causation_id
            .as_ref()
            .map_or(0, |id| id.as_wire_bytes().len())
        + event
            .correlation
            .idempotency_key
            .as_ref()
            .map_or(0, String::len)
        + event.integrity_metadata.len()
        + 64;
    for extension in &event.extensions {
        size += extension.name.len() + extension.payload.len();
    }
    debug_assert!(size <= MAX_EVENT_DELIVERY_SIZE);
    Ok(size)
}

/// Returns the aggregate byte count after adding one Event, or `None` when that Event must
/// start the next batch. Both durable store providers use this protocol-owned decision so their
/// batching semantics cannot diverge.
///
/// # Errors
/// Returns the canonical Event validation error before charging its size.
pub fn event_delivery_batch_next_size(
    current_bytes: usize,
    event: &EventEnvelope,
) -> Result<Option<usize>, crate::EventError> {
    let event_bytes = event_delivery_size(event)?;
    Ok(current_bytes
        .checked_add(event_bytes)
        .filter(|next| *next <= MAX_EVENT_DELIVERY_BATCH_BYTES))
}

/// Tests whether one canonical Event matches a canonical subscription filter.
/// Empty filter means all Event types in the exact subscription scope.
#[must_use]
pub fn event_matches_subscription(
    subscription: &EventSubscription,
    event: &ucr_model::EventEnvelope,
) -> bool {
    subscription.scope == event.scope
        && (subscription.event_types.is_empty()
            || subscription
                .event_types
                .binary_search(&event.event_type)
                .is_ok())
        && canonical_event(event).is_ok()
}

fn hash_id(hash: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("canonical identifier bounds fit u32");
    hash.update(length.to_be_bytes());
    hash.update(value);
}

#[cfg(test)]
mod tests {
    use ucr_model::{EventSubscriptionId, EventSubscriptionStart, OpaqueId, TenantId};

    use super::*;

    fn subscription(mode: EventSubscriptionMode) -> EventSubscription {
        EventSubscription {
            subscription_id: EventSubscriptionId::from_opaque(OpaqueId::new("sub-a").unwrap()),
            scope: TenantScope {
                tenant_id: TenantId::from_opaque(OpaqueId::new("tenant-a").unwrap()),
                namespace_id: None,
            },
            mode,
            webhook_uri: None,
            event_types: vec!["ucr.message.created".to_owned()],
            max_in_flight: 8,
            max_attempts: 5,
            start: EventSubscriptionStart::Beginning,
        }
    }

    fn delivery_event() -> EventEnvelope {
        use ucr_model::{
            ActorId, ActorKind, ActorRef, CorrelationContext, DeviceId, DeviceRef, EventId,
            IdentityId, ProtocolVersion,
        };

        EventEnvelope {
            event_id: EventId::from_opaque(OpaqueId::new("event-size").unwrap()),
            scope: subscription(EventSubscriptionMode::DurableStream).scope,
            event_type: "ucr.event.size".to_owned(),
            payload: vec![1, 2, 3],
            actor: ActorRef {
                actor_id: ActorId::from_opaque(OpaqueId::new("actor-size").unwrap()),
                kind: ActorKind::System,
                on_behalf_of: None,
            },
            source_device: DeviceRef {
                device_id: DeviceId::from_opaque(OpaqueId::new("device-size").unwrap()),
                identity_id: IdentityId::from_opaque(OpaqueId::new("identity-size").unwrap()),
            },
            wall_time_unix_ms: 1,
            logical_order: 1,
            correlation: CorrelationContext {
                correlation_id: OpaqueId::new("correlation-size").unwrap(),
                causation_id: None,
                idempotency_key: Some("idem".to_owned()),
            },
            schema_version: ProtocolVersion::new(1, 0),
            integrity_metadata: vec![4, 5],
            extensions: Vec::new(),
        }
    }

    #[test]
    fn subscription_canonicalizes_filters_and_enforces_webhook_security() {
        let mut stream = subscription(EventSubscriptionMode::DurableStream);
        stream.event_types = vec!["ucr.z".to_owned(), "ucr.a".to_owned()];
        let canonical = canonical_event_subscription(&stream).unwrap();
        assert_eq!(canonical.event_types, vec!["ucr.a", "ucr.z"]);
        stream.event_types.push("ucr.a".to_owned());
        assert_eq!(
            validate_event_subscription(&stream),
            Err(EventApiError::DuplicateFilter)
        );

        let mut webhook = subscription(EventSubscriptionMode::Webhook);
        webhook.max_in_flight = 1;
        webhook.webhook_uri = Some("https://events.example.test/ucr".to_owned());
        assert_eq!(validate_event_subscription(&webhook), Ok(()));
        webhook.webhook_uri = Some("https://token@events.example.test/ucr".to_owned());
        assert_eq!(
            validate_event_subscription(&webhook),
            Err(EventApiError::InvalidWebhookUri)
        );
    }

    #[test]
    fn delivery_size_charges_extensions_and_correlation() {
        use ucr_model::ProtocolExtension;

        let mut value = delivery_event();
        let base = event_delivery_size(&value).unwrap();
        value.extensions.push(ProtocolExtension {
            name: "vendor.size".to_owned(),
            critical: false,
            payload: vec![9; 7],
        });
        assert_eq!(
            event_delivery_size(&value).unwrap(),
            base + "vendor.size".len() + 7
        );
        assert!(MAX_EVENT_DELIVERY_BATCH_BYTES >= event_delivery_size(&value).unwrap());
    }

    #[test]
    fn aggregate_delivery_budget_defers_next_event_without_needing_a_large_fixture() {
        let value = delivery_event();
        let weight = event_delivery_size(&value).expect("Event weight");
        assert!(weight < MAX_EVENT_DELIVERY_BATCH_BYTES);
        let nearly_full = MAX_EVENT_DELIVERY_BATCH_BYTES - weight + 1;
        assert_eq!(
            event_delivery_batch_next_size(nearly_full, &value),
            Ok(None)
        );
        assert_eq!(event_delivery_batch_next_size(0, &value), Ok(Some(weight)));
    }

    #[test]
    fn retry_backoff_is_exponential_and_bounded() {
        assert_eq!(event_retry_delay_ms(2), 1_000);
        assert_eq!(event_retry_delay_ms(3), 2_000);
        assert_eq!(event_retry_delay_ms(4), 4_000);
        assert_eq!(event_retry_delay_ms(100), EVENT_RETRY_MAX_MS);
    }

    #[test]
    fn cursor_is_opaque_bounded_and_binds_attempt() {
        let subscription = subscription(EventSubscriptionMode::DurableStream);
        let first = event_consumer_cursor_token(&subscription.scope, &subscription, 1, 7, 1);
        let retry = event_consumer_cursor_token(&subscription.scope, &subscription, 1, 7, 2);
        assert_eq!(validate_event_consumer_cursor(&first), Ok(()));
        assert_ne!(first, retry);
        assert_eq!(first.token.len(), 32);
    }
}

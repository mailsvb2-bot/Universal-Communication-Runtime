use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ucr_model::{
    EventConsumerCursor, EventDeadLetter, EventDeliveryFailureKind, EventEnvelope, EventPollResult,
    EventSubscription, EventSubscriptionId, EventSubscriptionMode, OpaqueId,
    ServiceAuditOperationRef, ServiceCredentialId, TenantScope,
};
use ucr_protocol::{
    CanonicalError, CanonicalErrorCode, EVENT_APPEND_PERMISSION, EVENT_CONSUME_PERMISSION,
    EVENT_DEAD_LETTER_READ_PERMISSION, EVENT_REPLAY_PERMISSION, EVENT_SUBSCRIBE_PERMISSION,
    SERVICE_AUDIT_EVENT_ACK_OPERATION_KIND, SERVICE_AUDIT_EVENT_DEAD_LETTER_READ_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_POLL_OPERATION_KIND, SERVICE_AUDIT_EVENT_PUBLISH_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_REJECT_OPERATION_KIND, SERVICE_AUDIT_EVENT_REPLAY_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_SUBSCRIPTION_CREATE_OPERATION_KIND,
    SERVICE_AUDIT_EVENT_SUBSCRIPTION_READ_OPERATION_KIND,
};

use crate::{
    AuthorizationEvaluator, AuthorizedDurableRuntime, AuthorizedMutationError, DurableRecordStatus,
    DurableStoreError, EventAppendStatus, EventSubscriptionStore, ServiceAuditStore,
    ServiceCredentialSecret, ServiceCredentialStore, ServicePrincipalRequestGate,
    ServiceQuotaClock, ServiceQuotaStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDeliveryClockError {
    Unavailable,
}

/// Trusted local time source used only for Event retry scheduling/backoff.
/// It is not Event ordering, authentication, replay, identity, or authorization evidence.
pub trait EventDeliveryClock: fmt::Debug + Send + Sync {
    /// Returns current Unix epoch milliseconds for retry scheduling.
    ///
    /// # Errors
    /// Fails closed when a usable timestamp cannot be produced.
    fn now_unix_ms(&self) -> Result<i64, EventDeliveryClockError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEventDeliveryClock;

impl EventDeliveryClock for SystemEventDeliveryClock {
    fn now_unix_ms(&self) -> Result<i64, EventDeliveryClockError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EventDeliveryClockError::Unavailable)?;
        i64::try_from(duration.as_millis()).map_err(|_| EventDeliveryClockError::Unavailable)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EventCursorRejection<'a> {
    pub scope: &'a TenantScope,
    pub subscription_id: &'a EventSubscriptionId,
    pub cursor: &'a EventConsumerCursor,
    pub failure_kind: EventDeliveryFailureKind,
}

/// Transport-neutral Phase-14 ingress for external Service Principal Event operations.
///
/// Binding-specific credential presentation terminates before this boundary. The ingress composes
/// the existing Service Principal authentication/quota/audit/permission path with the single
/// canonical Event journal and its durable subscription state; it never exposes raw storage.
pub struct EventApiIngress<'a, Q, E, A, S> {
    quota_clock: &'a Q,
    event_clock: &'a E,
    authorization: &'a A,
    store: &'a S,
}

impl<Q, E, A, S> fmt::Debug for EventApiIngress<'_, Q, E, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventApiIngress")
            .finish_non_exhaustive()
    }
}

impl<'a, Q, E, A, S> EventApiIngress<'a, Q, E, A, S> {
    #[must_use]
    pub const fn new(
        quota_clock: &'a Q,
        event_clock: &'a E,
        authorization: &'a A,
        store: &'a S,
    ) -> Self {
        Self {
            quota_clock,
            event_clock,
            authorization,
            store,
        }
    }
}

impl<Q, E, A, S> EventApiIngress<'_, Q, E, A, S>
where
    Q: ServiceQuotaClock,
    E: EventDeliveryClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore + EventSubscriptionStore,
{
    /// Publishes/deduplicates one canonical fact through the existing append-only Event journal.
    ///
    /// # Errors
    /// Returns canonical authentication, quota, permission, validation, conflict, or store errors.
    pub fn publish_event(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        event: &EventEnvelope,
    ) -> Result<EventAppendStatus, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_PUBLISH_OPERATION_KIND,
            event.event_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_APPEND_PERMISSION,
            &event.scope,
            &operation,
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .append_event(&subject, event)
            .map_err(map_authorized_error)
    }

    /// Creates/deduplicates one durable Event subscription.
    ///
    /// # Errors
    /// Returns canonical admission, validation, conflict, or store errors.
    pub fn create_subscription(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        subscription: &EventSubscription,
    ) -> Result<EventSubscription, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_SUBSCRIPTION_CREATE_OPERATION_KIND,
            subscription.subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_SUBSCRIBE_PERMISSION,
            &subscription.scope,
            &operation,
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .persist_event_subscription(&subject, subscription)
            .map_err(map_authorized_error)?;
        self.store
            .event_subscription(&subscription.scope, &subscription.subscription_id)
            .map_err(map_store_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))
    }

    /// Reads one exact subscription only after complete admission/authorization.
    ///
    /// # Errors
    /// Returns `NOT_FOUND` only after authority succeeds, preventing existence probing.
    pub fn get_subscription(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
    ) -> Result<EventSubscription, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_SUBSCRIPTION_READ_OPERATION_KIND,
            subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_SUBSCRIBE_PERMISSION,
            scope,
            &operation,
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .event_subscription(&subject, scope, subscription_id)
            .map_err(map_authorized_error)?
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::NotFound))
    }

    /// Polls one bounded durable batch with cursor-based redelivery/backpressure semantics.
    ///
    /// # Errors
    /// Returns canonical admission, clock, validation, missing-subscription, or store errors.
    pub fn poll_events(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        max_items: usize,
    ) -> Result<EventPollResult, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_POLL_OPERATION_KIND,
            subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_CONSUME_PERMISSION,
            scope,
            &operation,
        )?;
        let now = self
            .event_clock
            .now_unix_ms()
            .map_err(map_event_clock_error)?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .poll_event_subscription(&subject, scope, subscription_id, max_items, now)
            .map_err(map_authorized_error)
    }

    /// Acknowledges the exact active cursor; equal retries are idempotent.
    ///
    /// # Errors
    /// Returns canonical admission, stale-cursor conflict, or store errors.
    pub fn acknowledge_events(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        cursor: &EventConsumerCursor,
    ) -> Result<DurableRecordStatus, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_ACK_OPERATION_KIND,
            subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_CONSUME_PERMISSION,
            scope,
            &operation,
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .acknowledge_event_cursor(&subject, scope, subscription_id, cursor)
            .map_err(map_authorized_error)
    }

    /// Rejects the exact active cursor and atomically applies retry/dead-letter policy.
    ///
    /// # Errors
    /// Returns canonical admission, clock, stale-cursor conflict, or store errors.
    pub fn reject_events(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        rejection: EventCursorRejection<'_>,
    ) -> Result<DurableRecordStatus, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_REJECT_OPERATION_KIND,
            rejection.subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_CONSUME_PERMISSION,
            rejection.scope,
            &operation,
        )?;
        let now = self
            .event_clock
            .now_unix_ms()
            .map_err(map_event_clock_error)?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .reject_event_cursor(
                &subject,
                rejection.scope,
                rejection.subscription_id,
                rejection.cursor,
                rejection.failure_kind,
                now,
            )
            .map_err(map_authorized_error)
    }

    /// Starts an idempotent full replay and invalidates all previous consumer cursors.
    ///
    /// # Errors
    /// Returns canonical admission, validation, missing-subscription, or store errors.
    pub fn replay_subscription(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        replay_id: &OpaqueId,
    ) -> Result<DurableRecordStatus, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_REPLAY_OPERATION_KIND,
            subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_REPLAY_PERMISSION,
            scope,
            &operation,
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .replay_event_subscription(&subject, scope, subscription_id, replay_id)
            .map_err(map_authorized_error)
    }

    /// Lists a bounded dead-letter view after independent dead-letter-read authority.
    ///
    /// # Errors
    /// Returns canonical admission, validation, missing-subscription, or store errors.
    pub fn list_dead_letters(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
        max_items: usize,
    ) -> Result<Vec<EventDeadLetter>, CanonicalError> {
        let operation = operation(
            SERVICE_AUDIT_EVENT_DEAD_LETTER_READ_OPERATION_KIND,
            subscription_id.as_opaque(),
        );
        let request = self.request(
            presented_scope,
            credential_id,
            secret,
            EVENT_DEAD_LETTER_READ_PERMISSION,
            scope,
            &operation,
        )?;
        let subject = request.subject().clone();
        AuthorizedDurableRuntime::new(&request, self.store)
            .event_dead_letters(&subject, scope, subscription_id, max_items)
            .map_err(map_authorized_error)
    }

    fn request(
        &self,
        presented_scope: &TenantScope,
        credential_id: &ServiceCredentialId,
        secret: &ServiceCredentialSecret,
        permission: &str,
        resource_scope: &TenantScope,
        operation: &ServiceAuditOperationRef,
    ) -> Result<crate::ServicePrincipalRequestAuthorization<'_, Q, A, S>, CanonicalError> {
        ServicePrincipalRequestGate::new(self.quota_clock, self.authorization, self.store)
            .authenticate_request_for_operation(
                presented_scope,
                credential_id,
                secret,
                permission,
                resource_scope,
                operation,
            )
    }
}

fn operation(kind: &str, id: &OpaqueId) -> ServiceAuditOperationRef {
    ServiceAuditOperationRef {
        operation_kind: kind.to_owned(),
        operation_id: id.clone(),
    }
}

const fn map_event_clock_error(_error: EventDeliveryClockError) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable)
}

const fn map_authorized_error(error: AuthorizedMutationError) -> CanonicalError {
    match error {
        AuthorizedMutationError::Authorization(error) => error,
        AuthorizedMutationError::Store(error) => map_store_error(error),
    }
}

const fn map_store_error(error: DurableStoreError) -> CanonicalError {
    CanonicalError::new(match error {
        DurableStoreError::InvalidRecord => CanonicalErrorCode::InvalidArgument,
        DurableStoreError::Conflict => CanonicalErrorCode::Conflict,
        DurableStoreError::Full => CanonicalErrorCode::ResourceExhausted,
        DurableStoreError::Unavailable => CanonicalErrorCode::TemporarilyUnavailable,
        DurableStoreError::PermissionDenied => CanonicalErrorCode::PermissionDenied,
        DurableStoreError::Corrupt
        | DurableStoreError::UnsupportedSchemaVersion
        | DurableStoreError::ForeignStore
        | DurableStoreError::Internal => CanonicalErrorCode::Internal,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventWebhookDeliveryError {
    Retryable,
    Permanent,
}

/// Deployment-owned webhook side effect. Phase 14 defines delivery semantics, not Internet transport.
pub trait EventWebhookSink: fmt::Debug + Send + Sync {
    /// Delivers exactly one canonical Event to the configured webhook destination.
    ///
    /// # Errors
    /// Classifies a failed attempt as retryable or permanent without leaking provider errors.
    fn deliver(
        &self,
        subscription: &EventSubscription,
        event: &EventEnvelope,
    ) -> Result<(), EventWebhookDeliveryError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookDispatchOutcome {
    Idle,
    RetryAfter { retry_after_ms: u64 },
    Delivered,
    RetryScheduled,
    DeadLettered,
}

/// Internal reference dispatcher over the same durable subscription owner used by public polling.
/// No HTTP client, listener, DNS policy, or Internet transport is implemented here.
#[derive(Debug)]
pub struct EventWebhookDispatcher<'a, E, S, W> {
    clock: &'a E,
    store: &'a S,
    sink: &'a W,
}

impl<'a, E, S, W> EventWebhookDispatcher<'a, E, S, W> {
    #[must_use]
    pub const fn new(clock: &'a E, store: &'a S, sink: &'a W) -> Self {
        Self { clock, store, sink }
    }
}

impl<E, S, W> EventWebhookDispatcher<'_, E, S, W>
where
    E: EventDeliveryClock,
    S: EventSubscriptionStore,
    W: EventWebhookSink,
{
    /// Attempts one bounded webhook delivery from durable state.
    ///
    /// # Errors
    /// Fails closed on invalid subscription mode, clock failure, or durable-state corruption.
    pub fn dispatch_once(
        &self,
        scope: &TenantScope,
        subscription_id: &EventSubscriptionId,
    ) -> Result<WebhookDispatchOutcome, DurableStoreError> {
        let subscription = self
            .store
            .event_subscription(scope, subscription_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        if subscription.mode != EventSubscriptionMode::Webhook || subscription.max_in_flight != 1 {
            return Err(DurableStoreError::InvalidRecord);
        }
        let now = self
            .clock
            .now_unix_ms()
            .map_err(|_| DurableStoreError::Unavailable)?;
        match self
            .store
            .poll_event_subscription(scope, subscription_id, 1, now)?
        {
            EventPollResult::Empty => Ok(WebhookDispatchOutcome::Idle),
            EventPollResult::RetryAfter { retry_after_ms } => {
                Ok(WebhookDispatchOutcome::RetryAfter { retry_after_ms })
            }
            EventPollResult::Batch(batch) => {
                let [event] = batch.events.as_slice() else {
                    return Err(DurableStoreError::Corrupt);
                };
                match self.sink.deliver(&subscription, event) {
                    Ok(()) => {
                        self.store.acknowledge_event_cursor(
                            scope,
                            subscription_id,
                            &batch.cursor,
                        )?;
                        Ok(WebhookDispatchOutcome::Delivered)
                    }
                    Err(error) => {
                        let failure = match error {
                            EventWebhookDeliveryError::Retryable => {
                                EventDeliveryFailureKind::Retryable
                            }
                            EventWebhookDeliveryError::Permanent => {
                                EventDeliveryFailureKind::Permanent
                            }
                        };
                        self.store.reject_event_cursor(
                            scope,
                            subscription_id,
                            &batch.cursor,
                            failure,
                            now,
                        )?;
                        if failure == EventDeliveryFailureKind::Permanent
                            || batch.attempt >= subscription.max_attempts
                        {
                            Ok(WebhookDispatchOutcome::DeadLettered)
                        } else {
                            Ok(WebhookDispatchOutcome::RetryScheduled)
                        }
                    }
                }
            }
        }
    }
}

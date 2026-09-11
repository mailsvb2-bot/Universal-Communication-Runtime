#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use ucr_core::{
    DeliveryStore, DurableRecordStatus, DurableStoreError, IdGenerationError, PolicyEvaluator,
    StoreForwardStore, generate_opaque_id,
};
use ucr_model::{
    DeliveryAttempt, DeliveryEvidence, DeliveryEvidenceKind, DeliveryPolicy, DeliveryState,
    MessageEnvelope, StoreForwardId, StoreForwardJob, StoreForwardLeaseId, StoreForwardOutcome,
    TenantScope, TransportFailoverPolicy, TransportResourceSnapshot, TransportRoutingHint,
};
use ucr_protocol::{
    StoreForwardError, store_forward_delivery_id, store_forward_next_attempt_at,
    validate_store_forward_job,
};
use ucr_transport_orchestrator::{
    TransportFailoverClock, TransportOrchestrator, TransportOrchestratorError, TransportRouteOption,
};

pub const STORE_FORWARD_CAPABILITY: &str = "ucr.delivery.store_forward";
pub const STORE_FORWARD_INTERNET_CAPABILITY: &str = "ucr.transport.internet.tcp";
pub const STORE_FORWARD_LOCAL_CAPABILITY: &str = "ucr.transport.local.tcp";

pub trait StoreForwardClock: core::fmt::Debug + Send + Sync {
    fn now_unix_ms(&self) -> i64;
}

#[derive(Debug, Default)]
pub struct SystemStoreForwardClock;

impl StoreForwardClock for SystemStoreForwardClock {
    fn now_unix_ms(&self) -> i64 {
        let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return 0;
        };
        i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
    }
}

impl TransportFailoverClock for SystemStoreForwardClock {
    fn now_unix_ms(&self) -> i64 {
        StoreForwardClock::now_unix_ms(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreForwardRuntimeError {
    Store(DurableStoreError),
    Protocol(StoreForwardError),
    IdGeneration(IdGenerationError),
    MissingJob,
    MissingIntent,
    MissingMessage,
    UnsupportedDeliveryPolicy,
    Orchestrator(TransportOrchestratorError),
}

impl From<DurableStoreError> for StoreForwardRuntimeError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<StoreForwardError> for StoreForwardRuntimeError {
    fn from(error: StoreForwardError) -> Self {
        Self::Protocol(error)
    }
}

impl From<IdGenerationError> for StoreForwardRuntimeError {
    fn from(error: IdGenerationError) -> Self {
        Self::IdGeneration(error)
    }
}

#[derive(Debug)]
struct PreparedAttempt {
    attempt: DeliveryAttempt,
    attempts_used: u16,
}

#[derive(Debug)]
pub struct StoreForwardRuntime<'a, S> {
    store: &'a S,
    orchestrator: TransportOrchestrator<'a>,
    clock: &'a dyn StoreForwardClock,
}

impl<'a, S> StoreForwardRuntime<'a, S> {
    #[must_use]
    pub const fn new(
        store: &'a S,
        policy: &'a dyn PolicyEvaluator,
        clock: &'a dyn StoreForwardClock,
    ) -> Self {
        Self {
            store,
            orchestrator: TransportOrchestrator::new(policy),
            clock,
        }
    }
}

impl<S> StoreForwardRuntime<'_, S>
where
    S: StoreForwardStore,
{
    /// Persists one sender-side durable Store-and-Forward scheduling job.
    ///
    /// # Errors
    /// Fails closed for malformed bounds, absent canonical Intent/Message owners, unsupported
    /// delivery policy, semantic ID reuse, or storage errors.
    pub fn enqueue(
        &self,
        job: &StoreForwardJob,
    ) -> Result<DurableRecordStatus, StoreForwardRuntimeError> {
        validate_store_forward_job(job)?;
        if job.attempts_used != 0 || job.last_delivery_id.is_some() {
            return Err(StoreForwardRuntimeError::Protocol(
                StoreForwardError::InvalidAttemptState,
            ));
        }
        let intent = self
            .store
            .communication_intent(&job.scope, &job.intent_id)?
            .ok_or(StoreForwardRuntimeError::MissingIntent)?;
        let message = self
            .store
            .message(&job.scope, &job.message_id)?
            .ok_or(StoreForwardRuntimeError::MissingMessage)?;
        validate_delivery_policy(&message, job)?;
        if intent.scope != job.scope || message.scope != job.scope {
            return Err(StoreForwardRuntimeError::Store(
                DurableStoreError::InvalidRecord,
            ));
        }
        self.store
            .persist_store_forward_job(job)
            .map_err(Into::into)
    }

    /// Returns bounded due jobs without exposing payload or route metadata.
    ///
    /// # Errors
    /// Returns explicit storage/validation failures.
    pub fn due_jobs(
        &self,
        scope: &TenantScope,
        max_items: usize,
    ) -> Result<Vec<StoreForwardId>, StoreForwardRuntimeError> {
        self.store
            .due_store_forward_jobs(scope, self.clock.now_unix_ms(), max_items)
            .map_err(Into::into)
    }

    /// Runs one bounded sender-side Store-and-Forward iteration.
    ///
    /// The scheduler reuses canonical Delivery attempts. It marks an attempt `IN_FLIGHT` before
    /// provider invocation; a crash from that point is therefore conservatively ambiguous and is
    /// never automatically replayed. Proven failure closes that attempt and a later retry gets a
    /// new deterministic `DeliveryId`.
    ///
    /// # Errors
    /// Returns explicit validation/storage/routing failures. A normal no-route state is rescheduled
    /// and returned as an outcome rather than an error.
    pub fn process_one(
        &self,
        scope: &TenantScope,
        store_forward_id: &StoreForwardId,
        resources: TransportResourceSnapshot,
        hints: &[TransportRoutingHint],
        options: Vec<TransportRouteOption<'_>>,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        let now = self.clock.now_unix_ms();
        let job = self
            .store
            .store_forward_job(scope, store_forward_id)?
            .ok_or(StoreForwardRuntimeError::MissingJob)?;
        validate_store_forward_job(&job)?;
        let last = self.last_attempt(&job)?;
        if let Some(outcome) = self.resolve_existing_state(&job, last.as_ref(), now)? {
            return Ok(outcome);
        }

        let Some(lease) = self.claim(&job, now)? else {
            return Ok(StoreForwardOutcome::Busy);
        };
        let (intent, message) = self.load_job_owners(&job)?;
        let filtered = filter_direct_options(message.delivery_policy, options);
        let plan = match self.plan_job(&intent, resources, hints, filtered) {
            Ok(plan) => plan,
            Err(
                TransportOrchestratorError::NoEligibleRoute
                | TransportOrchestratorError::PolicyDenied
                | TransportOrchestratorError::PolicyPending,
            ) => return self.reschedule_no_route(&lease, now),
            Err(error) => return Err(StoreForwardRuntimeError::Orchestrator(error)),
        };
        let prepared = self.prepare_attempt(&job, &lease, last)?;
        self.execute_attempt(&job, &lease, &intent, &plan, &prepared, now)
    }

    fn resolve_existing_state(
        &self,
        job: &StoreForwardJob,
        last: Option<&DeliveryAttempt>,
        now: i64,
    ) -> Result<Option<StoreForwardOutcome>, StoreForwardRuntimeError> {
        if last.is_some_and(|attempt| attempt.state == DeliveryState::InFlight) {
            return Ok(Some(StoreForwardOutcome::AcceptanceUnknown));
        }
        if last.is_some_and(|attempt| {
            matches!(
                attempt.state,
                DeliveryState::Acknowledged | DeliveryState::Delivered | DeliveryState::Read
            )
        }) {
            return self
                .finish_existing(job, now, StoreForwardOutcome::AcceptedByTransport)
                .map(Some);
        }
        if job
            .policy
            .expires_at_unix_ms
            .is_some_and(|expiry| now >= expiry)
        {
            return self.expire_existing(job, last, now).map(Some);
        }
        if last.is_some_and(|attempt| attempt.state == DeliveryState::Expired) {
            return self
                .finish_existing(job, now, StoreForwardOutcome::Expired)
                .map(Some);
        }
        if last.is_some_and(|attempt| attempt.state == DeliveryState::Failed)
            && job.attempts_used >= job.policy.max_delivery_attempts
        {
            return self
                .finish_existing(job, now, StoreForwardOutcome::AttemptsExhausted)
                .map(Some);
        }
        Ok((job.next_attempt_at_unix_ms > now).then_some(StoreForwardOutcome::NotDue))
    }

    fn load_job_owners(
        &self,
        job: &StoreForwardJob,
    ) -> Result<(ucr_model::CommunicationIntent, MessageEnvelope), StoreForwardRuntimeError> {
        let intent = self
            .store
            .communication_intent(&job.scope, &job.intent_id)?
            .ok_or(StoreForwardRuntimeError::MissingIntent)?;
        let message = self
            .store
            .message(&job.scope, &job.message_id)?
            .ok_or(StoreForwardRuntimeError::MissingMessage)?;
        validate_delivery_policy(&message, job)?;
        Ok((intent, message))
    }

    fn plan_job<'route>(
        &self,
        intent: &ucr_model::CommunicationIntent,
        resources: TransportResourceSnapshot,
        hints: &[TransportRoutingHint],
        options: Vec<TransportRouteOption<'route>>,
    ) -> Result<ucr_transport_orchestrator::TransportPlan<'route>, TransportOrchestratorError> {
        self.orchestrator.plan(intent, resources, hints, options)
    }

    fn prepare_attempt(
        &self,
        job: &StoreForwardJob,
        lease: &ucr_model::StoreForwardLease,
        last: Option<DeliveryAttempt>,
    ) -> Result<PreparedAttempt, StoreForwardRuntimeError> {
        let (mut attempt, attempts_used) = match last {
            Some(attempt) if attempt.state != DeliveryState::Failed => (attempt, job.attempts_used),
            _ => self.create_retry_attempt(lease)?,
        };
        normalize_pre_route_attempt(self.store, &mut attempt)?;
        if attempt.state == DeliveryState::Queued {
            self.store.transition_delivery(
                &attempt.scope,
                &attempt.delivery_id,
                DeliveryState::Queued,
                DeliveryState::RoutePlanned,
                None,
            )?;
            attempt.state = DeliveryState::RoutePlanned;
        }
        self.store.transition_delivery(
            &attempt.scope,
            &attempt.delivery_id,
            DeliveryState::RoutePlanned,
            DeliveryState::InFlight,
            None,
        )?;
        attempt.state = DeliveryState::InFlight;
        Ok(PreparedAttempt {
            attempt,
            attempts_used,
        })
    }

    fn execute_attempt(
        &self,
        job: &StoreForwardJob,
        lease: &ucr_model::StoreForwardLease,
        intent: &ucr_model::CommunicationIntent,
        plan: &ucr_transport_orchestrator::TransportPlan<'_>,
        prepared: &PreparedAttempt,
        now: i64,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        // One canonical DeliveryAttempt authorizes at most one actual provider invocation.
        // Phase-25 may skip a route before invocation, but any later provider-bearing retry gets
        // a fresh deterministic DeliveryId in a later Store-and-Forward iteration.
        let failover = TransportFailoverPolicy {
            max_route_attempts: 1,
            expires_at_unix_ms: job.policy.expires_at_unix_ms,
        };
        let clock = StoreForwardFailoverClock(self.clock);
        match self.orchestrator.transmit_with_failover(
            intent,
            plan,
            &job.encrypted_envelope,
            failover,
            &clock,
        ) {
            Ok(_) => self.accept_attempt(lease, &prepared.attempt, now),
            Err(error)
                if error.decision.stop_reason
                    == ucr_model::TransportFailoverStopReason::AcceptanceUnknown =>
            {
                Ok(StoreForwardOutcome::AcceptanceUnknown)
            }
            Err(_) => self.fail_attempt(job, lease, &prepared.attempt, prepared.attempts_used, now),
        }
    }

    fn accept_attempt(
        &self,
        lease: &ucr_model::StoreForwardLease,
        attempt: &DeliveryAttempt,
        now: i64,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        let evidence = DeliveryEvidence {
            delivery_id: attempt.delivery_id.clone(),
            scope: attempt.scope.clone(),
            message_id: attempt.message_id.clone(),
            kind: DeliveryEvidenceKind::AcceptedByTransport,
            logical_order: 2,
        };
        self.store.transition_delivery(
            &attempt.scope,
            &attempt.delivery_id,
            DeliveryState::InFlight,
            DeliveryState::Acknowledged,
            Some(&evidence),
        )?;
        self.store.complete_store_forward_job(lease, now)?;
        Ok(StoreForwardOutcome::AcceptedByTransport)
    }

    fn fail_attempt(
        &self,
        job: &StoreForwardJob,
        lease: &ucr_model::StoreForwardLease,
        attempt: &DeliveryAttempt,
        attempts_used: u16,
        now: i64,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        self.store.transition_delivery(
            &attempt.scope,
            &attempt.delivery_id,
            DeliveryState::InFlight,
            DeliveryState::Failed,
            None,
        )?;
        if attempts_used >= job.policy.max_delivery_attempts {
            self.store.complete_store_forward_job(lease, now)?;
            return Ok(StoreForwardOutcome::AttemptsExhausted);
        }
        if job
            .policy
            .expires_at_unix_ms
            .is_some_and(|expiry| now >= expiry)
        {
            self.store.complete_store_forward_job(lease, now)?;
            return Ok(StoreForwardOutcome::Expired);
        }
        let next = store_forward_next_attempt_at(now, &job.policy, attempts_used.max(1))?;
        self.store.reschedule_store_forward_job(lease, next, now)?;
        Ok(StoreForwardOutcome::RescheduledAfterFailure)
    }

    fn last_attempt(
        &self,
        job: &StoreForwardJob,
    ) -> Result<Option<DeliveryAttempt>, StoreForwardRuntimeError> {
        match job.last_delivery_id.as_ref() {
            Some(delivery_id) => self
                .store
                .delivery_attempt(&job.scope, delivery_id)?
                .map(Some)
                .ok_or(StoreForwardRuntimeError::Store(DurableStoreError::Corrupt)),
            None => Ok(None),
        }
    }

    fn claim(
        &self,
        job: &StoreForwardJob,
        now: i64,
    ) -> Result<Option<ucr_model::StoreForwardLease>, StoreForwardRuntimeError> {
        let lease_id = StoreForwardLeaseId::from_opaque(generate_opaque_id()?);
        let lease_ms = i64::try_from(job.policy.lease_duration_ms)
            .map_err(|_| StoreForwardRuntimeError::Store(DurableStoreError::InvalidRecord))?;
        let lease_until = now
            .checked_add(lease_ms)
            .ok_or(StoreForwardRuntimeError::Store(
                DurableStoreError::InvalidRecord,
            ))?;
        self.store
            .claim_store_forward_job(
                &job.scope,
                &job.store_forward_id,
                &lease_id,
                now,
                lease_until,
            )
            .map_err(Into::into)
    }

    fn create_retry_attempt(
        &self,
        lease: &ucr_model::StoreForwardLease,
    ) -> Result<(DeliveryAttempt, u16), StoreForwardRuntimeError> {
        let ordinal = lease.job.attempts_used.saturating_add(1);
        if ordinal == 0 || ordinal > lease.job.policy.max_delivery_attempts {
            return Err(StoreForwardRuntimeError::Protocol(
                StoreForwardError::InvalidAttemptState,
            ));
        }
        let delivery_id =
            store_forward_delivery_id(&lease.job.scope, &lease.job.store_forward_id, ordinal);
        let attempt = DeliveryAttempt {
            delivery_id: delivery_id.clone(),
            scope: lease.job.scope.clone(),
            message_id: lease.job.message_id.clone(),
            state: DeliveryState::Persisted,
        };
        let evidence = DeliveryEvidence {
            delivery_id: delivery_id.clone(),
            scope: lease.job.scope.clone(),
            message_id: lease.job.message_id.clone(),
            kind: DeliveryEvidenceKind::PersistedLocal,
            logical_order: 1,
        };
        let _ = self.store.create_delivery_attempt(&attempt, &evidence)?;
        self.store.record_store_forward_attempt(
            lease,
            &delivery_id,
            ordinal,
            self.clock.now_unix_ms(),
        )?;
        Ok((attempt, ordinal))
    }

    fn reschedule_no_route(
        &self,
        lease: &ucr_model::StoreForwardLease,
        now: i64,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        let backoff_ordinal = lease.job.attempts_used.max(1);
        let next = store_forward_next_attempt_at(now, &lease.job.policy, backoff_ordinal)?;
        self.store.reschedule_store_forward_job(lease, next, now)?;
        Ok(StoreForwardOutcome::RescheduledNoRoute)
    }

    fn finish_existing(
        &self,
        job: &StoreForwardJob,
        now: i64,
        outcome: StoreForwardOutcome,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        if job.next_attempt_at_unix_ms > now {
            return Ok(StoreForwardOutcome::NotDue);
        }
        match self.claim(job, now)? {
            Some(lease) => {
                self.store.complete_store_forward_job(&lease, now)?;
                Ok(outcome)
            }
            None => Ok(StoreForwardOutcome::Busy),
        }
    }

    fn expire_existing(
        &self,
        job: &StoreForwardJob,
        last: Option<&DeliveryAttempt>,
        now: i64,
    ) -> Result<StoreForwardOutcome, StoreForwardRuntimeError> {
        let Some(lease) = self.claim(job, now)? else {
            return Ok(StoreForwardOutcome::Busy);
        };
        if let Some(attempt) = last
            && !matches!(
                attempt.state,
                DeliveryState::Read | DeliveryState::Failed | DeliveryState::Expired
            )
        {
            self.store.transition_delivery(
                &attempt.scope,
                &attempt.delivery_id,
                attempt.state,
                DeliveryState::Expired,
                None,
            )?;
        }
        self.store.complete_store_forward_job(&lease, now)?;
        Ok(StoreForwardOutcome::Expired)
    }
}

#[derive(Debug)]
struct StoreForwardFailoverClock<'a>(&'a dyn StoreForwardClock);

impl TransportFailoverClock for StoreForwardFailoverClock<'_> {
    fn now_unix_ms(&self) -> i64 {
        self.0.now_unix_ms()
    }
}

fn normalize_pre_route_attempt<S>(
    store: &S,
    attempt: &mut DeliveryAttempt,
) -> Result<(), StoreForwardRuntimeError>
where
    S: DeliveryStore,
{
    if attempt.state == DeliveryState::Persisted {
        store.transition_delivery(
            &attempt.scope,
            &attempt.delivery_id,
            DeliveryState::Persisted,
            DeliveryState::Encrypted,
            None,
        )?;
        attempt.state = DeliveryState::Encrypted;
    }
    if attempt.state == DeliveryState::Encrypted {
        store.transition_delivery(
            &attempt.scope,
            &attempt.delivery_id,
            DeliveryState::Encrypted,
            DeliveryState::Queued,
            None,
        )?;
        attempt.state = DeliveryState::Queued;
    }
    if !matches!(
        attempt.state,
        DeliveryState::Queued | DeliveryState::RoutePlanned
    ) {
        return Err(StoreForwardRuntimeError::Store(DurableStoreError::Conflict));
    }
    Ok(())
}

fn validate_delivery_policy(
    message: &MessageEnvelope,
    job: &StoreForwardJob,
) -> Result<(), StoreForwardRuntimeError> {
    if message.delivery_state != DeliveryState::Persisted
        || message.delivery_policy == DeliveryPolicy::BestEffort
    {
        return Err(StoreForwardRuntimeError::UnsupportedDeliveryPolicy);
    }
    if message.delivery_policy == DeliveryPolicy::Expiring
        && job.policy.expires_at_unix_ms.is_none()
    {
        return Err(StoreForwardRuntimeError::UnsupportedDeliveryPolicy);
    }
    Ok(())
}

fn filter_direct_options(
    policy: DeliveryPolicy,
    options: Vec<TransportRouteOption<'_>>,
) -> Vec<TransportRouteOption<'_>> {
    options
        .into_iter()
        .filter(|option| {
            let capability = option.route.transport_capability.as_str();
            let is_local = capability == STORE_FORWARD_LOCAL_CAPABILITY;
            let is_direct = is_local || capability == STORE_FORWARD_INTERNET_CAPABILITY;
            match policy {
                DeliveryPolicy::LocalOnly | DeliveryPolicy::PrivateNetworkOnly => is_local,
                DeliveryPolicy::BestEffort => false,
                DeliveryPolicy::Durable
                | DeliveryPolicy::Urgent
                | DeliveryPolicy::Expiring
                | DeliveryPolicy::DirectOnly
                | DeliveryPolicy::NoRelay
                | DeliveryPolicy::NoExternalBridge => is_direct,
            }
        })
        .collect()
}

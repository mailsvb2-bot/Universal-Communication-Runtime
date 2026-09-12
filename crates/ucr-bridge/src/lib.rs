#![forbid(unsafe_code)]

use core::fmt;
use ucr_core::{
    AuthorizationEvaluator, BridgeActionStore, BridgeRegistrationStore, DurableRecordStatus,
    DurableStoreError, MessageStore,
};
use ucr_model::{
    AuthorizationRequest, BridgeAction, BridgeActionRecord, BridgeActionState, BridgeCapability,
    BridgeDataPermission, BridgeEventCursor, BridgeEventPage, BridgeProviderAcceptance,
    BridgeProviderManifest, BridgeRegistration, BridgeRegistrationState, DeliveryPolicy,
    IntegrationId, ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    BRIDGE_EVENTS_READ_PERMISSION, BRIDGE_EXECUTE_PERMISSION,
    BRIDGE_REGISTRATION_MANAGE_PERMISSION, BRIDGE_REGISTRATION_READ_PERMISSION,
    BridgeProtocolError, MAX_BRIDGE_EVENT_PAGE_ITEMS, bridge_action_fingerprint,
    bridge_manifest_allows_data, bridge_manifest_supports, canonical_bridge_manifest,
    validate_bridge_action, validate_bridge_event_cursor, validate_bridge_event_page,
    validate_bridge_provider_acceptance,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeProviderFailureKind {
    Unavailable,
    Backpressure,
    RateLimited,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeProviderFailure {
    NotAccepted(BridgeProviderFailureKind),
    AcceptanceUnknown(BridgeProviderFailureKind),
}

/// External-provider extension point. Provider-specific credentials and diagnostics remain behind
/// this boundary. The UCR host passes only the exact action/event context admitted by Core.
pub trait BridgeProvider: fmt::Debug + Send + Sync {
    fn manifest(&self) -> BridgeProviderManifest;

    /// Executes one already-authorized provider action.
    ///
    /// # Errors
    /// Providers must classify whether non-acceptance is proven. Unknown acceptance is never
    /// automatically retried by Core.
    fn execute(
        &self,
        action: &BridgeAction,
    ) -> Result<BridgeProviderAcceptance, BridgeProviderFailure>;

    /// Returns one bounded provider-event page. This does not itself create canonical UCR Messages.
    ///
    /// # Errors
    /// Provider/network/backpressure failures are explicit and never become canonical events.
    fn poll_events(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        cursor: Option<&BridgeEventCursor>,
        limit: usize,
    ) -> Result<BridgeEventPage, BridgeProviderFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeExecutionOutcome {
    pub acceptance: BridgeProviderAcceptance,
    pub replayed: bool,
}

#[derive(Debug)]
enum BridgeActionAdmission {
    Ready(BridgeActionRecord),
    Replayed(BridgeExecutionOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    Protocol(BridgeProtocolError),
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    RegistrationUnavailable,
    RegistrationInactive,
    ProviderIdentityMismatch,
    CapabilityUnavailable,
    DataPermissionDenied,
    ExternalBridgeForbidden,
    MessageUnavailable,
    MessageBindingMismatch,
    EventBindingMismatch,
    InvalidPageLimit,
    ActionInFlight,
    AcceptanceUnknown,
    Provider(BridgeProviderFailureKind),
}

impl From<BridgeProtocolError> for BridgeError {
    fn from(error: BridgeProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<DurableStoreError> for BridgeError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug)]
pub struct BridgeRuntime<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> BridgeRuntime<'a, A, S> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }
}

impl<A, S> BridgeRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: BridgeRegistrationStore + BridgeActionStore + MessageStore,
{
    /// Installs the manifest reported by the actual provider under one canonical `IntegrationId`.
    ///
    /// # Errors
    /// Returns authorization, protocol validation, conflict, permission, or storage failures.
    pub fn register(
        &self,
        actor: &ScopedPrincipal,
        integration_id: &IntegrationId,
        provider: &dyn BridgeProvider,
    ) -> Result<DurableRecordStatus, BridgeError> {
        authorize(
            self.authorization,
            actor,
            BRIDGE_REGISTRATION_MANAGE_PERMISSION,
        )?;
        let manifest = canonical_bridge_manifest(&provider.manifest())?;
        let registration = BridgeRegistration {
            scope: actor.scope.clone(),
            integration_id: integration_id.clone(),
            manifest,
            state: BridgeRegistrationState::Active,
            generation: 1,
        };
        self.store
            .install_bridge_registration(&registration)
            .map_err(BridgeError::Store)
    }

    /// Reads one exact bridge registration after explicit authorization.
    ///
    /// # Errors
    /// Returns authorization/storage failures or `RegistrationUnavailable` when no row exists.
    pub fn registration(
        &self,
        actor: &ScopedPrincipal,
        integration_id: &IntegrationId,
    ) -> Result<BridgeRegistration, BridgeError> {
        authorize(
            self.authorization,
            actor,
            BRIDGE_REGISTRATION_READ_PERMISSION,
        )?;
        self.store
            .bridge_registration(&actor.scope, integration_id)?
            .ok_or(BridgeError::RegistrationUnavailable)
    }

    /// Advances the durable bridge registration lifecycle using optimistic generation.
    ///
    /// # Errors
    /// Returns authorization, validation, conflict, permission, or storage failures.
    pub fn transition_registration(
        &self,
        actor: &ScopedPrincipal,
        integration_id: &IntegrationId,
        expected_generation: u64,
        next_state: BridgeRegistrationState,
    ) -> Result<DurableRecordStatus, BridgeError> {
        authorize(
            self.authorization,
            actor,
            BRIDGE_REGISTRATION_MANAGE_PERMISSION,
        )?;
        self.store
            .transition_bridge_registration(
                &actor.scope,
                integration_id,
                expected_generation,
                next_state,
            )
            .map_err(BridgeError::Store)
    }

    /// Executes/deduplicates one external provider side effect without promoting provider
    /// acceptance to canonical Delivery/Read evidence.
    ///
    /// # Errors
    /// Returns authorization/protocol/store failures, policy or message-binding denial, provider
    /// capability/data-permission failures, provider failure, or conservative acceptance ambiguity.
    pub fn execute(
        &self,
        actor: &ScopedPrincipal,
        action: &BridgeAction,
        provider: &dyn BridgeProvider,
    ) -> Result<BridgeExecutionOutcome, BridgeError> {
        authorize(self.authorization, actor, BRIDGE_EXECUTE_PERMISSION)?;
        validate_bridge_action(action)?;
        if action.scope != actor.scope {
            return Err(BridgeError::MessageBindingMismatch);
        }
        let fingerprint = bridge_action_fingerprint(action)?;
        let existing = self.load_existing_action(action, fingerprint)?;
        if let Some(BridgeActionAdmission::Replayed(outcome)) = existing {
            return Ok(outcome);
        }

        let (registration, provider_manifest) =
            self.admit_provider(&action.scope, &action.integration_id, provider)?;
        require_capability(
            &registration.manifest,
            &provider_manifest,
            action.capability,
        )?;
        self.validate_action_data(&registration, &provider_manifest, action)?;

        let record = match existing {
            Some(BridgeActionAdmission::Ready(record)) => record,
            Some(BridgeActionAdmission::Replayed(_)) => unreachable!("replay returned above"),
            None => self.prepare_action(action, fingerprint)?,
        };
        let in_flight_generation = self.mark_action_in_flight(action, &record)?;
        self.complete_provider_execution(
            action,
            &registration.manifest,
            &provider_manifest,
            provider,
            in_flight_generation,
        )
    }

    fn load_existing_action(
        &self,
        action: &BridgeAction,
        fingerprint: [u8; 32],
    ) -> Result<Option<BridgeActionAdmission>, BridgeError> {
        if let Some(existing) = self.store.bridge_action(&action.scope, &action.action_id)? {
            if existing.fingerprint != fingerprint
                || existing.integration_id != action.integration_id
                || existing.capability != action.capability
            {
                return Err(BridgeError::Store(DurableStoreError::Conflict));
            }
            return match existing.state {
                BridgeActionState::Accepted => Ok(Some(BridgeActionAdmission::Replayed(
                    BridgeExecutionOutcome {
                        acceptance: existing
                            .acceptance
                            .ok_or(BridgeError::Store(DurableStoreError::Corrupt))?,
                        replayed: true,
                    },
                ))),
                BridgeActionState::AcceptanceUnknown => Err(BridgeError::AcceptanceUnknown),
                BridgeActionState::InFlight => Err(BridgeError::ActionInFlight),
                BridgeActionState::Prepared | BridgeActionState::FailedNotAccepted => {
                    Ok(Some(BridgeActionAdmission::Ready(existing)))
                }
            };
        }
        Ok(None)
    }

    fn prepare_action(
        &self,
        action: &BridgeAction,
        fingerprint: [u8; 32],
    ) -> Result<BridgeActionRecord, BridgeError> {
        let prepared = BridgeActionRecord {
            scope: action.scope.clone(),
            action_id: action.action_id.clone(),
            integration_id: action.integration_id.clone(),
            capability: action.capability,
            fingerprint,
            state: BridgeActionState::Prepared,
            acceptance: None,
            generation: 1,
        };
        self.store.prepare_bridge_action(&prepared)?;
        Ok(prepared)
    }

    fn mark_action_in_flight(
        &self,
        action: &BridgeAction,
        record: &BridgeActionRecord,
    ) -> Result<u64, BridgeError> {
        let status = self.store.transition_bridge_action(
            &action.scope,
            &action.action_id,
            record.generation,
            record.state,
            BridgeActionState::InFlight,
            None,
        )?;
        if status == DurableRecordStatus::Duplicate {
            return Err(BridgeError::ActionInFlight);
        }
        record
            .generation
            .checked_add(1)
            .ok_or(BridgeError::Store(DurableStoreError::InvalidRecord))
    }

    fn complete_provider_execution(
        &self,
        action: &BridgeAction,
        registered_manifest: &BridgeProviderManifest,
        provider_manifest: &BridgeProviderManifest,
        provider: &dyn BridgeProvider,
        in_flight_generation: u64,
    ) -> Result<BridgeExecutionOutcome, BridgeError> {
        match provider.execute(action) {
            Ok(acceptance) => {
                if validate_bridge_provider_acceptance(
                    action,
                    registered_manifest,
                    provider_manifest,
                    &acceptance,
                )
                .is_err()
                {
                    let _ = self.store.transition_bridge_action(
                        &action.scope,
                        &action.action_id,
                        in_flight_generation,
                        BridgeActionState::InFlight,
                        BridgeActionState::AcceptanceUnknown,
                        None,
                    );
                    return Err(BridgeError::AcceptanceUnknown);
                }
                self.store.transition_bridge_action(
                    &action.scope,
                    &action.action_id,
                    in_flight_generation,
                    BridgeActionState::InFlight,
                    BridgeActionState::Accepted,
                    Some(&acceptance),
                )?;
                Ok(BridgeExecutionOutcome {
                    acceptance,
                    replayed: false,
                })
            }
            Err(BridgeProviderFailure::NotAccepted(kind)) => {
                self.store.transition_bridge_action(
                    &action.scope,
                    &action.action_id,
                    in_flight_generation,
                    BridgeActionState::InFlight,
                    BridgeActionState::FailedNotAccepted,
                    None,
                )?;
                Err(BridgeError::Provider(kind))
            }
            Err(BridgeProviderFailure::AcceptanceUnknown(_kind)) => {
                self.store.transition_bridge_action(
                    &action.scope,
                    &action.action_id,
                    in_flight_generation,
                    BridgeActionState::InFlight,
                    BridgeActionState::AcceptanceUnknown,
                    None,
                )?;
                Err(BridgeError::AcceptanceUnknown)
            }
        }
    }

    /// Converts a crash-left `InFlight` ledger row to terminal ambiguity without calling provider.
    ///
    /// # Errors
    /// Returns authorization/storage failures or conflict unless the exact row is currently
    /// `InFlight`.
    pub fn recover_in_flight_as_unknown(
        &self,
        actor: &ScopedPrincipal,
        action_id: &ucr_model::BridgeActionId,
    ) -> Result<DurableRecordStatus, BridgeError> {
        authorize(self.authorization, actor, BRIDGE_EXECUTE_PERMISSION)?;
        let record = self
            .store
            .bridge_action(&actor.scope, action_id)?
            .ok_or(BridgeError::Store(DurableStoreError::Conflict))?;
        if record.state != BridgeActionState::InFlight {
            return Err(BridgeError::Store(DurableStoreError::Conflict));
        }
        self.store
            .transition_bridge_action(
                &actor.scope,
                action_id,
                record.generation,
                BridgeActionState::InFlight,
                BridgeActionState::AcceptanceUnknown,
                None,
            )
            .map_err(BridgeError::Store)
    }

    /// Polls one bounded provider event page without promoting events into canonical Messages.
    ///
    /// # Errors
    /// Returns authorization, registration, capability/data-permission, provider, protocol, page
    /// binding, or cursor/limit failures.
    pub fn poll_events(
        &self,
        actor: &ScopedPrincipal,
        integration_id: &IntegrationId,
        provider: &dyn BridgeProvider,
        cursor: Option<&BridgeEventCursor>,
        limit: usize,
    ) -> Result<BridgeEventPage, BridgeError> {
        authorize(self.authorization, actor, BRIDGE_EVENTS_READ_PERMISSION)?;
        if limit == 0 || limit > MAX_BRIDGE_EVENT_PAGE_ITEMS {
            return Err(BridgeError::InvalidPageLimit);
        }
        if let Some(cursor) = cursor {
            validate_bridge_event_cursor(cursor)?;
        }
        let (registration, provider_manifest) =
            self.admit_provider(&actor.scope, integration_id, provider)?;
        require_data_permission(
            &registration.manifest,
            &provider_manifest,
            BridgeDataPermission::InboundEvents,
        )?;
        let page = provider
            .poll_events(&actor.scope, integration_id, cursor, limit)
            .map_err(map_poll_failure)?;
        validate_bridge_event_page(&page)?;
        if page.events.len() > limit
            || page.events.iter().any(|event| {
                event.scope != actor.scope
                    || event.integration_id != *integration_id
                    || !bridge_manifest_supports(&registration.manifest, event.capability)
                    || !bridge_manifest_supports(&provider_manifest, event.capability)
            })
        {
            return Err(BridgeError::EventBindingMismatch);
        }
        Ok(page)
    }

    fn admit_provider(
        &self,
        scope: &TenantScope,
        integration_id: &IntegrationId,
        provider: &dyn BridgeProvider,
    ) -> Result<(BridgeRegistration, BridgeProviderManifest), BridgeError> {
        let registration = self
            .store
            .bridge_registration(scope, integration_id)?
            .ok_or(BridgeError::RegistrationUnavailable)?;
        if registration.state != BridgeRegistrationState::Active {
            return Err(BridgeError::RegistrationInactive);
        }
        let current = canonical_bridge_manifest(&provider.manifest())?;
        if current.provider_id != registration.manifest.provider_id {
            return Err(BridgeError::ProviderIdentityMismatch);
        }
        Ok((registration, current))
    }

    fn validate_action_data(
        &self,
        registration: &BridgeRegistration,
        current: &BridgeProviderManifest,
        action: &BridgeAction,
    ) -> Result<(), BridgeError> {
        if !action.external_target.is_empty() {
            require_data_permission(
                &registration.manifest,
                current,
                BridgeDataPermission::ExternalIdentityReferences,
            )?;
        }
        if !action.provider_payload.is_empty() {
            require_data_permission(
                &registration.manifest,
                current,
                BridgeDataPermission::MessageContent,
            )?;
        }
        if !action.attachment_ids.is_empty() {
            require_data_permission(
                &registration.manifest,
                current,
                BridgeDataPermission::AttachmentReferences,
            )?;
        }
        if let Some(message_id) = &action.canonical_message_id {
            let message = self
                .store
                .message(&action.scope, message_id)?
                .ok_or(BridgeError::MessageUnavailable)?;
            if matches!(
                message.delivery_policy,
                DeliveryPolicy::LocalOnly
                    | DeliveryPolicy::PrivateNetworkOnly
                    | DeliveryPolicy::NoExternalBridge
            ) {
                return Err(BridgeError::ExternalBridgeForbidden);
            }
            if action.provider_payload != message.content
                || action.attachment_ids != message.attachment_ids
            {
                return Err(BridgeError::MessageBindingMismatch);
            }
        } else if !action.provider_payload.is_empty() || !action.attachment_ids.is_empty() {
            return Err(BridgeError::MessageBindingMismatch);
        }
        Ok(())
    }
}

fn require_capability(
    registered: &BridgeProviderManifest,
    current: &BridgeProviderManifest,
    capability: BridgeCapability,
) -> Result<(), BridgeError> {
    if bridge_manifest_supports(registered, capability)
        && bridge_manifest_supports(current, capability)
    {
        Ok(())
    } else {
        Err(BridgeError::CapabilityUnavailable)
    }
}

fn require_data_permission(
    registered: &BridgeProviderManifest,
    current: &BridgeProviderManifest,
    permission: BridgeDataPermission,
) -> Result<(), BridgeError> {
    if bridge_manifest_allows_data(registered, permission)
        && bridge_manifest_allows_data(current, permission)
    {
        Ok(())
    } else {
        Err(BridgeError::DataPermissionDenied)
    }
}

fn authorize(
    authorization: &impl AuthorizationEvaluator,
    actor: &ScopedPrincipal,
    permission: &str,
) -> Result<(), BridgeError> {
    authorization
        .authorize(&AuthorizationRequest {
            subject: actor.clone(),
            permission: permission.to_owned(),
            resource_scope: actor.scope.clone(),
        })
        .map_err(BridgeError::Authorization)
}

const fn map_poll_failure(failure: BridgeProviderFailure) -> BridgeError {
    match failure {
        BridgeProviderFailure::NotAccepted(kind)
        | BridgeProviderFailure::AcceptanceUnknown(kind) => BridgeError::Provider(kind),
    }
}

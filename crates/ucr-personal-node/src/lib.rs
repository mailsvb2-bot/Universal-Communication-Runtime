#![forbid(unsafe_code)]

use ucr_core::{
    AuthorizationEvaluator, BridgeRegistrationStore, DurableRecordStatus, DurableStoreError,
    PersonalNodeStore, StoreForwardStore, SyncStore,
};
use ucr_model::{
    AuthorizationRequest, BridgeRegistration, BridgeRegistrationState, DeliveryPolicy, EndpointId,
    IntegrationId, PersonalNodeObject, PersonalNodeObjectId, PersonalNodeObjectKind,
    PersonalNodeProfile, PersonalNodeService, PersonalNodeState, ScopedPrincipal, SessionId,
    StoreForwardId, StoreForwardJob, SyncLinkKind, SyncSession, SyncState, TenantScope,
};
use ucr_protocol::{
    BRIDGE_REGISTRATION_READ_PERMISSION, PERSONAL_NODE_MANAGE_PERMISSION,
    PERSONAL_NODE_OBJECT_READ_PERMISSION, PERSONAL_NODE_OBJECT_WRITE_PERMISSION,
    PERSONAL_NODE_READ_PERMISSION, PERSONAL_NODE_USE_PERMISSION, SYNC_READ_PERMISSION,
};

pub const PERSONAL_NODE_RUNTIME_CAPABILITY: &str = "ucr.personal_node";

#[derive(Debug)]
pub enum PersonalNodeError {
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    MissingProfile,
    NodeDisabled,
    ServiceDisabled,
    MissingSyncSession,
    SyncInactive,
    SyncBindingMismatch,
    MissingStoreForwardJob,
    RelayPolicyDenied,
    MissingBridgeRegistration,
    BridgeInactive,
}

impl From<DurableStoreError> for PersonalNodeError {
    fn from(value: DurableStoreError) -> Self {
        Self::Store(value)
    }
}

pub trait PersonalNodeRuntimeStore:
    PersonalNodeStore + SyncStore + StoreForwardStore + BridgeRegistrationStore
{
}
impl<T> PersonalNodeRuntimeStore for T where
    T: PersonalNodeStore + SyncStore + StoreForwardStore + BridgeRegistrationStore
{
}

#[derive(Debug)]
pub struct PersonalNodeRuntime<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> PersonalNodeRuntime<'a, A, S> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }
}
impl<A, S> PersonalNodeRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: PersonalNodeRuntimeStore,
{
    /// Installs one owner-controlled Personal Node profile.
    ///
    /// # Errors
    /// Returns authorization, validation, conflict, or durable-store failures.
    pub fn install_profile(
        &self,
        actor: &ScopedPrincipal,
        profile: &PersonalNodeProfile,
    ) -> Result<DurableRecordStatus, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            &profile.scope,
            PERSONAL_NODE_MANAGE_PERMISSION,
        )?;
        self.store
            .install_personal_node_profile(profile)
            .map_err(Into::into)
    }

    /// Reads one exact Personal Node profile.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn profile(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
    ) -> Result<Option<PersonalNodeProfile>, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_READ_PERMISSION,
        )?;
        self.store
            .personal_node_profile(scope, endpoint_id)
            .map_err(Into::into)
    }

    /// Applies one explicit Personal Node lifecycle transition.
    ///
    /// # Errors
    /// Returns authorization, invalid-transition, conflict, or durable-store failures.
    pub fn transition_profile(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        expected_generation: u64,
        next_state: PersonalNodeState,
    ) -> Result<DurableRecordStatus, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_MANAGE_PERMISSION,
        )?;
        self.store
            .transition_personal_node_profile(scope, endpoint_id, expected_generation, next_state)
            .map_err(Into::into)
    }

    /// Persists one encrypted mailbox/cache object after service admission.
    ///
    /// # Errors
    /// Returns authorization, disabled-service, validation, capacity, conflict, or store failures.
    pub fn put_object(
        &self,
        actor: &ScopedPrincipal,
        object: &PersonalNodeObject,
    ) -> Result<DurableRecordStatus, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            &object.scope,
            PERSONAL_NODE_OBJECT_WRITE_PERMISSION,
        )?;
        let required = match object.kind {
            PersonalNodeObjectKind::Mailbox => PersonalNodeService::EncryptedMailbox,
            PersonalNodeObjectKind::Cache => PersonalNodeService::Cache,
        };
        self.require_active_service(&object.scope, &object.endpoint_id, required)?;
        self.store
            .persist_personal_node_object(object)
            .map_err(Into::into)
    }

    /// Reads one exact encrypted Personal Node object.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures.
    pub fn object(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<Option<PersonalNodeObject>, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_OBJECT_READ_PERMISSION,
        )?;
        self.store
            .personal_node_object(scope, endpoint_id, object_id)
            .map_err(Into::into)
    }

    /// Lists a bounded set of encrypted Personal Node objects.
    ///
    /// # Errors
    /// Returns authorization, invalid-bound, or durable-store failures.
    pub fn objects(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        kind: Option<PersonalNodeObjectKind>,
        max_items: usize,
    ) -> Result<Vec<PersonalNodeObject>, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_OBJECT_READ_PERMISSION,
        )?;
        self.store
            .personal_node_objects(scope, endpoint_id, kind, max_items)
            .map_err(Into::into)
    }

    /// Explicitly removes one encrypted Personal Node object.
    ///
    /// # Errors
    /// Returns authorization, conflict, or durable-store failures.
    pub fn remove_object(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        object_id: &PersonalNodeObjectId,
    ) -> Result<DurableRecordStatus, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_OBJECT_WRITE_PERMISSION,
        )?;
        self.store
            .remove_personal_node_object(scope, endpoint_id, object_id)
            .map_err(Into::into)
    }
    /// Admits one already-active canonical Device→PersonalNode Sync session.
    ///
    /// # Errors
    /// Returns authorization, node/service state, Sync binding/state, or store failures.
    pub fn admit_sync(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        node_endpoint_id: &EndpointId,
        session_id: &SessionId,
    ) -> Result<SyncSession, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_USE_PERMISSION,
        )?;
        authorize(self.authorization, actor, scope, SYNC_READ_PERMISSION)?;
        self.require_active_service(scope, node_endpoint_id, PersonalNodeService::Sync)?;
        let session = self
            .store
            .sync_session(scope, session_id)?
            .ok_or(PersonalNodeError::MissingSyncSession)?;
        if session.state != SyncState::Active || session.link_kind != SyncLinkKind::DeviceNode {
            return Err(PersonalNodeError::SyncInactive);
        }
        if session.target_endpoint_id != *node_endpoint_id {
            return Err(PersonalNodeError::SyncBindingMismatch);
        }
        Ok(session)
    }

    /// Admits an existing sender-side Store-and-Forward job for Personal Node relay handling.
    /// No transport invocation or Delivery transition occurs here.
    ///
    /// # Errors
    /// Returns authorization, node/service state, missing-owner, policy, or store failures.
    pub fn admit_relay(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        node_endpoint_id: &EndpointId,
        store_forward_id: &StoreForwardId,
    ) -> Result<StoreForwardJob, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_USE_PERMISSION,
        )?;
        self.require_active_service(scope, node_endpoint_id, PersonalNodeService::Relay)?;
        let job = self
            .store
            .store_forward_job(scope, store_forward_id)?
            .ok_or(PersonalNodeError::MissingStoreForwardJob)?;
        let message = self
            .store
            .message(scope, &job.message_id)?
            .ok_or(PersonalNodeError::MissingStoreForwardJob)?;
        if !relay_policy_allowed(message.delivery_policy) {
            return Err(PersonalNodeError::RelayPolicyDenied);
        }
        Ok(job)
    }

    /// Admits an existing active Bridge registration for this Personal Node.
    /// Provider execution remains owned by the canonical Bridge runtime.
    ///
    /// # Errors
    /// Returns authorization, node/service state, registration lifecycle, or store failures.
    pub fn admit_bridge(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        node_endpoint_id: &EndpointId,
        integration_id: &IntegrationId,
    ) -> Result<BridgeRegistration, PersonalNodeError> {
        authorize(
            self.authorization,
            actor,
            scope,
            PERSONAL_NODE_USE_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            scope,
            BRIDGE_REGISTRATION_READ_PERMISSION,
        )?;
        self.require_active_service(scope, node_endpoint_id, PersonalNodeService::Bridge)?;
        let registration = self
            .store
            .bridge_registration(scope, integration_id)?
            .ok_or(PersonalNodeError::MissingBridgeRegistration)?;
        if registration.state != BridgeRegistrationState::Active {
            return Err(PersonalNodeError::BridgeInactive);
        }
        Ok(registration)
    }
    fn require_active_service(
        &self,
        scope: &TenantScope,
        endpoint_id: &EndpointId,
        service: PersonalNodeService,
    ) -> Result<PersonalNodeProfile, PersonalNodeError> {
        let profile = self
            .store
            .personal_node_profile(scope, endpoint_id)?
            .ok_or(PersonalNodeError::MissingProfile)?;
        if profile.state != PersonalNodeState::Active {
            return Err(PersonalNodeError::NodeDisabled);
        }
        if !profile.services.contains(&service) {
            return Err(PersonalNodeError::ServiceDisabled);
        }
        Ok(profile)
    }
}

fn authorize<A: AuthorizationEvaluator>(
    authorization: &A,
    actor: &ScopedPrincipal,
    scope: &TenantScope,
    permission: &str,
) -> Result<(), PersonalNodeError> {
    authorization
        .authorize(&AuthorizationRequest {
            subject: actor.clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        })
        .map_err(PersonalNodeError::Authorization)
}
fn relay_policy_allowed(policy: DeliveryPolicy) -> bool {
    matches!(
        policy,
        DeliveryPolicy::BestEffort
            | DeliveryPolicy::Durable
            | DeliveryPolicy::Urgent
            | DeliveryPolicy::Expiring
            | DeliveryPolicy::NoExternalBridge
    )
}

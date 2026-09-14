#![forbid(unsafe_code)]

use core::fmt;

use ucr_core::{
    AuthorizationEvaluator, BridgeRegistrationStore, DurableRecordStatus, DurableStoreError,
    GroupStore,
};
use ucr_model::{
    AuthorizationRequest, BridgeCapability, BridgeDataPermission, BridgeInboundEvent,
    BridgeRegistrationState, ConversationId, ConversationKind, ConversationRef, EventId,
    GroupBridgeMapping, GroupChange, GroupChangeKind, GroupId, GroupMemberState, IntegrationId,
    ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    BRIDGE_EVENTS_READ_PERMISSION, BRIDGE_REGISTRATION_READ_PERMISSION, GROUP_MANAGE_PERMISSION,
    GROUP_READ_PERMISSION, bridge_manifest_allows_data, bridge_manifest_supports,
    validate_bridge_inbound_event,
};

pub const OVERLAY_CONVERSATIONS_CAPABILITY: &str = "ucr.overlay.conversations";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayEndpointState {
    Ready,
    RegistrationUnavailable,
    RegistrationInactive,
    CapabilityUnavailable,
    DataPermissionDenied,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OverlayEndpoint {
    pub integration_id: IntegrationId,
    pub external_group_id: Vec<u8>,
    pub provider_id: Option<String>,
    pub state: OverlayEndpointState,
}

impl fmt::Debug for OverlayEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OverlayEndpoint")
            .field("integration_id", &self.integration_id)
            .field("external_group_id", &"<opaque>")
            .field("external_group_id_len", &self.external_group_id.len())
            .field("provider_id", &self.provider_id)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayConversationProjection {
    pub group_id: GroupId,
    pub conversation: ConversationRef,
    pub endpoints: Vec<OverlayEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayInboundResolution {
    pub group_id: GroupId,
    pub conversation: ConversationRef,
    pub integration_id: IntegrationId,
}

#[derive(Debug)]
pub enum OverlayError {
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    ScopeMismatch,
    InvalidEvent,
    RegistrationUnavailable,
    RegistrationInactive,
    CapabilityUnavailable,
    DataPermissionDenied,
}

impl From<DurableStoreError> for OverlayError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

pub trait OverlayStore: GroupStore + BridgeRegistrationStore {}
impl<T> OverlayStore for T where T: GroupStore + BridgeRegistrationStore {}

#[derive(Debug)]
pub struct OverlayRuntime<'a, A, S> {
    authorization: &'a A,
    store: &'a S,
}

impl<'a, A, S> OverlayRuntime<'a, A, S> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S) -> Self {
        Self {
            authorization,
            store,
        }
    }
}

impl<A, S> OverlayRuntime<'_, A, S>
where
    A: AuthorizationEvaluator,
    S: OverlayStore,
{
    /// Adds one provider Group endpoint through the existing canonical Group mutation owner.
    ///
    /// The referenced Bridge integration must already exist and be Active. The durable Group store
    /// repeats that invariant so callers cannot bypass it by skipping this facade.
    ///
    /// # Errors
    /// Returns explicit authorization, bridge-registration, conflict, validation, or storage failure.
    pub fn bind_endpoint(
        &self,
        actor: &ScopedPrincipal,
        event_id: EventId,
        group_id: GroupId,
        expected_revision: u64,
        mapping: GroupBridgeMapping,
    ) -> Result<DurableRecordStatus, OverlayError> {
        authorize(
            self.authorization,
            actor,
            &actor.scope,
            GROUP_MANAGE_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            &actor.scope,
            BRIDGE_REGISTRATION_READ_PERMISSION,
        )?;
        let registration = self
            .store
            .bridge_registration(&actor.scope, &mapping.integration_id)?
            .ok_or(OverlayError::RegistrationUnavailable)?;
        if registration.state != BridgeRegistrationState::Active {
            return Err(OverlayError::RegistrationInactive);
        }
        let change = GroupChange {
            event_id,
            scope: actor.scope.clone(),
            group_id,
            expected_revision,
            kind: GroupChangeKind::AddBridgeMapping { mapping },
            next_crypto_state: None,
        };
        self.store
            .apply_group_change(actor, &change)
            .map_err(OverlayError::Store)
    }

    /// Removes one exact endpoint mapping even when its Bridge registration is unavailable/revoked.
    ///
    /// # Errors
    /// Returns explicit authorization, conflict, validation, or storage failure.
    pub fn unbind_endpoint(
        &self,
        actor: &ScopedPrincipal,
        event_id: EventId,
        group_id: GroupId,
        expected_revision: u64,
        integration_id: IntegrationId,
        external_group_id: Vec<u8>,
    ) -> Result<DurableRecordStatus, OverlayError> {
        authorize(
            self.authorization,
            actor,
            &actor.scope,
            GROUP_MANAGE_PERMISSION,
        )?;
        let change = GroupChange {
            event_id,
            scope: actor.scope.clone(),
            group_id,
            expected_revision,
            kind: GroupChangeKind::RemoveBridgeMapping {
                integration_id,
                external_group_id,
            },
            next_crypto_state: None,
        };
        self.store
            .apply_group_change(actor, &change)
            .map_err(OverlayError::Store)
    }

    /// Projects one canonical Group Conversation to its configured text endpoints.
    ///
    /// Every configured mapping is returned. Missing/inactive/under-capable registrations are
    /// represented explicitly rather than silently dropped, so callers can surface degradation.
    /// Private Groups remain non-disclosing to inactive/non-members.
    ///
    /// # Errors
    /// Returns authorization or durable-store failures. Absence/non-membership returns `Ok(None)`.
    pub fn text_projection(
        &self,
        actor: &ScopedPrincipal,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<OverlayConversationProjection>, OverlayError> {
        require_scope(actor, scope)?;
        authorize(self.authorization, actor, scope, GROUP_READ_PERMISSION)?;
        authorize(
            self.authorization,
            actor,
            scope,
            BRIDGE_REGISTRATION_READ_PERMISSION,
        )?;
        let Some(group) = self.store.group_for_conversation(scope, conversation_id)? else {
            return Ok(None);
        };
        if !group_visible_to(self.store, actor, &group)? {
            return Ok(None);
        }
        let mut endpoints = Vec::with_capacity(group.bridge_mappings.len());
        for mapping in &group.bridge_mappings {
            let registration = self
                .store
                .bridge_registration(scope, &mapping.integration_id)?;
            let (provider_id, state) = match registration {
                None => (None, OverlayEndpointState::RegistrationUnavailable),
                Some(registration) if registration.state != BridgeRegistrationState::Active => (
                    Some(registration.manifest.provider_id),
                    OverlayEndpointState::RegistrationInactive,
                ),
                Some(registration)
                    if !bridge_manifest_supports(
                        &registration.manifest,
                        BridgeCapability::Text,
                    ) =>
                {
                    (
                        Some(registration.manifest.provider_id),
                        OverlayEndpointState::CapabilityUnavailable,
                    )
                }
                Some(registration)
                    if !bridge_manifest_allows_data(
                        &registration.manifest,
                        BridgeDataPermission::ExternalIdentityReferences,
                    ) || !bridge_manifest_allows_data(
                        &registration.manifest,
                        BridgeDataPermission::MessageContent,
                    ) =>
                {
                    (
                        Some(registration.manifest.provider_id),
                        OverlayEndpointState::DataPermissionDenied,
                    )
                }
                Some(registration) => (
                    Some(registration.manifest.provider_id),
                    OverlayEndpointState::Ready,
                ),
            };
            endpoints.push(OverlayEndpoint {
                integration_id: mapping.integration_id.clone(),
                external_group_id: mapping.external_group_id.clone(),
                provider_id,
                state,
            });
        }
        Ok(Some(OverlayConversationProjection {
            group_id: group.group_id,
            conversation: group.conversation,
            endpoints,
        }))
    }

    /// Resolves one already-received Bridge text event to the single canonical Overlay Group.
    ///
    /// This never promotes provider actor IDs into canonical Identity and never creates Messages.
    /// The caller must continue through the canonical Identity/Message owners after resolution.
    ///
    /// # Errors
    /// Returns authorization, registration, capability/data-permission, event-validation, or
    /// durable-store failure. Unknown endpoints and invisible private Groups return `Ok(None)`.
    pub fn resolve_inbound_text(
        &self,
        actor: &ScopedPrincipal,
        event: &BridgeInboundEvent,
    ) -> Result<Option<OverlayInboundResolution>, OverlayError> {
        require_scope(actor, &event.scope)?;
        authorize(
            self.authorization,
            actor,
            &event.scope,
            BRIDGE_EVENTS_READ_PERMISSION,
        )?;
        authorize(
            self.authorization,
            actor,
            &event.scope,
            GROUP_READ_PERMISSION,
        )?;
        validate_bridge_inbound_event(event).map_err(|_| OverlayError::InvalidEvent)?;
        if event.capability != BridgeCapability::Text {
            return Err(OverlayError::CapabilityUnavailable);
        }
        let registration = self
            .store
            .bridge_registration(&event.scope, &event.integration_id)?
            .ok_or(OverlayError::RegistrationUnavailable)?;
        if registration.state != BridgeRegistrationState::Active {
            return Err(OverlayError::RegistrationInactive);
        }
        if !bridge_manifest_supports(&registration.manifest, BridgeCapability::Text) {
            return Err(OverlayError::CapabilityUnavailable);
        }
        if !bridge_manifest_allows_data(&registration.manifest, BridgeDataPermission::InboundEvents)
            || !bridge_manifest_allows_data(
                &registration.manifest,
                BridgeDataPermission::ExternalIdentityReferences,
            )
            || !bridge_manifest_allows_data(
                &registration.manifest,
                BridgeDataPermission::MessageContent,
            )
        {
            return Err(OverlayError::DataPermissionDenied);
        }
        let Some(group) = self.store.group_for_bridge_mapping(
            &event.scope,
            &event.integration_id,
            &event.external_conversation_id,
        )?
        else {
            return Ok(None);
        };
        if !group_visible_to(self.store, actor, &group)? {
            return Ok(None);
        }
        Ok(Some(OverlayInboundResolution {
            group_id: group.group_id,
            conversation: group.conversation,
            integration_id: event.integration_id.clone(),
        }))
    }
}

fn group_visible_to<S: GroupStore>(
    store: &S,
    actor: &ScopedPrincipal,
    group: &ucr_model::GroupRecord,
) -> Result<bool, OverlayError> {
    if group.conversation.kind != ConversationKind::PrivateGroup {
        return Ok(true);
    }
    Ok(store
        .group_membership(&group.scope, &group.group_id, &actor.principal)?
        .is_some_and(|membership| membership.state == GroupMemberState::Active))
}

fn require_scope(actor: &ScopedPrincipal, scope: &TenantScope) -> Result<(), OverlayError> {
    if actor.scope == *scope {
        Ok(())
    } else {
        Err(OverlayError::ScopeMismatch)
    }
}

fn authorize(
    evaluator: &impl AuthorizationEvaluator,
    actor: &ScopedPrincipal,
    scope: &TenantScope,
    permission: &str,
) -> Result<(), OverlayError> {
    require_scope(actor, scope)?;
    evaluator
        .authorize(&AuthorizationRequest {
            subject: actor.clone(),
            permission: permission.to_owned(),
            resource_scope: scope.clone(),
        })
        .map_err(OverlayError::Authorization)
}

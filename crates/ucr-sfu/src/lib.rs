#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeMap;

use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, DurableStoreError, GroupStore,
    PrincipalIdentityBindingStore,
};
use ucr_crypto::TrustedSigningKeyResolver;
use ucr_media_e2ee::{
    GroupMediaE2eeCapabilityProvider, GroupMediaE2eeError, validate_group_media_source_frame,
};
use ucr_model::{
    AuthorizationRequest, CallParticipantState, CapabilityDescriptor, CapabilityMaturity, DeviceId,
    GroupMemberState, MediaKind, ScopedPrincipal, SfuForwardEnvelope, SfuForwardTarget,
    VideoSourceKind,
};
use ucr_protocol::{
    AUDIO_RECEIVE_PERMISSION, AUDIO_SEND_PERMISSION, CanonicalError, GROUP_MEDIA_E2EE_CAPABILITY,
    MAX_CALL_PARTICIPANTS, SCREEN_SHARE_SEND_PERMISSION, SFU_MEDIA_CAPABILITY, SfuProtocolError,
    VIDEO_RECEIVE_PERMISSION, VIDEO_SEND_PERMISSION, canonical_capabilities,
    canonical_sfu_forward_envelope, phase29_sfu_capabilities,
};

/// Ephemeral health state for one SFU worker in a horizontal deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuNodeState {
    Healthy,
    Draining,
    Unavailable,
}

/// Ephemeral operator-supplied description of one SFU worker.
///
/// This is infrastructure routing state only. It is not a durable Conference roster, membership
/// record, media archive, or authorization source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuNodeDescriptor {
    pub node_id: ucr_model::OpaqueId,
    pub region: String,
    pub state: SfuNodeState,
    pub active_sessions: u32,
    pub max_sessions: u32,
    pub lease_expires_at_unix_ms: i64,
}

impl SfuNodeDescriptor {
    fn is_live_at(&self, now_unix_ms: i64) -> bool {
        self.lease_expires_at_unix_ms > now_unix_ms && self.state != SfuNodeState::Unavailable
    }

    fn accepts_new_session_at(&self, now_unix_ms: i64) -> bool {
        self.is_live_at(now_unix_ms)
            && self.state == SfuNodeState::Healthy
            && self.max_sessions > 0
            && self.active_sessions < self.max_sessions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuPlacementPolicy {
    pub preferred_region: Option<String>,
    pub allow_cross_region_failover: bool,
}

impl Default for SfuPlacementPolicy {
    fn default() -> Self {
        Self {
            preferred_region: None,
            allow_cross_region_failover: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuPlacementDecision {
    pub node_id: ucr_model::OpaqueId,
    pub retained_sticky_placement: bool,
    pub crossed_region: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuPlacementError {
    InvalidNode,
    NoHealthyCapacity,
}

/// Ephemeral horizontal-SFU placement directory.
///
/// The directory owns no canonical Call, Conference, membership, permission or media state. Callers
/// pass an existing node ID when reconnecting so a healthy or draining node remains sticky. New
/// placement never targets draining/unavailable/expired/full nodes. If the sticky node is gone or
/// unhealthy, deterministic rendezvous-style scoring selects a healthy replacement.
#[derive(Debug, Default)]
pub struct SfuClusterDirectory {
    nodes: BTreeMap<String, SfuNodeDescriptor>,
}

impl SfuClusterDirectory {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Registers or refreshes one ephemeral worker heartbeat.
    ///
    /// # Errors
    /// Rejects empty region labels, zero capacity, over-capacity counters, or non-positive leases.
    pub fn upsert_node(&mut self, node: SfuNodeDescriptor) -> Result<(), SfuPlacementError> {
        if node.region.is_empty()
            || node.max_sessions == 0
            || node.active_sessions > node.max_sessions
            || node.lease_expires_at_unix_ms <= 0
        {
            return Err(SfuPlacementError::InvalidNode);
        }
        self.nodes.insert(node.node_id.as_str().to_owned(), node);
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: &ucr_model::OpaqueId) {
        self.nodes.remove(node_id.as_str());
    }

    /// Marks a live worker as draining. Existing sticky sessions may remain on it, while new
    /// placements immediately stop selecting it.
    ///
    /// # Errors
    /// Returns InvalidNode when the worker is unknown.
    pub fn mark_draining(&mut self, node_id: &ucr_model::OpaqueId) -> Result<(), SfuPlacementError> {
        let node = self
            .nodes
            .get_mut(node_id.as_str())
            .ok_or(SfuPlacementError::InvalidNode)?;
        node.state = SfuNodeState::Draining;
        Ok(())
    }

    /// Selects one worker for an already-authorized canonical Call.
    ///
    /// The optional current node is infrastructure stickiness only. It grants no Conference or
    /// media authority. A draining node is retained only when it is the explicit current placement.
    ///
    /// # Errors
    /// Returns NoHealthyCapacity when policy leaves no live worker capacity.
    pub fn select_node(
        &self,
        scope: &ucr_model::TenantScope,
        call_id: &ucr_model::CallId,
        current_node_id: Option<&ucr_model::OpaqueId>,
        policy: &SfuPlacementPolicy,
        now_unix_ms: i64,
    ) -> Result<SfuPlacementDecision, SfuPlacementError> {
        if let Some(current_node_id) = current_node_id
            && let Some(current) = self.nodes.get(current_node_id.as_str())
            && current.is_live_at(now_unix_ms)
            && current.active_sessions <= current.max_sessions
        {
            let preferred = policy.preferred_region.as_deref();
            let crossed_region = preferred.is_some_and(|region| current.region != region);
            if !crossed_region || policy.allow_cross_region_failover {
                return Ok(SfuPlacementDecision {
                    node_id: current.node_id.clone(),
                    retained_sticky_placement: true,
                    crossed_region,
                });
            }
        }

        let mut candidates = self
            .nodes
            .values()
            .filter(|node| node.accepts_new_session_at(now_unix_ms))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(SfuPlacementError::NoHealthyCapacity);
        }

        let preferred = policy.preferred_region.as_deref();
        if let Some(region) = preferred {
            let has_preferred = candidates.iter().any(|node| node.region == region);
            if has_preferred {
                candidates.retain(|node| node.region == region);
            } else if !policy.allow_cross_region_failover {
                return Err(SfuPlacementError::NoHealthyCapacity);
            }
        }

        let key = placement_key(scope, call_id);
        let selected = candidates
            .into_iter()
            .max_by_key(|node| placement_score(&key, node.node_id.as_wire_bytes()))
            .ok_or(SfuPlacementError::NoHealthyCapacity)?;
        Ok(SfuPlacementDecision {
            node_id: selected.node_id.clone(),
            retained_sticky_placement: false,
            crossed_region: preferred.is_some_and(|region| selected.region != region),
        })
    }
}

fn placement_key(scope: &ucr_model::TenantScope, call_id: &ucr_model::CallId) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(scope.tenant_id.as_opaque().as_wire_bytes());
    key.push(0);
    if let Some(namespace_id) = scope.namespace_id.as_ref() {
        key.extend_from_slice(namespace_id.as_opaque().as_wire_bytes());
    }
    key.push(0);
    key.extend_from_slice(call_id.as_opaque().as_wire_bytes());
    key
}

fn placement_score(key: &[u8], node_id: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in key.iter().chain(node_id.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuForwardSinkError {
    Unavailable,
    Backpressure,
    Rejected,
}

/// Infrastructure handoff for one already-encrypted group-media frame and one ephemeral recipient.
///
/// Implementations receive no plaintext media or key material. Returning success means only that
/// the SFU routing sink accepted this ciphertext for that recipient; it is not Delivery/Read
/// evidence and does not create durable Conference/subscription state.
pub trait SfuForwardSink: fmt::Debug + Send + Sync {
    /// Forwards one canonical encrypted envelope without mutating authenticated frame fields.
    ///
    /// # Errors
    /// Returns bounded infrastructure acceptance/backpressure failures.
    fn forward_encrypted(
        &self,
        target: &SfuForwardTarget,
        envelope: &SfuForwardEnvelope,
    ) -> Result<(), SfuForwardSinkError>;
}

pub trait SfuCapabilityProvider: fmt::Debug + Send + Sync {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedSfuCapabilities;

impl SfuCapabilityProvider for PreparedSfuCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        phase29_sfu_capabilities()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SfuForwardOutcome {
    pub accepted_recipients: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfuError {
    Protocol(SfuProtocolError),
    MediaE2ee(GroupMediaE2eeError),
    Authorization(CanonicalError),
    Store(DurableStoreError),
    CapabilityUnavailable,
    SourceMismatch,
    RecipientMembershipUnavailable,
    NoRecipients,
    TooManyRecipients,
    InvalidRecipientSet,
    Sink {
        accepted_before_failure: usize,
        error: SfuForwardSinkError,
    },
}

impl From<SfuProtocolError> for SfuError {
    fn from(error: SfuProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<GroupMediaE2eeError> for SfuError {
    fn from(error: GroupMediaE2eeError) -> Self {
        Self::MediaE2ee(error)
    }
}

impl From<DurableStoreError> for SfuError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug)]
pub struct SfuRuntime<'a, A, S, E, C> {
    authorization: &'a A,
    store: &'a S,
    group_e2ee_capabilities: &'a E,
    sfu_capabilities: &'a C,
}

impl<'a, A, S, E, C> SfuRuntime<'a, A, S, E, C> {
    #[must_use]
    pub const fn new(
        authorization: &'a A,
        store: &'a S,
        group_e2ee_capabilities: &'a E,
        sfu_capabilities: &'a C,
    ) -> Self {
        Self {
            authorization,
            store,
            group_e2ee_capabilities,
            sfu_capabilities,
        }
    }
}

impl<A, S, E, C> SfuRuntime<'_, A, S, E, C>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
    E: GroupMediaE2eeCapabilityProvider,
    C: SfuCapabilityProvider,
{
    /// Fans one source-authenticated MLS-backed group-media ciphertext out to the current accepted
    /// Call participants without decrypting it.
    ///
    /// All Group membership and send/receive permission checks are completed before the first sink
    /// side effect. The sink calls are then bounded by the canonical Call participant ceiling. A
    /// sink failure can therefore report an explicit partial-acceptance count rather than claiming
    /// rollback or exactly-once semantics that infrastructure cannot provide.
    ///
    /// # Errors
    /// Fails closed on stale/revoked Group/Call/Device/MLS authority, source signature forgery,
    /// spoofed source/device, lost permission, malformed ciphertext, recipient membership drift,
    /// unavailable capability, or sink failure.
    pub fn forward(
        &self,
        authenticated_source: &ScopedPrincipal,
        authenticated_source_device_id: &DeviceId,
        envelope: &SfuForwardEnvelope,
        sink: &dyn SfuForwardSink,
    ) -> Result<SfuForwardOutcome, SfuError> {
        self.forward_impl(
            authenticated_source,
            authenticated_source_device_id,
            envelope,
            None,
            sink,
        )
    }

    /// Fans one source-authenticated encrypted frame only to the explicitly selected current Call
    /// recipients. This is the scalable Phase-30 integration point: recipient selection is owned by
    /// the Conference coordinator, while SFU still revalidates canonical Call/Group/permission
    /// authority and never trusts the selection as authorization evidence.
    ///
    /// # Errors
    /// Rejects empty/duplicate/source-containing/non-participant recipient sets, stale authority,
    /// lost permissions, malformed ciphertext, or sink failure.
    pub fn forward_selected(
        &self,
        authenticated_source: &ScopedPrincipal,
        authenticated_source_device_id: &DeviceId,
        envelope: &SfuForwardEnvelope,
        recipients: &[ucr_model::PrincipalRef],
        sink: &dyn SfuForwardSink,
    ) -> Result<SfuForwardOutcome, SfuError> {
        self.forward_impl(
            authenticated_source,
            authenticated_source_device_id,
            envelope,
            Some(recipients),
            sink,
        )
    }

    fn forward_impl(
        &self,
        authenticated_source: &ScopedPrincipal,
        authenticated_source_device_id: &DeviceId,
        envelope: &SfuForwardEnvelope,
        selected_recipients: Option<&[ucr_model::PrincipalRef]>,
        sink: &dyn SfuForwardSink,
    ) -> Result<SfuForwardOutcome, SfuError> {
        let (context, canonical) = canonical_sfu_forward_envelope(envelope)?;
        if authenticated_source.scope != context.scope
            || authenticated_source.principal != canonical.frame.header.source
            || authenticated_source_device_id != &canonical.frame.header.source_device_id
        {
            return Err(SfuError::SourceMismatch);
        }
        require_sfu_capability(self.sfu_capabilities)?;
        require_group_e2ee_capability(self.group_e2ee_capabilities)?;
        let call = validate_group_media_source_frame(self.store, &context, &canonical.frame)?;
        let (send, receive) = permissions(
            canonical.frame.header.media_kind,
            canonical.frame.header.video_source_kind,
        );
        self.authorization
            .authorize(&AuthorizationRequest {
                subject: authenticated_source.clone(),
                permission: send.to_owned(),
                resource_scope: context.scope.clone(),
            })
            .map_err(SfuError::Authorization)?;

        let recipients = if let Some(selected) = selected_recipients {
            validate_selected_recipients(&call, &authenticated_source.principal, selected)?;
            selected.to_vec()
        } else {
            call.participants
                .iter()
                .filter(|participant| {
                    participant.principal != authenticated_source.principal
                        && participant.state == CallParticipantState::Accepted
                        && participant.left_revision.is_none()
                })
                .map(|participant| participant.principal.clone())
                .collect::<Vec<_>>()
        };
        if recipients.is_empty() {
            return Err(SfuError::NoRecipients);
        }
        if recipients.len() > MAX_CALL_PARTICIPANTS.saturating_sub(1) {
            return Err(SfuError::TooManyRecipients);
        }

        let mut targets = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let membership = self
                .store
                .group_membership_for_active_member(
                    authenticated_source,
                    &context.scope,
                    &context.group_id,
                    &recipient,
                )?
                .ok_or(SfuError::RecipientMembershipUnavailable)?;
            if membership.state != GroupMemberState::Active {
                return Err(SfuError::RecipientMembershipUnavailable);
            }
            let target_principal = ScopedPrincipal {
                scope: context.scope.clone(),
                principal: recipient.clone(),
            };
            self.authorization
                .authorize(&AuthorizationRequest {
                    subject: target_principal,
                    permission: receive.to_owned(),
                    resource_scope: context.scope.clone(),
                })
                .map_err(SfuError::Authorization)?;
            targets.push(SfuForwardTarget { recipient });
        }

        for (accepted, target) in targets.iter().enumerate() {
            if let Err(error) = sink.forward_encrypted(target, &canonical) {
                return Err(SfuError::Sink {
                    accepted_before_failure: accepted,
                    error,
                });
            }
        }
        Ok(SfuForwardOutcome {
            accepted_recipients: targets.len(),
        })
    }
}

fn validate_selected_recipients(
    call: &ucr_model::CallSession,
    source: &ucr_model::PrincipalRef,
    recipients: &[ucr_model::PrincipalRef],
) -> Result<(), SfuError> {
    if recipients.is_empty() || recipients.len() > MAX_CALL_PARTICIPANTS.saturating_sub(1) {
        return Err(SfuError::InvalidRecipientSet);
    }
    let mut unique = std::collections::HashSet::with_capacity(recipients.len());
    for recipient in recipients {
        if recipient == source || !unique.insert(recipient) {
            return Err(SfuError::InvalidRecipientSet);
        }
        let accepted = call.participants.iter().any(|participant| {
            participant.principal == *recipient
                && participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        });
        if !accepted {
            return Err(SfuError::InvalidRecipientSet);
        }
    }
    Ok(())
}

fn require_sfu_capability<C: SfuCapabilityProvider>(capabilities: &C) -> Result<(), SfuError> {
    require_capability(&capabilities.current_capabilities(), SFU_MEDIA_CAPABILITY)
}

fn require_group_e2ee_capability<C: GroupMediaE2eeCapabilityProvider>(
    capabilities: &C,
) -> Result<(), SfuError> {
    require_capability(
        &capabilities.current_capabilities(),
        GROUP_MEDIA_E2EE_CAPABILITY,
    )
}

fn require_capability(
    capabilities: &[CapabilityDescriptor],
    required: &str,
) -> Result<(), SfuError> {
    let capabilities =
        canonical_capabilities(capabilities).map_err(|_| SfuError::CapabilityUnavailable)?;
    if capabilities.iter().any(|capability| {
        capability.id == required
            && matches!(
                capability.maturity,
                CapabilityMaturity::Prepared
                    | CapabilityMaturity::Beta
                    | CapabilityMaturity::Production
            )
            && capability
                .extensions
                .iter()
                .all(|extension| !extension.critical)
    }) {
        Ok(())
    } else {
        Err(SfuError::CapabilityUnavailable)
    }
}

const fn permissions(
    media_kind: MediaKind,
    video_source_kind: Option<VideoSourceKind>,
) -> (&'static str, &'static str) {
    match (media_kind, video_source_kind) {
        (MediaKind::Video, Some(VideoSourceKind::ScreenShare)) => {
            (SCREEN_SHARE_SEND_PERMISSION, VIDEO_RECEIVE_PERMISSION)
        }
        (MediaKind::Video, _) => (VIDEO_SEND_PERMISSION, VIDEO_RECEIVE_PERMISSION),
        (MediaKind::Audio, _) => (AUDIO_SEND_PERMISSION, AUDIO_RECEIVE_PERMISSION),
    }
}

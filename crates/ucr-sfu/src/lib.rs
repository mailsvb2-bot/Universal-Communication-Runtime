#![forbid(unsafe_code)]

use core::fmt;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

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

pub const MAX_SFU_CLUSTER_NODES: usize = 256;
pub const MAX_SFU_REGION_BYTES: usize = 64;

/// Ephemeral health state for one SFU worker in a horizontal deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfuNodeState {
    Healthy,
    Draining,
    Unavailable,
}

/// Private routable media endpoint for one ephemeral SFU worker.
///
/// This is infrastructure-only routing metadata. It is never part of the public Conference API and
/// carries no tenant, participant, media-key, plaintext-media, or provider credential data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SfuNodeEndpoint {
    pub address: SocketAddr,
}

impl SfuNodeEndpoint {
    /// Creates a routable endpoint from an already-parsed socket address.
    ///
    /// # Errors
    /// Rejects zero ports and unspecified/multicast/broadcast IP targets.
    pub fn new(address: SocketAddr) -> Result<Self, SfuPlacementError> {
        let ip = address.ip();
        let invalid_ip = ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(value) if value.is_broadcast());
        if address.port() == 0 || invalid_ip {
            return Err(SfuPlacementError::InvalidEndpoint);
        }
        Ok(Self { address })
    }
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

}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuNodeCapacitySnapshot {
    pub node: SfuNodeDescriptor,
    pub reserved_sessions: u32,
    pub effective_sessions: u64,
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
    InvalidEndpoint,
    EndpointUnavailable,
    NoHealthyCapacity,
}

/// Ephemeral horizontal-SFU placement directory.
///
/// The directory owns no canonical Call, Conference, membership, permission or media state. It
/// keeps only an in-process Call-to-worker placement map so stickiness cannot be forged by a caller.
/// Worker-reported active load and coordinator-owned placement reservations remain separate: a
/// heartbeat must never erase capacity already reserved by the coordinator. New placement never
/// targets draining/unavailable/expired/full nodes. If the sticky node is gone or unhealthy,
/// deterministic rendezvous-style scoring selects a healthy replacement.
#[derive(Debug, Default)]
pub struct SfuClusterDirectory {
    nodes: BTreeMap<String, SfuNodeDescriptor>,
    endpoints: BTreeMap<String, SfuNodeEndpoint>,
    placements: BTreeMap<Vec<u8>, String>,
    reservations: BTreeMap<String, u32>,
}

impl SfuClusterDirectory {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
            && self.endpoints.is_empty()
            && self.placements.is_empty()
            && self.reservations.is_empty()
    }

    fn reserved_sessions(&self, node_id: &str) -> u32 {
        self.reservations.get(node_id).copied().unwrap_or(0)
    }

    fn effective_sessions(&self, node: &SfuNodeDescriptor) -> u64 {
        u64::from(node.active_sessions)
            + u64::from(self.reserved_sessions(node.node_id.as_str()))
    }

    fn accepts_new_session_at(&self, node: &SfuNodeDescriptor, now_unix_ms: i64) -> bool {
        node.is_live_at(now_unix_ms)
            && node.state == SfuNodeState::Healthy
            && node.max_sessions > 0
            && self.effective_sessions(node) < u64::from(node.max_sessions)
    }

    fn reserve_session(&mut self, node_id: &str) -> Result<(), SfuPlacementError> {
        let reserved = self.reserved_sessions(node_id);
        let next = reserved
            .checked_add(1)
            .ok_or(SfuPlacementError::NoHealthyCapacity)?;
        self.reservations.insert(node_id.to_owned(), next);
        Ok(())
    }

    fn release_reservation(&mut self, node_id: &str) -> Result<(), SfuPlacementError> {
        let reserved = self
            .reservations
            .get_mut(node_id)
            .ok_or(SfuPlacementError::InvalidNode)?;
        if *reserved == 0 {
            return Err(SfuPlacementError::InvalidNode);
        }
        *reserved -= 1;
        if *reserved == 0 {
            self.reservations.remove(node_id);
        }
        Ok(())
    }

    /// Registers or refreshes one ephemeral worker heartbeat.
    ///
    /// # Errors
    /// Rejects invalid/oversized region labels, zero capacity, over-capacity counters,
    /// non-positive leases, or a new node beyond the bounded cluster directory limit.
    pub fn upsert_node(&mut self, node: SfuNodeDescriptor) -> Result<(), SfuPlacementError> {
        if node.region.is_empty()
            || node.region.len() > MAX_SFU_REGION_BYTES
            || node.max_sessions == 0
            || node.active_sessions > node.max_sessions
            || node.lease_expires_at_unix_ms <= 0
            || (!self.nodes.contains_key(node.node_id.as_str())
                && self.nodes.len() >= MAX_SFU_CLUSTER_NODES)
        {
            return Err(SfuPlacementError::InvalidNode);
        }
        let node_id = node.node_id.as_str().to_owned();
        self.nodes.insert(node_id.clone(), node);
        self.endpoints.remove(&node_id);
        Ok(())
    }

    /// Registers or refreshes one worker together with its private media-routing endpoint.
    ///
    /// Endpoint and worker metadata share this same ephemeral directory so placement and routing
    /// cannot silently diverge into separate sources of truth.
    ///
    /// # Errors
    /// Returns the same node-validation errors as `upsert_node` and rejects an invalid endpoint
    /// before mutating either map.
    pub fn upsert_node_with_endpoint(
        &mut self,
        node: SfuNodeDescriptor,
        endpoint: SfuNodeEndpoint,
    ) -> Result<(), SfuPlacementError> {
        SfuNodeEndpoint::new(endpoint.address)?;
        let node_id = node.node_id.as_str().to_owned();
        self.upsert_node(node)?;
        self.endpoints.insert(node_id, endpoint);
        Ok(())
    }

    /// Resolves a private endpoint only for a currently live worker.
    ///
    /// Draining workers remain resolvable for already-sticky Calls, while unavailable/expired
    /// workers fail closed. This method does not select a node; selection remains owned by
    /// `place_session`.
    ///
    /// # Errors
    /// Returns `InvalidNode` for an unknown worker or `EndpointUnavailable` when the worker is
    /// expired/unavailable or has no registered endpoint.
    pub fn resolve_live_endpoint(
        &self,
        node_id: &ucr_model::OpaqueId,
        now_unix_ms: i64,
    ) -> Result<SfuNodeEndpoint, SfuPlacementError> {
        let node = self
            .nodes
            .get(node_id.as_str())
            .ok_or(SfuPlacementError::InvalidNode)?;
        if !node.is_live_at(now_unix_ms) {
            return Err(SfuPlacementError::EndpointUnavailable);
        }
        self.endpoints
            .get(node_id.as_str())
            .copied()
            .ok_or(SfuPlacementError::EndpointUnavailable)
    }

    #[must_use]
    pub fn node(&self, node_id: &ucr_model::OpaqueId) -> Option<SfuNodeDescriptor> {
        self.nodes.get(node_id.as_str()).cloned()
    }

    #[must_use]
    pub fn nodes(&self) -> Vec<SfuNodeDescriptor> {
        self.nodes.values().cloned().collect()
    }

    #[must_use]
    pub fn node_with_capacity(
        &self,
        node_id: &ucr_model::OpaqueId,
    ) -> Option<SfuNodeCapacitySnapshot> {
        self.nodes.get(node_id.as_str()).map(|node| SfuNodeCapacitySnapshot {
            node: node.clone(),
            reserved_sessions: self.reserved_sessions(node.node_id.as_str()),
            effective_sessions: self.effective_sessions(node),
        })
    }

    #[must_use]
    pub fn nodes_with_capacity(&self) -> Vec<SfuNodeCapacitySnapshot> {
        self.nodes
            .values()
            .map(|node| SfuNodeCapacitySnapshot {
                node: node.clone(),
                reserved_sessions: self.reserved_sessions(node.node_id.as_str()),
                effective_sessions: self.effective_sessions(node),
            })
            .collect()
    }

    /// Removes workers whose heartbeat lease has expired and clears any sticky placements that
    /// referenced them. This keeps the bounded ephemeral directory reusable across worker churn.
    pub fn prune_expired_nodes(&mut self, now_unix_ms: i64) -> usize {
        let expired = self
            .nodes
            .iter()
            .filter_map(|(node_id, node)| {
                (node.lease_expires_at_unix_ms <= now_unix_ms).then_some(node_id.clone())
            })
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return 0;
        }
        for node_id in &expired {
            self.nodes.remove(node_id);
            self.endpoints.remove(node_id);
            self.reservations.remove(node_id);
        }
        self.placements.retain(|_, assigned_node_id| {
            !expired.iter().any(|node_id| node_id == assigned_node_id)
        });
        expired.len()
    }

    pub fn remove_node(&mut self, node_id: &ucr_model::OpaqueId) {
        self.nodes.remove(node_id.as_str());
        self.endpoints.remove(node_id.as_str());
        self.reservations.remove(node_id.as_str());
        self.placements
            .retain(|_, assigned_node_id| assigned_node_id != node_id.as_str());
    }

    /// Marks a live worker as draining. Existing sticky sessions may remain on it, while new
    /// placements immediately stop selecting it.
    ///
    /// # Errors
    /// Returns `InvalidNode` when the worker is unknown.
    pub fn mark_draining(
        &mut self,
        node_id: &ucr_model::OpaqueId,
    ) -> Result<(), SfuPlacementError> {
        let node = self
            .nodes
            .get_mut(node_id.as_str())
            .ok_or(SfuPlacementError::InvalidNode)?;
        node.state = SfuNodeState::Draining;
        Ok(())
    }

    /// Places one already-authorized canonical Call and reserves capacity for a fresh placement.
    ///
    /// Stickiness is resolved only from this directory's ephemeral Call-to-worker map; callers
    /// cannot claim an arbitrary current worker. A draining worker is retained only for a Call
    /// already mapped to it. Fresh placement increments the selected worker's active-session count
    /// before returning, so one directory instance cannot overbook the last slot.
    ///
    /// # Errors
    /// Returns `NoHealthyCapacity` when policy leaves no live worker capacity.
    pub fn place_session(
        &mut self,
        scope: &ucr_model::TenantScope,
        call_id: &ucr_model::CallId,
        policy: &SfuPlacementPolicy,
        now_unix_ms: i64,
    ) -> Result<SfuPlacementDecision, SfuPlacementError> {
        let key = placement_key(scope, call_id);
        if let Some(current_node_id) = self.placements.get(&key).cloned() {
            if let Some(current) = self.nodes.get(&current_node_id)
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
            self.placements.remove(&key);
            self.release_reservation(&current_node_id)?;
        }

        let mut candidates = self
            .nodes
            .values()
            .filter(|node| self.accepts_new_session_at(node, now_unix_ms))
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

        let selected = candidates
            .into_iter()
            .max_by_key(|node| placement_score(&key, node.node_id.as_wire_bytes()))
            .ok_or(SfuPlacementError::NoHealthyCapacity)?;
        let selected_id = selected.node_id.as_str().to_owned();
        let selected_region = selected.region.clone();
        let selected_node = self
            .nodes
            .get(&selected_id)
            .ok_or(SfuPlacementError::NoHealthyCapacity)?;
        if !self.accepts_new_session_at(selected_node, now_unix_ms) {
            return Err(SfuPlacementError::NoHealthyCapacity);
        }
        let selected_node_id = selected_node.node_id.clone();
        self.reserve_session(&selected_id)?;
        self.placements.insert(key, selected_id);
        Ok(SfuPlacementDecision {
            node_id: selected_node_id,
            retained_sticky_placement: false,
            crossed_region: preferred.is_some_and(|region| selected_region != region),
        })
    }

    /// Releases one previously reserved horizontal-SFU session slot.
    ///
    /// # Errors
    /// Returns `InvalidNode` when the Call has no placement or its worker has no reserved session.
    pub fn release_session(
        &mut self,
        scope: &ucr_model::TenantScope,
        call_id: &ucr_model::CallId,
    ) -> Result<(), SfuPlacementError> {
        let key = placement_key(scope, call_id);
        let node_id = self
            .placements
            .remove(&key)
            .ok_or(SfuPlacementError::InvalidNode)?;
        if !self.nodes.contains_key(&node_id) {
            return Err(SfuPlacementError::InvalidNode);
        }
        self.release_reservation(&node_id)
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
    for byte in key {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= 0xff;
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    for byte in node_id {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }

    // SplitMix64 finalization gives the rendezvous comparison strong avalanche behavior even when
    // worker IDs share long prefixes such as sfu-1, sfu-2, sfu-3 and sfu-4.
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
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

#[cfg(test)]
mod horizontal_placement_tests {
    use std::net::SocketAddr;

    use super::{
        MAX_SFU_CLUSTER_NODES, SfuClusterDirectory, SfuNodeDescriptor, SfuNodeEndpoint,
        SfuNodeState, SfuPlacementError, SfuPlacementPolicy,
    };
    use ucr_model::{CallId, NamespaceId, OpaqueId, TenantId, TenantScope};

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("opaque id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque("tenant-a")),
            namespace_id: Some(NamespaceId::from_opaque(opaque("namespace-a"))),
        }
    }

    fn call(value: &str) -> CallId {
        CallId::from_opaque(opaque(value))
    }

    fn node(
        id: &str,
        region: &str,
        state: SfuNodeState,
        active_sessions: u32,
        max_sessions: u32,
        lease_expires_at_unix_ms: i64,
    ) -> SfuNodeDescriptor {
        SfuNodeDescriptor {
            node_id: opaque(id),
            region: region.to_owned(),
            state,
            active_sessions,
            max_sessions,
            lease_expires_at_unix_ms,
        }
    }

    #[test]
    fn endpointless_worker_refresh_cannot_leave_a_stale_route() {
        let mut directory = SfuClusterDirectory::default();
        let node_id = opaque("sfu-refresh");
        directory
            .upsert_node_with_endpoint(
                node("sfu-refresh", "eu", SfuNodeState::Healthy, 0, 100, 20_000),
                SfuNodeEndpoint::new("127.0.0.1:7002".parse().expect("socket")).expect("endpoint"),
            )
            .expect("node endpoint");
        directory
            .upsert_node(node(
                "sfu-refresh",
                "eu",
                SfuNodeState::Healthy,
                1,
                100,
                30_000,
            ))
            .expect("endpointless refresh");
        assert_eq!(
            directory.resolve_live_endpoint(&node_id, 10_000),
            Err(SfuPlacementError::EndpointUnavailable)
        );
    }

    #[test]
    fn private_endpoint_resolution_follows_node_lease_and_removal() {
        let mut directory = SfuClusterDirectory::default();
        let node_id = opaque("sfu-route");
        directory
            .upsert_node_with_endpoint(
                node("sfu-route", "eu", SfuNodeState::Healthy, 0, 100, 10_000),
                SfuNodeEndpoint::new("127.0.0.1:7001".parse().expect("socket")).expect("endpoint"),
            )
            .expect("node endpoint");

        assert_eq!(
            directory
                .resolve_live_endpoint(&node_id, 9_999)
                .expect("live endpoint")
                .address,
            "127.0.0.1:7001".parse::<SocketAddr>().expect("socket")
        );
        assert_eq!(
            directory.resolve_live_endpoint(&node_id, 10_000),
            Err(SfuPlacementError::EndpointUnavailable)
        );
        assert_eq!(directory.prune_expired_nodes(10_000), 1);
        assert_eq!(
            directory.resolve_live_endpoint(&node_id, 10_000),
            Err(SfuPlacementError::InvalidNode)
        );
        assert!(directory.is_empty());
    }

    #[test]
    fn deterministic_placement_is_sticky_without_mutating_call_state() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("sfu-a", "eu", SfuNodeState::Healthy, 1, 100, 10_000))
            .expect("node a");
        directory
            .upsert_node(node("sfu-b", "eu", SfuNodeState::Healthy, 1, 100, 10_000))
            .expect("node b");

        let first = directory
            .place_session(
                &scope(),
                &call("call-a"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("placement");
        assert!(!first.retained_sticky_placement);

        let sticky = directory
            .place_session(
                &scope(),
                &call("call-a"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("sticky");
        assert_eq!(sticky.node_id, first.node_id);
        assert!(sticky.retained_sticky_placement);
    }

    #[test]
    fn draining_node_keeps_existing_session_but_receives_no_new_placement() {
        let mut directory = SfuClusterDirectory::default();
        let draining_id = opaque("sfu-drain");
        directory
            .upsert_node(node(
                draining_id.as_str(),
                "eu",
                SfuNodeState::Healthy,
                0,
                100,
                10_000,
            ))
            .expect("draining candidate");
        let initial = directory
            .place_session(
                &scope(),
                &call("call-draining"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("initial placement");
        assert_eq!(initial.node_id, draining_id);

        directory
            .upsert_node(node("sfu-new", "eu", SfuNodeState::Healthy, 0, 100, 10_000))
            .expect("new candidate");
        directory
            .mark_draining(&draining_id)
            .expect("mark draining");

        let sticky = directory
            .place_session(
                &scope(),
                &call("call-draining"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("sticky draining");
        assert_eq!(sticky.node_id, draining_id);
        assert!(sticky.retained_sticky_placement);

        let fresh = directory
            .place_session(
                &scope(),
                &call("call-fresh"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("fresh placement");
        assert_eq!(fresh.node_id.as_str(), "sfu-new");
        assert!(!fresh.retained_sticky_placement);
    }

    #[test]
    fn expired_or_unavailable_sticky_node_fails_over_to_live_capacity() {
        let mut directory = SfuClusterDirectory::default();
        let expired = opaque("sfu-expired");
        directory
            .upsert_node(node(
                expired.as_str(),
                "eu",
                SfuNodeState::Healthy,
                0,
                100,
                10_000,
            ))
            .expect("initial node");
        let initial = directory
            .place_session(
                &scope(),
                &call("call-failover"),
                &SfuPlacementPolicy::default(),
                50,
            )
            .expect("initial placement");
        assert_eq!(initial.node_id, expired);

        directory
            .upsert_node(node(
                expired.as_str(),
                "eu",
                SfuNodeState::Healthy,
                1,
                100,
                99,
            ))
            .expect("expire node");
        directory
            .upsert_node(node(
                "sfu-live",
                "eu",
                SfuNodeState::Healthy,
                0,
                100,
                10_000,
            ))
            .expect("live node");

        let decision = directory
            .place_session(
                &scope(),
                &call("call-failover"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("failover");
        assert_eq!(decision.node_id.as_str(), "sfu-live");
        assert!(!decision.retained_sticky_placement);
    }

    #[test]
    fn removing_worker_clears_stale_stickiness_and_allows_fresh_failover() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("sfu-old", "eu", SfuNodeState::Healthy, 0, 100, 10_000))
            .expect("old node");
        let initial = directory
            .place_session(
                &scope(),
                &call("call-remove"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("initial placement");
        assert_eq!(initial.node_id.as_str(), "sfu-old");

        directory.remove_node(&initial.node_id);
        directory
            .upsert_node(node("sfu-new", "eu", SfuNodeState::Healthy, 0, 100, 10_000))
            .expect("new node");
        let failover = directory
            .place_session(
                &scope(),
                &call("call-remove"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("fresh failover");
        assert_eq!(failover.node_id.as_str(), "sfu-new");
        assert!(!failover.retained_sticky_placement);
    }

    #[test]
    fn region_policy_fails_closed_without_allowed_cross_region_capacity() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("sfu-us", "us", SfuNodeState::Healthy, 1, 100, 10_000))
            .expect("us node");
        let strict = SfuPlacementPolicy {
            preferred_region: Some("eu".to_owned()),
            allow_cross_region_failover: false,
        };
        assert_eq!(
            directory.place_session(&scope(), &call("call-region"), &strict, 100),
            Err(SfuPlacementError::NoHealthyCapacity)
        );

        let permissive = SfuPlacementPolicy {
            allow_cross_region_failover: true,
            ..strict
        };
        let decision = directory
            .place_session(&scope(), &call("call-region"), &permissive, 100)
            .expect("cross-region failover");
        assert_eq!(decision.node_id.as_str(), "sfu-us");
        assert!(decision.crossed_region);
    }

    #[test]
    fn fresh_placement_reserves_and_release_returns_capacity() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("single", "eu", SfuNodeState::Healthy, 0, 1, 10_000))
            .expect("single node");

        let first = directory
            .place_session(
                &scope(),
                &call("call-one"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("first placement");
        assert_eq!(first.node_id.as_str(), "single");
        assert_eq!(
            directory.place_session(
                &scope(),
                &call("call-two"),
                &SfuPlacementPolicy::default(),
                100,
            ),
            Err(SfuPlacementError::NoHealthyCapacity)
        );

        directory
            .release_session(&scope(), &call("call-one"))
            .expect("release capacity");
        let second = directory
            .place_session(
                &scope(),
                &call("call-two"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("second placement");
        assert_eq!(second.node_id.as_str(), "single");
    }

    #[test]
    fn heartbeat_cannot_erase_coordinator_capacity_reservation() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("single", "eu", SfuNodeState::Healthy, 0, 1, 10_000))
            .expect("single node");
        directory
            .place_session(
                &scope(),
                &call("call-one"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("first placement");

        directory
            .upsert_node(node("single", "eu", SfuNodeState::Healthy, 0, 1, 20_000))
            .expect("worker heartbeat refresh");
        let snapshot = directory
            .node_with_capacity(&opaque("single"))
            .expect("capacity snapshot");
        assert_eq!(snapshot.node.active_sessions, 0);
        assert_eq!(snapshot.reserved_sessions, 1);
        assert_eq!(snapshot.effective_sessions, 1);

        assert_eq!(
            directory.place_session(
                &scope(),
                &call("call-two"),
                &SfuPlacementPolicy::default(),
                100,
            ),
            Err(SfuPlacementError::NoHealthyCapacity)
        );

        directory
            .release_session(&scope(), &call("call-one"))
            .expect("release coordinator reservation");
        directory
            .place_session(
                &scope(),
                &call("call-two"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("capacity is reusable after release");
    }

    #[test]
    fn worker_reported_load_and_pending_reservations_are_counted_conservatively() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("node", "eu", SfuNodeState::Healthy, 0, 2, 10_000))
            .expect("node");
        directory
            .place_session(
                &scope(),
                &call("reserved"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("reservation");

        directory
            .upsert_node(node("node", "eu", SfuNodeState::Healthy, 1, 2, 20_000))
            .expect("worker heartbeat");
        assert_eq!(
            directory.place_session(
                &scope(),
                &call("second"),
                &SfuPlacementPolicy::default(),
                100,
            ),
            Err(SfuPlacementError::NoHealthyCapacity)
        );

        directory
            .release_session(&scope(), &call("reserved"))
            .expect("release reservation");
        directory
            .place_session(
                &scope(),
                &call("second"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("one reported active plus one reservation fits");
    }

    #[test]
    fn rendezvous_distribution_does_not_collapse_common_prefix_workers() {
        let mut counts = std::collections::BTreeMap::<String, usize>::new();
        for index in 0..1_024_u32 {
            let mut directory = SfuClusterDirectory::default();
            for id in ["sfu-1", "sfu-2", "sfu-3", "sfu-4"] {
                directory
                    .upsert_node(node(id, "eu", SfuNodeState::Healthy, 0, 2_000, 10_000))
                    .expect("worker");
            }
            let decision = directory
                .place_session(
                    &scope(),
                    &call(&format!("call-{index}")),
                    &SfuPlacementPolicy::default(),
                    100,
                )
                .expect("placement");
            *counts
                .entry(decision.node_id.as_str().to_owned())
                .or_default() += 1;
        }

        assert_eq!(counts.len(), 4);
        for (node_id, count) in counts {
            assert!(
                (160..=352).contains(&count),
                "rendezvous distribution collapsed for {node_id}: {count}"
            );
        }
    }

    #[test]
    fn expired_worker_pruning_reclaims_capacity_and_stale_stickiness() {
        let mut directory = SfuClusterDirectory::default();
        directory
            .upsert_node(node("expired", "eu", SfuNodeState::Healthy, 0, 100, 100))
            .expect("expired node");
        directory
            .place_session(
                &scope(),
                &call("stale-call"),
                &SfuPlacementPolicy::default(),
                50,
            )
            .expect("initial placement");
        directory
            .upsert_node(node("live", "eu", SfuNodeState::Healthy, 0, 100, 10_000))
            .expect("live node");

        assert_eq!(directory.prune_expired_nodes(100), 1);
        assert!(directory.node(&opaque("expired")).is_none());

        let replacement = directory
            .place_session(
                &scope(),
                &call("stale-call"),
                &SfuPlacementPolicy::default(),
                100,
            )
            .expect("fresh placement after prune");
        assert_eq!(replacement.node_id.as_str(), "live");
        assert!(!replacement.retained_sticky_placement);
    }

    #[test]
    fn cluster_directory_rejects_unbounded_worker_registration() {
        let mut directory = SfuClusterDirectory::default();
        for index in 0..MAX_SFU_CLUSTER_NODES {
            directory
                .upsert_node(node(
                    &format!("sfu-{index}"),
                    "eu",
                    SfuNodeState::Healthy,
                    0,
                    100,
                    10_000,
                ))
                .expect("bounded node");
        }
        assert_eq!(directory.nodes().len(), MAX_SFU_CLUSTER_NODES);
        assert_eq!(
            directory.upsert_node(node(
                "sfu-overflow",
                "eu",
                SfuNodeState::Healthy,
                0,
                100,
                10_000,
            )),
            Err(SfuPlacementError::InvalidNode)
        );

        directory
            .upsert_node(node("sfu-0", "eu", SfuNodeState::Draining, 1, 100, 20_000))
            .expect("existing node refresh remains allowed");
        assert_eq!(
            directory.node(&opaque("sfu-0")).expect("node").state,
            SfuNodeState::Draining
        );
    }

    #[test]
    fn invalid_or_full_nodes_never_become_new_placements() {
        let mut directory = SfuClusterDirectory::default();
        assert_eq!(
            directory.upsert_node(node("bad", "", SfuNodeState::Healthy, 0, 10, 10_000)),
            Err(SfuPlacementError::InvalidNode)
        );
        directory
            .upsert_node(node("full", "eu", SfuNodeState::Healthy, 10, 10, 10_000))
            .expect("full node registration");
        assert_eq!(
            directory.place_session(
                &scope(),
                &call("call-full"),
                &SfuPlacementPolicy::default(),
                100,
            ),
            Err(SfuPlacementError::NoHealthyCapacity)
        );
    }
}

#![forbid(unsafe_code)]

use core::fmt;

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
};
use ucr_protocol::{
    AUDIO_RECEIVE_PERMISSION, AUDIO_SEND_PERMISSION, CanonicalError, GROUP_MEDIA_E2EE_CAPABILITY,
    MAX_CALL_PARTICIPANTS, SFU_MEDIA_CAPABILITY, SfuProtocolError, VIDEO_RECEIVE_PERMISSION,
    VIDEO_SEND_PERMISSION, canonical_capabilities, canonical_sfu_forward_envelope,
    phase29_sfu_capabilities,
};

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
        let (send, receive) = permissions(canonical.frame.header.media_kind);
        self.authorization
            .authorize(&AuthorizationRequest {
                subject: authenticated_source.clone(),
                permission: send.to_owned(),
                resource_scope: context.scope.clone(),
            })
            .map_err(SfuError::Authorization)?;

        let recipients = call
            .participants
            .iter()
            .filter(|participant| {
                participant.principal != authenticated_source.principal
                    && participant.state == CallParticipantState::Accepted
                    && participant.left_revision.is_none()
            })
            .map(|participant| participant.principal.clone())
            .collect::<Vec<_>>();
        if recipients.is_empty() {
            return Err(SfuError::NoRecipients);
        }
        if recipients.len() >= MAX_CALL_PARTICIPANTS {
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

const fn permissions(media_kind: MediaKind) -> (&'static str, &'static str) {
    match media_kind {
        MediaKind::Audio => (AUDIO_SEND_PERMISSION, AUDIO_RECEIVE_PERMISSION),
        MediaKind::Video => (VIDEO_SEND_PERMISSION, VIDEO_RECEIVE_PERMISSION),
    }
}

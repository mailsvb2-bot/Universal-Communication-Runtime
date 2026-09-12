use core::fmt;
use std::collections::HashMap;

use ucr_core::{
    AuthorizationEvaluator, CallStore, DeviceLifecycleStore, DurableStoreError, GroupStore,
    PrincipalIdentityBindingStore,
};
use ucr_crypto::{
    AeadError, Ciphertext, GroupMediaEpochSecret, GroupMediaKeyError, GroupMediaSigningKeyHandle,
    SignatureBytes, SignatureError, TrustedKeyResolutionError, TrustedSigningKeyResolver,
    VerifyingKeyBytes, derive_group_media_traffic_key, verify_group_media_binding_signature,
};
use ucr_model::{
    AuthorizationRequest, CallParticipantState, CallSession, CallSignallingState,
    CapabilityDescriptor, CapabilityMaturity, ConversationKind, DeviceDescriptor, DeviceId,
    EncryptedGroupMediaFrame, GroupMediaE2eeContext, GroupMediaFrameHeader,
    GroupMediaSourceSignature, GroupMemberState, KeyId, KeyPurpose, MediaKind, OpaqueId,
    PrincipalKind, PrincipalRef, ScopedPrincipal,
};
use ucr_protocol::{
    ALGORITHM_VERSION, AUDIO_RECEIVE_PERMISSION, AUDIO_SEND_PERMISSION, CanonicalError,
    CryptoContractError, GROUP_MEDIA_E2EE_CAPABILITY, GROUP_MLS_CAPABILITY,
    GroupMediaE2eeProtocolError, MAX_MEDIA_STREAMS_PER_EPOCH, SIGNATURE_ALGORITHM_ID,
    VIDEO_RECEIVE_PERMISSION, VIDEO_SEND_PERMISSION, canonical_group_media_e2ee_context,
    device_allows_protected_access, group_media_frame_aad, group_media_source_signing_binding,
    validate_encrypted_group_media_frame, validate_public_key_descriptor,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMediaE2eeError {
    Authorization(CanonicalError),
    Store(DurableStoreError),
    Protocol(GroupMediaE2eeProtocolError),
    Crypto(AeadError),
    Key(GroupMediaKeyError),
    CapabilityUnavailable,
    ScopeMismatch,
    DeviceParticipantMismatch,
    PrincipalIdentityBindingUnavailable,
    PrincipalIdentityBindingMismatch,
    DeviceUnavailable,
    DeviceInactive,
    Trust(TrustedKeyResolutionError),
    InvalidTrustedKey(CryptoContractError),
    Signing(SignatureError),
    SigningKeyMismatch,
    SourceSignatureInvalid,
    CallUnavailable,
    CallNotActive,
    GroupCallRequired,
    NegotiationGenerationMismatch,
    NegotiationBindingMismatch,
    GroupUnavailable,
    GroupMismatch,
    GroupCryptoUnavailable,
    GroupCryptoStateMismatch,
    MembershipUnavailable,
    SourceNotAccepted,
    SourceNotMember,
    MediaKindMismatch,
    Replay,
    OutboundSequenceRegression,
    StreamCapacityExceeded,
}

impl From<DurableStoreError> for GroupMediaE2eeError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<GroupMediaE2eeProtocolError> for GroupMediaE2eeError {
    fn from(error: GroupMediaE2eeProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<AeadError> for GroupMediaE2eeError {
    fn from(error: AeadError) -> Self {
        Self::Crypto(error)
    }
}

impl From<GroupMediaKeyError> for GroupMediaE2eeError {
    fn from(error: GroupMediaKeyError) -> Self {
        Self::Key(error)
    }
}

pub trait GroupMediaE2eeCapabilityProvider: fmt::Debug + Send + Sync {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedGroupMediaE2eeCapabilities;

impl GroupMediaE2eeCapabilityProvider for PreparedGroupMediaE2eeCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        vec![CapabilityDescriptor {
            id: GROUP_MEDIA_E2EE_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        }]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GroupStreamCursorKey {
    source: PrincipalRef,
    source_device_id: DeviceId,
    media_kind: MediaKind,
    stream_id: OpaqueId,
}

#[derive(Debug)]
pub struct GroupMediaE2eeRuntime<'a, A, S, C> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
}

impl<'a, A, S, C> GroupMediaE2eeRuntime<'a, A, S, C> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S, capabilities: &'a C) -> Self {
        Self {
            authorization,
            store,
            capabilities,
        }
    }
}

impl<'a, A, S, C> GroupMediaE2eeRuntime<'a, A, S, C>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
    C: GroupMediaE2eeCapabilityProvider,
{
    /// Opens one endpoint group-media epoch from MLS exporter key material.
    ///
    /// The exporter secret remains endpoint-only. Current Group/Call/Device authority is validated
    /// when the session opens and again before every seal/open operation so membership or epoch
    /// changes fail closed instead of silently continuing on stale media keys.
    ///
    /// # Errors
    /// Rejects stale/mismatched Group, Call, Device, crypto epoch or missing Prepared capability.
    pub fn open_session(
        &'a self,
        local: &ScopedPrincipal,
        local_device_id: &DeviceId,
        context: &GroupMediaE2eeContext,
        epoch_secret: GroupMediaEpochSecret,
    ) -> Result<GroupMediaE2eeSession<'a, A, S, C>, GroupMediaE2eeError> {
        require_group_media_capability(self.capabilities)?;
        let context = canonical_group_media_e2ee_context(context)?;
        validate_group_media_e2ee_authority(self.store, local, local_device_id, &context)?;
        Ok(GroupMediaE2eeSession {
            authorization: self.authorization,
            store: self.store,
            capabilities: self.capabilities,
            local: local.clone(),
            local_device_id: local_device_id.clone(),
            context,
            epoch_secret,
            outbound_sequences: HashMap::new(),
            inbound_sequences: HashMap::new(),
        })
    }
}

pub struct GroupMediaE2eeSession<'a, A, S, C> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    local: ScopedPrincipal,
    local_device_id: DeviceId,
    context: GroupMediaE2eeContext,
    epoch_secret: GroupMediaEpochSecret,
    outbound_sequences: HashMap<GroupStreamCursorKey, u64>,
    inbound_sequences: HashMap<GroupStreamCursorKey, u64>,
}

impl<A, S, C> fmt::Debug for GroupMediaE2eeSession<'_, A, S, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupMediaE2eeSession")
            .field("local", &self.local)
            .field("local_device_id", &self.local_device_id)
            .field("context", &self.context)
            .field("epoch_secret", &"<secret>")
            .field("outbound_streams", &self.outbound_sequences.len())
            .field("inbound_streams", &self.inbound_sequences.len())
            .finish()
    }
}

impl<A, S, C> GroupMediaE2eeSession<'_, A, S, C>
where
    A: AuthorizationEvaluator,
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
    C: GroupMediaE2eeCapabilityProvider,
{
    #[must_use]
    pub const fn context(&self) -> &GroupMediaE2eeContext {
        &self.context
    }

    /// Encrypts one local group-media payload for SFU/P2P fan-out.
    ///
    /// # Errors
    /// Fails closed on stale membership/epoch, lost send permission, sequence regression or AEAD
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_payload(
        &mut self,
        media_kind: MediaKind,
        stream_id: &OpaqueId,
        sequence: u64,
        media_timestamp: u64,
        keyframe: bool,
        plaintext: &[u8],
        signing_key_id: &KeyId,
        signer: &impl GroupMediaSigningKeyHandle,
    ) -> Result<EncryptedGroupMediaFrame, GroupMediaE2eeError> {
        require_group_media_capability(self.capabilities)?;
        validate_group_media_e2ee_authority(
            self.store,
            &self.local,
            &self.local_device_id,
            &self.context,
        )?;
        let local_device = require_active_bound_participant_device(
            self.store,
            &self.context.scope,
            &self.local.principal,
            &self.local_device_id,
        )?;
        authorize_media(self.authorization, &self.local, send_permission(media_kind))?;
        let key_id = GroupStreamCursorKey {
            source: self.local.principal.clone(),
            source_device_id: self.local_device_id.clone(),
            media_kind,
            stream_id: stream_id.clone(),
        };
        require_next_outbound_sequence(&self.outbound_sequences, &key_id, sequence)?;
        require_stream_capacity(&self.outbound_sequences, &key_id)?;
        let header = GroupMediaFrameHeader {
            scope: self.context.scope.clone(),
            call_id: self.context.call_id.clone(),
            group_id: self.context.group_id.clone(),
            stream_id: stream_id.clone(),
            source: self.local.principal.clone(),
            source_device_id: self.local_device_id.clone(),
            negotiation_ref: self.context.negotiation_ref.clone(),
            negotiation_generation: self.context.negotiation_generation,
            crypto_epoch: self.context.crypto_epoch,
            crypto_state_ref: self.context.crypto_state_ref.clone(),
            crypto_suite: self.context.crypto_suite,
            media_kind,
            sequence,
            media_timestamp,
            keyframe,
        };
        let traffic_key = derive_group_media_traffic_key(
            &self.epoch_secret,
            &self.context,
            &header.source,
            &header.source_device_id,
            &header.stream_id,
            header.media_kind,
        )?;
        let aad = group_media_frame_aad(&header)?;
        let encrypted = traffic_key.encrypt(plaintext, &aad)?;
        let signing_binding =
            group_media_source_signing_binding(&header, &encrypted.nonce, &encrypted.bytes)?;
        let trusted = self
            .store
            .resolve_active_signing_key(
                &self.context.scope,
                &self.local_device_id,
                Some(&local_device.identity_id),
                signing_key_id,
            )
            .map_err(GroupMediaE2eeError::Trust)?;
        validate_public_key_descriptor(self.context.crypto_suite, &trusted)
            .map_err(GroupMediaE2eeError::InvalidTrustedKey)?;
        if trusted.purpose != KeyPurpose::Signing
            || trusted.public_key.as_slice() != signer.verifying_key().0.as_slice()
        {
            return Err(GroupMediaE2eeError::SigningKeyMismatch);
        }
        let signature = signer
            .sign_group_media_binding(&signing_binding)
            .map_err(GroupMediaE2eeError::Signing)?;
        let frame = EncryptedGroupMediaFrame {
            header,
            nonce: encrypted.nonce,
            ciphertext: encrypted.bytes,
            source_signature: GroupMediaSourceSignature {
                key_id: signing_key_id.clone(),
                algorithm_id: SIGNATURE_ALGORITHM_ID.to_owned(),
                algorithm_version: ALGORITHM_VERSION,
                signature: signature.0.to_vec(),
            },
        };
        validate_encrypted_group_media_frame(&self.context, &frame)?;
        self.outbound_sequences.insert(key_id, sequence);
        Ok(frame)
    }

    /// Authenticates and decrypts one current-epoch frame from another active group-call Device.
    ///
    /// # Errors
    /// Fails closed on stale epoch/membership, lost receive permission, spoofed/non-member source,
    /// replay, or AEAD integrity failure.
    pub fn open_payload(
        &mut self,
        frame: &EncryptedGroupMediaFrame,
    ) -> Result<Vec<u8>, GroupMediaE2eeError> {
        require_group_media_capability(self.capabilities)?;
        let call = validate_group_media_e2ee_authority(
            self.store,
            &self.local,
            &self.local_device_id,
            &self.context,
        )?;
        validate_encrypted_group_media_frame(&self.context, frame)?;
        authorize_media(
            self.authorization,
            &self.local,
            receive_permission(frame.header.media_kind),
        )?;
        if !accepted_participant(&call, &frame.header.source) {
            return Err(GroupMediaE2eeError::SourceNotAccepted);
        }
        let source_membership = self
            .store
            .group_membership_for_active_member(
                &self.local,
                &self.context.scope,
                &self.context.group_id,
                &frame.header.source,
            )?
            .ok_or(GroupMediaE2eeError::SourceNotMember)?;
        if source_membership.state != GroupMemberState::Active {
            return Err(GroupMediaE2eeError::SourceNotMember);
        }
        let source_device = require_active_bound_participant_device(
            self.store,
            &self.context.scope,
            &frame.header.source,
            &frame.header.source_device_id,
        )?;
        verify_source_signature(self.store, &source_device, frame)?;
        let key_id = GroupStreamCursorKey {
            source: frame.header.source.clone(),
            source_device_id: frame.header.source_device_id.clone(),
            media_kind: frame.header.media_kind,
            stream_id: frame.header.stream_id.clone(),
        };
        require_stream_capacity(&self.inbound_sequences, &key_id)?;
        if self
            .inbound_sequences
            .get(&key_id)
            .is_some_and(|last| frame.header.sequence <= *last)
        {
            return Err(GroupMediaE2eeError::Replay);
        }
        let traffic_key = derive_group_media_traffic_key(
            &self.epoch_secret,
            &self.context,
            &frame.header.source,
            &frame.header.source_device_id,
            &frame.header.stream_id,
            frame.header.media_kind,
        )?;
        let aad = group_media_frame_aad(&frame.header)?;
        let plaintext = traffic_key.decrypt(
            &Ciphertext {
                nonce: frame.nonce,
                bytes: frame.ciphertext.clone(),
            },
            &aad,
        )?;
        self.inbound_sequences.insert(key_id, frame.header.sequence);
        Ok(plaintext)
    }
}

/// Validates one encrypted group-media frame as coming from the claimed current source Device.
///
/// This helper decrypts nothing. It re-checks exact Group/Call/Device/Principal→Identity authority,
/// current MLS epoch binding, active source membership and the frame's Ed25519 Device signature.
///
/// # Errors
/// Rejects stale/revoked authority, malformed ciphertext metadata or source-signature forgery.
pub fn validate_group_media_source_frame<S>(
    store: &S,
    context: &GroupMediaE2eeContext,
    frame: &EncryptedGroupMediaFrame,
) -> Result<CallSession, GroupMediaE2eeError>
where
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
{
    let context = canonical_group_media_e2ee_context(context)?;
    validate_encrypted_group_media_frame(&context, frame)?;
    let source = ScopedPrincipal {
        scope: context.scope.clone(),
        principal: frame.header.source.clone(),
    };
    let call = validate_group_media_e2ee_authority(
        store,
        &source,
        &frame.header.source_device_id,
        &context,
    )?;
    let source_device = require_active_bound_participant_device(
        store,
        &context.scope,
        &frame.header.source,
        &frame.header.source_device_id,
    )?;
    verify_source_signature(store, &source_device, frame)?;
    Ok(call)
}

/// Revalidates the canonical Group/Call/Device authority behind one group-media epoch.
///
/// # Errors
/// Rejects stale epoch, removed/inactive Device membership, non-group Call, stale negotiation or
/// cross-scope/mismatched Group state.
pub fn validate_group_media_e2ee_authority<S>(
    store: &S,
    local: &ScopedPrincipal,
    local_device_id: &DeviceId,
    context: &GroupMediaE2eeContext,
) -> Result<CallSession, GroupMediaE2eeError>
where
    S: CallStore
        + GroupStore
        + DeviceLifecycleStore
        + PrincipalIdentityBindingStore
        + TrustedSigningKeyResolver,
{
    let context = canonical_group_media_e2ee_context(context)?;
    if local.scope != context.scope {
        return Err(GroupMediaE2eeError::ScopeMismatch);
    }
    require_active_bound_participant_device(
        store,
        &context.scope,
        &local.principal,
        local_device_id,
    )?;
    let call = store
        .call_for_participant(local, &context.scope, &context.call_id)?
        .ok_or(GroupMediaE2eeError::CallUnavailable)?;
    if !matches!(
        call.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return Err(GroupMediaE2eeError::GroupCallRequired);
    }
    if call.signalling_state != CallSignallingState::Active {
        return Err(GroupMediaE2eeError::CallNotActive);
    }
    if call.media_negotiation_generation != context.negotiation_generation {
        return Err(GroupMediaE2eeError::NegotiationGenerationMismatch);
    }
    if call.media_negotiation_ref.as_ref() != Some(&context.negotiation_ref) {
        return Err(GroupMediaE2eeError::NegotiationBindingMismatch);
    }
    if !accepted_participant(&call, &local.principal) {
        return Err(GroupMediaE2eeError::SourceNotAccepted);
    }
    let group = store
        .group_for_conversation(&context.scope, &call.conversation.conversation_id)?
        .ok_or(GroupMediaE2eeError::GroupUnavailable)?;
    if group.group_id != context.group_id || group.conversation != call.conversation {
        return Err(GroupMediaE2eeError::GroupMismatch);
    }
    if group.crypto_state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY) {
        return Err(GroupMediaE2eeError::GroupCryptoUnavailable);
    }
    if group.crypto_state.epoch != context.crypto_epoch
        || group.crypto_state.state_ref.as_ref() != Some(&context.crypto_state_ref)
    {
        return Err(GroupMediaE2eeError::GroupCryptoStateMismatch);
    }
    let membership = store
        .group_membership_for_active_member(
            local,
            &context.scope,
            &context.group_id,
            &local.principal,
        )?
        .ok_or(GroupMediaE2eeError::MembershipUnavailable)?;
    if membership.state != GroupMemberState::Active {
        return Err(GroupMediaE2eeError::MembershipUnavailable);
    }
    Ok(call)
}

fn require_active_bound_participant_device<S>(
    store: &S,
    scope: &ucr_model::TenantScope,
    participant: &PrincipalRef,
    device_id: &DeviceId,
) -> Result<DeviceDescriptor, GroupMediaE2eeError>
where
    S: DeviceLifecycleStore + PrincipalIdentityBindingStore,
{
    let device = store
        .device(scope, device_id)?
        .ok_or(GroupMediaE2eeError::DeviceUnavailable)?;
    if !device_allows_protected_access(&device) {
        return Err(GroupMediaE2eeError::DeviceInactive);
    }
    if participant.kind == PrincipalKind::Device {
        if participant.principal_id.as_opaque().as_wire_bytes()
            != device_id.as_opaque().as_wire_bytes()
        {
            return Err(GroupMediaE2eeError::DeviceParticipantMismatch);
        }
        return Ok(device);
    }
    let binding = store
        .principal_identity_binding(scope, participant)?
        .ok_or(GroupMediaE2eeError::PrincipalIdentityBindingUnavailable)?;
    if binding.identity_id != device.identity_id {
        return Err(GroupMediaE2eeError::PrincipalIdentityBindingMismatch);
    }
    Ok(device)
}

fn verify_source_signature<S>(
    store: &S,
    source_device: &DeviceDescriptor,
    frame: &EncryptedGroupMediaFrame,
) -> Result<(), GroupMediaE2eeError>
where
    S: TrustedSigningKeyResolver,
{
    let signature = &frame.source_signature;
    let trusted = store
        .resolve_active_signing_key(
            &frame.header.scope,
            &frame.header.source_device_id,
            Some(&source_device.identity_id),
            &signature.key_id,
        )
        .map_err(GroupMediaE2eeError::Trust)?;
    validate_public_key_descriptor(frame.header.crypto_suite, &trusted)
        .map_err(GroupMediaE2eeError::InvalidTrustedKey)?;
    if trusted.purpose != KeyPurpose::Signing
        || signature.algorithm_id != trusted.algorithm_id
        || signature.algorithm_version != trusted.algorithm_version
    {
        return Err(GroupMediaE2eeError::SourceSignatureInvalid);
    }
    let public_key: [u8; 32] = trusted
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| GroupMediaE2eeError::SourceSignatureInvalid)?;
    let signature_bytes: [u8; 64] = signature
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| GroupMediaE2eeError::SourceSignatureInvalid)?;
    let binding =
        group_media_source_signing_binding(&frame.header, &frame.nonce, &frame.ciphertext)?;
    verify_group_media_binding_signature(
        VerifyingKeyBytes(public_key),
        &binding,
        SignatureBytes(signature_bytes),
    )
    .map_err(|_| GroupMediaE2eeError::SourceSignatureInvalid)
}

fn require_group_media_capability<C: GroupMediaE2eeCapabilityProvider>(
    capabilities: &C,
) -> Result<(), GroupMediaE2eeError> {
    if capabilities
        .current_capabilities()
        .iter()
        .any(|capability| {
            capability.id == GROUP_MEDIA_E2EE_CAPABILITY
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
        })
    {
        Ok(())
    } else {
        Err(GroupMediaE2eeError::CapabilityUnavailable)
    }
}

fn authorize_media<A: AuthorizationEvaluator>(
    authorization: &A,
    subject: &ScopedPrincipal,
    permission: &str,
) -> Result<(), GroupMediaE2eeError> {
    authorization
        .authorize(&AuthorizationRequest {
            subject: subject.clone(),
            permission: permission.to_owned(),
            resource_scope: subject.scope.clone(),
        })
        .map_err(GroupMediaE2eeError::Authorization)
}

const fn send_permission(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Audio => AUDIO_SEND_PERMISSION,
        MediaKind::Video => VIDEO_SEND_PERMISSION,
    }
}

const fn receive_permission(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Audio => AUDIO_RECEIVE_PERMISSION,
        MediaKind::Video => VIDEO_RECEIVE_PERMISSION,
    }
}

fn accepted_participant(call: &CallSession, principal: &PrincipalRef) -> bool {
    call.participants.iter().any(|participant| {
        participant.principal == *principal
            && participant.state == CallParticipantState::Accepted
            && participant.left_revision.is_none()
    })
}

fn require_next_outbound_sequence(
    sequences: &HashMap<GroupStreamCursorKey, u64>,
    key: &GroupStreamCursorKey,
    sequence: u64,
) -> Result<(), GroupMediaE2eeError> {
    if sequences.get(key).is_some_and(|last| sequence <= *last) {
        Err(GroupMediaE2eeError::OutboundSequenceRegression)
    } else {
        Ok(())
    }
}

fn require_stream_capacity(
    sequences: &HashMap<GroupStreamCursorKey, u64>,
    key: &GroupStreamCursorKey,
) -> Result<(), GroupMediaE2eeError> {
    if !sequences.contains_key(key) && sequences.len() >= MAX_MEDIA_STREAMS_PER_EPOCH {
        Err(GroupMediaE2eeError::StreamCapacityExceeded)
    } else {
        Ok(())
    }
}

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::HashMap;

use ucr_core::{AuthorizationEvaluator, CallStore, DurableStoreError};
use ucr_crypto::{
    AeadError, AgreementPublicKey, Ciphertext, EstablishedSession, MediaE2eeBindingError,
    bind_media_e2ee_transcript,
};
use ucr_model::{
    AudioStreamDescriptor, AuthorizationRequest, CallId, CallParticipantState, CallSession,
    CallSignallingState, CapabilityDescriptor, CapabilityMaturity, ConversationKind, DeviceId,
    EncodedAudioFrame, EncodedVideoFrame, EncryptedMediaFrame, MediaE2eeContext,
    MediaE2eeFrameHeader, MediaKind, OpaqueId, PrincipalRef, ScopedPrincipal, TenantScope,
    VideoStreamDescriptor,
};
use ucr_protocol::{
    AUDIO_RECEIVE_PERMISSION, AUDIO_SEND_PERMISSION, CanonicalError, MAX_CALL_PARTICIPANTS,
    MAX_MEDIA_STREAMS_PER_EPOCH, MEDIA_E2EE_CAPABILITY, MediaE2eeProtocolError,
    NegotiationResultEnvelope, VIDEO_RECEIVE_PERMISSION, VIDEO_SEND_PERMISSION,
    canonical_capabilities, canonical_media_e2ee_context, canonical_negotiation_result,
    media_e2ee_frame_aad, phase22_media_e2ee_capabilities, require_supported_extensions,
    validate_audio_frame_for_stream, validate_encrypted_media_frame,
    validate_video_frame_for_stream,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaE2eeError {
    Authorization(CanonicalError),
    Store(DurableStoreError),
    Protocol(MediaE2eeProtocolError),
    Crypto(AeadError),
    Binding(MediaE2eeBindingError),
    ScopeMismatch,
    ParticipantMismatch,
    DeviceMismatch,
    CallUnavailable,
    CallNotActive,
    DirectCallRequired,
    NegotiationGenerationMismatch,
    MissingNegotiation,
    NegotiationBindingMismatch,
    NegotiationResolve(CanonicalError),
    NegotiationResultInvalid,
    NegotiatedCapabilityUnavailable,
    NegotiatedParticipantsInvalid,
    NegotiatedParticipantSetMismatch,
    UnsupportedNegotiationExtension,
    CapabilityUnavailable,
    UnauthenticatedPeerSession,
    SessionBindingMismatch,
    DirectionMismatch,
    MediaKindMismatch,
    StreamMismatch,
    CodecFrameInvalid,
    Replay,
    OutboundSequenceRegression,
    StreamCapacityExceeded,
    EpochRotationInvalid,
    EphemeralReuse,
    GroupCryptoUnavailable,
}

impl From<DurableStoreError> for MediaE2eeError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<MediaE2eeProtocolError> for MediaE2eeError {
    fn from(error: MediaE2eeProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<AeadError> for MediaE2eeError {
    fn from(error: AeadError) -> Self {
        Self::Crypto(error)
    }
}

impl From<MediaE2eeBindingError> for MediaE2eeError {
    fn from(error: MediaE2eeBindingError) -> Self {
        Self::Binding(error)
    }
}

pub trait MediaE2eeCapabilityProvider: fmt::Debug + Send + Sync {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedMediaE2eeCapabilities;

impl MediaE2eeCapabilityProvider for PreparedMediaE2eeCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        phase22_media_e2ee_capabilities()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMediaE2eeNegotiation {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub result: NegotiationResultEnvelope,
    pub negotiated_participants: Vec<PrincipalRef>,
}

pub trait MediaE2eeNegotiationResolver: fmt::Debug + Send + Sync {
    /// Resolves the exact canonical media negotiation already referenced by `CallSession`.
    ///
    /// # Errors
    /// Returns a canonical resolver failure; absence never enables plaintext fallback.
    fn resolve_media_e2ee_negotiation(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedMediaE2eeNegotiation>, CanonicalError>;
}

#[derive(Debug)]
pub struct MediaE2eeRuntime<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
}

impl<'a, A, S, C, N> MediaE2eeRuntime<'a, A, S, C, N> {
    #[must_use]
    pub const fn new(
        authorization: &'a A,
        store: &'a S,
        capabilities: &'a C,
        negotiations: &'a N,
    ) -> Self {
        Self {
            authorization,
            store,
            capabilities,
            negotiations,
        }
    }
}

impl<'a, A, S, C, N> MediaE2eeRuntime<'a, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: MediaE2eeCapabilityProvider,
    N: MediaE2eeNegotiationResolver,
{
    /// Opens a direct-call E2EE media key epoch over an already authenticated UCR crypto session.
    ///
    /// # Errors
    /// Fails closed for group calls, stale negotiation, unauthenticated/wrong peer Device, or a
    /// session transcript not bound to the exact media context and X25519 ephemerals.
    #[allow(clippy::too_many_arguments)]
    pub fn open_direct_session(
        &'a self,
        local: &ScopedPrincipal,
        local_device_id: &DeviceId,
        context: &MediaE2eeContext,
        established: EstablishedSession,
        initiator_ephemeral: AgreementPublicKey,
        responder_ephemeral: AgreementPublicKey,
    ) -> Result<MediaE2eeSession<'a, A, S, C, N>, MediaE2eeError> {
        let context = canonical_media_e2ee_context(context)?;
        let role = direct_role(local, local_device_id, &context)?;
        require_e2ee_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            local,
            &context,
        )?;
        let peer_device = role.peer_device(&context);
        if established.authenticated_peer_device_id() != Some(peer_device) {
            return Err(MediaE2eeError::UnauthenticatedPeerSession);
        }
        let binding =
            bind_media_e2ee_transcript(&context, initiator_ephemeral, responder_ephemeral)?;
        if established.transcript_binding() != &binding {
            return Err(MediaE2eeError::SessionBindingMismatch);
        }
        Ok(MediaE2eeSession {
            authorization: self.authorization,
            store: self.store,
            capabilities: self.capabilities,
            negotiations: self.negotiations,
            local: local.clone(),
            local_device_id: local_device_id.clone(),
            context,
            established,
            initiator_ephemeral,
            responder_ephemeral,
            outbound_sequences: HashMap::new(),
            inbound_sequences: HashMap::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectRole {
    Initiator,
    Responder,
}

impl DirectRole {
    fn peer(self, context: &MediaE2eeContext) -> &PrincipalRef {
        match self {
            Self::Initiator => &context.responder,
            Self::Responder => &context.initiator,
        }
    }

    fn peer_device(self, context: &MediaE2eeContext) -> &DeviceId {
        match self {
            Self::Initiator => &context.responder_device_id,
            Self::Responder => &context.initiator_device_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StreamCursorKey {
    media_kind: MediaKind,
    stream_id: OpaqueId,
}

pub struct MediaE2eeSession<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
    local: ScopedPrincipal,
    local_device_id: DeviceId,
    context: MediaE2eeContext,
    established: EstablishedSession,
    initiator_ephemeral: AgreementPublicKey,
    responder_ephemeral: AgreementPublicKey,
    outbound_sequences: HashMap<StreamCursorKey, u64>,
    inbound_sequences: HashMap<StreamCursorKey, u64>,
}

impl<A, S, C, N> fmt::Debug for MediaE2eeSession<'_, A, S, C, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaE2eeSession")
            .field("local", &self.local)
            .field("local_device_id", &self.local_device_id)
            .field("context", &self.context)
            .field("established", &"<authenticated-media-session>")
            .field("outbound_stream_count", &self.outbound_sequences.len())
            .field("inbound_stream_count", &self.inbound_sequences.len())
            .finish_non_exhaustive()
    }
}

impl<A, S, C, N> MediaE2eeSession<'_, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: MediaE2eeCapabilityProvider,
    N: MediaE2eeNegotiationResolver,
{
    #[must_use]
    pub const fn context(&self) -> &MediaE2eeContext {
        &self.context
    }

    /// Encrypts one already-canonical Opus frame. No plaintext fallback exists.
    ///
    /// # Errors
    /// Rejects lost authority, wrong direction/context, sequence regression, or AEAD failure.
    pub fn seal_audio(
        &mut self,
        descriptor: &AudioStreamDescriptor,
        frame: &EncodedAudioFrame,
    ) -> Result<EncryptedMediaFrame, MediaE2eeError> {
        validate_audio_frame_for_stream(descriptor, frame)
            .map_err(|_| MediaE2eeError::CodecFrameInvalid)?;
        self.require_descriptor_binding(
            &descriptor.scope,
            &descriptor.call_id,
            descriptor.stream_id.as_opaque(),
            &descriptor.source,
            &descriptor.negotiation_ref,
            descriptor.negotiation_generation,
            AUDIO_SEND_PERMISSION,
            true,
        )?;
        self.seal_payload(
            MediaKind::Audio,
            descriptor.stream_id.as_opaque(),
            frame.sequence,
            frame.media_timestamp_samples,
            false,
            &frame.payload,
        )
    }

    /// Authenticates/decrypts one audio envelope back to the original encoded Opus frame.
    ///
    /// # Errors
    /// Rejects tampering before replay-state mutation and never returns partial plaintext.
    pub fn open_audio(
        &mut self,
        descriptor: &AudioStreamDescriptor,
        frame: &EncryptedMediaFrame,
    ) -> Result<EncodedAudioFrame, MediaE2eeError> {
        self.require_descriptor_binding(
            &descriptor.scope,
            &descriptor.call_id,
            descriptor.stream_id.as_opaque(),
            &descriptor.source,
            &descriptor.negotiation_ref,
            descriptor.negotiation_generation,
            AUDIO_RECEIVE_PERMISSION,
            false,
        )?;
        let plaintext =
            self.open_payload(MediaKind::Audio, descriptor.stream_id.as_opaque(), frame)?;
        let output = EncodedAudioFrame {
            scope: descriptor.scope.clone(),
            call_id: descriptor.call_id.clone(),
            stream_id: descriptor.stream_id.clone(),
            source: descriptor.source.clone(),
            negotiation_ref: descriptor.negotiation_ref.clone(),
            negotiation_generation: descriptor.negotiation_generation,
            sequence: frame.header.sequence,
            media_timestamp_samples: frame.header.media_timestamp,
            payload: plaintext,
        };
        validate_audio_frame_for_stream(descriptor, &output)
            .map_err(|_| MediaE2eeError::CodecFrameInvalid)?;
        Ok(output)
    }

    /// Encrypts one already-canonical H.264 frame.
    ///
    /// # Errors
    /// Rejects lost authority, wrong direction/context, sequence regression, or AEAD failure.
    pub fn seal_video(
        &mut self,
        descriptor: &VideoStreamDescriptor,
        frame: &EncodedVideoFrame,
    ) -> Result<EncryptedMediaFrame, MediaE2eeError> {
        validate_video_frame_for_stream(descriptor, frame)
            .map_err(|_| MediaE2eeError::CodecFrameInvalid)?;
        self.require_descriptor_binding(
            &descriptor.scope,
            &descriptor.call_id,
            descriptor.stream_id.as_opaque(),
            &descriptor.source,
            &descriptor.negotiation_ref,
            descriptor.negotiation_generation,
            VIDEO_SEND_PERMISSION,
            true,
        )?;
        self.seal_payload(
            MediaKind::Video,
            descriptor.stream_id.as_opaque(),
            frame.sequence,
            frame.media_timestamp_us,
            frame.keyframe,
            &frame.payload,
        )
    }

    /// Authenticates/decrypts one video envelope back to the original encoded H.264 frame.
    ///
    /// # Errors
    /// Rejects tampering before replay-state mutation and never returns partial plaintext.
    pub fn open_video(
        &mut self,
        descriptor: &VideoStreamDescriptor,
        frame: &EncryptedMediaFrame,
    ) -> Result<EncodedVideoFrame, MediaE2eeError> {
        self.require_descriptor_binding(
            &descriptor.scope,
            &descriptor.call_id,
            descriptor.stream_id.as_opaque(),
            &descriptor.source,
            &descriptor.negotiation_ref,
            descriptor.negotiation_generation,
            VIDEO_RECEIVE_PERMISSION,
            false,
        )?;
        let plaintext =
            self.open_payload(MediaKind::Video, descriptor.stream_id.as_opaque(), frame)?;
        let output = EncodedVideoFrame {
            scope: descriptor.scope.clone(),
            call_id: descriptor.call_id.clone(),
            stream_id: descriptor.stream_id.clone(),
            source: descriptor.source.clone(),
            negotiation_ref: descriptor.negotiation_ref.clone(),
            negotiation_generation: descriptor.negotiation_generation,
            sequence: frame.header.sequence,
            media_timestamp_us: frame.header.media_timestamp,
            keyframe: frame.header.keyframe,
            payload: plaintext,
        };
        validate_video_frame_for_stream(descriptor, &output)
            .map_err(|_| MediaE2eeError::CodecFrameInvalid)?;
        Ok(output)
    }

    /// Replaces the live traffic keys with the next explicit key epoch.
    ///
    /// # Errors
    /// Requires exact context continuity, epoch+1, fresh role-specific X25519 ephemerals, current
    /// Call/negotiation authority, and a newly authenticated peer session bound to that context.
    pub fn rotate(
        &mut self,
        next_context: &MediaE2eeContext,
        next_session: EstablishedSession,
        initiator_ephemeral: AgreementPublicKey,
        responder_ephemeral: AgreementPublicKey,
    ) -> Result<(), MediaE2eeError> {
        let next_context = canonical_media_e2ee_context(next_context)?;
        if !same_context_except_epoch(&self.context, &next_context)
            || next_context.key_epoch
                != self
                    .context
                    .key_epoch
                    .checked_add(1)
                    .ok_or(MediaE2eeError::EpochRotationInvalid)?
        {
            return Err(MediaE2eeError::EpochRotationInvalid);
        }
        if initiator_ephemeral == self.initiator_ephemeral
            || responder_ephemeral == self.responder_ephemeral
        {
            return Err(MediaE2eeError::EphemeralReuse);
        }
        require_e2ee_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            &self.local,
            &next_context,
        )?;
        let role = direct_role(&self.local, &self.local_device_id, &next_context)?;
        if next_session.authenticated_peer_device_id() != Some(role.peer_device(&next_context)) {
            return Err(MediaE2eeError::UnauthenticatedPeerSession);
        }
        let binding =
            bind_media_e2ee_transcript(&next_context, initiator_ephemeral, responder_ephemeral)?;
        if next_session.transcript_binding() != &binding {
            return Err(MediaE2eeError::SessionBindingMismatch);
        }
        self.context = next_context;
        self.established = next_session;
        self.initiator_ephemeral = initiator_ephemeral;
        self.responder_ephemeral = responder_ephemeral;
        self.outbound_sequences.clear();
        self.inbound_sequences.clear();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn require_descriptor_binding(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        stream_id: &OpaqueId,
        source: &PrincipalRef,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
        permission: &str,
        outbound: bool,
    ) -> Result<(), MediaE2eeError> {
        if scope != &self.context.scope || call_id != &self.context.call_id {
            return Err(MediaE2eeError::ScopeMismatch);
        }
        if negotiation_ref != &self.context.negotiation_ref
            || negotiation_generation != self.context.negotiation_generation
        {
            return Err(MediaE2eeError::NegotiationBindingMismatch);
        }
        let role = direct_role(&self.local, &self.local_device_id, &self.context)?;
        let expected_source = if outbound {
            &self.local.principal
        } else {
            role.peer(&self.context)
        };
        if source != expected_source {
            return Err(MediaE2eeError::DirectionMismatch);
        }
        if stream_id.as_wire_bytes().is_empty() {
            return Err(MediaE2eeError::StreamMismatch);
        }
        require_e2ee_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            &self.local,
            &self.context,
        )?;
        self.authorization
            .authorize(&AuthorizationRequest {
                subject: self.local.clone(),
                permission: permission.to_owned(),
                resource_scope: self.context.scope.clone(),
            })
            .map_err(MediaE2eeError::Authorization)
    }

    fn seal_payload(
        &mut self,
        media_kind: MediaKind,
        stream_id: &OpaqueId,
        sequence: u64,
        media_timestamp: u64,
        keyframe: bool,
        plaintext: &[u8],
    ) -> Result<EncryptedMediaFrame, MediaE2eeError> {
        let key = StreamCursorKey {
            media_kind,
            stream_id: stream_id.clone(),
        };
        require_next_outbound_sequence(&self.outbound_sequences, &key, sequence)?;
        require_stream_capacity(&self.outbound_sequences, &key)?;
        let role = direct_role(&self.local, &self.local_device_id, &self.context)?;
        let header = MediaE2eeFrameHeader {
            scope: self.context.scope.clone(),
            call_id: self.context.call_id.clone(),
            stream_id: stream_id.clone(),
            source: self.local.principal.clone(),
            recipient: role.peer(&self.context).clone(),
            negotiation_ref: self.context.negotiation_ref.clone(),
            negotiation_generation: self.context.negotiation_generation,
            key_epoch: self.context.key_epoch,
            crypto_suite: self.context.crypto_suite,
            session_binding: *self.established.transcript_binding().as_bytes(),
            media_kind,
            sequence,
            media_timestamp,
            keyframe,
        };
        let aad = media_e2ee_frame_aad(&header)?;
        let encrypted = self.established.encrypt_outbound(plaintext, &aad)?;
        let output = EncryptedMediaFrame {
            header,
            nonce: encrypted.nonce,
            ciphertext: encrypted.bytes,
        };
        validate_encrypted_media_frame(&self.context, &output)?;
        self.outbound_sequences.insert(key, sequence);
        Ok(output)
    }

    fn open_payload(
        &mut self,
        media_kind: MediaKind,
        stream_id: &OpaqueId,
        frame: &EncryptedMediaFrame,
    ) -> Result<Vec<u8>, MediaE2eeError> {
        validate_encrypted_media_frame(&self.context, frame)?;
        if frame.header.media_kind != media_kind {
            return Err(MediaE2eeError::MediaKindMismatch);
        }
        if &frame.header.stream_id != stream_id {
            return Err(MediaE2eeError::StreamMismatch);
        }
        let role = direct_role(&self.local, &self.local_device_id, &self.context)?;
        if frame.header.source != *role.peer(&self.context)
            || frame.header.recipient != self.local.principal
        {
            return Err(MediaE2eeError::DirectionMismatch);
        }
        if frame.header.session_binding != *self.established.transcript_binding().as_bytes() {
            return Err(MediaE2eeError::SessionBindingMismatch);
        }
        let aad = media_e2ee_frame_aad(&frame.header)?;
        let plaintext = self.established.decrypt_inbound(
            &Ciphertext {
                nonce: frame.nonce,
                bytes: frame.ciphertext.clone(),
            },
            &aad,
        )?;
        let key = StreamCursorKey {
            media_kind,
            stream_id: stream_id.clone(),
        };
        require_stream_capacity(&self.inbound_sequences, &key)?;
        if self
            .inbound_sequences
            .get(&key)
            .is_some_and(|last| frame.header.sequence <= *last)
        {
            return Err(MediaE2eeError::Replay);
        }
        self.inbound_sequences.insert(key, frame.header.sequence);
        Ok(plaintext)
    }
}

fn direct_role(
    local: &ScopedPrincipal,
    local_device_id: &DeviceId,
    context: &MediaE2eeContext,
) -> Result<DirectRole, MediaE2eeError> {
    if local.scope != context.scope {
        return Err(MediaE2eeError::ScopeMismatch);
    }
    if local.principal == context.initiator && local_device_id == &context.initiator_device_id {
        Ok(DirectRole::Initiator)
    } else if local.principal == context.responder
        && local_device_id == &context.responder_device_id
    {
        Ok(DirectRole::Responder)
    } else if local.principal == context.initiator || local.principal == context.responder {
        Err(MediaE2eeError::DeviceMismatch)
    } else {
        Err(MediaE2eeError::ParticipantMismatch)
    }
}

fn require_e2ee_authority<A, S, C, N>(
    _authorization: &A,
    store: &S,
    capabilities: &C,
    negotiations: &N,
    local: &ScopedPrincipal,
    context: &MediaE2eeContext,
) -> Result<CallSession, MediaE2eeError>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: MediaE2eeCapabilityProvider,
    N: MediaE2eeNegotiationResolver,
{
    let capabilities = canonical_capabilities(&capabilities.current_capabilities())
        .map_err(|_| MediaE2eeError::CapabilityUnavailable)?;
    if !capability_is_usable(&capabilities, MEDIA_E2EE_CAPABILITY) {
        return Err(MediaE2eeError::CapabilityUnavailable);
    }
    let call = store
        .call_for_participant(local, &context.scope, &context.call_id)?
        .ok_or(MediaE2eeError::CallUnavailable)?;
    if call.conversation.kind != ConversationKind::Direct {
        return Err(MediaE2eeError::GroupCryptoUnavailable);
    }
    if call.signalling_state != CallSignallingState::Active {
        return Err(MediaE2eeError::CallNotActive);
    }
    if call.media_negotiation_generation != context.negotiation_generation {
        return Err(MediaE2eeError::NegotiationGenerationMismatch);
    }
    if call.media_negotiation_ref.as_ref() != Some(&context.negotiation_ref) {
        return Err(MediaE2eeError::NegotiationBindingMismatch);
    }
    require_exact_call_participants(&call, context)?;
    require_negotiated_e2ee(negotiations, &call, context)?;
    Ok(call)
}

fn require_negotiated_e2ee<N: MediaE2eeNegotiationResolver>(
    resolver: &N,
    call: &CallSession,
    context: &MediaE2eeContext,
) -> Result<(), MediaE2eeError> {
    let binding = resolver
        .resolve_media_e2ee_negotiation(
            &context.scope,
            &context.call_id,
            &context.negotiation_ref,
            context.negotiation_generation,
        )
        .map_err(MediaE2eeError::NegotiationResolve)?
        .ok_or(MediaE2eeError::MissingNegotiation)?;
    if binding.scope != context.scope
        || binding.call_id != context.call_id
        || binding.negotiation_ref != context.negotiation_ref
        || binding.negotiation_generation != context.negotiation_generation
    {
        return Err(MediaE2eeError::NegotiationBindingMismatch);
    }
    let result = canonical_negotiation_result(&binding.result)
        .map_err(|_| MediaE2eeError::NegotiationResultInvalid)?;
    require_supported_extensions(&result.extensions, core::iter::empty::<&str>())
        .map_err(|_| MediaE2eeError::UnsupportedNegotiationExtension)?;
    for capability in &result.capabilities {
        require_supported_extensions(&capability.extensions, core::iter::empty::<&str>())
            .map_err(|_| MediaE2eeError::UnsupportedNegotiationExtension)?;
    }
    if result.crypto_suite != context.crypto_suite
        || !capability_is_usable(&result.capabilities, MEDIA_E2EE_CAPABILITY)
    {
        return Err(MediaE2eeError::NegotiatedCapabilityUnavailable);
    }
    require_exact_negotiated_participants(call, &binding.negotiated_participants)
}

fn require_exact_call_participants(
    call: &CallSession,
    context: &MediaE2eeContext,
) -> Result<(), MediaE2eeError> {
    let accepted = call
        .participants
        .iter()
        .filter(|participant| {
            participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        })
        .map(|participant| &participant.principal)
        .collect::<Vec<_>>();
    if accepted.len() != 2
        || !accepted.contains(&&context.initiator)
        || !accepted.contains(&&context.responder)
    {
        return Err(MediaE2eeError::NegotiatedParticipantSetMismatch);
    }
    Ok(())
}

fn require_exact_negotiated_participants(
    call: &CallSession,
    negotiated: &[PrincipalRef],
) -> Result<(), MediaE2eeError> {
    if negotiated.is_empty() || negotiated.len() > MAX_CALL_PARTICIPANTS {
        return Err(MediaE2eeError::NegotiatedParticipantsInvalid);
    }
    let mut unique = std::collections::HashSet::with_capacity(negotiated.len());
    if negotiated.iter().any(|principal| !unique.insert(principal)) {
        return Err(MediaE2eeError::NegotiatedParticipantsInvalid);
    }
    let accepted = call
        .participants
        .iter()
        .filter(|participant| {
            participant.state == CallParticipantState::Accepted
                && participant.left_revision.is_none()
        })
        .map(|participant| &participant.principal)
        .collect::<Vec<_>>();
    if accepted.len() != negotiated.len()
        || accepted.iter().any(|principal| !unique.contains(principal))
    {
        return Err(MediaE2eeError::NegotiatedParticipantSetMismatch);
    }
    Ok(())
}

fn capability_is_usable(capabilities: &[CapabilityDescriptor], required: &str) -> bool {
    capabilities.iter().any(|capability| {
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
    })
}

fn require_next_outbound_sequence(
    sequences: &HashMap<StreamCursorKey, u64>,
    key: &StreamCursorKey,
    sequence: u64,
) -> Result<(), MediaE2eeError> {
    if sequences.get(key).is_some_and(|last| sequence <= *last) {
        Err(MediaE2eeError::OutboundSequenceRegression)
    } else {
        Ok(())
    }
}

fn require_stream_capacity(
    sequences: &HashMap<StreamCursorKey, u64>,
    key: &StreamCursorKey,
) -> Result<(), MediaE2eeError> {
    if !sequences.contains_key(key) && sequences.len() >= MAX_MEDIA_STREAMS_PER_EPOCH {
        Err(MediaE2eeError::StreamCapacityExceeded)
    } else {
        Ok(())
    }
}

fn same_context_except_epoch(left: &MediaE2eeContext, right: &MediaE2eeContext) -> bool {
    left.scope == right.scope
        && left.call_id == right.call_id
        && left.initiator == right.initiator
        && left.responder == right.responder
        && left.initiator_device_id == right.initiator_device_id
        && left.responder_device_id == right.responder_device_id
        && left.negotiation_ref == right.negotiation_ref
        && left.negotiation_generation == right.negotiation_generation
        && left.crypto_suite == right.crypto_suite
}

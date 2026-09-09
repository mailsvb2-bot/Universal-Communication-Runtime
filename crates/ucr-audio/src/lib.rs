#![forbid(unsafe_code)]

use core::fmt;

use opus::{Application, Channels, Decoder, Encoder};
use ucr_core::{AuthorizationEvaluator, CallStore, DurableStoreError};
use ucr_model::{
    AudioChannelLayout, AudioCodecConfig, AudioStreamDescriptor, AuthorizationRequest, CallId,
    CallParticipantState, CallSession, CallSignallingState, CapabilityDescriptor,
    CapabilityMaturity, EncodedAudioFrame, OpaqueId, ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    AUDIO_MEDIA_CAPABILITY, AUDIO_RECEIVE_PERMISSION, AUDIO_SEND_PERMISSION, AudioProtocolError,
    CanonicalError, MAX_ENCODED_AUDIO_FRAME_BYTES, NegotiationResultEnvelope,
    audio_samples_per_channel, canonical_audio_codec_config, canonical_audio_stream_descriptor,
    canonical_capabilities, canonical_negotiation_result, phase20_audio_capabilities,
    require_supported_extensions, validate_audio_frame_for_stream,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioError {
    Authorization(ucr_protocol::CanonicalError),
    Store(DurableStoreError),
    Protocol(AudioProtocolError),
    ScopeMismatch,
    SourceMismatch,
    CallUnavailable,
    CallNotActive,
    SubjectNotAccepted,
    SourceNotAccepted,
    NegotiationGenerationMismatch,
    MissingNegotiation,
    NegotiationBindingMismatch,
    NegotiationResolve(CanonicalError),
    NegotiationResultInvalid,
    NegotiatedCapabilityUnavailable,
    NegotiatedCodecMismatch,
    UnsupportedNegotiationExtension,
    CapabilityUnavailable,
    PcmFrameLength,
    Codec,
    DuplicateOrOutOfOrder,
    UnexpectedPacketDuration,
    SequenceOverflow,
    TimestampOverflow,
}

impl From<DurableStoreError> for AudioError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AudioProtocolError> for AudioError {
    fn from(error: AudioProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Runtime view of the already-canonical Capability model. Implementations may reflect OS
/// permission/device changes without inventing a second capability vocabulary.
pub trait AudioCapabilityProvider: fmt::Debug + Send + Sync {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;
}

/// Reference provider for an environment where the Phase-20 libopus capability is currently usable.
#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedAudioCapabilities;

impl AudioCapabilityProvider for PreparedAudioCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        phase20_audio_capabilities()
    }
}

/// Read-only resolution of the canonical media-negotiation result referenced by one Call generation.
///
/// The resolver does not negotiate capabilities and owns no parallel Call/media state. It only
/// resolves the exact opaque reference already committed into `CallSession`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAudioNegotiation {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub result: NegotiationResultEnvelope,
    pub selected_codec: AudioCodecConfig,
}

pub trait AudioNegotiationResolver: fmt::Debug + Send + Sync {
    /// Resolves one exact canonical media-negotiation result. Absence fails Audio closed.
    ///
    /// # Errors
    /// Returns a canonical resolver failure without authorizing fallback or renegotiation.
    fn resolve_audio_negotiation(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedAudioNegotiation>, CanonicalError>;
}

/// Prepared Phase-20 Audio entry point over the one canonical Call and authorization owners.
///
/// It owns no durable media table, route graph, peer identity, E2EE state, video state, or adaptive
/// policy. Sender/receiver objects re-check current Call authority for every realtime frame.
#[derive(Debug)]
pub struct AudioRuntime<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
}

impl<'a, A, S, C, N> AudioRuntime<'a, A, S, C, N> {
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

impl<'a, A, S, C, N> AudioRuntime<'a, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
    N: AudioNegotiationResolver,
{
    /// Opens a stateful Opus encoder for the authenticated source participant.
    ///
    /// # Errors
    /// Rejects cross-scope, unauthorized, inactive, stale-negotiation, non-participant, invalid
    /// codec, or codec-construction state.
    pub fn open_sender(
        &self,
        subject: &ScopedPrincipal,
        descriptor: &AudioStreamDescriptor,
    ) -> Result<OpusAudioSender<'a, A, S, C, N>, AudioError> {
        let descriptor = canonical_audio_stream_descriptor(descriptor)?;
        if descriptor.source != subject.principal {
            return Err(AudioError::SourceMismatch);
        }
        require_audio_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            subject,
            &descriptor,
            AUDIO_SEND_PERMISSION,
        )?;
        let encoder = Encoder::new(
            descriptor.codec.sample_rate_hz,
            opus_channels(descriptor.codec.channel_layout),
            Application::Voip,
        )
        .map_err(|_| AudioError::Codec)?;
        Ok(OpusAudioSender {
            authorization: self.authorization,
            store: self.store,
            capabilities: self.capabilities,
            negotiations: self.negotiations,
            subject: subject.clone(),
            descriptor,
            encoder,
            next_sequence: 0,
            next_timestamp_samples: 0,
        })
    }

    /// Opens a stateful Opus decoder for one exact source stream visible to the authenticated
    /// current Call participant.
    ///
    /// # Errors
    /// Rejects cross-scope, unauthorized, inactive, stale-negotiation, invalid-source, invalid
    /// codec, or codec-construction state.
    pub fn open_receiver(
        &self,
        subject: &ScopedPrincipal,
        descriptor: &AudioStreamDescriptor,
    ) -> Result<OpusAudioReceiver<'a, A, S, C, N>, AudioError> {
        let descriptor = canonical_audio_stream_descriptor(descriptor)?;
        require_audio_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            subject,
            &descriptor,
            AUDIO_RECEIVE_PERMISSION,
        )?;
        let decoder = Decoder::new(
            descriptor.codec.sample_rate_hz,
            opus_channels(descriptor.codec.channel_layout),
        )
        .map_err(|_| AudioError::Codec)?;
        Ok(OpusAudioReceiver {
            authorization: self.authorization,
            store: self.store,
            capabilities: self.capabilities,
            negotiations: self.negotiations,
            subject: subject.clone(),
            descriptor,
            decoder,
            last_sequence: None,
        })
    }
}

pub struct OpusAudioSender<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
    subject: ScopedPrincipal,
    descriptor: AudioStreamDescriptor,
    encoder: Encoder,
    next_sequence: u64,
    next_timestamp_samples: u64,
}

impl<A, S, C, N> fmt::Debug for OpusAudioSender<'_, A, S, C, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpusAudioSender")
            .field("subject", &self.subject)
            .field("descriptor", &self.descriptor)
            .field("next_sequence", &self.next_sequence)
            .field("next_timestamp_samples", &self.next_timestamp_samples)
            .finish_non_exhaustive()
    }
}

impl<A, S, C, N> OpusAudioSender<'_, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
    N: AudioNegotiationResolver,
{
    #[must_use]
    pub const fn descriptor(&self) -> &AudioStreamDescriptor {
        &self.descriptor
    }

    /// Encodes one exact PCM frame as Opus after re-checking current Call/media authority.
    ///
    /// PCM is interleaved signed 16-bit audio using the descriptor's channel layout. Phase 20
    /// deliberately emits encoded media only; it does not claim encryption or transport delivery.
    ///
    /// # Errors
    /// Rejects authority loss, invalid PCM frame length, counter overflow, or codec failure.
    pub fn encode_pcm(&mut self, pcm: &[i16]) -> Result<EncodedAudioFrame, AudioError> {
        require_audio_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            &self.subject,
            &self.descriptor,
            AUDIO_SEND_PERMISSION,
        )?;
        let samples_per_channel = audio_samples_per_channel(&self.descriptor.codec)?;
        let expected_samples = samples_per_channel
            .checked_mul(self.descriptor.codec.channel_layout.channels())
            .ok_or(AudioError::PcmFrameLength)?;
        if pcm.len() != expected_samples {
            return Err(AudioError::PcmFrameLength);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(AudioError::SequenceOverflow)?;
        let next_timestamp = self
            .next_timestamp_samples
            .checked_add(
                u64::try_from(samples_per_channel).map_err(|_| AudioError::TimestampOverflow)?,
            )
            .ok_or(AudioError::TimestampOverflow)?;
        let payload = self
            .encoder
            .encode_vec(pcm, MAX_ENCODED_AUDIO_FRAME_BYTES)
            .map_err(|_| AudioError::Codec)?;
        let frame = EncodedAudioFrame {
            scope: self.descriptor.scope.clone(),
            call_id: self.descriptor.call_id.clone(),
            stream_id: self.descriptor.stream_id.clone(),
            source: self.descriptor.source.clone(),
            negotiation_ref: self.descriptor.negotiation_ref.clone(),
            negotiation_generation: self.descriptor.negotiation_generation,
            sequence: self.next_sequence,
            media_timestamp_samples: self.next_timestamp_samples,
            payload,
        };
        validate_audio_frame_for_stream(&self.descriptor, &frame)?;
        self.next_sequence = next_sequence;
        self.next_timestamp_samples = next_timestamp;
        Ok(frame)
    }
}

pub struct OpusAudioReceiver<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
    subject: ScopedPrincipal,
    descriptor: AudioStreamDescriptor,
    decoder: Decoder,
    last_sequence: Option<u64>,
}

impl<A, S, C, N> fmt::Debug for OpusAudioReceiver<'_, A, S, C, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpusAudioReceiver")
            .field("subject", &self.subject)
            .field("descriptor", &self.descriptor)
            .field("last_sequence", &self.last_sequence)
            .finish_non_exhaustive()
    }
}

impl<A, S, C, N> OpusAudioReceiver<'_, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
    N: AudioNegotiationResolver,
{
    #[must_use]
    pub const fn descriptor(&self) -> &AudioStreamDescriptor {
        &self.descriptor
    }

    /// Decodes one bound Opus frame after re-checking recipient/source Call authority.
    ///
    /// Duplicate or non-increasing frame sequences are discarded. This is realtime duplicate
    /// suppression, not the cryptographic replay protection owned by the later E2EE Media phase.
    ///
    /// # Errors
    /// Rejects authority loss, cross-stream data, non-increasing sequence, unexpected packet
    /// duration, or codec failure.
    pub fn decode_frame(&mut self, frame: &EncodedAudioFrame) -> Result<Vec<i16>, AudioError> {
        require_audio_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            &self.subject,
            &self.descriptor,
            AUDIO_RECEIVE_PERMISSION,
        )?;
        validate_audio_frame_for_stream(&self.descriptor, frame)?;
        if self
            .last_sequence
            .is_some_and(|last_sequence| frame.sequence <= last_sequence)
        {
            return Err(AudioError::DuplicateOrOutOfOrder);
        }
        let samples_per_channel = audio_samples_per_channel(&self.descriptor.codec)?;
        let packet_samples = self
            .decoder
            .get_nb_samples(&frame.payload)
            .map_err(|_| AudioError::Codec)?;
        if packet_samples != samples_per_channel {
            return Err(AudioError::UnexpectedPacketDuration);
        }
        let output_samples = samples_per_channel
            .checked_mul(self.descriptor.codec.channel_layout.channels())
            .ok_or(AudioError::UnexpectedPacketDuration)?;
        let mut pcm = vec![0_i16; output_samples];
        let decoded_samples = self
            .decoder
            .decode(&frame.payload, &mut pcm, false)
            .map_err(|_| AudioError::Codec)?;
        if decoded_samples != samples_per_channel {
            return Err(AudioError::UnexpectedPacketDuration);
        }
        self.last_sequence = Some(frame.sequence);
        Ok(pcm)
    }
}

fn require_audio_authority<A, S, C, N>(
    authorization: &A,
    store: &S,
    capabilities: &C,
    negotiations: &N,
    subject: &ScopedPrincipal,
    descriptor: &AudioStreamDescriptor,
    permission: &str,
) -> Result<CallSession, AudioError>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
    N: AudioNegotiationResolver,
{
    if subject.scope != descriptor.scope {
        return Err(AudioError::ScopeMismatch);
    }
    require_current_capabilities(capabilities, descriptor)?;
    authorization
        .authorize(&AuthorizationRequest {
            subject: subject.clone(),
            permission: permission.to_owned(),
            resource_scope: descriptor.scope.clone(),
        })
        .map_err(AudioError::Authorization)?;
    let call = store
        .call_for_participant(subject, &descriptor.scope, &descriptor.call_id)?
        .ok_or(AudioError::CallUnavailable)?;
    if call.signalling_state != CallSignallingState::Active {
        return Err(AudioError::CallNotActive);
    }
    if call.media_negotiation_generation != descriptor.negotiation_generation {
        return Err(AudioError::NegotiationGenerationMismatch);
    }
    let Some(call_negotiation_ref) = call.media_negotiation_ref.as_ref() else {
        return Err(AudioError::MissingNegotiation);
    };
    if call_negotiation_ref != &descriptor.negotiation_ref {
        return Err(AudioError::NegotiationBindingMismatch);
    }
    if !accepted_participant(&call, &subject.principal) {
        return Err(AudioError::SubjectNotAccepted);
    }
    if !accepted_participant(&call, &descriptor.source) {
        return Err(AudioError::SourceNotAccepted);
    }
    require_negotiated_audio(negotiations, descriptor)?;
    Ok(call)
}

fn require_negotiated_audio<N: AudioNegotiationResolver>(
    negotiation_resolver: &N,
    descriptor: &AudioStreamDescriptor,
) -> Result<(), AudioError> {
    let binding = negotiation_resolver
        .resolve_audio_negotiation(
            &descriptor.scope,
            &descriptor.call_id,
            &descriptor.negotiation_ref,
            descriptor.negotiation_generation,
        )
        .map_err(AudioError::NegotiationResolve)?
        .ok_or(AudioError::MissingNegotiation)?;
    if binding.scope != descriptor.scope
        || binding.call_id != descriptor.call_id
        || binding.negotiation_ref != descriptor.negotiation_ref
        || binding.negotiation_generation != descriptor.negotiation_generation
    {
        return Err(AudioError::NegotiationBindingMismatch);
    }
    let result = canonical_negotiation_result(&binding.result)
        .map_err(|_| AudioError::NegotiationResultInvalid)?;
    require_supported_extensions(&result.extensions, core::iter::empty::<&str>())
        .map_err(|_| AudioError::UnsupportedNegotiationExtension)?;
    for capability in &result.capabilities {
        require_supported_extensions(&capability.extensions, core::iter::empty::<&str>())
            .map_err(|_| AudioError::UnsupportedNegotiationExtension)?;
    }
    for required in [
        AUDIO_MEDIA_CAPABILITY,
        descriptor.codec.codec_capability_id.as_str(),
    ] {
        if !capability_is_usable(&result.capabilities, required) {
            return Err(AudioError::NegotiatedCapabilityUnavailable);
        }
    }
    let selected_codec = canonical_audio_codec_config(&binding.selected_codec)?;
    if selected_codec != descriptor.codec {
        return Err(AudioError::NegotiatedCodecMismatch);
    }
    Ok(())
}

fn accepted_participant(call: &CallSession, principal: &ucr_model::PrincipalRef) -> bool {
    call.participants.iter().any(|participant| {
        participant.principal == *principal
            && participant.state == CallParticipantState::Accepted
            && participant.left_revision.is_none()
    })
}

fn require_current_capabilities<C: AudioCapabilityProvider>(
    provider: &C,
    descriptor: &AudioStreamDescriptor,
) -> Result<(), AudioError> {
    let capabilities = canonical_capabilities(&provider.current_capabilities())
        .map_err(|_| AudioError::CapabilityUnavailable)?;
    for required in [
        AUDIO_MEDIA_CAPABILITY,
        descriptor.codec.codec_capability_id.as_str(),
    ] {
        if !capability_is_usable(&capabilities, required) {
            return Err(AudioError::CapabilityUnavailable);
        }
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

const fn opus_channels(layout: AudioChannelLayout) -> Channels {
    match layout {
        AudioChannelLayout::Mono => Channels::Mono,
        AudioChannelLayout::Stereo => Channels::Stereo,
    }
}

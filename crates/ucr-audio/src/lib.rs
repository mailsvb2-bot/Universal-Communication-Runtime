#![forbid(unsafe_code)]

use core::fmt;

use opus::{Application, Channels, Decoder, Encoder};
use ucr_core::{AuthorizationEvaluator, CallStore, DurableStoreError};
use ucr_model::{
    AudioChannelLayout, AudioStreamDescriptor, AuthorizationRequest, CallParticipantState,
    CallSession, CallSignallingState, CapabilityDescriptor, CapabilityMaturity, EncodedAudioFrame,
    ScopedPrincipal,
};
use ucr_protocol::{
    AUDIO_MEDIA_CAPABILITY, AUDIO_RECEIVE_PERMISSION, AUDIO_SEND_PERMISSION, AudioProtocolError,
    MAX_ENCODED_AUDIO_FRAME_BYTES, audio_samples_per_channel, canonical_audio_stream_descriptor,
    canonical_capabilities, phase20_audio_capabilities, validate_audio_frame_for_stream,
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

/// Prepared Phase-20 Audio entry point over the one canonical Call and authorization owners.
///
/// It owns no durable media table, route graph, peer identity, E2EE state, video state, or adaptive
/// policy. Sender/receiver objects re-check current Call authority for every realtime frame.
#[derive(Debug)]
pub struct AudioRuntime<'a, A, S, C> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
}

impl<'a, A, S, C> AudioRuntime<'a, A, S, C> {
    #[must_use]
    pub const fn new(authorization: &'a A, store: &'a S, capabilities: &'a C) -> Self {
        Self {
            authorization,
            store,
            capabilities,
        }
    }
}

impl<'a, A, S, C> AudioRuntime<'a, A, S, C>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
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
    ) -> Result<OpusAudioSender<'a, A, S, C>, AudioError> {
        let descriptor = canonical_audio_stream_descriptor(descriptor)?;
        if descriptor.source != subject.principal {
            return Err(AudioError::SourceMismatch);
        }
        require_audio_authority(
            self.authorization,
            self.store,
            self.capabilities,
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
    ) -> Result<OpusAudioReceiver<'a, A, S, C>, AudioError> {
        let descriptor = canonical_audio_stream_descriptor(descriptor)?;
        require_audio_authority(
            self.authorization,
            self.store,
            self.capabilities,
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
            subject: subject.clone(),
            descriptor,
            decoder,
            last_sequence: None,
        })
    }
}

pub struct OpusAudioSender<'a, A, S, C> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    subject: ScopedPrincipal,
    descriptor: AudioStreamDescriptor,
    encoder: Encoder,
    next_sequence: u64,
    next_timestamp_samples: u64,
}

impl<A, S, C> fmt::Debug for OpusAudioSender<'_, A, S, C> {
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

impl<A, S, C> OpusAudioSender<'_, A, S, C>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
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

pub struct OpusAudioReceiver<'a, A, S, C> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    subject: ScopedPrincipal,
    descriptor: AudioStreamDescriptor,
    decoder: Decoder,
    last_sequence: Option<u64>,
}

impl<A, S, C> fmt::Debug for OpusAudioReceiver<'_, A, S, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpusAudioReceiver")
            .field("subject", &self.subject)
            .field("descriptor", &self.descriptor)
            .field("last_sequence", &self.last_sequence)
            .finish_non_exhaustive()
    }
}

impl<A, S, C> OpusAudioReceiver<'_, A, S, C>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
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

fn require_audio_authority<A, S, C>(
    authorization: &A,
    store: &S,
    capabilities: &C,
    subject: &ScopedPrincipal,
    descriptor: &AudioStreamDescriptor,
    permission: &str,
) -> Result<CallSession, AudioError>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: AudioCapabilityProvider,
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
    if !accepted_participant(&call, &subject.principal) {
        return Err(AudioError::SubjectNotAccepted);
    }
    if !accepted_participant(&call, &descriptor.source) {
        return Err(AudioError::SourceNotAccepted);
    }
    Ok(call)
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
        let usable = capabilities.iter().any(|capability| {
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
        });
        if !usable {
            return Err(AudioError::CapabilityUnavailable);
        }
    }
    Ok(())
}

const fn opus_channels(layout: AudioChannelLayout) -> Channels {
    match layout {
        AudioChannelLayout::Mono => Channels::Mono,
        AudioChannelLayout::Stereo => Channels::Stereo,
    }
}

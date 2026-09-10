#![forbid(unsafe_code)]

use core::fmt;

use h264_reader::nal::{
    Nal, RefNal, UnitType,
    sps::{FrameMbsFlags, Level as ParsedH264Level, Profile as ParsedH264Profile, SeqParameterSet},
};

use openh264::{
    OpenH264API,
    decoder::Decoder,
    encoder::{
        BitRate, Encoder, EncoderConfig, FrameRate, FrameType, Level, Profile, UsageType, VuiConfig,
    },
    formats::{RgbSliceU8, YUVBuffer, YUVSource},
    nal_units,
};
use ucr_core::{AuthorizationEvaluator, CallStore, DurableStoreError};
use ucr_model::{
    AuthorizationRequest, CallId, CallParticipantState, CallSession, CallSignallingState,
    CapabilityDescriptor, CapabilityMaturity, EncodedVideoFrame, OpaqueId, PrincipalRef,
    ScopedPrincipal, TenantScope, VideoCodecConfig, VideoSourceKind, VideoStreamDescriptor,
};
use ucr_protocol::{
    CanonicalError, H264_VIDEO_CODEC_CAPABILITY, MAX_CALL_PARTICIPANTS,
    MAX_ENCODED_VIDEO_FRAME_BYTES, NegotiationResultEnvelope, VIDEO_MEDIA_CAPABILITY,
    VIDEO_RECEIVE_PERMISSION, VIDEO_SEND_PERMISSION, VideoProtocolError, canonical_capabilities,
    canonical_negotiation_result, canonical_video_codec_config, canonical_video_stream_descriptor,
    h264_reference_coded_dimensions, h264_reference_max_dpb_frames, phase21_video_capabilities,
    require_supported_extensions, required_video_capability_for_source,
    validate_video_frame_for_stream, video_rgb8_len,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoError {
    Authorization(CanonicalError),
    Store(DurableStoreError),
    Protocol(VideoProtocolError),
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
    NegotiatedParticipantsInvalid,
    NegotiatedParticipantSetMismatch,
    UnsupportedNegotiationExtension,
    CapabilityUnavailable,
    RgbFrameLength,
    EncodedFrameTooLarge,
    Codec,
    NoDecodedFrame,
    MissingValidatedParameterSet,
    DecodedDimensionsMismatch,
    UnsupportedH264ProfileOrLevel,
    DecodedPictureBufferTooLarge,
    DuplicateOrOutOfOrder,
    SequenceOverflow,
    TimestampOverflow,
}

impl From<DurableStoreError> for VideoError {
    fn from(error: DurableStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<VideoProtocolError> for VideoError {
    fn from(error: VideoProtocolError) -> Self {
        Self::Protocol(error)
    }
}

pub trait VideoCapabilityProvider: fmt::Debug + Send + Sync {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedVideoCapabilities;

impl VideoCapabilityProvider for PreparedVideoCapabilities {
    fn current_capabilities(&self) -> Vec<CapabilityDescriptor> {
        phase21_video_capabilities()
    }
}

/// Read-only resolution of the one canonical Call media-negotiation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVideoNegotiation {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub negotiation_ref: OpaqueId,
    pub negotiation_generation: u64,
    pub result: NegotiationResultEnvelope,
    pub selected_codec: VideoCodecConfig,
    pub negotiated_participants: Vec<PrincipalRef>,
}

pub trait VideoNegotiationResolver: fmt::Debug + Send + Sync {
    /// # Errors
    /// Returns a canonical resolver failure without authorizing fallback or renegotiation.
    fn resolve_video_negotiation(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        negotiation_ref: &OpaqueId,
        negotiation_generation: u64,
    ) -> Result<Option<ResolvedVideoNegotiation>, CanonicalError>;
}

/// Prepared Phase-21 Video entry point over the existing canonical Call/authorization owners.
#[derive(Debug)]
pub struct VideoRuntime<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
}

impl<'a, A, S, C, N> VideoRuntime<'a, A, S, C, N> {
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

impl<'a, A, S, C, N> VideoRuntime<'a, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: VideoCapabilityProvider,
    N: VideoNegotiationResolver,
{
    /// # Errors
    /// Rejects unauthorized, inactive, stale-negotiation, invalid-source or codec state.
    pub fn open_sender(
        &self,
        subject: &ScopedPrincipal,
        descriptor: &VideoStreamDescriptor,
    ) -> Result<H264VideoSender<'a, A, S, C, N>, VideoError> {
        let descriptor = canonical_video_stream_descriptor(descriptor)?;
        if descriptor.source != subject.principal {
            return Err(VideoError::SourceMismatch);
        }
        require_video_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            subject,
            &descriptor,
            VIDEO_SEND_PERMISSION,
        )?;
        let encoder = build_h264_encoder(&descriptor)?;
        Ok(H264VideoSender {
            authorization: self.authorization,
            store: self.store,
            capabilities: self.capabilities,
            negotiations: self.negotiations,
            subject: subject.clone(),
            descriptor,
            encoder,
            encoder_usable: true,
            next_sequence: 0,
            next_timestamp_us: 0,
        })
    }

    /// # Errors
    /// Rejects unauthorized, inactive, stale-negotiation, invalid-source or codec state.
    pub fn open_receiver(
        &self,
        subject: &ScopedPrincipal,
        descriptor: &VideoStreamDescriptor,
    ) -> Result<H264VideoReceiver<'a, A, S, C, N>, VideoError> {
        let descriptor = canonical_video_stream_descriptor(descriptor)?;
        require_video_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            subject,
            &descriptor,
            VIDEO_RECEIVE_PERMISSION,
        )?;
        let decoder = Decoder::new().map_err(|_| VideoError::Codec)?;
        Ok(H264VideoReceiver {
            authorization: self.authorization,
            store: self.store,
            capabilities: self.capabilities,
            negotiations: self.negotiations,
            subject: subject.clone(),
            descriptor,
            decoder,
            last_sequence: None,
            validated_parameter_set: false,
            decoder_usable: true,
        })
    }
}

pub struct H264VideoSender<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
    subject: ScopedPrincipal,
    descriptor: VideoStreamDescriptor,
    encoder: Encoder,
    encoder_usable: bool,
    next_sequence: u64,
    next_timestamp_us: u64,
}

impl<A, S, C, N> fmt::Debug for H264VideoSender<'_, A, S, C, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H264VideoSender")
            .field("subject", &self.subject)
            .field("descriptor", &self.descriptor)
            .field("encoder_usable", &self.encoder_usable)
            .field("next_sequence", &self.next_sequence)
            .field("next_timestamp_us", &self.next_timestamp_us)
            .finish_non_exhaustive()
    }
}

impl<A, S, C, N> H264VideoSender<'_, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: VideoCapabilityProvider,
    N: VideoNegotiationResolver,
{
    #[must_use]
    pub const fn descriptor(&self) -> &VideoStreamDescriptor {
        &self.descriptor
    }

    pub fn force_keyframe(&mut self) {
        if self.encoder_usable {
            self.encoder.force_intra_frame();
        }
    }

    /// Encodes one exact contiguous RGB8 frame after re-checking current media authority.
    ///
    /// # Errors
    /// Rejects authority loss, invalid RGB length, counter overflow or codec failure.
    pub fn encode_rgb8(&mut self, rgb8: &[u8]) -> Result<EncodedVideoFrame, VideoError> {
        require_video_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            &self.subject,
            &self.descriptor,
            VIDEO_SEND_PERMISSION,
        )?;
        if !self.encoder_usable {
            return Err(VideoError::Codec);
        }
        if rgb8.len() != video_rgb8_len(&self.descriptor.codec)? {
            return Err(VideoError::RgbFrameLength);
        }
        let width =
            usize::try_from(self.descriptor.codec.width).map_err(|_| VideoError::RgbFrameLength)?;
        let height = usize::try_from(self.descriptor.codec.height)
            .map_err(|_| VideoError::RgbFrameLength)?;
        let source = RgbSliceU8::new(rgb8, (width, height));
        let yuv = YUVBuffer::from_rgb8_source(source);
        let (keyframe, payload) = if let Ok(bitstream) = self.encoder.encode(&yuv) {
            (
                matches!(bitstream.frame_type(), FrameType::IDR | FrameType::I),
                bitstream.to_vec(),
            )
        } else {
            self.recover_encoder()?;
            return Err(VideoError::Codec);
        };
        if payload.len() > MAX_ENCODED_VIDEO_FRAME_BYTES {
            self.recover_encoder()?;
            return Err(VideoError::EncodedFrameTooLarge);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(VideoError::SequenceOverflow)?;
        let frame_interval_us = 1_000_000_u64 / u64::from(self.descriptor.codec.frame_rate);
        let next_timestamp = self
            .next_timestamp_us
            .checked_add(frame_interval_us)
            .ok_or(VideoError::TimestampOverflow)?;
        let frame = EncodedVideoFrame {
            scope: self.descriptor.scope.clone(),
            call_id: self.descriptor.call_id.clone(),
            stream_id: self.descriptor.stream_id.clone(),
            source: self.descriptor.source.clone(),
            negotiation_ref: self.descriptor.negotiation_ref.clone(),
            negotiation_generation: self.descriptor.negotiation_generation,
            sequence: self.next_sequence,
            media_timestamp_us: self.next_timestamp_us,
            keyframe,
            payload,
        };
        validate_video_frame_for_stream(&self.descriptor, &frame)?;
        self.next_sequence = next_sequence;
        self.next_timestamp_us = next_timestamp;
        Ok(frame)
    }

    fn recover_encoder(&mut self) -> Result<(), VideoError> {
        self.encoder_usable = false;
        let replacement = build_h264_encoder(&self.descriptor)?;
        self.encoder = replacement;
        self.encoder_usable = true;
        Ok(())
    }
}

fn build_h264_encoder(descriptor: &VideoStreamDescriptor) -> Result<Encoder, VideoError> {
    let frame_rate = u16::try_from(descriptor.codec.frame_rate).map_err(|_| VideoError::Codec)?;
    let config = EncoderConfig::new()
        .profile(Profile::Baseline)
        .level(Level::Level_4_0)
        .bitrate(BitRate::from_bps(descriptor.codec.target_bitrate_bps))
        .max_frame_rate(FrameRate::from_hz(f32::from(frame_rate)))
        .usage_type(match descriptor.source_kind {
            VideoSourceKind::Camera => UsageType::CameraVideoRealTime,
            VideoSourceKind::ScreenShare => UsageType::ScreenContentRealTime,
        })
        .vui(VuiConfig::bt709());
    Encoder::with_api_config(OpenH264API::from_source(), config).map_err(|_| VideoError::Codec)
}

#[derive(Clone, PartialEq, Eq)]
pub struct DecodedVideoFrame {
    pub width: u32,
    pub height: u32,
    pub sequence: u64,
    pub media_timestamp_us: u64,
    pub rgb8: Vec<u8>,
}

impl fmt::Debug for DecodedVideoFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedVideoFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("sequence", &self.sequence)
            .field("media_timestamp_us", &self.media_timestamp_us)
            .field("rgb8", &"<decoded-video>")
            .field("rgb8_len", &self.rgb8.len())
            .finish()
    }
}

pub struct H264VideoReceiver<'a, A, S, C, N> {
    authorization: &'a A,
    store: &'a S,
    capabilities: &'a C,
    negotiations: &'a N,
    subject: ScopedPrincipal,
    descriptor: VideoStreamDescriptor,
    decoder: Decoder,
    last_sequence: Option<u64>,
    validated_parameter_set: bool,
    decoder_usable: bool,
}

impl<A, S, C, N> fmt::Debug for H264VideoReceiver<'_, A, S, C, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("H264VideoReceiver")
            .field("subject", &self.subject)
            .field("descriptor", &self.descriptor)
            .field("last_sequence", &self.last_sequence)
            .field("validated_parameter_set", &self.validated_parameter_set)
            .field("decoder_usable", &self.decoder_usable)
            .finish_non_exhaustive()
    }
}

impl<A, S, C, N> H264VideoReceiver<'_, A, S, C, N>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: VideoCapabilityProvider,
    N: VideoNegotiationResolver,
{
    #[must_use]
    pub const fn descriptor(&self) -> &VideoStreamDescriptor {
        &self.descriptor
    }

    /// # Errors
    /// Rejects authority loss, cross-stream data, duplicates, malformed codec data or dimensions.
    pub fn decode_frame(
        &mut self,
        frame: &EncodedVideoFrame,
    ) -> Result<DecodedVideoFrame, VideoError> {
        require_video_authority(
            self.authorization,
            self.store,
            self.capabilities,
            self.negotiations,
            &self.subject,
            &self.descriptor,
            VIDEO_RECEIVE_PERMISSION,
        )?;
        validate_video_frame_for_stream(&self.descriptor, frame)?;
        if self
            .last_sequence
            .is_some_and(|last| frame.sequence <= last)
        {
            return Err(VideoError::DuplicateOrOutOfOrder);
        }
        if !self.decoder_usable {
            return Err(VideoError::Codec);
        }
        let next_validated_parameter_set = preflight_h264_parameter_sets(
            &frame.payload,
            &self.descriptor.codec,
            self.validated_parameter_set,
        )?;
        let decode_result = (|| {
            let mut decoded = None;
            for packet in nal_units(&frame.payload) {
                let maybe_yuv = self.decoder.decode(packet).map_err(|_| VideoError::Codec)?;
                if let Some(yuv) = maybe_yuv {
                    let (width, height) = yuv.dimensions();
                    let mut rgb8 = vec![0_u8; yuv.rgb8_len()];
                    yuv.write_rgb8(&mut rgb8);
                    decoded = Some((width, height, rgb8));
                }
            }
            decoded.ok_or(VideoError::NoDecodedFrame)
        })();
        let (width, height, rgb8) = match decode_result {
            Ok(decoded) => decoded,
            Err(error) => {
                self.reset_decoder_after_rejected_frame()?;
                return Err(error);
            }
        };
        if width
            != usize::try_from(self.descriptor.codec.width)
                .map_err(|_| VideoError::DecodedDimensionsMismatch)?
            || height
                != usize::try_from(self.descriptor.codec.height)
                    .map_err(|_| VideoError::DecodedDimensionsMismatch)?
        {
            self.reset_decoder_after_rejected_frame()?;
            return Err(VideoError::DecodedDimensionsMismatch);
        }
        self.validated_parameter_set = next_validated_parameter_set;
        self.last_sequence = Some(frame.sequence);
        Ok(DecodedVideoFrame {
            width: self.descriptor.codec.width,
            height: self.descriptor.codec.height,
            sequence: frame.sequence,
            media_timestamp_us: frame.media_timestamp_us,
            rgb8,
        })
    }

    fn reset_decoder_after_rejected_frame(&mut self) -> Result<(), VideoError> {
        self.validated_parameter_set = false;
        if let Ok(decoder) = Decoder::new() {
            self.decoder = decoder;
            self.decoder_usable = true;
            Ok(())
        } else {
            self.decoder_usable = false;
            Err(VideoError::Codec)
        }
    }
}

/// Parses H.264 SPS metadata in safe Rust before native decode and enforces negotiated dimensions.
///
/// `already_validated` tracks whether this stream has previously accepted a matching SPS. A first
/// payload without a valid SPS fails closed. Later payloads may omit SPS until a replacement SPS is
/// signalled, which is checked again before native decode.
///
/// # Errors
/// Rejects malformed Annex-B/NAL/SPS syntax, a missing initial SPS, or dimensions that differ from
/// the already negotiated video configuration.
pub fn preflight_h264_parameter_sets(
    payload: &[u8],
    negotiated_codec: &VideoCodecConfig,
    already_validated: bool,
) -> Result<bool, VideoError> {
    let negotiated_codec = canonical_video_codec_config(negotiated_codec)?;
    let coded_canvas = h264_reference_coded_dimensions(&negotiated_codec)?;
    let mut saw_valid_sps = false;
    for packet in nal_units(payload) {
        let bytes = strip_annex_b_start_code(packet).ok_or(VideoError::Codec)?;
        let nal = RefNal::new(bytes, &[], true);
        let header = nal.header().map_err(|_| VideoError::Codec)?;
        if header.nal_unit_type() == UnitType::SeqParameterSet {
            let sps = SeqParameterSet::from_bits(nal.rbsp_bits()).map_err(|_| VideoError::Codec)?;
            validate_h264_sps(&sps, &negotiated_codec, coded_canvas)?;
            saw_valid_sps = true;
        }
    }
    if !already_validated && !saw_valid_sps {
        return Err(VideoError::MissingValidatedParameterSet);
    }
    Ok(already_validated || saw_valid_sps)
}

fn validate_h264_sps(
    sps: &SeqParameterSet,
    negotiated_codec: &VideoCodecConfig,
    coded_canvas: (u32, u32),
) -> Result<(), VideoError> {
    if !matches!(sps.frame_mbs_flags, FrameMbsFlags::Frames) {
        return Err(VideoError::DecodedDimensionsMismatch);
    }
    if !matches!(sps.profile(), ParsedH264Profile::Baseline)
        || sps.level() != ParsedH264Level::L4
        || sps.constraint_flags.reserved_zero_two_bits() != 0
    {
        return Err(VideoError::UnsupportedH264ProfileOrLevel);
    }
    let max_dpb_frames = h264_reference_max_dpb_frames(negotiated_codec)?;
    if sps.max_num_ref_frames > max_dpb_frames {
        return Err(VideoError::DecodedPictureBufferTooLarge);
    }
    if let Some(restrictions) = sps
        .vui_parameters
        .as_ref()
        .and_then(|vui| vui.bitstream_restrictions.as_ref())
        && (restrictions.max_dec_frame_buffering > max_dpb_frames
            || restrictions.max_num_reorder_frames > max_dpb_frames)
    {
        return Err(VideoError::DecodedPictureBufferTooLarge);
    }
    let coded_width_macroblocks = sps
        .pic_width_in_mbs_minus1
        .checked_add(1)
        .ok_or(VideoError::DecodedDimensionsMismatch)?;
    let coded_height_macroblocks = sps
        .pic_height_in_map_units_minus1
        .checked_add(1)
        .ok_or(VideoError::DecodedDimensionsMismatch)?;
    let coded_width = coded_width_macroblocks
        .checked_mul(16)
        .ok_or(VideoError::DecodedDimensionsMismatch)?;
    let coded_height = coded_height_macroblocks
        .checked_mul(16)
        .ok_or(VideoError::DecodedDimensionsMismatch)?;
    let coded_macroblocks = coded_width_macroblocks
        .checked_mul(coded_height_macroblocks)
        .ok_or(VideoError::DecodedDimensionsMismatch)?;
    let expected_macroblocks = coded_canvas
        .0
        .checked_div(16)
        .and_then(|width| {
            coded_canvas
                .1
                .checked_div(16)
                .and_then(|height| width.checked_mul(height))
        })
        .ok_or(VideoError::DecodedDimensionsMismatch)?;
    if (coded_width, coded_height) != coded_canvas || coded_macroblocks != expected_macroblocks {
        return Err(VideoError::DecodedDimensionsMismatch);
    }
    let display_dimensions = sps.pixel_dimensions().map_err(|_| VideoError::Codec)?;
    if display_dimensions != (negotiated_codec.width, negotiated_codec.height) {
        return Err(VideoError::DecodedDimensionsMismatch);
    }
    Ok(())
}

fn strip_annex_b_start_code(packet: &[u8]) -> Option<&[u8]> {
    let mut zeros = 0_usize;
    for (index, byte) in packet.iter().copied().enumerate() {
        if byte == 0 {
            zeros = zeros.saturating_add(1);
            continue;
        }
        if byte == 1 && zeros >= 2 {
            return packet.get(index + 1..).filter(|value| !value.is_empty());
        }
        return None;
    }
    None
}

fn require_video_authority<A, S, C, N>(
    authorization: &A,
    store: &S,
    capabilities: &C,
    negotiations: &N,
    subject: &ScopedPrincipal,
    descriptor: &VideoStreamDescriptor,
    permission: &str,
) -> Result<CallSession, VideoError>
where
    A: AuthorizationEvaluator,
    S: CallStore,
    C: VideoCapabilityProvider,
    N: VideoNegotiationResolver,
{
    if subject.scope != descriptor.scope {
        return Err(VideoError::ScopeMismatch);
    }
    require_current_capabilities(capabilities, descriptor)?;
    authorization
        .authorize(&AuthorizationRequest {
            subject: subject.clone(),
            permission: permission.to_owned(),
            resource_scope: descriptor.scope.clone(),
        })
        .map_err(VideoError::Authorization)?;
    let call = store
        .call_for_participant(subject, &descriptor.scope, &descriptor.call_id)?
        .ok_or(VideoError::CallUnavailable)?;
    if call.signalling_state != CallSignallingState::Active {
        return Err(VideoError::CallNotActive);
    }
    if call.media_negotiation_generation != descriptor.negotiation_generation {
        return Err(VideoError::NegotiationGenerationMismatch);
    }
    let Some(call_ref) = call.media_negotiation_ref.as_ref() else {
        return Err(VideoError::MissingNegotiation);
    };
    if call_ref != &descriptor.negotiation_ref {
        return Err(VideoError::NegotiationBindingMismatch);
    }
    if !accepted_participant(&call, &subject.principal) {
        return Err(VideoError::SubjectNotAccepted);
    }
    if !accepted_participant(&call, &descriptor.source) {
        return Err(VideoError::SourceNotAccepted);
    }
    require_negotiated_video(negotiations, &call, descriptor)?;
    Ok(call)
}

fn require_negotiated_video<N: VideoNegotiationResolver>(
    resolver: &N,
    call: &CallSession,
    descriptor: &VideoStreamDescriptor,
) -> Result<(), VideoError> {
    let binding = resolver
        .resolve_video_negotiation(
            &descriptor.scope,
            &descriptor.call_id,
            &descriptor.negotiation_ref,
            descriptor.negotiation_generation,
        )
        .map_err(VideoError::NegotiationResolve)?
        .ok_or(VideoError::MissingNegotiation)?;
    if binding.scope != descriptor.scope
        || binding.call_id != descriptor.call_id
        || binding.negotiation_ref != descriptor.negotiation_ref
        || binding.negotiation_generation != descriptor.negotiation_generation
    {
        return Err(VideoError::NegotiationBindingMismatch);
    }
    let result = canonical_negotiation_result(&binding.result)
        .map_err(|_| VideoError::NegotiationResultInvalid)?;
    require_supported_extensions(&result.extensions, core::iter::empty::<&str>())
        .map_err(|_| VideoError::UnsupportedNegotiationExtension)?;
    for capability in &result.capabilities {
        require_supported_extensions(&capability.extensions, core::iter::empty::<&str>())
            .map_err(|_| VideoError::UnsupportedNegotiationExtension)?;
    }
    let mut required = vec![
        VIDEO_MEDIA_CAPABILITY,
        descriptor.codec.codec_capability_id.as_str(),
    ];
    if let Some(source_capability) = required_video_capability_for_source(descriptor.source_kind) {
        required.push(source_capability);
    }
    if required
        .iter()
        .any(|id| !capability_is_usable(&result.capabilities, id))
    {
        return Err(VideoError::NegotiatedCapabilityUnavailable);
    }
    let selected_codec = canonical_video_codec_config(&binding.selected_codec)?;
    if selected_codec != descriptor.codec {
        return Err(VideoError::NegotiatedCodecMismatch);
    }
    require_exact_negotiated_participants(call, &binding.negotiated_participants)?;
    Ok(())
}

fn require_exact_negotiated_participants(
    call: &CallSession,
    negotiated: &[PrincipalRef],
) -> Result<(), VideoError> {
    if negotiated.is_empty() || negotiated.len() > MAX_CALL_PARTICIPANTS {
        return Err(VideoError::NegotiatedParticipantsInvalid);
    }
    let mut unique = std::collections::HashSet::with_capacity(negotiated.len());
    if negotiated.iter().any(|principal| !unique.insert(principal)) {
        return Err(VideoError::NegotiatedParticipantsInvalid);
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
        return Err(VideoError::NegotiatedParticipantSetMismatch);
    }
    Ok(())
}

fn accepted_participant(call: &CallSession, principal: &PrincipalRef) -> bool {
    call.participants.iter().any(|participant| {
        participant.principal == *principal
            && participant.state == CallParticipantState::Accepted
            && participant.left_revision.is_none()
    })
}

fn require_current_capabilities<C: VideoCapabilityProvider>(
    provider: &C,
    descriptor: &VideoStreamDescriptor,
) -> Result<(), VideoError> {
    let capabilities = canonical_capabilities(&provider.current_capabilities())
        .map_err(|_| VideoError::CapabilityUnavailable)?;
    let mut required = vec![
        VIDEO_MEDIA_CAPABILITY,
        descriptor.codec.codec_capability_id.as_str(),
    ];
    if let Some(source_capability) = required_video_capability_for_source(descriptor.source_kind) {
        required.push(source_capability);
    }
    if required
        .iter()
        .any(|id| !capability_is_usable(&capabilities, id))
    {
        return Err(VideoError::CapabilityUnavailable);
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

#[must_use]
pub const fn phase21_reference_codec_id() -> &'static str {
    H264_VIDEO_CODEC_CAPABILITY
}

#[cfg(test)]
mod tests {
    use h264_reader::nal::sps::{BitstreamRestrictions, FrameCropping, VuiParameters};

    use super::*;

    fn reference_codec() -> VideoCodecConfig {
        VideoCodecConfig {
            codec_capability_id: H264_VIDEO_CODEC_CAPABILITY.to_owned(),
            width: 320,
            height: 240,
            frame_rate: 20,
            target_bitrate_bps: 384_000,
        }
    }

    fn reference_sps() -> SeqParameterSet {
        let rgb = vec![16_u8; 320 * 240 * 3];
        let source = RgbSliceU8::new(&rgb, (320, 240));
        let yuv = YUVBuffer::from_rgb8_source(source);
        let config = EncoderConfig::new()
            .profile(Profile::Baseline)
            .level(Level::Level_4_0)
            .bitrate(BitRate::from_bps(384_000))
            .max_frame_rate(FrameRate::from_hz(20.0));
        let mut encoder = Encoder::with_api_config(OpenH264API::from_source(), config)
            .expect("reference encoder");
        let payload = encoder.encode(&yuv).expect("h264").to_vec();
        nal_units(&payload)
            .find_map(|packet| {
                let bytes = strip_annex_b_start_code(packet)?;
                let nal = RefNal::new(bytes, &[], true);
                let header = nal.header().ok()?;
                (header.nal_unit_type() == UnitType::SeqParameterSet)
                    .then(|| SeqParameterSet::from_bits(nal.rbsp_bits()).ok())
                    .flatten()
            })
            .expect("SPS")
    }

    #[test]
    fn cropped_display_dimensions_cannot_hide_a_larger_coded_canvas() {
        let codec = reference_codec();
        let mut sps = reference_sps();
        assert!(matches!(sps.profile(), ParsedH264Profile::Baseline));
        assert_eq!(sps.level(), ParsedH264Level::L4);
        sps.pic_width_in_mbs_minus1 = 39;
        sps.frame_cropping = Some(FrameCropping {
            left_offset: 0,
            right_offset: 160,
            top_offset: 0,
            bottom_offset: 0,
        });
        assert_eq!(sps.pixel_dimensions().expect("cropped display"), (320, 240));
        let coded_canvas = h264_reference_coded_dimensions(&codec).expect("coded shape");
        assert_eq!(
            validate_h264_sps(&sps, &codec, coded_canvas),
            Err(VideoError::DecodedDimensionsMismatch)
        );
    }

    #[test]
    fn level_4_dpb_limits_reference_frames_and_vui_buffering() {
        let codec = reference_codec();
        let coded_canvas = h264_reference_coded_dimensions(&codec).expect("coded shape");
        let max_dpb = h264_reference_max_dpb_frames(&codec).expect("max dpb");
        let mut sps = reference_sps();
        sps.max_num_ref_frames = max_dpb + 1;
        assert_eq!(
            validate_h264_sps(&sps, &codec, coded_canvas),
            Err(VideoError::DecodedPictureBufferTooLarge)
        );

        let mut sps = reference_sps();
        sps.max_num_ref_frames = max_dpb.min(1);
        let restrictions = BitstreamRestrictions {
            max_dec_frame_buffering: max_dpb + 1,
            ..BitstreamRestrictions::default()
        };
        let vui = sps
            .vui_parameters
            .get_or_insert_with(VuiParameters::default);
        vui.bitstream_restrictions = Some(restrictions);
        assert_eq!(
            validate_h264_sps(&sps, &codec, coded_canvas),
            Err(VideoError::DecodedPictureBufferTooLarge)
        );

        let mut sps = reference_sps();
        sps.level_idc = 41;
        assert_eq!(
            validate_h264_sps(&sps, &codec, coded_canvas),
            Err(VideoError::UnsupportedH264ProfileOrLevel)
        );
    }
}

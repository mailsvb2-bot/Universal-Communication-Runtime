use ucr_model::{
    AdaptiveMediaDecision, AdaptiveMediaStage, AdaptiveMediaTelemetry, MediaThermalState,
};
use ucr_protocol::{
    ADAPTIVE_DEGRADE_CONFIRM_SAMPLES, ADAPTIVE_RECOVERY_CONFIRM_SAMPLES,
    AdaptiveMediaProtocolError, adaptive_media_pressures, one_step_better,
    reference_deferred_fallbacks, reference_opus_target_bitrate, reference_stage_for_telemetry,
    reference_video_config, stage_requires_media_renegotiation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMediaError {
    Protocol(AdaptiveMediaProtocolError),
}

impl From<AdaptiveMediaProtocolError> for AdaptiveMediaError {
    fn from(error: AdaptiveMediaProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Ephemeral Phase-23 controller. It owns hysteresis only: no Call, route, transport, crypto,
/// persistence, or delivery authority is duplicated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveMediaController {
    current_stage: AdaptiveMediaStage,
    pending_stage: Option<AdaptiveMediaStage>,
    pending_samples: u8,
}

impl AdaptiveMediaController {
    #[must_use]
    pub const fn new(initial_stage: AdaptiveMediaStage) -> Self {
        Self {
            current_stage: initial_stage,
            pending_stage: None,
            pending_samples: 0,
        }
    }

    #[must_use]
    pub const fn current_stage(&self) -> AdaptiveMediaStage {
        self.current_stage
    }

    /// Observes one bounded telemetry sample and returns the currently actionable media decision.
    ///
    /// Degradation is confirmed faster than recovery; a critical thermal signal or loss of any
    /// sustainable realtime profile applies immediately. Recovery advances only one quality rung at
    /// a time. This prevents a single optimistic sample from jumping from fallback to high video.
    ///
    /// # Errors
    /// Returns canonical telemetry/profile validation failures without mutating controller state.
    pub fn observe(
        &mut self,
        telemetry: &AdaptiveMediaTelemetry,
    ) -> Result<AdaptiveMediaDecision, AdaptiveMediaError> {
        let recommended = reference_stage_for_telemetry(telemetry)?;
        let pressures = adaptive_media_pressures(telemetry)?;
        let previous = self.current_stage;
        let mut changed = false;

        if recommended == self.current_stage {
            self.clear_pending();
        } else if recommended > self.current_stage {
            let required = if recommended == AdaptiveMediaStage::EventualFallbackRequired
                || telemetry.thermal_state == MediaThermalState::Critical
            {
                1
            } else {
                ADAPTIVE_DEGRADE_CONFIRM_SAMPLES
            };
            if self.record_pending(recommended) >= required {
                self.current_stage = recommended;
                self.clear_pending();
                changed = true;
            }
        } else if self.record_pending(recommended) >= ADAPTIVE_RECOVERY_CONFIRM_SAMPLES {
            self.current_stage = one_step_better(self.current_stage);
            self.clear_pending();
            changed = self.current_stage != previous;
        }

        self.decision(previous, changed, pressures)
    }

    fn record_pending(&mut self, stage: AdaptiveMediaStage) -> u8 {
        if self.pending_stage == Some(stage) {
            self.pending_samples = self.pending_samples.saturating_add(1);
        } else {
            self.pending_stage = Some(stage);
            self.pending_samples = 1;
        }
        self.pending_samples
    }

    fn clear_pending(&mut self) {
        self.pending_stage = None;
        self.pending_samples = 0;
    }

    fn decision(
        &self,
        previous: AdaptiveMediaStage,
        changed: bool,
        pressures: Vec<ucr_model::AdaptiveMediaPressure>,
    ) -> Result<AdaptiveMediaDecision, AdaptiveMediaError> {
        Ok(AdaptiveMediaDecision {
            stage: self.current_stage,
            changed,
            requires_media_renegotiation: changed
                && stage_requires_media_renegotiation(previous, self.current_stage),
            video: reference_video_config(self.current_stage)?,
            opus_target_bitrate_bps: reference_opus_target_bitrate(self.current_stage),
            deferred_fallbacks: reference_deferred_fallbacks(self.current_stage),
            pressures,
        })
    }
}

/// An already-authorized, already-encrypted quality layer advertised by the existing media owner.
/// This is selection metadata only: no stream, route, key, subscription or permission authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewerVideoLayer {
    pub spatial_id: u8,
    pub width: u32,
    pub height: u32,
    pub frame_rate: u32,
    pub bitrate_bps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerLayerSelectionError {
    TooManyLayers,
    InvalidLayer,
    DuplicateLayer,
    InvalidViewport,
}

/// Pick the highest actually available decodable quality layer for **one viewer**.
/// Callers must first validate subscription permission and E2EE/epoch bindings through canonical
/// owners. This helper cannot authorize a feed or cause a transport switch.
///
/// A thumbnail has no reason to consume a Full HD layer; a pinned Full HD viewport gets the
/// highest fitting layer if the adaptive network/device stage permits it. Participant count,
/// room name and the words "webinar" / "conference" are intentionally not inputs.
///
/// A missing fitting layer is returned as None, never faked by an upscaled source.
/// Audio-only stages also select no video. Invalid/duplicate metadata fails closed.
/// No layer is synthesized and no plaintext access is required.
pub fn select_viewer_video_layer(
    stage: AdaptiveMediaStage,
    viewport_width: u32,
    viewport_height: u32,
    layers: &[ViewerVideoLayer],
) -> Result<Option<ViewerVideoLayer>, ViewerLayerSelectionError> {
    if viewport_width == 0
        || viewport_height == 0
        || viewport_width > 7680
        || viewport_height > 4320
    {
        return Err(ViewerLayerSelectionError::InvalidViewport);
    }
    if layers.len() > 8 {
        return Err(ViewerLayerSelectionError::TooManyLayers);
    }
    for (i, layer) in layers.iter().enumerate() {
        if layer.width == 0
            || layer.height == 0
            || layer.width > 7680
            || layer.height > 4320
            || layer.frame_rate == 0
            || layer.frame_rate > 120
            || layer.bitrate_bps == 0
            || layer.bitrate_bps > 100_000_000
        {
            return Err(ViewerLayerSelectionError::InvalidLayer);
        }
        if layers[..i]
            .iter()
            .any(|prior| prior.spatial_id == layer.spatial_id)
        {
            return Err(ViewerLayerSelectionError::DuplicateLayer);
        }
    }

    let config =
        reference_video_config(stage).map_err(|_| ViewerLayerSelectionError::InvalidLayer)?;
    let Some(ceiling) = config else {
        return Ok(None);
    };
    let max_width = viewport_width.min(ceiling.width);
    let max_height = viewport_height.min(ceiling.height);
    Ok(layers
        .iter()
        .copied()
        .filter(|layer| {
            layer.width <= max_width
                && layer.height <= max_height
                && layer.bitrate_bps <= ceiling.target_bitrate_bps
                && layer.frame_rate <= ceiling.frame_rate
        })
        .max_by_key(|layer| {
            (
                u64::from(layer.width) * u64::from(layer.height),
                layer.frame_rate,
                layer.bitrate_bps,
            )
        }))
}

#[cfg(test)]
mod tests {
    use ucr_model::{
        AdaptiveMediaPressure, AdaptiveMediaStage, AdaptiveMediaTelemetry, DeferredMediaFallback,
        MediaThermalState,
    };

    use super::AdaptiveMediaController;

    #[test]
    fn viewer_quality_follows_viewport_and_telemetry_not_conference_label_or_count() {
        let layers = [
            super::ViewerVideoLayer {
                spatial_id: 0,
                width: 640,
                height: 360,
                frame_rate: 15,
                bitrate_bps: 300_000,
            },
            super::ViewerVideoLayer {
                spatial_id: 1,
                width: 1280,
                height: 720,
                frame_rate: 30,
                bitrate_bps: 1_800_000,
            },
            super::ViewerVideoLayer {
                spatial_id: 2,
                width: 1920,
                height: 1080,
                frame_rate: 30,
                bitrate_bps: 3_500_000,
            },
        ];
        let pick = |stage, width, height| {
            super::select_viewer_video_layer(stage, width, height, &layers).expect("valid")
        };
        assert_eq!(
            pick(AdaptiveMediaStage::Video1080p, 1920, 1080),
            Some(layers[2])
        );
        assert_eq!(
            pick(AdaptiveMediaStage::Video1080p, 1280, 720),
            Some(layers[1])
        );
        assert_eq!(
            pick(AdaptiveMediaStage::Video1080p, 640, 360),
            Some(layers[0])
        );
        assert_eq!(
            pick(AdaptiveMediaStage::Video720p, 1920, 1080),
            Some(layers[1])
        );
        assert_eq!(
            pick(AdaptiveMediaStage::Video480p, 1920, 1080),
            Some(layers[0])
        );
        assert_eq!(pick(AdaptiveMediaStage::Audio, 1920, 1080), None);
        assert_eq!(
            pick(AdaptiveMediaStage::EventualFallbackRequired, 1920, 1080),
            None
        );
    }

    #[test]
    fn viewer_quality_never_invents_full_hd_or_accepts_untrusted_layer_metadata() {
        use super::{
            ViewerLayerSelectionError as Error, ViewerVideoLayer as Layer,
            select_viewer_video_layer as select,
        };
        let small = Layer {
            spatial_id: 0,
            width: 640,
            height: 360,
            frame_rate: 15,
            bitrate_bps: 300_000,
        };
        assert_eq!(
            select(AdaptiveMediaStage::Video1080p, 1920, 1080, &[small]),
            Ok(Some(small))
        );
        assert_eq!(
            select(AdaptiveMediaStage::Video1080p, 1920, 1080, &[]),
            Ok(None)
        );
        assert_eq!(
            select(AdaptiveMediaStage::Video1080p, 0, 1080, &[small]),
            Err(Error::InvalidViewport)
        );
        assert_eq!(
            select(AdaptiveMediaStage::Video1080p, 1920, 1080, &[small, small]),
            Err(Error::DuplicateLayer)
        );
        assert_eq!(
            select(
                AdaptiveMediaStage::Video1080p,
                1920,
                1080,
                &[Layer {
                    bitrate_bps: 0,
                    ..small
                }]
            ),
            Err(Error::InvalidLayer)
        );
        assert_eq!(
            select(AdaptiveMediaStage::Video1080p, 1920, 1080, &[small; 9]),
            Err(Error::TooManyLayers)
        );
        assert_eq!(
            select(
                AdaptiveMediaStage::Video1080p,
                1920,
                1080,
                &[Layer {
                    spatial_id: 1,
                    width: 3840,
                    height: 2160,
                    frame_rate: 60,
                    bitrate_bps: 12_000_000
                }]
            ),
            Ok(None)
        );
    }

    #[test]
    fn quality_selection_scales_across_thousand_independent_viewers_without_a_room_mode() {
        let layers = [
            super::ViewerVideoLayer {
                spatial_id: 0,
                width: 640,
                height: 360,
                frame_rate: 12,
                bitrate_bps: 300_000,
            },
            super::ViewerVideoLayer {
                spatial_id: 1,
                width: 1280,
                height: 720,
                frame_rate: 30,
                bitrate_bps: 1_800_000,
            },
            super::ViewerVideoLayer {
                spatial_id: 2,
                width: 1920,
                height: 1080,
                frame_rate: 30,
                bitrate_bps: 3_500_000,
            },
        ];
        for viewer in 0..1_000 {
            let (stage, width, height, expected) = match viewer % 4 {
                0 => (AdaptiveMediaStage::Video1080p, 1920, 1080, Some(layers[2])),
                1 => (AdaptiveMediaStage::Video720p, 1920, 1080, Some(layers[1])),
                2 => (AdaptiveMediaStage::Video1080p, 640, 360, Some(layers[0])),
                _ => (AdaptiveMediaStage::Audio, 1920, 1080, None),
            };
            assert_eq!(
                super::select_viewer_video_layer(stage, width, height, &layers),
                Ok(expected),
                "unexpected layer for viewer {viewer}"
            );
        }
    }

    fn ideal() -> AdaptiveMediaTelemetry {
        AdaptiveMediaTelemetry {
            estimated_bandwidth_bps: 8_000_000,
            packet_loss_basis_points: 20,
            jitter_ms: 10,
            rtt_ms: 40,
            cpu_utilization_percent: 30,
            gpu_utilization_percent: Some(25),
            battery_percent: 90,
            external_power: false,
            thermal_state: MediaThermalState::Nominal,
        }
    }

    #[test]
    fn degradation_requires_confirmation_but_recovery_is_slower_and_stepwise() {
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::Video1080p);
        let mut poor = ideal();
        poor.estimated_bandwidth_bps = 1_400_000;
        assert_eq!(
            controller.observe(&poor).expect("one").stage,
            AdaptiveMediaStage::Video1080p
        );
        let degraded = controller.observe(&poor).expect("two");
        assert_eq!(degraded.stage, AdaptiveMediaStage::Video480p);
        assert!(degraded.changed);
        assert!(degraded.requires_media_renegotiation);

        for _ in 0..3 {
            assert_eq!(
                controller.observe(&ideal()).expect("recover hold").stage,
                AdaptiveMediaStage::Video480p
            );
        }
        assert_eq!(
            controller.observe(&ideal()).expect("recover").stage,
            AdaptiveMediaStage::Video720p
        );
    }

    #[test]
    fn one_bad_sample_does_not_flap_quality() {
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::Video720p);
        let mut poor = ideal();
        poor.jitter_ms = 110;
        assert_eq!(
            controller.observe(&poor).expect("poor").stage,
            AdaptiveMediaStage::Video720p
        );
        assert_eq!(
            controller.observe(&ideal()).expect("good").stage,
            AdaptiveMediaStage::Video720p
        );
    }

    #[test]
    fn contradictory_sample_resets_pending_degradation_evidence() {
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::Video720p);
        let mut poor = ideal();
        poor.jitter_ms = 110;
        assert_eq!(
            controller.observe(&poor).expect("poor one").stage,
            AdaptiveMediaStage::Video720p
        );
        assert_eq!(
            controller.observe(&ideal()).expect("reset").stage,
            AdaptiveMediaStage::Video720p
        );
        assert_eq!(
            controller.observe(&poor).expect("poor after reset").stage,
            AdaptiveMediaStage::Video720p
        );
        assert_eq!(
            controller.observe(&poor).expect("poor confirmed").stage,
            AdaptiveMediaStage::VideoLowFps
        );
    }

    #[test]
    fn invalid_telemetry_does_not_mutate_hysteresis_state() {
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::Video1080p);
        let mut poor = ideal();
        poor.estimated_bandwidth_bps = 1_400_000;
        assert_eq!(
            controller.observe(&poor).expect("pending").stage,
            AdaptiveMediaStage::Video1080p
        );
        let mut invalid = poor.clone();
        invalid.cpu_utilization_percent = 101;
        assert!(controller.observe(&invalid).is_err());
        assert_eq!(
            controller
                .observe(&poor)
                .expect("confirmed after invalid")
                .stage,
            AdaptiveMediaStage::Video480p
        );
    }

    #[test]
    fn critical_thermal_pressure_degrades_immediately_without_touching_security() {
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::Video1080p);
        let mut hot = ideal();
        hot.thermal_state = MediaThermalState::Critical;
        let decision = controller.observe(&hot).expect("hot");
        assert_eq!(decision.stage, AdaptiveMediaStage::AudioLowBitrate);
        assert_eq!(decision.opus_target_bitrate_bps, Some(16_000));
        assert!(decision.pressures.contains(&AdaptiveMediaPressure::Thermal));
    }

    #[test]
    fn loss_of_realtime_capacity_stops_at_explicit_eventual_boundary() {
        let mut controller = AdaptiveMediaController::new(AdaptiveMediaStage::AudioLowBitrate);
        let mut offline = ideal();
        offline.estimated_bandwidth_bps = 0;
        let decision = controller.observe(&offline).expect("fallback");
        assert_eq!(decision.stage, AdaptiveMediaStage::EventualFallbackRequired);
        assert_eq!(
            decision.deferred_fallbacks,
            vec![
                DeferredMediaFallback::VoiceMessage,
                DeferredMediaFallback::Text,
                DeferredMediaFallback::StoreAndForward,
            ]
        );
        assert!(!decision.requires_media_renegotiation);
    }
}

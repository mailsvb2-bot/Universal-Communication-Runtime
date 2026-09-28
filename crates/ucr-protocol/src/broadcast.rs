use ucr_model::{CapabilityDescriptor, CapabilityMaturity};

pub const MEDIA_COMPOSITION_CAPABILITY: &str = "ucr.media.composition";
pub const RTMP_BROADCAST_CAPABILITY: &str = "ucr.broadcast.rtmp";
pub const HLS_BROADCAST_CAPABILITY: &str = "ucr.broadcast.hls";
pub const DASH_BROADCAST_CAPABILITY: &str = "ucr.broadcast.dash";

pub const MAX_BROADCAST_OUTPUTS: usize = 8;
pub const MAX_BROADCAST_AUDIO_SOURCES: usize = 64;
pub const MAX_BROADCAST_VIDEO_SOURCES: usize = 64;

#[must_use]
pub fn broadcast_capabilities() -> Vec<CapabilityDescriptor> {
    vec![
        CapabilityDescriptor {
            id: MEDIA_COMPOSITION_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
        CapabilityDescriptor {
            id: RTMP_BROADCAST_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
        CapabilityDescriptor {
            id: HLS_BROADCAST_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
        CapabilityDescriptor {
            id: DASH_BROADCAST_CAPABILITY.to_owned(),
            maturity: CapabilityMaturity::Prepared,
            extensions: Vec::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_capabilities_are_prepared_and_distinct() {
        let capabilities = broadcast_capabilities();
        assert_eq!(capabilities.len(), 4);
        assert!(
            capabilities
                .iter()
                .all(|item| item.maturity == CapabilityMaturity::Prepared)
        );
        for (index, item) in capabilities.iter().enumerate() {
            assert!(
                capabilities[index + 1..]
                    .iter()
                    .all(|candidate| candidate.id != item.id)
            );
        }
    }
}

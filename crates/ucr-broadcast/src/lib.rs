#![forbid(unsafe_code)]

use core::fmt;
use std::collections::HashSet;

use ucr_model::{CallId, CapabilityDescriptor, OpaqueId, TenantScope};
use ucr_protocol::{
    DASH_BROADCAST_CAPABILITY, HLS_BROADCAST_CAPABILITY, MAX_BROADCAST_OUTPUTS,
    MAX_BROADCAST_VIDEO_SOURCES, MEDIA_COMPOSITION_CAPABILITY, RTMP_BROADCAST_CAPABILITY,
    broadcast_capabilities,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionLayout {
    Gallery,
    ActiveSpeaker,
    ScreenWithSpeaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BroadcastProtocol {
    Rtmp,
    Hls,
    Dash,
}

impl BroadcastProtocol {
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::Rtmp => RTMP_BROADCAST_CAPABILITY,
            Self::Hls => HLS_BROADCAST_CAPABILITY,
            Self::Dash => DASH_BROADCAST_CAPABILITY,
        }
    }
}

/// Opaque operator/provider configuration reference.
///
/// Stream keys, signed CDN URLs and provider credentials belong behind the provider boundary and
/// must not be embedded in this canonical control value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BroadcastDestination {
    pub destination_id: OpaqueId,
    pub protocol: BroadcastProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionRequest {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub operation_id: OpaqueId,
    pub layout: CompositionLayout,
    pub video_source_ids: Vec<OpaqueId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastRequest {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub operation_id: OpaqueId,
    pub composition_id: OpaqueId,
    pub destinations: Vec<BroadcastDestination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastProviderHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastProviderError {
    InvalidRequest,
    Conflict,
    CapacityExceeded,
    TemporarilyUnavailable,
    Rejected,
    Internal,
}

pub trait CompositionProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn health(&self) -> BroadcastProviderHealth;
    fn capabilities(&self) -> Vec<CapabilityDescriptor>;

    /// Accepts one bounded composition operation.
    ///
    /// Exact retries of the same `operation_id` must be idempotent. Reusing an operation ID for
    /// changed composition semantics must fail with `Conflict`.
    ///
    /// # Errors
    /// Returns a bounded provider failure without mutating canonical Call/Conference state.
    fn compose(&self, request: &CompositionRequest) -> Result<(), BroadcastProviderError>;
}

pub trait BroadcastProvider: fmt::Debug + Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn health(&self) -> BroadcastProviderHealth;
    fn capabilities(&self) -> Vec<CapabilityDescriptor>;

    /// Publishes one already-composed media output to configured destinations.
    ///
    /// The destination IDs resolve to provider/operator configuration outside canonical UCR state;
    /// implementations must not log or persist stream keys through this request.
    ///
    /// # Errors
    /// Returns a bounded provider failure without creating Conference or SFU authority.
    fn publish(&self, request: &BroadcastRequest) -> Result<(), BroadcastProviderError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PreparedBroadcastCapabilities;

impl PreparedBroadcastCapabilities {
    #[must_use]
    pub fn current_capabilities(self) -> Vec<CapabilityDescriptor> {
        broadcast_capabilities()
    }
}

pub fn validate_composition_request(
    request: &CompositionRequest,
) -> Result<(), BroadcastProviderError> {
    if request.video_source_ids.is_empty()
        || request.video_source_ids.len() > MAX_BROADCAST_VIDEO_SOURCES
    {
        return Err(BroadcastProviderError::InvalidRequest);
    }
    let mut sources = HashSet::with_capacity(request.video_source_ids.len());
    if request
        .video_source_ids
        .iter()
        .any(|source| !sources.insert(source.as_str()))
    {
        return Err(BroadcastProviderError::InvalidRequest);
    }
    Ok(())
}

pub fn validate_broadcast_request(
    request: &BroadcastRequest,
) -> Result<(), BroadcastProviderError> {
    if request.destinations.is_empty() || request.destinations.len() > MAX_BROADCAST_OUTPUTS {
        return Err(BroadcastProviderError::InvalidRequest);
    }
    let mut destinations = HashSet::with_capacity(request.destinations.len());
    if request.destinations.iter().any(|destination| {
        !destinations.insert((
            destination.destination_id.as_str(),
            destination.protocol,
        ))
    }) {
        return Err(BroadcastProviderError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{TenantId, TenantScope};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("valid test id")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("broadcast-tenant")),
            namespace_id: None,
        }
    }

    #[test]
    fn composition_supports_required_layouts_and_rejects_duplicate_sources() {
        let request = CompositionRequest {
            scope: scope(),
            call_id: CallId::from_opaque(oid("broadcast-call")),
            operation_id: oid("composition-op"),
            layout: CompositionLayout::ScreenWithSpeaker,
            video_source_ids: vec![oid("screen"), oid("speaker")],
        };
        assert_eq!(validate_composition_request(&request), Ok(()));

        let duplicate = CompositionRequest {
            video_source_ids: vec![oid("screen"), oid("screen")],
            ..request
        };
        assert_eq!(
            validate_composition_request(&duplicate),
            Err(BroadcastProviderError::InvalidRequest)
        );
    }

    #[test]
    fn broadcast_uses_opaque_destination_refs_for_rtmp_hls_and_dash() {
        let request = BroadcastRequest {
            scope: scope(),
            call_id: CallId::from_opaque(oid("broadcast-call")),
            operation_id: oid("broadcast-op"),
            composition_id: oid("composition-op"),
            destinations: vec![
                BroadcastDestination {
                    destination_id: oid("rtmp-target"),
                    protocol: BroadcastProtocol::Rtmp,
                },
                BroadcastDestination {
                    destination_id: oid("hls-target"),
                    protocol: BroadcastProtocol::Hls,
                },
                BroadcastDestination {
                    destination_id: oid("dash-target"),
                    protocol: BroadcastProtocol::Dash,
                },
            ],
        };
        assert_eq!(validate_broadcast_request(&request), Ok(()));
        assert_eq!(
            request.destinations[0].protocol.capability(),
            RTMP_BROADCAST_CAPABILITY
        );
    }

    #[test]
    fn prepared_capabilities_do_not_claim_production() {
        let capabilities = PreparedBroadcastCapabilities.current_capabilities();
        assert!(capabilities.iter().any(|item| {
            item.id == MEDIA_COMPOSITION_CAPABILITY
                && item.maturity == ucr_model::CapabilityMaturity::Prepared
        }));
        assert!(capabilities.iter().all(|item| {
            item.maturity == ucr_model::CapabilityMaturity::Prepared
        }));
    }
}

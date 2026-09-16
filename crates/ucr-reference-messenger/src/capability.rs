/// Canon-required proof areas for the Reference Messenger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofCapability {
    Chat,
    Groups,
    Calls,
    MultiDevice,
    Local,
    Offline,
    P2p,
    Recovery,
    Accessibility,
}

/// Evidence state visible to Phase-40 architecture gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofState {
    /// A consumer-facing public UCR service exists and the Reference Messenger can use it.
    PublicApiAvailable,
    /// Canonical functionality exists below the public boundary but no consumer service exists yet.
    PublicApiGap,
    /// The Reference Messenger has a presentation contract, but platform UI evidence is not complete.
    PresentationModelOnly,
}

/// One explicit Phase-40 evidence item. Gaps are first-class and must not be hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofItem {
    pub capability: ProofCapability,
    pub state: ProofState,
    pub evidence: &'static str,
}

/// Returns the current honest Phase-40 proof matrix.
#[must_use]
pub const fn phase40_proof_matrix() -> [ProofItem; 9] {
    [
        ProofItem {
            capability: ProofCapability::Chat,
            state: ProofState::PublicApiAvailable,
            evidence: "IntegrationService Conversation/Message RPCs",
        },
        ProofItem {
            capability: ProofCapability::Groups,
            state: ProofState::PublicApiAvailable,
            evidence: "GroupService lifecycle/membership/message RPCs",
        },
        ProofItem {
            capability: ProofCapability::Calls,
            state: ProofState::PublicApiAvailable,
            evidence: "CallService signalling RPCs",
        },
        ProofItem {
            capability: ProofCapability::MultiDevice,
            state: ProofState::PublicApiAvailable,
            evidence: "DeviceService lifecycle + SyncService session/checkpoint RPCs",
        },
        ProofItem {
            capability: ProofCapability::Local,
            state: ProofState::PublicApiAvailable,
            evidence: "LocalTransportService authenticated direct transmit RPC",
        },
        ProofItem {
            capability: ProofCapability::Offline,
            state: ProofState::PublicApiAvailable,
            evidence: "StoreForwardService enqueue + payload-free status RPCs",
        },
        ProofItem {
            capability: ProofCapability::P2p,
            state: ProofState::PublicApiGap,
            evidence: "no public mesh/peer-to-peer consumer service",
        },
        ProofItem {
            capability: ProofCapability::Recovery,
            state: ProofState::PublicApiGap,
            evidence: "no public Recovery workflow service",
        },
        ProofItem {
            capability: ProofCapability::Accessibility,
            state: ProofState::PresentationModelOnly,
            evidence: "platform client evidence still required",
        },
    ]
}

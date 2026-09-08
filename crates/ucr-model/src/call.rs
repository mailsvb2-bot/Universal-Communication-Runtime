use crate::{CallId, ConversationRef, EventId, OpaqueId, PrincipalRef, TenantScope};

/// Canonical signalling lifecycle. `Active` means signalling acceptance has completed; it does not
/// claim that an audio/video media path is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSignallingState {
    Inviting,
    Ringing,
    Active,
    Reconnecting,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallParticipantState {
    Invited,
    Ringing,
    Accepted,
    Rejected,
    Busy,
    Left,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallTerminationReason {
    Rejected,
    Busy,
    Cancelled,
    TimedOut,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallReconnectPhase {
    Started,
    Restored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallParticipantUpdateKind {
    Add,
    Remove,
}

/// Canonical participant lifecycle for one `CallSession`. Removed/rejected/busy participants are kept
/// as tombstones so a stale signalling retry cannot silently regain authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallParticipant {
    pub principal: PrincipalRef,
    pub state: CallParticipantState,
    pub joined_revision: u64,
    pub left_revision: Option<u64>,
}

/// Transport-agnostic `CallSession`. It owns only signalling state. Audio, video, E2EE media,
/// adaptive media and route orchestration are deliberately later capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSession {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub conversation: ConversationRef,
    pub initiated_by: PrincipalRef,
    pub participants: Vec<CallParticipant>,
    pub signalling_state: CallSignallingState,
    /// Opaque reference to signalling-owned negotiation metadata. Phase 19 never interprets media
    /// descriptions/codecs/keys; later media owners may resolve this reference.
    pub media_negotiation_ref: Option<OpaqueId>,
    pub media_negotiation_generation: u64,
    pub replication_generation: u64,
    pub revision: u64,
    pub termination_reason: Option<CallTerminationReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallSignalKind {
    Ringing,
    Accept,
    Reject,
    Busy,
    Cancel,
    Timeout,
    Reconnect {
        phase: CallReconnectPhase,
    },
    ParticipantUpdate {
        participant: PrincipalRef,
        kind: CallParticipantUpdateKind,
    },
    MediaRenegotiation {
        negotiation_ref: OpaqueId,
    },
    Terminate {
        reason: CallTerminationReason,
    },
}

/// One idempotent security-sensitive signalling mutation.
///
/// `event_id` is reserved at exact `TenantScope` against unrelated canonical Event/Group/Call facts.
/// The authenticated actor is supplied by Core and is intentionally not caller-controlled here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSignal {
    pub event_id: EventId,
    pub scope: TenantScope,
    pub call_id: CallId,
    pub expected_revision: u64,
    pub kind: CallSignalKind,
}

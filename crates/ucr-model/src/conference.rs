use crate::{CallId, CallSession, GroupId, MediaKind, OpaqueId, PrincipalRef, TenantScope};

/// Phase-30 conference topology. Conferences reuse the canonical Call/Group owners and require
/// encrypted SFU fan-out rather than creating an independent participant graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConferenceTopology {
    Sfu,
}

/// Intent to start one Conference over an existing canonical Group.
///
/// The authenticated caller is always the Call initiator; it is deliberately not caller-controlled
/// inside this value. `invitees` contains only remote Group principals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceStart {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub group_id: GroupId,
    pub invitees: Vec<PrincipalRef>,
}

/// One recipient-owned ephemeral media subscription used only to bound SFU fan-out.
///
/// The authenticated recipient is not embedded here; callers may only mutate their own subscription
/// set. This is routing preference, not Call membership, Group membership, authorization or Delivery
/// evidence, and it is intentionally not durable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConferenceMediaSubscription {
    pub source: PrincipalRef,
    pub media_kind: MediaKind,
}

/// Complete replacement of one participant's ephemeral Conference receive subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceSubscriptionSet {
    pub scope: TenantScope,
    pub call_id: CallId,
    pub subscriptions: Vec<ConferenceMediaSubscription>,
}

/// Non-durable Conference projection derived from canonical Call + Group + MLS state.
///
/// This is a read model, never a second signalling/membership source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceSnapshot {
    pub call: CallSession,
    pub group_id: GroupId,
    pub topology: ConferenceTopology,
    pub group_crypto_epoch: u64,
    pub group_crypto_state_ref: OpaqueId,
}

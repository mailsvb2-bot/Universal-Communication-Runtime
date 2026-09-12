use ucr_model::{
    CapabilityDescriptor, CapabilityMaturity, ConferenceSnapshot, ConferenceStart,
    ConferenceSubscriptionSet, ConferenceTopology, ConversationKind, PrincipalRef, TenantScope,
};

use crate::{GROUP_MLS_CAPABILITY, MAX_CALL_PARTICIPANTS};

pub const CONFERENCE_CAPABILITY: &str = "ucr.conference.sfu";
pub const MAX_CONFERENCE_INVITEES: usize = MAX_CALL_PARTICIPANTS - 1;
pub const MAX_CONFERENCE_SUBSCRIPTIONS_PER_RECIPIENT: usize = 32;
pub const MAX_TRACKED_CONFERENCE_RECIPIENT_SETS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConferenceProtocolError {
    ScopeMismatch,
    EmptyInvitees,
    TooManyInvitees,
    DuplicateInvitee,
    InitiatorIncluded,
    NotGroupCall,
    WrongTopology,
    GroupMismatch,
    MissingMlsState,
    TooManySubscriptions,
    DuplicateSubscription,
    SelfSubscription,
}

#[must_use]
pub fn phase30_conference_capabilities() -> Vec<CapabilityDescriptor> {
    vec![CapabilityDescriptor {
        id: CONFERENCE_CAPABILITY.to_owned(),
        maturity: CapabilityMaturity::Prepared,
        extensions: Vec::new(),
    }]
}

/// Canonicalizes bounded Conference start intent without creating a second Call owner.
///
/// # Errors
/// Rejects cross-scope, empty/duplicate/full invitee sets, and attempts to smuggle the authenticated
/// initiator into the remote invitee list.
pub fn canonical_conference_start(
    start: &ConferenceStart,
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
) -> Result<ConferenceStart, ConferenceProtocolError> {
    if &start.scope != actor_scope {
        return Err(ConferenceProtocolError::ScopeMismatch);
    }
    if start.invitees.is_empty() {
        return Err(ConferenceProtocolError::EmptyInvitees);
    }
    if start.invitees.len() > MAX_CONFERENCE_INVITEES {
        return Err(ConferenceProtocolError::TooManyInvitees);
    }
    if start.invitees.iter().any(|invitee| invitee == actor) {
        return Err(ConferenceProtocolError::InitiatorIncluded);
    }
    for (index, invitee) in start.invitees.iter().enumerate() {
        if start.invitees[index + 1..]
            .iter()
            .any(|candidate| candidate == invitee)
        {
            return Err(ConferenceProtocolError::DuplicateInvitee);
        }
    }
    Ok(start.clone())
}

/// Canonicalizes one authenticated participant's complete ephemeral receive-subscription set.
///
/// Empty sets are valid and mean "unsubscribe from all media". The recipient is the authenticated
/// actor and is intentionally absent from the wire/model value, so callers cannot mutate another
/// participant's routing preference.
///
/// # Errors
/// Rejects cross-scope, self-subscription, duplicate source/media pairs, or sets above the bounded
/// per-recipient ceiling.
pub fn canonical_conference_subscription_set(
    set: &ConferenceSubscriptionSet,
    actor_scope: &TenantScope,
    actor: &PrincipalRef,
) -> Result<ConferenceSubscriptionSet, ConferenceProtocolError> {
    if &set.scope != actor_scope {
        return Err(ConferenceProtocolError::ScopeMismatch);
    }
    if set.subscriptions.len() > MAX_CONFERENCE_SUBSCRIPTIONS_PER_RECIPIENT {
        return Err(ConferenceProtocolError::TooManySubscriptions);
    }
    for (index, subscription) in set.subscriptions.iter().enumerate() {
        if &subscription.source == actor {
            return Err(ConferenceProtocolError::SelfSubscription);
        }
        if set.subscriptions[index + 1..].iter().any(|candidate| {
            candidate.source == subscription.source
                && candidate.media_kind == subscription.media_kind
        }) {
            return Err(ConferenceProtocolError::DuplicateSubscription);
        }
    }
    Ok(set.clone())
}

/// Validates that a Conference projection still maps exactly to one canonical Group Call + MLS
/// epoch and the required SFU topology.
///
/// # Errors
/// Rejects direct calls, stale Group identity, missing MLS state, or non-SFU topology.
pub fn validate_conference_snapshot(
    snapshot: &ConferenceSnapshot,
) -> Result<(), ConferenceProtocolError> {
    if !matches!(
        snapshot.call.conversation.kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    ) {
        return Err(ConferenceProtocolError::NotGroupCall);
    }
    if snapshot.topology != ConferenceTopology::Sfu {
        return Err(ConferenceProtocolError::WrongTopology);
    }
    if snapshot.group_crypto_state_ref.as_str().is_empty() {
        return Err(ConferenceProtocolError::MissingMlsState);
    }
    Ok(())
}

#[must_use]
pub fn is_conference_group_kind(kind: ConversationKind) -> bool {
    matches!(
        kind,
        ConversationKind::PrivateGroup | ConversationKind::PublicGroup
    )
}

#[must_use]
pub fn is_mls_conference_capability(capability: Option<&str>) -> bool {
    capability == Some(GROUP_MLS_CAPABILITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ucr_model::{
        CallId, GroupId, OpaqueId, PrincipalId, PrincipalKind, PrincipalRef, TenantId, TenantScope,
    };

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("id")
    }
    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-conference")),
            namespace_id: None,
        }
    }
    fn principal(name: impl AsRef<str>) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(name.as_ref())),
            kind: PrincipalKind::Person,
        }
    }

    #[test]
    fn conference_start_is_bounded_and_actor_is_not_an_invitee() {
        let alice = principal("alice");
        let start = ConferenceStart {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call")),
            group_id: GroupId::from_opaque(oid("group")),
            invitees: vec![principal("bob")],
        };
        assert_eq!(
            canonical_conference_start(&start, &scope(), &alice),
            Ok(start.clone())
        );
        let mut duplicate = start.clone();
        duplicate.invitees.push(principal("bob"));
        assert_eq!(
            canonical_conference_start(&duplicate, &scope(), &alice),
            Err(ConferenceProtocolError::DuplicateInvitee)
        );
        let mut self_invite = start;
        self_invite.invitees = vec![alice.clone()];
        assert_eq!(
            canonical_conference_start(&self_invite, &scope(), &alice),
            Err(ConferenceProtocolError::InitiatorIncluded)
        );
    }

    #[test]
    fn thousand_person_conference_fits_but_1025th_participant_fails_closed() {
        let alice = principal("alice");
        assert_eq!(MAX_CALL_PARTICIPANTS, 1024);
        assert_eq!(MAX_CONFERENCE_INVITEES, 1023);
        let invitees = (0..999)
            .map(|index| principal(format!("person-{index:04}")))
            .collect::<Vec<_>>();
        let start = ConferenceStart {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call-1000")),
            group_id: GroupId::from_opaque(oid("group-1000")),
            invitees,
        };
        assert_eq!(
            canonical_conference_start(&start, &scope(), &alice),
            Ok(start)
        );

        let too_many = ConferenceStart {
            scope: scope(),
            call_id: CallId::from_opaque(oid("call-1025")),
            group_id: GroupId::from_opaque(oid("group-1025")),
            invitees: (0..1024)
                .map(|index| principal(format!("overflow-{index:04}")))
                .collect(),
        };
        assert_eq!(
            canonical_conference_start(&too_many, &scope(), &alice),
            Err(ConferenceProtocolError::TooManyInvitees)
        );
    }

    #[test]
    fn recipient_owned_subscriptions_are_bounded_unique_and_not_self_targeted() {
        let alice = principal("alice");
        let base = ConferenceSubscriptionSet {
            scope: scope(),
            call_id: CallId::from_opaque(oid("subscription-call")),
            subscriptions: vec![ucr_model::ConferenceMediaSubscription {
                source: principal("bob"),
                media_kind: ucr_model::MediaKind::Video,
            }],
        };
        assert_eq!(
            canonical_conference_subscription_set(&base, &scope(), &alice),
            Ok(base.clone())
        );
        let empty = ConferenceSubscriptionSet {
            subscriptions: Vec::new(),
            ..base.clone()
        };
        assert_eq!(
            canonical_conference_subscription_set(&empty, &scope(), &alice),
            Ok(empty)
        );
        let duplicate = ConferenceSubscriptionSet {
            subscriptions: vec![base.subscriptions[0].clone(), base.subscriptions[0].clone()],
            ..base.clone()
        };
        assert_eq!(
            canonical_conference_subscription_set(&duplicate, &scope(), &alice),
            Err(ConferenceProtocolError::DuplicateSubscription)
        );
        let self_subscription = ConferenceSubscriptionSet {
            subscriptions: vec![ucr_model::ConferenceMediaSubscription {
                source: alice.clone(),
                media_kind: ucr_model::MediaKind::Audio,
            }],
            ..base.clone()
        };
        assert_eq!(
            canonical_conference_subscription_set(&self_subscription, &scope(), &alice),
            Err(ConferenceProtocolError::SelfSubscription)
        );
        let oversized = ConferenceSubscriptionSet {
            subscriptions: (0..=MAX_CONFERENCE_SUBSCRIPTIONS_PER_RECIPIENT)
                .map(|index| ucr_model::ConferenceMediaSubscription {
                    source: principal(format!("source-{index:02}")),
                    media_kind: ucr_model::MediaKind::Video,
                })
                .collect(),
            ..base
        };
        assert_eq!(
            canonical_conference_subscription_set(&oversized, &scope(), &alice),
            Err(ConferenceProtocolError::TooManySubscriptions)
        );
    }
}

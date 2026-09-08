from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"marker missing in {path}: {old[:160]!r}")
    target.write_text(text.replace(old, new, 1))

# Release truth.
replace_once(
    "README.md",
    "**Phase 17 — Chat (Prepared/reference complete; Phase 18 Groups not started).**",
    "**Phase 18 — Groups (Prepared/reference complete; Phase 19 not started).**",
)
replace_once(
    "README.md",
    "The Chat capability remains Prepared; Phase 18 Groups and Phase 24 Transport Orchestrator are not started.",
    "The Chat capability remains Prepared. Phase 18 now adds a Prepared Groups reference layer with canonical private/public Group aggregates, restart-safe membership tombstones, role/ownership/history/public-policy transitions, deterministic Event-ID mutation deduplication, SQLite schema v21, and membership-gated access to the existing canonical Message owner without a second Conversation/Message/Delivery/Identity brain. Group membership and revision changes are atomic, Service Account Message provenance remains Core-owned, and v20 migration invents no Groups or memberships. The Groups capability remains Prepared; Phase 19 is not started, and Phase 24 Transport Orchestrator is not started.",
)

# Repository guards.
replace_once(
    ".github/workflows/ci.yml",
    "          test -s spec/local-transport.md &&\n          test -s spec/chat.md",
    "          test -s spec/local-transport.md &&\n          test -s spec/chat.md &&\n          test -s spec/groups.md",
)
replace_once(
    ".github/workflows/ci.yml",
    "          test -s docs/adr/0054-phase16-local-direct-transport-reuses-canonical-transport-and-crypto-owners.md &&\n          test -s docs/adr/0055-phase17-chat-reuses-canonical-conversation-message-and-delivery-owners.md",
    "          test -s docs/adr/0054-phase16-local-direct-transport-reuses-canonical-transport-and-crypto-owners.md &&\n          test -s docs/adr/0055-phase17-chat-reuses-canonical-conversation-message-and-delivery-owners.md &&\n          test -s docs/adr/0056-phase18-groups-reuse-canonical-conversation-message-and-authorization-owners.md",
)

# Strong SQLite restart/security evidence for the actual Group owner.
group_store = Path("crates/ucr-storage-sqlite/src/group_store.rs")
text = group_store.read_text()
if "fn membership_tombstone_and_group_message_gate_survive_restart" not in text:
    text += r'''

#[cfg(test)]
mod phase18_restart_security_tests {
    use ucr_core::{DurableRecordStatus, DurableStoreError, GroupMessageStore, GroupStore};
    use ucr_model::*;

    use super::SqliteLocalStore;
    use crate::message_store::tests::{TestDb, message, scope};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }

    fn principal(value: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind: PrincipalKind::Person,
        }
    }

    fn subject(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: principal(value),
        }
    }

    fn group_fixture() -> (ConversationRecord, GroupRecord, ScopedPrincipal) {
        let owner = subject("phase18-owner");
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("phase18-group-conversation")),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid("phase18-group")),
            conversation: conversation.conversation.clone(),
            ownership: GroupOwnership::PersonOwned(owner.principal.clone()),
            history_policy: GroupHistoryPolicy::FullHistory,
            delivery_policy: DeliveryPolicy::Durable,
            crypto_state: GroupCryptoState {
                capability_id: None,
                epoch: 0,
                state_ref: None,
            },
            public_policy: None,
            media_state: GroupMediaState::Idle,
            bridge_mappings: Vec::new(),
            replication_generation: 0,
            revision: 0,
        };
        (conversation, group, owner)
    }

    fn member_message(conversation: &ConversationRef, member: &PrincipalRef, suffix: &str) -> MessageEnvelope {
        let mut value = message(format!("group-{suffix}").as_bytes());
        value.message_id = MessageId::from_opaque(oid(&format!("phase18-message-{suffix}")));
        value.conversation = conversation.clone();
        value.delivery_policy = DeliveryPolicy::Durable;
        value.origin.principal_id = Some(member.principal_id.clone());
        value.correlation.correlation_id = oid(&format!("phase18-correlation-{suffix}"));
        value.correlation.idempotency_key = Some(format!("phase18-idempotency-{suffix}"));
        value
    }

    #[test]
    fn membership_tombstone_and_group_message_gate_survive_restart() {
        let db = TestDb::new();
        let (conversation, group, owner) = group_fixture();
        let member = subject("phase18-member");
        let add = GroupChange {
            event_id: EventId::from_opaque(oid("phase18-add-member")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 0,
            kind: GroupChangeKind::AddMember {
                member: member.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        };
        let remove = GroupChange {
            event_id: EventId::from_opaque(oid("phase18-remove-member")),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: 1,
            kind: GroupChangeKind::RemoveMember {
                member: member.principal.clone(),
            },
            next_crypto_state: None,
        };
        let first_message = member_message(&conversation.conversation, &member.principal, "before-remove");

        {
            let store = SqliteLocalStore::open(db.path()).expect("open Group store");
            assert_eq!(
                store.create_group(&conversation, &group, &owner),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.apply_group_change(&owner, &add),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.persist_group_message(&member, &first_message),
                Ok(DurableRecordStatus::Persisted)
            );
        }

        {
            let reopened = SqliteLocalStore::open(db.path()).expect("reopen before removal");
            assert_eq!(
                reopened
                    .group(&scope(), &group.group_id)
                    .expect("load group")
                    .expect("group exists")
                    .revision,
                1
            );
            assert!(
                reopened
                    .group_message(&member, &scope(), &first_message.message_id)
                    .expect("member history read")
                    .is_some()
            );
            assert_eq!(
                reopened.apply_group_change(&owner, &remove),
                Ok(DurableRecordStatus::Persisted)
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen after removal");
        let tombstone = reopened
            .group_membership(&scope(), &group.group_id, &member.principal)
            .expect("load membership")
            .expect("tombstone exists");
        assert_eq!(tombstone.state, GroupMemberState::Removed);
        assert_eq!(tombstone.removed_revision, Some(2));
        assert_eq!(
            reopened.apply_group_change(&owner, &remove),
            Ok(DurableRecordStatus::Duplicate)
        );
        assert!(
            reopened
                .group_message(&member, &scope(), &first_message.message_id)
                .expect("removed member history query")
                .is_none()
        );
        let denied = member_message(&conversation.conversation, &member.principal, "after-remove");
        assert_eq!(
            reopened.persist_group_message(&member, &denied),
            Err(DurableStoreError::PermissionDenied)
        );
        assert_eq!(
            reopened
                .group(&scope(), &group.group_id)
                .expect("load final group")
                .expect("final group exists")
                .revision,
            2
        );
    }
}
'''
group_store.write_text(text)

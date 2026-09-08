from pathlib import Path

path = Path("crates/ucr-protocol/src/group.rs")
text = path.read_text()

old_call = '''    apply_change_kind(
        &mut group,
        &mut memberships,
        actor,
        actor_index,
        actor_role,
        change,
        next_revision,
        add_history_floor_logical_order,
    )?;'''
new_call = '''    let context = GroupChangeContext {
        actor,
        actor_index,
        actor_role,
        next_revision,
        history_floor: add_history_floor_logical_order,
    };
    apply_change_kind(&mut group, &mut memberships, change, &context)?;'''
if old_call not in text:
    raise SystemExit("apply_change_kind call marker missing")
text = text.replace(old_call, new_call, 1)

start = text.index("fn apply_change_kind(")
end = text.index("fn apply_add_member(", start)
new_dispatch = r'''struct GroupChangeContext<'a> {
    actor: &'a PrincipalRef,
    actor_index: usize,
    actor_role: GroupRole,
    next_revision: u64,
    history_floor: Option<u64>,
}

fn apply_change_kind(
    group: &mut GroupRecord,
    memberships: &mut Vec<GroupMembership>,
    change: &GroupChange,
    context: &GroupChangeContext<'_>,
) -> Result<(), GroupError> {
    match &change.kind {
        GroupChangeKind::AddMember { member, role } => apply_add_member(
            group,
            memberships,
            context.actor_role,
            member,
            *role,
            context.next_revision,
            context.history_floor,
        ),
        GroupChangeKind::RemoveMember { member } => apply_remove_member(
            memberships,
            context.actor,
            context.actor_role,
            member,
            context.next_revision,
        ),
        GroupChangeKind::ChangeRole { member, role } => {
            apply_role_change(memberships, context.actor_role, member, *role)
        }
        GroupChangeKind::TransferOwnership { new_owner } => apply_ownership_transfer(
            group,
            memberships,
            context.actor,
            context.actor_index,
            context.actor_role,
            new_owner,
        ),
        GroupChangeKind::SetHistoryPolicy { policy } => {
            apply_history_policy(group, context.actor_role, policy)
        }
        GroupChangeKind::SetPublicPolicy { policy } => {
            apply_public_policy(group, context.actor_role, policy)
        }
        GroupChangeKind::SetDeliveryPolicy { policy } => {
            require_manage_group(context.actor_role)?;
            group.delivery_policy = *policy;
            Ok(())
        }
    }
}

'''
text = text[:start] + new_dispatch + text[end:]

marker = "pub fn validate_group_member_list_limit(max_items: usize) -> Result<(), GroupError> {"
doc = "/// Validates a bounded Group membership-list request size.\n///\n/// # Errors\n/// Returns `InvalidListLimit` for zero or above-limit requests.\n"
if doc + marker not in text:
    if marker not in text:
        raise SystemExit("list-limit marker missing")
    text = text.replace(marker, doc + marker, 1)

path.write_text(text)

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError};
use ucr_group_mls::{
    AtomicMlsGroupChangeResult, DeviceKeyPackage, GroupMlsAtomicStore, GroupMlsStoreError,
    MlsCommitArtifacts, MlsDeviceAdmission, MlsGroupState, MlsTransitionInput,
    create_device_key_package, create_group, current_crypto_state, decode_key_package, load_group,
    member_device_ids, mls_change_request_fingerprint, own_device_id, sqlite_provider,
    stage_transition,
};
use ucr_model::{
    ConversationRecord, DeviceId, GroupChange, GroupChangeKind, GroupCryptoState, GroupId,
    GroupRecord, OpaqueId, PrincipalKind, PrincipalRef, ScopedPrincipal, TenantScope,
};
use ucr_protocol::{
    GROUP_MLS_CAPABILITY, device_allows_protected_access, group_change_fingerprint,
};

use super::{
    SqliteLocalStore, group_store, map_sqlite_error, namespace_storage_key,
    principal_identity_binding_store,
};

impl GroupMlsAtomicStore for SqliteLocalStore {
    fn create_mls_device_key_package(
        &self,
        scope: &TenantScope,
        device_id: &DeviceId,
    ) -> Result<DeviceKeyPackage, GroupMlsStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        require_active_device(&transaction, scope, device_id)?;
        let package = {
            let provider = sqlite_provider(&transaction);
            create_device_key_package(&provider, scope, device_id)?
        };
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(package)
    }

    fn create_mls_backed_group(
        &self,
        conversation: &ConversationRecord,
        group_template: &GroupRecord,
        creator: &ScopedPrincipal,
        creator_device_id: &DeviceId,
        creator_key_package: &DeviceKeyPackage,
    ) -> Result<(DurableRecordStatus, GroupRecord), GroupMlsStoreError> {
        if group_template.crypto_state.capability_id.is_some()
            || group_template.crypto_state.epoch != 0
            || group_template.crypto_state.state_ref.is_some()
        {
            return Err(GroupMlsStoreError::InvalidBootstrap);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        require_device_for_principal(
            &transaction,
            &creator.scope,
            &creator.principal,
            creator_device_id,
            true,
        )?;
        let (status, group) = {
            let provider = sqlite_provider(&transaction);
            let decoded = decode_key_package(
                &provider,
                &creator.scope,
                creator_device_id,
                &creator_key_package.bytes,
            )?;
            if decoded.leaf_node().signature_key().as_slice()
                != creator_key_package.signer_public_key.as_slice()
            {
                return Err(GroupMlsStoreError::ActorDeviceMismatch);
            }
            let canonical_existing = group_store::load_group_from(
                &transaction,
                &group_template.scope,
                &group_template.group_id,
            )?;
            let mls_existing =
                load_group(&provider, &group_template.scope, &group_template.group_id)?;
            let mut group = group_template.clone();
            let status = match (canonical_existing, mls_existing) {
                (None, None) => {
                    let (_mls_group, state) = create_group(
                        &provider,
                        &group.scope,
                        &group.group_id,
                        creator_device_id,
                        &creator_key_package.signer_public_key,
                    )?;
                    group.crypto_state = state;
                    group_store::create_group_in_transaction(
                        &transaction,
                        conversation,
                        &group,
                        creator,
                    )?
                }
                (Some(existing), Some(mls_group)) => {
                    group.crypto_state =
                        current_crypto_state(&group.scope, &group.group_id, &mls_group)?;
                    if existing != group {
                        return Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict));
                    }
                    group_store::create_group_in_transaction(
                        &transaction,
                        conversation,
                        &group,
                        creator,
                    )?
                }
                _ => return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt)),
            };
            (status, group)
        };
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok((status, group))
    }

    fn apply_mls_backed_group_change(
        &self,
        actor: &ScopedPrincipal,
        actor_device_id: &DeviceId,
        requested_change: &GroupChange,
        added_devices: &[MlsDeviceAdmission],
    ) -> Result<AtomicMlsGroupChangeResult, GroupMlsStoreError> {
        if requested_change.next_crypto_state.is_some() || actor.scope != requested_change.scope {
            return Err(GroupMlsStoreError::InvalidChangeMaterial);
        }
        let request_fingerprint =
            mls_change_request_fingerprint(requested_change, actor_device_id, added_devices)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(outcome) = existing_transition_outcome(
            &transaction,
            actor,
            actor_device_id,
            requested_change,
            &request_fingerprint,
        )? {
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(outcome);
        }
        let outcome = apply_new_transition_in_transaction(
            &transaction,
            actor,
            actor_device_id,
            requested_change,
            added_devices,
            &request_fingerprint,
        )?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(outcome)
    }
}

#[derive(Debug)]
struct StoredTransition {
    group_id: GroupId,
    actor_device_id: DeviceId,
    request_fingerprint: [u8; 32],
    artifacts: MlsCommitArtifacts,
}

fn existing_transition_outcome(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    actor_device_id: &DeviceId,
    requested_change: &GroupChange,
    request_fingerprint: &[u8; 32],
) -> Result<Option<AtomicMlsGroupChangeResult>, GroupMlsStoreError> {
    if let Some(stored) = load_transition(
        transaction,
        &requested_change.scope,
        requested_change.event_id.as_opaque().as_str(),
    )? {
        return duplicate_transition(
            transaction,
            actor,
            actor_device_id,
            requested_change,
            request_fingerprint,
            stored,
        )
        .map(Some);
    }
    if group_store::load_change_record(
        transaction,
        &requested_change.scope,
        requested_change.event_id.as_opaque().as_str(),
    )?
    .is_some()
    {
        return Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict));
    }
    Ok(None)
}

fn apply_new_transition_in_transaction(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    actor_device_id: &DeviceId,
    requested_change: &GroupChange,
    added_devices: &[MlsDeviceAdmission],
    request_fingerprint: &[u8; 32],
) -> Result<AtomicMlsGroupChangeResult, GroupMlsStoreError> {
    let canonical_group = group_store::load_group_from(
        transaction,
        &requested_change.scope,
        &requested_change.group_id,
    )?
    .ok_or(GroupMlsStoreError::Durable(
        DurableStoreError::InvalidRecord,
    ))?;
    if canonical_group.crypto_state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY) {
        return Err(GroupMlsStoreError::InvalidChangeMaterial);
    }
    require_device_for_principal(
        transaction,
        &actor.scope,
        &actor.principal,
        actor_device_id,
        true,
    )?;
    let input = prepare_transition_input(
        transaction,
        requested_change,
        added_devices,
        &canonical_group,
    )?;
    let (artifacts, mut mls_group) = stage_verified_transition(
        transaction,
        actor_device_id,
        requested_change,
        &canonical_group.crypto_state,
        &input,
    )?;
    let mut applied_change = requested_change.clone();
    applied_change.next_crypto_state = Some(artifacts.next_crypto_state.clone());
    let status =
        group_store::apply_group_change_in_transaction(transaction, actor, &applied_change, true)?;
    if status != DurableRecordStatus::Persisted {
        return Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict));
    }
    insert_transition(
        transaction,
        actor_device_id,
        request_fingerprint,
        &applied_change,
        &artifacts,
    )?;
    {
        let provider = sqlite_provider(transaction);
        ucr_group_mls::merge_pending(
            &provider,
            &mut mls_group,
            &requested_change.scope,
            &requested_change.group_id,
            &artifacts.next_crypto_state,
        )?;
    }
    Ok(AtomicMlsGroupChangeResult {
        status,
        applied_change,
        artifacts: Some(artifacts),
    })
}

fn prepare_transition_input(
    transaction: &Transaction<'_>,
    requested_change: &GroupChange,
    added_devices: &[MlsDeviceAdmission],
    canonical_group: &GroupRecord,
) -> Result<MlsTransitionInput, GroupMlsStoreError> {
    match &requested_change.kind {
        GroupChangeKind::AddMember { member, .. } => {
            if added_devices.is_empty() {
                return Err(GroupMlsStoreError::InvalidChangeMaterial);
            }
            let current_devices = {
                let provider = sqlite_provider(transaction);
                let group = load_group(
                    &provider,
                    &requested_change.scope,
                    &requested_change.group_id,
                )?
                .ok_or(GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
                if current_crypto_state(
                    &requested_change.scope,
                    &requested_change.group_id,
                    &group,
                )? != canonical_group.crypto_state
                {
                    return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt));
                }
                member_device_ids(&group, &requested_change.scope)?
            };
            for admission in added_devices {
                if current_devices.contains(&admission.device_id) {
                    return Err(GroupMlsStoreError::TargetDeviceMismatch);
                }
                require_device_for_principal(
                    transaction,
                    &requested_change.scope,
                    member,
                    &admission.device_id,
                    true,
                )?;
            }
            Ok(MlsTransitionInput::Add(added_devices.to_vec()))
        }
        GroupChangeKind::RemoveMember { member } => {
            if !added_devices.is_empty() {
                return Err(GroupMlsStoreError::InvalidChangeMaterial);
            }
            let current_devices =
                current_mls_devices(transaction, requested_change, canonical_group)?;
            let mut removed = Vec::new();
            for device_id in current_devices {
                if device_belongs_to_principal(
                    transaction,
                    &requested_change.scope,
                    member,
                    &device_id,
                    false,
                )? {
                    removed.push(device_id);
                }
            }
            if removed.is_empty() {
                return Err(GroupMlsStoreError::TargetDeviceMismatch);
            }
            Ok(MlsTransitionInput::Remove(removed))
        }
        GroupChangeKind::ChangeRole { .. } | GroupChangeKind::TransferOwnership { .. } => {
            if !added_devices.is_empty() {
                return Err(GroupMlsStoreError::InvalidChangeMaterial);
            }
            current_mls_devices(transaction, requested_change, canonical_group)?;
            Ok(MlsTransitionInput::Rekey)
        }
        GroupChangeKind::SetHistoryPolicy { .. }
        | GroupChangeKind::SetPublicPolicy { .. }
        | GroupChangeKind::SetDeliveryPolicy { .. } => {
            Err(GroupMlsStoreError::InvalidChangeMaterial)
        }
    }
}

fn current_mls_devices(
    transaction: &Transaction<'_>,
    requested_change: &GroupChange,
    canonical_group: &GroupRecord,
) -> Result<Vec<DeviceId>, GroupMlsStoreError> {
    let provider = sqlite_provider(transaction);
    let group = load_group(
        &provider,
        &requested_change.scope,
        &requested_change.group_id,
    )?
    .ok_or(GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    if current_crypto_state(&requested_change.scope, &requested_change.group_id, &group)?
        != canonical_group.crypto_state
    {
        return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt));
    }
    member_device_ids(&group, &requested_change.scope).map_err(Into::into)
}

fn stage_verified_transition(
    transaction: &Transaction<'_>,
    actor_device_id: &DeviceId,
    requested_change: &GroupChange,
    expected_crypto_state: &GroupCryptoState,
    input: &MlsTransitionInput,
) -> Result<(MlsCommitArtifacts, MlsGroupState), GroupMlsStoreError> {
    let provider = sqlite_provider(transaction);
    let mut group = load_group(
        &provider,
        &requested_change.scope,
        &requested_change.group_id,
    )?
    .ok_or(GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    if current_crypto_state(&requested_change.scope, &requested_change.group_id, &group)?
        != *expected_crypto_state
    {
        return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt));
    }
    if own_device_id(&group, &requested_change.scope)? != *actor_device_id {
        return Err(GroupMlsStoreError::ActorDeviceMismatch);
    }
    let artifacts = stage_transition(
        &provider,
        &mut group,
        &requested_change.scope,
        &requested_change.group_id,
        input,
    )?;
    Ok((artifacts, group))
}

fn duplicate_transition(
    transaction: &Transaction<'_>,
    actor: &ScopedPrincipal,
    actor_device_id: &DeviceId,
    requested_change: &GroupChange,
    request_fingerprint: &[u8; 32],
    stored: StoredTransition,
) -> Result<AtomicMlsGroupChangeResult, GroupMlsStoreError> {
    if stored.group_id != requested_change.group_id
        || stored.actor_device_id != *actor_device_id
        || stored.request_fingerprint != *request_fingerprint
    {
        return Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict));
    }
    let (recorded_actor, recorded_fingerprint) = group_store::load_change_record(
        transaction,
        &requested_change.scope,
        requested_change.event_id.as_opaque().as_str(),
    )?
    .ok_or(GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    if recorded_actor != actor.principal {
        return Err(GroupMlsStoreError::Durable(
            DurableStoreError::PermissionDenied,
        ));
    }
    let mut applied_change = requested_change.clone();
    applied_change.next_crypto_state = Some(stored.artifacts.next_crypto_state.clone());
    let expected = group_change_fingerprint(&applied_change)
        .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    if expected != recorded_fingerprint {
        return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt));
    }
    Ok(AtomicMlsGroupChangeResult {
        status: DurableRecordStatus::Duplicate,
        applied_change,
        artifacts: Some(stored.artifacts),
    })
}

fn require_active_device(
    connection: &Connection,
    scope: &TenantScope,
    device_id: &DeviceId,
) -> Result<ucr_model::DeviceDescriptor, GroupMlsStoreError> {
    let device = super::device_store::load_device(connection, scope, device_id)?
        .ok_or(GroupMlsStoreError::TargetDeviceMismatch)?;
    if !device_allows_protected_access(&device) {
        return Err(GroupMlsStoreError::TargetDeviceMismatch);
    }
    Ok(device)
}

fn require_device_for_principal(
    connection: &Connection,
    scope: &TenantScope,
    principal: &PrincipalRef,
    device_id: &DeviceId,
    require_active: bool,
) -> Result<ucr_model::DeviceDescriptor, GroupMlsStoreError> {
    let device = super::device_store::load_device(connection, scope, device_id)?
        .ok_or(GroupMlsStoreError::TargetDeviceMismatch)?;
    if require_active && !device_allows_protected_access(&device) {
        return Err(GroupMlsStoreError::TargetDeviceMismatch);
    }
    if principal.kind == PrincipalKind::Device {
        if principal.principal_id.as_opaque().as_wire_bytes()
            != device_id.as_opaque().as_wire_bytes()
        {
            return Err(GroupMlsStoreError::TargetDeviceMismatch);
        }
        return Ok(device);
    }
    let binding =
        principal_identity_binding_store::load_binding_from(connection, scope, principal)?
            .ok_or(GroupMlsStoreError::TargetDeviceMismatch)?;
    if binding.identity_id != device.identity_id {
        return Err(GroupMlsStoreError::TargetDeviceMismatch);
    }
    Ok(device)
}

fn device_belongs_to_principal(
    connection: &Connection,
    scope: &TenantScope,
    principal: &PrincipalRef,
    device_id: &DeviceId,
    require_active: bool,
) -> Result<bool, GroupMlsStoreError> {
    match require_device_for_principal(connection, scope, principal, device_id, require_active) {
        Ok(_) => Ok(true),
        Err(GroupMlsStoreError::TargetDeviceMismatch) => Ok(false),
        Err(error) => Err(error),
    }
}

fn insert_transition(
    transaction: &Transaction<'_>,
    actor_device_id: &DeviceId,
    request_fingerprint: &[u8; 32],
    change: &GroupChange,
    artifacts: &MlsCommitArtifacts,
) -> Result<(), GroupMlsStoreError> {
    let namespace = namespace_storage_key(&change.scope);
    let state_ref = artifacts
        .next_crypto_state
        .state_ref
        .as_ref()
        .ok_or(GroupMlsStoreError::InvalidChangeMaterial)?;
    transaction
        .execute(
            "INSERT INTO group_mls_transitions (
                tenant_id, namespace_present, namespace_id, event_id, group_id,
                actor_device_id, request_fingerprint, commit_bytes, welcome_bytes,
                crypto_epoch, crypto_state_ref
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                change.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                change.event_id.as_opaque().as_str(),
                change.group_id.as_opaque().as_str(),
                actor_device_id.as_opaque().as_str(),
                request_fingerprint.as_slice(),
                artifacts.commit.as_slice(),
                artifacts.welcome.as_deref(),
                artifacts.next_crypto_state.epoch.to_be_bytes().as_slice(),
                state_ref.as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_transition(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<Option<StoredTransition>, GroupMlsStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT group_id, actor_device_id, request_fingerprint, commit_bytes,
                    welcome_bytes, crypto_epoch, crypto_state_ref
             FROM group_mls_transitions
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event_id,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((group_id, actor_device_id, fingerprint, commit, welcome, epoch, state_ref)) = row
    else {
        return Ok(None);
    };
    let request_fingerprint: [u8; 32] = fingerprint
        .try_into()
        .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    let epoch: [u8; 8] = epoch
        .try_into()
        .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    let state_ref = OpaqueId::new(state_ref)
        .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    Ok(Some(StoredTransition {
        group_id: GroupId::from_opaque(
            OpaqueId::new(group_id)
                .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?,
        ),
        actor_device_id: DeviceId::from_opaque(
            OpaqueId::new(actor_device_id)
                .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?,
        ),
        request_fingerprint,
        artifacts: MlsCommitArtifacts {
            commit,
            welcome,
            next_crypto_state: GroupCryptoState {
                capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
                epoch: u64::from_be_bytes(epoch),
                state_ref: Some(state_ref),
            },
        },
    }))
}

#[cfg(test)]
mod phase29_atomic_mls_tests {
    use ucr_core::{
        DeviceLifecycleStore, GroupStore, IdentityStore, PrincipalIdentityBindingStore,
    };
    use ucr_group_mls::{GroupMlsAtomicStore, GroupMlsStoreError, MlsDeviceAdmission};
    use ucr_model::*;

    use super::*;
    use crate::message_store::tests::{TestDb, scope};

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }
    fn principal(value: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(oid(value)),
            kind: PrincipalKind::Person,
        }
    }
    fn identity(value: &str) -> IdentityId {
        IdentityId::from_opaque(oid(value))
    }
    fn device(value: &str) -> DeviceId {
        DeviceId::from_opaque(oid(value))
    }
    fn subject(value: &str) -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: principal(value),
        }
    }

    fn install_person(store: &SqliteLocalStore, name: &str, devices: &[&str]) {
        let identity_id = identity(&format!("identity-{name}"));
        store
            .persist_identity(&IdentityRecord {
                scope: scope(),
                identity_id: identity_id.clone(),
                ownership: IdentityOwnership::UcrNative,
                evidence: IdentityEvidence::DeviceVerified,
                expires_at_unix_ms: None,
            })
            .expect("identity");
        store
            .persist_principal_identity_binding(&PrincipalIdentityBinding {
                scope: scope(),
                principal: principal(name),
                identity_id: identity_id.clone(),
            })
            .expect("principal identity binding");
        for name in devices {
            store
                .register_device(
                    &scope(),
                    &DeviceDescriptor {
                        device_id: device(name),
                        identity_id: identity_id.clone(),
                        state: DeviceLifecycleState::Active,
                    },
                )
                .expect("device");
        }
    }

    fn group_template(owner: &ScopedPrincipal) -> (ConversationRecord, GroupRecord) {
        let conversation = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("phase29-mls-conversation")),
                kind: ConversationKind::PrivateGroup,
            },
            parent_conversation_id: None,
        };
        let group = GroupRecord {
            scope: scope(),
            group_id: GroupId::from_opaque(oid("phase29-mls-group")),
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
        (conversation, group)
    }

    fn add_change(
        group: &GroupRecord,
        event: &str,
        member: &ScopedPrincipal,
        revision: u64,
    ) -> GroupChange {
        GroupChange {
            event_id: EventId::from_opaque(oid(event)),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: revision,
            kind: GroupChangeKind::AddMember {
                member: member.principal.clone(),
                role: GroupRole::Member,
            },
            next_crypto_state: None,
        }
    }

    fn remove_change(
        group: &GroupRecord,
        event: &str,
        member: &ScopedPrincipal,
        revision: u64,
    ) -> GroupChange {
        GroupChange {
            event_id: EventId::from_opaque(oid(event)),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: revision,
            kind: GroupChangeKind::RemoveMember {
                member: member.principal.clone(),
            },
            next_crypto_state: None,
        }
    }

    fn bootstrap(store: &SqliteLocalStore) -> (GroupRecord, ScopedPrincipal, ScopedPrincipal) {
        let owner = subject("phase29-owner");
        let bob = subject("phase29-bob");
        install_person(store, "phase29-owner", &["phase29-owner-device"]);
        install_person(
            store,
            "phase29-bob",
            &["phase29-bob-device-1", "phase29-bob-device-2"],
        );
        let owner_package = store
            .create_mls_device_key_package(&scope(), &device("phase29-owner-device"))
            .unwrap();
        let (conversation, template) = group_template(&owner);
        let (status, group) = store
            .create_mls_backed_group(
                &conversation,
                &template,
                &owner,
                &device("phase29-owner-device"),
                &owner_package,
            )
            .unwrap();
        assert_eq!(status, DurableRecordStatus::Persisted);
        assert_eq!(group.crypto_state.epoch, 0);
        (group, owner, bob)
    }

    fn admission(store: &SqliteLocalStore, device_name: &str) -> MlsDeviceAdmission {
        let device_id = device(device_name);
        let package = store
            .create_mls_device_key_package(&scope(), &device_id)
            .unwrap();
        MlsDeviceAdmission {
            device_id,
            key_package: package.bytes,
        }
    }

    fn mls_snapshot(
        store: &SqliteLocalStore,
        group: &GroupRecord,
    ) -> (GroupCryptoState, Vec<DeviceId>) {
        let connection = store.lock_connection().unwrap();
        let provider = sqlite_provider(&connection);
        let mls = load_group(&provider, &scope(), &group.group_id)
            .unwrap()
            .unwrap();
        let state = current_crypto_state(&scope(), &group.group_id, &mls).unwrap();
        let devices = member_device_ids(&mls, &scope()).unwrap();
        (state, devices)
    }

    #[test]
    fn stale_group_revision_rolls_back_staged_mls_writes() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).unwrap();
        let (group, owner, bob) = bootstrap(&store);
        let bob_admission = admission(&store, "phase29-bob-device-1");
        let before = mls_snapshot(&store, &group);
        let stale = add_change(&group, "phase29-stale-add", &bob, 99);
        assert!(matches!(
            store.apply_mls_backed_group_change(
                &owner,
                &device("phase29-owner-device"),
                &stale,
                std::slice::from_ref(&bob_admission)
            ),
            Err(GroupMlsStoreError::Durable(
                DurableStoreError::Conflict | DurableStoreError::InvalidRecord
            ))
        ));
        assert_eq!(mls_snapshot(&store, &group), before);
        assert!(
            store
                .group_membership(&scope(), &group.group_id, &bob.principal)
                .unwrap()
                .is_none()
        );
        let valid = add_change(&group, "phase29-valid-add", &bob, 0);
        let result = store
            .apply_mls_backed_group_change(
                &owner,
                &device("phase29-owner-device"),
                &valid,
                &[bob_admission],
            )
            .unwrap();
        assert_eq!(result.status, DurableRecordStatus::Persisted);
        assert_eq!(
            result
                .applied_change
                .next_crypto_state
                .as_ref()
                .unwrap()
                .epoch,
            1
        );
    }

    #[test]
    fn exact_retry_survives_restart_without_advancing_epoch_and_changed_retry_conflicts() {
        let db = TestDb::new();
        let (group, owner, bob, first_admission, first_state) = {
            let store = SqliteLocalStore::open(db.path()).unwrap();
            let (group, owner, bob) = bootstrap(&store);
            let admission = admission(&store, "phase29-bob-device-1");
            let change = add_change(&group, "phase29-retry-add", &bob, 0);
            let result = store
                .apply_mls_backed_group_change(
                    &owner,
                    &device("phase29-owner-device"),
                    &change,
                    std::slice::from_ref(&admission),
                )
                .unwrap();
            (
                group,
                owner,
                bob,
                admission,
                result.applied_change.next_crypto_state.unwrap(),
            )
        };
        let store = SqliteLocalStore::open(db.path()).unwrap();
        let change = add_change(&group, "phase29-retry-add", &bob, 0);
        let duplicate = store
            .apply_mls_backed_group_change(
                &owner,
                &device("phase29-owner-device"),
                &change,
                &[first_admission],
            )
            .unwrap();
        assert_eq!(duplicate.status, DurableRecordStatus::Duplicate);
        assert_eq!(
            duplicate.applied_change.next_crypto_state.as_ref(),
            Some(&first_state)
        );
        assert_eq!(mls_snapshot(&store, &group).0, first_state);
        let changed = admission(&store, "phase29-bob-device-2");
        assert_eq!(
            store.apply_mls_backed_group_change(
                &owner,
                &device("phase29-owner-device"),
                &change,
                &[changed],
            ),
            Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict))
        );
        assert_eq!(mls_snapshot(&store, &group).0, first_state);
    }

    #[test]
    fn removing_principal_removes_all_admitted_devices_in_one_epoch_and_survives_restart() {
        let db = TestDb::new();
        let (group, owner, bob, removed_state) = {
            let store = SqliteLocalStore::open(db.path()).unwrap();
            let (group, owner, bob) = bootstrap(&store);
            let first = admission(&store, "phase29-bob-device-1");
            let second = admission(&store, "phase29-bob-device-2");
            let add = add_change(&group, "phase29-add-two-devices", &bob, 0);
            let added = store
                .apply_mls_backed_group_change(
                    &owner,
                    &device("phase29-owner-device"),
                    &add,
                    &[first, second],
                )
                .unwrap();
            assert_eq!(
                added
                    .applied_change
                    .next_crypto_state
                    .as_ref()
                    .unwrap()
                    .epoch,
                1
            );
            let devices = mls_snapshot(&store, &group).1;
            assert!(devices.contains(&device("phase29-bob-device-1")));
            assert!(devices.contains(&device("phase29-bob-device-2")));
            let remove = remove_change(&group, "phase29-remove-bob", &bob, 1);
            let removed = store
                .apply_mls_backed_group_change(
                    &owner,
                    &device("phase29-owner-device"),
                    &remove,
                    &[],
                )
                .unwrap();
            let state = removed.applied_change.next_crypto_state.unwrap();
            assert_eq!(state.epoch, 2);
            (group, owner, bob, state)
        };
        let store = SqliteLocalStore::open(db.path()).unwrap();
        let (state, devices) = mls_snapshot(&store, &group);
        assert_eq!(state, removed_state);
        assert!(!devices.contains(&device("phase29-bob-device-1")));
        assert!(!devices.contains(&device("phase29-bob-device-2")));
        let membership = store
            .group_membership(&scope(), &group.group_id, &bob.principal)
            .unwrap()
            .unwrap();
        assert_eq!(membership.state, GroupMemberState::Removed);
        assert_eq!(
            store
                .group(&scope(), &group.group_id)
                .unwrap()
                .unwrap()
                .crypto_state,
            removed_state
        );
        let _ = owner;
    }
}

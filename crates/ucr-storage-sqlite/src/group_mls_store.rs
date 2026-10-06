use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{DurableRecordStatus, DurableStoreError};
use ucr_group_mls::{
    AtomicMlsGroupChangeResult, DeviceKeyPackage, GroupMlsAtomicStore, GroupMlsBootstrapStore,
    GroupMlsStoreError, MAX_MLS_BOOTSTRAP_BYTES, MAX_MLS_BOOTSTRAP_COMMITS, MlsBootstrapCommit,
    MlsCommitArtifacts, MlsDeviceAdmission, MlsDeviceBootstrap, MlsGroupState, MlsTransitionInput,
    create_device_key_package, create_group, current_crypto_state, decode_key_package, load_group,
    member_device_ids, mls_change_request_fingerprint, mls_device_admission_fingerprint,
    own_device_id, sqlite_provider, stage_transition,
};
use ucr_model::{
    ConversationRecord, DeviceId, EventId, GroupChange, GroupChangeKind, GroupCryptoState, GroupId,
    GroupMemberState, GroupRecord, OpaqueId, PrincipalKind, PrincipalRef, ScopedPrincipal,
    TenantScope,
};
use ucr_protocol::{
    GROUP_MLS_CAPABILITY, device_allows_protected_access, group_change_fingerprint,
};

use super::{
    SqliteLocalStore, group_store, map_schema_change_error, map_sqlite_error,
    namespace_storage_key, principal_identity_binding_store, verify_table_columns,
};

const V49_OBJECTS_SQL: &str = r"
CREATE TABLE group_mls_transition_admissions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id, device_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, event_id)
      REFERENCES group_mls_transitions(tenant_id, namespace_present, namespace_id, event_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE INDEX group_mls_transition_admissions_device
ON group_mls_transition_admissions(
    tenant_id, namespace_present, namespace_id, device_id, event_id
);
";

pub(super) fn create_v49_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V49_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v49_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "group_mls_transition_admissions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("event_id", "TEXT", 1, 4),
            ("device_id", "TEXT", 1, 5),
        ],
    )
}

const V50_OBJECTS_SQL: &str = r"
CREATE TABLE group_mls_transitions_v50 (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    actor_device_id TEXT NOT NULL,
    request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
    commit_bytes BLOB NOT NULL CHECK(length(commit_bytes) BETWEEN 1 AND 2097152),
    welcome_bytes BLOB CHECK(welcome_bytes IS NULL OR length(welcome_bytes) BETWEEN 1 AND 2097152),
    crypto_epoch BLOB NOT NULL CHECK(length(crypto_epoch)=8),
    crypto_state_ref TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, group_id)
      REFERENCES groups(tenant_id, namespace_present, namespace_id, group_id) ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE group_mls_transition_admissions_v50 (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, event_id, device_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, event_id)
      REFERENCES group_mls_transitions_v50(tenant_id, namespace_present, namespace_id, event_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

INSERT INTO group_mls_transitions_v50 (
    tenant_id, namespace_present, namespace_id, event_id, group_id,
    actor_device_id, request_fingerprint, commit_bytes, welcome_bytes,
    crypto_epoch, crypto_state_ref
)
SELECT tenant_id, namespace_present, namespace_id, event_id, group_id,
       actor_device_id, request_fingerprint, commit_bytes, welcome_bytes,
       crypto_epoch, crypto_state_ref
FROM group_mls_transitions;

INSERT INTO group_mls_transition_admissions_v50 (
    tenant_id, namespace_present, namespace_id, event_id, device_id
)
SELECT tenant_id, namespace_present, namespace_id, event_id, device_id
FROM group_mls_transition_admissions;

DROP INDEX IF EXISTS group_mls_transition_admissions_device;
DROP TABLE group_mls_transition_admissions;
DROP TABLE group_mls_transitions;
ALTER TABLE group_mls_transitions_v50 RENAME TO group_mls_transitions;
ALTER TABLE group_mls_transition_admissions_v50 RENAME TO group_mls_transition_admissions;

CREATE INDEX group_mls_transition_admissions_device
ON group_mls_transition_admissions(
    tenant_id, namespace_present, namespace_id, device_id, event_id
);

DROP TRIGGER event_id_owner_events;
DROP TRIGGER event_id_owner_group_changes;
DROP TRIGGER event_id_owner_call_signals;

CREATE TRIGGER event_id_owner_events BEFORE INSERT ON events
WHEN EXISTS(SELECT 1 FROM group_changes WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM call_signals WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM group_mls_transitions WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;

CREATE TRIGGER event_id_owner_group_changes BEFORE INSERT ON group_changes
WHEN EXISTS(SELECT 1 FROM events WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM call_signals WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM group_mls_transitions WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;

CREATE TRIGGER event_id_owner_call_signals BEFORE INSERT ON call_signals
WHEN EXISTS(SELECT 1 FROM events WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM group_changes WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM group_mls_transitions WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;

CREATE TRIGGER event_id_owner_group_mls_transitions BEFORE INSERT ON group_mls_transitions
WHEN EXISTS(SELECT 1 FROM events WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(SELECT 1 FROM call_signals WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present AND namespace_id=NEW.namespace_id AND event_id=NEW.event_id)
  OR EXISTS(
      SELECT 1 FROM group_changes
      WHERE tenant_id=NEW.tenant_id
        AND namespace_present=NEW.namespace_present
        AND namespace_id=NEW.namespace_id
        AND event_id=NEW.event_id
        AND group_id<>NEW.group_id
  )
BEGIN SELECT RAISE(ABORT, 'ucr event id already reserved'); END;
";

pub(super) fn create_v50_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V50_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v50_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_v49_objects(connection)?;
    verify_foreign_key_columns(
        connection,
        "group_mls_transitions",
        "groups",
        &[
            ("tenant_id", "tenant_id"),
            ("namespace_present", "namespace_present"),
            ("namespace_id", "namespace_id"),
            ("group_id", "group_id"),
        ],
    )?;
    verify_foreign_key_columns(
        connection,
        "group_mls_transition_admissions",
        "group_mls_transitions",
        &[
            ("tenant_id", "tenant_id"),
            ("namespace_present", "namespace_present"),
            ("namespace_id", "namespace_id"),
            ("event_id", "event_id"),
        ],
    )?;
    let transition_trigger: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='trigger' AND name='event_id_owner_group_mls_transitions'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !transition_trigger {
        return Err(DurableStoreError::Corrupt);
    }
    let invalid_collision: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM events e
                JOIN group_mls_transitions m
                  ON e.tenant_id=m.tenant_id
                 AND e.namespace_present=m.namespace_present
                 AND e.namespace_id=m.namespace_id
                 AND e.event_id=m.event_id
                UNION ALL
                SELECT 1 FROM call_signals c
                JOIN group_mls_transitions m
                  ON c.tenant_id=m.tenant_id
                 AND c.namespace_present=m.namespace_present
                 AND c.namespace_id=m.namespace_id
                 AND c.event_id=m.event_id
                UNION ALL
                SELECT 1 FROM group_changes g
                JOIN group_mls_transitions m
                  ON g.tenant_id=m.tenant_id
                 AND g.namespace_present=m.namespace_present
                 AND g.namespace_id=m.namespace_id
                 AND g.event_id=m.event_id
                 AND g.group_id<>m.group_id
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if invalid_collision {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(())
}

fn verify_foreign_key_columns(
    connection: &Connection,
    table: &str,
    expected_target: &str,
    expected_columns: &[(&str, &str)],
) -> Result<(), DurableStoreError> {
    let sql = format!("PRAGMA foreign_key_list('{table}')");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut actual = Vec::new();
    for row in rows {
        actual.push(row.map_err(|error| map_sqlite_error(&error))?);
    }
    actual.sort();
    let mut expected = expected_columns
        .iter()
        .map(|(from, to)| (expected_target.to_owned(), (*from).to_owned(), (*to).to_owned()))
        .collect::<Vec<_>>();
    expected.sort();
    if actual == expected {
        Ok(())
    } else {
        Err(DurableStoreError::Corrupt)
    }
}

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

    fn admit_mls_device(
        &self,
        actor: &ScopedPrincipal,
        actor_device_id: &DeviceId,
        group_id: &GroupId,
        member: &PrincipalRef,
        event_id: &EventId,
        admission: &MlsDeviceAdmission,
    ) -> Result<DurableRecordStatus, GroupMlsStoreError> {
        if admission.key_package.is_empty() {
            return Err(GroupMlsStoreError::InvalidChangeMaterial);
        }
        let request_fingerprint = mls_device_admission_fingerprint(
            &actor.scope,
            group_id,
            actor_device_id,
            member,
            event_id,
            admission,
        )?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;

        if let Some(stored) =
            load_transition(&transaction, &actor.scope, event_id.as_opaque().as_str())?
        {
            let admitted = transition_admits_device(
                &transaction,
                &actor.scope,
                event_id,
                &admission.device_id,
            )?;
            if stored.group_id != *group_id
                || stored.actor_device_id != *actor_device_id
                || stored.request_fingerprint != request_fingerprint
                || !admitted
            {
                return Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict));
            }
            transaction
                .commit()
                .map_err(|error| map_sqlite_error(&error))?;
            return Ok(DurableRecordStatus::Duplicate);
        }
        if group_store::load_change_record(
            &transaction,
            &actor.scope,
            event_id.as_opaque().as_str(),
        )?
        .is_some()
            || super::event_journal::load_event_by_id(&transaction, &actor.scope, event_id)?
                .is_some()
            || super::call_store::call_signal_reserves_event_id(
                &transaction,
                &actor.scope,
                event_id.as_opaque().as_str(),
            )?
        {
            return Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict));
        }

        let mut canonical_group =
            group_store::load_group_from(&transaction, &actor.scope, group_id)?.ok_or(
                GroupMlsStoreError::Durable(DurableStoreError::InvalidRecord),
            )?;
        if canonical_group.crypto_state.capability_id.as_deref() != Some(GROUP_MLS_CAPABILITY) {
            return Err(GroupMlsStoreError::InvalidChangeMaterial);
        }
        let membership =
            group_store::load_membership_from(&transaction, &actor.scope, group_id, member)?
                .ok_or(GroupMlsStoreError::Durable(
                    DurableStoreError::PermissionDenied,
                ))?;
        if membership.state != GroupMemberState::Active {
            return Err(GroupMlsStoreError::Durable(
                DurableStoreError::PermissionDenied,
            ));
        }
        require_device_for_principal(
            &transaction,
            &actor.scope,
            &actor.principal,
            actor_device_id,
            true,
        )?;
        require_device_for_principal(
            &transaction,
            &actor.scope,
            member,
            &admission.device_id,
            true,
        )?;

        let (artifacts, mut mls_group) = {
            let provider = sqlite_provider(&transaction);
            let mut mls_group = load_group(&provider, &actor.scope, group_id)?
                .ok_or(GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
            if current_crypto_state(&actor.scope, group_id, &mls_group)?
                != canonical_group.crypto_state
                || own_device_id(&mls_group, &actor.scope)? != *actor_device_id
            {
                return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt));
            }
            let current_devices = member_device_ids(&mls_group, &actor.scope)?;
            if current_devices.contains(&admission.device_id) {
                return Err(GroupMlsStoreError::TargetDeviceMismatch);
            }
            let artifacts = stage_transition(
                &provider,
                &mut mls_group,
                &actor.scope,
                group_id,
                &MlsTransitionInput::Add(vec![admission.clone()]),
            )?;
            (artifacts, mls_group)
        };

        canonical_group.crypto_state = artifacts.next_crypto_state.clone();
        group_store::update_group(&transaction, &canonical_group)?;
        insert_transition(
            &transaction,
            &actor.scope,
            group_id,
            event_id,
            actor_device_id,
            &request_fingerprint,
            &artifacts,
            std::slice::from_ref(admission),
        )?;
        {
            let provider = sqlite_provider(&transaction);
            ucr_group_mls::merge_pending(
                &provider,
                &mut mls_group,
                &actor.scope,
                group_id,
                &artifacts.next_crypto_state,
            )?;
        }
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
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
        &applied_change.scope,
        &applied_change.group_id,
        &applied_change.event_id,
        actor_device_id,
        request_fingerprint,
        &artifacts,
        added_devices,
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
            if added_devices.is_empty() {
                // Principal-level Conference/Group admission is authoritative even before a
                // browser Device has supplied its endpoint-owned KeyPackage. Rekey existing MLS
                // members so the authorization change still advances the crypto epoch; the Device
                // leaf is admitted later by `admit_mls_device`.
                return Ok(MlsTransitionInput::Rekey);
            }
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
        | GroupChangeKind::SetDeliveryPolicy { .. }
        | GroupChangeKind::AddBridgeMapping { .. }
        | GroupChangeKind::RemoveBridgeMapping { .. } => {
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

pub(super) fn mls_transition_reserves_event_id(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &str,
) -> Result<bool, DurableStoreError> {
    let table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='group_mls_transitions')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if !table_exists {
        return Ok(false);
    }
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM group_mls_transitions
                WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND event_id=?4
             )",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event_id,
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
}

fn transition_admits_device(
    connection: &Connection,
    scope: &TenantScope,
    event_id: &EventId,
    device_id: &DeviceId,
) -> Result<bool, GroupMlsStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM group_mls_transition_admissions
                WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                  AND event_id=?4 AND device_id=?5
             )",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event_id.as_opaque().as_str(),
                device_id.as_opaque().as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))
        .map_err(Into::into)
}

fn insert_transition(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    group_id: &GroupId,
    event_id: &EventId,
    actor_device_id: &DeviceId,
    request_fingerprint: &[u8; 32],
    artifacts: &MlsCommitArtifacts,
    added_devices: &[MlsDeviceAdmission],
) -> Result<(), GroupMlsStoreError> {
    let namespace = namespace_storage_key(scope);
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
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                event_id.as_opaque().as_str(),
                group_id.as_opaque().as_str(),
                actor_device_id.as_opaque().as_str(),
                request_fingerprint.as_slice(),
                artifacts.commit.as_slice(),
                artifacts.welcome.as_deref(),
                artifacts.next_crypto_state.epoch.to_be_bytes().as_slice(),
                state_ref.as_str(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if artifacts.welcome.is_none() && !added_devices.is_empty() {
        return Err(GroupMlsStoreError::InvalidChangeMaterial);
    }
    for admission in added_devices {
        transaction
            .execute(
                "INSERT INTO group_mls_transition_admissions (
                    tenant_id, namespace_present, namespace_id, event_id, device_id
                 ) VALUES (?1,?2,?3,?4,?5)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    event_id.as_opaque().as_str(),
                    admission.device_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
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

fn decode_crypto_state(
    epoch: Vec<u8>,
    state_ref: String,
) -> Result<GroupCryptoState, GroupMlsStoreError> {
    let epoch: [u8; 8] = epoch
        .try_into()
        .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
    Ok(GroupCryptoState {
        capability_id: Some(GROUP_MLS_CAPABILITY.to_owned()),
        epoch: u64::from_be_bytes(epoch),
        state_ref: Some(
            OpaqueId::new(state_ref)
                .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?,
        ),
    })
}

fn load_device_admission(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
    device_id: &DeviceId,
) -> Result<Option<(EventId, Vec<u8>, GroupCryptoState)>, GroupMlsStoreError> {
    let namespace = namespace_storage_key(scope);
    let admission = connection
        .query_row(
            "SELECT a.event_id, t.welcome_bytes, t.crypto_epoch, t.crypto_state_ref
             FROM group_mls_transition_admissions a
             JOIN group_mls_transitions t
               ON t.tenant_id=a.tenant_id
              AND t.namespace_present=a.namespace_present
              AND t.namespace_id=a.namespace_id
              AND t.event_id=a.event_id
             WHERE a.tenant_id=?1
               AND a.namespace_present=?2
               AND a.namespace_id=?3
               AND a.device_id=?4
               AND t.group_id=?5
             ORDER BY t.crypto_epoch DESC
             LIMIT 1",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                device_id.as_opaque().as_str(),
                group_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    admission
        .map(|(event_id, welcome, epoch, state_ref)| {
            Ok((
                EventId::from_opaque(
                    OpaqueId::new(event_id)
                        .map_err(|_| GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?,
                ),
                welcome.ok_or(GroupMlsStoreError::InvalidChangeMaterial)?,
                decode_crypto_state(epoch, state_ref)?,
            ))
        })
        .transpose()
}

fn load_commits_after_epoch(
    connection: &Connection,
    scope: &TenantScope,
    group_id: &GroupId,
    admitted_epoch: u64,
) -> Result<Vec<MlsBootstrapCommit>, GroupMlsStoreError> {
    let namespace = namespace_storage_key(scope);
    let limit = i64::try_from(MAX_MLS_BOOTSTRAP_COMMITS + 1)
        .map_err(|_| GroupMlsStoreError::InvalidChangeMaterial)?;
    let mut statement = connection
        .prepare(
            "SELECT commit_bytes, crypto_epoch, crypto_state_ref
             FROM group_mls_transitions
             WHERE tenant_id=?1
               AND namespace_present=?2
               AND namespace_id=?3
               AND group_id=?4
               AND crypto_epoch>?5
             ORDER BY crypto_epoch ASC
             LIMIT ?6",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                group_id.as_opaque().as_str(),
                admitted_epoch.to_be_bytes().as_slice(),
                limit,
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut commits = Vec::new();
    for row in rows {
        let (commit, epoch, state_ref) = row.map_err(|error| map_sqlite_error(&error))?;
        commits.push(MlsBootstrapCommit {
            commit,
            next_crypto_state: decode_crypto_state(epoch, state_ref)?,
        });
    }
    if commits.len() > MAX_MLS_BOOTSTRAP_COMMITS {
        return Err(GroupMlsStoreError::BootstrapTooLarge);
    }
    Ok(commits)
}

impl GroupMlsBootstrapStore for SqliteLocalStore {
    fn mls_bootstrap_for_device(
        &self,
        scope: &TenantScope,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<Option<MlsDeviceBootstrap>, GroupMlsStoreError> {
        let connection = self.lock_connection()?;
        require_active_device(&connection, scope, device_id)?;
        let Some((admission_event_id, welcome, welcome_crypto_state)) =
            load_device_admission(&connection, scope, group_id, device_id)?
        else {
            return Ok(None);
        };
        let subsequent_commits =
            load_commits_after_epoch(&connection, scope, group_id, welcome_crypto_state.epoch)?;
        let total_bytes = subsequent_commits
            .iter()
            .try_fold(welcome.len(), |total, item| {
                total
                    .checked_add(item.commit.len())
                    .ok_or(GroupMlsStoreError::BootstrapTooLarge)
            })?;
        if total_bytes > MAX_MLS_BOOTSTRAP_BYTES {
            return Err(GroupMlsStoreError::BootstrapTooLarge);
        }
        let canonical_group = group_store::load_group_from(&connection, scope, group_id)?
            .ok_or(GroupMlsStoreError::Durable(DurableStoreError::Corrupt))?;
        let current_crypto_state = canonical_group.crypto_state;
        let projected_current = subsequent_commits
            .last()
            .map_or(&welcome_crypto_state, |commit| &commit.next_crypto_state);
        if *projected_current != current_crypto_state {
            return Err(GroupMlsStoreError::Durable(DurableStoreError::Corrupt));
        }

        Ok(Some(MlsDeviceBootstrap {
            group_id: group_id.clone(),
            admission_event_id,
            welcome,
            welcome_crypto_state,
            subsequent_commits,
            current_crypto_state,
        }))
    }
}

#[cfg(test)]
mod phase29_atomic_mls_tests {
    use ucr_core::{
        DeviceLifecycleStore, GroupStore, IdentityStore, PrincipalIdentityBindingStore,
    };
    use ucr_group_mls::{
        GroupMlsAtomicStore, GroupMlsBootstrapStore, GroupMlsStoreError, MlsDeviceAdmission,
    };
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

    fn role_change(
        group: &GroupRecord,
        event: &str,
        member: &ScopedPrincipal,
        revision: u64,
        role: GroupRole,
    ) -> GroupChange {
        GroupChange {
            event_id: EventId::from_opaque(oid(event)),
            scope: scope(),
            group_id: group.group_id.clone(),
            expected_revision: revision,
            kind: GroupChangeKind::ChangeRole {
                member: member.principal.clone(),
                role,
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
    fn device_bound_bootstrap_returns_only_exact_admission_and_advances_to_current_state() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).unwrap();
        let (group, owner, bob) = bootstrap(&store);
        let admitted_device = device("phase29-bob-device-1");
        let other_device = device("phase29-bob-device-2");
        let add = add_change(&group, "phase29-bootstrap-add", &bob, 0);
        let added = store
            .apply_mls_backed_group_change(
                &owner,
                &device("phase29-owner-device"),
                &add,
                &[admission(&store, "phase29-bob-device-1")],
            )
            .unwrap();
        let admitted_state = added.applied_change.next_crypto_state.unwrap();
        assert_eq!(admitted_state.epoch, 1);

        let initial = store
            .mls_bootstrap_for_device(&scope(), &group.group_id, &admitted_device)
            .unwrap()
            .expect("device bootstrap");
        assert!(!initial.welcome.is_empty());
        assert_eq!(
            initial.admission_event_id.as_opaque().as_str(),
            "phase29-bootstrap-add"
        );
        assert_eq!(initial.welcome_crypto_state, admitted_state);
        assert!(initial.subsequent_commits.is_empty());
        assert_eq!(initial.current_crypto_state, admitted_state);
        assert!(
            store
                .mls_bootstrap_for_device(&scope(), &group.group_id, &other_device)
                .unwrap()
                .is_none()
        );

        let rekey = role_change(&group, "phase29-bootstrap-rekey", &bob, 1, GroupRole::Admin);
        let rekeyed = store
            .apply_mls_backed_group_change(&owner, &device("phase29-owner-device"), &rekey, &[])
            .unwrap();
        let current_state = rekeyed.applied_change.next_crypto_state.unwrap();
        assert_eq!(current_state.epoch, 2);

        let advanced = store
            .mls_bootstrap_for_device(&scope(), &group.group_id, &admitted_device)
            .unwrap()
            .expect("advanced bootstrap");
        assert_eq!(
            advanced.admission_event_id.as_opaque().as_str(),
            "phase29-bootstrap-add"
        );
        assert_eq!(advanced.welcome_crypto_state, admitted_state);
        assert_eq!(advanced.subsequent_commits.len(), 1);
        assert!(!advanced.subsequent_commits[0].commit.is_empty());
        assert_eq!(
            advanced.subsequent_commits[0].next_crypto_state,
            current_state
        );
        assert_eq!(advanced.current_crypto_state, current_state);
    }

    #[test]
    fn principal_admission_precedes_endpoint_owned_device_leaf_and_retry_is_durable() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).unwrap();
        let (group, owner, bob) = bootstrap(&store);

        let principal_add = add_change(&group, "phase29-principal-only-add", &bob, 0);
        let added = store
            .apply_mls_backed_group_change(
                &owner,
                &device("phase29-owner-device"),
                &principal_add,
                &[],
            )
            .unwrap();
        assert_eq!(added.status, DurableRecordStatus::Persisted);
        let principal_state = added.applied_change.next_crypto_state.unwrap();
        assert_eq!(principal_state.epoch, 1);
        let membership = store
            .group_membership(&scope(), &group.group_id, &bob.principal)
            .unwrap()
            .expect("principal membership");
        assert_eq!(membership.state, GroupMemberState::Active);
        assert!(
            !mls_snapshot(&store, &group)
                .1
                .contains(&device("phase29-bob-device-1"))
        );
        assert!(
            store
                .mls_bootstrap_for_device(
                    &scope(),
                    &group.group_id,
                    &device("phase29-bob-device-1")
                )
                .unwrap()
                .is_none()
        );

        let endpoint_admission = admission(&store, "phase29-bob-device-1");
        let event_id = EventId::from_opaque(oid("rkp-phase29-endpoint-admission"));
        let persisted = store
            .admit_mls_device(
                &owner,
                &device("phase29-owner-device"),
                &group.group_id,
                &bob.principal,
                &event_id,
                &endpoint_admission,
            )
            .unwrap();
        assert_eq!(persisted, DurableRecordStatus::Persisted);
        let after_admission = store
            .group(&scope(), &group.group_id)
            .unwrap()
            .expect("group after endpoint admission");
        assert_eq!(after_admission.revision, 1);
        assert_eq!(after_admission.crypto_state.epoch, 2);
        assert!(
            mls_snapshot(&store, &group)
                .1
                .contains(&device("phase29-bob-device-1"))
        );
        let bootstrap = store
            .mls_bootstrap_for_device(&scope(), &group.group_id, &device("phase29-bob-device-1"))
            .unwrap()
            .expect("endpoint bootstrap");
        assert_eq!(bootstrap.admission_event_id, event_id);
        assert_eq!(bootstrap.current_crypto_state, after_admission.crypto_state);

        let duplicate = store
            .admit_mls_device(
                &owner,
                &device("phase29-owner-device"),
                &group.group_id,
                &bob.principal,
                &event_id,
                &endpoint_admission,
            )
            .unwrap();
        assert_eq!(duplicate, DurableRecordStatus::Duplicate);
        assert_eq!(
            store
                .group(&scope(), &group.group_id)
                .unwrap()
                .expect("group after exact retry")
                .crypto_state,
            after_admission.crypto_state
        );

        let changed = admission(&store, "phase29-bob-device-2");
        assert_eq!(
            store.admit_mls_device(
                &owner,
                &device("phase29-owner-device"),
                &group.group_id,
                &bob.principal,
                &event_id,
                &changed,
            ),
            Err(GroupMlsStoreError::Durable(DurableStoreError::Conflict))
        );

        let colliding_group_change = role_change(
            &group,
            "rkp-phase29-endpoint-admission",
            &bob,
            1,
            GroupRole::Admin,
        );
        assert_eq!(
            store.apply_group_change(&owner, &colliding_group_change),
            Err(DurableStoreError::Conflict)
        );
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

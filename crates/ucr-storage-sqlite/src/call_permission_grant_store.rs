//! Durable permissions bound to exactly ONE Call (schema v56).
//!
//! A row authorizes only `authorize_in_call` for its own Call and only while
//! that Call is not terminated and the grantee is a current (invited, ringing
//! or accepted, not-left) participant. Media forwarding additionally requires
//! an ACTIVE Call and an ACCEPTED participant; that remains enforced by the SFU. Triggers delete the rows atomically with Call
//! termination or participant departure, whatever code path performs it
//! (participants are rewritten by delete+insert, hence the INSERT trigger).
//! v56 also revokes historic tenant-wide media grants that older builds minted
//! implicitly for self-service first-party accounts on direct-Call Join.
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{CallPermissionGrantStore, DurableStoreError};
use ucr_model::{AuthorizationRequest, CallId, PrincipalKind, PrincipalRef, TenantScope};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

/// Media permissions that legacy builds granted tenant-wide on first-party Join.
pub(super) const LEGACY_IMPLICIT_MEDIA_PERMISSIONS: [&str; 5] = [
    ucr_protocol::CONFERENCE_SUBSCRIBE_PERMISSION,
    ucr_protocol::AUDIO_SEND_PERMISSION,
    ucr_protocol::AUDIO_RECEIVE_PERMISSION,
    ucr_protocol::VIDEO_SEND_PERMISSION,
    ucr_protocol::VIDEO_RECEIVE_PERMISSION,
];

const V56_SQL: &str = r"
CREATE TABLE call_permission_grants (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0,1)),
    namespace_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    permission TEXT NOT NULL CHECK(length(permission) BETWEEN 1 AND 128),
    PRIMARY KEY(tenant_id,namespace_present,namespace_id,call_id,principal_id,principal_kind,permission),
    FOREIGN KEY(tenant_id,namespace_present,namespace_id,call_id)
      REFERENCES calls(tenant_id,namespace_present,namespace_id,call_id) ON DELETE CASCADE,
    CHECK((namespace_present=0 AND namespace_id='') OR (namespace_present=1 AND namespace_id<>''))
) WITHOUT ROWID;

CREATE TRIGGER call_permission_grants_revoke_on_terminate
AFTER UPDATE OF signalling_state ON calls
WHEN NEW.signalling_state='terminated'
BEGIN
    DELETE FROM call_permission_grants
     WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present
       AND namespace_id=NEW.namespace_id AND call_id=NEW.call_id;
END;

CREATE TRIGGER call_permission_grants_revoke_on_leave
AFTER INSERT ON call_participants
WHEN NEW.state NOT IN ('invited','ringing','accepted') OR NEW.left_revision IS NOT NULL
BEGIN
    DELETE FROM call_permission_grants
     WHERE tenant_id=NEW.tenant_id AND namespace_present=NEW.namespace_present
       AND namespace_id=NEW.namespace_id AND call_id=NEW.call_id
       AND principal_id=NEW.principal_id AND principal_kind=NEW.principal_kind;
END;
";

pub(super) fn create_v56_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V56_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

/// Revokes media grants that pre-v56 builds minted implicitly, tenant-wide, for
/// self-service first-party persons. Administratively provisioned principals
/// (no first-party recovery credential) are deliberately left untouched.
pub(super) fn revoke_legacy_implicit_media_grants(
    transaction: &Transaction<'_>,
) -> Result<usize, DurableStoreError> {
    let mut removed = 0;
    for permission in LEGACY_IMPLICIT_MEDIA_PERMISSIONS {
        removed += transaction
            .execute(
                "DELETE FROM permission_grants
                  WHERE permission=?1 AND scope_kind='exact' AND principal_kind='person'
                    AND EXISTS (
                        SELECT 1 FROM first_party_recovery_credentials c
                         WHERE c.tenant_id=permission_grants.grantee_tenant_id
                           AND c.namespace_present=permission_grants.grantee_namespace_present
                           AND c.namespace_id=permission_grants.grantee_namespace_id
                           AND c.identity_id=permission_grants.principal_id)",
                params![permission],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(removed)
}

pub(super) fn verify_v56_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "call_permission_grants",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("call_id", "TEXT", 1, 4),
            ("principal_id", "TEXT", 1, 5),
            ("principal_kind", "TEXT", 1, 6),
            ("permission", "TEXT", 1, 7),
        ],
    )?;
    for trigger in [
        "call_permission_grants_revoke_on_terminate",
        "call_permission_grants_revoke_on_leave",
    ] {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name=?1)",
                params![trigger],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if !present {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

const fn principal_kind_text(kind: PrincipalKind) -> &'static str {
    super::group_store::principal_kind_name(kind)
}

/// True only for a grant on a non-terminated Call whose grantee is a current participant.
pub(super) fn has_live_call_grant(
    connection: &Connection,
    request: &AuthorizationRequest,
    call_id: &CallId,
) -> Result<bool, DurableStoreError> {
    if request.subject.scope != request.resource_scope {
        return Ok(false);
    }
    let ns = namespace_storage_key(&request.subject.scope);
    connection
        .query_row(
            "SELECT 1 FROM call_permission_grants g
               JOIN calls c ON c.tenant_id=g.tenant_id AND c.namespace_present=g.namespace_present
                AND c.namespace_id=g.namespace_id AND c.call_id=g.call_id
               JOIN call_participants p ON p.tenant_id=g.tenant_id
                AND p.namespace_present=g.namespace_present AND p.namespace_id=g.namespace_id
                AND p.call_id=g.call_id AND p.principal_id=g.principal_id
                AND p.principal_kind=g.principal_kind
              WHERE g.tenant_id=?1 AND g.namespace_present=?2 AND g.namespace_id=?3
                AND g.call_id=?4 AND g.principal_id=?5 AND g.principal_kind=?6
                AND g.permission=?7
                AND c.signalling_state<>'terminated'
                AND p.state IN ('invited','ringing','accepted') AND p.left_revision IS NULL",
            params![
                request.subject.scope.tenant_id.as_opaque().as_str(),
                ns.present,
                ns.value,
                call_id.as_opaque().as_str(),
                request.subject.principal.principal_id.as_opaque().as_str(),
                principal_kind_text(request.subject.principal.kind),
                request.permission,
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|error| map_sqlite_error(&error))
}

impl CallPermissionGrantStore for SqliteLocalStore {
    fn grant_call_permissions(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
        grantees: &[PrincipalRef],
        permissions: &[&str],
    ) -> Result<(), DurableStoreError> {
        if grantees.is_empty()
            || permissions.is_empty()
            || permissions
                .iter()
                .any(|permission| permission.is_empty() || permission.len() > 128)
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let ns = namespace_storage_key(scope);
        for grantee in grantees {
            for permission in permissions {
                // Atomic liveness check: insert only while the Call is not
                // terminated and the grantee is a current, not-left participant.
                let inserted = tx
                    .execute(
                        "INSERT OR IGNORE INTO call_permission_grants
                         (tenant_id,namespace_present,namespace_id,call_id,
                          principal_id,principal_kind,permission)
                         SELECT ?1,?2,?3,?4,?5,?6,?7
                          WHERE EXISTS (
                            SELECT 1 FROM calls c JOIN call_participants p
                              ON p.tenant_id=c.tenant_id AND p.namespace_present=c.namespace_present
                             AND p.namespace_id=c.namespace_id AND p.call_id=c.call_id
                           WHERE c.tenant_id=?1 AND c.namespace_present=?2 AND c.namespace_id=?3
                             AND c.call_id=?4 AND p.principal_id=?5 AND p.principal_kind=?6
                             AND c.signalling_state<>'terminated'
                             AND p.state IN ('invited','ringing','accepted') AND p.left_revision IS NULL)",
                        params![
                            scope.tenant_id.as_opaque().as_str(),
                            ns.present,
                            ns.value,
                            call_id.as_opaque().as_str(),
                            grantee.principal_id.as_opaque().as_str(),
                            principal_kind_text(grantee.kind),
                            permission,
                        ],
                    )
                    .map_err(|error| map_sqlite_error(&error))?;
                if inserted == 0 {
                    let probe = AuthorizationRequest {
                        subject: ucr_model::ScopedPrincipal {
                            scope: scope.clone(),
                            principal: grantee.clone(),
                        },
                        permission: (*permission).to_owned(),
                        resource_scope: scope.clone(),
                    };
                    // Idempotent repeat is fine; anything else is a stale Call.
                    if !has_live_call_grant(&tx, &probe, call_id)? {
                        return Err(DurableStoreError::Conflict);
                    }
                }
            }
        }
        tx.commit().map_err(|error| map_sqlite_error(&error))
    }

    fn revoke_call_permissions(
        &self,
        scope: &TenantScope,
        call_id: &CallId,
    ) -> Result<usize, DurableStoreError> {
        let connection = self.lock_connection()?;
        let ns = namespace_storage_key(scope);
        connection
            .execute(
                "DELETE FROM call_permission_grants
                  WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND call_id=?4",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    ns.present,
                    ns.value,
                    call_id.as_opaque().as_str()
                ],
            )
            .map_err(|error| map_sqlite_error(&error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_store::tests::TestDb;
    use ucr_core::{AuthorizationEvaluator, PermissionGrantStore, StorageProvider};
    use ucr_model::{
        OpaqueId, PermissionGrant, PermissionScope, PrincipalId, ScopedPrincipal, TenantId,
    };

    fn id(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test identifier")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(id("call-grant-tenant")),
            namespace_id: None,
        }
    }

    fn person(value: &str) -> PrincipalRef {
        PrincipalRef {
            principal_id: PrincipalId::from_opaque(id(value)),
            kind: PrincipalKind::Person,
        }
    }

    fn request(principal: &PrincipalRef, permission: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            subject: ScopedPrincipal {
                scope: scope(),
                principal: principal.clone(),
            },
            permission: permission.to_owned(),
            resource_scope: scope(),
        }
    }

    /// Raw fixture: one Call with the given participant states (FK to the
    /// conversation is irrelevant for these grant semantics).
    fn seed_call(db: &TestDb, call: &str, state: &str, participants: &[(&str, &str)]) {
        let connection = Connection::open(db.path()).expect("fixture connection");
        connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .expect("fixture pragma");
        connection
            .execute(
                "INSERT INTO calls (tenant_id,namespace_present,namespace_id,call_id,
                   conversation_id,conversation_kind,initiated_by_principal_id,
                   initiated_by_principal_kind,creation_fingerprint,signalling_state,
                   media_negotiation_generation,replication_generation,revision)
                 VALUES ('call-grant-tenant',0,'',?1,'conv','private_group','alice','person',
                   zeroblob(32),?2,zeroblob(8),zeroblob(8),zeroblob(8))",
                params![call, state],
            )
            .expect("seed call");
        for (principal, participant_state) in participants {
            set_participant(&connection, call, principal, participant_state);
        }
    }

    /// Mirrors the canonical delete+reinsert rewrite of a participant row.
    fn set_participant(connection: &Connection, call: &str, principal: &str, state: &str) {
        connection
            .execute(
                "DELETE FROM call_participants WHERE call_id=?1 AND principal_id=?2",
                params![call, principal],
            )
            .expect("delete participant");
        let left: Option<Vec<u8>> = (state == "left").then(|| vec![0; 8]);
        connection
            .execute(
                "INSERT INTO call_participants (tenant_id,namespace_present,namespace_id,call_id,
                   principal_id,principal_kind,state,joined_revision,left_revision)
                 VALUES ('call-grant-tenant',0,'',?1,?2,'person',?3,zeroblob(8),?4)",
                params![call, principal, state, left],
            )
            .expect("insert participant");
    }

    fn call(value: &str) -> CallId {
        CallId::from_opaque(id(value))
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one linear end-to-end grant lifecycle scenario
    fn call_grant_is_bound_to_one_live_call_and_revoked_on_terminate_and_leave() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("store");
        seed_call(
            &db,
            "c1",
            "active",
            &[("alice", "accepted"), ("bob", "invited")],
        );
        seed_call(&db, "c2", "active", &[("alice", "accepted")]);
        let (alice, bob, carol) = (person("alice"), person("bob"), person("carol"));
        let perm = ucr_protocol::AUDIO_SEND_PERMISSION;
        store
            .grant_call_permissions(
                &scope(),
                &call("c1"),
                &[alice.clone(), bob.clone()],
                &[perm],
            )
            .expect("grant");
        // Idempotent repeat.
        store
            .grant_call_permissions(&scope(), &call("c1"), std::slice::from_ref(&alice), &[perm])
            .expect("idempotent grant");
        assert!(
            store
                .authorize_in_call(&request(&alice, perm), &call("c1"))
                .is_ok()
        );
        assert!(
            store
                .authorize_in_call(&request(&bob, perm), &call("c1"))
                .is_ok()
        );
        // Never tenant-wide, never another Call, never another permission or principal.
        assert!(store.authorize(&request(&alice, perm)).is_err());
        assert!(
            store
                .authorize_in_call(&request(&alice, perm), &call("c2"))
                .is_err()
        );
        assert!(
            store
                .authorize_in_call(
                    &request(&alice, ucr_protocol::VIDEO_SEND_PERMISSION),
                    &call("c1")
                )
                .is_err()
        );
        assert!(
            store
                .authorize_in_call(&request(&carol, perm), &call("c1"))
                .is_err()
        );
        // A non-participant cannot be granted.
        assert_eq!(
            store.grant_call_permissions(&scope(), &call("c1"), &[carol], &[perm]),
            Err(DurableStoreError::Conflict)
        );
        // Cross-tenant subject never matches.
        let mut foreign = request(&alice, perm);
        foreign.resource_scope.tenant_id = TenantId::from_opaque(id("other-tenant"));
        assert!(store.authorize_in_call(&foreign, &call("c1")).is_err());

        // Leaving (delete+reinsert as 'left') revokes only that participant.
        {
            let connection = Connection::open(db.path()).expect("fixture connection");
            set_participant(&connection, "c1", "bob", "left");
            set_participant(&connection, "c1", "bob", "accepted");
        }
        assert!(
            store
                .authorize_in_call(&request(&bob, perm), &call("c1"))
                .is_err()
        );
        assert!(
            store
                .authorize_in_call(&request(&alice, perm), &call("c1"))
                .is_ok()
        );

        // Termination revokes every grant of that Call atomically.
        {
            let connection = Connection::open(db.path()).expect("fixture connection");
            connection
                .execute(
                    "UPDATE calls SET signalling_state='terminated', termination_reason='completed'
                      WHERE call_id='c1'",
                    [],
                )
                .expect("terminate");
            let rows: i64 = connection
                .query_row(
                    "SELECT count(*) FROM call_permission_grants WHERE call_id='c1'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0, "terminate trigger must delete the grants");
        }
        assert!(
            store
                .authorize_in_call(&request(&alice, perm), &call("c1"))
                .is_err()
        );
        assert_eq!(
            store.grant_call_permissions(&scope(), &call("c1"), &[alice], &[perm]),
            Err(DurableStoreError::Conflict),
            "a terminated Call can never be re-granted"
        );
    }

    #[test]
    fn tenant_wide_grants_still_authorize_in_call() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("store");
        let admin = person("admin");
        store
            .grant_permission(&PermissionGrant {
                grantee: ScopedPrincipal {
                    scope: scope(),
                    principal: admin.clone(),
                },
                permission: ucr_protocol::AUDIO_SEND_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("explicit grant");
        assert!(
            store
                .authorize_in_call(
                    &request(&admin, ucr_protocol::AUDIO_SEND_PERMISSION),
                    &call("any")
                )
                .is_ok()
        );
    }

    #[test]
    fn v55_to_v56_revokes_only_legacy_self_service_media_grants() {
        let db = TestDb::new();
        drop(SqliteLocalStore::open(db.path()).expect("current schema"));
        {
            let connection = Connection::open(db.path()).expect("historical fixture");
            crate::test_remove_v56_objects(&connection).expect("remove v56");
            connection
                .execute_batch(
                    "INSERT INTO identities
                       (tenant_id,namespace_present,namespace_id,identity_id,ownership,evidence)
                       VALUES ('call-grant-tenant',0,'','selfservice','ucr_native','self_asserted');
                     INSERT INTO first_party_recovery_credentials
                       (tenant_id,namespace_present,namespace_id,identity_id,verifier,generation)
                       VALUES ('call-grant-tenant',0,'','selfservice',zeroblob(32),1);
                     PRAGMA user_version=55;",
                )
                .expect("v55 fixture");
        }
        {
            let store = SqliteLocalStore::open(db.path()).expect("open v55 as v56 then rewind");
            for principal in ["selfservice", "admin"] {
                for permission in LEGACY_IMPLICIT_MEDIA_PERMISSIONS
                    .iter()
                    .chain([&ucr_protocol::CALL_OBSERVE_PERMISSION])
                {
                    store
                        .grant_permission(&PermissionGrant {
                            grantee: ScopedPrincipal {
                                scope: scope(),
                                principal: person(principal),
                            },
                            permission: (*permission).to_owned(),
                            scope: PermissionScope::Exact(scope()),
                        })
                        .expect("legacy grant");
                }
            }
        }
        {
            // Re-stamp as v55 with the legacy grants present; v56 must revoke them.
            let connection = Connection::open(db.path()).expect("historical fixture");
            crate::test_remove_v56_objects(&connection).expect("remove v56");
            connection
                .execute_batch("PRAGMA user_version=55;")
                .expect("v55 marker");
        }
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v55 to v56");
        assert_eq!(migrated.schema_version(), Ok(crate::SQLITE_SCHEMA_VERSION));
        for permission in LEGACY_IMPLICIT_MEDIA_PERMISSIONS {
            assert!(
                migrated
                    .authorize(&request(&person("selfservice"), permission))
                    .is_err(),
                "legacy implicit {permission} must be revoked"
            );
            assert!(
                migrated
                    .authorize(&request(&person("admin"), permission))
                    .is_ok(),
                "admin-provisioned {permission} must survive"
            );
        }
        assert!(
            migrated
                .authorize(&request(
                    &person("selfservice"),
                    ucr_protocol::CALL_OBSERVE_PERMISSION
                ))
                .is_ok()
        );
    }
}

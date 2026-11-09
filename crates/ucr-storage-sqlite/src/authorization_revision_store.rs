//! Monotonic authorization revision (schema v58).
//!
//! One singleton counter is bumped by triggers, inside the SAME transaction,
//! on every INSERT/UPDATE/DELETE of a table that any authorization decision
//! (tenant grants, Call-scoped grants, Call participation, Group/MLS
//! membership, Device and trusted-key lifecycle, identity bindings,
//! organization management, service credentials) reads. A cache keyed by this
//! revision therefore can never outlive a revoke, Leave, Hangup, membership
//! rekey or Device revocation, including one committed by another process
//! sharing the same file.
use std::fmt::Write as _;

use rusqlite::{Connection, Transaction};
use ucr_core::DurableStoreError;

use super::{SqliteLocalStore, map_schema_change_error, map_sqlite_error, verify_table_columns};

/// Every table whose content can change an authorization outcome.
pub(super) const AUTHORIZATION_TABLES: &[&str] = &[
    "calls",
    "call_participants",
    "call_permission_grants",
    "permission_grants",
    "groups",
    "group_memberships",
    "group_mls_transitions",
    "group_mls_transition_admissions",
    "server_mls_custody_quarantine",
    "devices",
    "trusted_signing_keys",
    "principal_identity_bindings",
    "identities",
    "external_identity_bindings",
    "organization_managed_devices",
    "organization_managed_identities",
    "organization_mode_profiles",
    "service_credentials",
];

const OPERATIONS: &[(&str, &str)] = &[("ins", "INSERT"), ("upd", "UPDATE"), ("del", "DELETE")];

pub(super) fn trigger_name(table: &str, suffix: &str) -> String {
    format!("authz_rev_{table}_{suffix}")
}

pub(super) fn create_v58_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    let mut sql = String::from(
        "CREATE TABLE authorization_revision (
             singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
             revision INTEGER NOT NULL CHECK(revision >= 0)
         );
         INSERT INTO authorization_revision(singleton, revision) VALUES (1, 0);",
    );
    for table in AUTHORIZATION_TABLES {
        for (suffix, operation) in OPERATIONS {
            let _ = write!(
                sql,
                "CREATE TRIGGER {} AFTER {operation} ON {table} BEGIN
                     UPDATE authorization_revision SET revision = revision + 1
                      WHERE singleton = 1;
                 END;",
                trigger_name(table, suffix)
            );
        }
    }
    transaction
        .execute_batch(&sql)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v58_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "authorization_revision",
        &[
            ("singleton", "INTEGER", 1, 1),
            ("revision", "INTEGER", 1, 0),
        ],
    )?;
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM authorization_revision", [], |row| {
            row.get(0)
        })
        .map_err(|error| map_sqlite_error(&error))?;
    if rows != 1 {
        return Err(DurableStoreError::Corrupt);
    }
    for table in AUTHORIZATION_TABLES {
        for (suffix, operation) in OPERATIONS {
            let name = trigger_name(table, suffix);
            let sql: Option<String> = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1 AND tbl_name=?2",
                    [name.as_str(), table],
                    |row| row.get(0),
                )
                .map_or_else(
                    |error| match error {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(map_sqlite_error(&other)),
                    },
                    |value| Ok(Some(value)),
                )?;
            let valid = sql.is_some_and(|sql| {
                sql.contains(&format!("AFTER {operation} ON {table}"))
                    && sql.contains("UPDATE authorization_revision SET revision = revision + 1")
            });
            if !valid {
                return Err(DurableStoreError::Corrupt);
            }
        }
    }
    Ok(())
}

impl SqliteLocalStore {
    /// Reads the current committed authorization revision.
    ///
    /// # Errors
    /// Returns a durable-store error on `SQLite` failure.
    pub fn authorization_revision_value(&self) -> Result<u64, DurableStoreError> {
        let connection = self.lock_connection()?;
        let value: i64 = connection
            .query_row(
                "SELECT revision FROM authorization_revision WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        u64::try_from(value).map_err(|_| DurableStoreError::Corrupt)
    }
}

#[cfg(test)]
pub(super) fn test_drop_sql() -> String {
    let mut sql = String::new();
    for table in AUTHORIZATION_TABLES {
        for (suffix, _) in OPERATIONS {
            let _ = write!(
                sql,
                "DROP TRIGGER IF EXISTS {};",
                trigger_name(table, suffix)
            );
        }
    }
    sql.push_str("DROP TABLE IF EXISTS authorization_revision;");
    sql
}

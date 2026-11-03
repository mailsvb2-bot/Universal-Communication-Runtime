//! Durable first-party browser sessions and signup admission (schema v57).
//!
//! Only a SHA-256 digest of the random cookie token is stored, never the token
//! itself. A Logout or Device revoke deletes every row for that exact Device
//! binding in one statement, so the revocation survives a process restart and
//! is visible to every BFF process that shares this `SQLite` file. The signup
//! window is a fixed-size sliding log checked and appended atomically inside
//! one IMMEDIATE transaction, so concurrent processes cannot both take the
//! last slot.
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::DurableStoreError;

use super::{SqliteLocalStore, map_schema_change_error, map_sqlite_error, verify_table_columns};

const V57_SQL: &str = r"
CREATE TABLE first_party_sessions (
    token_digest BLOB NOT NULL PRIMARY KEY CHECK(length(token_digest)=32),
    binding_key TEXT NOT NULL CHECK(length(binding_key) BETWEEN 1 AND 2048),
    owner_key TEXT NOT NULL CHECK(length(owner_key) BETWEEN 1 AND 2048),
    signer_key_id TEXT NOT NULL CHECK(length(signer_key_id) BETWEEN 1 AND 256),
    signer_public_key BLOB NOT NULL CHECK(length(signer_public_key)=32),
    issued_unix_ms INTEGER NOT NULL,
    expires_unix_ms INTEGER NOT NULL CHECK(expires_unix_ms > issued_unix_ms)
) WITHOUT ROWID;
CREATE INDEX first_party_sessions_binding ON first_party_sessions(binding_key);
CREATE INDEX first_party_sessions_owner ON first_party_sessions(owner_key, issued_unix_ms);
CREATE INDEX first_party_sessions_expiry ON first_party_sessions(expires_unix_ms);

CREATE TABLE first_party_signup_admissions (
    admission_id INTEGER PRIMARY KEY AUTOINCREMENT,
    admitted_unix_ms INTEGER NOT NULL
);
CREATE INDEX first_party_signup_admissions_time
    ON first_party_signup_admissions(admitted_unix_ms);
";

pub(super) fn create_v57_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V57_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v57_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "first_party_sessions",
        &[
            ("token_digest", "BLOB", 1, 1),
            ("binding_key", "TEXT", 1, 0),
            ("owner_key", "TEXT", 1, 0),
            ("signer_key_id", "TEXT", 1, 0),
            ("signer_public_key", "BLOB", 1, 0),
            ("issued_unix_ms", "INTEGER", 1, 0),
            ("expires_unix_ms", "INTEGER", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "first_party_signup_admissions",
        &[
            ("admission_id", "INTEGER", 0, 1),
            ("admitted_unix_ms", "INTEGER", 1, 0),
        ],
    )
}

/// One durable, still-unexpired first-party session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstPartySessionRecord {
    pub binding_key: String,
    pub signer_key_id: String,
    pub signer_public_key: [u8; 32],
    pub expires_unix_ms: i64,
}

/// Input for [`SqliteLocalStore::persist_first_party_session`].
#[derive(Debug, Clone, Copy)]
pub struct NewFirstPartySession<'a> {
    pub token_digest: &'a [u8; 32],
    pub binding_key: &'a str,
    /// Sessions sharing an owner (one person) are capped together.
    pub owner_key: &'a str,
    pub signer_key_id: &'a str,
    pub signer_public_key: &'a [u8; 32],
    pub issued_unix_ms: i64,
    pub expires_unix_ms: i64,
    pub max_per_owner: u32,
    pub max_total: u32,
}

impl SqliteLocalStore {
    /// Persists one session; evicts only the SAME owner's oldest sessions beyond
    /// `max_per_owner`. Returns `Ok(false)` when the global bound is reached.
    ///
    /// # Errors
    /// Returns a durable-store error on invalid input or `SQLite` failure.
    pub fn persist_first_party_session(
        &self,
        session: &NewFirstPartySession<'_>,
    ) -> Result<bool, DurableStoreError> {
        if session.binding_key.is_empty()
            || session.owner_key.is_empty()
            || session.signer_key_id.is_empty()
            || session.expires_unix_ms <= session.issued_unix_ms
            || session.max_per_owner == 0
        {
            return Err(DurableStoreError::InvalidRecord);
        }
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        tx.execute(
            "DELETE FROM first_party_sessions WHERE expires_unix_ms <= ?1",
            params![session.issued_unix_ms],
        )
        .map_err(|error| map_sqlite_error(&error))?;
        tx.execute(
            "DELETE FROM first_party_sessions WHERE token_digest IN (
                SELECT token_digest FROM first_party_sessions WHERE owner_key=?1
                 ORDER BY issued_unix_ms DESC, token_digest LIMIT -1 OFFSET ?2)",
            params![session.owner_key, i64::from(session.max_per_owner - 1)],
        )
        .map_err(|error| map_sqlite_error(&error))?;
        let total: i64 = tx
            .query_row("SELECT count(*) FROM first_party_sessions", [], |row| {
                row.get(0)
            })
            .map_err(|error| map_sqlite_error(&error))?;
        if total >= i64::from(session.max_total) {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO first_party_sessions
             (token_digest,binding_key,owner_key,signer_key_id,signer_public_key,
              issued_unix_ms,expires_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                session.token_digest.as_slice(),
                session.binding_key,
                session.owner_key,
                session.signer_key_id,
                session.signer_public_key.as_slice(),
                session.issued_unix_ms,
                session.expires_unix_ms,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
        tx.commit().map_err(|error| map_sqlite_error(&error))?;
        Ok(true)
    }

    /// Returns the live session for a token digest, or `None` if it was never
    /// issued, has expired, or was revoked by Logout/Device revoke.
    ///
    /// # Errors
    /// Returns a durable-store error on `SQLite` failure or a corrupt row.
    pub fn first_party_session(
        &self,
        token_digest: &[u8; 32],
        now_unix_ms: i64,
    ) -> Result<Option<FirstPartySessionRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT binding_key,signer_key_id,signer_public_key,expires_unix_ms
                   FROM first_party_sessions WHERE token_digest=?1 AND expires_unix_ms > ?2",
                params![token_digest.as_slice(), now_unix_ms],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| map_sqlite_error(&error))?;
        row.map(|(binding_key, signer_key_id, key, expires_unix_ms)| {
            Ok(FirstPartySessionRecord {
                binding_key,
                signer_key_id,
                signer_public_key: key.try_into().map_err(|_| DurableStoreError::Corrupt)?,
                expires_unix_ms,
            })
        })
        .transpose()
    }

    /// Revokes every durable session of one exact Device binding.
    ///
    /// # Errors
    /// Returns a durable-store error on `SQLite` failure.
    pub fn revoke_first_party_sessions(
        &self,
        binding_key: &str,
    ) -> Result<usize, DurableStoreError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM first_party_sessions WHERE binding_key=?1",
                params![binding_key],
            )
            .map_err(|error| map_sqlite_error(&error))
    }

    /// Atomically admits one anonymous signup if fewer than `max` were admitted
    /// in the sliding window ending at `now_unix_ms`.
    ///
    /// # Errors
    /// Returns a durable-store error on `SQLite` failure.
    pub fn admit_first_party_signup(
        &self,
        now_unix_ms: i64,
        window_ms: i64,
        max: u32,
    ) -> Result<bool, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let floor = now_unix_ms.saturating_sub(window_ms);
        tx.execute(
            "DELETE FROM first_party_signup_admissions WHERE admitted_unix_ms <= ?1",
            params![floor],
        )
        .map_err(|error| map_sqlite_error(&error))?;
        let admitted: i64 = tx
            .query_row(
                "SELECT count(*) FROM first_party_signup_admissions",
                [],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if admitted >= i64::from(max) {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO first_party_signup_admissions(admitted_unix_ms) VALUES (?1)",
            params![now_unix_ms],
        )
        .map_err(|error| map_sqlite_error(&error))?;
        tx.commit().map_err(|error| map_sqlite_error(&error))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::NewFirstPartySession;
    use crate::{SqliteLocalStore, message_store::tests::TestDb};

    fn new<'a>(digest: &'a [u8; 32], binding: &'a str, at: i64) -> NewFirstPartySession<'a> {
        NewFirstPartySession {
            token_digest: digest,
            binding_key: binding,
            owner_key: "owner",
            signer_key_id: "key",
            signer_public_key: &[3; 32],
            issued_unix_ms: at,
            expires_unix_ms: at + 1_000,
            max_per_owner: 2,
            max_total: 16,
        }
    }

    #[test]
    fn logout_revocation_and_signup_quota_survive_reopen() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).unwrap();
        assert!(
            store
                .persist_first_party_session(&new(&[1; 32], "dev-a", 10))
                .unwrap()
        );
        assert!(
            store
                .persist_first_party_session(&new(&[2; 32], "dev-b", 11))
                .unwrap()
        );
        assert!(store.admit_first_party_signup(100, 50, 1).unwrap());
        drop(store);
        let store = SqliteLocalStore::open(db.path()).unwrap();
        assert!(store.first_party_session(&[1; 32], 20).unwrap().is_some());
        assert!(
            !store.admit_first_party_signup(120, 50, 1).unwrap(),
            "quota is durable"
        );
        assert!(
            store.admit_first_party_signup(151, 50, 1).unwrap(),
            "window slides"
        );
        assert_eq!(store.revoke_first_party_sessions("dev-a").unwrap(), 1);
        drop(store);
        let store = SqliteLocalStore::open(db.path()).unwrap();
        assert!(store.first_party_session(&[1; 32], 20).unwrap().is_none());
        assert!(store.first_party_session(&[2; 32], 20).unwrap().is_some());
        assert!(
            store
                .first_party_session(&[2; 32], 2_000)
                .unwrap()
                .is_none(),
            "expiry"
        );
        // Per-owner cap evicts only the oldest session of the same owner.
        assert!(
            store
                .persist_first_party_session(&new(&[4; 32], "dev-c", 12))
                .unwrap()
        );
        assert!(
            store
                .persist_first_party_session(&new(&[5; 32], "dev-c", 13))
                .unwrap()
        );
        assert!(store.first_party_session(&[2; 32], 20).unwrap().is_none());
        assert!(store.first_party_session(&[4; 32], 20).unwrap().is_some());
    }
}

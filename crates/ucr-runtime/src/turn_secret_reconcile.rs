#![forbid(unsafe_code)]

use std::path::Path;

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use ucr_secrets::{SecretHandle, SecretProvider, SecretPurpose};
use ucr_webrtc::validate_coturn_rest_secret_material;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnSecretReconcileError {
    WrongPurpose,
    InvalidRealm,
    ProviderUnavailable,
    InvalidSecret,
    ExclusiveOwnershipRequired,
    DatabaseUnavailable,
    SchemaMismatch,
    DatabaseFailure,
    VerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnSecretReconcileOutcome {
    pub desired_count: usize,
    pub inserted_count: usize,
    pub removed_count: usize,
    pub retained_count: usize,
}

/// Reconciles one coturn SQLite realm to the provider's exact current/previous secret snapshot.
///
/// The caller must explicitly assert exclusive ownership of the realm's `turn_secret` rows.
/// Without that assertion UCR cannot distinguish stale UCR roots from secrets managed by another
/// operator because coturn stores only `(realm, value)`, not provider version identifiers.
///
/// The database is opened read-write without CREATE, mutated under an IMMEDIATE transaction, and
/// verified before commit. Secret values are never logged or returned.
///
/// # Errors
/// Fails closed on wrong purpose, unsafe realm/secret material, non-exclusive ownership,
/// unavailable provider/database, schema mismatch, transaction failure, or post-write mismatch.
pub fn reconcile_coturn_sqlite_secret_set(
    provider: &dyn SecretProvider,
    handle: &SecretHandle,
    database: &Path,
    realm: &str,
    exclusive_realm: bool,
) -> Result<TurnSecretReconcileOutcome, TurnSecretReconcileError> {
    if handle.purpose != SecretPurpose::TurnCredentials {
        return Err(TurnSecretReconcileError::WrongPurpose);
    }
    validate_realm(realm)?;
    if !exclusive_realm {
        return Err(TurnSecretReconcileError::ExclusiveOwnershipRequired);
    }

    let set = provider
        .active_secret_set(handle)
        .map_err(|_| TurnSecretReconcileError::ProviderUnavailable)?;
    let current = secret_text(set.current.material.as_bytes())?;
    let previous = set
        .previous
        .as_ref()
        .map(|version| secret_text(version.material.as_bytes()))
        .transpose()?;

    let mut desired = Vec::with_capacity(2);
    desired.push(current);
    if let Some(previous) = previous {
        if desired.iter().any(|value| value.as_str() == previous.as_str()) {
            return Err(TurnSecretReconcileError::InvalidSecret);
        }
        desired.push(previous);
    }

    let mut connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| TurnSecretReconcileError::DatabaseUnavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;
    verify_schema(&connection)?;

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;
    let existing = load_realm_secrets(&transaction, realm)?;

    let retained_count = existing
        .iter()
        .filter(|value| desired.iter().any(|candidate| candidate.as_str() == value.as_str()))
        .count();
    let mut inserted_count = 0;
    for value in &desired {
        let changed = transaction
            .execute(
                "INSERT OR IGNORE INTO turn_secret (realm, value) VALUES (?1, ?2)",
                params![realm, value.as_str()],
            )
            .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;
        inserted_count += changed;
    }

    let mut removed_count = 0;
    for value in &existing {
        if desired
            .iter()
            .all(|candidate| candidate.as_str() != value.as_str())
        {
            removed_count += transaction
                .execute(
                    "DELETE FROM turn_secret WHERE realm = ?1 AND value = ?2",
                    params![realm, value.as_str()],
                )
                .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;
        }
    }

    let verified = load_realm_secrets(&transaction, realm)?;
    if !same_secret_set(&verified, &desired) {
        return Err(TurnSecretReconcileError::VerificationFailed);
    }
    transaction
        .commit()
        .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;

    Ok(TurnSecretReconcileOutcome {
        desired_count: desired.len(),
        inserted_count,
        removed_count,
        retained_count,
    })
}

fn validate_realm(realm: &str) -> Result<(), TurnSecretReconcileError> {
    if realm.is_empty()
        || realm.len() > 127
        || realm.chars().any(char::is_control)
    {
        return Err(TurnSecretReconcileError::InvalidRealm);
    }
    Ok(())
}

fn secret_text(material: &[u8]) -> Result<Zeroizing<String>, TurnSecretReconcileError> {
    validate_coturn_rest_secret_material(material)
        .map_err(|_| TurnSecretReconcileError::InvalidSecret)?;
    let text = std::str::from_utf8(material)
        .map_err(|_| TurnSecretReconcileError::InvalidSecret)?
        .to_owned();
    Ok(Zeroizing::new(text))
}

fn verify_schema(connection: &Connection) -> Result<(), TurnSecretReconcileError> {
    connection
        .prepare("SELECT realm, value FROM turn_secret LIMIT 0")
        .map(|_| ())
        .map_err(|_| TurnSecretReconcileError::SchemaMismatch)
}

fn load_realm_secrets(
    connection: &Connection,
    realm: &str,
) -> Result<Vec<Zeroizing<String>>, TurnSecretReconcileError> {
    let mut statement = connection
        .prepare("SELECT value FROM turn_secret WHERE realm = ?1 ORDER BY value")
        .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;
    let rows = statement
        .query_map(params![realm], |row| row.get::<_, String>(0))
        .map_err(|_| TurnSecretReconcileError::DatabaseFailure)?;
    let mut values = Vec::new();
    for row in rows {
        values.push(Zeroizing::new(
            row.map_err(|_| TurnSecretReconcileError::DatabaseFailure)?,
        ));
    }
    Ok(values)
}

fn same_secret_set(left: &[Zeroizing<String>], right: &[Zeroizing<String>]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|value| right.iter().any(|candidate| candidate.as_str() == value.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use ucr_model::OpaqueId;
    use ucr_secrets::{
        InMemorySecretProvider, SecretMaterial, SecretProvider, SecretVersion,
    };

    fn temp_db(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ucr-coturn-{name}-{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    fn provider_with(
        current: &[u8],
        previous: Option<&[u8]>,
    ) -> (InMemorySecretProvider, SecretHandle) {
        let provider = InMemorySecretProvider::default();
        let handle = SecretHandle {
            secret_id: OpaqueId::new("turn-root").expect("id"),
            purpose: SecretPurpose::TurnCredentials,
        };
        provider
            .provision(
                handle.clone(),
                SecretVersion {
                    version_id: OpaqueId::new("v1").expect("version"),
                    material: SecretMaterial::new(current.to_vec()).expect("secret"),
                },
            )
            .expect("provision");
        if let Some(previous) = previous {
            provider
                .rotate(
                    &handle,
                    SecretVersion {
                        version_id: OpaqueId::new("v2").expect("version"),
                        material: SecretMaterial::new(previous.to_vec()).expect("secret"),
                    },
                )
                .expect("rotate");
        }
        (provider, handle)
    }

    fn initialize_db(path: &Path) {
        let connection = Connection::open(path).expect("db");
        connection
            .execute_batch(
                "CREATE TABLE turn_secret (
                    realm varchar(127) default '',
                    value varchar(128),
                    PRIMARY KEY (realm, value)
                );",
            )
            .expect("schema");
    }

    #[test]
    fn reconciliation_exactly_matches_current_and_previous_and_is_idempotent() {
        let path = temp_db("overlap");
        initialize_db(&path);
        let connection = Connection::open(&path).expect("db");
        connection
            .execute(
                "INSERT INTO turn_secret (realm, value) VALUES (?1, ?2)",
                params!["turn.example", "StaleStaleStaleStaleStaleStale12"],
            )
            .expect("stale");
        drop(connection);

        let (provider, handle) = provider_with(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Some(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        );
        let first = reconcile_coturn_sqlite_secret_set(
            &provider,
            &handle,
            &path,
            "turn.example",
            true,
        )
        .expect("reconcile");
        assert_eq!(first.desired_count, 2);
        assert_eq!(first.inserted_count, 2);
        assert_eq!(first.removed_count, 1);

        let second = reconcile_coturn_sqlite_secret_set(
            &provider,
            &handle,
            &path,
            "turn.example",
            true,
        )
        .expect("idempotent");
        assert_eq!(second.inserted_count, 0);
        assert_eq!(second.removed_count, 0);
        assert_eq!(second.retained_count, 2);

        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn reconciliation_does_not_touch_other_realms() {
        let path = temp_db("scope");
        initialize_db(&path);
        let connection = Connection::open(&path).expect("db");
        connection
            .execute(
                "INSERT INTO turn_secret (realm, value) VALUES (?1, ?2)",
                params!["other.example", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"],
            )
            .expect("other");
        drop(connection);

        let (provider, handle) =
            provider_with(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None);
        reconcile_coturn_sqlite_secret_set(
            &provider,
            &handle,
            &path,
            "turn.example",
            true,
        )
        .expect("reconcile");

        let connection = Connection::open(&path).expect("db");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM turn_secret WHERE realm = ?1",
                params!["other.example"],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 1);
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn reconciliation_requires_explicit_exclusive_ownership() {
        let path = temp_db("ownership");
        initialize_db(&path);
        let (provider, handle) =
            provider_with(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None);
        assert_eq!(
            reconcile_coturn_sqlite_secret_set(
                &provider,
                &handle,
                &path,
                "turn.example",
                false,
            ),
            Err(TurnSecretReconcileError::ExclusiveOwnershipRequired)
        );
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn reconciliation_fails_closed_on_missing_schema_or_unsafe_material() {
        let missing_schema = temp_db("missing-schema");
        Connection::open(&missing_schema).expect("db");
        let (provider, handle) =
            provider_with(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None);
        assert_eq!(
            reconcile_coturn_sqlite_secret_set(
                &provider,
                &handle,
                &missing_schema,
                "turn.example",
                true,
            ),
            Err(TurnSecretReconcileError::SchemaMismatch)
        );
        fs::remove_file(missing_schema).expect("cleanup");

        let path = temp_db("unsafe");
        initialize_db(&path);
        let (provider, handle) =
            provider_with(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!", None);
        assert_eq!(
            reconcile_coturn_sqlite_secret_set(
                &provider,
                &handle,
                &path,
                "turn.example",
                true,
            ),
            Err(TurnSecretReconcileError::InvalidSecret)
        );
        fs::remove_file(path).expect("cleanup");
    }
}

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{AttachmentStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{
    AttachmentChunk, AttachmentContentId, AttachmentDescriptor, AttachmentId, NamespaceId, OpaqueId,
    TenantId, TenantScope,
};
use ucr_protocol::{validate_attachment_descriptor, verify_attachment_chunk};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V45_OBJECTS_SQL: &str = "
CREATE TABLE attachments (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    content_sha256 BLOB NOT NULL CHECK(length(content_sha256) = 32),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    chunk_size_bytes INTEGER NOT NULL CHECK(chunk_size_bytes > 0),
    chunk_count INTEGER NOT NULL CHECK(chunk_count >= 0),
    media_type TEXT,
    file_name TEXT,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, attachment_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;

CREATE TABLE attachment_chunks (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
    offset_bytes INTEGER NOT NULL CHECK(offset_bytes >= 0),
    payload BLOB NOT NULL,
    sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, attachment_id, chunk_index),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, attachment_id)
      REFERENCES attachments(tenant_id, namespace_present, namespace_id, attachment_id)
      ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v45_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V45_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_v45_objects(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "attachments",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("attachment_id", "TEXT", 1, 4),
            ("content_sha256", "BLOB", 1, 0),
            ("size_bytes", "INTEGER", 1, 0),
            ("chunk_size_bytes", "INTEGER", 1, 0),
            ("chunk_count", "INTEGER", 1, 0),
            ("media_type", "TEXT", 0, 0),
            ("file_name", "TEXT", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "attachment_chunks",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("attachment_id", "TEXT", 1, 4),
            ("chunk_index", "INTEGER", 1, 5),
            ("offset_bytes", "INTEGER", 1, 0),
            ("payload", "BLOB", 1, 0),
            ("sha256", "BLOB", 1, 0),
        ],
    )?;

    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| map_sqlite_error(&error))?;
    if foreign_key_check
        .query([])
        .map_err(|error| map_sqlite_error(&error))?
        .next()
        .map_err(|error| map_sqlite_error(&error))?
        .is_some()
    {
        return Err(DurableStoreError::Corrupt);
    }
    drop(foreign_key_check);

    verify_rows(connection)
}

fn parse_id(value: String) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)
}

fn parse_scope(
    tenant: String,
    namespace_present: i64,
    namespace: String,
) -> Result<TenantScope, DurableStoreError> {
    let namespace_id = match (namespace_present, namespace.is_empty()) {
        (0, true) => None,
        (1, false) => Some(NamespaceId::from_opaque(parse_id(namespace)?)),
        _ => return Err(DurableStoreError::Corrupt),
    };
    Ok(TenantScope {
        tenant_id: TenantId::from_opaque(parse_id(tenant)?),
        namespace_id,
    })
}

fn hash32(value: Vec<u8>) -> Result<[u8; 32], DurableStoreError> {
    value.try_into().map_err(|_| DurableStoreError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, DurableStoreError> {
    i64::try_from(value).map_err(|_| DurableStoreError::InvalidRecord)
}

fn to_i64_u32(value: u32) -> i64 {
    i64::from(value)
}

fn from_u64(value: i64) -> Result<u64, DurableStoreError> {
    u64::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn from_u32(value: i64) -> Result<u32, DurableStoreError> {
    u32::try_from(value).map_err(|_| DurableStoreError::Corrupt)
}

fn load_descriptor_from(
    connection: &Connection,
    scope: &TenantScope,
    attachment_id: &AttachmentId,
) -> Result<Option<AttachmentDescriptor>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    connection
        .query_row(
            "SELECT content_sha256, size_bytes, chunk_size_bytes, chunk_count, media_type, file_name
             FROM attachments
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND attachment_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                attachment_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(
            |(sha256, size_bytes, chunk_size_bytes, chunk_count, media_type, file_name)| {
                let descriptor = AttachmentDescriptor {
                    attachment_id: attachment_id.clone(),
                    scope: scope.clone(),
                    content_id: AttachmentContentId {
                        sha256: hash32(sha256)?,
                    },
                    size_bytes: from_u64(size_bytes)?,
                    chunk_size_bytes: from_u32(chunk_size_bytes)?,
                    chunk_count: from_u32(chunk_count)?,
                    media_type,
                    file_name,
                };
                validate_attachment_descriptor(&descriptor)
                    .map_err(|_| DurableStoreError::Corrupt)?;
                Ok(descriptor)
            },
        )
        .transpose()
}

fn load_chunk_from(
    connection: &Connection,
    scope: &TenantScope,
    attachment_id: &AttachmentId,
    index: u32,
) -> Result<Option<AttachmentChunk>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let chunk = connection
        .query_row(
            "SELECT offset_bytes, payload, sha256 FROM attachment_chunks
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND attachment_id=?4 AND chunk_index=?5",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                attachment_id.as_opaque().as_str(),
                to_i64_u32(index),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?
        .map(|(offset_bytes, bytes, sha256)| {
            Ok(AttachmentChunk {
                attachment_id: attachment_id.clone(),
                index,
                offset_bytes: from_u64(offset_bytes)?,
                bytes,
                sha256: hash32(sha256)?,
            })
        })
        .transpose()?;

    if let Some(chunk) = chunk {
        let descriptor = load_descriptor_from(connection, scope, attachment_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        verify_attachment_chunk(&descriptor, &chunk).map_err(|_| DurableStoreError::Corrupt)?;
        Ok(Some(chunk))
    } else {
        Ok(None)
    }
}

fn verify_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT tenant_id, namespace_present, namespace_id, attachment_id FROM attachments",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| map_sqlite_error(&error))?;
    let mut descriptors = Vec::new();
    for row in rows {
        let (tenant, present, namespace, attachment_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        descriptors.push((
            parse_scope(tenant, present, namespace)?,
            AttachmentId::from_opaque(parse_id(attachment_id)?),
        ));
    }
    drop(statement);

    for (scope, attachment_id) in descriptors {
        let descriptor = load_descriptor_from(connection, &scope, &attachment_id)?
            .ok_or(DurableStoreError::Corrupt)?;
        for index in 0..descriptor.chunk_count {
            if let Some(chunk) = load_chunk_from(connection, &scope, &attachment_id, index)? {
                verify_attachment_chunk(&descriptor, &chunk)
                    .map_err(|_| DurableStoreError::Corrupt)?;
            }
        }

        let invalid_index: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM attachment_chunks
                    WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
                      AND attachment_id=?4 AND chunk_index>=?5
                )",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace_storage_key(&scope).present,
                    namespace_storage_key(&scope).value,
                    attachment_id.as_opaque().as_str(),
                    to_i64_u32(descriptor.chunk_count),
                ],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(&error))?;
        if invalid_index {
            return Err(DurableStoreError::Corrupt);
        }
    }
    Ok(())
}

impl AttachmentStore for SqliteLocalStore {
    fn persist_attachment_descriptor(
        &self,
        descriptor: &AttachmentDescriptor,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_attachment_descriptor(descriptor).map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&descriptor.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;

        if let Some(existing) =
            load_descriptor_from(&transaction, &descriptor.scope, &descriptor.attachment_id)?
        {
            return if existing == *descriptor {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }

        transaction
            .execute(
                "INSERT INTO attachments (
                    tenant_id, namespace_present, namespace_id, attachment_id, content_sha256,
                    size_bytes, chunk_size_bytes, chunk_count, media_type, file_name
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    descriptor.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    descriptor.attachment_id.as_opaque().as_str(),
                    descriptor.content_id.sha256.as_slice(),
                    to_i64(descriptor.size_bytes)?,
                    to_i64_u32(descriptor.chunk_size_bytes),
                    to_i64_u32(descriptor.chunk_count),
                    descriptor.media_type.as_deref(),
                    descriptor.file_name.as_deref(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn attachment_descriptor(
        &self,
        scope: &TenantScope,
        attachment_id: &AttachmentId,
    ) -> Result<Option<AttachmentDescriptor>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_descriptor_from(&connection, scope, attachment_id)
    }

    fn persist_attachment_chunk(
        &self,
        scope: &TenantScope,
        chunk: &AttachmentChunk,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let namespace = namespace_storage_key(scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let descriptor = load_descriptor_from(&transaction, scope, &chunk.attachment_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        verify_attachment_chunk(&descriptor, chunk)
            .map_err(|_| DurableStoreError::InvalidRecord)?;

        if let Some(existing) =
            load_chunk_from(&transaction, scope, &chunk.attachment_id, chunk.index)?
        {
            return if existing == *chunk {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }

        transaction
            .execute(
                "INSERT INTO attachment_chunks (
                    tenant_id, namespace_present, namespace_id, attachment_id, chunk_index,
                    offset_bytes, payload, sha256
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    chunk.attachment_id.as_opaque().as_str(),
                    to_i64_u32(chunk.index),
                    to_i64(chunk.offset_bytes)?,
                    chunk.bytes.as_slice(),
                    chunk.sha256.as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn attachment_chunk(
        &self,
        scope: &TenantScope,
        attachment_id: &AttachmentId,
        index: u32,
    ) -> Result<Option<AttachmentChunk>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_chunk_from(&connection, scope, attachment_id, index)
    }
}

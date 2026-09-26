use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{AttachmentStore, DurableRecordStatus, DurableStoreError};
use ucr_model::{
    AttachmentChunk, AttachmentContentId, AttachmentDescriptor, AttachmentId, TenantScope,
};
use ucr_protocol::{
    AttachmentProtocolError, validate_attachment_descriptor, verify_attachment_chunk,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_table_columns,
};

const V45_OBJECTS_SQL: &str = r"
CREATE TABLE attachments (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    content_sha256 BLOB NOT NULL CHECK(length(content_sha256) = 32),
    size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 68719476736),
    chunk_size_bytes INTEGER NOT NULL CHECK(chunk_size_bytes BETWEEN 1 AND 1048576),
    chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 0 AND 65536),
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
    chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 65535),
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
    Ok(())
}

impl AttachmentStore for SqliteLocalStore {
    fn persist_attachment_descriptor(
        &self,
        descriptor: &AttachmentDescriptor,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_attachment_descriptor(descriptor).map_err(map_attachment_write_error)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;

        if let Some(existing) =
            load_descriptor(&transaction, &descriptor.scope, &descriptor.attachment_id)?
        {
            return if existing == *descriptor {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }

        insert_descriptor(&transaction, descriptor)?;
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
        load_descriptor(&connection, scope, attachment_id)
    }

    fn persist_attachment_chunk(
        &self,
        scope: &TenantScope,
        chunk: &AttachmentChunk,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let descriptor = load_descriptor(&transaction, scope, &chunk.attachment_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        verify_attachment_chunk(&descriptor, chunk).map_err(map_attachment_write_error)?;

        if let Some(existing) = load_chunk(&transaction, &descriptor, chunk.index)? {
            return if existing == *chunk {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }

        insert_chunk(&transaction, scope, chunk)?;
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
        let Some(descriptor) = load_descriptor(&connection, scope, attachment_id)? else {
            return Ok(None);
        };
        load_chunk(&connection, &descriptor, index)
    }

    fn attachment_resume_index(
        &self,
        scope: &TenantScope,
        attachment_id: &AttachmentId,
    ) -> Result<u32, DurableStoreError> {
        let connection = self.lock_connection()?;
        let descriptor = load_descriptor(&connection, scope, attachment_id)?
            .ok_or(DurableStoreError::InvalidRecord)?;
        for index in 0..descriptor.chunk_count {
            match load_chunk(&connection, &descriptor, index)? {
                Some(_) => {}
                None => return Ok(index),
            }
        }
        Ok(descriptor.chunk_count)
    }
}

fn insert_descriptor(
    transaction: &Transaction<'_>,
    descriptor: &AttachmentDescriptor,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&descriptor.scope);
    let size_bytes =
        i64::try_from(descriptor.size_bytes).map_err(|_| DurableStoreError::InvalidRecord)?;
    transaction
        .execute(
            "INSERT INTO attachments (
                tenant_id, namespace_present, namespace_id, attachment_id,
                content_sha256, size_bytes, chunk_size_bytes, chunk_count, media_type, file_name
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                descriptor.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                descriptor.attachment_id.as_opaque().as_str(),
                descriptor.content_id.sha256.as_slice(),
                size_bytes,
                i64::from(descriptor.chunk_size_bytes),
                i64::from(descriptor.chunk_count),
                descriptor.media_type.as_deref(),
                descriptor.file_name.as_deref(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn insert_chunk(
    transaction: &Transaction<'_>,
    scope: &TenantScope,
    chunk: &AttachmentChunk,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let offset = i64::try_from(chunk.offset_bytes).map_err(|_| DurableStoreError::InvalidRecord)?;
    transaction
        .execute(
            "INSERT INTO attachment_chunks (
                tenant_id, namespace_present, namespace_id, attachment_id,
                chunk_index, offset_bytes, payload, sha256
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                chunk.attachment_id.as_opaque().as_str(),
                i64::from(chunk.index),
                offset,
                chunk.bytes.as_slice(),
                chunk.sha256.as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn load_descriptor(
    connection: &Connection,
    scope: &TenantScope,
    attachment_id: &AttachmentId,
) -> Result<Option<AttachmentDescriptor>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let stored = connection
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
        .map_err(|error| map_sqlite_error(&error))?;

    let Some((content_sha256, size_bytes, chunk_size_bytes, chunk_count, media_type, file_name)) =
        stored
    else {
        return Ok(None);
    };

    let sha256: [u8; 32] = content_sha256
        .try_into()
        .map_err(|_| DurableStoreError::Corrupt)?;
    let descriptor = AttachmentDescriptor {
        attachment_id: attachment_id.clone(),
        scope: scope.clone(),
        content_id: AttachmentContentId { sha256 },
        size_bytes: u64::try_from(size_bytes).map_err(|_| DurableStoreError::Corrupt)?,
        chunk_size_bytes: u32::try_from(chunk_size_bytes)
            .map_err(|_| DurableStoreError::Corrupt)?,
        chunk_count: u32::try_from(chunk_count).map_err(|_| DurableStoreError::Corrupt)?,
        media_type,
        file_name,
    };
    validate_attachment_descriptor(&descriptor).map_err(map_attachment_read_error)?;
    Ok(Some(descriptor))
}

fn load_chunk(
    connection: &Connection,
    descriptor: &AttachmentDescriptor,
    index: u32,
) -> Result<Option<AttachmentChunk>, DurableStoreError> {
    let namespace = namespace_storage_key(&descriptor.scope);
    let stored = connection
        .query_row(
            "SELECT offset_bytes, payload, sha256 FROM attachment_chunks
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3
               AND attachment_id=?4 AND chunk_index=?5",
            params![
                descriptor.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                descriptor.attachment_id.as_opaque().as_str(),
                i64::from(index),
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
        .map_err(|error| map_sqlite_error(&error))?;

    let Some((offset_bytes, bytes, sha256)) = stored else {
        return Ok(None);
    };
    let sha256: [u8; 32] = sha256.try_into().map_err(|_| DurableStoreError::Corrupt)?;
    let chunk = AttachmentChunk {
        attachment_id: descriptor.attachment_id.clone(),
        index,
        offset_bytes: u64::try_from(offset_bytes).map_err(|_| DurableStoreError::Corrupt)?,
        bytes,
        sha256,
    };
    verify_attachment_chunk(descriptor, &chunk).map_err(map_attachment_read_error)?;
    Ok(Some(chunk))
}

const fn map_attachment_write_error(_error: AttachmentProtocolError) -> DurableStoreError {
    DurableStoreError::InvalidRecord
}

const fn map_attachment_read_error(_error: AttachmentProtocolError) -> DurableStoreError {
    DurableStoreError::Corrupt
}

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use ucr_core::{ConversationStore, DurableRecordStatus, DurableStoreError, MessageStore};
use ucr_model::{
    ActorId, ActorKind, ActorRef, AttachmentId, ConversationId, ConversationKind,
    ConversationRecord, ConversationRef, CorrelationContext, CryptoSuite, DeliveryPolicy,
    DeliveryState, DeviceId, DeviceRef, EndpointId, ExternalMessageMapping, IdentityId,
    IntegrationId, KeyId, MessageCryptoMetadata, MessageEnvelope, MessageId, MessageRelation,
    MessageRelationKind, MessageSignature, OpaqueId, OriginRef, PrincipalId, ProtocolExtension,
    TenantScope,
};
use ucr_protocol::{
    EXTERNAL_MESSAGE_ID_LIMIT, MAX_PROTOCOL_EXTENSIONS, MESSAGE_CRYPTO_METADATA_LIMIT,
    canonical_message, canonical_protocol_extensions, validate_conversation,
    validate_conversation_parent_kind,
};

use super::{
    SqliteLocalStore, map_schema_change_error, map_sqlite_error, namespace_storage_key,
    verify_schema_v4, verify_table_columns,
};

pub(super) const V5_OBJECTS_SQL: &str = "
CREATE TABLE conversations (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    parent_conversation_id TEXT,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, conversation_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, parent_conversation_id)
      REFERENCES conversations(tenant_id, namespace_present, namespace_id, conversation_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";
const MESSAGE_TABLE_SQL: &str = "
CREATE TABLE messages (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    conversation_kind TEXT NOT NULL,
    author_id TEXT NOT NULL,
    author_kind TEXT NOT NULL,
    on_behalf_of TEXT,
    author_device_id TEXT NOT NULL,
    author_identity_id TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    logical_order BLOB NOT NULL CHECK(length(logical_order) = 8),
    content BLOB NOT NULL,
    reply_to TEXT,
    crypto_suite INTEGER,
    crypto_key_id TEXT,
    crypto_metadata BLOB,
    delivery_policy TEXT NOT NULL,
    delivery_state TEXT NOT NULL CHECK(delivery_state = 'persisted'),
    origin_principal_id TEXT,
    origin_endpoint_id TEXT,
    origin_integration_id TEXT,
    correlation_id TEXT NOT NULL,
    causation_id TEXT,
    idempotency_key TEXT,
    signature_key_id TEXT,
    signature_algorithm_id TEXT,
    signature_algorithm_version INTEGER,
    signature BLOB,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, message_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, conversation_id)
      REFERENCES conversations(tenant_id, namespace_present, namespace_id, conversation_id),
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> '')),
    CHECK(origin_principal_id IS NOT NULL OR origin_endpoint_id IS NOT NULL OR origin_integration_id IS NOT NULL),
    CHECK((crypto_suite IS NULL AND crypto_key_id IS NULL AND crypto_metadata IS NULL) OR crypto_suite = 1),
    CHECK((signature_key_id IS NULL AND signature_algorithm_id IS NULL AND
           signature_algorithm_version IS NULL AND signature IS NULL) OR
          (signature_key_id IS NOT NULL AND signature_algorithm_id = 'ed25519' AND
           signature_algorithm_version = 1 AND length(signature) = 64))
) WITHOUT ROWID;
";

const MESSAGE_CHILD_TABLES_SQL: &str = "
CREATE TABLE message_attachments (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    attachment_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, message_id, ordinal),
    UNIQUE(tenant_id, namespace_present, namespace_id, message_id, attachment_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE message_relations (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    relation_kind TEXT NOT NULL,
    target_message_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, message_id, ordinal),
    UNIQUE(tenant_id, namespace_present, namespace_id, message_id, relation_kind, target_message_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id) ON DELETE CASCADE
) WITHOUT ROWID;
";
const EXTERNAL_MAPPING_TABLE_SQL: &str = "
CREATE TABLE message_external_mappings (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL,
    namespace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    external_message_id BLOB NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, message_id, integration_id),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id) ON DELETE CASCADE
) WITHOUT ROWID;
";

const V10_OBJECTS_SQL: &str = "
CREATE TABLE message_extensions (
    tenant_id TEXT NOT NULL,
    namespace_present INTEGER NOT NULL CHECK(namespace_present IN (0, 1)),
    namespace_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0),
    name TEXT NOT NULL,
    critical INTEGER NOT NULL CHECK(critical IN (0, 1)),
    payload BLOB NOT NULL,
    PRIMARY KEY(tenant_id, namespace_present, namespace_id, message_id, position),
    UNIQUE(tenant_id, namespace_present, namespace_id, message_id, name),
    FOREIGN KEY(tenant_id, namespace_present, namespace_id, message_id)
      REFERENCES messages(tenant_id, namespace_present, namespace_id, message_id) ON DELETE CASCADE,
    CHECK((namespace_present = 0 AND namespace_id = '') OR
          (namespace_present = 1 AND namespace_id <> ''))
) WITHOUT ROWID;
";

pub(super) fn create_v5_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    for sql in [
        V5_OBJECTS_SQL,
        MESSAGE_TABLE_SQL,
        MESSAGE_CHILD_TABLES_SQL,
        EXTERNAL_MAPPING_TABLE_SQL,
    ] {
        transaction
            .execute_batch(sql)
            .map_err(|error| map_schema_change_error(&error))?;
    }
    Ok(())
}

pub(super) fn create_v10_objects(transaction: &Transaction<'_>) -> Result<(), DurableStoreError> {
    transaction
        .execute_batch(V10_OBJECTS_SQL)
        .map_err(|error| map_schema_change_error(&error))
}

pub(super) fn verify_schema_v10(connection: &Connection) -> Result<(), DurableStoreError> {
    super::command_store::verify_schema_v9(connection)?;
    verify_table_columns(
        connection,
        "message_extensions",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("message_id", "TEXT", 1, 4),
            ("position", "INTEGER", 1, 5),
            ("name", "TEXT", 1, 0),
            ("critical", "INTEGER", 1, 0),
            ("payload", "BLOB", 1, 0),
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
    verify_message_extension_rows(connection)
}

pub(super) fn verify_schema_v5(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_schema_v4(connection)?;
    verify_table_columns(
        connection,
        "conversations",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("conversation_id", "TEXT", 1, 4),
            ("kind", "TEXT", 1, 0),
            ("parent_conversation_id", "TEXT", 0, 0),
        ],
    )?;
    verify_message_table_shapes(connection)?;
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
    verify_conversation_rows(connection)?;
    verify_message_rows(connection)?;
    Ok(())
}

fn verify_message_table_shapes(connection: &Connection) -> Result<(), DurableStoreError> {
    verify_table_columns(
        connection,
        "messages",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("message_id", "TEXT", 1, 4),
            ("conversation_id", "TEXT", 1, 0),
            ("conversation_kind", "TEXT", 1, 0),
            ("author_id", "TEXT", 1, 0),
            ("author_kind", "TEXT", 1, 0),
            ("on_behalf_of", "TEXT", 0, 0),
            ("author_device_id", "TEXT", 1, 0),
            ("author_identity_id", "TEXT", 1, 0),
            ("created_at_unix_ms", "INTEGER", 1, 0),
            ("logical_order", "BLOB", 1, 0),
            ("content", "BLOB", 1, 0),
            ("reply_to", "TEXT", 0, 0),
            ("crypto_suite", "INTEGER", 0, 0),
            ("crypto_key_id", "TEXT", 0, 0),
            ("crypto_metadata", "BLOB", 0, 0),
            ("delivery_policy", "TEXT", 1, 0),
            ("delivery_state", "TEXT", 1, 0),
            ("origin_principal_id", "TEXT", 0, 0),
            ("origin_endpoint_id", "TEXT", 0, 0),
            ("origin_integration_id", "TEXT", 0, 0),
            ("correlation_id", "TEXT", 1, 0),
            ("causation_id", "TEXT", 0, 0),
            ("idempotency_key", "TEXT", 0, 0),
            ("signature_key_id", "TEXT", 0, 0),
            ("signature_algorithm_id", "TEXT", 0, 0),
            ("signature_algorithm_version", "INTEGER", 0, 0),
            ("signature", "BLOB", 0, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "message_attachments",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("message_id", "TEXT", 1, 4),
            ("ordinal", "INTEGER", 1, 5),
            ("attachment_id", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "message_relations",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("message_id", "TEXT", 1, 4),
            ("ordinal", "INTEGER", 1, 5),
            ("relation_kind", "TEXT", 1, 0),
            ("target_message_id", "TEXT", 1, 0),
        ],
    )?;
    verify_table_columns(
        connection,
        "message_external_mappings",
        &[
            ("tenant_id", "TEXT", 1, 1),
            ("namespace_present", "INTEGER", 1, 2),
            ("namespace_id", "TEXT", 1, 3),
            ("message_id", "TEXT", 1, 4),
            ("integration_id", "TEXT", 1, 5),
            ("external_message_id", "BLOB", 1, 0),
        ],
    )?;
    Ok(())
}

fn verify_conversation_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let invalid: bool = connection
        .query_row(
            r"SELECT EXISTS(
                SELECT 1
                FROM conversations AS child
                LEFT JOIN conversations AS parent
                  ON parent.tenant_id = child.tenant_id
                 AND parent.namespace_present = child.namespace_present
                 AND parent.namespace_id = child.namespace_id
                 AND parent.conversation_id = child.parent_conversation_id
                WHERE child.kind NOT IN ('direct','private_group','public_group','broadcast','community','room','topic','thread','system')
                   OR (child.kind IN ('topic','thread') AND child.parent_conversation_id IS NULL)
                   OR (child.kind NOT IN ('topic','thread') AND child.parent_conversation_id IS NOT NULL)
                   OR (child.kind = 'topic' AND (parent.conversation_id IS NULL OR parent.kind IN ('topic','thread')))
                   OR (child.kind = 'thread' AND (parent.conversation_id IS NULL OR parent.kind <> 'topic'))
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if invalid {
        Err(DurableStoreError::Corrupt)
    } else {
        Ok(())
    }
}

fn verify_message_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let crypto_limit =
        i64::try_from(MESSAGE_CRYPTO_METADATA_LIMIT).map_err(|_| DurableStoreError::Internal)?;
    let external_limit =
        i64::try_from(EXTERNAL_MESSAGE_ID_LIMIT).map_err(|_| DurableStoreError::Internal)?;
    let invalid: bool = connection
        .query_row(
            r"SELECT
                EXISTS(
                    SELECT 1 FROM messages AS m
                    JOIN conversations AS c
                      ON c.tenant_id=m.tenant_id AND c.namespace_present=m.namespace_present
                     AND c.namespace_id=m.namespace_id AND c.conversation_id=m.conversation_id
                    WHERE m.conversation_kind <> c.kind
                       OR m.author_kind NOT IN ('person','ai_agent','bot','organization','system')
                       OR m.delivery_policy NOT IN ('best_effort','durable','urgent','expiring','local_only','direct_only','no_relay','no_external_bridge','private_network_only')
                       OR (m.crypto_suite IS NOT NULL AND m.crypto_suite <> 1)
                       OR (m.crypto_metadata IS NOT NULL AND length(m.crypto_metadata) > ?1)
                       OR (length(m.content)=0
                           AND NOT EXISTS(SELECT 1 FROM message_attachments AS a WHERE a.tenant_id=m.tenant_id AND a.namespace_present=m.namespace_present AND a.namespace_id=m.namespace_id AND a.message_id=m.message_id)
                           AND NOT EXISTS(SELECT 1 FROM message_relations AS r WHERE r.tenant_id=m.tenant_id AND r.namespace_present=m.namespace_present AND r.namespace_id=m.namespace_id AND r.message_id=m.message_id))
                       OR (m.reply_to IS NULL AND EXISTS(SELECT 1 FROM message_relations AS r WHERE r.tenant_id=m.tenant_id AND r.namespace_present=m.namespace_present AND r.namespace_id=m.namespace_id AND r.message_id=m.message_id AND r.relation_kind='reply'))
                       OR (m.reply_to IS NOT NULL AND 1 <> (SELECT COUNT(*) FROM message_relations AS r WHERE r.tenant_id=m.tenant_id AND r.namespace_present=m.namespace_present AND r.namespace_id=m.namespace_id AND r.message_id=m.message_id AND r.relation_kind='reply' AND r.target_message_id=m.reply_to))
                )
                OR EXISTS(
                    SELECT 1 FROM message_relations AS r
                    WHERE r.relation_kind NOT IN ('reply','quote','edit','reaction','thread_parent','forward','reference')
                       OR r.target_message_id = r.message_id
                )
                OR EXISTS(
                    SELECT 1 FROM message_external_mappings AS x
                    WHERE length(x.external_message_id)=0 OR length(x.external_message_id) > ?2
                )",
            rusqlite::params![crypto_limit, external_limit],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    if invalid {
        Err(DurableStoreError::Corrupt)
    } else {
        Ok(())
    }
}

impl ConversationStore for SqliteLocalStore {
    fn persist_conversation(
        &self,
        conversation: &ConversationRecord,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        validate_conversation(conversation).map_err(|_| DurableStoreError::InvalidRecord)?;
        let namespace = namespace_storage_key(&conversation.scope);
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        if let Some(parent_id) = &conversation.parent_conversation_id {
            let parent = load_conversation_from(&transaction, &conversation.scope, parent_id)?
                .ok_or(DurableStoreError::InvalidRecord)?;
            validate_conversation_parent_kind(
                conversation.conversation.kind,
                parent.conversation.kind,
            )
            .map_err(|_| DurableStoreError::InvalidRecord)?;
        }
        let existing = load_conversation_from(
            &transaction,
            &conversation.scope,
            &conversation.conversation.conversation_id,
        )?;
        if let Some(existing) = existing {
            return if existing == *conversation {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        transaction
            .execute(
                "INSERT INTO conversations (
                    tenant_id, namespace_present, namespace_id,
                    conversation_id, kind, parent_conversation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    conversation.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    conversation
                        .conversation
                        .conversation_id
                        .as_opaque()
                        .as_str(),
                    conversation_kind_name(conversation.conversation.kind),
                    conversation
                        .parent_conversation_id
                        .as_ref()
                        .map(|value| value.as_opaque().as_str()),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn conversation(
        &self,
        scope: &TenantScope,
        conversation_id: &ConversationId,
    ) -> Result<Option<ConversationRecord>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_conversation_from(&connection, scope, conversation_id)
    }
}

fn load_conversation_from(
    connection: &Connection,
    scope: &TenantScope,
    conversation_id: &ConversationId,
) -> Result<Option<ConversationRecord>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT kind, parent_conversation_id FROM conversations
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND conversation_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                conversation_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some((kind, parent)) = row else {
        return Ok(None);
    };
    let kind = parse_conversation_kind(&kind)?;
    let parent_conversation_id = parent
        .map(|value| OpaqueId::new(value).map(ConversationId::from_opaque))
        .transpose()
        .map_err(|_| DurableStoreError::Corrupt)?;
    Ok(Some(ConversationRecord {
        scope: scope.clone(),
        conversation: ConversationRef {
            conversation_id: conversation_id.clone(),
            kind,
        },
        parent_conversation_id,
    }))
}

const fn conversation_kind_name(kind: ConversationKind) -> &'static str {
    match kind {
        ConversationKind::Direct => "direct",
        ConversationKind::PrivateGroup => "private_group",
        ConversationKind::PublicGroup => "public_group",
        ConversationKind::Broadcast => "broadcast",
        ConversationKind::Community => "community",
        ConversationKind::Room => "room",
        ConversationKind::Topic => "topic",
        ConversationKind::Thread => "thread",
        ConversationKind::System => "system",
    }
}

fn parse_conversation_kind(value: &str) -> Result<ConversationKind, DurableStoreError> {
    match value {
        "direct" => Ok(ConversationKind::Direct),
        "private_group" => Ok(ConversationKind::PrivateGroup),
        "public_group" => Ok(ConversationKind::PublicGroup),
        "broadcast" => Ok(ConversationKind::Broadcast),
        "community" => Ok(ConversationKind::Community),
        "room" => Ok(ConversationKind::Room),
        "topic" => Ok(ConversationKind::Topic),
        "thread" => Ok(ConversationKind::Thread),
        "system" => Ok(ConversationKind::System),
        _ => Err(DurableStoreError::Corrupt),
    }
}

impl MessageStore for SqliteLocalStore {
    fn persist_message(
        &self,
        message: &MessageEnvelope,
    ) -> Result<DurableRecordStatus, DurableStoreError> {
        let mut persisted =
            canonical_message(message).map_err(|_| DurableStoreError::InvalidRecord)?;
        if !matches!(
            persisted.delivery_state,
            DeliveryState::Created | DeliveryState::Persisted
        ) {
            return Err(DurableStoreError::InvalidRecord);
        }
        persisted.delivery_state = DeliveryState::Persisted;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sqlite_error(&error))?;
        let conversation = load_conversation_from(
            &transaction,
            &persisted.scope,
            &persisted.conversation.conversation_id,
        )?
        .ok_or(DurableStoreError::InvalidRecord)?;
        if conversation.conversation != persisted.conversation {
            return Err(DurableStoreError::Conflict);
        }
        if let Some(existing) =
            load_message_from(&transaction, &persisted.scope, &persisted.message_id)?
        {
            return if existing == persisted {
                Ok(DurableRecordStatus::Duplicate)
            } else {
                Err(DurableStoreError::Conflict)
            };
        }
        insert_message_row(&transaction, &persisted)?;
        insert_message_children(&transaction, &persisted)?;
        transaction
            .commit()
            .map_err(|error| map_sqlite_error(&error))?;
        Ok(DurableRecordStatus::Persisted)
    }

    fn message(
        &self,
        scope: &TenantScope,
        message_id: &MessageId,
    ) -> Result<Option<MessageEnvelope>, DurableStoreError> {
        let connection = self.lock_connection()?;
        load_message_from(&connection, scope, message_id)
    }
}

fn insert_message_row(
    transaction: &Transaction<'_>,
    message: &MessageEnvelope,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&message.scope);
    let crypto_suite = message
        .crypto_metadata
        .as_ref()
        .map(|value| match value.suite {
            CryptoSuite::UcrV1 => 1_i64,
        });
    let crypto_key_id = message
        .crypto_metadata
        .as_ref()
        .and_then(|value| value.key_id.as_ref())
        .map(|value| value.as_opaque().as_str());
    let crypto_metadata = message
        .crypto_metadata
        .as_ref()
        .map(|value| value.opaque_metadata.as_slice());
    let signature_key_id = message
        .signature
        .as_ref()
        .map(|value| value.key_id.as_opaque().as_str());
    let signature_algorithm = message
        .signature
        .as_ref()
        .map(|value| value.algorithm_id.as_str());
    let signature_version = message
        .signature
        .as_ref()
        .map(|value| i64::from(value.algorithm_version));
    let signature = message
        .signature
        .as_ref()
        .map(|value| value.signature.as_slice());
    transaction
        .execute(
            "INSERT INTO messages (
              tenant_id, namespace_present, namespace_id, message_id,
              conversation_id, conversation_kind, author_id, author_kind, on_behalf_of,
              author_device_id, author_identity_id, created_at_unix_ms, logical_order, content,
              reply_to, crypto_suite, crypto_key_id, crypto_metadata, delivery_policy, delivery_state,
              origin_principal_id, origin_endpoint_id, origin_integration_id, correlation_id,
              causation_id, idempotency_key, signature_key_id, signature_algorithm_id,
              signature_algorithm_version, signature
             ) VALUES (
              ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,
              ?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,
              ?21,?22,?23,?24,?25,?26,?27,?28,?29,?30
             )",
            params![
                message.scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message.message_id.as_opaque().as_str(),
                message.conversation.conversation_id.as_opaque().as_str(),
                conversation_kind_name(message.conversation.kind),
                message.author.actor_id.as_opaque().as_str(),
                actor_kind_name(message.author.kind),
                message.author.on_behalf_of.as_ref().map(|v| v.as_opaque().as_str()),
                message.author_device.device_id.as_opaque().as_str(),
                message.author_device.identity_id.as_opaque().as_str(),
                message.created_at_unix_ms,
                message.logical_order.to_be_bytes().as_slice(),
                message.content.as_slice(),
                message.reply_to.as_ref().map(|v| v.as_opaque().as_str()),
                crypto_suite,
                crypto_key_id,
                crypto_metadata,
                delivery_policy_name(message.delivery_policy),
                "persisted",
                message.origin.principal_id.as_ref().map(|v| v.as_opaque().as_str()),
                message.origin.endpoint_id.as_ref().map(|v| v.as_opaque().as_str()),
                message.origin.integration_id.as_ref().map(|v| v.as_opaque().as_str()),
                message.correlation.correlation_id.as_str(),
                message.correlation.causation_id.as_ref().map(OpaqueId::as_str),
                message.correlation.idempotency_key.as_deref(),
                signature_key_id,
                signature_algorithm,
                signature_version,
                signature,
            ],
        )
        .map_err(|error| map_sqlite_error(&error))?;
    Ok(())
}

fn insert_message_children(
    transaction: &Transaction<'_>,
    message: &MessageEnvelope,
) -> Result<(), DurableStoreError> {
    let namespace = namespace_storage_key(&message.scope);
    for (index, attachment) in message.attachment_ids.iter().enumerate() {
        let ordinal = i64::try_from(index).map_err(|_| DurableStoreError::InvalidRecord)?;
        transaction
            .execute(
                "INSERT INTO message_attachments VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    message.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    message.message_id.as_opaque().as_str(),
                    ordinal,
                    attachment.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    for (index, relation) in message.relations.iter().enumerate() {
        let ordinal = i64::try_from(index).map_err(|_| DurableStoreError::InvalidRecord)?;
        transaction
            .execute(
                "INSERT INTO message_relations VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    message.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    message.message_id.as_opaque().as_str(),
                    ordinal,
                    relation_kind_name(relation.kind),
                    relation.target_message_id.as_opaque().as_str(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    for mapping in &message.external_mappings {
        transaction
            .execute(
                "INSERT INTO message_external_mappings VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    message.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    message.message_id.as_opaque().as_str(),
                    mapping.integration_id.as_opaque().as_str(),
                    mapping.external_message_id.as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    for (position, extension) in message.extensions.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO message_extensions (
                    tenant_id, namespace_present, namespace_id, message_id,
                    position, name, critical, payload
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    message.scope.tenant_id.as_opaque().as_str(),
                    namespace.present,
                    namespace.value,
                    message.message_id.as_opaque().as_str(),
                    i64::try_from(position).map_err(|_| DurableStoreError::InvalidRecord)?,
                    extension.name,
                    i64::from(extension.critical),
                    extension.payload,
                ],
            )
            .map_err(|error| map_sqlite_error(&error))?;
    }
    Ok(())
}

const fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Person => "person",
        ActorKind::AiAgent => "ai_agent",
        ActorKind::Bot => "bot",
        ActorKind::Organization => "organization",
        ActorKind::System => "system",
    }
}

fn parse_actor_kind(value: &str) -> Result<ActorKind, DurableStoreError> {
    match value {
        "person" => Ok(ActorKind::Person),
        "ai_agent" => Ok(ActorKind::AiAgent),
        "bot" => Ok(ActorKind::Bot),
        "organization" => Ok(ActorKind::Organization),
        "system" => Ok(ActorKind::System),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn delivery_policy_name(policy: DeliveryPolicy) -> &'static str {
    match policy {
        DeliveryPolicy::BestEffort => "best_effort",
        DeliveryPolicy::Durable => "durable",
        DeliveryPolicy::Urgent => "urgent",
        DeliveryPolicy::Expiring => "expiring",
        DeliveryPolicy::LocalOnly => "local_only",
        DeliveryPolicy::DirectOnly => "direct_only",
        DeliveryPolicy::NoRelay => "no_relay",
        DeliveryPolicy::NoExternalBridge => "no_external_bridge",
        DeliveryPolicy::PrivateNetworkOnly => "private_network_only",
    }
}

fn parse_delivery_policy(value: &str) -> Result<DeliveryPolicy, DurableStoreError> {
    match value {
        "best_effort" => Ok(DeliveryPolicy::BestEffort),
        "durable" => Ok(DeliveryPolicy::Durable),
        "urgent" => Ok(DeliveryPolicy::Urgent),
        "expiring" => Ok(DeliveryPolicy::Expiring),
        "local_only" => Ok(DeliveryPolicy::LocalOnly),
        "direct_only" => Ok(DeliveryPolicy::DirectOnly),
        "no_relay" => Ok(DeliveryPolicy::NoRelay),
        "no_external_bridge" => Ok(DeliveryPolicy::NoExternalBridge),
        "private_network_only" => Ok(DeliveryPolicy::PrivateNetworkOnly),
        _ => Err(DurableStoreError::Corrupt),
    }
}

const fn relation_kind_name(kind: MessageRelationKind) -> &'static str {
    match kind {
        MessageRelationKind::Reply => "reply",
        MessageRelationKind::Quote => "quote",
        MessageRelationKind::Edit => "edit",
        MessageRelationKind::Reaction => "reaction",
        MessageRelationKind::ThreadParent => "thread_parent",
        MessageRelationKind::Forward => "forward",
        MessageRelationKind::Reference => "reference",
    }
}

fn parse_relation_kind(value: &str) -> Result<MessageRelationKind, DurableStoreError> {
    match value {
        "reply" => Ok(MessageRelationKind::Reply),
        "quote" => Ok(MessageRelationKind::Quote),
        "edit" => Ok(MessageRelationKind::Edit),
        "reaction" => Ok(MessageRelationKind::Reaction),
        "thread_parent" => Ok(MessageRelationKind::ThreadParent),
        "forward" => Ok(MessageRelationKind::Forward),
        "reference" => Ok(MessageRelationKind::Reference),
        _ => Err(DurableStoreError::Corrupt),
    }
}

struct StoredMessageRow {
    conversation_id: String,
    conversation_kind: String,
    author_id: String,
    author_kind: String,
    on_behalf_of: Option<String>,
    author_device_id: String,
    author_identity_id: String,
    created_at_unix_ms: i64,
    logical_order: Vec<u8>,
    content: Vec<u8>,
    reply_to: Option<String>,
    crypto_suite: Option<i64>,
    crypto_key_id: Option<String>,
    crypto_metadata: Option<Vec<u8>>,
    delivery_policy: String,
    delivery_state: String,
    origin_principal_id: Option<String>,
    origin_endpoint_id: Option<String>,
    origin_integration_id: Option<String>,
    correlation_id: String,
    causation_id: Option<String>,
    idempotency_key: Option<String>,
    signature_key_id: Option<String>,
    signature_algorithm_id: Option<String>,
    signature_algorithm_version: Option<i64>,
    signature: Option<Vec<u8>>,
}

fn load_message_from(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &MessageId,
) -> Result<Option<MessageEnvelope>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let row = connection
        .query_row(
            "SELECT conversation_id, conversation_kind, author_id, author_kind, on_behalf_of,
                    author_device_id, author_identity_id, created_at_unix_ms, logical_order, content,
                    reply_to, crypto_suite, crypto_key_id, crypto_metadata, delivery_policy,
                    delivery_state, origin_principal_id, origin_endpoint_id, origin_integration_id,
                    correlation_id, causation_id, idempotency_key, signature_key_id,
                    signature_algorithm_id, signature_algorithm_version, signature
             FROM messages
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4",
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |row| {
                Ok(StoredMessageRow {
                    conversation_id: row.get(0)?,
                    conversation_kind: row.get(1)?,
                    author_id: row.get(2)?,
                    author_kind: row.get(3)?,
                    on_behalf_of: row.get(4)?,
                    author_device_id: row.get(5)?,
                    author_identity_id: row.get(6)?,
                    created_at_unix_ms: row.get(7)?,
                    logical_order: row.get(8)?,
                    content: row.get(9)?,
                    reply_to: row.get(10)?,
                    crypto_suite: row.get(11)?,
                    crypto_key_id: row.get(12)?,
                    crypto_metadata: row.get(13)?,
                    delivery_policy: row.get(14)?,
                    delivery_state: row.get(15)?,
                    origin_principal_id: row.get(16)?,
                    origin_endpoint_id: row.get(17)?,
                    origin_integration_id: row.get(18)?,
                    correlation_id: row.get(19)?,
                    causation_id: row.get(20)?,
                    idempotency_key: row.get(21)?,
                    signature_key_id: row.get(22)?,
                    signature_algorithm_id: row.get(23)?,
                    signature_algorithm_version: row.get(24)?,
                    signature: row.get(25)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_sqlite_error(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let attachment_ids = load_attachments(connection, scope, message_id)?;
    let relations = load_relations(connection, scope, message_id)?;
    let external_mappings = load_external_mappings(connection, scope, message_id)?;
    let extensions = load_message_extensions(connection, scope, message_id)?;
    let message = decode_message_row(
        scope,
        message_id,
        row,
        attachment_ids,
        relations,
        external_mappings,
        extensions,
    )?;
    canonical_message(&message)
        .map(Some)
        .map_err(|_| DurableStoreError::Corrupt)
}

fn decode_message_row(
    scope: &TenantScope,
    message_id: &MessageId,
    row: StoredMessageRow,
    attachment_ids: Vec<AttachmentId>,
    relations: Vec<MessageRelation>,
    external_mappings: Vec<ExternalMessageMapping>,
    extensions: Vec<ProtocolExtension>,
) -> Result<MessageEnvelope, DurableStoreError> {
    let logical_order: [u8; 8] = row
        .logical_order
        .try_into()
        .map_err(|_| DurableStoreError::Corrupt)?;
    let crypto_metadata =
        decode_crypto_metadata(row.crypto_suite, row.crypto_key_id, row.crypto_metadata)?;
    let signature = decode_signature(
        row.signature_key_id,
        row.signature_algorithm_id,
        row.signature_algorithm_version,
        row.signature,
    )?;
    if row.delivery_state != "persisted" {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(MessageEnvelope {
        message_id: message_id.clone(),
        scope: scope.clone(),
        conversation: ConversationRef {
            conversation_id: ConversationId::from_opaque(parse_opaque(row.conversation_id)?),
            kind: parse_conversation_kind(&row.conversation_kind)?,
        },
        author: ActorRef {
            actor_id: ActorId::from_opaque(parse_opaque(row.author_id)?),
            kind: parse_actor_kind(&row.author_kind)?,
            on_behalf_of: row
                .on_behalf_of
                .map(parse_opaque)
                .transpose()?
                .map(PrincipalId::from_opaque),
        },
        author_device: DeviceRef {
            device_id: DeviceId::from_opaque(parse_opaque(row.author_device_id)?),
            identity_id: IdentityId::from_opaque(parse_opaque(row.author_identity_id)?),
        },
        created_at_unix_ms: row.created_at_unix_ms,
        logical_order: u64::from_be_bytes(logical_order),
        content: row.content,
        attachment_ids,
        reply_to: row
            .reply_to
            .map(parse_opaque)
            .transpose()?
            .map(MessageId::from_opaque),
        relations,
        crypto_metadata,
        delivery_policy: parse_delivery_policy(&row.delivery_policy)?,
        delivery_state: DeliveryState::Persisted,
        origin: OriginRef {
            principal_id: row
                .origin_principal_id
                .map(parse_opaque)
                .transpose()?
                .map(PrincipalId::from_opaque),
            endpoint_id: row
                .origin_endpoint_id
                .map(parse_opaque)
                .transpose()?
                .map(EndpointId::from_opaque),
            integration_id: row
                .origin_integration_id
                .map(parse_opaque)
                .transpose()?
                .map(IntegrationId::from_opaque),
        },
        correlation: CorrelationContext {
            correlation_id: parse_opaque(row.correlation_id)?,
            causation_id: row.causation_id.map(parse_opaque).transpose()?,
            idempotency_key: row.idempotency_key,
        },
        extensions,
        external_mappings,
        signature,
    })
}

fn parse_opaque(value: String) -> Result<OpaqueId, DurableStoreError> {
    OpaqueId::new(value).map_err(|_| DurableStoreError::Corrupt)
}

fn decode_crypto_metadata(
    suite: Option<i64>,
    key_id: Option<String>,
    metadata: Option<Vec<u8>>,
) -> Result<Option<MessageCryptoMetadata>, DurableStoreError> {
    match (suite, key_id, metadata) {
        (None, None, None) => Ok(None),
        (Some(1), key_id, Some(opaque_metadata)) => Ok(Some(MessageCryptoMetadata {
            suite: CryptoSuite::UcrV1,
            key_id: key_id
                .map(parse_opaque)
                .transpose()?
                .map(KeyId::from_opaque),
            opaque_metadata,
        })),
        _ => Err(DurableStoreError::Corrupt),
    }
}

fn decode_signature(
    key_id: Option<String>,
    algorithm_id: Option<String>,
    algorithm_version: Option<i64>,
    signature: Option<Vec<u8>>,
) -> Result<Option<MessageSignature>, DurableStoreError> {
    match (key_id, algorithm_id, algorithm_version, signature) {
        (None, None, None, None) => Ok(None),
        (Some(key_id), Some(algorithm_id), Some(version), Some(signature)) => {
            let algorithm_version =
                u32::try_from(version).map_err(|_| DurableStoreError::Corrupt)?;
            Ok(Some(MessageSignature {
                key_id: KeyId::from_opaque(parse_opaque(key_id)?),
                algorithm_id,
                algorithm_version,
                signature,
            }))
        }
        _ => Err(DurableStoreError::Corrupt),
    }
}
fn load_attachments(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &MessageId,
) -> Result<Vec<AttachmentId>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT attachment_id FROM message_attachments
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4
             ORDER BY ordinal ASC",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| map_sqlite_error(&error))?
        .map(|value| value.map_err(|error| map_sqlite_error(&error)))
        .map(|value| value.and_then(parse_opaque).map(AttachmentId::from_opaque))
        .collect()
}
fn load_relations(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &MessageId,
) -> Result<Vec<MessageRelation>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT relation_kind, target_message_id FROM message_relations
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4
             ORDER BY ordinal ASC",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| {
        let (kind, target) = row.map_err(|error| map_sqlite_error(&error))?;
        Ok(MessageRelation {
            kind: parse_relation_kind(&kind)?,
            target_message_id: MessageId::from_opaque(parse_opaque(target)?),
        })
    })
    .collect()
}
fn load_external_mappings(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &MessageId,
) -> Result<Vec<ExternalMessageMapping>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT integration_id, external_message_id FROM message_external_mappings
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4
             ORDER BY integration_id ASC",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error))?;
    rows.map(|row| {
        let (integration_id, external_message_id) =
            row.map_err(|error| map_sqlite_error(&error))?;
        Ok(ExternalMessageMapping {
            integration_id: IntegrationId::from_opaque(parse_opaque(integration_id)?),
            external_message_id,
        })
    })
    .collect()
}

fn load_message_extensions(
    connection: &Connection,
    scope: &TenantScope,
    message_id: &MessageId,
) -> Result<Vec<ProtocolExtension>, DurableStoreError> {
    let namespace = namespace_storage_key(scope);
    let mut statement = connection
        .prepare(
            "SELECT position, name, critical, payload FROM message_extensions
             WHERE tenant_id=?1 AND namespace_present=?2 AND namespace_id=?3 AND message_id=?4
             ORDER BY position ASC",
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let rows = statement
        .query_map(
            params![
                scope.tenant_id.as_opaque().as_str(),
                namespace.present,
                namespace.value,
                message_id.as_opaque().as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error))?;
    let mut extensions = Vec::new();
    for (expected_position, row) in rows.enumerate() {
        if expected_position >= MAX_PROTOCOL_EXTENSIONS {
            return Err(DurableStoreError::Corrupt);
        }
        let (position, name, critical, payload) = row.map_err(|error| map_sqlite_error(&error))?;
        if position != i64::try_from(expected_position).map_err(|_| DurableStoreError::Corrupt)? {
            return Err(DurableStoreError::Corrupt);
        }
        let critical = match critical {
            0 => false,
            1 => true,
            _ => return Err(DurableStoreError::Corrupt),
        };
        extensions.push(ProtocolExtension {
            name,
            critical,
            payload,
        });
    }
    let canonical =
        canonical_protocol_extensions(&extensions).map_err(|_| DurableStoreError::Corrupt)?;
    if canonical != extensions {
        return Err(DurableStoreError::Corrupt);
    }
    Ok(extensions)
}

fn verify_message_extension_rows(connection: &Connection) -> Result<(), DurableStoreError> {
    let mut statement = connection
        .prepare("SELECT tenant_id, namespace_present, namespace_id, message_id FROM messages")
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
    let mut keys = Vec::new();
    for row in rows {
        keys.push(row.map_err(|error| map_sqlite_error(&error))?);
    }
    drop(statement);
    for (tenant, present, namespace, message_id) in keys {
        let namespace_id = match (present, namespace.is_empty()) {
            (0, true) => None,
            (1, false) => Some(ucr_model::NamespaceId::from_opaque(parse_opaque(
                namespace,
            )?)),
            _ => return Err(DurableStoreError::Corrupt),
        };
        let scope = TenantScope {
            tenant_id: ucr_model::TenantId::from_opaque(parse_opaque(tenant)?),
            namespace_id,
        };
        let message_id = MessageId::from_opaque(parse_opaque(message_id)?);
        load_message_extensions(connection, &scope, &message_id)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    };

    use rusqlite::Connection;
    use ucr_core::{
        CommandAcceptanceStore, ConversationStore, DurableRecordStatus, DurableStoreError,
        MessageStore, StorageProvider,
    };
    use ucr_model::*;
    use ucr_protocol::{CommandReceiptStatus, MAX_PROTOCOL_EXTENSIONS, canonical_message};

    use super::SqliteLocalStore;
    use crate::{SQLITE_SCHEMA_VERSION, UCR_SQLITE_APPLICATION_ID};

    static DB_SEQUENCE: AtomicU64 = AtomicU64::new(40_000);
    pub(crate) struct TestDb(PathBuf);

    impl TestDb {
        pub(crate) fn new() -> Self {
            let sequence = DB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ucr-message-{}-{sequence}.sqlite3",
                std::process::id()
            )))
        }

        pub(crate) fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    fn oid(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test id")
    }
    pub(crate) fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(oid("tenant-a")),
            namespace_id: Some(NamespaceId::from_opaque(oid("namespace-a"))),
        }
    }

    pub(crate) fn conversation() -> ConversationRecord {
        ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("conversation-a")),
                kind: ConversationKind::Direct,
            },
            parent_conversation_id: None,
        }
    }

    pub(crate) fn message(content: &[u8]) -> MessageEnvelope {
        let reply = MessageId::from_opaque(oid("message-parent"));
        MessageEnvelope {
            message_id: MessageId::from_opaque(oid("message-a")),
            scope: scope(),
            conversation: conversation().conversation,
            author: ActorRef {
                actor_id: ActorId::from_opaque(oid("actor-a")),
                kind: ActorKind::Person,
                on_behalf_of: Some(PrincipalId::from_opaque(oid("principal-delegated"))),
            },
            author_device: DeviceRef {
                device_id: DeviceId::from_opaque(oid("device-a")),
                identity_id: IdentityId::from_opaque(oid("identity-a")),
            },
            created_at_unix_ms: 1_700_000_000_000,
            logical_order: 42,
            content: content.to_vec(),
            attachment_ids: vec![
                AttachmentId::from_opaque(oid("attachment-a")),
                AttachmentId::from_opaque(oid("attachment-b")),
            ],
            reply_to: Some(reply.clone()),
            relations: vec![
                MessageRelation {
                    kind: MessageRelationKind::Quote,
                    target_message_id: MessageId::from_opaque(oid("message-quoted")),
                },
                MessageRelation {
                    kind: MessageRelationKind::Reply,
                    target_message_id: reply,
                },
            ],
            crypto_metadata: Some(MessageCryptoMetadata {
                suite: CryptoSuite::UcrV1,
                key_id: Some(KeyId::from_opaque(oid("message-key-a"))),
                opaque_metadata: b"crypto-metadata".to_vec(),
            }),
            delivery_policy: DeliveryPolicy::Durable,
            delivery_state: DeliveryState::Created,
            origin: OriginRef {
                principal_id: Some(PrincipalId::from_opaque(oid("principal-origin"))),
                endpoint_id: Some(EndpointId::from_opaque(oid("endpoint-origin"))),
                integration_id: Some(IntegrationId::from_opaque(oid("integration-origin"))),
            },
            correlation: CorrelationContext {
                correlation_id: oid("correlation-a"),
                causation_id: Some(oid("causation-a")),
                idempotency_key: Some("message-idempotency-a".to_owned()),
            },
            extensions: Vec::new(),
            external_mappings: vec![
                ExternalMessageMapping {
                    integration_id: IntegrationId::from_opaque(oid("integration-z")),
                    external_message_id: b"external-z".to_vec(),
                },
                ExternalMessageMapping {
                    integration_id: IntegrationId::from_opaque(oid("integration-a")),
                    external_message_id: b"external-a".to_vec(),
                },
            ],
            signature: Some(MessageSignature {
                key_id: KeyId::from_opaque(oid("signing-key-a")),
                algorithm_id: "ed25519".to_owned(),
                algorithm_version: 1,
                signature: vec![7_u8; 64],
            }),
        }
    }

    fn command() -> CommandEnvelope {
        CommandEnvelope {
            command_id: CommandId::from_opaque(oid("command-v4")),
            scope: scope(),
            command_type: "ucr.message.persist".to_owned(),
            payload: b"before-v5".to_vec(),
            correlation: CorrelationContext {
                correlation_id: oid("correlation-v4"),
                causation_id: None,
                idempotency_key: Some("idempotency-v4".to_owned()),
            },
            schema_version: ProtocolVersion::new(1, 0),
            extensions: Vec::new(),
        }
    }
    #[test]
    fn message_round_trip_survives_restart_with_all_canonical_fields() {
        let db = TestDb::new();
        let mut expected = canonical_message(&message(b"hello")).expect("canonical message");
        expected.delivery_state = DeliveryState::Persisted;
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            assert_eq!(
                store.persist_conversation(&conversation()),
                Ok(DurableRecordStatus::Persisted)
            );
            assert_eq!(
                store.persist_message(&message(b"hello")),
                Ok(DurableRecordStatus::Persisted)
            );
        }
        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let loaded = reopened
            .message(&scope(), &message(b"hello").message_id)
            .expect("load message")
            .expect("message exists");
        assert_eq!(loaded, expected);
    }
    #[test]
    fn conversation_hierarchy_requires_existing_parent_with_valid_kind() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        let root = conversation();
        store.persist_conversation(&root).expect("persist root");

        let topic = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("topic-sqlite")),
                kind: ConversationKind::Topic,
            },
            parent_conversation_id: Some(root.conversation.conversation_id.clone()),
        };
        assert_eq!(
            store.persist_conversation(&topic),
            Ok(DurableRecordStatus::Persisted)
        );

        let thread = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("thread-sqlite")),
                kind: ConversationKind::Thread,
            },
            parent_conversation_id: Some(topic.conversation.conversation_id.clone()),
        };
        assert_eq!(
            store.persist_conversation(&thread),
            Ok(DurableRecordStatus::Persisted)
        );

        let invalid = ConversationRecord {
            scope: scope(),
            conversation: ConversationRef {
                conversation_id: ConversationId::from_opaque(oid("thread-invalid")),
                kind: ConversationKind::Thread,
            },
            parent_conversation_id: Some(root.conversation.conversation_id.clone()),
        };
        assert_eq!(
            store.persist_conversation(&invalid),
            Err(DurableStoreError::InvalidRecord)
        );
    }

    #[test]
    fn message_extensions_survive_restart_and_are_part_of_conflict_semantics() {
        let db = TestDb::new();
        let mut first = message(b"extension-message");
        first.extensions = vec![
            ProtocolExtension {
                name: "vendor.example.z".to_owned(),
                critical: false,
                payload: b"z".to_vec(),
            },
            ProtocolExtension {
                name: "ucr.example.a".to_owned(),
                critical: false,
                payload: b"a".to_vec(),
            },
        ];
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .persist_conversation(&conversation())
                .expect("persist conversation");
            assert_eq!(
                store.persist_message(&first),
                Ok(DurableRecordStatus::Persisted)
            );
        }

        let reopened = SqliteLocalStore::open(db.path()).expect("reopen store");
        let loaded = reopened
            .message(&scope(), &first.message_id)
            .expect("load message")
            .expect("message exists");
        assert_eq!(loaded.extensions[0].name, "ucr.example.a");
        assert_eq!(loaded.extensions[1].name, "vendor.example.z");

        let mut reordered = first.clone();
        reordered.extensions.reverse();
        assert_eq!(
            reopened.persist_message(&reordered),
            Ok(DurableRecordStatus::Duplicate)
        );

        let mut changed = reordered;
        changed.extensions[0].payload.push(b'!');
        assert_eq!(
            reopened.persist_message(&changed),
            Err(DurableStoreError::Conflict)
        );
    }

    #[test]
    fn scoped_message_id_reuse_with_different_semantics_conflicts() {
        let db = TestDb::new();
        let store = SqliteLocalStore::open(db.path()).expect("open store");
        store
            .persist_conversation(&conversation())
            .expect("persist conversation");
        assert_eq!(
            store.persist_message(&message(b"first")),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            store.persist_message(&message(b"second")),
            Err(DurableStoreError::Conflict)
        );
        assert_eq!(
            store.persist_message(&message(b"first")),
            Ok(DurableRecordStatus::Duplicate)
        );
    }
    #[test]
    fn concurrent_conflicting_messages_have_single_winner() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize store");
            store
                .persist_conversation(&conversation())
                .expect("persist conversation");
        }
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |payload: &'static [u8]| {
            let path = db.path().to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let store = SqliteLocalStore::open(path).expect("open concurrent store");
                barrier.wait();
                store.persist_message(&message(payload))
            })
        };
        let first = spawn(b"first");
        let second = spawn(b"second");
        barrier.wait();
        let results = [
            first.join().expect("first thread"),
            second.join().expect("second thread"),
        ];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(DurableRecordStatus::Persisted)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DurableStoreError::Conflict)))
                .count(),
            1
        );
    }
    #[test]
    fn corrupt_conversation_hierarchy_is_rejected_on_reopen() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            let root = conversation();
            store.persist_conversation(&root).expect("persist root");
            let topic = ConversationRecord {
                scope: scope(),
                conversation: ConversationRef {
                    conversation_id: ConversationId::from_opaque(oid("topic-corrupt")),
                    kind: ConversationKind::Topic,
                },
                parent_conversation_id: Some(root.conversation.conversation_id),
            };
            store.persist_conversation(&topic).expect("persist topic");
        }
        let raw = Connection::open(db.path()).expect("raw sqlite");
        raw.execute(
            "UPDATE conversations SET kind='thread' WHERE conversation_id='topic-corrupt'",
            [],
        )
        .expect("corrupt hierarchy");
        drop(raw);
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn v9_to_v10_migration_preserves_existing_messages_as_empty_extensions() {
        let db = TestDb::new();
        let legacy = message(b"pre-v10");
        {
            let store = SqliteLocalStore::open(db.path()).expect("create current store");
            store
                .persist_conversation(&conversation())
                .expect("persist conversation");
            store
                .persist_message(&legacy)
                .expect("persist legacy message");
        }
        {
            let connection = Connection::open(db.path()).expect("open raw sqlite");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=OFF;
                     DROP TABLE message_extensions;
                     PRAGMA user_version=9;",
                )
                .expect("simulate exact v9 shape");
        }

        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v9 to v10");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let loaded = migrated
            .message(&scope(), &legacy.message_id)
            .expect("load migrated message")
            .expect("message exists");
        assert!(loaded.extensions.is_empty());
    }

    #[test]
    fn oversized_persisted_message_extension_set_is_rejected_on_reopen() {
        let db = TestDb::new();
        let value = message(b"extension-budget");
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .persist_conversation(&conversation())
                .expect("persist conversation");
            store.persist_message(&value).expect("persist message");
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            for position in 0..=MAX_PROTOCOL_EXTENSIONS {
                connection
                    .execute(
                        "INSERT INTO message_extensions (
                            tenant_id, namespace_present, namespace_id, message_id,
                            position, name, critical, payload
                         ) VALUES (?1,1,?2,?3,?4,?5,0,?6)",
                        rusqlite::params![
                            "tenant-a",
                            "namespace-a",
                            value.message_id.as_opaque().as_str(),
                            i64::try_from(position).expect("position"),
                            format!("vendor.example.message-{position}"),
                            Vec::<u8>::new(),
                        ],
                    )
                    .expect("insert corrupt message extension");
            }
        }
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn corrupt_message_extension_rows_are_rejected_on_reopen() {
        let db = TestDb::new();
        let mut value = message(b"corrupt-extension");
        value.extensions.push(ProtocolExtension {
            name: "ucr.example.valid".to_owned(),
            critical: false,
            payload: b"payload".to_vec(),
        });
        {
            let store = SqliteLocalStore::open(db.path()).expect("open store");
            store
                .persist_conversation(&conversation())
                .expect("persist conversation");
            store.persist_message(&value).expect("persist message");
        }
        {
            let connection = Connection::open(db.path()).expect("raw sqlite");
            connection
                .execute("UPDATE message_extensions SET name='not-namespaced'", [])
                .expect("corrupt extension");
        }
        assert!(matches!(
            SqliteLocalStore::open(db.path()),
            Err(DurableStoreError::Corrupt)
        ));
    }

    #[test]
    fn v4_store_migrates_to_v5_without_losing_existing_durable_state() {
        let db = TestDb::new();
        {
            let store = SqliteLocalStore::open(db.path()).expect("initialize store");
            let accepted = store.accept_command(&command()).expect("accept command");
            assert_eq!(accepted.status, CommandReceiptStatus::Accepted);
        }
        let connection = Connection::open(db.path()).expect("open raw store");
        connection
            .execute_batch(
                "DROP TABLE message_extensions;
                 DROP TABLE command_extensions;
                 DROP TABLE command_protocol_metadata;
                 DROP TABLE event_extensions;
                 DROP TABLE sync_checkpoints;
                 DROP TABLE sync_session_conversations;
                 DROP TABLE sync_sessions;
                 DROP TABLE delivery_evidence;
                 DROP TABLE delivery_attempts;
                 DROP TABLE message_external_mappings;
                 DROP TABLE message_relations;
                 DROP TABLE message_attachments;
                 DROP TABLE messages;
                 DROP TABLE conversations;",
            )
            .expect("remove v5 objects");
        connection
            .pragma_update(None, "application_id", UCR_SQLITE_APPLICATION_ID)
            .expect("keep application id");
        connection
            .pragma_update(None, "user_version", 4_u32)
            .expect("set v4");
        drop(connection);
        let migrated = SqliteLocalStore::open(db.path()).expect("migrate v4 to v5");
        assert_eq!(migrated.schema_version(), Ok(SQLITE_SCHEMA_VERSION));
        let duplicate = migrated
            .accept_command(&command())
            .expect("deduplicate pre-v5 command");
        assert_eq!(duplicate.status, CommandReceiptStatus::Duplicate);
        assert_eq!(
            migrated.persist_conversation(&conversation()),
            Ok(DurableRecordStatus::Persisted)
        );
        assert_eq!(
            migrated.persist_message(&message(b"after-migration")),
            Ok(DurableRecordStatus::Persisted)
        );
    }
}

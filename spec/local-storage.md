# UCR local storage contract

Status: **Experimental / Phase 6 foundation, extended through Phase 12 and post-Phase-12 Command parity hardening**

Local storage is a capability boundary, not a public database schema and not an alternate UCR protocol. External consumers never receive direct database access.

The storage abstraction must support at minimum:

- SQLite local storage;
- a memory test store;
- server durable stores;
- future embedded stores.

The abstraction must not be reduced to the lowest common denominator. Domain capabilities use explicit storage interfaces such as `CommandAcceptanceStore`, `EventJournalStore`, `RecoveryPlanStore`, `ConversationStore`, and `MessageStore`; `DeliveryStore`, `SyncStore`, and `AntiEntropyStore` are additional capability-specific contracts above `StorageProvider`; future identity and attachment stores add their own contracts without reducing the abstraction.

## Command acceptance durability

A command is validated before storage. New acceptance is one atomic transaction:

1. acquire a write transaction;
2. inspect the scoped idempotency key;
3. return Duplicate only for identical previously accepted Command type, payload, schema version, and canonical extension semantics;
4. return Conflict for scoped key reuse with any difference in those semantics;
5. insert a new acceptance record;
6. commit;
7. only then return Accepted.
An uncommitted transaction is not an acceptance. A process restart must preserve committed deduplication state. The same key in another tenant or namespace is a different idempotency domain.

Acceptance does not prove the requested effect occurred. A scoped `CommandId` is unique within the store; reusing it with another accepted command is a conflict even when the idempotency key differs.

## Event journal and terminal outcomes

Canonical Events are append-only. Re-appending the same scoped Event ID with identical semantics is a Duplicate; reusing it with different semantics is a Conflict. Events are validated and size-bounded before persistence.

A terminal Event may be linked atomically to one previously accepted Command only when tenant/namespace scope matches and `causation_id` references that Command ID. The Event insert/deduplication and terminal link commit in one transaction. A second different terminal Event for the same Command is a Conflict.

A terminal Event records UCR processing state; it is not universal exactly-once evidence for an external side effect. Crash-safe work claiming, handler recovery, and downstream idempotency require additional contracts.

## SQLite reference store

The reference local store uses pinned bundled SQLite and must configure:

- WAL journal mode;
- `synchronous=FULL`;
- foreign keys enabled;
- a finite busy timeout;
- `trusted_schema=OFF`;
- a UCR `application_id`;
- explicit `user_version` schema versioning.

A database carrying another application ID or unrelated user tables must not be silently adopted or mutated during rejection. A schema newer than the binary must be rejected; silent downgrade is forbidden. Schema shape and foreign-key consistency are validated when opening an existing store.

Canonical `OpaqueId` values are exact non-empty UTF-8 tokens bounded to 128 bytes by the public semantic contract. The SQLite reference store therefore persists canonical IDs losslessly in `TEXT` columns without a binary/text conversion layer; byte identity is the UTF-8 encoding of the stored token. Unicode normalization, case-folding, or trimming is forbidden at storage boundaries. This OpaqueId clarification requires no SQLite schema migration.

Schema v2 migrates v1 transactionally: existing command acceptance/deduplication records are preserved, then scoped Command ID uniqueness and Event/outcome tables are added. If legacy rows contain duplicate scoped Command IDs, migration fails and the database remains at v1. Schema v3 migrates v2 transactionally by adding durable handshake replay state while preserving accepted commands and Events. Schema v4 migrates v3 transactionally by adding public Recovery Plan/authority/active-plan metadata while preserving command, Event, and replay state. Recovery secrets are not stored in these tables. Schema v5 migrates v4 transactionally by adding normalized Conversation/Message, ordered attachment/relation reference, and external-message-mapping tables while preserving all pre-existing durable state. Schema v6 migrates v5 transactionally by adding normalized DeliveryAttempt and append-only DeliveryEvidence tables while preserving all earlier durable state. Schema v7 migrates v6 transactionally by adding normalized SyncSession, partial Conversation selection, and append-only SyncCheckpoint tables while preserving all earlier durable state. Schema v8 migrates v7 transactionally by adding normalized canonical Event extension rows; pre-v8 Events are preserved exactly and represent an empty extension list. Schema v9 migrates v8 transactionally by adding normalized Command protocol-version metadata and canonical Command extension rows while leaving the historical `accepted_commands` layout unchanged. Every pre-v9 accepted Command is backfilled as schema version `1.0` with an empty extension list, matching the only Command semantics representable by the pre-v9 Rust reference model. Schema v10 migrates v9 transactionally by adding normalized canonical Message extension rows. Existing v9 Messages require no backfill rows: absence of child rows is the empty extension list, matching the only Message extension semantics representable by the pre-v10 Rust reference model.
Schema v11 migrates v10 transactionally by adding scoped trusted public signing-key lifecycle state. The migration starts with an empty trusted-key set because no pre-v11 durable trust owner existed; all existing Command/Event/replay/recovery/Message/Delivery/Sync state is preserved. A partial unique index enforces at most one Active trusted signing key per exact Tenant/Namespace scope and Device.

On Unix, the database file is created and hardened as owner-only (`0600`), and SQLite WAL/SHM sidecars must not widen group/other access. Other operating systems must rely on the platform's private application-data ACL/sandbox and must not expose the database as a user-shared document.
## Explicit failure semantics

Storage exhaustion, corruption, unavailability, permission failures, foreign-store detection, schema incompatibility, invalid records, and idempotency conflicts are explicit failures. None may be converted to success. Persisted extension collections are bounded while being read: a corrupt Command, Event, or Message extension journal that exceeds the shared protocol-extension count limit fails before the loader accumulates additional rows.

`SQLITE_FULL` maps to the canonical storage-full state. Corrupt or non-database files fail explicitly. Busy/locked/I/O/open failures are unavailable, not accepted.

## Persisted-field purpose and classification

| Field | Purpose | Owner | Retention | Classification |
|---|---|---|---|---|
| tenant / namespace | idempotency security boundary | UCR Core | acceptance retention window | INTERNAL |
| idempotency key | effectively-once deduplication | UCR Core | acceptance retention window | INTERNAL |
| command ID | duplicate provenance | UCR Core | acceptance retention window | INTERNAL |
| command type | semantic conflict detection / recovery | UCR Core | acceptance retention window | INTERNAL |
| command payload | semantic conflict detection / future recovery | originating command | acceptance retention window | inherits payload classification |
| Command schema version | versioned semantic conflict detection | UCR Protocol/Command | acceptance retention window | INTERNAL |
| Command extensions | canonical versioned extension semantics; payload remains non-loggable | UCR Protocol/Command | acceptance retention window | inherits extension payload classification |
| Event provenance | canonical actor/source-device attribution | UCR Core | event retention policy | INTERNAL / identity metadata |
| Event payload | immutable canonical fact payload | originating event | event retention policy | inherits payload classification |
| integrity metadata | future cryptographic/integrity evidence | UCR Core | event retention policy | SECURITY METADATA |
| Event extensions | canonical versioned extension semantics; payload remains non-loggable | UCR Protocol/Event | event retention policy | inherits extension payload classification |
| terminal Command→Event link | durable processing outcome relation | UCR Core | command/event retention window | INTERNAL |
| peer key + transcript binding | authenticated-handshake replay detection | UCR Crypto | replay retention policy | SECURITY METADATA / AUDIT |
| recovery plan + authority identifiers | durable recovery policy and CAS rotation | UCR Recovery | recovery-policy retention | SECURITY METADATA / AUDIT |
| Conversation identity/kind/parent | provider-independent durable communication context | UCR Conversation | conversation retention policy | INTERNAL / identity metadata |
| Message content + provenance + relations | durable canonical user communication | UCR Message | message retention policy | PRIVATE or originating classification |
| Message crypto/signature metadata | future verification/decryption context | UCR Message/Crypto | message retention policy | SECURITY METADATA |
| Trusted public signing key + key trust state | scoped author/peer authentication trust lifecycle | UCR Crypto/Core trust owner | security trust/audit retention | SECURITY METADATA / AUDIT |
| Service Principal credential ID + digest + lifecycle | exact-scope Service Account authentication; no plaintext secret | UCR Core authentication owner | credential lifecycle retention | SECURITY METADATA / AUTHENTICATION |
| Service Principal quota policy + fixed-window usage | restart-safe abuse-control accounting for an exact Service Account | UCR Core quota owner | quota/accounting retention | SECURITY METADATA / AUDIT |
| Service Principal admission audit chain | metadata-only authentication/quota/authorization decisions; no request payload or credential secret | UCR Core audit owner | security audit retention | AUDIT / SECURITY METADATA |
| external Message mappings | provider Integration reconciliation only | UCR Integration | mapping retention policy | INTERNAL / provider metadata |
| DeliveryAttempt state | monotonic per-attempt delivery state | UCR Delivery | delivery retention policy | INTERNAL / AUDIT |
| DeliveryEvidence | typed proof for persisted/transport/relay/device/user stages | UCR Delivery | delivery evidence retention | AUDIT / SECURITY METADATA |
| SyncSession + partial selection | durable provider-independent synchronization scope and lifecycle | UCR Sync | sync session retention | INTERNAL / SECURITY METADATA |
| SyncCheckpoint + resume token | restart-safe progress/resume state; token remains opaque | UCR Sync | sync checkpoint retention | INTERNAL / SECURITY METADATA |

Idempotency keys must not be used to carry secrets. Payload persistence is not telemetry and does not imply permission to export it. Private signing/agreement keys are never stored in this general SQLite schema; Phase-7 uses a separate non-exporting key-operation boundary. Payload-at-rest encryption remains a separate explicit decision and is not implied by transport/session crypto.

SQLite schema v12 additionally persists normalized canonical permission grants. Grant rows contain authorization metadata only; authentication credentials, private keys, bearer tokens, and audit history are not stored in the permission table. v11-to-v12 migration starts with an empty grant set rather than inferring authority from existing identities, keys, messages, or tenant-root scope. SQLite schema v13 adds Service Principal credential metadata and one-way digests; plaintext credential secrets are never stored. v12-to-v13 migration is additive and starts with no credentials rather than inferring authentication from grants or signing keys. SQLite schema v14 adds Service Principal quota policy/usage plus a metadata-only append-only audit chain. v13-to-v14 migration is additive and starts with no quota/audit state rather than inferring it from credentials or permission grants.

## Migration and rollback

Every future migration must be deterministic, versioned, preserve unsynced/durable state, and document rollback compatibility. Migration failure must leave the prior committed database valid or fail explicitly; destructive best-effort migration is forbidden.

# UCR local storage contract

Status: **Experimental / Phase 6**

Local storage is a capability boundary, not a public database schema and not an alternate UCR protocol. External consumers never receive direct database access.

The storage abstraction must support at minimum:

- SQLite local storage;
- a memory test store;
- server durable stores;
- future embedded stores.

The abstraction must not be reduced to the lowest common denominator. Domain capabilities use explicit storage interfaces such as `CommandAcceptanceStore`; future message, identity, sync, and delivery stores add their own contracts above `StorageProvider`.

## Command acceptance durability

A command is validated before storage. New acceptance is one atomic transaction:

1. acquire a write transaction;
2. inspect the scoped idempotency key;
3. return Duplicate for identical previously accepted semantics;
4. return Conflict for key reuse with different semantics;
5. insert a new acceptance record;
6. commit;
7. only then return Accepted.
An uncommitted transaction is not an acceptance. A process restart must preserve committed deduplication state. The same key in another tenant or namespace is a different idempotency domain.

This Phase-6 capability does not claim that accepting a command proves its requested effect occurred. Command execution recovery and event/outcome persistence require their own durable contracts.

## SQLite reference store

The reference local store uses pinned bundled SQLite and must configure:

- WAL journal mode;
- `synchronous=FULL`;
- foreign keys enabled;
- a finite busy timeout;
- `trusted_schema=OFF`;
- a UCR `application_id`;
- explicit `user_version` schema versioning.

A database carrying another application ID or unrelated user tables must not be silently adopted or mutated during rejection. A schema newer than the binary must be rejected; silent downgrade is forbidden. Schema shape is validated when opening an existing store.

On Unix, the database file is created and hardened as owner-only (`0600`), and SQLite WAL/SHM sidecars must not widen group/other access. Other operating systems must rely on the platform's private application-data ACL/sandbox and must not expose the database as a user-shared document.
## Explicit failure semantics

Storage exhaustion, corruption, unavailability, permission failures, foreign-store detection, schema incompatibility, invalid records, and idempotency conflicts are explicit failures. None may be converted to success.

`SQLITE_FULL` maps to the canonical storage-full state. Corrupt or non-database files fail explicitly. Busy/locked/I/O/open failures are unavailable, not accepted.

## Persisted-field purpose and classification

| Field | Purpose | Owner | Retention | Classification |
|---|---|---|---|---|
| tenant / namespace | idempotency security boundary | UCR Core | acceptance retention window | INTERNAL |
| idempotency key | effectively-once deduplication | UCR Core | acceptance retention window | INTERNAL |
| command ID | duplicate provenance | UCR Core | acceptance retention window | INTERNAL |
| command type | semantic conflict detection / recovery | UCR Core | acceptance retention window | INTERNAL |
| command payload | semantic conflict detection / future recovery | originating command | acceptance retention window | inherits payload classification |

Idempotency keys must not be used to carry secrets. Payload persistence is not telemetry and does not imply permission to export it. Phase-7 cryptographic storage/key decisions may strengthen at-rest protection without changing command semantics.

## Migration and rollback

Every future migration must be deterministic, versioned, preserve unsynced/durable state, and document rollback compatibility. Migration failure must leave the prior committed database valid or fail explicitly; destructive best-effort migration is forbidden.

# ADR-0017: CommandEnvelope version and extensions are durable idempotency semantics

Status: Accepted

## Context

The public protobuf `CommandEnvelope` has always carried `schema_version` and repeated protocol `extensions`, while the canonical Rust Command model and durable command-acceptance stores historically omitted both fields. SQLite therefore compared only scoped idempotency key, command type, and payload after restart. Two wire-distinct Commands could be incorrectly classified as one duplicate when their schema version or extension semantics differed.

This is silent semantic loss at the canonical boundary. It also creates inconsistent behavior between an implementation that preserves the public wire contract and one using the reference Rust/storage path.

## Decision

The canonical Rust `CommandEnvelope` carries `schema_version` and protocol `extensions`. Command validation requires a non-zero schema major and the same extension namespace/count/payload rules used elsewhere. Extension input order is non-semantic; canonical order is lexical by extension name and duplicate names are invalid.

For one scoped idempotency key, duplicate equality includes command type, payload, schema version, and canonical extension semantics. A difference in any of those fields is a conflict. Correlation and causation identifiers remain tracing/provenance metadata and do not redefine the existing scoped action idempotency identity.

SQLite schema v9 keeps the historical `accepted_commands` table unchanged and adds normalized `command_protocol_metadata` and `command_extensions` tables. New acceptance persists the base acceptance row plus protocol metadata/extensions in one transaction. Duplicate comparison after restart requires the metadata row and fails closed if it is missing or corrupt.

The v8-to-v9 migration is additive and transactional. Every pre-v9 accepted Command is backfilled as schema version `1.0` with an empty extension list, matching the only Command semantics representable by the pre-v9 Rust reference model. Historical v1-v8 table verifiers remain exact.

## Consequences

Rust, protobuf, memory storage, and SQLite now agree on Command schema/extension semantics. Reordered extensions deduplicate canonically, while changed schema or extension content cannot be silently collapsed into an old accepted Command after restart.

Existing SQLite databases migrate without rewriting the `accepted_commands` base table. A v9 database missing protocol metadata for an accepted Command is corrupt rather than implicitly downgraded.

This ADR does not claim complete parity for every other runtime protobuf envelope; each public type still requires its own model/validation/persistence review.

## Security and privacy impact

Command and extension payloads may carry sensitive protocol data. They inherit their originating payload classification, remain inside the private durable-storage boundary, and must not be emitted through ordinary Debug/telemetry paths. `CommandEnvelope` Debug redacts command payload/correlation material, while nested `ProtocolExtension` Debug redacts extension payloads; both behaviors have regression coverage.

## Rejected alternatives

- Ignore Command schema/extensions during idempotency: rejected because it produces false duplicates and silent semantic loss.
- Treat extension order as semantic: rejected because protocol extension sets are canonically ordered, not user-ordered actions.
- Add new columns directly to historical `accepted_commands`: rejected because it would force old schema verifiers to accept shapes that never existed and weaken migration evidence.
- Use `CREATE TABLE IF NOT EXISTS` in historical migrations: rejected because it masks mixed-version/corrupt fixtures instead of proving an exact migration path.
- Backfill an unknown/latest schema version: rejected because pre-v9 reference Commands had only the effective v1.0, empty-extension semantics; migration must not invent data.

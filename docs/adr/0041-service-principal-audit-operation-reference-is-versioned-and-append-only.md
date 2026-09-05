# ADR-0041: Service Principal audit operation reference is versioned and append-only

- Status: Accepted
- Date: 2026-09-05
- Supersedes: none

## Problem

Phase 13 `SubmitCommand` already routes an external Service Principal through authentication,
quota/audit, permission enforcement, and durable Command acceptance. The admission audit records
who was evaluated, for which permission and scope, but did not durably identify the exact
canonical operation whose admission was attempted.

A Command-specific audit table or `command_id` special case would narrow the audit model around
one API method and force later Intent/Message/Conversation APIs to invent parallel attribution.
Rewriting the existing audit rows would also destroy the exact historical
`UCR-SERVICE-AUDIT-HASH-V1` evidence already stored by schema v14-v16.
## Decision

`ServiceAuditRecord` gains one optional generic `ServiceAuditOperationRef` containing a
namespaced `operation_kind` and one canonical opaque `operation_id`. It remains part of the
existing Service Principal audit model and `ServiceAuditStore`; it is not a new audit owner.

Phase 13 command ingress binds `operation_kind = ucr.command` and the canonical `CommandId`
before credential authentication. Therefore authentication failure, quota failure, permission
denial, authorization success, duplicate retry, and semantic conflict all retain the operation
that was actually attempted without copying Command payload or credential material into audit.

Audit records without an operation continue to use the exact V1 hash algorithm and domain.
Operation-bound records use `UCR-SERVICE-AUDIT-HASH-V2`, which commits the same legacy fields,
the previous record hash, operation presence, kind, and ID.
SQLite schema v17 adds only the normalized `service_audit_operations` child table, lookup index,
and UPDATE/DELETE rejection triggers. The existing `service_audit_records` table is not rewritten.
Presence of the child selects V2 reconstruction; absence preserves V1 reconstruction. Both remain
one continuous append-only chain. The same `ServiceAuditStore` exposes an indexed exact-operation
lookup, and `AuthorizedDurableRuntime` protects it with the existing Service Principal audit-read
permission rather than creating a new permission or Command-specific query owner.

## Alternatives rejected

Adding `command_id` directly to the legacy audit row was rejected because it is Command-specific
and would require rewriting or ambiguously versioning historical rows. A separate
`service_command_audit` store was rejected as a second audit brain. Recomputing all legacy hashes
was rejected because migration must preserve historical evidence, not manufacture replacement
evidence. Embedding audit attribution into Command payload/extensions was rejected because audit
provenance is security metadata, not Command semantics.

## Security and privacy impact

The operation reference contains no payload, secret, credential digest, provider credential, or
decrypted content. Offline addition, deletion, or mutation of an operation reference breaks the
hash chain; ordinary mutation is additionally rejected by SQLite triggers.
The reference records the attempted operation even when authentication fails, but the operation ID
remains untrusted caller-controlled metadata until normal canonical admission succeeds. It grants
no authority and is never treated as resource existence or execution evidence.

## Compatibility, migration, and rollback

Migration v16→v17 is additive and transactional. It creates the child table/index/triggers and
leaves every legacy audit row and V1 `record_hash` byte-for-byte unchanged. New V2 rows may then
continue the same chain from the final legacy hash.

An older v16 binary must reject schema v17 as newer. After any V2 operation-bound record exists,
silently dropping the v17 child state is not a valid rollback because it would erase semantic
audit evidence and make the stored V2 hash unverifiable. Rollback therefore requires a documented
pre-migration compatible database copy or a forward-compatible binary, never destructive schema
downgrade.
## Testing strategy

Protocol tests lock unchanged V1 and V2 golden vectors and prove V2 binds operation kind/ID. Memory
integration tests prove successful and denied Phase-13 command admissions retain the same canonical
operation reference and that exact-operation lookup is denied before the existing audit-read grant. SQLite tests prove restart round-trip, v16→v17 migration without rehashing
legacy V1 evidence, full historical migration compatibility, append-only triggers, and reopen-time
detection of offline operation-reference tampering.

## Non-claims

An `Authorized` admission audit is not proof that Command validation, durable acceptance, dispatch,
or a real-world communication effect succeeded. This ADR does not add operation-result audit,
external cryptographic anchoring, Event API, SDKs, network API servers, or Internet transport.
ADR-0040 remains the Integration API ownership decision; this ADR only strengthens its audit
attribution through the already existing Service Principal security boundary.
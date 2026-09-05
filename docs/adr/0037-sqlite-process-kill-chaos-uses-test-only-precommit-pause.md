# ADR-0037: SQLite process-kill chaos uses a test-only pre-commit pause

Status: Accepted

## Context

The Canon requires process-kill chaos evidence that proves durable-state invariants. Ordinary drop/reopen, an uncommitted transaction that exits normally, or a raw SQLite-only test does not prove what happens when the actual UCR storage process dies after production mutation logic has started but before commit.

A deterministic kill point is needed to avoid timing-only tests. Exposing a public crash/fault API or duplicating Command persistence in a test harness would pollute the production boundary and create a second storage-policy owner.

## Decision

`ucr-storage-sqlite` owns one private `#[cfg(test)]` pause immediately after the real `accepted_commands` and protocol-metadata inserts in `CommandAcceptanceStore::accept_command`, and immediately before the real transaction commit. The hook is absent from production builds and is activated only for one exact test Command ID through child-process environment.

The parent test launches a separate instance of the actual SQLite crate test binary. The child opens the normal `SqliteLocalStore`, invokes the real `accept_command` path, signals after it reaches the pre-commit pause, and blocks. The parent then forcibly terminates that process rather than allowing Rust transaction drop/cleanup to run normally.

After termination, the parent reopens the same database through the production constructor. The store must be Healthy, the interrupted idempotency key must still be available for a fresh Accepted command, and a subsequent retry must deduplicate against that fresh command. This proves the killed transaction left no ghost acceptance or partial protocol metadata.

No public fault-injection API, alternate store, or duplicate Command persistence/transaction implementation is added.

## Limits

This evidence covers abrupt userspace process termination while the implemented SQLite Command-acceptance transaction is open. It does not claim kernel panic, machine power loss, filesystem corruption/loss, platform-specific storage semantics beyond SQLite durability, or behavior of future durable providers. Those boundaries require their own evidence when applicable.

## Rejected alternatives

Renaming app restart or ordinary rollback as process-kill evidence was rejected because normal unwinding/drop is materially different. Reimplementing the transaction with raw `rusqlite` in the parent was rejected because it would not exercise production UCR mutation semantics. A public pause/fault constructor was rejected because testing controls must not expand the runtime API. A timing-only kill without a deterministic pre-commit signal was rejected as flaky and incapable of proving which side of commit was killed.

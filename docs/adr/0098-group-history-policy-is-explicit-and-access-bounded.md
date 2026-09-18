# ADR 0098: Group history policy is explicit and access-bounded

Status: Accepted

## Context

The Canon requires Group history to distinguish NO_HISTORY, FROM_JOIN, LAST_N_MESSAGES, FROM_TIMESTAMP, FULL_HISTORY and CUSTOM_POLICY.

## Decision

`GroupHistoryPolicy` is canonical Group state with the six required modes. It governs history eligibility; it never bypasses current membership, tenant scope, permissions, cryptographic epoch access or data-lifecycle rules.

`CustomPolicy` is a named policy reference, not executable untrusted code embedded in Group state. Changing history policy is an auditable Group change and affects future authorization decisions; it does not silently manufacture plaintext or re-encrypt inaccessible historical content.

For a newly joined/recovered Device, history delivery is the intersection of GroupHistoryPolicy, current authorization, available ciphertext/key epochs and lifecycle retention.

## Consequences

FULL_HISTORY is not equivalent to unconditional access. NO_HISTORY and FROM_JOIN remain enforceable across sync/restart because policy is durable canonical Group state.

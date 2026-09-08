# Phase 17 Chat security properties

Phase 17 inherits canonical authentication/authorization, tenant scope, Message integrity, Delivery evidence, and transport security. It does not weaken them for chat convenience.

- Exact subject/resource scope is checked before Chat durable or ephemeral work.
- Durable Chat mutations use `AuthorizedDurableRuntime`.
- Service Accounts cannot use the local ephemeral typing path without a Core-owned admission boundary; the reference API denies them fail-closed.
- Typing carries no message content and expires within a bounded TTL.
- Transport acknowledgement cannot manufacture `READ`; explicit `READ_BY_USER` evidence is mandatory.
- Group semantics are rejected rather than approximated.
- No Chat-owned durable database, queue, identity map, or route planner exists.

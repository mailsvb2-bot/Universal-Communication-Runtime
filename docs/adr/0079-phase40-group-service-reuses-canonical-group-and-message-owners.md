# ADR-0079: Phase 40 GroupService reuses canonical Group and Message owners

- Status: Accepted
- Date: 2026-09-16
- Phase: 40 — Reference Messenger

## Problem

The Reference Messenger Canon requires Groups to be proven through the public UCR boundary. Phase 18 already owns Group lifecycle, membership, policy and membership-gated Message access, but Phase 40 initially had no consumer-facing Group service.

Linking the Reference Messenger directly to `ucr-core`, `GroupStore`, SQLite or the Phase-18 runtime would create privileged product access and would make the public proof false.

## Decision

Add a versioned `GroupService` to `ucr.v1`. The gRPC adapter terminates Service Principal metadata and delegates to `IntegrationIngress`; the ingress reuses `AuthorizedDurableRuntime`, `GroupStore` and `GroupMessageStore`.

The public wire record maps to the existing canonical Group aggregate. The existing `OfflineGroupChange` protobuf shape is reused for mutation requests because it already represents canonical `GroupChange` and avoids a second mutation vocabulary.

Group creation preserves both existing permissions, `ucr.conversation.write` and `ucr.group.create`. One external `CreateGroup` request performs one authentication/quota admission bound to `ucr.group.create`. Once that primary permission is authorized and audited, the same request evaluator checks `ucr.conversation.write` for the identical authenticated subject and resource scope, writes a separate audit decision, and deliberately does not consume request quota twice. The admission proof itself remains exact-permission and is never treated as proof of the additional permission.

## Consequences

The Reference Messenger and external SDK consumers can create/read/manage Groups and send/read membership-gated Group Messages without hidden access. Existing privacy, revision, role, membership, history and storage semantics remain authoritative.

One public-API gap is closed; multi-device, local, offline, P2P, recovery and concrete accessibility evidence remain separate Phase-40 work.

## Rejected alternatives

### Let Reference Messenger import GroupStore or SQLite

Rejected because it bypasses the public contract and creates product-only authority.

### Add a second simplified Group model for the UI

Rejected because it would fork Group identity, membership and policy semantics.

### Require only `ucr.group.create`

Rejected because canonical Group creation also creates/binds the existing Conversation owner and already requires `ucr.conversation.write`.

### Treat one Service Principal admission proof as proof of both permissions

Rejected because admission proofs remain deliberately exact-permission and single-use. The accepted design keeps that invariant: the primary proof authorizes only `ucr.group.create`; `ucr.conversation.write` is a separate authorization decision for the same already-admitted request, with its own audit row and no second quota consumption.

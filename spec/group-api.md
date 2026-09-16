# Phase 40 — Public Group Service

## Status

Prepared public consumer API for the existing canonical Group and Group-Message owners.
It closes the Reference Messenger `Groups` public-API gap without creating a second Group, Conversation, Message, membership, authorization, delivery, or storage model.

## Boundary

The only allowed execution path is:

```text
Reference Messenger / external SDK consumer
                 ↓
             GroupService
                 ↓
        IntegrationIngress
                 ↓
 Service Principal admission + audit
                 ↓
 AuthorizedDurableRuntime / GroupStore / GroupMessageStore
```

`GroupService` is a thin authenticated binding. The protobuf records map to the existing `ucr_model` Group types. `OfflineGroupChange` is reused as the already-versioned wire representation of canonical `GroupChange`; Phase 40 does not introduce a second mutation vocabulary.

## Operations

The public service exposes:

- `CreateGroup` — atomically creates the canonical group-kind Conversation, Group aggregate, and creator membership;
- `GetGroup` — preserves private-group non-disclosure and canonical authorization;
- `GetMembership` / `ListMemberships` — preserve active-member-gated snapshot semantics;
- `ApplyChange` — preserves optimistic revision, role, membership, ownership and crypto-transition checks;
- `SendGroupMessage` — writes through the canonical Message owner with active membership gating;
- `GetGroupMessage` — reads through the canonical Message owner with membership/history-policy gating.

## Group creation permissions

Canonical Group creation already requires both `ucr.conversation.write` and `ucr.group.create`. One external `CreateGroup` RPC performs one Service Principal authentication/quota admission bound to `ucr.group.create`. After that primary permission is authorized and audited, the same request evaluator checks `ucr.conversation.write` for the identical authenticated subject and resource scope as an additional separately audited permission, without consuming request quota a second time. The admission proof itself remains exact-permission and is not reused as proof of `ucr.conversation.write`; only after both authorization decisions succeed is the existing atomic `GroupStore::create_group` invoked.

The public API must not weaken this to one permission, infer one permission from the other, or bypass the existing atomic creation owner.

## Authentication and audit

Credentials remain the exact binary Service Principal metadata used by the rest of the public API. Group operations receive explicit audit operation kinds. Authentication, quota, permission and audit failures fail closed before the durable operation is entered.

## Semantics preserved

- public/private Group visibility remains Core-owned;
- membership tombstones remain durable;
- membership list/read checks remain atomic with the caller's active-membership check;
- Group messages remain canonical `MessageEnvelope`s in the existing Message store;
- acknowledgement proves persistence/deduplication only, not delivery/read success;
- no SDK or Reference Messenger retry engine is introduced;
- no direct database access is exposed.

## Nonclaims

This service does not close multi-device, local, offline, P2P or recovery gaps. It does not add group discovery, invite delivery, moderation, federation discovery or a second group-crypto implementation.

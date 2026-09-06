# ADR-0051: Phase-13 gRPC completes IntegrationService over canonical owners

Status: Accepted
Date: 2026-09-06

## Problem

The checked-in Phase-13 `IntegrationService` already defines eleven language-independent RPCs and
`IntegrationIngress` already owns their transport-neutral admission path. ADR-0049 bound
`SubmitCommand`; ADR-0050 then bound the four Identity-facing methods. The remaining Conversation,
Message, and Communication Intent RPCs still returned gRPC `UNIMPLEMENTED` even though their canonical
Core owners and Service Principal admission semantics already existed.

Leaving those six methods unbound would keep Phase 13 artificially incomplete and would encourage
future adapters to bypass `IntegrationIngress` or duplicate Conversation/Message/Intent policy in the
transport layer.

## Decision

Bind `CreateConversation`, `GetConversation`, `SendMessage`, `GetMessage`,
`CreateCommunicationIntent`, and `GetCommunicationIntent` in the existing `ucr-api-grpc` crate.
Together with the five already-bound methods, all eleven checked-in `IntegrationService` RPCs now
terminate in the same `IntegrationIngress`.

The gRPC adapter may perform only structural protobuf decoding/encoding and binding-specific Service
Principal credential extraction. It does not own authorization, quotas, audit semantics,
idempotency/conflict policy, durable state, Message provenance policy, Conversation hierarchy rules,
or Communication Intent validation.

`ConversationStore`, `MessageStore`, and `CommunicationIntentStore` remain the canonical durable
owners. Service Account Message writes continue to require the authenticated Service Principal in
`Message.origin.principal_id` through `AuthorizedDurableRuntime`; the adapter does not synthesize or
repair provenance. External provider message IDs and extension payloads remain exact opaque bytes.

Canonical failures continue to use the method-specific protobuf response `error` envelope after
successful gRPC decoding. Missing/invalid protobuf structure and unknown/`UNSPECIFIED` enum values map
to canonical `INVALID_ARGUMENT`. Authorized absence maps to canonical `NOT_FOUND` only after the same
Service Principal authentication, quota/audit, and permission boundary has succeeded.

The finite server decode ceiling now covers every canonical Phase-13 request rather than being sized only
for `IntegrationCommandRequest`. The adapter derives upper bounds for the three payload-bearing maxima
(Command, Message, and Communication Intent) from the canonical payload, collection, extension, crypto,
provider-mapping, policy, and protobuf wire limits, then uses their maximum as the single Tonic ceiling.
This prevents a canonically valid maximum Message/Intent from being rejected before Core while retaining
a finite bound and avoiding Tonic's 4 MiB default. This ADR does not turn the reference loopback listener
into a production Internet listener.

## Consequences

- The checked-in Phase-13 gRPC `IntegrationService` surface is now 11/11 bound.
- Production adapter code contains zero intentional `Status::unimplemented` Integration RPCs.
- Generated Tonic/Prost types remain disposable mappings, not Core or protocol owners.
- Conversation create/read preserves provider-independent Conversation semantics.
- Message send/read preserves generic-ACK-only persistence semantics, canonical conflict behavior,
  opaque external mappings, and Service Account provenance enforcement.
- Communication Intent create/read preserves durable intent semantics without route selection or
  provider effects.
- Read-side resource existence remains non-disclosing until authorization succeeds.
- No SQLite schema or new permission/audit/storage vocabulary is introduced.

## Evidence

Required executable evidence includes:

1. all eleven generated RPCs delegate to `IntegrationIngress` and no production RPC returns
   `UNIMPLEMENTED`;
2. Conversation create -> equal retry -> get succeeds, same-ID semantic change conflicts, and
   unauthorized present/absent reads are indistinguishable;
3. Message send -> equal retry -> get succeeds with persisted state, opaque external mapping bytes and
   authenticated Service Principal provenance preserved;
4. forged Service Account Message provenance returns `PERMISSION_DENIED`, creates no ghost Message,
   and a subsequent valid retry succeeds;
5. Communication Intent create -> equal retry -> get succeeds with payload, constraints, correlation,
   and extension bytes preserved; same-ID semantic change conflicts;
6. unauthorized present/absent Intent reads are indistinguishable;
7. malformed remaining-RPC structural/enum inputs return canonical `INVALID_ARGUMENT` without ghost
   Conversation/Intent state;
8. maximum canonical Command, Message, and Communication Intent protobuf requests each fit beneath the
   single derived gRPC decode ceiling and still validate in their canonical protocol owners;
9. existing credential-metadata, Identity, RustSec, fuzz, threat, chaos, and workspace regression gates
   remain green.

## Security impact

This removes no trust boundary. Every newly bound RPC reaches storage only after the existing
Service Principal authentication, quota consumption, append-only admission audit, and exact permission
check. Read authorization still precedes `NOT_FOUND`. Message provenance remains enforced in Core, not
trusted from the adapter. No credential or payload is added to generic audit records.

## Privacy impact

The adapter does not normalize or copy opaque external provider IDs into canonical Identity or generic
audit state. Message/Intent payloads and private policy data remain request/durable-owner data and are
not promoted into transport diagnostics.

## Compatibility impact

The protobuf service shape is unchanged. Previously generated methods that returned gRPC
`UNIMPLEMENTED` now execute the already-defined Experimental Phase-13 semantics. Existing five bound
RPCs and credential metadata keys are unchanged.

## Migration strategy

No durable migration is required. The change is adapter-only plus documentation/governance evidence;
all durable owners already existed before this ADR.

## Rollback strategy

Rollback the adapter commit and ADR together. Durable data remains readable by the pre-change Core
owners because no schema or canonical entity representation changes.

## Testing strategy

Run gRPC loopback tests, workspace fmt/check/Clippy/docs/debug tests, release tests, architecture locks,
RustSec audits for both lockfiles, and the bounded fuzz smoke suite. Merge only from the exact tested
head and require the same protected CI gates again on the merge SHA.

## Non-claims

This does not implement Phase 14 Event API, webhook/event streaming, Phase 15 Internet Transport,
production TLS/listener/deployment, HTTP/local IPC/SDK packages, routing/delivery effects, Attachments,
Groups, Calls/Media, provider bridges, federation, or production hardening.

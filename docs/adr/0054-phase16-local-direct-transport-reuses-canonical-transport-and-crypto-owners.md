# ADR 0054 — Phase 16 Local / Direct transport reuses canonical Transport and Crypto owners

- Status: Accepted
- Date: 2026-09-07
- Phase: 16 — LAN / Direct

## Problem

Phase 16 must make native UCR communication possible over a directly reachable local network without introducing a second communication brain, weakening Phase 15 Internet constraints, or making a LAN address itself an identity/trust signal.

A naive change that simply allows RFC1918/link-local addresses inside `InternetTransportProvider` would blur capability negotiation, route policy and cryptographic context. A separate copy of Message/Delivery/Identity logic would violate the UCR Canon.

## Existing state

Phase 15 already owns a Prepared authenticated TCP reference path behind the canonical `TransportProvider` boundary. Canonical Message/Conversation/Delivery/Identity/Device/Policy state stays in existing owners. `ucr-crypto` already provides trusted signing-key resolution, ephemeral key agreement, transcript binding, replay protection and key confirmation. The Phase 15 bounded protobuf/framing substrate already carries handshake records, encrypted chunks and authenticated transport receipts.

Phase 15 deliberately rejects local/private client routes and is not modified to claim LAN capability.

## Considered options

### A. Permit private addresses in Internet Transport

Rejected. This makes one advertised Internet capability mean two materially different route classes and weakens the explicit Phase 15 public-route contract.

### B. Build an independent local message/delivery runtime

Rejected. That creates a second communication brain and duplicates canonical ownership.

### C. Create an unrelated second TCP framing/crypto protocol

Rejected for Phase 16. It duplicates mature bounded framing and increases downgrade/cross-protocol review surface without adding a user-visible capability.

### D. Add a distinct Local/Direct provider over the same canonical Transport/Crypto owners and bounded TCP wire substrate

Accepted.

## Decision

Phase 16 adds a distinct Prepared capability `ucr.transport.local.tcp` and route scheme `ucr.local.tcp` inside the existing transport reference crate.

The local provider:

1. implements the existing `ucr_core::TransportProvider` contract;
2. consumes only already-canonical opaque encrypted envelopes;
3. accepts only literal loopback/private/link-local IPv4/IPv6 route classes defined by `spec/local-transport.md`;
4. requires its own critical handshake context `ucr.transport.local.context.v1`;
5. negotiates the Local capability rather than the Internet capability;
6. uses distinct local scope/AAD/receipt/attempt/retry cryptographic domains;
7. reuses canonical trusted Device/signing-key resolution and replay protection;
8. reuses the bounded existing protobuf/framing substrate for handshake/chunk/receipt records;
9. produces transport acceptance only, never canonical Delivered/Read evidence;
10. has bounded retry/timeouts/backoff/resources and exposes local health/metrics;
11. creates no hidden listener/runtime/discovery owner.

The existing `InternetPeerExpectationResolver` is reused as the endpoint-to-trusted-Device/key expectation interface even though its Phase 15 name is historical. Introducing a duplicate expectation store or resolver semantic solely for LAN would add no new authority and would increase split-brain risk. Public Local aliases are provided at the crate boundary.

## Why the shared wire frame names remain

The checked-in protobuf currently names the encrypted data/receipt records and frame kinds `InternetTransportData` / `InternetData` and `InternetTransportReceipt` / `InternetReceipt`. Phase 16 reuses those bounded records as a wire substrate rather than inventing a second codec. Session capability/context and cryptographic domain separation prevent silent Internet/Local session interchange.

Renaming public frame vocabulary is a compatibility/versioning change and is intentionally not smuggled into Phase 16. A future protocol-version ADR can introduce transport-neutral names while retaining backward decoding if that is justified.

## Advantages

- preserves one canonical Message/Conversation/Delivery/Identity model;
- preserves the Phase 15 public-route client contract;
- makes local/direct TCP a distinct negotiated capability;
- reuses reviewed cryptographic/session primitives and bounded framing;
- supports no-cloud same-device/LAN direct communication when addresses are already known;
- keeps route orchestration and discovery out of the transport implementation;
- provides deterministic idempotent retry and authenticated receipts without inventing Delivery truth.

## Disadvantages

- the containing crate and reused frame/protobuf names still carry the historical `internet` name;
- Phase 16 does not yet provide discovery, interface enumeration or Wi-Fi Direct lifecycle;
- the synchronous reference provider is not a production async networking stack;
- loopback/private/link-local classification is intentionally conservative and excludes CGNAT and DNS names.

## Risks

### Cross-protocol confusion

Mitigated by requiring the Local capability and Local critical context in negotiation plus distinct scope, data AAD, receipt AAD and attempt domains. An Internet session cannot silently satisfy Local negotiation.

### LAN attacker

A same-LAN source address is never trust evidence. Trusted key resolution, endpoint expectation, transcript signatures, replay protection and key confirmation are still mandatory.

### Retry storms / resource pressure

Policies retain bounded attempts, connect/I/O timeouts, exponential backoff with bounded jitter, canonical envelope ceiling and chunk-reassembly bounds.

### False delivery claims

Encrypted transport receipt semantics remain `Accepted` / `Duplicate` only. They do not advance user delivery/read truth.

## Security impact

Positive: local direct traffic receives authenticated peer identity, key confirmation, replay protection, encrypted payload chunks, authenticated receipts, strict local route admission and protocol-domain separation.

No plaintext fallback is introduced. No peer is trusted because it is local. Public Internet routes are rejected by the Local provider before connect.

## Privacy impact

Positive: a direct local path can avoid relay/provider disclosure when policy/routing later selects it. The transport itself does not log or expose plaintext, keys, auth credentials or application business context.

Phase 16 does not claim metadata anonymity: local peers still observe network-layer addresses and timing inherent to direct TCP.

## Compatibility impact

No existing Phase 15 public capability, route scheme, protobuf field number or frame-kind value changes. Existing Internet clients remain valid. The new Local capability is additive and negotiated explicitly.

## Migration strategy

No durable schema migration is required. Existing canonical Identity, Device, Message, Delivery and Conversation data remain untouched. Consumers may begin advertising Local capability only when they have an actual local/direct transport endpoint and policy permits it.

## Rollback strategy

Remove the Local module exports and stop advertising `ucr.transport.local.tcp`. Because Phase 16 adds no durable owner/schema and does not rewrite Phase 15 protocol values, rollback does not require data migration.

## Testing strategy

Required Phase 16 reference evidence includes:

- unit tests for accepted/rejected IPv4/IPv6 local route classes;
- exact capability/scheme/port fail-closed tests;
- authenticated encrypted loopback round-trip through the real provider/server;
- multi-chunk bounded envelope transfer;
- lost-receipt reconnect using the same attempt ID and sink deduplication;
- exact-scope rejection before network use;
- public-route rejection before network use;
- architecture gates proving canonical-owner reuse, Local capability/context/domain separation, docs and Prepared/nonclaim boundaries;
- the existing shared untrusted TCP frame fuzz target remains applicable because Phase 16 adds no new binary frame decoder.

Phase 17 Chat is explicitly outside this ADR and must not be started as part of Phase 16 completion.

# ADR-0053: Phase 15 Internet Transport reuses canonical Transport and Crypto owners

Status: Accepted

Date: 2026-09-07

## Context

The Canon requires the Internet Transport milestone to provide real remote delivery mechanics with retry, acknowledgement, reconnect, authenticated handshake, key confirmation, nonce/replay/downgrade protection, malformed-frame handling, and bounded time/size behavior. The repository already owns canonical `TransportProvider`, Endpoint/Route separation, negotiation, trusted signing-key resolution, replay protection, X25519 session derivation, key confirmation, AEAD, and Delivery evidence vocabulary.

Creating a second Internet-specific Message/Identity store, crypto handshake, routing engine, or durable retry queue would violate those owners and the no-second-brain rule. Phase 24, not Phase 15, owns transport orchestration/failover.

## Decision

Add `ucr-transport-internet` as a concrete `TransportProvider` adapter with `Prepared` capability `ucr.transport.internet.tcp`. It consumes one already-selected `RouteCandidate` and one already-encrypted opaque envelope. Production routes are literal public IPv4/IPv6 socket addresses; DNS and LAN/private address resolution are deliberately absent so an Internet route cannot silently become an SSRF/local-network route.

Reuse the existing authenticated UCR session flow. A critical Hello extension binds Endpoint plus a domain-separated exact-scope digest into the signed transcript. Independently resolved expected Endpoint -> Device/key state and the existing trusted signing-key resolver remain authoritative; peer-supplied descriptors never self-provision trust.

Add bounded Internet data/receipt protobuf payloads and framing kinds. Application envelopes are session-encrypted in 64 KiB–1 MiB chunks with a 16 MiB aggregate maximum and at most 256 chunks. Reassembly validates count/index/stable attempt identity before accepting growth.

Use deterministic `UCR-INTERNET-ATTEMPT-ID-V2` over scope + source Endpoint + destination Endpoint + envelope. Bounded reconnect retries reuse that token. The injected `InternetEnvelopeSink` is responsible for durable accept/dedup and returns `Accepted` or `Duplicate`; no transport-local database or queue is introduced.

Encrypt the receipt itself with the established session. Receipt AAD binds a dedicated domain, exact transcript, and attempt ID; the authenticated inner attempt ID must match the outer selection value. This closes plaintext/forgeable receipt semantics while retaining the strict nonclaim that transport acceptance is not end-user delivery.

## Security and privacy

Public route parsing rejects loopback/private/link-local/CGNAT/documentation/multicast/unspecified addresses and DNS names before connect. Timeouts, attempts, backoff, chunk size, chunk count, envelope bytes, and frame payloads have finite ceilings. MITM signing-key substitution, reorder, absurd chunk count, cross-scope use, and receipt tampering fail closed.

The transport necessarily observes network peer address, packet/frame sizes/timing, handshake public material, Endpoint identifiers, pseudonymous retry attempt token, and encrypted envelope bytes. It must not receive Message plaintext merely to route, export private keys, infer authority from IP reachability, or persist a second canonical state graph.

## Evidence

The transport crate has real TCP loopback evidence for authenticated session establishment, multi-chunk encryption, the 16 MiB canonical maximum, receipt-loss reconnect/dedup, MITM substitution rejection, bounded malicious chunk count, reordered-chunk rejection, and AEAD receipt tamper rejection. Cross-crate security evidence proves Internet provider routing blocks LAN/loopback/DNS before connection attempts. A dedicated bounded fuzz target parses the real Internet framing/protobuf boundary.

## Consequences

UCR now has a real reference Internet TCP transport that other runtime layers can call through the existing provider contract. Retry and acknowledgement have explicit semantics and do not invent Message/Delivery truth.

This completes Phase 15 only at `Prepared` reference maturity. It does not start Phase 16 Local Transport, Phase 24 Transport Orchestrator, Relay/NAT traversal, DNS discovery, HTTP webhook networking, production listener/service deployment, or any end-user messenger UI.

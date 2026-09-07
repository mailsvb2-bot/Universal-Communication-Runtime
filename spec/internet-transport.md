# Phase 15 — Internet Transport

Status: **Prepared reference transport; Phase 16 Local Transport not started**.

Phase 15 adds a concrete public-Internet TCP transport without changing canonical Identity, Endpoint, Route, Message, Delivery, Policy, or routing ownership. `ucr-transport-internet` implements the existing Core `TransportProvider` boundary and accepts only an already-encrypted opaque envelope plus one selected `RouteCandidate`.

## Capability and route contract

The capability is `ucr.transport.internet.tcp` with `Prepared` maturity. The route address scheme is `ucr.internet.tcp`; the address value is an exact UTF-8 `SocketAddr` literal. Production-path route parsing accepts public IPv4/IPv6 literals only. Loopback, private, link-local, CGNAT, benchmark/documentation ranges, multicast/unspecified addresses, zero ports, malformed values, and DNS names fail closed before `connect`.

This separation is deliberate: DNS discovery/resolution, Local/LAN transport, Relay/NAT traversal, route selection, scoring, failover orchestration, and multipath are not owned by Phase 15. In particular, Phase 24 remains the Transport Orchestrator owner.

## Authenticated session

Every connection performs the existing UCR negotiation and Crypto session sequence before application bytes are accepted:

1. fresh non-zero handshake nonce;
2. version/Crypto/capability negotiation with downgrade policy;
3. ephemeral X25519 agreement;
4. exact wire-transcript binding;
5. Ed25519 transcript authentication through the non-exporting signing-key boundary;
6. independently resolved expected Endpoint -> Device/key identity and trusted active signing-key verification;
7. replay-protector admission;
8. directional session-key derivation;
9. bidirectional key confirmation;
10. only then an `EstablishedSession` may encrypt/decrypt transport data.

The critical `ucr.transport.internet.context.v1` Hello extension carries the claimed Endpoint ID and a domain-separated SHA-256 binding of the exact `TenantScope`. Raw tenant/namespace identifiers are not duplicated into that extension. Endpoint and scope context therefore participate in the signed transcript instead of being unauthenticated socket metadata.

## Bounded data framing

Phase 15 adds frame kinds for handshake key exchange, handshake authentication, key confirmation, Internet data, and Internet receipt. Public protobuf messages in `proto/ucr/v1/internet_transport.proto` define the Internet-specific payload shapes; Rust generated code is not a second protocol owner.

A single opaque envelope may be at most the canonical 16 MiB framing payload budget. It is split into session-encrypted chunks with plaintext size from 64 KiB through 1 MiB. The receive path checks declared chunk count, monotonic index, stable attempt ID/count, AEAD nonce/ciphertext bounds, aggregate plaintext budget, and non-final minimum chunk size before growing reassembly state. A 16 MiB envelope therefore requires at most 256 accepted chunks.

Chunk associated data binds the established transcript, transport attempt ID, chunk index, and chunk count. Reordered, substituted, cross-session, or tampered chunks fail closed.

## Attempt idempotency and reconnect

The deterministic attempt token uses the domain `UCR-INTERNET-ATTEMPT-ID-V2` and binds exact scope, source Endpoint, destination Endpoint, and the complete opaque envelope. The same transport retry therefore preserves one attempt ID; a different source, destination, scope, or envelope does not collide semantically.

Retry is bounded by policy: finite connect/I/O deadlines, at most 16 configured attempts, finite initial/max backoff, exponential growth capped by policy, and deterministic bounded jitter derived from the attempt token. Retry/reconnect is allowed only for availability/timeout/internal transport failures. Policy, malformed, rejection, unsupported-capability, and resource-exhaustion failures do not become availability retries.

If the peer durably accepted an envelope but its receipt was lost, reconnect sends the same attempt token. The injected inbound `InternetEnvelopeSink` must accept-or-deduplicate that token; `Duplicate` is a successful transport outcome and prevents the transport from claiming a second effect.

## Authenticated transport receipt

A receipt is **not plaintext network evidence**. Its inner protobuf (`attempt_id`, `Accepted|Duplicate`) is encrypted with the established session outbound key. Receipt AEAD associated data binds a dedicated domain, the exact handshake transcript, and attempt ID. The outer attempt ID only selects the expected AAD and is checked against the authenticated inner ID after decryption.

`Accepted`/`Duplicate` means only that the peer transport sink accepted or deduplicated the complete envelope. It is equivalent to `ACCEPTED_BY_TRANSPORT` evidence at most. It does **not** prove `RECEIVED_BY_DEVICE`, decrypt success, presentation, user delivery, or read state, and this transport does not directly mutate canonical `DeliveryStore` state.

## Ownership and observability

`InternetTransportProvider` owns connection/retry/session transport mechanics only. `InternetTransportServer` processes one accepted connection at a time; listener lifecycle, concurrency, cancellation, deployment, and durable inbound storage remain caller-owned. The injected `InternetEnvelopeSink` is the sole inbound persistence/idempotency boundary; Phase 15 introduces no transport database, queue, Message store, Identity store, or routing brain.

Reference metrics are bounded counters for connection attempts, reconnects, established handshakes, accepted/duplicate receipts, failures/timeouts, and bytes. Health is `Healthy`, `Degraded`, or `Unavailable`. Metrics never include envelope plaintext, private keys, tenant IDs, authentication secrets, or provider credentials.

## Security evidence

Executable transport tests cover authenticated encrypted round-trip, the full 16 MiB envelope, lost-receipt reconnect with one deduplicated effect, source/destination-bound attempt IDs, public-route fail-closed behavior, substituted-signing-key MITM, malicious unbounded chunk count, reordered chunks, and tampered encrypted receipts. Cross-crate security evidence verifies LAN/loopback/DNS routes fail before network side effects. The `internet_transport_wire` fuzz target exercises the real frame/protobuf semantic decoder under bounded input/RSS/time budgets.

## Nonclaims

Phase 15 is `Prepared`, not `Production`. It does not provide DNS discovery, HTTP webhook delivery, TLS PKI, QUIC, proxy support, NAT traversal, Relay, store-and-forward, Local/LAN transport, Bluetooth/Wi-Fi Direct, long-lived connection pooling, listener daemon/service lifecycle, distributed abuse throttling, route discovery/selection/scoring, automatic failover between transports, multipath, production deployment, or SDK packaging. Those capabilities belong to later phases or deployment layers.

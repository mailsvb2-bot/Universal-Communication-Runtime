# UCR Local / Direct Transport — Phase 16 reference contract

Status: **Prepared reference implementation**, not Production.

This document specifies the Phase 16 LAN/direct transport boundary. It does not define Chat, Groups, discovery, mesh, Wi-Fi Direct control, Relay, NAT traversal, or the Phase 24 Transport Orchestrator.

## 1. Canonical ownership

Local/direct transport is a concrete implementation of the existing `ucr_core::TransportProvider` boundary. It does not own Message, Conversation, Delivery, Identity, Device, Policy, retry evidence, or application business semantics.

The caller supplies an already-canonical encrypted envelope and a transient `RouteCandidate`. The local transport supplies only transport acceptance evidence. A transport receipt is not `DELIVERED`, `PRESENTED_TO_USER`, or `READ_BY_USER` evidence.

## 2. Capability and addressing

The Prepared reference capability is:

```text
ucr.transport.local.tcp
```

The route address scheme is:

```text
ucr.local.tcp
```

The route value is a literal `SocketAddr`. DNS and mDNS names are not accepted by this Phase 16 provider; discovery remains a separate capability/layer.

Accepted local/direct address classes are deliberately narrow:

- IPv4 loopback `127.0.0.0/8` for same-device/local-daemon direct communication;
- IPv4 RFC1918 private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
- IPv4 link-local `169.254.0.0/16`;
- IPv6 loopback `::1`;
- IPv6 unique-local `fc00::/7`;
- IPv6 link-local `fe80::/10`.

Public Internet addresses, CGNAT `100.64.0.0/10`, documentation ranges, multicast, unspecified addresses, DNS names, wrong capability/scheme values, and port zero fail closed before connection establishment.

This is a route restriction, not identity evidence. A local source address never authenticates a peer.

## 3. Authentication and cryptographic separation

Every local/direct session uses the existing UCR trusted-session cryptographic owner:

- fresh ephemeral agreement keys;
- transcript binding;
- canonical protocol/capability negotiation;
- exact `TenantScope` binding;
- expected Endpoint -> Device/signing-key resolution;
- trusted signing-key verification;
- replay protection;
- key confirmation.

Phase 16 has a distinct critical handshake context:

```text
ucr.transport.local.context.v1
```

and distinct scope, data-AAD, receipt-AAD, attempt-ID, and retry-jitter domains. Therefore an authenticated Internet Transport session is not silently interchangeable with a Local Transport session even though both reference transports reuse the same bounded protobuf/framing substrate.

AI, provider names, application identities, CRM entities, and product-specific metadata are not introduced into the transport handshake.

## 4. Wire reuse without a second protocol brain

Phase 16 deliberately reuses the already checked-in bounded TCP framing/protobuf structures used by Phase 15 for handshake messages, chunk records, and encrypted transport receipts. The frame-kind names `InternetData` / `InternetReceipt` are legacy wire vocabulary; Phase 16 distinguishes its session before payload processing through the required local capability/context and separate cryptographic domains.

This choice avoids a second implementation of canonical framing and does not make Internet Transport the owner of local communication semantics.

A future wire-vocabulary rename requires compatibility/versioning governance; Phase 16 does not silently fork or renumber existing frame kinds.

## 5. Durable/idempotent transport behavior

The provider accepts one opaque encrypted envelope up to the canonical 16 MiB ceiling. Payload is chunked within existing bounded frame limits.

For one exact `(scope, source endpoint, destination endpoint, encrypted envelope)`, the local transport derives a deterministic transport attempt ID in the local attempt domain. Retrying after an ambiguous connection loss therefore reaches the sink with the same attempt ID.

The inbound sink owns atomic acceptance/deduplication. `Accepted` and `Duplicate` are both valid transport-acceptance outcomes. Conflicting attempt reuse must fail closed in the sink.

The provider has bounded connect/I/O timeouts, bounded retry count, exponential backoff with deterministic bounded jitter, and no infinite retry loop.

## 6. Receipts and delivery evidence

Transport receipts are encrypted and authenticated inside the established session and bind the attempt ID. A missing, malformed, tampered, wrong-attempt, or unauthenticated receipt is not success.

A receipt proves only that the authenticated peer-side transport sink returned `Accepted` or `Duplicate`. It does not prove decryption by the destination application or presentation/read by a human.

## 7. Health and metrics

The Prepared provider exposes transport-local health (`Healthy`, `Degraded`, `Unavailable`) and bounded counters for connection attempts, reconnects, established handshakes, accepted/duplicate receipts, failures, timeouts, and bytes sent/received.

These metrics must not contain plaintext envelopes, keys, credentials, recovery material, or peer secrets.

## 8. Inbound boundary

`LocalTransportServer` accepts only peers whose TCP source address is in an allowed local/direct class. This is an additional route-surface reduction only; the cryptographic handshake is still mandatory and authoritative.

Listener lifecycle and cancellation are caller-owned. Phase 16 does not create a hidden daemon, discovery service, global listener, or second runtime.

## 9. Failure semantics

Provider-specific failures map to the canonical transport error vocabulary. Important fail-closed mappings include:

- non-local route -> `PolicyDenied`;
- wrong local capability/scheme -> `UnsupportedCapability`;
- malformed address / port zero / empty or oversized envelope -> `Rejected`;
- timeout -> `Timeout`;
- connection loss -> `Unavailable`;
- malformed/tampered receipt -> `MalformedResponse`;
- sink resource exhaustion -> `ResourceExhausted`.

No failure path silently falls back to Internet Transport or an external bridge. Route orchestration belongs to Phase 24.

## 10. Security properties and nonclaims

Phase 16 evidence covers strict local address classification, exact-scope admission, authenticated local handshake, encrypted chunked round-trip, bounded resources, lost-receipt reconnect, deterministic idempotent retry, sink deduplication, health/metrics, and rejection of public routes before network use.

Prepared does **not** claim:

- automatic LAN discovery;
- mDNS/Bonjour discovery;
- Wi-Fi Direct / hotspot lifecycle;
- Bluetooth/BLE transport;
- mesh or multi-hop forwarding;
- route ranking/failover/multipath orchestration;
- QUIC;
- production listener hardening for every supported OS;
- firewall automation;
- production load qualification;
- Chat or any Phase 17 user-facing conversation workflow.

Those are later capabilities/phases and must not be inferred from this reference transport.

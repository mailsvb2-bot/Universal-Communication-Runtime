# ADR-0113: Horizontal SFU node media uses a separate infrastructure trust boundary

Status: Accepted

## Problem

Horizontal SFU placement can now select and resolve live worker nodes, but the runtime still has no
authenticated inter-node media data plane. Treating a UCR tenant `Identity`, `Device`,
`Principal`, Service Account, or public M2M bearer as an SFU worker identity would merge deployment
infrastructure trust with user/product identity. That would create a second meaning for canonical
identity records and make cluster topology tenant-dependent.

The SFU must also preserve the existing endpoint E2EE boundary: workers route already-encrypted
MLS-backed media and must not receive endpoint traffic keys or plaintext merely because the
deployment becomes horizontal.

## Existing state

- `SfuRuntime` authorizes and validates one source-authenticated encrypted media envelope before
  fan-out.
- `SfuForwardSink` receives only `SfuForwardTarget + SfuForwardEnvelope`.
- `SfuClusterDirectory` owns ephemeral worker health, placement, capacity and private node
  endpoints, but no canonical Call/Conference/Identity state.
- `SfuPlacementService` is private control plane only and explicitly does not transport media.
- machine access tokens authenticate tenant-scoped canonical Service Accounts and therefore are not
  infrastructure node identity.
- public `horizontal_sfu` remains fail-closed.

## Options considered

1. **Reuse tenant Device/Service Account identity for SFU nodes.** Rejected: infrastructure would
   become a tenant identity concern and node rotation could mutate user authorization semantics.
2. **Trust private IP addresses or operator heartbeat alone.** Rejected: address/placement metadata
   is not cryptographic peer authentication.
3. **Create a second durable SFU user/identity registry.** Rejected: this duplicates canonical
   identity/security ownership and violates the single-source-of-truth rule.
4. **Use a deployment-scoped mutually authenticated node transport.** Chosen: cluster certificate
   trust is infrastructure-only, while UCR's canonical user identities and endpoint media crypto
   remain unchanged.

## Decision

Add an internal streaming `SfuNodeMediaService` contract that carries only:

- a connection-local monotonically increasing `stream_sequence` for request/receipt correlation;
- the already-derived ephemeral `SfuForwardTarget`;
- the canonical already-encrypted `SfuForwardEnvelope`.

The service is private infrastructure and must be exposed only through a mutually authenticated
node transport. The node trust root/certificates are deployment credentials, not UCR
`Identity`/`Device`/`Principal` records and not tenant Service Accounts. The concrete receiving
runtime binding uses an isolated private mTLS listener and sources server certificate/private-key
material through the shared secret-provider boundary with bounded current/previous overlap. It
installs only explicitly configured client CA roots and fails closed when peer authentication cannot
be established. The outbound client now consumes only the immutable canonical
`SfuValidatedForwardBatch`, resolves its mTLS identity through the same `SecretProvider`
abstraction, trusts only explicit server CA material, and requires one exact destination receipt per
target before returning success. A placement-aware router now derives the canonical scope/Call
coordinates from that validated batch, obtains one sticky placement through the private loopback
`SfuPlacementService`, resolves only the selected node, revalidates node identity/private endpoint,
and then invokes the mTLS client. Realtime-session ownership and bounded failover/drain are wired
through the canonical placement lifecycle. New outbound connections resolve the current client
certificate/private-key provider snapshot, and the private node listener builds a fresh mTLS server
snapshot per accepted TCP connection; therefore certificate/private-key rotation becomes visible to
new connections without restarting the runtime. Existing negotiated TLS sessions are not rewritten.

The stream is bounded and backpressure-aware. `ACCEPTED` means only that the authenticated
destination SFU process accepted the ciphertext routing item into its bounded ingress. It is not
canonical `Delivery` evidence and does not prove device receipt, decrypt, presentation, or read.
`BACKPRESSURE` and `REJECTED` are explicit per-item outcomes. Authentication/protocol failure
terminates the connection rather than being converted to acceptance.

The node service does not authorize a Call participant by itself. The sending SFU path must have
already validated the canonical Call/Group/Device/source-signature/permission state before the
network side effect. A receiver may additionally revalidate canonical authority when that state is
available, but must never treat possession of an infrastructure certificate as participant
authorization.

## Security impact

The chosen boundary prevents tenant credentials from becoming cluster credentials and prevents a
private IP/heartbeat from becoming peer authentication. Endpoint E2EE remains end-to-end through
the SFU: node transport receives ciphertext and permitted routing metadata only. Mutual node
authentication protects the data-plane admission boundary; the concrete transport must also protect
routing metadata in transit.

A compromised trusted SFU node remains an infrastructure threat and may cause availability abuse or
attempt ciphertext injection. It still does not receive endpoint traffic keys from this design, and
source-authenticated media envelopes remain independently verifiable.

## Privacy impact

Inter-node metadata is limited to the existing SFU-visible scope/call/source/recipient routing
metadata, encrypted packet metadata, and ciphertext. The contract adds no Message plaintext,
Conference business metadata, unrelated roster history, media keys, provider credentials, or
tenant-wide identity export.

## Compatibility impact

This is an additive private protobuf service. Existing public Universal Conference, REST,
RealtimeService, SDK and integration contracts do not change. Existing local single-process SFU
forwarding remains valid. `horizontal_sfu` stays false until load/adversity evidence at the target
deployment scale is complete; the authenticated node transport, realtime placement binding,
failover/drain, and live node-identity reload paths are now wired.

## Migration strategy

No durable schema migration is introduced. Deployment can add node transport credentials and a
private listener alongside the existing local runtime. Single-node deployments require no data
migration.

## Rollback strategy

Remove/disable the private node media listener and client routing together and return to local-only
SFU forwarding. Do not leave remote placement enabled without a working authenticated data plane;
that would create black-holed media with misleading capacity evidence.

## Testing strategy

The contract and architecture guards must prove:

- the node stream contains only target + encrypted envelope + transport-local sequence;
- receipts do not claim Delivery/device/user evidence;
- public Universal Conference and public realtime APIs do not expose infrastructure credentials;
- machine-token/Service Account identity is not reused as node identity;
- `horizontal_sfu` remains false until a concrete authenticated transport and session routing are
  wired;
- the receiving binding must prove real mTLS/authentication failure and bounded backpressure over
  the network boundary;
- outbound client mTLS must reject an untrusted client certificate and reach the private node
  service with a trusted deployment certificate;
- outbound batch success must be driven by exact ordered destination receipts, preserving explicit
  partial acceptance/backpressure/rejection;
- placement-aware routing must reject node-ID confusion, public media endpoints, and non-loopback
  plaintext control-plane connections;
- remaining implementation must prove live credential rotation, realtime-session binding,
  reconnect, node failure/drain, and load/adversity before the Production claim.

# Phase 36 — Federation

Status: **Prepared/reference**.

Phase 36 establishes the Canon federation trust and admission layer for independently administered UCR nodes. It permits an explicitly configured local scope to communicate with an explicitly configured remote scope without treating network reachability, node possession, a provider account, or one successful handshake as authority.

Federation is not a new Communication Core and not a second communication brain. Canonical Identity, Endpoint, Conversation, Message, Delivery, Sync, Policy, permissions and cryptographic Device/key trust remain owned by their existing layers.

## Federation peer relation

One durable `FederationPeerRecord` is local policy. Its key is the exact local scope + remote scope + remote node Endpoint. It binds:

- local and remote `TenantScope`;
- local and remote node `EndpointId`;
- remote node kind (`PersonalNode` or `OrganizationNode`);
- expected remote Device and signing-key IDs;
- an explicit bounded capability allow-list;
- trust state and optimistic generation.

The remote scope and remote endpoint are data supplied to local policy. They are never self-authorizing claims from the remote peer.
## Trust lifecycle

The states are deliberately distinct:

`Known -> Authenticated -> Authorized -> Trusted`.

`Known` means only that local policy knows the peer. `Authenticated` means the configured Device/key has been cryptographically proven, but every later admission still revalidates the live session and current durable Device/key trust. `Authorized` permits only explicitly allowed federation operations. `Trusted` is a stronger local policy classification but never bypasses ordinary permissions, communication policy, capability checks, or resource ownership.

Any non-terminal state may move to `Revoked` or `Blocked`. Neither terminal state can be silently promoted back to an active state. Credential rotation is a separate explicit operation and always resets the relation to `Known`, requiring fresh authentication and authorization.

Trust state is restart-safe in SQLite schema v29. Migration from v28 creates no inferred federation relationship, credentials, authorization, or trust.

## Cross-scope admission

Cross-tenant federation is explicit local policy, never an inference from reachability or a remote claim. Federation does not weaken exact tenant/namespace isolation. A cross-scope operation exists only because local policy contains the exact remote scope relation and the local caller has the relevant federation permission.

Prepared Phase-36 sync admission additionally requires an existing Active canonical `SyncSession` using `DeviceNode`, exact local/remote Endpoint binding, an allowed federation capability, an authenticated live `EstablishedSession`, an Active expected remote Device, and the currently trusted expected signing key. A stale or revoked Device/key invalidates an already established session for new admissions.

## Non-claims

Phase 36 does not claim global discovery, NAT traversal, a managed federation directory, federated Relay, automatic content replication, Personal Node lifecycle, Organization Mode, HA, SLA, or Production maturity. It prepares the trust/admission boundary that later node and infrastructure phases may use.

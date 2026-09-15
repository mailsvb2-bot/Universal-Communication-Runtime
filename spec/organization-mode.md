# Phase 38 — Organization Mode

Status: **Prepared/reference**.

Phase 38 implements the Canon Organization Mode as an explicit tenant/namespace policy and self-hosting composition layer. An Organization may have private namespace, private discovery, private relay, private SFU, private bridge, managed identities and managed devices without forking UCR Protocol.

Organization Mode is not a second Identity, Device, Message, Conversation, Delivery, relay, SFU, Bridge or authorization brain. It composes the existing canonical owners and stores only organization policy/profile state plus explicit managed Identity/Device associations.

## Namespace and organization identity

Every `OrganizationModeProfile` is bound to an exact `TenantScope` with a required `namespace_id`, one canonical `PrincipalRef` whose kind is `Organization`, and one existing `EndpointId` classified as `EndpointKind::OrganizationNode`.

The namespace is the private organization boundary. Absence of a namespace is invalid; possession of the node, endpoint or organization principal identifier is not authority.
## Lifecycle and services

A profile has an explicit service set, `Active <-> Disabled` lifecycle and optimistic generation. SQLite v31 persists the profile and associations restart-safely; v30→v31 migration creates empty Organization Mode state and infers no organization ownership from pre-existing Identities, Devices, Federation peers, Bridges, Calls or Messages.

`PrivateDiscovery` is a bounded organization-private directory over explicit `OrganizationManagedIdentityBinding` records. Each projected entry is re-read from the canonical `IdentityStore` and must still have `IdentityOwnership::OrganizationManaged`.

`ManagedIdentities` never copies Root Identity state. Binding requires an existing canonical organization-managed Identity and exact-scope organization authority.

`ManagedDevices` never copies Device lifecycle state. Binding requires an existing canonical Device that currently allows protected access and whose canonical Identity is already explicitly managed by the same organization.
`PrivateRelay` admits only an already-existing canonical Store-and-Forward job and rechecks the canonical Message delivery policy. `NoRelay`, `LocalOnly`, `DirectOnly` and `PrivateNetworkOnly` remain fail-closed at this boundary.

`PrivateSfu` is an organization policy/admission capability only. Phase 38 creates no second SFU roster, media state, membership graph or media key owner; actual encrypted forwarding remains the existing `SfuRuntime` boundary.

`PrivateBridge` admits only an existing Active canonical `BridgeRegistration`. Provider execution and provider-specific lifecycle remain owned by the Bridge runtime and adapter.

Disabling Organization Mode denies subsequent service admission without rewriting canonical Identity, Device, Store-and-Forward, Message, Bridge or SFU state.

## Authorization and self-hosting

Organization-specific permissions are additive, not a bypass. Identity/device/bridge operations also require the corresponding existing canonical read authority before canonical state is returned or associated.

A self-hosted organization uses the same UCR Protocol and canonical model as managed deployment. Phase 38 introduces no private fork, privileged ClientPlatform/BusinessAIOS path, mandatory cloud account or provider-specific organization model.
## Privacy, ownership and non-claims

The Organization Node may observe only its explicitly authorized exact tenant/namespace policy, managed-association metadata, canonical state required to revalidate admitted services, and content already permitted by the underlying canonical owner/policy. Organization ownership never implies cross-tenant visibility or automatic access to historical recovery content.

Phase 38 does not claim a new global discovery service, a production relay listener, a new SFU transport, Bridge provider execution, enterprise backup, compliance archive, HA/SLA, deployment automation, DNS/NAT traversal or Production maturity. Those remain existing owners or future infrastructure work.

This phase is **Prepared**: it proves the self-hosting composition and authority boundaries required by the Canon, not production operations for a real enterprise deployment.

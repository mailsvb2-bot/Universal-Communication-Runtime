# Identity and Addressing Contract

Status: **Experimental / Phase 0**

## 1. Separation invariant

UCR treats `Identity`, `Address`, `Endpoint`, and `Route` as different concepts.

- Identity is durable canonical subject identity.
- Address is opaque locator material inside a namespaced addressing scheme.
- Endpoint is a communication presence/reachability surface that may have addresses.
- Route is transient runtime planning state and is never canonical Identity.

No phone number, email, external account ID, provider ID, hostname, IP address, or business-system ID becomes canonical Identity by representation alone.
## 2. Principal and Actor

A Principal is a subject of authorization. An Actor is a participant that performed or is represented in communication activity.

`on_behalf_of` is explicit. An AI agent, bot, organization, automation, external platform, device, or service principal must not be silently represented as a human principal.

## 3. Endpoint

An endpoint has a canonical endpoint ID, an endpoint kind, optional Identity/Device bindings, declared capabilities, and zero or more addresses.

A Device endpoint requires both its Device ID and owning Identity ID. Other endpoint kinds may be temporarily unbound while discovery or linking is incomplete.

Endpoint capability IDs and address schemes are namespaced protocol identifiers. A public Capability also preserves canonical protocol extensions; nested extension namespace, duplicate-name, count, and payload budgets are validated at the Endpoint boundary. Duplicate capability declarations are invalid.

`ENDPOINT_KIND_UNSPECIFIED` is a protobuf wire default only. It is not a valid canonical Endpoint kind after semantic decoding.
## 4. Address

Address values are opaque bytes to Core. Interpretation belongs to the addressing/transport implementation for the declared scheme.

Protocol parsers enforce bounded sizes before transport use. Address material is sensitive by default and must not be emitted verbatim by generic debug/telemetry surfaces.

An endpoint may exist with zero currently usable addresses; lack of a route must not delete or rewrite Identity.

## 5. External Identity Binding

`ExternalIdentityBinding` maps an integration-scoped external entity ID to canonical UCR Identity inside an explicit tenant/namespace scope.

The binding does not import business meaning into UCR. The runtime may know that an opaque external entity maps to an Identity; it does not infer that the entity is a customer, patient, lead, employee, payer, or other business-domain object.

Phase-13 durability uses one `ExternalIdentityBindingStore`. The exact durable key is `TenantScope + IntegrationId + external_namespace + external_entity_id bytes`; opaque entity bytes are preserved without case, Unicode, provider, or application normalization. First link is persisted, an equal retry is duplicate, and the same exact key with a different `IdentityId` conflicts. No relink/unlink lifecycle is defined yet; future replacement or deletion requires a separate canonical contract rather than storage-level overwrite. Independent `ucr.identity.external_binding.link` and `ucr.identity.external_binding.read` permissions guard the authorized runtime surface.
## 6. Route

Route selection belongs to UCR runtime/orchestration. A route candidate references a canonical Endpoint and one opaque EndpointAddress together with a transport capability.

External consumers may constrain routing policy, but must not create a parallel provider-specific routing core. Route state is replaceable and temporary.

## 7. Accountless and privacy properties

Canonical Identity must be able to exist without mandatory phone, email, password, provider account, or cloud registration.

Generic logs, `Debug`, crash reports, and telemetry must redact address bytes and external entity identifiers. Explicit diagnostic tooling may expose them only through an authorized, purpose-specific path with appropriate data classification.

## 8. Resource limits

Phase-0 reference limits are explicit and fail closed: address values and external entity IDs are bounded, endpoint address/capability collections are bounded, and duplicate entries are rejected before route planning.

Current Phase-0 reference limits:

- EndpointAddress value: 2048 bytes maximum.
- External entity ID: 2048 bytes maximum.
- Addresses per EndpointDescriptor: 64 maximum.
- Capabilities per EndpointDescriptor: 256 maximum.

Exceeding these limits is an explicit resource-limit failure; implementations must not allocate unbounded collections first and validate later.

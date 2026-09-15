# Infrastructure Metadata Visibility Contract

Status: **Security metadata baseline / release-gated living contract**.

## 1. Purpose

Every trust-boundary infrastructure component named by the UCR threat model must declare the metadata it can observe, the data it must not observe, retention expectations, export rules, and implementation status. The machine-checked companion inventory is `spec/metadata-visibility.tsv`.

The inventory is a **minimum-disclosure ceiling**, not an entitlement to collect data. A component may observe less. A `not_implemented` row describes the maximum visibility a future implementation may assume without a new reviewed ADR; it is not evidence that the component already exists.

## 2. Classification and interpretation

Canon classifications remain `PUBLIC`, `INTERNAL`, `PRIVATE`, `SECRET`, `KEY_MATERIAL`, `EPHEMERAL`, and `AUDIT`. Metadata such as social graph, IP history, routing history, group membership, presence, and contact-discovery material is privacy-sensitive even when content is encrypted.

`may_observe` records the minimum data shape an implementation may need for its declared role. `must_not_observe` records hard negative boundaries. `retention` never grants a component permission to persist data it was not allowed to observe. `export_rule` describes the only class of outward data flow allowed by the component contract.

## 3. Boundary-specific rules

The eleven numbered trust boundaries in `THREAT_MODEL.md` are authoritative and must each have exactly one inventory row. `Observability` is additionally mandatory because telemetry may be local, organization-hosted, or managed and therefore crosses a privacy boundary even though it is not one of the eleven canonical runtime boundaries.

Internet Transport visibility is limited to the exact scope/Endpoint/selected route needed for the session, public handshake material, pseudonymous retry token, encrypted envelope bytes, and network size/timing; it does not gain Message plaintext or private keys. Relay visibility is limited to relay-required network/routing context, encrypted payload size/timing, and minimal delivery state; relay operation never requires plaintext content. SFU visibility is limited to negotiated media-routing context and does not automatically include media plaintext. Bridge visibility is action-specific: provider identifiers and, only when explicitly required and policy-permitted, provider-visible content may cross the bridge. A bridge never receives unrelated tenant/conversation state merely because it can reach an external provider.

Cloud hosting adds no new authority. `Cloud Infrastructure` is an umbrella deployment boundary: every hosted child role remains constrained by its own inventory contract, and native/local Identity or durable state must not depend on a cloud account.

## 4. Observability

Observability is optional. Normal operation must not depend on central telemetry upload. Health, bounded counters, timings, sizes, and canonical error categories are suitable by default. Plaintext messages, decrypted attachments, recovery secrets, authentication secrets, and `KEY_MATERIAL` are prohibited. Raw addresses/provider identifiers require an authorized, purpose-specific diagnostic path rather than generic telemetry.

This contract does **not** close the separate `secret/plaintext telemetry regression tests` blocker. That blocker requires executable end-to-end evidence for actual telemetry/tracing/crash-report/integration paths when those paths exist.

## 5. Evolution rule

Architecture CI parses the numbered trust-boundary list from `THREAT_MODEL.md` and the TSV inventory. Adding or renaming a trust boundary without a visibility row fails the architecture gate. Duplicate rows, missing required fields, unknown implementation statuses, or loss of the mandatory Observability row also fail.

A future transport, signalling service, store-and-forward node, discovery service, hosted key provider, backup provider, or other externally visible infrastructure role must either fit an existing declared boundary without widening visibility or add a new threat-model boundary/inventory row and reviewed ADR in the same change.

Phase 28 Mesh adds no new infrastructure trust-boundary row: forwarding occurs between already-modeled authenticated User Devices. Participating peers may observe the bounded forward Device path required for loop prevention; that path is not authorization, Identity, social-graph, or Delivery evidence. A future Relay remains governed by the existing `not_implemented` Relay ceiling.

Phase 29 promotes the SFU boundary to `prepared`: it may observe only the exact Group/Call/stream routing context, source/recipient principals, source Device, MLS epoch/state reference, authenticated media header/signature metadata and encrypted packet size/timing required for fan-out. It receives no media plaintext, MLS exporter/traffic/private keys, and routing acceptance is not Identity, authorization, Delivery or Read evidence. Conference coordination remains out of scope.


Phase 36 Federation adds no new infrastructure trust-boundary row. The federation admission facade is Core policy over already-declared Personal/Organization Node endpoints and may observe only exact local/remote scope identifiers, node Endpoint identifiers, expected Device/key identifiers, allowed capability identifiers, trust state/generation, Sync binding and live authentication metadata needed for admission. It receives no new entitlement to Message/attachment plaintext, recovery/authentication secrets, private keys, unrelated tenant state or a global social/discovery graph. Organization Node remains `not_implemented` until Phase 38; Personal Node is promoted separately by Phase 37.


Phase 37 promotes the Personal Node inventory row to `prepared`. A Personal Node may observe only its owner-assigned exact scope, configured PersonalNode Endpoint/profile, enabled-service metadata, canonical Sync/Store-and-Forward/Bridge references needed for admission, and node-local opaque encrypted mailbox/cache objects selected by the owner. It must not infer authority from possession, reachability, federation, or provider data; it must not gain unrelated-tenant state, private/recovery/authentication keys, or undisclosed central telemetry. Disabling the node removes new Personal Node admission without granting permission to mutate canonical owner state.


Phase 38 promotes the Organization Node inventory row to `prepared`. Organization Mode may observe only its exact tenant/namespace, explicit Organization principal and OrganizationNode profile, managed Identity/Device association metadata, live canonical Identity/Device state required for revalidation, and exact Store-and-Forward/Bridge/SFU admission references needed by enabled services. Private discovery is a bounded projection of explicitly managed canonical Identities, not a global people graph. Node possession, hosting, reachability, federation, provider data, or an association row does not create authority. Organization Mode gains no entitlement to unrelated namespaces, plaintext history, recovery/authentication secrets, private keys, hidden telemetry, or a mandatory cloud path.

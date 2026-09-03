# Infrastructure Metadata Visibility Contract

Status: **Security metadata baseline / release-gated living contract**.

## 1. Purpose

Every trust-boundary infrastructure component named by the UCR threat model must declare the metadata it can observe, the data it must not observe, retention expectations, export rules, and implementation status. The machine-checked companion inventory is `spec/metadata-visibility.tsv`.

The inventory is a **minimum-disclosure ceiling**, not an entitlement to collect data. A component may observe less. A `not_implemented` row describes the maximum visibility a future implementation may assume without a new reviewed ADR; it is not evidence that the component already exists.

## 2. Classification and interpretation

Canon classifications remain `PUBLIC`, `INTERNAL`, `PRIVATE`, `SECRET`, `KEY_MATERIAL`, `EPHEMERAL`, and `AUDIT`. Metadata such as social graph, IP history, routing history, group membership, presence, and contact-discovery material is privacy-sensitive even when content is encrypted.

`may_observe` records the minimum data shape an implementation may need for its declared role. `must_not_observe` records hard negative boundaries. `retention` never grants a component permission to persist data it was not allowed to observe. `export_rule` describes the only class of outward data flow allowed by the component contract.

## 3. Boundary-specific rules

The ten numbered trust boundaries in `THREAT_MODEL.md` are authoritative and must each have exactly one inventory row. `Observability` is additionally mandatory because telemetry may be local, organization-hosted, or managed and therefore crosses a privacy boundary even though it is not one of the ten canonical runtime boundaries.

Relay visibility is limited to relay-required network/routing context, encrypted payload size/timing, and minimal delivery state; relay operation never requires plaintext content. SFU visibility is limited to negotiated media-routing context and does not automatically include media plaintext. Bridge visibility is action-specific: provider identifiers and, only when explicitly required and policy-permitted, provider-visible content may cross the bridge. A bridge never receives unrelated tenant/conversation state merely because it can reach an external provider.

Cloud hosting adds no new authority. `Cloud Infrastructure` is an umbrella deployment boundary: every hosted child role remains constrained by its own inventory contract, and native/local Identity or durable state must not depend on a cloud account.

## 4. Observability

Observability is optional. Normal operation must not depend on central telemetry upload. Health, bounded counters, timings, sizes, and canonical error categories are suitable by default. Plaintext messages, decrypted attachments, recovery secrets, authentication secrets, and `KEY_MATERIAL` are prohibited. Raw addresses/provider identifiers require an authorized, purpose-specific diagnostic path rather than generic telemetry.

This contract does **not** close the separate `secret/plaintext telemetry regression tests` blocker. That blocker requires executable end-to-end evidence for actual telemetry/tracing/crash-report/integration paths when those paths exist.

## 5. Evolution rule

Architecture CI parses the numbered trust-boundary list from `THREAT_MODEL.md` and the TSV inventory. Adding or renaming a trust boundary without a visibility row fails the architecture gate. Duplicate rows, missing required fields, unknown implementation statuses, or loss of the mandatory Observability row also fail.

A future transport, signalling service, store-and-forward node, discovery service, hosted key provider, backup provider, or other externally visible infrastructure role must either fit an existing declared boundary without widening visibility or add a new threat-model boundary/inventory row and reviewed ADR in the same change.

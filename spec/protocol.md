# UCR Protocol v0 — foundational contract

Status: **Experimental / Phase 0**

## 1. Namespaces and versioning

Stable canonical protocol identifiers use the `ucr.*` namespace. Experimental extensions use `experimental.*`. Vendor and organization extensions use `vendor.<name>.*` and `organization.<id>.*`.

Every protocol envelope carries an explicit schema/protocol version. Unknown optional extensions must be ignorable/preservable where their enclosing type allows it. Unknown critical extensions cause explicit negotiation failure.

## 2. Canonical IDs

IDs are opaque protocol values. Their semantic meaning must not be inferred from phone numbers, emails, IP addresses, hostnames, provider IDs or server database sequences. Offline generation is required by the Canon; the concrete generation algorithm requires a dedicated ADR before production.

## 3. Scope

Security-sensitive envelopes carry `tenant_id`; namespace is explicit where additional resource separation is required. Tenant scope must never be inferred from transport/provider metadata.

## 4. Command/Event boundary

A `Command` requests an action. An accepted command is not evidence that its requested real-world effect happened.

An `Event` records a fact in UCR state. Events carry an event ID, tenant, actor/source context, logical ordering, schema version and integrity metadata as those subsystems become implemented.

Commands and events carry correlation/idempotency data sufficient for effectively-once user experience without claiming universal exactly-once execution.

## 5. Communication Intent

Communication Intent is a first-class primitive. It identifies a target and payload together with constraints such as urgency, privacy, allowed/forbidden transports, cost and region constraints.

External consumers express intent and policy constraints. They do not control the internal routing graph.

## 6. Version negotiation

Peers advertise supported protocol ranges. Negotiation selects the highest mutually supported version that also satisfies local minimum-security/compatibility policy.

If there is no mutually permitted version, negotiation fails explicitly. Implementations must not silently fall back below configured minimum policy.

A future authenticated handshake must bind the negotiated version/capability transcript to integrity protection to prevent downgrade attacks.

## 7. Capabilities

Capabilities describe observed/declared abilities, not assumptions based solely on OS/provider names. Capability maturity is explicit: Experimental, Prepared, Beta, Production, Deprecated or Disabled.

## 8. Error semantics

Errors are structured and machine-readable. Provider-specific failures are mapped to canonical error categories while optional provider details remain non-canonical diagnostics.

Failure state must not be hidden. Prepared/experimental capability must not be represented as production-ready.

## 9. Compatibility

Stable public fields are not removed or repurposed without versioning. Unknown optional fields/extensions are tolerated according to schema rules. Critical unsupported extensions fail explicitly.

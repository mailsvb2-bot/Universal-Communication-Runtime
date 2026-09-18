# ADR 0102: Metadata privacy is minimum disclosure

Status: Accepted

## Context

The Canon requires every infrastructure component to have an explicit metadata visibility boundary and calls out social graph, IP/routing history, group membership, presence and contact discovery as sensitive metadata.

## Decision

UCR applies minimum disclosure by component and scope.

Relay receives only routing/forwarding metadata required for the admitted encrypted envelope. SFU receives only media-routing metadata required for the current authorized Call and no media plaintext/key material. Bridge receives only provider context required by its declared action. Diagnostics/telemetry expose bounded operational state and never plaintext messages, decrypted attachments, private keys, recovery secrets or authentication secrets.

Metadata visibility never confers authorization. Tenant/namespace and permission checks are revalidated at the canonical owner before disclosure.

Any new infrastructure component must document its visible metadata and redaction boundary before a Production maturity claim.

## Consequences

Operational observability remains possible without turning infrastructure telemetry into a second communication database or unnecessary social-graph store.

# ADR 0095: Persona model preserves explicit separation

Status: Accepted

## Context

The Canon requires Person and Persona as distinct canonical concepts and requires Private, Work, Anonymous, Event, Organization and Temporary identities not to be merged automatically. The current model had `PersonId` and `PersonaId` identifiers but no record expressing that separation.

## Decision

UCR keeps `Person`, `Persona` and `Identity` distinct.

A `PersonRecord` is only a scoped physical-person aggregate. A `PersonaRecord` binds one scoped Persona to exactly one canonical Identity and may optionally reference a Person. Anonymous, organization-managed or temporary Personas may deliberately have no Person link. Persona kinds are Private, Work, Anonymous, Event, Organization, Temporary or an explicitly named Custom kind.

No display name, provider identifier, endpoint, phone, email or profile similarity may create or merge a Person/Persona/Identity association. Correlation requires an explicit authorized operation and remains tenant/namespace scoped.

Temporary Persona expiry is explicit metadata; expiry never silently rewrites or merges another Identity.

## Consequences

Persona separation is now representable without a second identity model. Pseudonymous use remains possible without mandatory cloud/account identity. Future profile presentation data may attach to Persona, but canonical Identity remains provider-independent and unchanged.

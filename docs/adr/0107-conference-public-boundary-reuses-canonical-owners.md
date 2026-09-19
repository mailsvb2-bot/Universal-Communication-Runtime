# ADR 0107: Conference public boundary reuses canonical owners

Status: Accepted

## Context

Conference coordination and SFU routing existed as internal/reference runtimes, while the public v1 contract intentionally exposed only CallService. Webinar/product integration needs a stable service boundary without creating a second conference state machine.

## Decision

`ucr.v1.ConferenceService` is the stable public facade for Conference Start/Get/Signal/subscription preference/join URL issuance.

The service delegates to canonical `CallSession`, Group, MLS and SFU owners. `ConferenceSnapshot` remains a projection. Service authentication is binding metadata; credentials never become canonical Conference payload. Existing Call/Group/media authorization is revalidated rather than replaced.

Join grants are short-lived and exact-scope. They bind TenantScope, Call, participant, optional Device, session and expiry. Browser join credentials are placed in URL fragments and then presented as Authorization metadata, reducing accidental URL-log/referrer disclosure.

## Consequences

ClientPlatform or another product can depend on a stable UCR Conference API without embedding UCR internals or gaining a privileged hidden API. Durable signalling/membership stays single-owned.

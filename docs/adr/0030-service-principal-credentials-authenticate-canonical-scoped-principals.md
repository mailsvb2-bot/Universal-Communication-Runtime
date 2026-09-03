# ADR-0030: Service Principal credentials authenticate canonical scoped principals

Status: Accepted

## Context

UCR already has one canonical Principal model and deny-by-default durable permission enforcement, but runtime callers still supplied an "already authenticated" `ScopedPrincipal`. Treating a principal ID, process identity, provider account, or permission grant as authentication proof would create a second security brain. Service Principal authentication therefore needs an independent credential lifecycle that resolves back into the existing canonical `ScopedPrincipal`.

## Decision

The Rust reference runtime uses an opaque credential ID plus a 256-bit OS-CSPRNG secret. The plaintext secret is one-time issuance material, redacted from `Debug`, zeroized on drop, and never stored in the general durable store. Durable state stores only exact scope, canonical Service Account principal ID, lifecycle state, and a domain-separated SHA-256 digest bound to scope + principal + credential ID + secret. Verification uses constant-time digest comparison.

Missing, wrong-scope, wrong-secret, revoked, and invalid-kind credentials share one non-disclosing authentication failure mapped to canonical `UNAUTHENTICATED`. Successful authentication returns only the independently persisted canonical `ScopedPrincipal`; it confers no permissions. Existing `AuthorizedDurableRuntime` remains the single least-privilege authorization owner.

Credential provision and revoke are themselves covered by distinct protocol-owned runtime permissions. Raw store access remains internal bootstrap/persistence capability. SQLite v13 adds restart-safe credential state through an additive v12-to-v13 migration and never infers credentials from prior authorization or identity state.

## Consequences

Service Principal authentication and least-privilege runtime enforcement now have executable reference evidence without changing Principal identity semantics or embedding credentials in grants. Credential revocation survives restart and cannot silently reactivate a revoked credential ID. A credential can authenticate successfully while every unrelated operation remains denied until separately granted.

This closes the production blocker named `Service Principal authentication/least-privilege enforcement`. It does not claim quota/rate-limit enforcement, audit persistence, public API transport syntax, OAuth/OIDC, Device-wide revocation, or remote peer authentication. Because the Canon also requires quotas and auditability for production Service Principals, those remaining requirements stay visible as the separate blocker `Service Principal quota and audit enforcement`.

## Rejected alternatives

- Put API keys inside `PermissionGrant`: rejected because authorization state is not authentication proof.
- Trust a caller-supplied `ScopedPrincipal`: rejected because an identifier is not proof of possession.
- Hash only the secret: rejected because durable credential state must be cryptographically bound to its canonical scope/principal/credential identity.
- Return different failures for missing, revoked, or wrong secret: rejected because that creates a credential-enumeration oracle.

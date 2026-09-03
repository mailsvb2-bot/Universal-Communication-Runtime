# Service Principal Authentication

Status: **Experimental / production-security foundation**.

A Service Principal is the existing canonical `ScopedPrincipal` whose `PrincipalKind` is `ServiceAccount`. Authentication MUST resolve that canonical principal from independently persisted credential state; caller-supplied Principal, Actor, Endpoint, provider identity, process identity, or network origin is not authentication proof.

## Credential form

The Rust reference credential is a random 256-bit secret plus an opaque credential ID generated offline from the OS CSPRNG. The plaintext secret is returned only at issuance, is redacted from `Debug`, and is zeroized on drop. General durable storage contains only the credential ID, exact tenant/namespace scope, canonical Service Account principal ID, lifecycle state, and a 32-byte SHA-256 digest.

The v1 digest is domain-separated with `UCR-SERVICE-CREDENTIAL-DIGEST-V1\0` and binds the exact tenant ID, optional namespace ID, principal ID, credential ID, and secret using length-prefixed canonical ID bytes. Digest comparison is constant-time. A credential digest is authentication metadata, not a password-equivalent plaintext export surface.

## Authentication semantics

Authentication resolves by exact `(TenantScope, credential_id)`. The resolved record MUST be Active, MUST belong to `PrincipalKind::ServiceAccount`, and MUST match the presented secret digest. Missing credentials, wrong scope, wrong secret, malformed/non-ServiceAccount records, and revoked credentials all fail with the same non-disclosing authentication result; the canonical API error is `UNAUTHENTICATED`.

Successful authentication returns the persisted canonical `ScopedPrincipal`. It does not grant authority by itself. The result enters the existing `AuthorizedDurableRuntime`, where deny-by-default `PermissionGrant` evaluation supplies least privilege. A valid credential with no applicable permission remains denied.

## Lifecycle and administration

Credential provisioning and revocation are durable capabilities. Runtime provisioning and revocation require distinct protocol-owned permissions: `ucr.authentication.service_credential.provision` and `ucr.authentication.service_credential.revoke`. Raw credential storage is an internal persistence/bootstrap capability, not an external API bypass.

Revocation is irreversible for the credential ID. Repeating the same revocation is idempotent. New credentials may be issued and old credentials revoked without changing the canonical Service Principal identity or its permission grants.

SQLite schema v13 persists this lifecycle and migrates additively from v12 without inferring credentials from permission grants, signing keys, messages, or any existing identity state.

## Explicit non-goals

This foundation does not define public HTTP/gRPC bearer syntax, browser sessions, human login, OAuth/OIDC federation, quotas/rate limits, or audit-log persistence. It also does not replace Device authentication or remote peer/session authentication. Service Principal quota and audit enforcement remain production work.

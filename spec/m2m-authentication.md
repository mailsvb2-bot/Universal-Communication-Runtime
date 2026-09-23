# Machine-to-Machine Authentication

Status: **Prepared v1 public contract with signed token codec/runtime; public HTTPS edge is not yet claimed**.

This layer adds a standard machine-to-machine authentication boundary for external applications without creating a second identity, credential, authorization, tenant, or permission owner. The canonical Service Account remains the client identity and the existing Service Credential remains the long-lived client authentication proof.

## Client credentials grant

The v1 grant is OAuth2-compatible `client_credentials` semantics.

A concrete HTTPS token edge authenticates a client with the existing canonical Service Credential. The credential identifier and secret are transport credentials and MUST NOT be copied into the protobuf request body or persisted in an access token record.

The token request carries only:

- exact `TenantScope`;
- `client_id`, which is the canonical Service Account principal / integration identifier;
- requested `scope` values;
- required `audience`.

Authentication MUST resolve the existing durable Service Credential and MUST prove that its canonical Service Account principal exactly matches `client_id`. A caller cannot select another Service Account after authenticating.

## Access tokens

Access tokens are short-lived bearer credentials. They MUST contain or cryptographically bind:

- issuer;
- audience;
- subject / canonical Service Account principal ID;
- exact tenant and optional namespace;
- granted scopes;
- issued-at;
- expiry;
- key ID;
- unique token ID.

The default token lifetime is deployment policy. The public request may ask for a shorter lifetime but MUST NOT extend the deployment maximum. Tokens with an unknown issuer, wrong audience, expired lifetime, unknown/revoked signing key, malformed scope, or mismatched tenant fail closed.

Access tokens MUST NOT contain the long-lived Service Credential secret or its digest.

## Scopes and canonical authorization

OAuth scopes are an integration-facing attenuation layer, not a second authorization database.

A granted scope can only remove authority. Every authenticated API operation still enters the existing canonical authorization path and MUST satisfy both:

1. the access token contains the required public scope; and
2. the canonical Service Account has the corresponding Permission Grant in the exact scope.

Possessing a broad token never creates a Permission Grant. Revoking or narrowing the underlying canonical authorization therefore remains authoritative even for an otherwise-valid token.

The initial universal Conference scope vocabulary is:

- `conference:create`;
- `conference:manage`;
- `conference:join:issue`;
- `conference:read`;
- `attendance:read`;
- `recording:manage`.

Future public APIs may add namespaced scopes without changing this ownership rule.

## Signing keys, rotation and JWKS

Access tokens are signed by an asymmetric deployment signing key. A token header carries a `kid`. Verification uses the active public key set.

Key rotation MUST allow an overlap window: a new signing key may become active while the previous public key remains published until every token signed by it can no longer be valid. Revoking a key early intentionally invalidates outstanding tokens signed by that key.

The public HTTPS edge MUST expose an RFC-compatible JWKS document and stable issuer metadata. Private signing material never appears in JWKS, protobuf, logs, metrics, Event payloads, or general durable application storage.

## Audience and issuer

The issuer is deployment-owned and stable for one security domain. The audience is explicit and required. Tokens minted for one UCR deployment/API audience MUST NOT authenticate to a different audience.

The typed contract models issuer/audience metadata so REST/OAuth and gRPC adapters can share one semantic source instead of inventing gateway-specific token rules.

## Revocation semantics

Long-lived client access is revoked through the existing irreversible Service Credential lifecycle or Service Account authorization changes.

Short-lived access tokens are intentionally bounded by expiry and signing-key validity. A deployment MAY add a token-ID deny list for emergency revocation, but that list must remain an authentication sidecar and must not become a second Service Account or Permission owner.

## Public transport

The normative typed contract is `ucr.v1.MachineAuthService`.

The production OAuth2-compatible HTTPS edge will map:

- token exchange to `POST /oauth2/token`;
- authorization server metadata to a stable well-known document;
- public signing keys to JWKS.

The HTTPS adapter must remain transport-only. It must not duplicate credential authentication, scope attenuation, tenant isolation or Permission Grant decisions.

## Security logging

Token values, client secrets and Service Credential digests are secrets and MUST NOT be logged. Audit may record redaction-safe facts such as client ID, tenant scope, requested/granted scope identifiers, token key ID, issuance outcome and expiry.

## Nonclaims

This contract does not claim human login, authorization-code flow, PKCE, refresh tokens, browser SSO, social login, user OIDC federation, or a production public HTTPS OAuth edge.

`ucr-crypto::machine_token` now provides the reference Ed25519 signed access-token issuer/verifier over an already authenticated canonical Service Account. It enforces bounded token size, issuer/audience, short lifetime, `kid`, canonical tenant/namespace/service-account identity, scope attenuation, expiry and redacted token/private-key diagnostics. A resolver abstraction allows overlapping public keys during rotation without exporting private key material.

This runtime codec still does not make M2M authentication production-ready by itself. `MachineAuthService` composition with canonical Service Credential authentication, public HTTPS `POST /oauth2/token`, JWKS/metadata publication, bearer admission on public API boundaries, durable deployment key rotation and HTTPS conformance remain required.

# Machine-to-Machine Authentication

Status: **Prepared v1 public contract with signed token codec/runtime, canonical MachineAuthService composition, loopback production-daemon wiring, and bounded public verification-key/JWKS projection; public HTTPS edge is not yet claimed**.

This layer adds a standard machine-to-machine authentication boundary for external applications without creating a second identity, credential, authorization, tenant, or permission owner. The canonical Service Account remains the client identity and the existing Service Credential remains the long-lived client authentication proof.

## Client credentials grant

The v1 grant is OAuth2-compatible `client_credentials` semantics.

For the standard HTTP `client_secret_basic` binding, the external username is the canonical Service Account / integration `client_id`. The password is one opaque UCR OAuth client secret. That secret packages the exact canonical tenant scope, Service Credential locator and one-time credential secret into one redacted, zeroizing transport value. An integration therefore persists only `client_id + client_secret`; it is not required to persist or understand UCR's internal `credential_id` or tenant/namespace credential lookup tuple separately.

Decoding this opaque transport value never authenticates by itself. The HTTP adapter must pass the decoded scope, credential ID and secret into the existing `ServicePrincipalRequestGate`, then require the independently presented Basic username / `client_id` to match the authenticated canonical Service Account exactly. Rotation remains the existing Service Credential lifecycle: issue a new credential/client-secret value, overlap as deployment policy permits, then irreversibly revoke the old credential. No OAuth-specific credential database is introduced.

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

The public HTTPS edge MUST expose an RFC-compatible JWKS document and stable issuer metadata. `ucr-crypto` provides a bounded `MachineTokenPublicKeySet` that implements the canonical verification-key resolver, supports overlap windows, explicit key removal, and RFC 8037 Ed25519 JWKS projection containing only public `kid`/`x` material. The typed `MachineAuthService.GetJwks` contract now exposes the active deployment verification key as structured RFC 8037/JWKS fields (`OKP`, `Ed25519`, `sig`, `EdDSA`, `kid`, Base64URL `x`) so a future HTTPS adapter does not need signing-key access or duplicate key projection rules. Private signing material never appears in JWKS, protobuf, logs, metrics, Event payloads, or general durable application storage.

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
- `MachineAuthService.GetJwks` to the public JWKS resource.

Public discovery advertises `client_secret_basic` as the external token-endpoint authentication method. The internal loopback gRPC credential metadata remains an implementation transport and is not advertised to integrations.

The HTTPS adapter must remain transport-only. It must not duplicate credential authentication, scope attenuation, tenant isolation or Permission Grant decisions.

## Security logging

Token values, client secrets and Service Credential digests are secrets and MUST NOT be logged. Audit may record redaction-safe facts such as client ID, tenant scope, requested/granted scope identifiers, token key ID, issuance outcome and expiry.

## Nonclaims

This contract does not claim human login, authorization-code flow, PKCE, refresh tokens, browser SSO, social login, user OIDC federation, or a production public HTTPS OAuth edge.

`ucr-crypto::machine_token` now provides the reference Ed25519 signed access-token issuer/verifier over an already authenticated canonical Service Account. It enforces bounded token size, issuer/audience, short lifetime, `kid`, canonical tenant/namespace/service-account identity, scope attenuation, expiry and redacted token/private-key diagnostics. A resolver abstraction allows overlapping public keys during rotation without exporting private key material.

This runtime codec still does not make M2M authentication production-ready by itself. `MachineAuthService` composition with canonical Service Credential authentication, public HTTPS `POST /oauth2/token`, JWKS/metadata publication, bearer admission on public API boundaries, durable deployment key rotation and HTTPS conformance remain required.


## Canonical MachineAuthService composition

The reference gRPC `MachineAuthService` now composes token issuance with the existing Service Principal admission boundary. Credential ID and secret remain transport metadata; the request body carries only scope, client ID, requested OAuth scopes, audience and optional bounded TTL.

Token exchange:

1. authenticates the presented Service Credential through the existing `ServicePrincipalRequestGate`;
2. requires the authenticated canonical Service Account principal to exactly match `client_id`;
3. maps every requested OAuth scope to an existing canonical permission;
4. authorizes the first permission through the normal quota/audit admission path and every additional requested permission through the same admitted Service Principal context;
5. issues a short-lived signed access token only after all requested authority has been proven.

The initial mapping is:

- `conference:create` -> `ucr.conference.create`;
- `conference:manage` -> `ucr.conference.manage`;
- `conference:join:issue` -> `ucr.conference.join.issue`;
- `conference:read` -> `ucr.conference.read`;
- `attendance:read` -> `ucr.conference.attendance.read`;
- `recording:manage` -> `ucr.conference.recording.manage`.

Unknown or duplicate OAuth scopes fail closed. This mapping is an attenuation/projection of canonical authorization and does not persist OAuth scopes as a second permission owner.

The gRPC composition still does not claim the production HTTPS `POST /oauth2/token` edge, JWKS serving, bearer middleware on public APIs, or durable deployment signing-key rotation. The shared machine-auth crate now defines the opaque `client_id + client_secret` transport binding required for standard HTTP `client_secret_basic`; the concrete HTTPS parser/response adapter remains separate transport work.


## Shared machine-auth runtime owner and fixed token admission

The canonical token-exchange rules are now owned by the transport-neutral `ucr-machine-auth` runtime. gRPC and future HTTPS/REST adapters must delegate to that owner rather than reimplementing credential, scope, client-ID, quota, audit or token-signing rules.

Token exchange has its own canonical permission:

`ucr.authentication.machine_token.issue`

A Service Account must hold that permission before any requested OAuth scope is considered. The request is admitted through the normal Service Principal gate under that fixed permission, so token exchange always consumes the canonical Management request-rate bucket. The order of requested OAuth scopes therefore cannot change or bypass token-request rate limiting.

After fixed token admission succeeds, every requested OAuth scope is checked as an additional canonical permission for the same authenticated Service Account and exact tenant scope. Only after all requested permissions are proven may the runtime issue the short-lived signed token.

This closes the earlier transport-local behavior where the first requested OAuth scope could determine the primary Service Principal admission permission and therefore its request-rate class.


## Production daemon wiring

The production runtime now has an explicit `serve-auth` mode that serves the canonical `MachineAuthService` on a loopback-only gRPC listener over the same durable SQLite Service Credential, Permission Grant, quota and audit owners used by the rest of UCR.

The daemon requires deployment-owned machine-token configuration:

- stable HTTPS issuer;
- explicit API audience;
- stable signing-key ID;
- public HTTPS token endpoint URL;
- public HTTPS JWKS URL;
- bounded maximum token TTL;
- a protected operator secret file containing the 32-byte Ed25519 signing seed encoded as hexadecimal text.

The signing seed is read into zeroizing process memory and is never accepted as a command-line argument or dedicated `UCR_MACHINE_TOKEN_SIGNING_KEY_HEX` environment variable. The private seed is never printed, persisted in the application database, returned by gRPC, or included in discovery metadata.

The stable seed means the same deployment key survives daemon restart. The crypto layer now has a bounded public key-set primitive for overlap verification, explicit key removal, and JWKS projection. This is still not the final durable rotation owner: active/previous signing-key lifecycle, restart-safe key-set persistence and public HTTPS JWKS serving remain future work.

The local auth daemon refuses non-loopback plaintext binding. External OAuth2 traffic must still terminate at a trusted HTTPS edge before reaching this local service. The typed service now exposes public discovery plus the active public JWKS key and advertises `client_secret_basic`, but the concrete HTTP Basic parser, public `POST /oauth2/token`, public JWKS/metadata HTTP routes, bearer admission on public APIs, and durable active/previous signing-key rotation remain separate work.

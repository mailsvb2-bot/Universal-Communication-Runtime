use core::fmt;

use ucr_core::{
    AuthorizationEvaluator, ServiceAuditStore, ServiceCredentialStore,
    ServicePrincipalRequestAuthorization, ServicePrincipalRequestGate, ServiceQuotaClock,
    ServiceQuotaStore,
};
use ucr_crypto::{
    MachineTokenError, MachineTokenKeyResolver, MachineTokenPolicy, VerifiedMachineAccessToken,
    verify_machine_access_token,
};
use ucr_model::{AuthorizationRequest, KeyId, OpaqueId, ScopedPrincipal, TenantScope};
use ucr_protocol::{CanonicalError, CanonicalErrorCode};

use crate::{canonical_permission_for_scope, machine_scope_for_permission};

/// Canonical result of admitting one short-lived machine Bearer token.
///
/// The original encoded token is deliberately not retained. This proof contains only the
/// authenticated Service Account identity, token identifier, attenuated public scopes and
/// verification-key/lifetime metadata needed by a transport or API adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineBearerAdmission {
    subject: ScopedPrincipal,
    token_id: OpaqueId,
    granted_scopes: Vec<String>,
    expires_at_unix_s: u64,
    key_id: KeyId,
}

impl MachineBearerAdmission {
    #[must_use]
    pub const fn subject(&self) -> &ScopedPrincipal {
        &self.subject
    }

    #[must_use]
    pub const fn token_id(&self) -> &OpaqueId {
        &self.token_id
    }

    #[must_use]
    pub fn granted_scopes(&self) -> &[String] {
        &self.granted_scopes
    }

    #[must_use]
    pub const fn expires_at_unix_s(&self) -> u64 {
        self.expires_at_unix_s
    }

    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

/// Shared semantic owner for machine Bearer admission.
///
/// Token verification authenticates the signed canonical Service Account and attenuated OAuth
/// scopes. Admission then re-evaluates the current canonical Permission Grant for the requested
/// resource. A previously issued token therefore cannot preserve authority after its underlying
/// Permission Grant is revoked.
///
/// Request-rate quota, durable operation audit and transport parsing remain owned by the concrete
/// API ingress that invokes this runtime; this type intentionally owns no credential or token
/// database.
pub struct MachineBearerAdmissionRuntime<'a, C, A, R> {
    clock: &'a C,
    authorization: &'a A,
    resolver: &'a R,
    policy: &'a MachineTokenPolicy,
}

impl<'a, C, A, R> MachineBearerAdmissionRuntime<'a, C, A, R> {
    #[must_use]
    pub const fn new(
        clock: &'a C,
        authorization: &'a A,
        resolver: &'a R,
        policy: &'a MachineTokenPolicy,
    ) -> Self {
        Self {
            clock,
            authorization,
            resolver,
            policy,
        }
    }
}

impl<C, A, R> fmt::Debug for MachineBearerAdmissionRuntime<'_, C, A, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineBearerAdmissionRuntime")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<C, A, R> MachineBearerAdmissionRuntime<'_, C, A, R>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    R: MachineTokenKeyResolver,
{
    /// Verifies and admits one machine Bearer token for exactly one public OAuth scope.
    ///
    /// The required scope is server-selected by the API route. A token must contain that scope and
    /// the authenticated Service Account must still hold the corresponding canonical Permission
    /// Grant for the resource scope.
    ///
    /// # Errors
    /// Invalid, expired, forged, wrong-issuer/audience and unknown-key tokens collapse to
    /// `Unauthenticated`. Missing token scope or a revoked/absent current Permission Grant fails
    /// with `PermissionDenied`. Unknown server-side scope configuration fails closed as `Internal`.
    pub fn admit(
        &self,
        encoded: &str,
        required_scope: &str,
        resource_scope: &TenantScope,
    ) -> Result<MachineBearerAdmission, CanonicalError> {
        let (verified, permission) = self.authenticate_scope(encoded, required_scope)?;
        self.authorization.authorize(&AuthorizationRequest {
            subject: verified.subject.clone(),
            permission: permission.to_owned(),
            resource_scope: resource_scope.clone(),
        })?;
        Ok(admission_from_verified(verified))
    }

    fn authenticate_scope(
        &self,
        encoded: &str,
        required_scope: &str,
    ) -> Result<(VerifiedMachineAccessToken, &'static str), CanonicalError> {
        let permission = canonical_permission_for_scope(required_scope)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
        let now_unix_s = now_unix_s(self.clock)?;
        let verified = verify_machine_access_token(self.resolver, self.policy, encoded, now_unix_s)
            .map_err(map_bearer_token_error)?;
        if !verified
            .granted_scopes
            .iter()
            .any(|scope| scope == required_scope)
        {
            return Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied));
        }
        Ok((verified, permission))
    }
}

/// Machine Bearer request gate that reuses the canonical Service Principal quota/audit owner.
///
/// Token signature, issuer, audience, lifetime and OAuth scope are verified here. Canonical
/// Permission Grant evaluation, request-rate quota consumption and durable audit are then performed
/// exactly once by `ServicePrincipalRequestAuthorization`.
pub struct MachineBearerRequestGate<'a, C, A, R, S> {
    bearer: MachineBearerAdmissionRuntime<'a, C, A, R>,
    request: ServicePrincipalRequestGate<'a, C, A, S>,
}

impl<'a, C, A, R, S> MachineBearerRequestGate<'a, C, A, R, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    #[must_use]
    pub const fn new(
        clock: &'a C,
        authorization: &'a A,
        store: &'a S,
        resolver: &'a R,
        policy: &'a MachineTokenPolicy,
    ) -> Self {
        Self {
            bearer: MachineBearerAdmissionRuntime::new(clock, authorization, resolver, policy),
            request: ServicePrincipalRequestGate::new(clock, authorization, store),
        }
    }
}

impl<C, A, R, S> fmt::Debug for MachineBearerRequestGate<'_, C, A, R, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineBearerRequestGate")
            .finish_non_exhaustive()
    }
}

impl<'a, C, A, R, S> MachineBearerRequestGate<'a, C, A, R, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    R: MachineTokenKeyResolver,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    /// Verifies one Bearer and binds it to the canonical quota/authorization/audit evaluator.
    ///
    /// # Errors
    /// Fails closed for invalid Bearer tokens/scopes and for malformed route permission mapping.
    pub fn authenticate_request(
        &self,
        encoded: &str,
        required_scope: &str,
        resource_scope: &TenantScope,
    ) -> Result<ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        let (verified, permission) = self.bearer.authenticate_scope(encoded, required_scope)?;
        self.request.bind_machine_bearer_request(
            verified.subject,
            verified.token_id,
            permission,
            resource_scope,
        )
    }

    /// Verifies a Bearer for the OAuth scope owned by one canonical API permission.
    ///
    /// # Errors
    /// Unknown public permission mappings fail closed as internal route configuration errors.
    pub fn authenticate_permission_request(
        &self,
        encoded: &str,
        permission: &str,
        resource_scope: &TenantScope,
    ) -> Result<ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        let required_scope = machine_scope_for_permission(permission)
            .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::Internal))?;
        let (verified, _) = self.bearer.authenticate_scope(encoded, required_scope)?;
        self.request.bind_machine_bearer_request(
            verified.subject,
            verified.token_id,
            permission,
            resource_scope,
        )
    }

    /// Operation-bound Bearer request admission.
    ///
    /// # Errors
    /// Fails closed for invalid Bearer tokens/scopes or malformed operation metadata.
    pub fn authenticate_request_for_operation(
        &self,
        encoded: &str,
        required_scope: &str,
        resource_scope: &TenantScope,
        operation: &ucr_model::ServiceAuditOperationRef,
    ) -> Result<ServicePrincipalRequestAuthorization<'a, C, A, S>, CanonicalError> {
        let (verified, permission) = self.bearer.authenticate_scope(encoded, required_scope)?;
        self.request.bind_machine_bearer_request_for_operation(
            verified.subject,
            verified.token_id,
            permission,
            resource_scope,
            operation,
        )
    }
}

fn admission_from_verified(verified: VerifiedMachineAccessToken) -> MachineBearerAdmission {
    MachineBearerAdmission {
        subject: verified.subject,
        token_id: verified.token_id,
        granted_scopes: verified.granted_scopes,
        expires_at_unix_s: verified.expires_at_unix_s,
        key_id: verified.key_id,
    }
}

fn now_unix_s<C: ServiceQuotaClock>(clock: &C) -> Result<u64, CanonicalError> {
    let now_unix_ms = clock
        .now_unix_ms()
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
    let now_unix_ms = u64::try_from(now_unix_ms)
        .map_err(|_| CanonicalError::new(CanonicalErrorCode::TemporarilyUnavailable))?;
    Ok(now_unix_ms / 1_000)
}

const fn map_bearer_token_error(error: MachineTokenError) -> CanonicalError {
    match error {
        MachineTokenError::InvalidPolicy => CanonicalError::new(CanonicalErrorCode::Internal),
        MachineTokenError::InvalidTtl
        | MachineTokenError::InvalidScope
        | MachineTokenError::ScopeNotAllowed
        | MachineTokenError::NotServiceAccount
        | MachineTokenError::RandomUnavailable
        | MachineTokenError::Serialization
        | MachineTokenError::TokenTooLarge
        | MachineTokenError::MalformedToken
        | MachineTokenError::UnknownSigningKey
        | MachineTokenError::InvalidSignature
        | MachineTokenError::WrongIssuer
        | MachineTokenError::WrongAudience
        | MachineTokenError::NotYetValid
        | MachineTokenError::Expired
        | MachineTokenError::InvalidLifetime => {
            CanonicalError::new(CanonicalErrorCode::Unauthenticated)
        }
    }
}

#[cfg(test)]
mod tests {
    use ucr_core::{
        PermissionGrantStore, ServiceAuditStore, ServiceQuotaClockError, ServiceQuotaStore,
    };
    use ucr_crypto::{AccessTokenIssueRequest, MachineTokenSigningKey, issue_machine_access_token};
    use ucr_model::{
        NamespaceId, PermissionGrant, PermissionScope, PrincipalId, PrincipalKind, PrincipalRef,
        ServiceAuditOutcome, ServiceAuthenticationRef, ServiceQuotaPolicy, TenantId,
    };
    use ucr_protocol::{CONFERENCE_MANAGE_PERMISSION, CONFERENCE_READ_PERMISSION};
    use ucr_storage_memory::MemoryLocalStore;

    use super::*;
    use crate::{MACHINE_SCOPE_CONFERENCE_MANAGE, MACHINE_SCOPE_CONFERENCE_READ};

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(i64);

    impl ServiceQuotaClock for FixedClock {
        fn now_unix_ms(&self) -> Result<i64, ServiceQuotaClockError> {
            Ok(self.0)
        }
    }

    fn opaque(value: &str) -> OpaqueId {
        OpaqueId::new(value).expect("test opaque ID")
    }

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::from_opaque(opaque("tenant-bearer")),
            namespace_id: Some(NamespaceId::from_opaque(opaque("namespace-bearer"))),
        }
    }

    fn subject() -> ScopedPrincipal {
        ScopedPrincipal {
            scope: scope(),
            principal: PrincipalRef {
                principal_id: PrincipalId::from_opaque(opaque("integration-bearer")),
                kind: PrincipalKind::ServiceAccount,
            },
        }
    }

    fn policy() -> MachineTokenPolicy {
        MachineTokenPolicy {
            issuer: "https://auth.ucr.example.test".to_owned(),
            audience: "ucr-api".to_owned(),
            max_ttl_seconds: 900,
        }
    }

    fn signing_key() -> MachineTokenSigningKey {
        MachineTokenSigningKey::from_seed(
            KeyId::from_opaque(opaque("machine-bearer-key")),
            [7_u8; 32],
        )
    }

    fn issue(
        key: &MachineTokenSigningKey,
        policy: &MachineTokenPolicy,
        scopes: &[String],
    ) -> ucr_crypto::MachineAccessToken {
        let subject = subject();
        let token_id = opaque("machine-bearer-token");
        issue_machine_access_token(
            key,
            policy,
            AccessTokenIssueRequest {
                subject: &subject,
                token_id: &token_id,
                requested_scopes: scopes,
                allowed_scopes: scopes,
                issued_at_unix_s: 1_000,
                requested_ttl_seconds: Some(300),
            },
        )
        .expect("issue token")
    }

    fn grant(store: &MemoryLocalStore, permission: &str) {
        store
            .grant_permission(&PermissionGrant {
                grantee: subject(),
                permission: permission.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("grant permission");
    }

    #[test]
    fn bearer_admission_requires_both_token_scope_and_current_permission() {
        let store = MemoryLocalStore::default();
        grant(&store, CONFERENCE_READ_PERMISSION);
        let key = signing_key();
        let public = key.public_key();
        let policy = policy();
        let scopes = vec![MACHINE_SCOPE_CONFERENCE_READ.to_owned()];
        let token = issue(&key, &policy, &scopes);
        let clock = FixedClock(1_100_000);
        let runtime = MachineBearerAdmissionRuntime::new(&clock, &store, &public, &policy);

        let admission = runtime
            .admit(token.as_str(), MACHINE_SCOPE_CONFERENCE_READ, &scope())
            .expect("admit bearer");
        assert_eq!(admission.subject(), &subject());
        assert_eq!(admission.token_id().as_str(), "machine-bearer-token");
        assert_eq!(admission.granted_scopes(), scopes);
        assert_eq!(
            admission.key_id().as_opaque().as_str(),
            "machine-bearer-key"
        );
        assert_eq!(admission.expires_at_unix_s(), 1_300);
    }

    #[test]
    fn bearer_scope_is_an_attenuation_even_when_permission_exists() {
        let store = MemoryLocalStore::default();
        grant(&store, CONFERENCE_READ_PERMISSION);
        grant(&store, CONFERENCE_MANAGE_PERMISSION);
        let key = signing_key();
        let public = key.public_key();
        let policy = policy();
        let scopes = vec![MACHINE_SCOPE_CONFERENCE_READ.to_owned()];
        let token = issue(&key, &policy, &scopes);
        let clock = FixedClock(1_100_000);
        let runtime = MachineBearerAdmissionRuntime::new(&clock, &store, &public, &policy);

        let error = runtime
            .admit(token.as_str(), MACHINE_SCOPE_CONFERENCE_MANAGE, &scope())
            .expect_err("token scope must attenuate permission");
        assert_eq!(error.code, CanonicalErrorCode::PermissionDenied);
    }

    #[test]
    fn permission_revocation_takes_effect_before_token_expiry() {
        let store = MemoryLocalStore::default();
        grant(&store, CONFERENCE_READ_PERMISSION);
        let key = signing_key();
        let public = key.public_key();
        let policy = policy();
        let scopes = vec![MACHINE_SCOPE_CONFERENCE_READ.to_owned()];
        let token = issue(&key, &policy, &scopes);

        store
            .revoke_permission(&PermissionGrant {
                grantee: subject(),
                permission: CONFERENCE_READ_PERMISSION.to_owned(),
                scope: PermissionScope::Exact(scope()),
            })
            .expect("revoke permission");

        let clock = FixedClock(1_100_000);
        let runtime = MachineBearerAdmissionRuntime::new(&clock, &store, &public, &policy);
        let error = runtime
            .admit(token.as_str(), MACHINE_SCOPE_CONFERENCE_READ, &scope())
            .expect_err("revoked permission must fail");
        assert_eq!(error.code, CanonicalErrorCode::PermissionDenied);
    }

    #[test]
    fn invalid_or_expired_bearer_collapses_to_unauthenticated() {
        let store = MemoryLocalStore::default();
        grant(&store, CONFERENCE_READ_PERMISSION);
        let key = signing_key();
        let public = key.public_key();
        let policy = policy();
        let scopes = vec![MACHINE_SCOPE_CONFERENCE_READ.to_owned()];
        let token = issue(&key, &policy, &scopes);
        let expired_clock = FixedClock(1_400_000);
        let runtime = MachineBearerAdmissionRuntime::new(&expired_clock, &store, &public, &policy);

        let expired = runtime
            .admit(token.as_str(), MACHINE_SCOPE_CONFERENCE_READ, &scope())
            .expect_err("expired token");
        assert_eq!(expired.code, CanonicalErrorCode::Unauthenticated);

        let malformed = runtime
            .admit("not-a-token", MACHINE_SCOPE_CONFERENCE_READ, &scope())
            .expect_err("malformed token");
        assert_eq!(malformed.code, CanonicalErrorCode::Unauthenticated);
    }

    #[test]
    fn bearer_request_gate_reuses_quota_and_audit_with_exact_token_id() {
        let store = MemoryLocalStore::default();
        grant(&store, CONFERENCE_READ_PERMISSION);
        store
            .set_service_quota_policy(&ServiceQuotaPolicy {
                subject: subject(),
                max_requests: 1,
                window_ms: 1_000,
            })
            .expect("install request quota");

        let key = signing_key();
        let public = key.public_key();
        let policy = policy();
        let scopes = vec![MACHINE_SCOPE_CONFERENCE_READ.to_owned()];
        let token = issue(&key, &policy, &scopes);
        let clock = FixedClock(1_100_000);
        let gate = MachineBearerRequestGate::new(&clock, &store, &store, &public, &policy);
        let request = AuthorizationRequest {
            subject: subject(),
            permission: CONFERENCE_READ_PERMISSION.to_owned(),
            resource_scope: scope(),
        };

        let first = gate
            .authenticate_request(token.as_str(), MACHINE_SCOPE_CONFERENCE_READ, &scope())
            .expect("authenticate bearer request");
        first.authorize(&request).expect("authorize first request");

        let second = gate
            .authenticate_request(token.as_str(), MACHINE_SCOPE_CONFERENCE_READ, &scope())
            .expect("authenticate second bearer request");
        let limited = second
            .authorize(&request)
            .expect_err("second request must share canonical quota");
        assert_eq!(limited.code, CanonicalErrorCode::RateLimited);

        let audit = store
            .service_audit_records(&scope(), 8)
            .expect("read bearer audit");
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].outcome, ServiceAuditOutcome::Authorized);
        assert_eq!(audit[1].outcome, ServiceAuditOutcome::RateLimited);
        assert!(audit.iter().all(|record| matches!(
            &record.authentication,
            ServiceAuthenticationRef::MachineAccessToken(token_id)
                if token_id.as_str() == "machine-bearer-token"
        )));
    }

    #[test]
    fn unknown_server_scope_fails_as_internal_configuration_error() {
        let store = MemoryLocalStore::default();
        let key = signing_key();
        let public = key.public_key();
        let policy = policy();
        let clock = FixedClock(1_100_000);
        let runtime = MachineBearerAdmissionRuntime::new(&clock, &store, &public, &policy);

        let error = runtime
            .admit("irrelevant", "conference:unknown", &scope())
            .expect_err("unknown route scope");
        assert_eq!(error.code, CanonicalErrorCode::Internal);
    }
}

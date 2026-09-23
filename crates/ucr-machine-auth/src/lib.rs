use core::fmt;
use std::collections::BTreeSet;

use ucr_core::{
    AuthorizationEvaluator, ServiceAuditStore, ServiceCredentialSecret, ServiceCredentialStore,
    ServicePrincipalRequestGate, ServiceQuotaClock, ServiceQuotaStore, generate_opaque_id,
};
use ucr_crypto::{
    AccessTokenIssueRequest, MachineTokenError, MachineTokenPolicy, MachineTokenSigningKey,
    issue_machine_access_token,
};
use ucr_model::{
    AuthorizationRequest, KeyId, OpaqueId, PrincipalKind, ScopedPrincipal, ServiceCredentialId,
    TenantScope,
};
use ucr_protocol::{
    CONFERENCE_ATTENDANCE_READ_PERMISSION, CONFERENCE_CREATE_PERMISSION,
    CONFERENCE_JOIN_ISSUE_PERMISSION, CONFERENCE_MANAGE_PERMISSION, CONFERENCE_READ_PERMISSION,
    CONFERENCE_RECORDING_MANAGE_PERMISSION, CanonicalError, CanonicalErrorCode,
    MACHINE_TOKEN_ISSUE_PERMISSION,
};

pub const MACHINE_SCOPE_CONFERENCE_CREATE: &str = "conference:create";
pub const MACHINE_SCOPE_CONFERENCE_MANAGE: &str = "conference:manage";
pub const MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE: &str = "conference:join:issue";
pub const MACHINE_SCOPE_CONFERENCE_READ: &str = "conference:read";
pub const MACHINE_SCOPE_ATTENDANCE_READ: &str = "attendance:read";
pub const MACHINE_SCOPE_RECORDING_MANAGE: &str = "recording:manage";

pub const SUPPORTED_MACHINE_SCOPES: [&str; 6] = [
    MACHINE_SCOPE_CONFERENCE_CREATE,
    MACHINE_SCOPE_CONFERENCE_MANAGE,
    MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE,
    MACHINE_SCOPE_CONFERENCE_READ,
    MACHINE_SCOPE_ATTENDANCE_READ,
    MACHINE_SCOPE_RECORDING_MANAGE,
];

#[derive(Debug)]
pub struct MachineAuthExchangeRequest<'a> {
    pub scope: &'a TenantScope,
    pub credential_id: &'a ServiceCredentialId,
    pub secret: &'a ServiceCredentialSecret,
    pub client_id: &'a OpaqueId,
    pub requested_scopes: &'a [String],
    pub audience: &'a str,
    pub requested_ttl_seconds: Option<u32>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MachineAuthGrant {
    access_token: String,
    pub expires_in_seconds: u32,
    pub granted_scopes: Vec<String>,
    pub issuer: String,
    pub audience: String,
    pub key_id: KeyId,
}

impl MachineAuthGrant {
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
}

impl fmt::Debug for MachineAuthGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineAuthGrant")
            .field("access_token", &"<redacted>")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field("granted_scopes", &self.granted_scopes)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("key_id", &self.key_id)
            .finish()
    }
}

pub struct MachineAuthRuntime<'a, C, A, S> {
    clock: &'a C,
    authorization: &'a A,
    store: &'a S,
    signing_key: &'a MachineTokenSigningKey,
    policy: &'a MachineTokenPolicy,
}

impl<'a, C, A, S> MachineAuthRuntime<'a, C, A, S> {
    #[must_use]
    pub const fn new(
        clock: &'a C,
        authorization: &'a A,
        store: &'a S,
        signing_key: &'a MachineTokenSigningKey,
        policy: &'a MachineTokenPolicy,
    ) -> Self {
        Self {
            clock,
            authorization,
            store,
            signing_key,
            policy,
        }
    }
}

impl<C, A, S> fmt::Debug for MachineAuthRuntime<'_, C, A, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineAuthRuntime")
            .field("policy", &self.policy)
            .field("signing_key", &"<secret>")
            .finish_non_exhaustive()
    }
}

impl<C, A, S> MachineAuthRuntime<'_, C, A, S>
where
    C: ServiceQuotaClock,
    A: AuthorizationEvaluator,
    S: ServiceCredentialStore + ServiceQuotaStore + ServiceAuditStore,
{
    /// Authenticates an existing canonical Service Credential, requires explicit machine-token
    /// issuance authority, proves every requested public OAuth scope against canonical Permission
    /// Grants, and returns a short-lived signed access token.
    ///
    /// # Errors
    /// Fails closed for invalid credentials, missing token-issuance authority, mismatched
    /// `client_id`, unknown/duplicate scopes, denied canonical permissions, invalid audience/TTL,
    /// quota or audit failure, entropy failure, or token-signing failure.
    pub fn exchange(
        &self,
        request: MachineAuthExchangeRequest<'_>,
    ) -> Result<MachineAuthGrant, CanonicalError> {
        if request.audience != self.policy.audience {
            return Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument));
        }
        let permissions = requested_scope_permissions(request.requested_scopes)?;

        let gate = ServicePrincipalRequestGate::new(self.clock, self.authorization, self.store);
        let admission = gate.authenticate_request(
            request.scope,
            request.credential_id,
            request.secret,
            MACHINE_TOKEN_ISSUE_PERMISSION,
            request.scope,
        )?;
        let subject = admission.subject().clone();
        admission.authorize(&AuthorizationRequest {
            subject: subject.clone(),
            permission: MACHINE_TOKEN_ISSUE_PERMISSION.to_owned(),
            resource_scope: request.scope.clone(),
        })?;

        require_client_id(&subject, request.client_id)?;
        for permission in permissions {
            admission.authorize_additional_permission(permission)?;
        }

        let now_unix_s = now_unix_s(self.clock)?;
        let token_id =
            generate_opaque_id().map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;
        let token = issue_machine_access_token(
            self.signing_key,
            self.policy,
            AccessTokenIssueRequest {
                subject: &subject,
                token_id: &token_id,
                requested_scopes: request.requested_scopes,
                allowed_scopes: request.requested_scopes,
                issued_at_unix_s: now_unix_s,
                requested_ttl_seconds: request.requested_ttl_seconds,
            },
        )
        .map_err(map_machine_token_error)?;

        let expires_in_seconds = u32::try_from(token.expires_at_unix_s.saturating_sub(now_unix_s))
            .map_err(|_| CanonicalError::new(CanonicalErrorCode::Internal))?;

        Ok(MachineAuthGrant {
            access_token: token.as_str().to_owned(),
            expires_in_seconds,
            granted_scopes: token.granted_scopes,
            issuer: self.policy.issuer.clone(),
            audience: self.policy.audience.clone(),
            key_id: token.key_id,
        })
    }
}

fn requested_scope_permissions(scopes: &[String]) -> Result<Vec<&'static str>, CanonicalError> {
    if scopes.is_empty() {
        return Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument));
    }
    let mut seen = BTreeSet::new();
    let mut permissions = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !seen.insert(scope.as_str()) {
            return Err(CanonicalError::new(CanonicalErrorCode::InvalidArgument));
        }
        permissions.push(
            canonical_permission_for_scope(scope)
                .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::PermissionDenied))?,
        );
    }
    Ok(permissions)
}

const fn canonical_permission_for_scope(scope: &str) -> Option<&'static str> {
    match scope.as_bytes() {
        b"conference:create" => Some(CONFERENCE_CREATE_PERMISSION),
        b"conference:manage" => Some(CONFERENCE_MANAGE_PERMISSION),
        b"conference:join:issue" => Some(CONFERENCE_JOIN_ISSUE_PERMISSION),
        b"conference:read" => Some(CONFERENCE_READ_PERMISSION),
        b"attendance:read" => Some(CONFERENCE_ATTENDANCE_READ_PERMISSION),
        b"recording:manage" => Some(CONFERENCE_RECORDING_MANAGE_PERMISSION),
        _ => None,
    }
}

fn require_client_id(subject: &ScopedPrincipal, client_id: &OpaqueId) -> Result<(), CanonicalError> {
    if subject.principal.kind == PrincipalKind::ServiceAccount
        && subject.principal.principal_id.as_opaque() == client_id
    {
        Ok(())
    } else {
        Err(CanonicalError::new(CanonicalErrorCode::PermissionDenied))
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

const fn map_machine_token_error(error: MachineTokenError) -> CanonicalError {
    let code = match error {
        MachineTokenError::InvalidTtl | MachineTokenError::InvalidScope => {
            CanonicalErrorCode::InvalidArgument
        }
        MachineTokenError::ScopeNotAllowed | MachineTokenError::NotServiceAccount => {
            CanonicalErrorCode::PermissionDenied
        }
        MachineTokenError::TokenTooLarge => CanonicalErrorCode::ResourceExhausted,
        MachineTokenError::InvalidPolicy
        | MachineTokenError::RandomUnavailable
        | MachineTokenError::Serialization
        | MachineTokenError::MalformedToken
        | MachineTokenError::UnknownSigningKey
        | MachineTokenError::InvalidSignature
        | MachineTokenError::WrongIssuer
        | MachineTokenError::WrongAudience
        | MachineTokenError::NotYetValid
        | MachineTokenError::Expired
        | MachineTokenError::InvalidLifetime => CanonicalErrorCode::Internal,
    };
    CanonicalError::new(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_machine_scopes_map_only_to_existing_canonical_permissions() {
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_CREATE),
            Some(CONFERENCE_CREATE_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_MANAGE),
            Some(CONFERENCE_MANAGE_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_JOIN_ISSUE),
            Some(CONFERENCE_JOIN_ISSUE_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_CONFERENCE_READ),
            Some(CONFERENCE_READ_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_ATTENDANCE_READ),
            Some(CONFERENCE_ATTENDANCE_READ_PERMISSION)
        );
        assert_eq!(
            canonical_permission_for_scope(MACHINE_SCOPE_RECORDING_MANAGE),
            Some(CONFERENCE_RECORDING_MANAGE_PERMISSION)
        );
        assert_eq!(canonical_permission_for_scope("admin:all"), None);
    }

    #[test]
    fn duplicate_unknown_and_empty_scopes_fail_closed() {
        assert!(requested_scope_permissions(&[]).is_err());
        assert!(
            requested_scope_permissions(&[
                MACHINE_SCOPE_CONFERENCE_READ.to_owned(),
                MACHINE_SCOPE_CONFERENCE_READ.to_owned(),
            ])
            .is_err()
        );
        assert!(requested_scope_permissions(&["admin:all".to_owned()]).is_err());
    }
}
